import json, os, socket, time, uuid, threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .audit import AuditLog
from .canonical import atomic_write_json, canonical_bytes, digest
from .health import health
from .operation import OperationLog
from .payload_policy import sanitize_payload
from .peer_auth import AccessControl, peer_credentials
from .state import RuntimeState
ALLOWED = {'health', 'metrics', 'mode', 'config', 'register', 'rootResult', 'feedback', 'inspect', 'snapshot'}
ACCESS_LOG_BYTES = 8 * 1024 * 1024


class RuntimeService:
    def __init__(self, state_root, txn_root, peer_creds=True, allowed_uids=None, max_concurrency=32):
        self.state_root = Path(state_root)
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.txn_root = Path(txn_root)
        self.state = RuntimeState(self.state_root / 'runtime-state.json')
        self.audit = AuditLog(self.state_root / 'audit')
        self.ops = OperationLog(self.state_root / 'operations', audit=self.audit)
        self.recovery = self.ops.recover()
        self.acl = AccessControl(allowed_uids)
        self.sem = threading.BoundedSemaphore(max_concurrency)
        self.access_log = self.state_root / 'access-log.jsonl'
        self.pool = ThreadPoolExecutor(max_workers=max_concurrency)
        self._stop = threading.Event()
        self._socket_path = None

    def _log_access(self, creds, method, ok):
        if self.access_log.exists() and self.access_log.stat().st_size > ACCESS_LOG_BYTES:
            self.access_log.rename(self.access_log.with_suffix('.old'))
        line = {'ts': int(time.time()), 'pid': creds[0] if creds else None,
                'uid': creds[1] if creds else None, 'gid': creds[2] if creds else None,
                'method': method, 'ok': ok}
        try:
            with self.access_log.open('a') as f:
                f.write(json.dumps(line, sort_keys=True) + '\n')
                os.fsync(f.fileno())
        except OSError:
            pass

    def _reject(self, c, rid, code, message):
        try:
            c.sendall(canonical_bytes({'schemaVersion': 3, 'requestId': rid, 'ok': False,
                                       'error': {'code': code, 'message': message[:256]}}) + b'\n')
        except OSError:
            pass
        finally:
            c.close()

    def _op(self, kind, state_fn, event_type, event_details, actor_type='system', actor_id='runtime'):
        def wrapped(loaded):
            if loaded is None:
                loaded = self.state.empty()
            return state_fn(loaded)
        return self.ops.execute(kind, self.state.path, wrapped, event_type, event_details, actor_type, actor_id)

    def handle(self, e, peer_uid=None):
        rid = e.get('requestId') or str(uuid.uuid4())
        m = e.get('method')
        b = e.get('body') or {}
        try:
            if e.get('schemaVersion') != 3 or m not in ALLOWED:
                raise ValueError('invalid envelope/method')
            if m == 'health':
                r = health(self.state_root, self.txn_root, self.audit, self.ops)
            elif m == 'metrics':
                s = self.state.load()
                r = {'pending': len(s['pending']), 'completed': len(s['completed']), 'closed': len(s['closed']),
                     'activeOperations': self.ops.pending_count(), 'acl': self.acl.describe()}
            elif m == 'mode':
                mode = b.get('mode')
                if mode not in {'normal', 'observe-only', 'safe-disabled'}:
                    raise ValueError('invalid mode')

                def tx(s):
                    s['mode'] = mode
                    s['routeAssistEnabled'] = False if mode != 'normal' else s['routeAssistEnabled']
                    return {'mode': mode}, s
                r = self._op('mode', tx, 'runtime.mode.changed', {'mode': mode}, actor_id=str(peer_uid))
            elif m == 'config':
                s = self.state.load()
                r = {'mode': s['mode'], 'routeAssistEnabled': s['routeAssistEnabled'], 'boundedAutoAllowed': False}
            elif m == 'register':
                def tx(s):
                    ident = {'capability': b['capability'], 'decisionId': b['decisionId'],
                             'modelGeneration': int(b['modelGeneration']), 'createdAtEpochSeconds': int(b['createdAtEpochSeconds'])}
                    existing = (s['pending'].get(b['decisionId']) or s['completed'].get(b['decisionId']))
                    if existing:
                        if existing.get('identity') == ident:
                            return {'status': 'idempotent'}, s
                        raise ValueError('decision ID different identity')
                    tomb = s['closed'].get(b['decisionId'])
                    if tomb:
                        if tomb['identityHash'] == digest(ident):
                            return {'status': 'idempotent'}, s
                        raise ValueError('decision ID different identity')
                    s['pending'][b['decisionId']] = {'identity': ident, 'rootResult': None,
                                                     'registeredAtEpochSeconds': int(time.time())}
                    return {'status': 'registered'}, s
                r = self._op('register', tx, 'decision.registered', {'decisionId': b['decisionId']})
            elif m == 'rootResult':
                def tx(s):
                    p = s['pending'].get(b['decisionId'])
                    if not p:
                        raise ValueError('unknown pending decision')
                    if p.get('rootResult'):
                        if json.dumps(p['rootResult'], sort_keys=True) == json.dumps(b['result'], sort_keys=True):
                            return {'status': 'idempotent'}, s
                        raise ValueError('conflicting result')
                    p['rootResult'] = b['result']
                    return {'status': 'committed'}, s
                r = self._op('rootResult', tx, 'decision.root_result', {'decisionId': b['decisionId']})
            elif m == 'feedback':
                def tx(s):
                    psha = digest(b)
                    c = s['completed'].get(b['decisionId'])
                    if c:
                        if c['payloadSha256'] == psha:
                            return {'status': 'idempotent', 'accepted': True}, s
                        raise ValueError('conflicting completed feedback')
                    t = s['closed'].get(b['decisionId'])
                    if t:
                        if t['payloadHash'] == psha:
                            return {'status': 'idempotent', 'accepted': True}, s
                        raise ValueError('conflicting closed feedback')
                    p = s['pending'].get(b['decisionId'])
                    if not p:
                        raise ValueError('feedback unknown')
                    ident = p['identity']
                    if b.get('capability') != ident['capability'] or b.get('modelGeneration') != ident['modelGeneration']:
                        raise ValueError('feedback identity conflict')
                    if ident['capability'] == 'route' and not p.get('rootResult'):
                        raise ValueError('feedback before root result')
                    payload_meta = sanitize_payload(b)
                    s['completed'][b['decisionId']] = {'identity': ident, 'payloadMeta': payload_meta,
                                                       'payloadSha256': psha,
                                                       'acceptedAtEpochSeconds': int(time.time())}
                    del s['pending'][b['decisionId']]
                    while len(s['completed']) > self.state.max_completed:
                        evicted = sorted(s['completed'])[0]
                        e = s['completed'].pop(evicted)
                        s['closed'][evicted] = {'decisionIdHash': digest(evicted), 'identityHash': digest(e['identity']),
                                                'payloadHash': e['payloadSha256'], 'closedAtEpochSeconds': e['acceptedAtEpochSeconds']}
                    return {'status': 'accepted', 'accepted': True}, s
                r = self._op('feedback', tx, 'decision.feedback', {'decisionId': b.get('decisionId')})
            elif m == 'inspect':
                s = self.state.load()
                did = b.get('decisionId')
                r = {'pending': s['pending'].get(did), 'completed': s['completed'].get(did), 'closed': s['closed'].get(did)}
            else:
                r = self.state.load()
            return {'schemaVersion': 3, 'requestId': rid, 'ok': True, 'result': r}
        except Exception as x:
            return {'schemaVersion': 3, 'requestId': rid, 'ok': False,
                    'error': {'code': getattr(x, 'code', 'contractViolation'), 'message': str(x)[:512]}}

    def client(self, c):
        c.settimeout(5)
        creds = peer_credentials(c)
        rid = 'unknown'
        try:
            if not self.sem.acquire(blocking=False):
                self._reject(c, rid, 'serverBusy', 'concurrency limit reached')
                return
            try:
                d = b''
                while b'\n' not in d and len(d) <= 1048576:
                    x = c.recv(65536)
                    if not x:
                        break
                    d += x
                if len(d) > 1048576:
                    raise ValueError('too large')
                envelope = json.loads(d.split(b'\n', 1)[0])
                rid = envelope.get('requestId') or rid
                if not self.acl.authorize(creds):
                    self._log_access(creds, envelope.get('method'), False)
                    self._reject(c, rid, 'forbiddenPeer', 'peer uid not allowed')
                    return
                out = self.handle(envelope, peer_uid=(creds[1] if creds else None))
                self._log_access(creds, envelope.get('method'), bool(out.get('ok')))
                c.sendall(canonical_bytes(out) + b'\n')
            finally:
                self.sem.release()
        except Exception as x:
            self._log_access(creds, rid, False)
            try:
                c.sendall(canonical_bytes({'schemaVersion': 3, 'requestId': rid, 'ok': False,
                                           'error': {'code': 'transportError', 'message': str(x)[:256]}}) + b'\n')
            except Exception:
                pass
        finally:
            c.close()

    def stop(self):
        self._stop.set()
        if self._socket_path:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as wake:
                    wake.settimeout(.2)
                    wake.connect(str(self._socket_path))
            except Exception:
                pass

    def serve(self, path):
        path = Path(path)
        self._socket_path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(path))
        os.chmod(path, 0o660)
        s.listen(32)
        s.settimeout(1)
        try:
            while not self._stop.is_set():
                try:
                    c, _ = s.accept()
                except socket.timeout:
                    continue
                self.pool.submit(self.client, c)
        finally:
            s.close()
            self.pool.shutdown(wait=True, cancel_futures=True)
            path.unlink(missing_ok=True)
            self._socket_path = None


def time_now():
    import time
    return int(time.time())