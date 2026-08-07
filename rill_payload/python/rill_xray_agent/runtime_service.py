import json, os, socket, time, uuid, threading, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .audit import AuditLog
from .canonical import atomic_write_json, canonical_bytes, digest
from .health import health
from .operation import OperationLog
from .payload_policy import sanitize_payload, sanitize_root_result, RootResultViolation
from .peer_auth import AccessControl, peer_credentials
from .state import RuntimeState
from .root_txn import RootTransaction

ALLOWED = {'health', 'metrics', 'mode', 'config', 'register', 'rootResult', 'feedback', 'inspect', 'snapshot'}
ACCESS_LOG_BYTES = 8 * 1024 * 1024
MAX_FRAME_BYTES = 1048576


class BoundedQueue:
    """Fail-closed bounded acceptance gate shared by Runtime and Agent.

    The global slot is acquired BEFORE the connection is dispatched to a
    worker, so futures and sockets can never pile up unboundedly. A rejected
    connection is answered with serverBusy and closed immediately.
    """

    def __init__(self, capacity):
        self.capacity = int(capacity)
        self._sem = threading.BoundedSemaphore(self.capacity)
        self.active = 0
        self.rejected = 0
        self._lock = threading.Lock()

    def acquire(self):
        got = self._sem.acquire(blocking=False)
        if got:
            with self._lock:
                self.active += 1
        else:
            with self._lock:
                self.rejected += 1
        return got

    def release(self):
        with self._lock:
            self.active -= 1
        self._sem.release()

    def available(self):
        return max(0, self.capacity - self.active)

    def metrics(self):
        return {'capacity': self.capacity, 'activeConnections': self.active,
                'rejectedConnections': self.rejected, 'availableSlots': self.available()}


class RuntimeService:
    def __init__(self, state_root, txn_root, peer_creds=True, allowed_uids=None,
                 max_concurrency=32, max_completed=4096, ledger_max_entries=0,
                 ledger_max_bytes=None, replay_protection_seconds=21600,
                 default_uid=None):
        self.state_root = Path(state_root)
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.txn_root = Path(txn_root)
        self.state = RuntimeState(self.state_root / 'runtime-state.json', max_completed=max_completed,
                                  ledger_dir=self.state_root / 'closed-ledger',
                                  max_ledger_entries=ledger_max_entries,
                                  max_ledger_bytes=ledger_max_bytes,
                                  replay_protection_seconds=replay_protection_seconds)
        self.audit = AuditLog(self.state_root / 'audit')
        self.ops = OperationLog(self.state_root / 'operations', audit=self.audit)
        self.ops_report = self.ops.recover()
        self.txn = RootTransaction(self.txn_root, self.state_root / 'delivery',
                                   self.state_root / 'generation')
        # READ-ONLY: the production Runtime runs with ReadOnlyPaths on the
        # root transaction area and must NEVER materialize, rewrite history
        # or restore root-owned managed files. Privileged recovery is a
        # host-owned helper responsibility; the Runtime only scans.
        self.txn_scan = self.txn.scan_recovery_state()
        self.recovery_required = any(r['recoveryRequired'] for r in self.txn_scan)
        self.recovery = {'unresolved': [r['workDir'] for r in self.txn_scan if r['recoveryRequired']],
                         'scanned': self.txn_scan, 'privilegedRecoveryRequired': self.recovery_required}
        self.delivery_file = self.state_root / 'delivery' / 'route-delivery.json'
        # Fail-closed ACL: explicit allowlist; open access only when the
        # caller explicitly opts in (tests) with allow_open=True semantics.
        self.allowed_uids = set(allowed_uids) if allowed_uids is not None else set()
        if default_uid is not None:
            self.allowed_uids.add(default_uid)
        self.acl = AccessControl(self.allowed_uids)
        self.queue = BoundedQueue(max_concurrency)
        self.sem = self.queue._sem
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
                r = health(self.state_root, self.txn_root, self.audit, self.ops, self.delivery_file)
            elif m == 'metrics':
                s = self.state.load()
                r = {'pending': len(s['pending']), 'completed': len(s['completed']),
                     'closed': self.state.ledger.count(), 'closedLedger': self.state.ledger.count(),
                     'activeOperations': self.ops.pending_count(), 'acl': self.acl.describe(),
                     'queue': self.queue.metrics(),
                     'recoveryRequired': self.recovery_required,
                     'rootTransactionsUnresolved': len(self.recovery['unresolved'])}
            elif m == 'mode':
                mode = b.get('mode')
                if mode not in {'normal', 'observe-only', 'safe-disabled'}:
                    raise ValueError('invalid mode')
                if not self.acl.write_permitted(peer_uid):
                    raise ValueError('mode requires privileged peer')

                def tx(s):
                    s['mode'] = mode
                    s['routeAssistEnabled'] = False if mode != 'normal' else s['routeAssistEnabled']
                    return {'mode': mode}, s
                r = self._op('mode', tx, 'runtime.mode.changed', {'mode': mode}, actor_id=str(peer_uid))
            elif m == 'config':
                s = self.state.load()
                r = {'mode': s['mode'], 'routeAssistEnabled': s['routeAssistEnabled'], 'boundedAutoAllowed': False}
            elif m == 'register':
                did = b['decisionId']

                def tx(s):
                    ident = {'capability': b['capability'], 'decisionId': did,
                             'modelGeneration': int(b['modelGeneration']), 'createdAtEpochSeconds': int(b['createdAtEpochSeconds'])}
                    existing = (s['pending'].get(did) or s['completed'].get(did))
                    if existing:
                        if existing.get('identity') == ident:
                            return {'status': 'idempotent'}, s
                        raise ValueError('decision ID different identity')
                    tomb = self.state.ledger.get(did)
                    if tomb:
                        if tomb.get('corrupt'):
                            raise ValueError('closed ledger corrupt')
                        if tomb['identityHash'] == digest(ident):
                            return {'status': 'idempotent'}, s
                        raise ValueError('decision ID different identity')
                    s['pending'][did] = {'identity': ident, 'rootResult': None,
                                         'registeredAtEpochSeconds': int(time.time())}
                    return {'status': 'registered'}, s
                r = self._op('register', tx, 'decision.registered', {'decisionId': did})
            elif m == 'rootResult':
                did = b['decisionId']
                projection = sanitize_root_result(b['result'])

                def tx(s):
                    p = s['pending'].get(did)
                    if not p:
                        raise ValueError('unknown pending decision')
                    if p.get('rootResult'):
                        if json.dumps(p['rootResult'], sort_keys=True) == json.dumps(projection, sort_keys=True):
                            return {'status': 'idempotent'}, s
                        raise ValueError('conflicting result')
                    p['rootResult'] = projection
                    return {'status': 'committed'}, s
                r = self._op('rootResult', tx, 'decision.root_result', {'decisionId': did})
            elif m == 'feedback':
                def on_evict(evicted, entry):
                    self.state.ledger.put(evicted, digest(entry['identity']), entry['payloadSha256'],
                                          entry['acceptedAtEpochSeconds'])

                def tx(s):
                    psha = digest(b)
                    c = s['completed'].get(b['decisionId'])
                    if c:
                        if c['payloadSha256'] == psha:
                            return {'status': 'idempotent', 'accepted': True}, s
                        raise ValueError('conflicting completed feedback')
                    t = self.state.ledger.get(b['decisionId'])
                    if t:
                        if t.get('corrupt'):
                            raise ValueError('closed ledger corrupt')
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
                        on_evict(evicted, e)
                    return {'status': 'accepted', 'accepted': True}, s
                r = self._op('feedback', tx, 'decision.feedback', {'decisionId': b.get('decisionId')})
            elif m == 'inspect':
                s = self.state.load()
                did = b.get('decisionId')
                r = {'pending': s['pending'].get(did), 'completed': s['completed'].get(did),
                     'closed': self.state.ledger.get(did)}
            elif m == 'snapshot':
                s = self.state.load()
                r = self._snapshot(s)
            else:
                r = self.state.load()
            return {'schemaVersion': 3, 'requestId': rid, 'ok': True, 'result': r}
        except Exception as x:
            code = 'contractViolation'
            if isinstance(x, RootResultViolation):
                code = 'rootResultViolation'
            elif getattr(x, 'code', None):
                code = x.code
            return {'schemaVersion': 3, 'requestId': rid, 'ok': False,
                    'error': {'code': code, 'message': str(x)[:512]}}

    def _snapshot(self, s):
        """Safe projection: hashes and counts only, never raw bodies."""
        pending = {}
        for did, v in s['pending'].items():
            pending[did] = {
                'identityHash': digest(v.get('identity')),
                'rootResultPresent': v.get('rootResult') is not None,
                'registeredAtEpochSeconds': v.get('registeredAtEpochSeconds'),
            }
        completed = {}
        for did, v in s['completed'].items():
            completed[did] = {
                'identityHash': digest(v.get('identity')),
                'payloadSha256': v.get('payloadSha256'),
                'acceptedAtEpochSeconds': v.get('acceptedAtEpochSeconds'),
            }
        closed = self.state.ledger.entries()
        return {
            'mode': s['mode'],
            'routeAssistEnabled': s['routeAssistEnabled'],
            'boundedAutoAllowed': False,
            'schemaVersion': s['schemaVersion'],
            'restartCount': s['restartCount'],
            'pendingCount': len(s['pending']),
            'completedCount': len(s['completed']),
            'closedCount': len(closed),
            'pending': pending,
            'completed': completed,
            'closed': closed,
            'health': self.health_status(),
        }

    def health_status(self):
        try:
            h = health(self.state_root, self.txn_root, self.audit, self.ops, self.delivery_file)
        except Exception:
            h = {'status': 'recovery-required', 'reasons': ['health_unavailable'],
                 'canObserve': True, 'canRecommend': False, 'canApply': False,
                 'rootTransactions': {}}
        if self.recovery_required and h.get('status') != 'recovery-required':
            h = {**h, 'status': 'recovery-required',
                 'reasons': (h.get('reasons') or []) + ['privileged_host_recovery_required'],
                 'canRecommend': False, 'canApply': False}
        elif h.get('status') == 'recovery-required':
            h = {**h, 'canRecommend': False, 'canApply': False}
        return h

    def client(self, c):
        c.settimeout(5)
        creds = peer_credentials(c)
        rid = 'unknown'
        try:
            try:
                d = b''
                while b'\n' not in d and len(d) <= MAX_FRAME_BYTES:
                    x = c.recv(65536)
                    if not x:
                        break
                    d += x
                if len(d) > MAX_FRAME_BYTES:
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
                self.queue.release()
        except Exception as x:
            self._log_access(creds, None, False)
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
                if not self.queue.acquire():
                    self._reject(c, 'unknown', 'serverBusy', 'concurrency limit reached')
                    continue
                try:
                    self.pool.submit(self.client, c)
                except Exception:
                    self.queue.release()
                    c.close()
        finally:
            s.close()
            self.pool.shutdown(wait=True, cancel_futures=True)
            path.unlink(missing_ok=True)
            self._socket_path = None


def time_now():
    import time
    return int(time.time())