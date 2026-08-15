import json, os, socket, threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .canonical import canonical_bytes
from .peer_auth import peer_credentials
from .runtime_service import BoundedQueue, MAX_FRAME_BYTES

ALLOWED = {'health', 'metrics', 'mode', 'config', 'register', 'rootResult', 'feedback', 'inspect', 'snapshot',
           'routeStatus', 'routeStage', 'routePlan', 'routeApprove', 'routeReject', 'routeHistory',
           'autoStatus', 'autoConfirm'}
READ_ONLY = {'health', 'metrics', 'config', 'inspect', 'snapshot', 'routeStatus', 'routeHistory', 'autoStatus'}
OPERATOR = {'register', 'rootResult', 'feedback', 'routeStage', 'routePlan', 'routeApprove', 'routeReject',
            'autoConfirm'}
ROOT_ONLY = {'mode'}
ROUTE_METHODS = {'routeStatus', 'routeStage', 'routePlan', 'routeApprove', 'routeReject', 'routeHistory',
                 'autoStatus', 'autoConfirm'}


class AgentService:
    def __init__(self, runtime_socket, allowed_uids=None, max_concurrency=32):
        self.runtime_socket = Path(runtime_socket)
        self.allowed_uids = set(allowed_uids) if allowed_uids is not None else set()
        self.pool = ThreadPoolExecutor(max_workers=max_concurrency)
        self.queue = BoundedQueue(max_concurrency)
        self._stop = threading.Event()
        self._socket_path = None

    def method_allowed(self, method, uid):
        if uid is None or uid not in self.allowed_uids:
            return False
        if method in ROOT_ONLY:
            return uid == 0
        if method in OPERATOR:
            return True
        if method in READ_ONLY:
            return True
        return False

    def proxy(self, e):
        if e.get('method') not in ALLOWED:
            return {'schemaVersion': 3, 'requestId': e.get('requestId', 'unknown'), 'ok': False,
                    'error': {'code': 'forbiddenMethod', 'message': 'not allowed'}}
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(str(self.runtime_socket))
                s.sendall(canonical_bytes(e) + b'\n')
                d = b''
                while b'\n' not in d and len(d) <= MAX_FRAME_BYTES:
                    x = s.recv(65536)
                    if not x:
                        break
                    d += x
                return json.loads(d.split(b'\n', 1)[0])
        except Exception as x:
            return {'schemaVersion': 3, 'requestId': e.get('requestId', 'unknown'), 'ok': False,
                    'error': {'code': 'runtimeUnavailable', 'message': str(x)[:256]}}

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
                envelope = json.loads(d.split(b'\n', 1)[0])
                rid = envelope.get('requestId') or rid
                if not self.method_allowed(envelope.get('method'), creds[1] if creds else None):
                    c.sendall(canonical_bytes({'schemaVersion': 3, 'requestId': rid, 'ok': False,
                                               'error': {'code': 'forbiddenPeer',
                                                         'message': 'peer uid not allowed'}}) + b'\n')
                    return
                c.sendall(canonical_bytes(self.proxy(envelope)) + b'\n')
            finally:
                self.queue.release()
        except Exception as x:
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
                if self._stop.is_set():
                    # Shutdown raced with an accepted connection: close it
                    # rather than stranding it in a cancelled future.
                    c.close()
                    break
                if not self.queue.acquire():
                    try:
                        c.sendall(canonical_bytes({'schemaVersion': 3, 'requestId': 'unknown', 'ok': False,
                                                   'error': {'code': 'serverBusy',
                                                             'message': 'concurrency limit reached'}}) + b'\n')
                    except OSError:
                        pass
                    c.close()
                    continue
                try:
                    self.pool.submit(self.client, c)
                except Exception:
                    self.queue.release()
                    c.close()
        finally:
            s.close()
            # Drain every submitted client so no accepted connection is dropped
            # open. client() always closes its socket; never cancel_futures here
            # or a cancelled client future would strand its connection open.
            self.pool.shutdown(wait=True)
            path.unlink(missing_ok=True)
            self._socket_path = None
