import hashlib, json, os, time, uuid
from pathlib import Path
from .audit import AuditLog
from .canonical import atomic_write_json, canonical_bytes, digest, file_sha256, fsync_dir, read_json
from .errors import OperationError
from .locking import FileLock

FAULT_INTENT = 'RILL_OP_FAIL_AFTER_OPERATION_INTENT'
FAULT_STATE = 'RILL_OP_FAIL_AFTER_STATE_COMMIT'
FAULT_AUDIT = 'RILL_OP_FAIL_AFTER_AUDIT_EVENT'
FAULT_TERMINAL = 'RILL_OP_FAIL_AFTER_OPERATION_TERMINAL'


def _fault(name):
    if os.environ.get(name) == '1':
        raise OperationError(f'fault injected: {name}')


def _fsync_file(path):
    with path.open('ab') as f:
        os.fsync(f.fileno())


class OperationLog:
    def __init__(self, root, audit=None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.audit = audit
        self.lock = self.root / '.lock'

    def intents(self):
        return sorted(self.root.glob('op-*.intent.json'))

    def terminal_path(self, op_id):
        return self.root / f'op-{op_id}.terminal.json'

    def execute(self, kind, state_path, state_fn, event_type, event_details=None,
                actor_type='system', actor_id='runtime', now=None):
        with FileLock(self.lock):
            op_id = uuid.uuid4().hex
            state_path = Path(state_path)
            pre_sha = self._state_sha(state_path)
            result, post_state = state_fn(self._load_state(state_path))
            if isinstance(result, dict) and result.get('status') == 'idempotent':
                return {'operationId': None, 'result': result, 'auditEventHash': None}
            post_sha = self._dict_sha(post_state)
            event = None
            if self.audit:
                event = self.audit.build_event(event_type, actor_type, actor_id, event_details, now)
                self.audit.reserve(event_type, actor_type, actor_id, event_details, now, event=event)
            intent = {
                'schemaVersion': 1,
                'operationId': op_id,
                'kind': kind,
                'createdAtEpochSeconds': int(now or time.time()),
                'statePath': state_path.as_posix(),
                'preStateSha256': pre_sha,
                'postStateSha256': post_sha,
                'postState': post_state,
                'auditEvent': event,
                'actorType': actor_type,
                'actorId': actor_id,
            }
            atomic_write_json(self.root / f'op-{op_id}.intent.json', intent)
            fsync_dir(self.root)
            _fault(FAULT_INTENT)
            atomic_write_json(state_path, post_state)
            fsync_dir(state_path.parent)
            _fault(FAULT_STATE)
            if self.audit:
                self.audit.commit_event(event)
                _fault(FAULT_AUDIT)
            atomic_write_json(self.terminal_path(op_id), {'schemaVersion': 1, 'operationId': op_id, 'kind': kind,
                                                          'completedAtEpochSeconds': int(now or time.time())})
            fsync_dir(self.root)
            _fault(FAULT_TERMINAL)
            self._cleanup(op_id)
            return {'operationId': op_id, 'result': result, 'auditEventHash': event['eventHash'] if event else None}

    def _cleanup(self, op_id):
        (self.root / f'op-{op_id}.intent.json').unlink(missing_ok=True)

    def _state_sha(self, state_path):
        if not state_path.exists():
            return digest(None)
        return file_sha256(state_path)

    @staticmethod
    def _dict_sha(state):
        return hashlib.sha256(canonical_bytes(state) + b'\n').hexdigest()

    def _load_state(self, state_path):
        if not state_path.exists():
            return None
        return read_json(state_path)

    def recover(self):
        report = {'recovered': [], 'cancelled': [], 'unresolved': []}
        for intent_path in self.intents():
            try:
                self._recover_one(intent_path, report)
            except Exception as exc:
                report['unresolved'].append({'operationId': intent_path.stem, 'reason': str(exc)[:256]})
        return report

    def _recover_one(self, intent_path, report):
        intent = read_json(intent_path)
        op_id = intent['operationId']
        state_path = Path(intent['statePath'])
        pre_sha = intent['preStateSha256']
        post_sha = intent['postStateSha256']
        actual = self._state_sha(state_path)
        event = intent.get('auditEvent')
        audit_written = bool(event and self.audit and self.audit.contains(event['eventHash']))
        terminal = self.terminal_path(op_id).exists()
        if terminal:
            self._cleanup(op_id)
            report['recovered'].append(op_id)
            return
        if actual == post_sha:
            if audit_written:
                atomic_write_json(self.terminal_path(op_id), {'schemaVersion': 1, 'operationId': op_id,
                                                              'kind': intent['kind'], 'completedAtEpochSeconds': int(time.time())})
                self._cleanup(op_id)
                report['recovered'].append(op_id)
            else:
                if self.audit:
                    self.audit.commit_event(event)
                atomic_write_json(self.terminal_path(op_id), {'schemaVersion': 1, 'operationId': op_id,
                                                              'kind': intent['kind'], 'completedAtEpochSeconds': int(time.time())})
                self._cleanup(op_id)
                report['recovered'].append(op_id)
            return
        if actual == pre_sha:
            if audit_written:
                atomic_write_json(state_path, intent['postState'])
                atomic_write_json(self.terminal_path(op_id), {'schemaVersion': 1, 'operationId': op_id,
                                                              'kind': intent['kind'], 'completedAtEpochSeconds': int(time.time())})
                self._cleanup(op_id)
                report['recovered'].append(op_id)
            else:
                if self.audit:
                    self.audit.dismiss_pending(event['eventHash'] if event else None)
                self._cleanup(op_id)
                report['cancelled'].append(op_id)
            return
        report['unresolved'].append({'operationId': op_id, 'reason': 'state hash undeterminable'})

    def pending_count(self):
        return len(self.intents())

    def health(self):
        if self.intents():
            return 'recovery-required'
        return 'ready'