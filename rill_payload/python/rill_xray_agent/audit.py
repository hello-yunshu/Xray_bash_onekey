import json, os, time
from pathlib import Path
from .canonical import atomic_write_json, canonical_bytes, digest, read_json, fsync_dir
from .errors import AuditError
from .locking import FileLock
GENESIS = '0' * 64
SENSITIVE = ('privatekey', 'password', 'token', 'secret', 'uuid', 'shortid', 'credential', 'authorization', 'vless://')


def redact(v, key=''):
    if any(x in key.lower() for x in SENSITIVE):
        return '<redacted>'
    if isinstance(v, dict):
        return {k: redact(x, k) for k, x in v.items()}
    if isinstance(v, list):
        return [redact(x, key) for x in v]
    if isinstance(v, str) and any(x in v.lower() for x in SENSITIVE):
        return '<redacted>'
    return v


def _fsync_file(path):
    with path.open('ab') as f:
        os.fsync(f.fileno())


class AuditLog:
    def __init__(self, root, segment_bytes=1048576, total_bytes=8388608):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.segment_bytes = segment_bytes
        self.total_bytes = total_bytes
        self.head = self.root / 'head.json'
        self.intent = self.root / 'append-intent.json'
        self.lock = self.root / '.lock'

    def segments(self):
        return sorted(self.root.glob('events-*.jsonl'))

    def verify(self):
        prev = GENESIS
        seq = 0
        for p in self.segments():
            if p.is_symlink():
                raise AuditError('symlink segment')
            for line in p.read_text().splitlines():
                e = json.loads(line)
                sup = e.pop('eventHash')
                if e.get('sequence') != seq + 1 or e.get('previousEventHash') != prev or digest(e) != sup:
                    raise AuditError(f'chain invalid {seq + 1}')
                seq += 1
                prev = sup
        if self.head.exists() and read_json(self.head) != {'schemaVersion': 1, 'sequence': seq, 'headHash': prev}:
            raise AuditError('head mismatch')
        if seq and not self.head.exists():
            raise AuditError('head missing')
        return {'events': seq, 'headHash': prev}

    def _achain_head(self):
        return self.reconcile() if self.intent.exists() else (self.verify() if self.head.exists() else {'events': 0, 'headHash': GENESIS})

    def reconcile(self):
        if not self.intent.exists():
            return self.verify()
        i = read_json(self.intent)
        e = i['event']
        if not self.contains(e['eventHash']):
            self._append_segment(e)
        atomic_write_json(self.head, {'schemaVersion': 1, 'sequence': e['sequence'], 'headHash': e['eventHash']})
        self.intent.unlink(missing_ok=True)
        fsync_dir(self.root)
        return self.verify()

    def _append_segment(self, e):
        segs = self.segments()
        seg = segs[-1] if segs else self.root / 'events-000001.jsonl'
        line_len = len(canonical_bytes(e)) + 1
        if seg.exists() and seg.stat().st_size + line_len > self.segment_bytes:
            seg = self.root / f'events-{len(segs) + 1:06d}.jsonl'
        if sum(p.stat().st_size for p in segs) + line_len > self.total_bytes:
            raise AuditError('audit capacity exhausted')
        self._write_line(seg, e)

    def contains(self, event_hash):
        try:
            for p in self.segments():
                if p.is_symlink():
                    continue
                for line in p.read_text().splitlines():
                    if json.loads(line).get('eventHash') == event_hash:
                        return True
        except Exception:
            return False
        return False

    def build_event(self, event_type, actor_type='system', actor_id='runtime', details=None, now=None):
        st = self._achain_head()
        e = {'schemaVersion': 1, 'sequence': st['events'] + 1, 'eventType': event_type,
             'timestampEpochSeconds': int(now or time.time()), 'actorType': actor_type, 'actorId': actor_id,
             'details': redact(details or {}), 'previousEventHash': st['headHash']}
        e['eventHash'] = digest(e)
        return e

    def reserve(self, event_type, actor_type='system', actor_id='runtime', details=None, now=None, event=None):
        with FileLock(self.lock):
            e = event or self.build_event(event_type, actor_type, actor_id, details, now)
            line_len = len(canonical_bytes(e)) + 1
            if sum(p.stat().st_size for p in self.segments()) + line_len > self.total_bytes:
                raise AuditError('audit capacity exhausted')
            self.intent.write_bytes(canonical_bytes({'schemaVersion': 1, 'event': e}) + b'\n')
            _fsync_file(self.intent)
            fsync_dir(self.root)
            return e

    def dismiss_pending(self, event_hash=None):
        if not self.intent.exists():
            return False
        if event_hash is not None:
            i = read_json(self.intent)
            if i.get('event', {}).get('eventHash') != event_hash:
                return False
        self.intent.unlink(missing_ok=True)
        fsync_dir(self.root)
        return True

    def commit_event(self, e):
        with FileLock(self.lock):
            if os.environ.get('RILL_AUDIT_IO_ERROR') == '1':
                raise AuditError('fault injected: RILL_AUDIT_IO_ERROR')
            if self.intent.exists():
                i = read_json(self.intent)
                if i['event']['eventHash'] != e['eventHash']:
                    self.intent.unlink(missing_ok=True)
                    fsync_dir(self.root)
            if not self.contains(e['eventHash']):
                self._append_segment(e)
            if os.environ.get('RILL_AUDIT_FAIL_AFTER_EVENT') == '1':
                raise AuditError('fault injected: RILL_AUDIT_FAIL_AFTER_EVENT')
            atomic_write_json(self.head, {'schemaVersion': 1, 'sequence': e['sequence'], 'headHash': e['eventHash']})
            self.intent.unlink(missing_ok=True)
            fsync_dir(self.root)
            return e

    def _write_line(self, seg, e):
        line = canonical_bytes(e) + b'\n'
        with seg.open('ab') as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        fsync_dir(seg.parent)

    def append(self, event_type, actor_type='system', actor_id='runtime', details=None, now=None):
        return self.commit_event(self.reserve(event_type, actor_type, actor_id, details, now))