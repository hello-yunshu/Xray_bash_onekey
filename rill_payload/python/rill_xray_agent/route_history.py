"""Bounded, secret-free route history store.

Records shadow plans, approval/rejection decisions and auto status snapshots.
Every entry is built by the Runtime from safe metadata only (see
payload_policy.sanitize_route_plan_meta); this module additionally enforces a
strict scalar allowlist so a bug upstream can never persist raw config,
selector values or secrets. The file is a single JSONL journal with an entry
cap; oldest entries are pruned once the cap is exceeded.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from .canonical import atomic_write_bytes

MAX_HISTORY_ENTRIES = 2000
MAX_ENTRY_BYTES = 4096
# Scalar, non-sensitive fields only. Anything else is dropped before persist.
_ALLOWED_FIELDS = {
    'id', 'eventType', 'createdAtEpochSeconds', 'expiresAtEpochSeconds',
    'recommendationId', 'planSha256', 'sourceConfigSha256',
    'configurationGeneration', 'risk', 'reasonCode',
    'operationCount', 'operationKinds', 'operationsDigest',
    'effectiveStage', 'wouldApply', 'wouldReject', 'applied',
    'blockedBy', 'rejectReasonCode', 'mode', 'releaseReleased',
    'requestSha256', 'schemaVersion',
}
_BOOL_FIELDS = {'wouldApply', 'wouldReject', 'applied', 'releaseReleased'}
_INT_FIELDS = {'createdAtEpochSeconds', 'expiresAtEpochSeconds', 'configurationGeneration', 'operationCount', 'schemaVersion'}
_LIST_FIELDS = {'operationKinds', 'blockedBy'}
_EVENT_TYPES = {'plan', 'approve', 'reject', 'auto-status'}
_FORBIDDEN_TOKENS = ('vless://', 'vmess://', 'trojan://', 'ssh://',
                     'privatekey', 'publickey', 'shortid', '-----begin ')


def _has_forbidden(value):
    lowered = value.lower()
    return any(token in lowered for token in _FORBIDDEN_TOKENS)


class RouteHistory:
    def __init__(self, path, max_entries=MAX_HISTORY_ENTRIES):
        self.path = Path(path)
        self.max_entries = int(max_entries)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _safe_entry(entry):
        if not isinstance(entry, dict):
            raise ValueError('route history entry must be an object')
        if entry.get('eventType') not in _EVENT_TYPES:
            raise ValueError('invalid route history eventType')
        out = {}
        for key, value in entry.items():
            if key not in _ALLOWED_FIELDS:
                continue
            if key in _BOOL_FIELDS:
                if not isinstance(value, bool):
                    raise ValueError(f'route history {key} must be a boolean')
                out[key] = value
            elif key in _INT_FIELDS:
                if not isinstance(value, int) or isinstance(value, bool):
                    raise ValueError(f'route history {key} must be an integer')
                out[key] = value
            elif key in _LIST_FIELDS:
                if not isinstance(value, list) or len(value) > 64:
                    raise ValueError(f'route history {key} must be a short list')
                if not all(isinstance(x, str) and x for x in value):
                    raise ValueError(f'route history {key} must contain strings')
                if any(_has_forbidden(x) for x in value):
                    raise ValueError(f'forbidden material in route history {key}')
                out[key] = list(value)
            elif isinstance(value, str):
                if len(value) > 256:
                    raise ValueError(f'route history {key} too long')
                if _has_forbidden(value):
                    raise ValueError(f'forbidden material in route history {key}')
                out[key] = value
            else:
                raise ValueError(f'route history {key} has unsupported type')
        if 'createdAtEpochSeconds' not in out or 'id' not in out:
            raise ValueError('route history entry missing id/timestamp')
        return out

    def append(self, entry):
        safe = self._safe_entry(entry)
        data = json.dumps(safe, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':')) + '\n'
        if len(data.encode()) > MAX_ENTRY_BYTES:
            raise ValueError('route history entry oversized')
        with self._lock:
            # Append-only with O_APPEND so a crash never corrupts earlier lines.
            with self.path.open('a') as f:
                f.write(data)
                os.fsync(f.fileno())
            self._prune_locked()
        return safe

    def _prune_locked(self):
        lines = self.path.read_text().splitlines()
        if len(lines) <= self.max_entries:
            return
        kept = lines[-self.max_entries:]
        tmp = self.path.with_suffix('.jsonl.tmp')
        atomic_write_bytes(tmp, ('\n'.join(kept) + '\n').encode(), 0o600)
        os.replace(tmp, self.path)

    def read(self, limit=100):
        with self._lock:
            if not self.path.is_file():
                return []
            lines = self.path.read_text().splitlines()
        out = []
        for line in lines[-int(limit):]:
            try:
                out.append(json.loads(line))
            except (ValueError, TypeError):
                continue
        return out

    def get(self, entry_id):
        if not isinstance(entry_id, str) or not entry_id or len(entry_id) > 128:
            return None
        with self._lock:
            if not self.path.is_file():
                return None
            for line in reversed(self.path.read_text().splitlines()):
                try:
                    entry = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if entry.get('id') == entry_id:
                    return entry
        return None
