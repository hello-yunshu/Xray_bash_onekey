"""Bounded, crash-safe event journal for the safe observation timeline.

Mirrors the AuditLog design philosophy (segment + total size bounds, atomic
fsync'd appends, symlink rejection, corrupt-entry detection) but with a
distinct on-disk format suitable for a *timeline* rather than an immutable
evidence chain. The journal keeps only *meaningful state-change events*:

    baseline_observed, xray_config_changed, xray_validation_failed, ...

Events are intentionally bounded: when the total size cap is reached the
oldest segments are safely rotated away (ring-buffer semantics) so the
timeline can never grow without bound. Writes are atomic per event and
fsync'd before returning; readers reject symlinked or corrupt segments.
"""
import json
import os
import time
from pathlib import Path

from .canonical import canonical_bytes, digest, fsync_dir
from .errors import EventJournalError

DEFAULT_SEGMENT_BYTES = 512 * 1024
DEFAULT_TOTAL_BYTES = 4 * 1024 * 1024


def _fsync_file(path: Path) -> None:
    with path.open('ab') as f:
        os.fsync(f.fileno())


class EventJournal:
    """Bounded append-only journal of safe state-change events.

    On-disk layout (bounded ring buffer):

        events-000001.jsonl   JSONL, one canonical event per line
        events-000002.jsonl   ...
        meta.json             {nextSequence, nextSegment}

    Capacity is enforced by total_bytes; when an append would exceed it the
    oldest segment(s) are removed first (safe rollover). Appends are atomic
    (single line, fsync'd). Symlinked segments are always rejected.
    """

    def __init__(self, root, segment_bytes=DEFAULT_SEGMENT_BYTES,
                 total_bytes=DEFAULT_TOTAL_BYTES, now=None, read_only=False):
        self.root = Path(root)
        if not read_only:
            self.root.mkdir(parents=True, exist_ok=True)
        self.segment_bytes = int(segment_bytes)
        self.total_bytes = int(total_bytes)
        self._now = now
        self.read_only = read_only

    # -- time ------------------------------------------------------------
    def _time(self) -> int:
        return int(self._now) if self._now else int(time.time())

    # -- segments --------------------------------------------------------
    def _segments(self):
        """All event segments (including symlinks, so readers can reject them)."""
        return sorted(self.root.glob('events-*.jsonl'))

    def _data_segments(self):
        return [p for p in self._segments() if not p.is_symlink()]

    def _reject_symlink(self, path: Path) -> None:
        if path.is_symlink():
            raise EventJournalError('symlink segment rejected')

    def _total_size(self) -> int:
        total = 0
        for p in self._data_segments():
            try:
                total += p.stat().st_size
            except OSError:
                pass
        return total

    def _meta(self):
        meta = self.root / 'meta.json'
        if not meta.is_file():
            return {'nextSequence': 1, 'nextSegment': 1}
        if meta.is_symlink():
            raise EventJournalError('symlink meta rejected')
        try:
            data = json.loads(meta.read_text())
        except Exception as exc:
            raise EventJournalError(f'corrupt journal meta: {exc}')
        return {'nextSequence': int(data.get('nextSequence', 1)),
                'nextSegment': int(data.get('nextSegment', 1))}

    def _write_meta(self, meta) -> None:
        from .canonical import atomic_write_json
        atomic_write_json(self.root / 'meta.json',
                          {'schemaVersion': 1, 'nextSequence': meta['nextSequence'],
                           'nextSegment': meta['nextSegment']}, mode=0o640)

    # -- capacity / rollover ---------------------------------------------
    def _make_room(self, line_len: int) -> None:
        """Safely drop the oldest segments until an append fits (ring buffer).

        Never deletes generic files; only events-*.jsonl segments are ever
        considered. A single oversized event still fails closed rather than
        silently splitting across segments.
        """
        if line_len > self.segment_bytes:
            raise EventJournalError('event larger than segment bound')
        while self._total_size() + line_len > self.total_bytes:
            segs = self._data_segments()
            if not segs:
                return
            oldest = segs[0]
            try:
                oldest.unlink()
            except OSError as exc:
                raise EventJournalError(f'rollover failed: {exc}')
            fsync_dir(self.root)

    # -- append ----------------------------------------------------------
    def append_event(self, event) -> dict:
        if self.read_only:
            raise EventJournalError('journal is read-only')
        if not isinstance(event, dict):
            raise EventJournalError('event must be an object')
        if event.get('schemaVersion') != 1:
            raise EventJournalError('unsupported event schema')
        event_type = event.get('eventType')
        if not event_type or not isinstance(event_type, str):
            raise EventJournalError('eventType required')
        meta = self._meta()
        event = dict(event)
        event.setdefault('sequence', meta['nextSequence'])
        event.setdefault('capturedAtEpochSeconds', self._time())
        # eventId covers the event payload excluding eventId itself, so the
        # identity is stable regardless of when/where the field is added.
        base = {k: v for k, v in event.items() if k != 'eventId'}
        event['eventId'] = event.get('eventId') or digest(base)
        line = canonical_bytes(event) + b'\n'
        self._make_room(len(line))
        seg_num = meta['nextSegment']
        seg = self.root / f'events-{seg_num:06d}.jsonl'
        if seg.exists() and seg.stat().st_size + len(line) > self.segment_bytes:
            seg_num += 1
            seg = self.root / f'events-{seg_num:06d}.jsonl'
        self._reject_symlink(seg)
        with seg.open('ab') as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        fsync_dir(self.root)
        meta['nextSequence'] += 1
        meta['nextSegment'] = seg_num
        self._write_meta(meta)
        return event

    # -- read -------------------------------------------------------------
    def read(self, limit=None, after_sequence=None):
        """Return events in deterministic append order (oldest first).

        `limit` caps how many are returned (most recent `limit` when reading
        backwards). Corrupt segments/lines raise EventJournalError so the
        caller can treat history as insufficient evidence.
        """
        all_events = []
        for seg in self._segments():
            self._reject_symlink(seg)
            for line_no, line in enumerate(seg.read_text().splitlines(), 1):
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except Exception as exc:
                    raise EventJournalError(f'corrupt event {seg.name}:{line_no}: {exc}')
                base = {k: v for k, v in event.items() if k != 'eventId'}
                if digest(base) != event.get('eventId'):
                    raise EventJournalError(f'eventId mismatch {seg.name}:{line_no}')
                all_events.append(event)
        all_events.sort(key=lambda e: e.get('sequence', 0))
        if after_sequence is not None:
            all_events = [e for e in all_events if e.get('sequence', 0) > after_sequence]
        if limit is not None:
            all_events = all_events[-int(limit):]
        return all_events

    def verify(self):
        events = self.read()
        seq = 0
        for e in events:
            if e.get('sequence', 0) <= seq:
                raise EventJournalError('sequence not monotonic')
            seq = e.get('sequence', 0)
        return {'events': len(events), 'segments': len(self._segments()),
                'totalBytes': self._total_size()}