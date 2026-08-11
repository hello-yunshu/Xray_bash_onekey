"""Bounded, crash-safe event journal for the safe observation timeline.

Mirrors the AuditLog design philosophy (segment + total size bounds, atomic
fsync'd appends, symlink rejection, corrupt-entry detection) but with a
distinct on-disk format suitable for a *timeline* rather than an immutable
evidence chain. The journal keeps only *meaningful state-change events*:

    baseline_observed, xray_config_changed, xray_validation_failed, ...

Events are intentionally bounded: when the total size cap is reached the
oldest segments are safely rotated away (ring-buffer semantics) so the
timeline can never grow without bound.

# Journal Commit Contract

An event is *committed* only when all of the following are durable:

    1. a complete canonical JSON line was written to a segment
    2. the newline terminating that line is complete
    3. the event carries a valid deterministic eventId
    4. the segment file was fsync'd

The meta.json bookkeeping file is *not* the source of truth. Verified segments
are authoritative: on every writer recovery the journal scans every segment,
truncates any torn (newline-incomplete) tail, validates every complete line
(fail-closed), recovers the maximum sequence and reconciles meta. A reader
(Runtime) treats a torn tail as an uncommitted event and simply skips it.
"""
import json
import os
import time
from pathlib import Path

from .canonical import atomic_write_json, canonical_bytes, digest, fsync_dir
from .errors import EventJournalError
from .locking import FileLock

DEFAULT_SEGMENT_BYTES = 512 * 1024
DEFAULT_TOTAL_BYTES = 4 * 1024 * 1024

# Authoritative steady-state total bound; a single append may transiently
# exceed it by at most one event/segment before rollover trims it back.
# Rollover victims are only ever deleted AFTER the new event is committed.
MAX_TRANSIENT_OVER_BOUND_BYTES = DEFAULT_SEGMENT_BYTES


def _fsync_file(path: Path) -> None:
    with path.open('ab') as f:
        os.fsync(f.fileno())


class EventJournal:
    """Bounded append-only journal of safe state-change events.

    On-disk layout (bounded ring buffer):

        events-000001.jsonl   JSONL, one canonical event per line
        events-000002.jsonl   ...
        meta.json             {nextSequence, nextSegment}  (advisory only)

    Authoritative state is always reconstructed from the verified segments:

        scan verified segments
        -> reject symlink segments
        -> truncate torn tail (write mode) / skip it (read-only)
        -> validate every complete line (JSON, eventId, sequence)
        -> recover max sequence + newest segment
        -> compare meta
        -> reconcile (reconstruct on missing/stale/malformed;
           fail closed on meta ahead of segments or corrupt complete events)

    Appends, rollover and meta updates happen inside one single-writer critical
    section (FileLock). Rollover victims are deleted only AFTER the new event
    is fully committed, so a crash can never lose committed history.
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
        self._lock_path = self.root / '.journal.lock'

    # -- time ------------------------------------------------------------
    def _time(self) -> int:
        return int(self._now) if self._now else int(time.time())

    # -- segments --------------------------------------------------------
    def _segments(self):
        """All event segments (including symlinks, so readers can reject them)."""
        return sorted(self.root.glob('events-*.jsonl'))

    def _data_segments(self):
        return [p for p in self._segments() if not p.is_symlink()]

    @staticmethod
    def _segment_number(path: Path) -> int:
        return int(path.name[len('events-'):-len('.jsonl')])

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

    # -- meta ------------------------------------------------------------
    def _read_meta(self):
        """Return the on-disk meta dict, or None when absent/malformed.

        Symlinked meta is always rejected (fail closed). Malformed meta is
        treated as absent so the segment-directed recovery path can rebuild
        it deterministically when the segments are valid.
        """
        meta = self.root / 'meta.json'
        if not meta.is_file():
            return None
        if meta.is_symlink():
            raise EventJournalError('symlink meta rejected')
        try:
            data = json.loads(meta.read_text())
        except Exception:
            return None
        if data.get('schemaVersion') != 1:
            return None
        try:
            return {'nextSequence': int(data.get('nextSequence')),
                    'nextSegment': int(data.get('nextSegment'))}
        except (TypeError, ValueError):
            return None

    def _write_meta(self, meta) -> None:
        atomic_write_json(self.root / 'meta.json',
                          {'schemaVersion': 1, 'nextSequence': meta['nextSequence'],
                           'nextSegment': meta['nextSegment']}, mode=0o640)

    # -- recovery / reconciliation ---------------------------------------
    def _recover(self, recover_tail=True):
        """Rebuild authoritative journal state from verified segments.

        Returns a dict with:

            nextSequence   max(valid committed sequence) + 1
            nextSegment    newest segment number + 1
            events         validated events in append order (for failure report)
            metaReconciled True when this run rewrote meta.json
            truncatedTail  True when a torn tail was truncated

        Raises EventJournalError when a *complete* line is corrupt (invalid
        JSON, eventId mismatch, duplicate/non-integer sequence), when a
        symlinked segment or meta is present, or when meta is ahead of the
        durable segments (committed events would be re-issued with duplicate
        identity - fail closed instead of reusing sequences).
        """
        raw_meta = self._read_meta()
        events = []
        max_sequence = 0
        newest_segment = 0
        truncated = False
        events_seen = {}  # sequence -> (segment, line) for duplicate detection

        for seg in self._segments():
            if seg.is_symlink():
                raise EventJournalError('symlink segment rejected')
            num = self._segment_number(seg)
            newest_segment = max(newest_segment, num)
            raw = seg.read_bytes()
            if not raw:
                continue
            complete, tail = self._split_tail(raw)
            if tail is not None:
                if self.read_only or not recover_tail:
                    # Reader: the uncommitted tail is skipped, never repaired.
                    # Iterate only the verified complete lines, never the tail.
                    raw = complete
                else:
                    # Writer: truncate to the last complete newline, then make
                    # both the file and the directory durable.
                    with seg.open('r+b') as f:
                        f.truncate(len(complete))
                        os.fsync(f.fileno())
                    fsync_dir(self.root)
                    truncated = True
                    raw = complete
            for line_no, line in enumerate(raw.split(b'\n'), 1):
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except Exception as exc:
                    raise EventJournalError(
                        f'corrupt event {seg.name}:{line_no}: {exc}')
                base = {k: v for k, v in event.items() if k != 'eventId'}
                if digest(base) != event.get('eventId'):
                    raise EventJournalError(f'eventId mismatch {seg.name}:{line_no}')
                try:
                    sequence = int(event.get('sequence'))
                except (TypeError, ValueError):
                    raise EventJournalError(f'invalid sequence {seg.name}:{line_no}')
                if sequence in events_seen:
                    raise EventJournalError(
                        f'duplicate sequence {sequence} ({events_seen[sequence]} '
                        f'and {seg.name}:{line_no})')
                events_seen[sequence] = f'{seg.name}:{line_no}'
                events.append(event)
                max_sequence = max(max_sequence, sequence)

        next_sequence = max_sequence + 1
        next_segment = newest_segment + 1
        meta_reconciled = False

        if raw_meta is not None:
            if raw_meta['nextSequence'] - 1 > max_sequence:
                # meta claims committed events that no verified segment holds:
                # re-issuing those sequences would duplicate identity. Fail
                # closed rather than guessing.
                raise EventJournalError(
                    'journal meta ahead of verified segments '
                    f'(meta nextSequence={raw_meta["nextSequence"]}, '
                    f'max durable sequence={max_sequence})')
            stale = (raw_meta['nextSequence'] != next_sequence
                     or raw_meta['nextSegment'] != next_segment)
            if stale:
                meta_reconciled = True
                if not self.read_only:
                    self._write_meta({'nextSequence': next_sequence,
                                      'nextSegment': next_segment})
        elif events:
            meta_reconciled = True
            if not self.read_only:
                self._write_meta({'nextSequence': next_sequence,
                                  'nextSegment': next_segment})

        return {'nextSequence': next_sequence, 'nextSegment': next_segment,
                'events': sorted(events, key=lambda e: e.get('sequence', 0)),
                'metaReconciled': meta_reconciled,
                'truncatedTail': truncated}

    @staticmethod
    def _split_tail(raw: bytes):
        """Split segment bytes into (complete-lines-bytes, partial-tail-or-None).

        A torn write is only possible at the very end of the newest segment;
        that is exactly the position this split inspects.
        """
        if raw.endswith(b'\n'):
            return raw, None
        idx = raw.rfind(b'\n')
        if idx < 0:
            return b'', raw  # whole segment is one partial line: all uncommitted
        return raw[:idx + 1], raw[idx + 1:]

    def recover(self) -> dict:
        """Writer-facing reconciliation entry point (observer calls it once at
        startup). Read-only journals reject it: the Runtime must never write
        into the host-owned observation tree."""
        if self.read_only:
            raise EventJournalError('journal is read-only')
        with FileLock(self._lock_path):
            return self._recover()

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
        with FileLock(self._lock_path):
            state = self._recover()
            event = dict(event)
            event['sequence'] = state['nextSequence']
            event.setdefault('capturedAtEpochSeconds', self._time())
            # eventId covers the event payload excluding eventId itself, so the
            # identity is stable regardless of when/where the field is added.
            base = {k: v for k, v in event.items() if k != 'eventId'}
            event['eventId'] = event.get('eventId') or digest(base)
            line = canonical_bytes(event) + b'\n'
            if len(line) > self.segment_bytes:
                raise EventJournalError('event larger than segment bound')
            seg_num = state['nextSegment']
            seg = self.root / f'events-{seg_num:06d}.jsonl'
            if seg.exists() and seg.stat().st_size + len(line) > self.segment_bytes:
                seg_num += 1
                seg = self.root / f'events-{seg_num:06d}.jsonl'
            self._reject_symlink(seg)
            # 1) commit the new event first (file + directory fsync).
            with seg.open('ab') as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            fsync_dir(self.root)
            # 2) only now delete rollover victims (oldest first, never the
            #    just-written segment) so a crash mid-rollover cannot lose
            #    committed history. A single overshoot segment is a tolerated
            #    transient; the steady-state bound is restored here.
            while self._total_size() > self.total_bytes:
                segs = self._data_segments()
                if len(segs) <= 1:
                    break
                segs[0].unlink()
                fsync_dir(self.root)
            # 3) update advisory meta last.
            self._write_meta({'nextSequence': state['nextSequence'] + 1,
                              'nextSegment': seg_num})
            return event

    # -- read -------------------------------------------------------------
    def read(self, limit=None, after_sequence=None):
        """Return events in deterministic append order (oldest first).

        `limit` caps how many are returned (most recent `limit` when reading
        backwards). A trailing uncommitted line (torn tail) is skipped, never
        reported as history. Any other corrupt line (complete invalid JSON,
        eventId mismatch, duplicate sequence) raises EventJournalError so the
        caller can treat history as insufficient evidence.
        """
        events = self._recover(recover_tail=False)['events']
        if after_sequence is not None:
            events = [e for e in events if e.get('sequence', 0) > after_sequence]
        if limit is not None:
            events = events[-int(limit):]
        return events

    def verify(self):
        state = self._recover(recover_tail=False)
        events = state['events']
        seq = 0
        for e in events:
            if e.get('sequence', 0) <= seq:
                raise EventJournalError('sequence not monotonic')
            seq = e.get('sequence', 0)
        return {'events': len(events), 'segments': len(self._segments()),
                'totalBytes': self._total_size()}