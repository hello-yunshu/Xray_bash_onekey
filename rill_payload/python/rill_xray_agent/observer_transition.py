"""Crash-safe exactly-once commit of an observer state transition.

The observer derives meaningful events from a (previous, current) observation
transition, commits them to the bounded EventJournal, then atomically replaces
the observation document. A crash *between* the journal append and the
observation replace recomputes the same events on restart and would duplicate
the real transition.

We make the commit exactly-once (no lost, no duplicate) with a tiny
host-owned safe checkpoint that records the in-flight transition by its stable
state fingerprints:

    pending-observation-transition.json
    {"schemaVersion":1, "previousStateDigest":..., "currentStateDigest":...,
     "eventTransitionIds":[...]}

Transition identity is stable across crash/restart because it is derived from
safe state fingerprints that exclude volatile timing fields. A checkpoint whose
fingerprints match the current observation anchor proves the SAME transition is
still in flight, so already-committed events are skipped (idempotent event
commit) and only the remainder is appended. Once the observation is replaced
the checkpoint is removed, so a genuinely repeated transition later (for
example O0->O1, then O1->O0, then O0->O1 again) is recorded fresh - this is
never a global forever-dedup of an identical payload.

Safety: only safe metadata (state digest hex strings + event transition ids)
is ever persisted here. No raw config, command output, addresses or free text.
"""
import json
from pathlib import Path

from .canonical import atomic_write_json
from .events import derive_events, observation_state_fingerprint, transition_event_id

CHECKPOINT_NAME = 'pending-observation-transition.json'
CHECKPOINT_SCHEMA_VERSION = 1


def load_checkpoint(path):
    """Return the checkpoint dict, or None when absent/stale/malformed.

    A symlinked checkpoint is treated as absent (never followed): the worst
    that can happen is a duplicate event, which is a correctness issue, not a
    security boundary (the journal itself still rejects symlinked segments).
    """
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        return None
    try:
        data = json.loads(path.read_text())
    except Exception:
        return None
    if data.get('schemaVersion') != CHECKPOINT_SCHEMA_VERSION:
        return None
    prev = data.get('previousStateDigest')
    current = data.get('currentStateDigest')
    ids = data.get('eventTransitionIds')
    if not isinstance(prev, str) or not isinstance(current, str):
        return None
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        return None
    return {'previousStateDigest': prev, 'currentStateDigest': current,
            'eventTransitionIds': ids}


def _write_checkpoint(path, previous_fp, current_fp, event_transition_ids) -> None:
    atomic_write_json(path, {
        'schemaVersion': CHECKPOINT_SCHEMA_VERSION,
        'previousStateDigest': previous_fp,
        'currentStateDigest': current_fp,
        'eventTransitionIds': sorted(event_transition_ids),
    }, mode=0o640)


def _clear_checkpoint(path) -> None:
    path = Path(path)
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _write_observation(path, observation) -> None:
    atomic_write_json(path, observation, mode=0o640)


def _inject(event, transition_id):
    """Return a copy of the event carrying its transition identity."""
    copy = dict(event)
    copy['transitionId'] = transition_id
    return copy


def _fault(fault, point):
    """Test-only crash-injection hook. Never set in production."""
    if fault == point:
        raise RuntimeError(f'test-only observer crash injection at {point}')


def commit_transition(journal, observation_path, checkpoint_path, previous,
                      current, fault=None):
    """Commit the (previous -> current) observation transition exactly once.

    Appends the derived events to `journal`, then atomically replaces
    `observation_path` with `current`. Returns a dict with the outcome:

        appended   number of events newly committed
        idempotent number of already-committed events skipped on resume
        transition True when a meaningful transition was recorded

    `fault` is a test-only crash-injection hook (default None, never set by
    production): it raises after a defined sub-step to simulate a process
    crash, letting fault-matrix tests drive recovery through this same path.
    """
    previous_fp = observation_state_fingerprint(previous)
    current_fp = observation_state_fingerprint(current)
    events = derive_events(previous, current)
    ids = [transition_event_id(previous_fp, current_fp, e) for e in events]

    checkpoint = load_checkpoint(checkpoint_path)
    resume = (checkpoint is not None
              and checkpoint['previousStateDigest'] == previous_fp
              and checkpoint['currentStateDigest'] == current_fp)

    if not events:
        # No meaningful change. A stale checkpoint (e.g. crash between the
        # observation replace and the checkpoint clear) is safely discarded;
        # the observation is refreshed to the current time.
        _write_observation(observation_path, current)
        _clear_checkpoint(checkpoint_path)
        return {'appended': 0, 'idempotent': 0, 'transition': False}

    if resume:
        # The SAME transition is still in flight (crash resumed): append only
        # the events that are not already committed.
        appended = 0
        idempotent = 0
        for event, tid in zip(events, ids):
            if journal.has_transition(tid):
                idempotent += 1
                continue
            journal.append_event(_inject(event, tid))
            appended += 1
    else:
        # Fresh transition: persist the checkpoint FIRST so a crash mid-commit
        # can be resumed, then append every event unconditionally (a later,
        # genuinely repeated transition is never deduped).
        _write_checkpoint(checkpoint_path, previous_fp, current_fp, ids)
        _fault(fault, 'after-checkpoint')
        appended = 0
        idempotent = 0
        for i, (event, tid) in enumerate(zip(events, ids), 1):
            journal.append_event(_inject(event, tid))
            appended += 1
            _fault(fault, f'after-event-{i}')

    _fault(fault, 'before-observation-replace')
    _write_observation(observation_path, current)
    _fault(fault, 'after-observation-replace')
    _clear_checkpoint(checkpoint_path)
    return {'appended': appended, 'idempotent': idempotent, 'transition': True}