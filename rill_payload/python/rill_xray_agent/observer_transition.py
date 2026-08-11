"""Crash-safe exactly-once commit of an observer state transition.

The observer derives meaningful events from a (previous, current) observation
transition, commits them to the bounded EventJournal, then atomically replaces
the observation document. A crash *between* the journal append and the
observation replace recomputes the same events on restart and would duplicate
the real transition.

We make the commit exactly-once (no lost, no duplicate) with a tiny
host-owned safe checkpoint that records the in-flight transition by its stable
state fingerprints AND a safe projection of the pending current observation:

    pending-observation-transition.json
    {"schemaVersion":2, "previousStateDigest":..., "currentStateDigest":...,
     "eventTransitionIds":[...], "currentObservation":{...safe only...}}

Saving the safe current projection makes the pending transition *independently
recoverable*: restart no longer needs to re-observe an identical current to
finish the transition. If the host continues to change while the observer is
down (O0->O1 pending, then live moves to O2), recovery first completes the
pending O0->O1 from the checkpoint projection and only then processes the new
live O2, yielding the correct O0->O1->O2 chain instead of a bogus O0->O2.

Transition identity is stable across crash/restart because it is derived from
safe state fingerprints that exclude volatile timing fields. The checkpoint's
eventTransitionIds are a real recovery contract: they are re-derived from the
saved projection and must match exactly, otherwise recovery fails closed.

A checkpoint that exists but cannot be trusted - malformed JSON, wrong or
unsupported schema, wrong field types, invalid digests, duplicate or invalid
transition ids, a symlink, or a non-regular file - raises
ObserverTransitionError and is NEVER silently discarded (fail closed). Only a
checkpoint that truly does not exist returns None (legitimate fresh start).

Safety: only safe metadata (state digest hex strings, event transition ids,
and the already-safe observation projection) is ever persisted here. No raw
config, command output, addresses or free text.
"""
import json
import os
import re
from pathlib import Path

from .canonical import atomic_write_json, fsync_dir
from .errors import ObserverTransitionError
from .events import derive_events, observation_state_fingerprint, transition_event_id

CHECKPOINT_NAME = 'pending-observation-transition.json'
CHECKPOINT_SCHEMA_VERSION = 2

_HEX64 = re.compile(r'^[0-9a-f]{64}$')


def _valid_digest(value, allow_empty=False):
    """A SHA-256 hex digest (64 lowercase hex), or optionally the empty sentinel
    used for the baseline (previous=None) state fingerprint."""
    if not isinstance(value, str):
        return False
    if allow_empty and value == '':
        return True
    return bool(_HEX64.match(value))


def load_checkpoint(path):
    """Load and fully validate the pending transition checkpoint.

    Returns None ONLY when the checkpoint truly does not exist (legitimate
    fresh start). Any checkpoint that exists but cannot be trusted - symlink,
    non-regular file, malformed JSON, wrong/unsupported schema, missing or
    ill-typed fields, invalid digests, duplicate or malformed transition ids -
    raises ObserverTransitionError (fail closed). The observer must never
    silently discard a corrupt pending transition and re-derive, because the
    events of that transition may already be durable.
    """
    path = Path(path)
    if not os.path.lexists(path):
        return None
    if path.is_symlink():
        raise ObserverTransitionError(
            f'pending transition checkpoint is a symlink: {path}')
    if not path.is_file():
        raise ObserverTransitionError(
            f'pending transition checkpoint is not a regular file: {path}')
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        raise ObserverTransitionError(
            f'pending transition checkpoint is not valid JSON: {path}: {exc}')
    if not isinstance(data, dict):
        raise ObserverTransitionError(
            f'pending transition checkpoint is not an object: {path}')
    if data.get('schemaVersion') != CHECKPOINT_SCHEMA_VERSION:
        raise ObserverTransitionError(
            f'unsupported pending transition checkpoint schema: '
            f'{data.get("schemaVersion")!r} (expected {CHECKPOINT_SCHEMA_VERSION})')
    prev = data.get('previousStateDigest')
    current = data.get('currentStateDigest')
    ids = data.get('eventTransitionIds')
    current_obs = data.get('currentObservation')
    if not _valid_digest(prev, allow_empty=True):
        raise ObserverTransitionError(
            f'invalid previousStateDigest in checkpoint: {path}')
    if not _valid_digest(current):
        raise ObserverTransitionError(
            f'invalid currentStateDigest in checkpoint: {path}')
    if not isinstance(current_obs, dict):
        raise ObserverTransitionError(
            f'invalid currentObservation in checkpoint: {path}')
    if not isinstance(ids, list) or not ids:
        raise ObserverTransitionError(
            f'eventTransitionIds must be a non-empty list: {path}')
    if not all(_valid_digest(i) for i in ids):
        raise ObserverTransitionError(
            f'invalid eventTransitionIds in checkpoint: {path}')
    if len(set(ids)) != len(ids):
        raise ObserverTransitionError(
            f'duplicate eventTransitionIds in checkpoint: {path}')
    return {'previousStateDigest': prev, 'currentStateDigest': current,
            'eventTransitionIds': list(ids), 'currentObservation': current_obs}


def _read_observation(path):
    """Read the on-disk observation anchor, or None when absent/unreadable.

    The anchor is only consulted to place a pending transition in context; a
    malformed anchor is treated as absent (derivation then fails closed if it
    must match a checkpoint's previousStateDigest).
    """
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        return None
    try:
        data = json.loads(path.read_text())
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _write_checkpoint(path, previous_fp, current_fp, event_transition_ids,
                      current_observation) -> None:
    atomic_write_json(path, {
        'schemaVersion': CHECKPOINT_SCHEMA_VERSION,
        'previousStateDigest': previous_fp,
        'currentStateDigest': current_fp,
        'eventTransitionIds': event_transition_ids,
        'currentObservation': current_observation,
    }, mode=0o640)


def _clear_checkpoint(path) -> None:
    path = Path(path)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    fsync_dir(path.parent)


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


def recover_pending_transition(journal, observation_path, checkpoint_path,
                               fault=None):
    """Complete a pending observer transition from its durable checkpoint.

    Must run BEFORE any new live state is committed. Returns the recovered
    current observation (the pending O1) when a pending transition existed, or
    None when there was no pending transition. Recovery always uses the safe
    projection saved in the checkpoint, never the (possibly already-changed)
    live state, so a crash followed by live O1->O2 changes still yields the
    correct O0->O1->O2 chain instead of a bogus O0->O2.

    A checkpoint that exists but cannot be trusted (malformed, symlink,
    tampered ids, inconsistent projection) raises ObserverTransitionError and
    leaves the journal, observation and checkpoint untouched (fail closed).
    """
    checkpoint = load_checkpoint(checkpoint_path)
    if checkpoint is None:
        return None
    current = checkpoint['currentObservation']
    current_fp = observation_state_fingerprint(current)
    if current_fp != checkpoint['currentStateDigest']:
        raise ObserverTransitionError(
            'pending checkpoint currentObservation inconsistent with its digest')
    disk = _read_observation(observation_path)
    disk_fp = observation_state_fingerprint(disk) if disk else ''
    if disk_fp == checkpoint['currentStateDigest']:
        # Transition already fully committed (crash between the observation
        # replace and the checkpoint clear). Verify every planned event is
        # durable, then clear the checkpoint. No re-append, no new observation.
        for tid in checkpoint['eventTransitionIds']:
            if not journal.has_transition(tid):
                raise ObserverTransitionError(
                    'pending checkpoint converged but a planned event is missing')
        _clear_checkpoint(checkpoint_path)
        return disk
    # Still pending: the on-disk anchor must be the transition's previous state.
    if disk_fp != checkpoint['previousStateDigest']:
        raise ObserverTransitionError(
            'pending checkpoint previous does not match the observation anchor')
    previous = disk
    previous_fp = disk_fp
    events = derive_events(previous, current)
    ids = [transition_event_id(previous_fp, current_fp, e) for e in events]
    if ids != checkpoint['eventTransitionIds']:
        raise ObserverTransitionError(
            'pending checkpoint eventTransitionIds mismatch derived transition')
    appended = idempotent = 0
    for event, tid in zip(events, ids):
        if journal.has_transition(tid):
            idempotent += 1
            continue
        journal.append_event(_inject(event, tid))
        appended += 1
        _fault(fault, 'after-pending-event')
    _fault(fault, 'before-pending-observation')
    _write_observation(observation_path, current)
    _fault(fault, 'after-pending-observation')
    _clear_checkpoint(checkpoint_path)
    return current


def commit_transition(journal, observation_path, checkpoint_path, previous,
                      current, fault=None):
    """Commit the (previous -> current) observation transition exactly once.

    Appends the derived events to `journal`, then atomically replaces
    `observation_path` with `current`. Returns a dict with the outcome:

        appended   number of events newly committed
        idempotent number of already-committed events skipped on resume
        transition True when a meaningful transition was recorded

    Recovery ordering is enforced: if a pending checkpoint exists that does
    NOT describe this exact (previous, current) transition, the caller has
    skipped a required recovery and this raises ObserverTransitionError - the
    pending transition must be completed first (see recover_pending_transition)
    so a changed live state can never overwrite a pending O0->O1.

    `fault` is a test-only crash-injection hook (default None, never set by
    production): it raises after a defined sub-step to simulate a process
    crash, letting fault-matrix tests drive recovery through this same path.
    """
    previous_fp = observation_state_fingerprint(previous)
    current_fp = observation_state_fingerprint(current)
    events = derive_events(previous, current)
    ids = [transition_event_id(previous_fp, current_fp, e) for e in events]
    checkpoint = load_checkpoint(checkpoint_path)

    if not events:
        # No meaningful change. A leftover checkpoint is cleared only when the
        # observation already reflects the pending current (fully committed);
        # an unfinished pending transition must be recovered first.
        if checkpoint is not None:
            disk = _read_observation(observation_path)
            disk_fp = observation_state_fingerprint(disk) if disk else ''
            if disk_fp != checkpoint['currentStateDigest']:
                raise ObserverTransitionError(
                    'pending transition not converged: '
                    'recover_pending_transition must run first')
        _write_observation(observation_path, current)
        _clear_checkpoint(checkpoint_path)
        return {'appended': 0, 'idempotent': 0, 'transition': False}

    if checkpoint is not None:
        # A checkpoint exists. The SAME in-flight transition is resumed iff it
        # matches the fingerprints, the saved projection and the id plan;
        # anything else is a conflicting pending that must be recovered first.
        same = (checkpoint['previousStateDigest'] == previous_fp
                and checkpoint['currentStateDigest'] == current_fp
                and observation_state_fingerprint(checkpoint['currentObservation']) == current_fp
                and checkpoint['eventTransitionIds'] == ids)
        if not same:
            raise ObserverTransitionError(
                'conflicting pending transition: '
                'recover_pending_transition must run first')
        appended = idempotent = 0
        for event, tid in zip(events, ids):
            if journal.has_transition(tid):
                idempotent += 1
                continue
            journal.append_event(_inject(event, tid))
            appended += 1
        _fault(fault, 'before-observation-replace')
        _write_observation(observation_path, current)
        _fault(fault, 'after-observation-replace')
        _clear_checkpoint(checkpoint_path)
        return {'appended': appended, 'idempotent': idempotent, 'transition': True}

    # Fresh transition: persist the pending checkpoint FIRST, then every event,
    # then the observation anchor, then clear the checkpoint. A crash anywhere
    # in between is recovered on the next run by recover_pending_transition.
    _write_checkpoint(checkpoint_path, previous_fp, current_fp, ids, current)
    _fault(fault, 'after-checkpoint')
    appended = idempotent = 0
    for i, (event, tid) in enumerate(zip(events, ids), 1):
        journal.append_event(_inject(event, tid))
        appended += 1
        _fault(fault, f'after-event-{i}')
    _fault(fault, 'before-observation-replace')
    _write_observation(observation_path, current)
    _fault(fault, 'after-observation-replace')
    _clear_checkpoint(checkpoint_path)
    return {'appended': appended, 'idempotent': idempotent, 'transition': True}