"""Bounded Auto policy: cooldown, rate limit and consecutive-rollback fuse.

The auto policy is fully implemented but the production release gate keeps
'actual' auto-apply locked. evaluate() computes the same decision a released
auto would make (shadow), while record_apply()/record_rollback() are only ever
reached through the release-gated executor path.

The fuse is persistent: once it opens after N consecutive rollbacks it stays
open across restarts until an explicit human acknowledgment resets it. Restart
must never silently re-enable auto.

Corruption / unreadability / invalid schema / symlink / bad ownership or
permissions NEVER reset the policy to a fresh default (that would widen the
auto window). Instead the policy is marked integrity=invalid, auto is blocked,
and every state-mutating call raises AutoPolicyIntegrityError until a human
repairs the file.
"""
from __future__ import annotations

import time
from pathlib import Path

from .canonical import atomic_write_json, read_json

DEFAULT_POLICY = {
    'sameRecommendationCooldownSeconds': 1800,   # 30 min
    'globalCooldownSeconds': 300,                # 5 min
    'maxAutoMutationsPerHour': 3,
    'consecutiveRollbackFuseLimit': 2,
}

# key -> required persisted type. A file violating this is corrupt.
_STATE_SCHEMA = {
    'lastAutoAtEpochSeconds': int,
    'lastByRecommendation': dict,
    'mutationTimes': list,
    'consecutiveRollbacks': int,
    'fuseOpen': bool,
    'fuseAcknowledged': bool,
    # 'processedOutcomes' is NOT in the required schema: it is P0-5's
    # optional exactly-once set, backfilled to {} on load so a pre-P0-5
    # ledger stays valid (upgrade must preserve fuse/cooldown history).
}


def _fresh_default_state():
    """A pristine default state. Deep-built so nested containers are never
    shared between policy instances (a shared mutation list would leak state
    across restarts/instances)."""
    return {'lastAutoAtEpochSeconds': 0, 'lastByRecommendation': {},
            'mutationTimes': [], 'consecutiveRollbacks': 0, 'fuseOpen': False,
            'fuseOpenedAtEpochSeconds': None, 'fuseAcknowledged': False,
            'processedOutcomes': {}}


class AutoPolicyIntegrityError(RuntimeError):
    """Raised on any attempt to mutate a corrupt auto policy.

    Auto must stay blocked until a human repairs the policy file.
    """


class AutoPolicy:
    def __init__(self, path, config=None, now=None):
        self.path = Path(path)
        self.config = {**DEFAULT_POLICY, **(config or {})}
        self._now = now
        self._integrity_valid = True
        self._corrupt_reason = None
        self._state = self._load()

    def _clock(self):
        return int(self._now if self._now is not None else time.time())

    def _corrupt(self, reason):
        """Fail closed: keep a pristine default state (never a widened window),
        mark integrity invalid and remember why for human repair."""
        self._integrity_valid = False
        self._corrupt_reason = reason
        return _fresh_default_state()

    def _load(self):
        path = self.path
        # Security boundary: never trust a symlink or non-regular file. This
        # must be checked BEFORE exists(): a dangling symlink fails exists() but
        # is still a symlink and must never be treated as a fresh install (§15).
        if path.is_symlink():
            return self._corrupt('policy path must be a regular file, not a symlink or special file')
        # A missing file is a fresh install: pristine default, valid.
        if not path.exists():
            return _fresh_default_state()
        if not path.is_file():
            return self._corrupt('policy path must be a regular file, not a symlink or special file')
        try:
            st = path.stat()
        except OSError as exc:
            return self._corrupt('policy file unreadable: %s' % exc)
        # Group/world-writable policy widens the auto attack surface.
        if st.st_mode & 0o022:
            return self._corrupt('policy file must not be group/world writable')
        try:
            data = read_json(path)
        except (ValueError, OSError) as exc:
            return self._corrupt('policy file unparseable: %s' % exc)
        if not isinstance(data, dict):
            return self._corrupt('policy file root must be a JSON object')
        missing = [k for k in _STATE_SCHEMA if k not in data]
        if missing:
            return self._corrupt('policy file missing required keys: ' + ','.join(missing))
        for key, typ in _STATE_SCHEMA.items():
            if not isinstance(data[key], typ):
                return self._corrupt("policy key %r has wrong type %s (expected %s)"
                                     % (key, type(data[key]).__name__, typ.__name__))
        if data['fuseOpenedAtEpochSeconds'] is not None and not isinstance(data['fuseOpenedAtEpochSeconds'], int):
            return self._corrupt("policy key 'fuseOpenedAtEpochSeconds' must be an int or null")
        if not all(isinstance(t, int) for t in data['mutationTimes']):
            return self._corrupt('policy mutationTimes must contain only integers')
        if not all(isinstance(k, str) for k in data['lastByRecommendation']):
            return self._corrupt('policy lastByRecommendation keys must be strings')
        # P0-5: optional exactly-once outcome set. A pre-P0-5 ledger is
        # backfilled to {} (valid); a present-but-malformed value is corrupt.
        # Shape: {kind: {autoOutcomeId: epochSeconds}} where kind is
        # 'applied' or 'rolledBack' — the same outcome id may legitimately
        # appear in BOTH (an apply recorded, then a crash-forced rollback).
        processed = data.get('processedOutcomes')
        if processed is None:
            processed = {'applied': {}, 'rolledBack': {}}
        if not isinstance(processed, dict) \
                or not all(
                    isinstance(k, str) and isinstance(v, dict)
                    and all(isinstance(i, str) and isinstance(t, int) and not isinstance(t, bool)
                            for i, t in v.items())
                    for k, v in processed.items()):
            return self._corrupt('policy processedOutcomes must be a dict of kind -> {outcomeId: epoch}')
        data['processedOutcomes'] = processed
        return data

    @property
    def integrity_valid(self):
        return self._integrity_valid

    @property
    def corrupt_reason(self):
        return self._corrupt_reason

    def snapshot(self):
        """Read-only status for display / shadow (no secrets)."""
        s = self._state
        now = self._clock()
        last_auto = int(s['lastAutoAtEpochSeconds'])
        # A zero sentinel means "never auto-applied": there is no cooldown to
        # report rather than a cooldown measured from the epoch start.
        global_cooldown_remaining = (
            0 if last_auto == 0 else max(
                0, int(self.config['globalCooldownSeconds']) - (now - last_auto)))
        return {
            'integrity': 'valid' if self._integrity_valid else 'invalid',
            'corruptReason': self._corrupt_reason,
            'canAutoApply': self._integrity_valid,
            'fuseOpen': bool(s['fuseOpen']),
            'fuseAcknowledged': bool(s['fuseAcknowledged']),
            'fuseOpenedAtEpochSeconds': s['fuseOpenedAtEpochSeconds'],
            'consecutiveRollbacks': int(s['consecutiveRollbacks']),
            'consecutiveRollbackFuseLimit': int(self.config['consecutiveRollbackFuseLimit']),
            'autoMutationsLastHour': len([t for t in s['mutationTimes'] if now - t < 3600]),
            'maxAutoMutationsPerHour': int(self.config['maxAutoMutationsPerHour']),
            'globalCooldownRemainingSeconds': global_cooldown_remaining,
            'lastAutoAtEpochSeconds': last_auto,
        }

    def evaluate(self, recommendation_id):
        """Shadow/actual auto-eligibility decision. Returns (allowed, blocked_by).

        This is the single place auto cooldown/rate/fuse is decided. It never
        mutates state, so it is safe to call in shadow mode. A corrupt policy
        is always blocked and never widened.
        """
        if not self._integrity_valid:
            return (False, ['policy_corrupt'])
        s = self._state
        now = self._clock()
        blocked = []
        if s['fuseOpen'] and not s['fuseAcknowledged']:
            blocked.append('fusible_closed')
        last_rec = int(s['lastByRecommendation'].get(recommendation_id, 0) or 0)
        if last_rec != 0 and now - last_rec < int(self.config['sameRecommendationCooldownSeconds']):
            blocked.append('same_recommendation_cooldown')
        last_auto = int(s['lastAutoAtEpochSeconds'])
        if last_auto != 0 and now - last_auto < int(self.config['globalCooldownSeconds']):
            blocked.append('auto_global_cooldown')
        s['mutationTimes'] = [t for t in s['mutationTimes'] if now - t < 3600]
        if len(s['mutationTimes']) >= int(self.config['maxAutoMutationsPerHour']):
            blocked.append('auto_rate_limited')
        if int(s['consecutiveRollbacks']) >= int(self.config['consecutiveRollbackFuseLimit']):
            blocked.append('fusible_closed')
        return (not blocked, blocked)

    def _require_valid(self):
        if not self._integrity_valid:
            raise AutoPolicyIntegrityError(
                self._corrupt_reason or 'auto policy corrupt; human repair required')

    def record_apply(self, recommendation_id, auto_outcome_id=None):
        """Record an actual (gate-open) auto apply. Only call after a real
        mutation succeeded; never call from shadow evaluation.

        P0-5: when auto_outcome_id is given (auto applies), the record is
        exactly-once — replaying the same outcome id (e.g. during crash
        recovery reconciliation) is a no-op, so a single auto transaction is
        never double-counted in the mutation window / cooldown. The apply and
        rollback dedup sets are independent, so a crash-forced rollback of an
        already-recorded apply still records the rollback (the fuse is never
        weakened).
        """
        self._require_valid()
        processed = self._state['processedOutcomes'].setdefault('applied', {})
        if auto_outcome_id is not None and auto_outcome_id in processed:
            return
        now = self._clock()
        s = self._state
        s['lastAutoAtEpochSeconds'] = now
        s['lastByRecommendation'][recommendation_id] = now
        s['mutationTimes'] = [t for t in s['mutationTimes'] if now - t < 3600]
        s['mutationTimes'].append(now)
        # A successful apply resets the consecutive-rollback counter but never
        # clears an already-open fuse.
        if not s['fuseOpen']:
            s['consecutiveRollbacks'] = 0
        if auto_outcome_id is not None:
            processed[auto_outcome_id] = now
        self._persist()

    def record_rollback(self, auto_outcome_id=None):
        """Record an actual (gate-open) auto rollback. Opens the fuse at the
        configured consecutive limit; the fuse then requires explicit human
        acknowledgment and survives restarts.

        P0-5: when auto_outcome_id is given, the record is exactly-once —
        replaying the same rollback outcome id during crash recovery is a
        no-op, so a crash rollback is never double-counted and never inflates
        the fuse.
        """
        self._require_valid()
        processed = self._state['processedOutcomes'].setdefault('rolledBack', {})
        if auto_outcome_id is not None and auto_outcome_id in processed:
            return
        now = self._clock()
        s = self._state
        s['consecutiveRollbacks'] = int(s['consecutiveRollbacks']) + 1
        if s['consecutiveRollbacks'] >= int(self.config['consecutiveRollbackFuseLimit']):
            s['fuseOpen'] = True
            s['fuseOpenedAtEpochSeconds'] = now
            s['fuseAcknowledged'] = False
        if auto_outcome_id is not None:
            processed[auto_outcome_id] = now
        self._persist()

    def acknowledge_fuse(self, acknowledged=True):
        """Explicit human acknowledgment required to re-arm auto after a fuse.
        Restart never clears this on its own."""
        self._require_valid()
        s = self._state
        if acknowledged and s['fuseOpen']:
            s['fuseAcknowledged'] = True
            s['consecutiveRollbacks'] = 0
        elif not acknowledged:
            s['fuseAcknowledged'] = False
        self._persist()

    def _persist(self):
        atomic_write_json(self.path, self._state, 0o600)
