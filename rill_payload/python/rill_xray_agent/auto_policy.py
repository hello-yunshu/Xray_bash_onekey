"""Bounded Auto policy: cooldown, rate limit and consecutive-rollback fuse.

The auto policy is fully implemented but the production release gate keeps
'actual' auto-apply locked. evaluate() computes the same decision a released
auto would make (shadow), while record_apply()/record_rollback() are only ever
reached through the release-gated executor path.

The fuse is persistent: once it opens after N consecutive rollbacks it stays
open across restarts until an explicit human acknowledgment resets it. Restart
must never silently re-enable auto.
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

_AUTO_POLICY_KEYS = ('lastAutoAtEpochSeconds', 'lastByRecommendation',
                     'mutationTimes', 'consecutiveRollbacks', 'fuseOpen',
                     'fuseOpenedAtEpochSeconds', 'fuseAcknowledged')


class AutoPolicy:
    def __init__(self, path, config=None, now=None):
        self.path = Path(path)
        self.config = {**DEFAULT_POLICY, **(config or {})}
        self._now = now
        self._state = self._load()

    def _clock(self):
        return int(self._now if self._now is not None else time.time())

    def _load(self):
        default = {'lastAutoAtEpochSeconds': 0, 'lastByRecommendation': {},
                   'mutationTimes': [], 'consecutiveRollbacks': 0,
                   'fuseOpen': False, 'fuseOpenedAtEpochSeconds': None,
                   'fuseAcknowledged': False}
        try:
            data = read_json(self.path)
        except (ValueError, OSError):
            return default
        if not isinstance(data, dict):
            return default
        for key in _AUTO_POLICY_KEYS:
            if key not in data:
                data[key] = default[key]
        # Fail closed on malformed persisted values: a corrupt policy file must
        # never widen the auto window.
        if not isinstance(data.get('mutationTimes'), list):
            data['mutationTimes'] = []
        if not isinstance(data.get('lastByRecommendation'), dict):
            data['lastByRecommendation'] = {}
        for key in ('lastAutoAtEpochSeconds', 'consecutiveRollbacks'):
            if not isinstance(data.get(key), int):
                data[key] = 0
        for key in ('fuseOpen', 'fuseAcknowledged'):
            if not isinstance(data.get(key), bool):
                data[key] = False
        return data

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
        mutates state, so it is safe to call in shadow mode.
        """
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

    def record_apply(self, recommendation_id):
        """Record an actual (gate-open) auto apply. Only call after a real
        mutation succeeded; never call from shadow evaluation."""
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
        self._persist()

    def record_rollback(self):
        """Record an actual (gate-open) auto rollback. Opens the fuse at the
        configured consecutive limit; the fuse then requires explicit human
        acknowledgment and survives restarts."""
        now = self._clock()
        s = self._state
        s['consecutiveRollbacks'] = int(s['consecutiveRollbacks']) + 1
        if s['consecutiveRollbacks'] >= int(self.config['consecutiveRollbackFuseLimit']):
            s['fuseOpen'] = True
            s['fuseOpenedAtEpochSeconds'] = now
            s['fuseAcknowledged'] = False
        self._persist()

    def acknowledge_fuse(self, acknowledged=True):
        """Explicit human acknowledgment required to re-arm auto after a fuse.
        Restart never clears this on its own."""
        s = self._state
        if acknowledged and s['fuseOpen']:
            s['fuseAcknowledged'] = True
            s['consecutiveRollbacks'] = 0
        elif not acknowledged:
            s['fuseAcknowledged'] = False
        self._persist()

    def _persist(self):
        atomic_write_json(self.path, self._state, 0o600)
