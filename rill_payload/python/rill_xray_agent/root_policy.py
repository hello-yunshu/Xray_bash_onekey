"""Root-owned execution policy and auto-execution ledger.

The unprivileged Runtime may write its own state root, so Runtime state can
never be the final authority for route / auto execution (§16). The root-owned
policy area holds:

  /var/lib/rill-xray-agent-root/execution-policy.json
    schemaVersion, executionEpoch, autoConfirmed, autoConfirmedAtEpochSeconds,
    mode, routeStage

  /var/lib/rill-xray-agent-root/auto-execution-ledger.json
    schemaVersion, lastAutoAtEpochSeconds, lastByRecommendation,
    mutationTimes, consecutiveRollbacks, fuseOpen, fuseOpenedAtEpochSeconds,
    fuseAcknowledged

executionEpoch is bumped on every authorization-relevant transition (§12):
mode change, routeStage change, safe-disabled, auto confirm/revoke, fuse
transition, fuse acknowledge, policy reset. Any ApplyRequest bound to an older
epoch is stale and blocked (§12/§13). The root executor re-validates the epoch
against THIS file, never against the request body.

The root executor computes confirmation / cooldown / same-recommendation
cooldown / rate / fuse itself from the ledger and independently re-evaluates
the auto risk and operation allowlist (§16/§19); it never trusts request
booleans or risk labels.

Corruption / unreadability / invalid schema / symlink / bad ownership or
permissions NEVER reset the policy to a fresh default (that would widen the
auto window): integrity=invalid, execution blocked, all mutating calls raise
RootPolicyIntegrityError until a human repairs the files.
"""
from __future__ import annotations

import time
from pathlib import Path

from .auto_policy import AutoPolicy
from .canonical import atomic_write_json, digest, read_json
from .route_contract import AUTO_MAX_RISK, AUTO_ROUTE_OPS

# Root execution policy layout (defaults, overridable only for tests).
DEFAULT_EXECUTION_POLICY_PATH = Path('/var/lib/rill-xray-agent-root/execution-policy.json')
DEFAULT_LEDGER_PATH = Path('/var/lib/rill-xray-agent-root/auto-execution-ledger.json')
DEFAULT_PROJECTION_PATH = Path('/var/lib/rill-xray-agent-xray/status/execution-policy.json')

# Fixed, allowlisted epoch-bump reasons (§12). A helper may only ever pass one
# of these; anything else is rejected at the CLI boundary.
EPOCH_BUMP_REASONS = frozenset({
    'mode-change', 'route-stage-change', 'safe-disabled', 'auto-confirm',
    'auto-revoke', 'fuse-transition', 'fuse-acknowledge', 'policy-reset',
})

MODES = frozenset({'normal', 'observe-only', 'safe-disabled'})
ROUTE_STAGES = frozenset({'observe', 'assist', 'auto', 'disabled'})

DEFAULT_EXECUTION_POLICY = {
    'schemaVersion': 1,
    'executionEpoch': 0,
    'autoConfirmed': False,
    'autoConfirmedAtEpochSeconds': None,
    'mode': 'observe-only',
    'routeStage': 'observe',
}

# key -> required persisted type. A file violating this is corrupt.
_POLICY_SCHEMA = {
    'schemaVersion': int,
    'executionEpoch': int,
    'autoConfirmed': bool,
    'autoConfirmedAtEpochSeconds': int,   # also accepts null (checked below)
    'mode': str,
    'routeStage': str,
}


class RootPolicyIntegrityError(RuntimeError):
    """Raised on any attempt to mutate a corrupt root policy / ledger.

    Route / auto execution must stay blocked until a human repairs the file.
    """


class RootExecutionPolicy:
    """Root-authoritative execution policy + auto ledger (final authority).

    The cooldown / rate / fuse engine is delegated to the tested AutoPolicy
    core pointed at the root-owned ledger file. Epoch + human confirmation +
    host mode/stage are owned here. Every mutating transition persists
    atomically and (where authorization-relevant) bumps executionEpoch.
    """

    def __init__(self, root_dir=None, policy_path=None, ledger_path=None,
                 auto_config=None, now=None):
        self.root_dir = Path(root_dir) if root_dir is not None \
            else Path('/var/lib/rill-xray-agent-root')
        self.policy_path = Path(policy_path or self.root_dir / 'execution-policy.json')
        self.ledger_path = Path(ledger_path or self.root_dir / 'auto-execution-ledger.json')
        self._now = now
        self._integrity_valid = True
        self._corrupt_reason = None
        self._policy = self._load_policy()
        # Ledger engine: same tested cooldown/rate/fuse core as the Runtime
        # shadow policy, but persisted at the ROOT-owned path.
        self.auto = AutoPolicy(self.ledger_path, config=auto_config, now=now)

    def _clock(self):
        return int(self._now if self._now is not None else time.time())

    def _corrupt(self, reason):
        """Fail closed: keep a pristine default state, mark integrity invalid
        and remember why for human repair."""
        self._integrity_valid = False
        self._corrupt_reason = reason
        return dict(DEFAULT_EXECUTION_POLICY)

    def _load_policy(self):
        path = self.policy_path
        # Security boundary: never trust a symlink or non-regular file. This
        # must be checked BEFORE exists(): a dangling symlink fails exists() but
        # is still a symlink and must never be treated as a fresh install (§15).
        if path.is_symlink():
            return self._corrupt('execution policy must be a regular file, not a symlink or special file')
        # A missing file is a fresh install: pristine default, valid.
        if not path.exists():
            return dict(DEFAULT_EXECUTION_POLICY)
        if not path.is_file():
            return self._corrupt('execution policy must be a regular file, not a symlink or special file')
        try:
            st = path.stat()
        except OSError as exc:
            return self._corrupt('execution policy unreadable: %s' % exc)
        # Group/world-writable policy widens the attack surface.
        if st.st_mode & 0o022:
            return self._corrupt('execution policy must not be group/world writable')
        try:
            data = read_json(path)
        except (ValueError, OSError) as exc:
            return self._corrupt('execution policy unparseable: %s' % exc)
        if not isinstance(data, dict):
            return self._corrupt('execution policy root must be a JSON object')
        missing = [k for k in _POLICY_SCHEMA if k not in data]
        if missing:
            return self._corrupt('execution policy missing required keys: ' + ','.join(missing))
        for key, typ in _POLICY_SCHEMA.items():
            if key == 'autoConfirmedAtEpochSeconds':
                continue
            if not isinstance(data[key], typ):
                return self._corrupt("execution policy key %r has wrong type %s (expected %s)"
                                     % (key, type(data[key]).__name__, typ.__name__))
        if data['autoConfirmedAtEpochSeconds'] is not None \
                and not isinstance(data['autoConfirmedAtEpochSeconds'], int):
            return self._corrupt("execution policy key 'autoConfirmedAtEpochSeconds' must be int or null")
        if data['schemaVersion'] != 1:
            return self._corrupt('execution policy schemaVersion != 1')
        if isinstance(data['executionEpoch'], bool) or data['executionEpoch'] < 0:
            return self._corrupt('execution policy executionEpoch invalid')
        if data['mode'] not in MODES:
            return self._corrupt('execution policy mode invalid')
        if data['routeStage'] not in ROUTE_STAGES:
            return self._corrupt('execution policy routeStage invalid')
        return data

    # ---- integrity ------------------------------------------------------
    @property
    def integrity_valid(self):
        return self._integrity_valid and self.auto.integrity_valid

    @property
    def corrupt_reason(self):
        if not self._integrity_valid:
            return self._corrupt_reason
        if not self.auto.integrity_valid:
            return 'auto ledger: ' + (self.auto.corrupt_reason or 'invalid')
        return None

    def _require_valid(self):
        if not self.integrity_valid:
            raise RootPolicyIntegrityError(
                self.corrupt_reason or 'root policy corrupt; human repair required')

    # ---- accessors ------------------------------------------------------
    def execution_epoch(self):
        return int(self._policy['executionEpoch'])

    def is_auto_confirmed(self):
        return bool(self._policy['autoConfirmed'])

    def mode(self):
        return self._policy['mode']

    def route_stage(self):
        return self._policy['routeStage']

    def _persist_policy(self):
        atomic_write_json(self.policy_path, self._policy, 0o600)

    # ---- root-side state transitions (all bump epoch where relevant) ----
    def bump_execution_epoch(self, reason):
        """Bump the root execution epoch for a fixed, allowlisted reason."""
        if reason not in EPOCH_BUMP_REASONS:
            raise RootPolicyIntegrityError('illegal epoch bump reason: %r' % (reason,))
        self._require_valid()
        self._policy['executionEpoch'] = self.execution_epoch() + 1
        self._persist_policy()

    def set_mode(self, mode):
        if mode not in MODES:
            raise RootPolicyIntegrityError('illegal mode: %r' % (mode,))
        self._require_valid()
        if self._policy['mode'] == mode:
            return False
        self._policy['mode'] = mode
        self._policy['executionEpoch'] = self.execution_epoch() + 1  # mode change
        self._persist_policy()
        return True

    def set_route_stage(self, stage):
        if stage not in ROUTE_STAGES:
            raise RootPolicyIntegrityError('illegal routeStage: %r' % (stage,))
        self._require_valid()
        if self._policy['routeStage'] == stage:
            return False
        self._policy['routeStage'] = stage
        self._policy['executionEpoch'] = self.execution_epoch() + 1  # routeStage change
        self._persist_policy()
        return True

    def safe_disable(self):
        """Operator safe-disable (§13): revoke route/auto execution and bump
        the epoch so every queued request becomes stale."""
        self._require_valid()
        changed = False
        if self._policy['mode'] != 'safe-disabled':
            self._policy['mode'] = 'safe-disabled'
            changed = True
        self._policy['autoConfirmed'] = False
        self._policy['autoConfirmedAtEpochSeconds'] = None
        self._policy['executionEpoch'] = self.execution_epoch() + 1  # safe-disabled
        self._persist_policy()
        return changed

    def set_auto_confirmed(self, confirmed):
        """Explicit human confirmation/revocation of auto intent. Either
        transition bumps the epoch so queued auto requests are invalidated."""
        self._require_valid()
        confirmed = bool(confirmed)
        now = self._clock()
        if self._policy['autoConfirmed'] == confirmed:
            return False
        self._policy['autoConfirmed'] = confirmed
        self._policy['autoConfirmedAtEpochSeconds'] = now if confirmed else None
        # auto confirm / auto revoke both bump the epoch (§12).
        self._policy['executionEpoch'] = self.execution_epoch() + 1
        self._persist_policy()
        return True

    def reset_policy(self):
        """Explicit human policy reset. Bumps the epoch (policy reset §12),
        clears confirmation and re-arms auto intent to its pristine default.
        The ledger (fuse/cooldown history) is intentionally NOT cleared here:
        the fuse is a safety record that requires explicit acknowledge_fuse.
        """
        self._require_valid()
        self._policy['executionEpoch'] = self.execution_epoch() + 1  # policy reset
        self._policy['autoConfirmed'] = False
        self._policy['autoConfirmedAtEpochSeconds'] = None
        self._persist_policy()

    # ---- auto ledger (delegated to the tested AutoPolicy core) ---------
    def record_apply(self, recommendation_id):
        """Record an actual (gate-open) auto apply. Only call after a real
        mutation committed."""
        self._require_valid()
        self.auto.record_apply(recommendation_id)

    def record_rollback(self):
        """Record an actual (gate-open) auto rollback. A fuse transition (the
        consecutive limit is reached) bumps the epoch so queued auto requests
        become stale."""
        self._require_valid()
        before = self.auto.snapshot()
        self.auto.record_rollback()
        after = self.auto.snapshot()
        if after['fuseOpen'] and not before['fuseOpen']:
            self.bump_execution_epoch('fuse-transition')

    def acknowledge_fuse(self, acknowledged=True):
        """Explicit human acknowledgment required to re-arm auto after a fuse.
        The acknowledgment transition bumps the epoch (§12)."""
        self._require_valid()
        before = self.auto.snapshot()
        self.auto.acknowledge_fuse(acknowledged)
        after = self.auto.snapshot()
        if before['fuseAcknowledged'] != after['fuseAcknowledged']:
            self.bump_execution_epoch('fuse-acknowledge')

    # ---- root-authoritative auto decision ------------------------------
    @staticmethod
    def _auto_ops_allowlisted(operations):
        if not isinstance(operations, list) or not operations:
            return False
        for op in operations:
            if not isinstance(op, dict) or op.get('op') not in AUTO_ROUTE_OPS:
                return False
        return True

    def evaluate(self, recommendation_id, requested_epoch, risk, operations):
        """Root-authoritative auto-eligibility decision.

        Recomputes EVERYTHING root-side (§16): epoch match, human
        confirmation, mode not safe-disabled, cooldown, same-recommendation
        cooldown, rate, fuse, and independently re-evaluates the auto risk and
        operation allowlist (§19). Never trusts request booleans or risk
        labels. Never mutates persistent state.
        """
        if not self.integrity_valid:
            return (False, ['policy_corrupt'])
        blocked = []
        if self._policy['mode'] == 'safe-disabled':
            blocked.append('mode_safe_disabled')
        if requested_epoch != self.execution_epoch():
            blocked.append('execution_epoch_mismatch')
        if not self._policy['autoConfirmed']:
            blocked.append('auto_requires_confirmation')
        allowed, lblocked = self.auto.evaluate(recommendation_id)
        blocked.extend(lblocked)
        # Root-side risk eligibility (§19): only AUTO_MAX_RISK is eligible.
        if risk != AUTO_MAX_RISK:
            blocked.append('auto_risk_not_eligible')
        # Root-side operation allowlist (§19): auto may only touch AUTO_ROUTE_OPS.
        if not self._auto_ops_allowlisted(operations):
            blocked.append('auto_op_not_allowlisted')
        return (not blocked, blocked)

    # ---- projection / digest -------------------------------------------
    def snapshot(self):
        """Read-only, secret-free status projection for the Runtime/UI."""
        ledger = self.auto.snapshot()
        return {
            'integrity': 'valid' if self.integrity_valid else 'invalid',
            'corruptReason': self.corrupt_reason,
            'executionEpoch': self.execution_epoch(),
            'autoConfirmed': bool(self._policy['autoConfirmed']),
            'autoConfirmedAtEpochSeconds': self._policy['autoConfirmedAtEpochSeconds'],
            'mode': self._policy['mode'],
            'routeStage': self._policy['routeStage'],
            'fuseOpen': ledger['fuseOpen'],
            'fuseAcknowledged': ledger['fuseAcknowledged'],
            'fuseOpenedAtEpochSeconds': ledger['fuseOpenedAtEpochSeconds'],
            'consecutiveRollbacks': ledger['consecutiveRollbacks'],
            'consecutiveRollbackFuseLimit': ledger['consecutiveRollbackFuseLimit'],
            'autoMutationsLastHour': ledger['autoMutationsLastHour'],
            'maxAutoMutationsPerHour': ledger['maxAutoMutationsPerHour'],
            'globalCooldownRemainingSeconds': ledger['globalCooldownRemainingSeconds'],
            'lastAutoAtEpochSeconds': ledger['lastAutoAtEpochSeconds'],
        }

    def policy_snapshot_digest(self):
        return digest(self.snapshot())

    def write_projection(self, path):
        """Write the safe projection to a root-writable / runtime-readable
        path (e.g. /var/lib/rill-xray-agent-xray/status/execution-policy.json).
        Called by the root helper and the root executor after every mutation so
        the unprivileged Runtime can bind the current epoch / confirmation /
        mode into requests and display live status. policySnapshotDigest is the
        exact digest of the embedded policy snapshot, so the Runtime can bind
        it into an ApplyRequest without re-deriving authority itself."""
        snap = self.snapshot()
        atomic_write_json(Path(path), {
            'schemaVersion': 1,
            'policySnapshotDigest': digest(snap),
            'policy': snap,
        }, 0o640)
