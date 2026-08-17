"""Root-owned, constrained route mutation executor.

The executor is the ONLY component allowed to mutate the managed Xray routing
config on the host. It is invoked by a root-owned systemd oneshot
(rill-xray-agent-apply.service) from a fixed spool directory
(/var/spool/rill-xray-agent-apply). Every request is re-validated against the
CURRENT release manifest and CURRENT managed-config digest/generation; nothing
in the request is trusted by itself (anti-TOCTOU / anti-bypass / anti-replay).

Components:
  - RouteMutationCompiler: typed RoutePlan operations -> in-memory Xray JSON
    AST mutation. Never runs shell / sed / awk / perl; never emits arbitrary
    paths, argv or code.
  - ApplyRequest validator: bounded, digest-anchored, allowlisted request.
  - RouteExecutor: spool safety + request validation + RootTransaction
    integration (apply_fn / verify_fn) + ApplyResult / receipt.

This module never writes to the runtime state, audit, timeline or observation;
the Runtime observes outcomes through the transaction delivery file and the
audit log.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import time
from pathlib import Path

from .canonical import atomic_write_bytes, canonical_bytes, digest, file_sha256, read_json
from .errors import ContractError, TransactionError
from .root_txn import (DEFAULT_GENERATION_PATH, RootTransaction,
                       auto_outcome_id_for)
from .root_policy import DEFAULT_PROJECTION_PATH, RootExecutionPolicy, RootPolicyIntegrityError
from .route_analyzer import RECOMMENDATION_TYPES, RouteAnalyzer
from .route_planner import RoutePlanner
from .route_topology import RouteTopologyProjection
from .route_contract import (ALLOWED_OPS, INDEX_KEYS, MAX_OPERATIONS, MAX_PARAMS,
                             MAX_REQUEST_BYTES, MAX_RULES, OP_PARAM_KEYS, SAFE_CHARS,
                             SHA_RE, managed_rule_id_valid, managed_tag, overall_risk)

# Fixed production locations (overridable only for tests via env).
DEFAULT_APPLY_SPOOL_DIR = Path('/var/spool/rill-xray-agent-apply')
# P0-5: single host contract. The managed Xray config is the real
# /etc/idleleo/conf/xray/config.json (Xray_bash_onekey layout). There is no
# second live truth under a Rill-private host mirror.
DEFAULT_MANAGED_CONFIG_PATH = Path(
    os.environ.get('RILL_MANAGED_CONFIG', '/etc/idleleo/conf/xray/config.json'))
# P0-9: fixed, allowlisted service name for the live Xray convergence. Never
# derived from request content or config.
DEFAULT_XRAY_SERVICE = os.environ.get('RILL_XRAY_SERVICE', 'xray')
MANAGED_PREFIX = 'rill-managed-'
ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,128}$')

# applyType -> release feature gates that must hold in the CURRENT manifest.
APPLY_TYPE_RELEASE = {
    'manual': ('routeAssist',),
    'auto': ('routeAssist', 'boundedAuto'),
}


def _safe_string(value):
    if not isinstance(value, str) or not value:
        raise ContractError('parameter must be a non-empty string')
    if value.startswith('/'):
        raise ContractError('parameter must not be an absolute path')
    if len(value) > 4096:
        raise ContractError('parameter too long')
    if any(c not in SAFE_CHARS for c in value):
        raise ContractError('unsafe characters in parameter')
    return value


def request_digest(request):
    """Canonical SHA-256 of an ApplyRequest BODY.

    requestSha256 is self-anchoring: a field cannot be the digest of the very
    object that contains it, so it is excluded from the computation. Every
    other field participates, so any tampering breaks the anchor. This is the
    single definition shared by the producer (Runtime), the validator and the
    tests.
    """
    body = {key: value for key, value in request.items() if key != 'requestSha256'}
    return digest(body)


def validate_apply_request(request):
    """Strict, dependency-free structural validation of an ApplyRequest.

    Fails closed (ContractError) on any malformed, oversized, unknown, expired
    or digest-inconsistent field. Never mutates the host.
    """
    if not isinstance(request, dict):
        raise ContractError('apply request must be an object')
    if request.get('schemaVersion') != 2:
        raise ContractError('apply request schemaVersion != 2')
    if len(json.dumps(request)) > MAX_REQUEST_BYTES:
        raise ContractError('apply request oversized')
    rid = request.get('recommendationId')
    if not isinstance(rid, str) or not ID_RE.match(rid):
        raise ContractError('invalid recommendationId')
    now = int(time.time())
    created = request.get('createdAtEpochSeconds')
    expires = request.get('expiresAtEpochSeconds')
    if not isinstance(created, int) or not isinstance(expires, int):
        raise ContractError('apply request missing timestamps')
    if now > expires:
        raise ContractError('apply request expired')
    generation = request.get('configurationGeneration')
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
        raise ContractError('invalid configurationGeneration')
    # Root-authoritative epoch binding (§12): the request must be bound to the
    # exact execution epoch that authorizes it. The root executor re-checks
    # this value against the CURRENT root execution policy before any mutation.
    epoch = request.get('executionEpoch')
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise ContractError('invalid executionEpoch')
    # Recommendation identity (§22/§24): a fixed enum type plus the semantic
    # fingerprint used by the same-recommendation cooldown.
    rtype = request.get('recommendationType')
    if not isinstance(rtype, str) or rtype not in RECOMMENDATION_TYPES:
        raise ContractError('invalid recommendationType')
    fingerprint = request.get('semanticFingerprint')
    if not isinstance(fingerprint, str) or not ID_RE.match(fingerprint):
        raise ContractError('invalid semanticFingerprint')
    # Root policy snapshot digest (audit/binding only; the executor re-computes
    # every authorization decision and never trusts the snapshot booleans).
    policy_snapshot = request.get('policySnapshotDigest')
    if not isinstance(policy_snapshot, str) or not SHA_RE.match(policy_snapshot):
        raise ContractError('invalid policySnapshotDigest')
    for key in ('sourceConfigSha256', 'planSha256', 'requestSha256'):
        value = request.get(key)
        if not isinstance(value, str) or not SHA_RE.match(value):
            raise ContractError(f'invalid {key}')
    if request.get('applyType') not in ('manual', 'auto'):
        raise ContractError('invalid applyType')
    if request.get('mode') not in ('normal', 'observe-only', 'safe-disabled'):
        raise ContractError('invalid mode')
    if request.get('effectiveStage') not in ('observe', 'assist', 'auto', 'disabled'):
        raise ContractError('invalid effectiveStage')
    snapshot = request.get('releaseSnapshot')
    if not isinstance(snapshot, dict) or not {'routeAssist', 'boundedAuto'} <= set(snapshot):
        raise ContractError('invalid releaseSnapshot')
    for feature in ('routeAssist', 'boundedAuto'):
        entry = snapshot.get(feature)
        if (not isinstance(entry, dict)
                or not isinstance(entry.get('supported'), bool)
                or not isinstance(entry.get('released'), bool)):
            raise ContractError(f'invalid releaseSnapshot.{feature}')
    operations = request.get('operations')
    if not isinstance(operations, list) or not operations:
        raise ContractError('apply request has no operations')
    if len(operations) > MAX_OPERATIONS:
        raise ContractError('apply request has too many operations')
    for op in operations:
        _validate_operation(op)
    # Canonical digest anchor: the request body must be the exact object that
    # produced requestSha256 (the self-referential field itself is excluded;
    # see request_digest).
    if request_digest(request) != request.get('requestSha256'):
        raise ContractError('apply request digest mismatch')
    return True


def _validate_operation(op):
    if not isinstance(op, dict):
        raise ContractError('operation must be an object')
    opname = op.get('op')
    if opname not in ALLOWED_OPS:
        raise ContractError('unsupported operation')
    if op.get('managedScope') is not True:
        raise ContractError('operation must be managedScope')
    params = op.get('params')
    if not isinstance(params, dict):
        raise ContractError('operation params must be an object')
    if len(params) > MAX_PARAMS:
        raise ContractError('operation has too many params')
    unknown = set(params) - OP_PARAM_KEYS[opname]
    if unknown:
        raise ContractError('unsafe operation params')
    # P0-1: insert / replaceManaged MUST bind the root-owned stable
    # managedRuleId. The executor derives the deterministic Xray tag from it,
    # so identity between root intent and the live rule can never drift. A
    # request that omits it is rejected (no legacy hash-of-params identity).
    if opname in ('routingRule.insert', 'routingRule.replaceManaged'):
        managed_id = params.get('managedRuleId')
        if not managed_rule_id_valid(managed_id):
            raise ContractError(f'{opname} requires valid managedRuleId')
    for key, value in params.items():
        if key in INDEX_KEYS:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ContractError('index must be a non-negative integer')
        elif key == 'selectorValue':
            if isinstance(value, str):
                _safe_string(value)
            elif isinstance(value, list) and value:
                if len(value) > 64:
                    raise ContractError('selectorValue list too long')
                for item in value:
                    _safe_string(item)
            else:
                raise ContractError('selectorValue must be a string or non-empty list')
        else:
            _safe_string(value)


class RouteMutationCompiler:
    """Compile typed RoutePlan operations into an in-memory Xray JSON AST.

    Only routing.rules entries tagged with the Rill-managed prefix are ever
    mutated/removed; user-maintained rules are never touched. The output is
    canonical-safe JSON, never a shell string.
    """

    def __init__(self, config, operations, managed_prefix=MANAGED_PREFIX):
        if not isinstance(config, dict):
            raise ContractError('config must be an object')
        self.config = config
        self.operations = list(operations or [])
        self.managed_prefix = managed_prefix
        for op in self.operations:
            _validate_operation(op)
        # Fail closed at construction on a malformed managed config shape, so
        # an unusable routing tree is rejected before any mutation is compiled.
        self._rules()

    @classmethod
    def parse_text(cls, text, operations, managed_prefix=MANAGED_PREFIX):
        try:
            config = json.loads(text)
        except (ValueError, TypeError) as exc:
            raise ContractError('managed config is not valid JSON') from exc
        return cls(config, operations, managed_prefix=managed_prefix)

    def _rules(self):
        routing = self.config.get('routing')
        if not isinstance(routing, dict):
            raise ContractError('config has no routing object')
        rules = routing.get('rules')
        if not isinstance(rules, list):
            raise ContractError('config routing.rules is not a list')
        if len(rules) > MAX_RULES:
            raise ContractError('config has too many routing rules')
        return rules

    def _is_managed(self, rule):
        tag = rule.get('tag') if isinstance(rule, dict) else None
        return isinstance(tag, str) and tag.startswith(self.managed_prefix)

    def _managed_index(self, rules, index, opname):
        if not isinstance(index, int) or index < 0 or index >= len(rules):
            raise ContractError(f'{opname}: rule index out of range')
        rule = rules[index]
        if not isinstance(rule, dict) or not self._is_managed(rule):
            raise ContractError(f'{opname}: rule {index} is not Rill-managed')
        return rule

    def _managed_identity(self, rule, opname):
        """Stable managed identity of a live rule as recorded in the AST.

        P0-1: a live Rill-managed rule carries the deterministic tag derived
        from the root-owned managedRuleId. The identity check uses the tag as
        recorded on the live rule; callers compare it against the requested
        managedRuleId's deterministic tag."""
        tag = rule.get('tag') if isinstance(rule, dict) else None
        return tag if isinstance(tag, str) and tag.startswith(self.managed_prefix) else None

    def _new_tag(self, op):
        # P0-1: the tag is deterministically derived from the root-owned
        # managedRuleId ONLY, never from position / selector / generation, so
        # the identity between root intent and live rule can never drift.
        # Validation already requires managedRuleId for insert/replaceManaged;
        # this fails closed rather than falling back to a hash-of-params tag.
        params = op.get('params') if isinstance(op.get('params'), dict) else {}
        managed_id = params.get('managedRuleId')
        if not managed_rule_id_valid(managed_id):
            raise ContractError(f'{op.get("op")}: missing valid managedRuleId')
        return managed_tag(managed_id)

    def _new_rule(self, op):
        params = op['params']
        rule = {'tag': self._new_tag(op), 'type': 'field'}
        selector_type = params.get('selectorType')
        selector_value = params.get('selectorValue')
        if selector_type in ('domain', 'ip', 'port', 'network', 'protocol', 'source'):
            rule[selector_type] = selector_value
        else:
            raise ContractError(f'unsupported selectorType for insert: {selector_type}')
        outbound = params.get('outboundTag')
        if outbound:
            rule['outboundTag'] = outbound
        return rule

    def compile(self):
        """Return a deep-copied mutated config dict (no host writes)."""
        out = copy.deepcopy(self.config)
        rules = out.get('routing', {}).get('rules')
        if not isinstance(rules, list):
            raise ContractError('config has no routing.rules')
        for op in self.operations:
            opname = op['op']
            params = op['params']
            if opname == 'routingRule.insert':
                position = params.get('position', len(rules))
                # P0-8: no silent clamp. Only 0 <= position <= len(rules) is
                # valid; an out-of-range position is rejected (999999 must not
                # silently become append).
                if (not isinstance(position, int) or isinstance(position, bool)
                        or position < 0 or position > len(rules)):
                    raise ContractError('insert position out of range')
                rules.insert(position, self._new_rule(op))
            elif opname == 'routingRule.removeManaged':
                index = params['ruleIndex']
                self._managed_index(rules, index, opname)
                del rules[index]
            elif opname == 'routingRule.replaceManaged':
                index = params['ruleIndex']
                rule = self._managed_index(rules, index, opname)
                # P0-1: when the op binds a managedRuleId, verify the live rule
                # at ruleIndex actually carries that exact identity (TOCTOU /
                # index-drift protection) before mutating it.
                requested_id = params.get('managedRuleId')
                if managed_rule_id_valid(requested_id):
                    expected = managed_tag(requested_id)
                    if self._managed_identity(rule, opname) != expected:
                        raise ContractError(
                            f'replaceManaged: rule {index} identity != managedRuleId')
                selector_type = params.get('selectorType')
                selector_value = params.get('selectorValue')
                if selector_type in ('domain', 'ip', 'port', 'network', 'protocol', 'source'):
                    for key in ('domain', 'ip', 'port', 'network', 'protocol', 'source'):
                        rule.pop(key, None)
                    rule[selector_type] = selector_value
                else:
                    raise ContractError(f'unsupported selectorType for replace: {selector_type}')
                outbound = params.get('outboundTag')
                if outbound:
                    rule['outboundTag'] = outbound
            elif opname == 'routingRule.moveManaged':
                from_index = params['fromIndex']
                to_index = params['toIndex']
                rule = self._managed_index(rules, from_index, opname)
                # P0-8: no silent clamp. toIndex must be within the rule range.
                if (not isinstance(to_index, int) or isinstance(to_index, bool)
                        or to_index < 0 or to_index > len(rules)):
                    raise ContractError('move toIndex out of range')
                del rules[from_index]
                rules.insert(to_index, rule)
            else:
                raise ContractError('unsupported operation')
        return out

    def compiled_bytes(self):
        return canonical_bytes(self.compile())


class RouteExecutor:
    """Spool-safe, release-gated executor wrapping RootTransaction.

    apply() is the production path invoked by the root oneshot. Every input is
    re-checked here: spool safety, request validity, digest/generation/expiry,
    and the CURRENT release manifest gate. RootTransaction supplies
    backup/apply/verify/commit/rollback/recovery.
    """

    def __init__(self, state_root, txn_root, spool_dir=None, release_capabilities=None,
                 managed_config_path=None, xray_bin=None, allowed_producer_uids=None,
                 root_policy=None, projection_path=None, generation_file=None,
                 restart_fn=None, xray_service=None, rill_config_path=None):
        self.state_root = Path(state_root)
        self.txn_root = Path(txn_root)
        self.spool_dir = Path(spool_dir or DEFAULT_APPLY_SPOOL_DIR)
        # §P0-7: generation lives at the ROOT-owned path
        # (/var/lib/rill-xray-agent-root/generation). The Runtime reads the
        # SAME file (read-only) to observe committed generations; the
        # executor is the root-owned writer. The delivery file stays under
        # the runtime state root because it is a one-way, informational
        # delivery channel the Runtime consumes.
        self.txn = RootTransaction(self.txn_root,
                                   self.state_root / 'delivery',
                                   generation_file or DEFAULT_GENERATION_PATH,
                                   restart_fn=restart_fn)
        from .release_capabilities import ReleaseCapabilities
        self.release = release_capabilities if release_capabilities is not None \
            else ReleaseCapabilities()
        self.managed_config_path = Path(
            managed_config_path or os.environ.get('RILL_MANAGED_CONFIG',
                                                  str(DEFAULT_MANAGED_CONFIG_PATH)))
        self.xray_bin = Path(xray_bin or os.environ.get('RILL_XRAY_BIN', '/usr/local/bin/xray'))
        self.xray_service = xray_service or DEFAULT_XRAY_SERVICE
        self.allowed_producer_uids = set(allowed_producer_uids) if allowed_producer_uids is not None \
            else {0}
        # Root-authoritative execution policy (§16). The executor NEVER trusts
        # the request's mode/stage/confirmation; it re-reads epoch, mode,
        # routeStage and the auto ledger from this root-owned policy and
        # re-evaluates risk/allowlist from the live config.
        self.root_policy = root_policy if root_policy is not None else RootExecutionPolicy()
        self.projection_path = Path(projection_path or DEFAULT_PROJECTION_PATH)
        # §P0-4: root-owned Rill config path (managed route intent source).
        # Overridable only for tests via env or the constructor.
        self.rill_config_path = Path(
            rill_config_path
            or os.environ.get('RILL_XRAY_AGENT_RUNTIME_CONFIG',
                              str(self.DEFAULT_RILL_CONFIG_PATH)))

    # ---- live Xray convergence (P0-9) --------------------------------
    def _xray_test(self, path):
        """Official Xray config validation of a config file. Returns True only
        when the xray binary validates the given file cleanly."""
        import subprocess
        try:
            probe = subprocess.run(
                [str(self.xray_bin), 'run', '-test', '-config', str(path)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return probe.returncode == 0

    def restart_xray(self):
        """Live Xray convergence (P0-9 Phase B): restart + require active.
        Returns False on any failure so the caller rolls back. The service
        name is a fixed allowlist, never derived from request/config."""
        import subprocess
        for cmd in (['/bin/systemctl', 'restart', self.xray_service],
                    ['/bin/systemctl', 'is-active', '--quiet', self.xray_service]):
            try:
                probe = subprocess.run(cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                return False
            if probe.returncode != 0:
                return False
        return True

    # ---- spool safety -------------------------------------------------
    def check_spool_file(self, path):
        path = Path(path)
        try:
            st = path.lstat()
        except OSError as exc:
            raise ContractError(f'spool unreadable: {path}') from exc
        if not path.is_file() or path.is_symlink():
            raise ContractError('spool entry must be a regular non-symlink file')
        if st.st_nlink > 1:
            raise ContractError('spool entry has multiple links')
        if st.st_uid not in self.allowed_producer_uids:
            raise ContractError('spool entry owner not allowed')
        if st.st_mode & 0o022:
            raise ContractError('spool entry is group/world writable')
        if st.st_size <= 0 or st.st_size > MAX_REQUEST_BYTES:
            raise ContractError('spool entry size out of bounds')

    def check_spool_dir(self):
        path = self.spool_dir
        if not path.is_dir() or path.is_symlink():
            raise ContractError('spool dir missing or symlink')
        # In production the executor runs as root so the spool must be
        # root-owned; in tests (non-root executor) the effective user owns it.
        if path.stat().st_uid != os.geteuid():
            raise ContractError('spool dir owner not allowed')

    # ---- request lifecycle -------------------------------------------
    def _claim(self):
        """Atomically claim the pending request.

        Returns (claim_file, 'claimed') when claimed fresh, (None,
        'in_progress') when a claim is already in place (in-flight / crashed /
        done) so the caller can recover/report, or (None, 'none') when nothing
        is pending. Raises ContractError (mapped to ``rejected`` by the
        caller) on any spool anomaly: symlink, unreadable, wrong owner, unsafe
        mode or out-of-bounds size.
        """
        request_file = self.spool_dir / 'apply.json'
        claim_file = self.spool_dir / 'apply.claim'
        if claim_file.exists():
            if claim_file.is_symlink():
                raise ContractError('apply claim is a symlink')
            return None, 'in_progress'
        if not request_file.exists():
            return None, 'none'
        if not request_file.is_file() or request_file.is_symlink():
            raise ContractError('apply request is not a regular file')
        self.check_spool_file(request_file)
        try:
            os.rename(request_file, claim_file)
        except OSError as exc:
            raise ContractError('apply request already claimed') from exc
        return claim_file, 'claimed'

    def read_request(self, path):
        self.check_spool_file(path)
        try:
            request = read_json(path)
        except (ValueError, OSError) as exc:
            raise ContractError('apply request unreadable') from exc
        validate_apply_request(request)
        return request

    def _release_gate(self, request):
        blocked = []
        for feature in APPLY_TYPE_RELEASE.get(request.get('applyType'), ()):
            if not self.release.is_supported(feature):
                blocked.append('feature_not_supported')
            elif not self.release.is_released(feature):
                blocked.append('feature_not_released')
        return blocked

    def _root_gate(self, request):
        """Root-authoritative authorization gate (§12/§13/§16/§19).

        The request body is NOT the authority: mode, routeStage, confirmation,
        epoch and auto eligibility are re-read from the root-owned execution
        policy and the LIVE managed config. Any stale/corrupt/mismatched state
        fails closed. Never mutates persistent state.
        """
        blocked = []
        rp = self.root_policy
        if not rp.integrity_valid:
            blocked.append('root_policy_corrupt')
        if rp.mode() != 'normal':
            blocked.append('root_mode_not_normal')
        if request.get('executionEpoch') != rp.execution_epoch():
            blocked.append('execution_epoch_mismatch')
        apply_type = request.get('applyType')
        stage = rp.route_stage()
        if apply_type == 'manual':
            if stage not in ('assist', 'auto'):
                blocked.append('route_stage_not_assist')
        elif apply_type == 'auto':
            if stage != 'auto':
                blocked.append('route_stage_not_auto')
            # Root-side auto eligibility: the executor re-evaluates the risk
            # against the LIVE managed rules and the op allowlist itself. It
            # never trusts a request-declared risk label.
            rules = self._current_rules()
            risk = overall_risk(request.get('operations') or [], rules)
            auto_ok, auto_blocked = rp.evaluate(
                request.get('recommendationId'),
                request.get('executionEpoch'),
                risk,
                request.get('operations') or [])
            if not auto_ok:
                blocked.extend(auto_blocked)
        return blocked

    def _current_rules(self):
        """Routing rules from the LIVE managed config (for root-side risk
        re-evaluation). Returns [] on any anomaly so risk defaults high."""
        try:
            if not self.managed_config_path.is_file() or self.managed_config_path.is_symlink():
                return []
            data = read_json(self.managed_config_path)
            rules = (data or {}).get('routing', {}).get('rules')
            return rules if isinstance(rules, list) else []
        except (ValueError, OSError):
            return []

    def _global_recovery_gate(self):
        """§P0-7: global recovery gate — final authority for "may a new
        mutation start".

        Before ANY new apply the executor scans the WHOLE root transaction
        area. Any transaction in an intermediate / unverified / corrupt /
        incomplete state means the host may hold a partially-applied or
        unverified outcome; the Runtime cannot bypass this because it has no
        write access to the root transaction area. The executor (root) may
        recover first; only after the area is globally safe may a new apply
        proceed. If recovery cannot make the area safe, the new apply is
        BLOCKED (recovery_required) — never allowed on top of an unsafe host.
        """
        scan = self.txn.scan_recovery_state()
        if not any(r.get('recoveryRequired') for r in scan):
            return []
        # A crash/interrupt left an unfinished transaction: the root executor
        # is allowed to recover it. Recover is idempotent and replay-safe
        # (never re-executes a mutation).
        try:
            self.txn.recover_all()
        except Exception:
            pass
        # §P0-5: after recovery, reconcile the auto ledger against the durable
        # terminal outcomes (exactly-once per autoOutcomeId). Never blocks on
        # a policy/ledger failure here; the following rescan decides safety.
        self._reconcile_ledger()
        scan = self.txn.scan_recovery_state()
        if any(r.get('recoveryRequired') for r in scan):
            # Still unsafe after recovery (e.g. rollbackUnverified): the host
            # must be reconciled by a human/operator before any new mutation.
            return ['recovery_required']
        return []

    def _reconcile_ledger(self):
        """§P0-5: crash-safe exactly-once auto ledger reconciliation.

        Runs after recover_all() settles every interrupted transaction to a
        durable terminal state. For each auto transaction it reconciles the
        root-owned auto ledger against the DURABLE terminal outcome so the
        host outcome, the transaction outcome and the auto ledger can never
        disagree (§8.3):

          committed           -> record_apply exactly once
          rolledBack          -> record_rollback exactly once
          rollbackUnverified  -> never a false apply; the rollback is recorded
                                 so the consecutive-rollback fuse stays
                                 conservative (a real crash rollback is never
                                 silently missed)

        record_apply / record_rollback are idempotent per autoOutcomeId
        (P0-5), so replaying reconciliation (e.g. on every boot) never
        double-counts a mutation in the cooldown/rate window and never
        inflates the fuse. Non-auto transactions never touch the auto ledger.
        A work dir without a readable request or terminal state is skipped
        (recovery already classified it).
        """
        try:
            workdirs = sorted(
                p for p in self.txn_root.iterdir() if p.is_dir() and not p.is_symlink())
        except OSError:
            return
        for w in workdirs:
            try:
                request = read_json(w / 'request.json')
            except Exception:
                continue
            if not isinstance(request, dict) or request.get('applyType') != 'auto':
                continue
            try:
                state = read_json(w / 'state.json').get('state')
            except Exception:
                continue
            rid = request.get('recommendationId')
            aoi = auto_outcome_id_for(request)
            if state == 'committed':
                self.root_policy.record_apply(rid, auto_outcome_id=aoi)
            elif state in ('rolledBack', 'rollbackUnverified'):
                self.root_policy.record_rollback(auto_outcome_id=aoi)

    # P0-4: root-owned Rill config path (managed route intent source).
    # The root observer reads this same file for the topology projection.
    DEFAULT_RILL_CONFIG_PATH = Path(
        os.environ.get('RILL_XRAY_AGENT_RUNTIME_CONFIG',
                       '/etc/rill-xray-agent/config.json'))

    def _read_root_intent(self):
        """§P0-4: read the root-owned managed route intent.

        Reads the root-owned Rill config file and returns the
        'managedRouteIntent' block. Any missing / unreadable / corrupt /
        symlink path fails closed to None (never invents an intent). The
        Runtime has no write access to this path.
        """
        path = self.rill_config_path
        if path.is_symlink() or not path.is_file():
            return None
        try:
            raw = read_json(path)
        except Exception:
            return None
        if not isinstance(raw, dict):
            return None
        intent = raw.get('managedRouteIntent')
        return intent if isinstance(intent, dict) else None

    def _root_intent_proof(self, request):
        """§P0-4: Root Executor 独立证明 Auto Operation 来自 Root-owned Intent.

        When applyType=auto, the executor independently verifies that the
        requested operations exactly match what the root-owned managed route
        intent would produce. Steps:
          1. Read root-owned managed route intent
          2. Read live /etc/idleleo/conf/xray/config.json
          3. Recompute topology projection (same as root observer)
          4. Run analyzer + planner to derive expected deterministic ops
          5. Canonicalize expected ops and request ops
          6. Compare exact canonical digest
          7. Mismatch => block (auto_intent_mismatch)

        The Runtime (even if compromised) cannot construct a request whose
        operations differ from the root intent, because the root executor
        independently recomputes what the intent says and compares byte-stable
        canonical digests. A missing or unreadable intent also blocks (the
        root has no intent to authorize against).
        """
        if request.get('applyType') != 'auto':
            return []
        # 1. Read root-owned managed route intent.
        intent = self._read_root_intent()
        if intent is None:
            return ['auto_intent_unavailable']
        # 2. Read live managed config.
        try:
            if self.managed_config_path.is_symlink() or not self.managed_config_path.is_file():
                return ['auto_intent_live_config_unreadable']
            live = read_json(self.managed_config_path)
        except Exception:
            return ['auto_intent_live_config_unreadable']
        routing = (live or {}).get('routing')
        if not isinstance(routing, dict):
            return ['auto_intent_live_config_unreadable']
        # 3. Recompute topology projection (same selector-digest logic as
        #    the root observer, so the analyzer sees the same rule identities).
        generation = self.txn.generation()
        projection = RouteTopologyProjection(
            routing,
            config_generation=generation,
            whole_config_safe_digest=file_sha256(self.managed_config_path),
            captured_at_epoch_seconds=int(time.time()),
            intent=intent,
        ).project()
        # 4. Run the deterministic analyzer + planner.
        try:
            analyzer = RouteAnalyzer(projection, intent=intent)
            rec = analyzer.analyze()
        except Exception:
            return ['auto_intent_analysis_failed']
        if rec.get('recommendationType') != 'managed-route-intent-restore':
            # No restore needed -> the expected operations are empty.
            expected_ops = []
        else:
            planner = RoutePlanner(projection)
            actionable, reason, expected_ops = planner.operations_from_recommendation(rec)
            if not actionable:
                expected_ops = []
        # 5. Canonicalize both.
        # 6. Compare exact canonical digest.
        expected_digest = digest(RoutePlanner.canonicalize_operations(expected_ops))
        request_digest_val = digest(RoutePlanner.canonicalize_operations(
            request.get('operations') or []))
        if expected_digest == request_digest_val:
            return []
        return ['auto_intent_mismatch']

    def _recover_and_report(self, claim_path):
        """A claim already exists: the previous run either crashed mid-way or
        was interrupted. Recover the interrupted transaction (root executor may
        do so) and report the terminal state; never re-execute the mutation."""
        recovered = self.txn.recover_all()
        # §P0-5: reconcile the auto ledger against the durable terminal
        # outcomes so host outcome, transaction outcome and auto ledger can
        # never disagree after a crash recovery.
        self._reconcile_ledger()
        # Find a terminal outcome for the request that was being claimed.
        if not claim_path.is_file() or claim_path.is_symlink():
            return None
        try:
            request = self.read_request(claim_path)
        except ContractError:
            return None
        rid = request['recommendationId']
        w = self.txn_root / RootTransaction.work_dir_name(rid)
        bundle = w / 'commit-bundle.json'
        if bundle.is_file():
            try:
                b = read_json(bundle)
                terminal = b.get('terminalState')
                result = b.get('result') or {}
                receipt = b.get('receipt') or {}
                return {
                    'schemaVersion': 1,
                    'recommendationId': rid,
                    'status': 'committed' if terminal == 'committed' else (
                        'rollbackUnverified' if terminal == 'rollbackUnverified' else 'rolledBack'),
                    'blockedBy': [],
                    'configurationGeneration': request['configurationGeneration'],
                    'nextConfigurationGeneration': result.get('nextConfigurationGeneration'),
                    'planSha256': request['planSha256'],
                    'sourceConfigSha256': request['sourceConfigSha256'],
                    'resultSha256': result.get('resultSha256'),
                    'receiptSha256': receipt.get('resultSha256'),
                    'committedAtEpochSeconds': int(time.time()),
                }
            except Exception:
                return None
        return None

    def _quarantine(self, path, reason='rejected'):
        """Preserve an invalid / anomalous / unrecoverable spool entry (P0-11).

        A rejected or unrecoverable request must never be silently discarded
        and never be re-processed in a loop: it is moved (atomically) into the
        spool quarantine directory with a reason-stamped name so a human can
        inspect it. Returns True when quarantined."""
        try:
            qdir = self.spool_dir / 'quarantine'
            qdir.mkdir(parents=True, exist_ok=True)
            os.replace(path, qdir / f'{path.name}-{reason}-{int(time.time())}')
            return True
        except OSError:
            return False

    def apply(self, request=None):
        """Full constrained execution path (boot/crash-safe spool drain).

        P0-11 ordering: recover an interrupted claim FIRST (a crash/reboot
        left it), settle it to a terminal marker, THEN claim and process any
        pending new request. Recovery only materializes durable commit bundles
        and never re-executes a mutation (idempotent / replay-safe / no double
        apply). Rejected or unrecoverable entries are quarantined (never
        silently discarded). Returns the terminal outcome of the last request
        processed (the recovered claim when no new request is pending).
        """
        results = []

        # Phase 1 (P0-11): recover an interrupted claim first.
        claim_path = self.spool_dir / 'apply.claim'
        if claim_path.exists():
            if claim_path.is_symlink():
                self._quarantine(claim_path, reason='claim-symlink')
            else:
                recovered = self._recover_and_report(claim_path)
                if recovered is not None:
                    results.append(recovered)
                    # Terminal outcome durable -> settle the claim so a future
                    # boot does not re-report it forever.
                    self._settle_claim(claim_path)
                else:
                    # Unrecoverable claim (corrupt / unreadable): quarantine so
                    # it is preserved for inspection and never silently dropped
                    # (and never retried in a loop).
                    self._quarantine(claim_path, reason='claim-unrecoverable')
                    results.append({'schemaVersion': 1, 'status': 'blocked',
                                    'blockedBy': ['apply_in_progress'],
                                    'committedAtEpochSeconds': int(time.time())})

        # Phase 2: then the pending new request.
        try:
            claim_path, claimed = self._claim()
        except ContractError as exc:
            # Spool anomaly (symlink, wrong owner, unsafe mode, bad size...):
            # never process it, surface as rejected.
            return self._error_result(None, None, exc)
        if claimed == 'none':
            if results:
                return results[-1]
            return {'schemaVersion': 1, 'status': 'blocked',
                    'blockedBy': ['no_pending_request'],
                    'committedAtEpochSeconds': int(time.time())}
        if claimed == 'in_progress':
            # A claim appeared between Phase 1 and here (rare): recover/report
            # and settle it rather than blocking forever.
            recovered = self._recover_and_report(claim_path)
            if recovered is not None:
                results.append(recovered)
                self._settle_claim(claim_path)
                return recovered
            return {'schemaVersion': 1, 'status': 'blocked',
                    'blockedBy': ['apply_in_progress'],
                    'committedAtEpochSeconds': int(time.time())}
        request = None
        try:
            # Re-validate the claimed payload byte-for-byte.
            self.check_spool_file(claim_path)
            request = self.read_request(claim_path)
            rid = request['recommendationId']
            blocked = self._release_gate(request)
            if blocked:
                return self._blocked_result(request, blocked)
            # The Runtime must never be able to smuggle a gate through the
            # request body: mode/effectiveStage must be consistent with apply.
            if request.get('mode') != 'normal':
                return self._blocked_result(request, ['mode_not_normal'])
            if request.get('applyType') == 'auto' and request.get('effectiveStage') != 'auto':
                return self._blocked_result(request, ['effective_stage_not_auto'])
            if request.get('applyType') == 'manual' and request.get('effectiveStage') not in ('assist', 'auto'):
                return self._blocked_result(request, ['effective_stage_not_assist'])
            # Root-authoritative authorization gate (§12/§13/§16/§19). The
            # request body is never the authority: mode / routeStage /
            # executionEpoch / auto confirmation / cooldown / rate / fuse /
            # risk / op-allowlist are all re-read from the ROOT policy and the
            # LIVE managed config. Any stale or corrupt root state blocks.
            blocked = self._root_gate(request)
            if blocked:
                return self._blocked_result(request, blocked)
            # Managed config digest/generation binding against the CURRENT file.
            if not self.managed_config_path.is_file() or self.managed_config_path.is_symlink():
                return self._blocked_result(request, ['managed_config_missing'])
            current_sha = file_sha256(self.managed_config_path)
            if current_sha != request['sourceConfigSha256']:
                return self._blocked_result(request, ['config_hash_mismatch'])
            generation = self.txn.generation()
            if generation != request['configurationGeneration']:
                return self._blocked_result(request, ['generation_mismatch'])
            # §P0-7: global recovery gate — the FINAL authority before any new
            # mutation. Any unfinished / unverified / corrupt transaction
            # anywhere in the root transaction area blocks the new apply
            # (recovery_required) until the host is globally safe. The
            # unprivileged Runtime has no write access to this area, so the
            # gate cannot be bypassed by a compromised Runtime.
            blocked = self._global_recovery_gate()
            if blocked:
                return self._blocked_result(request, blocked)
            # §P0-4: Root Executor 独立证明 Auto Operation 来自 Root-owned Intent.
            # For applyType=auto the executor independently recomputes the
            # expected operations from the root-owned managed route intent and
            # compares their canonical digest with the request's operations.
            # A compromised Runtime cannot construct an allowlisted request
            # whose operations differ from the root intent.
            blocked = self._root_intent_proof(request)
            if blocked:
                return self._blocked_result(request, blocked)
            result = self._run_transaction(request, claim_path)
            results.append(result)
            return result
        except Exception as exc:
            # Rejected: preserve the claimed request for inspection instead of
            # silently discarding it (P0-11). The finally-block settlement then
            # becomes a no-op because the claim has already been moved away.
            self._quarantine(claim_path, reason='rejected')
            return self._error_result(request, claim_path, exc)
        finally:
            self._settle_claim(claim_path)

    def _run_transaction(self, request, claim_path):
        rid = request['recommendationId']
        text = self.managed_config_path.read_text()
        compiler = RouteMutationCompiler.parse_text(
            text, request['operations'])
        compiled = compiler.compile()
        committed_sha = digest(compiled)
        # §P0-6: the compiled candidate is validated by the official Xray
        # binary BEFORE the live config is ever touched. The candidate bytes
        # are the exact bytes that will be atomically written on PASS.
        candidate = canonical_bytes(compiled)

        def pre_verify_fn(candidate_path):
            # §P0-6: official `xray run -test -config candidate.json` against
            # the CANDIDATE (never the live file). Never writes the host and
            # never restarts Xray: a failed pre-test is a zero-mutation abort.
            return self._xray_test(candidate_path)

        def apply_fn():
            atomic_write_bytes(self.managed_config_path, candidate, 0o640)

        def verify_fn():
            # §P0-6 post-restart validation: the committed live file must equal
            # the compiled candidate exactly. Live validity is independently
            # proven by restart + is-active (Xray refuses to start on an
            # invalid config); the byte check anchors the file we actually
            # wrote to the candidate that was pre-validated.
            return file_sha256(self.managed_config_path) == committed_sha

        is_auto = request.get('applyType') == 'auto'
        # §P0-5: stable auto outcome id (single source: root_txn) so the
        # ledger records are exactly-once across crash recovery replays.
        aoi = auto_outcome_id_for(request)
        try:
            # P0-10: the auto ledger record is part of the transaction, not an
            # afterthought. commit_hook/rollback_hook run INSIDE RootTransaction
            # and are durable BEFORE the terminal commit, so a crash can never
            # leave "host changed but no durable ledger record" (or vice versa).
            # P0-5: the hooks carry autoOutcomeId; AutoPolicy dedups per
            # outcome id, so repeated recovery reconciliation can never
            # double-count applies/rollbacks or inflate the fuse.
            # P0-6: the candidate is pre-validated inside the transaction
            # before any live mutation; a failed pre-test aborts with zero
            # host change (candidate_pre_validation_failed).
            result = self.txn.apply(
                request, self.managed_config_path, apply_fn, verify_fn,
                commit_hook=(lambda: self.root_policy.record_apply(rid, auto_outcome_id=aoi)) if is_auto else None,
                rollback_hook=(lambda: self.root_policy.record_rollback(auto_outcome_id=aoi)) if is_auto else None,
                pre_verify_fn=pre_verify_fn,
                candidate_bytes=candidate,
            )
        except TransactionError as exc:
            # Generation mismatch / conflict / verify-fail rollback already
            # handled inside RootTransaction; surface the structured outcome.
            return self._error_result(request, claim_path, exc)
        status = result['status']
        # Refresh the safe root-policy projection so the unprivileged
        # Runtime/UI immediately sees the updated epoch / confirmation / fuse.
        self._refresh_projection()
        return {
            'schemaVersion': 1,
            'recommendationId': rid,
            'status': 'committed' if status == 'committed' else (
                'rollbackUnverified' if status == 'rollbackUnverified' else 'rolledBack'),
            'blockedBy': [],
            'configurationGeneration': request['configurationGeneration'],
            'nextConfigurationGeneration': result['result'].get('nextConfigurationGeneration'),
            'planSha256': request['planSha256'],
            'sourceConfigSha256': request['sourceConfigSha256'],
            'committedConfigSha256': committed_sha,
            'resultSha256': result['result'].get('resultSha256'),
            'receiptSha256': result['receipt'].get('resultSha256'),
            'committedAtEpochSeconds': int(time.time()),
        }

    def _refresh_projection(self):
        """Refresh the safe root-policy projection for the Runtime/UI.
        Best-effort: a projection write failure never alters the executed
        transaction outcome."""
        try:
            self.root_policy.write_projection(self.projection_path)
        except Exception:
            pass

    def _blocked_result(self, request, blocked):
        return {
            'schemaVersion': 1,
            'recommendationId': request.get('recommendationId'),
            'status': 'blocked',
            'blockedBy': blocked,
            'configurationGeneration': request.get('configurationGeneration'),
            'planSha256': request.get('planSha256'),
            'sourceConfigSha256': request.get('sourceConfigSha256'),
            'committedAtEpochSeconds': int(time.time()),
        }

    def _error_result(self, request, claim_path, exc):
        return {
            'schemaVersion': 1,
            'recommendationId': request.get('recommendationId') if isinstance(request, dict) else None,
            'status': 'rejected',
            'blockedBy': [str(exc)[:200]],
            'configurationGeneration': request.get('configurationGeneration') if isinstance(request, dict) else None,
            'planSha256': request.get('planSha256') if isinstance(request, dict) else None,
            'sourceConfigSha256': request.get('sourceConfigSha256') if isinstance(request, dict) else None,
            'committedAtEpochSeconds': int(time.time()),
        }

    def _settle_claim(self, claim_path):
        """Move the consumed claim to a done marker. Never re-executes."""
        try:
            done = self.spool_dir / 'apply.done'
            if claim_path.exists():
                os.replace(claim_path, done)
        except OSError:
            pass
