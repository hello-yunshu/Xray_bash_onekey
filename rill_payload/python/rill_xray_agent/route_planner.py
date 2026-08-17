import hashlib
import time
import uuid
from .canonical import canonical_bytes, digest
from .route_contract import (ALLOWED_OPS, INDEX_KEYS, OP_PARAM_KEYS, SAFE_CHARS,
                             op_risk, overall_risk)
from .route_analyzer import RECOMMENDATION_TYPES


def plan_digest(plan):
    """Canonical SHA-256 of a RoutePlan BODY.

    planSha256 is self-anchoring: a field cannot be the digest of the very
    object that contains it, so it is excluded from the computation. Every
    other field participates, so any tampering breaks the anchor. This is the
    single definition shared by the planner and consumers.
    """
    body = {key: value for key, value in plan.items() if key != 'planSha256'}
    return digest(body)


class RoutePlanner:
    """Deterministic, declarative RoutePlan builder.

    Input is restricted to a trusted safe topology projection (see
    route_topology.RouteTopologyProjection) plus the structured, already-parsed
    routing.rules dict. The planner NEVER consumes raw config text and NEVER
    produces shell/argv/executable paths: output is a typed, allowlisted,
    bounded RoutePlan that an executor compiles against the Xray JSON AST.
    """

    def __init__(self, topology, routing=None, config=None):
        self.topology = topology
        # Structured routing rules come from the trusted parse path; fall back
        # to an embedded 'routing' dict only when a caller passes the raw
        # config-shaped object (never raw text).
        self._routing = routing if isinstance(routing, dict) else (
            topology.get('routing') if isinstance(topology.get('routing'), dict)
            else ({'rules': topology.get('rules')} if isinstance(topology.get('rules'), list)
                  else {}))
        config = config or {}
        self.ttl_seconds = int(config.get('ttlSeconds', 300))
        self.configuration_generation = topology.get('configurationGeneration', 0)
        # The projection is the source of the whole-config digest. Accept the
        # v1 field name (wholeConfigSha256) with the plan-facing alias
        # (sourceConfigSha256) for schema-migration safety.
        self.source_config_sha256 = (
            topology.get('sourceConfigSha256')
            or topology.get('wholeConfigSha256') or '')

    @staticmethod
    def deterministic_id(topology, operations):
        material = canonical_bytes(
            {'topology': digest(topology), 'operations': digest(operations)})
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, hashlib.sha256(material).hexdigest()))

    def _rules(self):
        rules = self._routing.get('rules')
        return rules if isinstance(rules, list) else []

    @staticmethod
    def _safe_string(value):
        if not isinstance(value, str) or not value:
            raise ValueError('parameter must be a non-empty string')
        if value.startswith('/'):
            raise ValueError('parameter must not be an absolute path')
        if any(c not in SAFE_CHARS for c in value):
            raise ValueError('unsafe characters in parameter')
        return value

    @staticmethod
    def canonicalize_operations(operations):
        """Canonicalize (typed, allowlisted, managedScope) a list of
        operations for digest binding. Rejects any unknown op, unsafe param or
        non-managed operation. The resulting list is byte-stable so the digest
        is comparable across Runtime / CLI / executor."""
        return [RoutePlanner._canonical_operation(op) for op in (operations or [])]

    def operations_from_recommendation(self, recommendation):
        """Deterministic mapping: recommendationType -> (actionable, reason, ops).

        Only recommendation types understood by the contract produce
        operations; any situation that cannot be safely turned into a typed,
        low-risk operation is returned as advisory/manual-only
        (actionable=False with an explicit reason) instead of a fake
        "successful" plan with operations=[].

        The planner never lets the analyzer emit arbitrary operations: the
        mapping below is the only bridge, and every synthesized op is
        re-validated through the route contract. For the Bounded-Auto restore
        scenario the analyzer only records the *intent* (Rill-owned managed
        route state); the planner turns that intent into typed ops here.
        """
        if not isinstance(recommendation, dict):
            raise ValueError('recommendation must be an object')
        rtype = recommendation.get('recommendationType')
        if rtype not in RECOMMENDATION_TYPES:
            raise ValueError('unknown recommendationType')
        if rtype == 'managed-route-intent-restore':
            return self._ops_from_intent(recommendation)
        # The remaining analyzer observations cannot be turned into a safe
        # auto/manual operation without a root-authoritative intent: the
        # analyzer never invents a selector value, so these are advisory-only.
        if rtype in ('managed-rule-shadowed', 'unreachable-rule'):
            return (False, 'insufficient-safe-intent', [])
        if rtype == 'managed-rule-added':
            # A managed rule is present and healthy: status-only, nothing to do.
            return (False, 'status-only-no-action', [])
        # no-recommendation / stale-topology: nothing actionable.
        return (False, 'no-action', [])

    def _ops_from_intent(self, recommendation):
        """Deterministic typed operations for the root-authoritative managed
        route intent (§P0-2). Only LOW-RISK, AUTO_ROUTE_OPS operations are
        produced: insert a missing intent rule, or replace a drifted managed
        rule's selector/outbound to restore the Rill-owned target state. The
        intent selector values come from the Rill-owned intent (never from
        user config secrets). Returns (actionable, reason, ops)."""
        intent = recommendation.get('intent')
        if not isinstance(intent, list) or not intent:
            return (False, 'insufficient-safe-intent', [])
        ops = []
        for entry in intent:
            if not isinstance(entry, dict):
                continue
            kind = entry.get('kind')
            params = {}
            managed_id = entry.get('managedRuleId')
            if kind == 'missing':
                # Restore a missing Rill-owned managed rule by APPENDING it at
                # the end of the rule list (never before user rules): the
                # append position is LOW risk and cannot shadow earlier rules.
                # P0-1: the op carries the root-owned STABLE managedRuleId so
                # the executor derives the deterministic Xray tag from it
                # (identity between intent and live rule can never drift).
                params = {'position': len(self._rules()),
                          'selectorType': entry.get('selectorType'),
                          'selectorValue': entry.get('selectorValue'),
                          'outboundTag': entry.get('outboundTag')}
                if managed_id:
                    params['managedRuleId'] = managed_id
                op = 'routingRule.insert'
            elif kind == 'drifted':
                # P0-1: replace binds BOTH ruleIndex and managedRuleId so the
                # root executor can verify the live rule at ruleIndex actually
                # carries the requested stable identity (TOCTOU / index-drift
                # protection).
                params = {'ruleIndex': entry.get('ruleIndex'),
                          'selectorType': entry.get('selectorType'),
                          'selectorValue': entry.get('selectorValue'),
                          'outboundTag': entry.get('outboundTag')}
                if managed_id:
                    params['managedRuleId'] = managed_id
                op = 'routingRule.replaceManaged'
            else:
                continue
            params = {k: v for k, v in params.items() if v is not None}
            try:
                ops.append(self._canonical_operation({'op': op, 'params': params}))
            except ValueError:
                # Never synthesize an unsafe operation: drop it (advisory-only).
                continue
        if not ops:
            return (False, 'insufficient-safe-intent', [])
        return (True, 'managed-route-intent-restore', ops)

    @staticmethod
    def _canonical_operation(op):
        if not isinstance(op, dict):
            raise ValueError('operation must be an object')
        opname = op.get('op')
        if opname not in ALLOWED_OPS:
            raise ValueError('unsupported operation')
        params = op.get('params')
        if not isinstance(params, dict):
            raise ValueError('operation params must be an object')
        unknown = set(params) - OP_PARAM_KEYS[opname]
        if unknown:
            raise ValueError('unsafe operation params')
        clean = {}
        for key, value in params.items():
            if key in INDEX_KEYS:
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError('index must be a non-negative integer')
                clean[key] = value
            elif key == 'selectorValue':
                if isinstance(value, str):
                    clean[key] = RoutePlanner._safe_string(value)
                elif isinstance(value, list) and all(isinstance(x, str) for x in value):
                    clean[key] = [RoutePlanner._safe_string(x) for x in value]
                else:
                    raise ValueError('selectorValue must be a string or list of strings')
            else:
                clean[key] = RoutePlanner._safe_string(value)
        return {'op': opname, 'params': clean, 'managedScope': True}

    def _op_risk(self, op):
        return op_risk(op, self._rules())

    def _overall_risk(self, ops):
        return overall_risk(ops, self._rules())

    def _reason_code(self, ops):
        if not ops:
            return 'no-operations'
        kinds = sorted({o['op'] for o in ops})
        return 'managed-route-plan:' + ','.join(kinds)

    def _preconditions(self, ops):
        conds = ['source-config-sha256-unchanged']
        referenced = []
        for o in ops:
            p = o['params']
            if o['op'] == 'routingRule.insert':
                conds.append('insert-position-within-rule-range')
            elif o['op'] == 'routingRule.removeManaged':
                referenced.append(p['ruleIndex'])
            elif o['op'] == 'routingRule.replaceManaged':
                referenced.append(p['ruleIndex'])
            else:
                referenced.append(p['fromIndex'])
                referenced.append(p['toIndex'])
        if referenced:
            conds.append('referenced-managed-rule-indexes-in-range')
        return conds

    def _verification(self, ops):
        steps = ['config-valid-after-apply']
        for o in ops:
            steps.append(o['op'] + '-applied')
        steps.append('managed-rule-set-consistent')
        return steps

    def plan(self, operations=None, now=None, recommendation=None, recommendation_id=None):
        ops = [self._canonical_operation(o) for o in (operations or [])]
        created = int(now if now is not None else time.time())
        # The recommendationId is a SEMANTIC fingerprint when a recommendation
        # is available (stable across re-captures of the same situation); the
        # deterministic topology+operations id is the fallback so the 30-minute
        # same-recommendation cooldown stays meaningful (§22).
        rid = recommendation_id or RoutePlanner.deterministic_id(self.topology, ops)
        if recommendation is not None:
            rec = recommendation if isinstance(recommendation, dict) else {}
            fingerprint = rec.get('semanticFingerprint')
            if fingerprint:
                rid = fingerprint
        plan = {
            'schemaVersion': 1,
            'recommendationId': rid,
            'semanticFingerprint': rid,
            'createdAtEpochSeconds': created,
            'expiresAtEpochSeconds': created + self.ttl_seconds,
            'configurationGeneration': self.configuration_generation,
            'sourceConfigSha256': self.source_config_sha256,
            'topologySha256': digest(self.topology),
            'risk': self._overall_risk(ops),
            'reasonCode': self._reason_code(ops),
            'operations': ops,
            'preconditions': self._preconditions(ops),
            'verification': self._verification(ops),
            'managedScopeOnly': True,
            'planSha256': '',
        }
        if recommendation is not None:
            # The semantic fingerprint (§22) excludes capture timing: it binds
            # normalized topology semantics + recommendation type + operation
            # semantics + config generation/hash, so the same situation keeps
            # the SAME fingerprint (and the same-recommendation cooldown stays
            # meaningful across re-captures).
            plan['recommendationType'] = recommendation.get('recommendationType')
            plan['evidenceDigest'] = recommendation.get('evidenceDigest')
            fingerprint = recommendation.get('semanticFingerprint')
            if fingerprint:
                plan['semanticFingerprint'] = fingerprint
        plan['planSha256'] = plan_digest(plan)
        return plan
