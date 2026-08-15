import hashlib
import time
import uuid
from .canonical import canonical_bytes, digest

ALLOWED_OPS = {
    'routingRule.insert',
    'routingRule.removeManaged',
    'routingRule.replaceManaged',
    'routingRule.moveManaged',
}
OP_PARAM_KEYS = {
    'routingRule.insert': {'position', 'selectorType', 'selectorValue', 'outboundTag'},
    'routingRule.removeManaged': {'ruleIndex'},
    'routingRule.replaceManaged': {'ruleIndex', 'selectorType', 'selectorValue', 'outboundTag'},
    'routingRule.moveManaged': {'fromIndex', 'toIndex'},
}
INDEX_KEYS = {'position', 'ruleIndex', 'fromIndex', 'toIndex'}
SAFE_CHARS = frozenset(
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:,/@+')
RISK_RANK = {'low': 0, 'medium': 1, 'high': 2}


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
            topology.get('routing') if isinstance(topology.get('routing'), dict) else {})
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

    def _rule_at(self, index):
        rules = self._rules()
        if 0 <= index < len(rules) and isinstance(rules[index], dict):
            return rules[index]
        return None

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
        opname = op['op']
        params = op['params']
        if opname == 'routingRule.insert':
            position = params.get('position')
            count = len(self._rules())
            return 'low' if position >= (count - 1) else 'medium'
        if opname == 'routingRule.removeManaged':
            return 'low'
        if opname == 'routingRule.replaceManaged':
            current = self._rule_at(params.get('ruleIndex'))
            if current and current.get('selectorType') == params.get('selectorType'):
                return 'low'
            return 'medium'
        if opname == 'routingRule.moveManaged':
            return 'low'
        return 'high'

    def _overall_risk(self, ops):
        if not ops:
            return 'low'
        return max((self._op_risk(o) for o in ops), key=RISK_RANK.get)

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

    def plan(self, operations=None, now=None):
        ops = [self._canonical_operation(o) for o in (operations or [])]
        created = int(now if now is not None else time.time())
        plan = {
            'schemaVersion': 1,
            'recommendationId': RoutePlanner.deterministic_id(self.topology, ops),
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
        plan['planSha256'] = plan_digest(plan)
        return plan
