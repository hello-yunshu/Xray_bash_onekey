"""Single source of truth for the route mutation contract.

ALLOWED_OPS, parameter keys, index keys, safe characters, selector enums,
operation/plan limits and risk classification are defined HERE and imported by
the planner, the analyzer, the executor and the schemas. No component keeps its
own copy of the contract (that drift caused planner/executor disagreements).

Scope rules (security-sensitive):
  - MANUAL_ROUTE_OPS: every audited operation the operator may approve.
  - AUTO_ROUTE_OPS: a strictly smaller, more conservative allowlist for the
    Bounded-Auto producer. remove/move are manual-only in Auto V1; the root
    executor re-evaluates auto eligibility against THIS contract and never
    trusts a request-declared ``risk``.
"""
from __future__ import annotations

import re

# ---- operation enums -----------------------------------------------------
ALLOWED_OPS = frozenset({
    'routingRule.insert',
    'routingRule.removeManaged',
    'routingRule.replaceManaged',
    'routingRule.moveManaged',
})

MANUAL_ROUTE_OPS = frozenset(ALLOWED_OPS)

# Auto V1 is intentionally conservative: it may INSERT a managed rule or
# REPLACE a managed rule's selector/outbound, but never remove or reorder
# rules. Reordering/removal changes the reachability of other rules and is
# always left to an audited human decision.
AUTO_ROUTE_OPS = frozenset({'routingRule.insert', 'routingRule.replaceManaged'})

# ---- operation parameter keys -------------------------------------------
OP_PARAM_KEYS = {
    'routingRule.insert': {'position', 'selectorType', 'selectorValue', 'outboundTag'},
    'routingRule.removeManaged': {'ruleIndex'},
    'routingRule.replaceManaged': {'ruleIndex', 'selectorType', 'selectorValue', 'outboundTag'},
    'routingRule.moveManaged': {'fromIndex', 'toIndex'},
}
INDEX_KEYS = frozenset({'position', 'ruleIndex', 'fromIndex', 'toIndex'})

# Selector types the compiler understands (rule field name -> value).
SELECTOR_TYPES = frozenset(
    {'domain', 'ip', 'network', 'port', 'protocol', 'source'})

# Characters allowed inside a free-text parameter value. Paths, whitespace and
# shell metacharacters are rejected.
SAFE_CHARS = frozenset(
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:,/@+')

# ---- limits --------------------------------------------------------------
MAX_OPERATIONS = 32
MAX_PARAMS = 8
MAX_RULES = 512
MAX_SELECTOR_LIST = 64
MAX_STRING = 4096
MAX_REQUEST_BYTES = 256 * 1024
MAX_TOPOLOGY_RULES = 4096

ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
SHA_RE = re.compile(r'^[a-f0-9]{64}$')

# Risk rank used by the planner and the executor's auto re-evaluation.
RISK_RANK = {'low': 0, 'medium': 1, 'high': 2}

# Auto V1 risk ceiling: any operation above LOW is never auto-eligible unless
# the (future) policy explicitly relaxes it. Kept here as the single contract.
AUTO_MAX_RISK = 'low'

# Managed-rule tag prefix: ownership marker for rules Rill may mutate/remove.
MANAGED_PREFIX = 'rill-managed-'


def risk_rank(risk):
    """Deterministic numeric ordering of risk labels (default: high)."""
    return RISK_RANK.get(risk, RISK_RANK['high'])


def rule_at(rules, index):
    """Return the rule dict at ``index`` in a routing rules list, or None.

    Shared by the planner and the root executor so both evaluate operations
    against the same live rule list shape.
    """
    if not isinstance(rules, list) or not isinstance(index, int):
        return None
    if 0 <= index < len(rules):
        rule = rules[index]
        return rule if isinstance(rule, dict) else None
    return None


# Selector field names as they appear in a REAL Xray rule. Xray rules carry
# fields such as ``domain``/``ip``/``port``/``network``/``protocol``/``source``
# directly; they never carry a synthetic ``selectorType`` key. This is the
# single mapping used to derive a selector type from a live rule (see §4).
SELECTOR_FIELD_ORDER = ('domain', 'ip', 'network', 'port', 'protocol', 'source',
                        'inboundTag', 'user', 'email')


def rule_selector_type(rule):
    """Derive the selector type of a live Xray rule from its actual fields.

    Returns the FIRST present selector field (in contract order) or None. The
    planner and the root executor share this so their risk classification is
    semantically identical; the root executor remains the final authority.

    Also understands the SAFE topology projection rule shape (route_topology):
    a projected rule records its selector types explicitly as ``selectorTypes``
    (ordered list), so the advisory planner risk can be computed from the
    secret-free projection without ever reading the raw Xray config (§4/§P0-4).
    """
    if not isinstance(rule, dict):
        return None
    st = rule.get('selectorTypes')
    if isinstance(st, list) and st and isinstance(st[0], str):
        return st[0]
    for field in SELECTOR_FIELD_ORDER:
        value = rule.get(field)
        if value is not None and not (isinstance(value, (list, str, int))
                                      and value == []):
            return field
    return None


def op_risk(op, rules):
    """Deterministic risk classification of a single typed operation,
    evaluated against the CURRENT routing rules.

    This is the single classification used by the planner AND re-evaluated
    root-side by the executor (§19): auto eligibility is never trusted from a
    request-declared label, it is recomputed here from the live rules.
    """
    if not isinstance(op, dict):
        return 'high'
    opname = op.get('op')
    params = op.get('params') if isinstance(op.get('params'), dict) else {}
    if opname == 'routingRule.insert':
        position = params.get('position')
        count = len(rules) if isinstance(rules, list) else 0
        if isinstance(position, int) and position >= (count - 1):
            return 'low'
        return 'medium'
    if opname == 'routingRule.removeManaged':
        return 'low'
    if opname == 'routingRule.replaceManaged':
        current = rule_at(rules, params.get('ruleIndex'))
        # §4: real Xray rules never carry a synthetic ``selectorType`` field.
        # Derive the current selector type from the live rule's actual fields
        # and compare it to the operation's target selector type.
        current_type = rule_selector_type(current)
        if current_type is not None and current_type == params.get('selectorType'):
            return 'low'
        return 'medium'
    if opname == 'routingRule.moveManaged':
        return 'low'
    return 'high'


def overall_risk(ops, rules):
    """Aggregate risk of an operation list against the live rules."""
    if not ops:
        return 'low'
    return max((op_risk(o, rules) for o in ops), key=risk_rank)
