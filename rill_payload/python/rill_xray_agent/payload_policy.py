import json

from .audit import redact
from .canonical import digest

ALLOWED_PAYLOAD_KEYS = {'decisionId', 'capability', 'modelGeneration', 'createdAtEpochSeconds'}
XRAY_CONFIG_SIGNATURES = {'inbounds', 'outbounds', 'routing', 'policy', 'dns', 'stats', 'reverse'}
FORBIDDEN_SUBSTRINGS = ('-----BEGIN ', 'vless://', 'vmess://', 'trojan://', 'ssh://', 'privateKey', 'publicKey', 'shortId', 'token')
ROOT_RESULT_ALLOWLIST = {
    'status', 'outcome', 'ok',
    'returnCode',
    'outputSha256',
    'configurationGeneration', 'nextConfigurationGeneration',
    'startedAtEpochSeconds', 'finishedAtEpochSeconds', 'updatedAtEpochSeconds',
    'routeAssistAllowed', 'autoReapplyAllowed', 'observed', 'matched',
}

# Structured Doctor feedback: enum/boolean/scalar only. Free-text comments are
# intentionally rejected so users cannot accidentally persist secrets, URLs or
# raw configuration through feedback.
DOCTOR_FEEDBACK_OUTCOMES = {'resolved', 'not-resolved', 'not-applicable'}
DOCTOR_FEEDBACK_BOOLS = {'helpful', 'diagnosisCorrect'}

# Route artifacts (RoutePlan / RouteTopology) are never persisted verbatim:
# selector values (domains/IPs/...) can carry user privacy and config secrets.
# Only typed operation names, counts and digests are stored in history.
ROUTE_OP_ALLOWLIST = {
    'routingRule.insert', 'routingRule.removeManaged',
    'routingRule.replaceManaged', 'routingRule.moveManaged',
}


class RootResultViolation(ValueError):
    pass


def sanitize_doctor_feedback(payload):
    """Validate structured Doctor feedback before persistent storage.

    Accepts only the decision identity fields plus scalar feedback fields:
    outcome (enum), helpful (bool), diagnosisCorrect (bool). Free-text, nested
    payloads and any secret/config material are rejected, never stored.
    """
    if not isinstance(payload, dict):
        raise ValueError('doctor feedback must be an object')
    out = {}
    for key, value in payload.items():
        if key in XRAY_CONFIG_SIGNATURES:
            raise ValueError('xray configuration body prohibited')
        if key in DOCTOR_FEEDBACK_BOOLS:
            if not isinstance(value, bool):
                raise ValueError(f'doctor feedback {key} must be a boolean')
            out[key] = value
            continue
        if key == 'outcome':
            if value not in DOCTOR_FEEDBACK_OUTCOMES:
                raise ValueError('doctor feedback outcome invalid')
            out[key] = value
            continue
        if key in ALLOWED_PAYLOAD_KEYS:
            if isinstance(value, str) and str(value).lower().startswith('vless://'):
                raise ValueError('v2 transport material prohibited')
            out[key] = value
            continue
        raise ValueError(f'unexpected doctor feedback field: {key}')
    return out


def sanitize_payload(payload):
    """Schema allowlist: only known metadata keys persist; everything else is redacted.

    Xray configuration bodies (inbounds/outbounds/...) are never stored. Stored values
    go through the audit redaction filter so private keys, UUIDs, shortIds, tokens and
    vless:// material cannot be saved.
    """
    if not isinstance(payload, dict):
        raise ValueError('payload must be an object')
    out = {}
    for key, value in payload.items():
        if key in XRAY_CONFIG_SIGNATURES:
            raise ValueError('xray configuration body prohibited')
        if key in ALLOWED_PAYLOAD_KEYS:
            if isinstance(value, str) and str(value).lower().startswith('vless://'):
                raise ValueError('v2 transport material prohibited')
            out[key] = value
            continue
        if key == 'terminalPayload':
            out[key] = redact(value, key)
            continue
    d = redact(out)
    if any(sig in d for sig in XRAY_CONFIG_SIGNATURES):
        raise ValueError('xray configuration body prohibited')
    return d


def sanitize_root_result(result):
    """Allowlist projection of an agent-supplied root result.

    Only scalar fields in ROOT_RESULT_ALLOWLIST are retained. Raw output,
    X-Config bodies, secrets, transport links and arbitrary nested payloads
    are rejected, not stored. The result is never written verbatim into state.
    """
    if not isinstance(result, dict):
        raise RootResultViolation('root result must be an object')
    out = {}
    for key, value in result.items():
        if key not in ROOT_RESULT_ALLOWLIST:
            continue
        if isinstance(value, bool):
            out[key] = value
            continue
        if isinstance(value, int) and not isinstance(value, bool):
            out[key] = value
            continue
        if isinstance(value, str):
            lowered = value.lower()
            for token in FORBIDDEN_SUBSTRINGS:
                if token and token.lower() in lowered:
                    raise RootResultViolation(f'forbidden material in {key}')
            if any(sig in value for sig in XRAY_CONFIG_SIGNATURES):
                raise RootResultViolation(f'xray config signature in {key}')
            out[key] = value
            continue
        raise RootResultViolation(f'non-scalar value for {key}')
    return out


def sanitize_route_plan_meta(plan):
    """Safe, secret-free metadata projection of a RoutePlan for history.

    Only non-sensitive identifiers, digests, counts and typed operation names
    are retained. Raw selector values (domains/IPs), outbound tags and any
    free-text are never persisted: they may carry user privacy or config
    secrets. The operations are collapsed to a digest plus their typed names.
    """
    if not isinstance(plan, dict):
        raise ValueError('route plan must be an object')
    if plan.get('schemaVersion') != 1:
        raise ValueError('route plan schemaVersion != 1')
    for key in ('recommendationId', 'planSha256', 'sourceConfigSha256'):
        if not isinstance(plan.get(key), str) or not plan.get(key):
            raise ValueError(f'route plan missing {key}')
    operations = plan.get('operations')
    if not isinstance(operations, list):
        raise ValueError('route plan operations must be a list')
    kinds = []
    for op in operations:
        if (not isinstance(op, dict) or op.get('op') not in ROUTE_OP_ALLOWLIST
                or op.get('managedScope') is not True):
            raise ValueError('unsafe route operation in plan')
        kinds.append(op['op'])
    lowered = json.dumps(plan, sort_keys=True).lower()
    for token in FORBIDDEN_SUBSTRINGS:
        if token and token.lower() in lowered:
            raise ValueError('forbidden material in route plan')
    return {
        # schemaVersion is kept so a re-read plan (routeApprove) can be
        # re-validated as a concrete RoutePlan by evaluate_plan_policy (§P0-1).
        'schemaVersion': plan['schemaVersion'],
        'recommendationId': plan['recommendationId'],
        'planSha256': plan['planSha256'],
        'sourceConfigSha256': plan['sourceConfigSha256'],
        'configurationGeneration': plan.get('configurationGeneration'),
        'risk': plan.get('risk'),
        'reasonCode': plan.get('reasonCode'),
        'createdAtEpochSeconds': plan.get('createdAtEpochSeconds'),
        'expiresAtEpochSeconds': plan.get('expiresAtEpochSeconds'),
        'operationCount': len(operations),
        'operationKinds': sorted(set(kinds)),
        'operationsDigest': digest({'operations': operations}),
    }