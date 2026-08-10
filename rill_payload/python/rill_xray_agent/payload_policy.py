from .audit import redact

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


class RootResultViolation(ValueError):
    pass


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