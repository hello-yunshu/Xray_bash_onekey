from .audit import redact

ALLOWED_PAYLOAD_KEYS = {'decisionId', 'capability', 'modelGeneration', 'createdAtEpochSeconds'}
XRAY_CONFIG_SIGNATURES = {'inbounds', 'outbounds', 'routing', 'policy', 'dns', 'stats', 'reverse'}


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