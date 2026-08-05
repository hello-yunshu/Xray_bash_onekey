#!/usr/bin/env bash
# Unified port validation.
#
# Coverage:
#   - validate_port_number accepts 1-65535, rejects 0, 65536, non-numeric
#   - validate_active_ports: port=443,xport=443 fails (duplicate)
#   - validate_active_ports: xport=10086,gport=10086 fails (duplicate)
#   - validate_active_ports: Reality using 9443 fails (reserved)
#   - validate_active_ports: different ports succeed
#   - validate_active_ports: disabled protocol ports don't participate
#
# Run: bash .github/test/test_port_validation.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { :; }
gettext() { printf '%s' "$1"; }

echo "============================================================"
echo "  Section 4: Unified Port Validation"
echo "============================================================"

# --- validate_port_number tests ---
echo "--- validate_port_number ---"
for valid_port in 1 80 443 8080 65535; do
    if validate_port_number "${valid_port}"; then
        ok "validate_port_number '${valid_port}' returns 0 (valid)"
    else
        bad "validate_port_number '${valid_port}' should return 0"
    fi
done

for invalid_port in 0 65536 -1 abc "" 999999; do
    if validate_port_number "${invalid_port}"; then
        bad "validate_port_number '${invalid_port}' should return 1 (invalid)"
    else
        ok "validate_port_number '${invalid_port}' returns 1 (invalid)"
    fi
done

# --- validate_active_ports: duplicate port=443,xport=443 ---
echo "--- port=443, xport=443 fails (duplicate) ---"
port="443"
xport="443"
gport=""
xhttpport=""
transport_mode="onlyws"
tls_mode="TLS"
if validate_active_ports; then
    bad "validate_active_ports should fail: port=443, xport=443 (duplicate)"
else
    ok "validate_active_ports fails: port=443, xport=443 (duplicate)"
fi

# --- validate_active_ports: xport=10086, gport=10086 ---
echo "--- xport=10086, gport=10086 fails (duplicate) ---"
port=""
xport="10086"
gport="10086"
xhttpport=""
transport_mode="wsgRPCxhttp"
tls_mode="None"
if validate_active_ports; then
    bad "validate_active_ports should fail: xport=10086, gport=10086 (duplicate)"
else
    ok "validate_active_ports fails: xport=10086, gport=10086 (duplicate)"
fi

# --- validate_active_ports: Reality using 9443 fails (reserved) ---
echo "--- Reality using port 9443 fails (reserved) ---"
port="9443"
xport=""
gport=""
xhttpport=""
transport_mode="None"
tls_mode="Reality"
if validate_active_ports; then
    bad "validate_active_ports should fail: Reality port=9443 (reserved)"
else
    ok "validate_active_ports fails: Reality port=9443 (reserved)"
fi

# --- validate_active_ports: Reality xport=9443 also fails ---
echo "--- Reality xport=9443 fails (reserved) ---"
port="443"
xport="9443"
gport=""
xhttpport=""
transport_mode="onlyws"
tls_mode="Reality"
if validate_active_ports; then
    bad "validate_active_ports should fail: Reality xport=9443 (reserved)"
else
    ok "validate_active_ports fails: Reality xport=9443 (reserved)"
fi

# --- validate_active_ports: different ports succeed ---
echo "--- Different ports succeed ---"
port="443"
xport="10086"
gport="10087"
xhttpport="10088"
transport_mode="wsgRPCxhttp"
tls_mode="TLS"
if validate_active_ports; then
    ok "validate_active_ports succeeds: all different ports"
else
    bad "validate_active_ports should succeed with different ports"
fi

# --- validate_active_ports: different ports succeed (None mode, onlyws) ---
echo "--- Different ports succeed (None mode, onlyws) ---"
port=""
xport="10086"
gport=""
xhttpport=""
transport_mode="onlyws"
tls_mode="None"
if validate_active_ports; then
    ok "validate_active_ports succeeds: single ws port"
else
    bad "validate_active_ports should succeed with single ws port"
fi

# --- validate_active_ports: disabled protocol ports don't participate ---
echo "--- Disabled protocol ports don't participate ---"
# Set gport to same as xport, but transport_mode is onlyws (not gRPC)
# So gport should NOT participate in validation
port="443"
xport="10086"
gport="10086"  # Same as xport, but gRPC is not enabled
xhttpport=""
transport_mode="onlyws"
tls_mode="TLS"
if validate_active_ports; then
    ok "validate_active_ports succeeds: gport excluded (gRPC disabled) even if duplicate"
else
    bad "validate_active_ports should ignore gport when gRPC is disabled"
fi

# --- validate_active_ports: xhttp disabled doesn't participate ---
echo "--- Disabled xhttp port doesn't participate ---"
port="443"
xport="10086"
gport=""
xhttpport="10086"  # Same as xport, but xHTTP is not enabled
transport_mode="onlyws"
tls_mode="TLS"
if validate_active_ports; then
    ok "validate_active_ports succeeds: xhttpport excluded (xHTTP disabled)"
else
    bad "validate_active_ports should ignore xhttpport when xHTTP is disabled"
fi

# --- validate_active_ports: None values are skipped ---
echo "--- 'None' port values are skipped ---"
port="None"
xport="10086"
gport="None"
xhttpport="None"
transport_mode="wsgRPCxhttp"
tls_mode="None"
if validate_active_ports; then
    ok "validate_active_ports succeeds: 'None' values skipped"
else
    bad "validate_active_ports should skip 'None' values"
fi

echo ""
echo "============================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
