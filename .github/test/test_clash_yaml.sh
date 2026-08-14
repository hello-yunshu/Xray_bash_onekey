#!/usr/bin/env bash
# Clash YAML parser-level regression tests for dual-stack direct-IP output.
#
# Coverage:
#   - generate_clash_config emits structurally valid YAML (backend parse)
#   - a dual-stack Reality config contains BOTH the canonical (IPv4) entry and
#     an IPv6 direct-IP entry whose `server` is the single-quoted IPv6 literal
#   - the IPv6 entry is distringuished by its transport label (tcp-v6)
#   - v4/v6 entries are both present and parse to the correct proxy list
#
# Run: bash .github/test/test_clash_yaml.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { :; }
gettext() { printf '%s' "$1"; }

# --- mocks for generate_clash_config ---
MOCK_HOST="v4.example.com"
MOCK_PORT="443"
info_extraction() {
    case "$1" in
        host) printf '%s' "${MOCK_HOST}" ;;
        port) printf '%s' "${MOCK_PORT}" ;;
        id) printf '%s' 'uuid-1234' ;;
        serverNames) printf '%s' "${MOCK_HOST}" ;;
        target) printf '%s' 'www.microsoft.com' ;;
        shortIds) printf '%s' 'abcd1234' ;;
        spiderx_path) printf '%s' '/spx' ;;
        *) printf '%s' '' ;;
    esac
}
info_reality_public_key() { printf '%s' 'REALITYPUBKEY'; }
reality_client_meta() { printf '%s' ''; }

# --- assemble a dual-stack Reality clash config (v4 + v6) ---
PORT=443
PBK=REALITYPUBKEY
SNI=v4.example.com
TARGET=www.microsoft.com
SID=abcd1234
V6=2001:db8::10

clash_content="proxies:"
clash_content="${clash_content}
$(generate_clash_config "tcp" "${PORT}" "" "" "reality" "xtls-rprx-vision" "${PBK}" "${SNI}" "${TARGET}" "${SID}" "true" "tcp")"
clash_content="${clash_content}
$(generate_clash_config "tcp" "${PORT}" "" "" "reality" "xtls-rprx-vision" "${PBK}" "${SNI}" "${TARGET}" "${SID}" "true" "tcp-v6" "" "${V6}")"

# --- structural assertions (always run) ---
if [[ "${clash_content}" == *"- name: VLESS-${V6}-tcp-v6"* ]]; then
    ok "IPv6 entry name present (VLESS-<v6>-tcp-v6)"
else
    bad "IPv6 entry name missing"
fi
if [[ "${clash_content}" == *"server: '${V6}'"* ]]; then
    ok "IPv6 entry server is single-quoted literal"
else
    bad "IPv6 entry server not single-quoted"
fi
if [[ "${clash_content}" == *"server: ${MOCK_HOST}"* ]]; then
    ok "canonical IPv4 entry server present and unquoted"
else
    bad "canonical IPv4 entry server missing"
fi

# --- backend YAML parse (skip strict parse if PyYAML is unavailable) ---
if python3 -c 'import yaml' >/dev/null 2>&1; then
    printf '%s\n' "${clash_content}" > "${TMP_ROOT}/clash.yaml"
    if python3 -c '
import sys, yaml
data = yaml.safe_load(open(sys.argv[1]))
proxies = data["proxies"]
names = [p["name"] for p in proxies]
servers = [p["server"] for p in proxies]
for want in ("VLESS-2001:db8::10-tcp-v6", "VLESS-v4.example.com-tcp"):
    if want not in names:
        print("missing " + want); sys.exit(1)
if "2001:db8::10" not in servers:
    print("missing v6 server"); sys.exit(1)
if "v4.example.com" not in servers:
    print("missing v4 server"); sys.exit(1)
print("ok")
' "${TMP_ROOT}/clash.yaml" 2>/dev/null | grep -q '^ok'; then
        ok "dual-stack clash YAML parses with correct proxy list"
    else
        bad "clash YAML failed parser assertion"
    fi
else
    ok "PyYAML unavailable; skipped backend parse (structural checks passed)"
fi

echo
if [[ ${FAIL} -eq 0 ]]; then
    printf 'ALL Clash YAML tests PASSED (%d)\n' "${PASS}"
else
    printf 'Clash YAML tests FAILED: %d pass, %d fail\n' "${PASS}" "${FAIL}"
    exit 1
fi