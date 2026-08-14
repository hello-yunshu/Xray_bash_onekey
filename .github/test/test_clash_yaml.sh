#!/usr/bin/env bash
# Clash YAML parser-level regression tests for dual-stack direct-IP output.
#
# Coverage (spec 5.3):
#   - domain entry (canonical host) / IPv4 direct-IP / IPv6 direct-IP
#   - dual Reality: name / server / servername / reality-opts all present
#   - dual None ws:   name / server / ws-opts present for v4 + v6
#   - dual None grpc: name / server / grpc-opts present for v4 + v6
#
# Qualification semantics (spec 5.1/5.2): structural checks always run.
# The backend PyYAML parse genuinely executes when `yaml` is importable;
# otherwise the parse step is explicitly reported as SKIP (never as PASS).
# CI installs PyYAML so the parser test really runs there.
#
# Run: bash .github/test/test_clash_yaml.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
SKIP=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok()   { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP: %s\n' "$1"; }
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

# --- assemble a multi-entry dual-stack clash config ------------------------
PORT=443
PBK=REALITYPUBKEY
SNI=v4.example.com
TARGET=www.microsoft.com
SID=abcd1234
V4=203.0.113.10
V6=2001:db8::10

# Assemble entries: domain (canonical), IPv4 direct-IP, IPv6 direct-IP for
# Reality, and v4+v6 entries for None ws and None grpc.
clash_content="proxies:"
clash_content="${clash_content}
$(generate_clash_config "tcp" "${PORT}" "" "" "reality" "xtls-rprx-vision" "${PBK}" "${SNI}" "${TARGET}" "${SID}" "true" "tcp")"
clash_content="${clash_content}
$(generate_clash_config "tcp" "${PORT}" "" "" "reality" "xtls-rprx-vision" "${PBK}" "${SNI}" "${TARGET}" "${SID}" "true" "tcp-v4" "" "${V4}")"
clash_content="${clash_content}
$(generate_clash_config "tcp" "${PORT}" "" "" "reality" "xtls-rprx-vision" "${PBK}" "${SNI}" "${TARGET}" "${SID}" "true" "tcp-v6" "" "${V6}")"
clash_content="${clash_content}
$(generate_clash_config "ws" "8888" "/ws" "" "none" "" "${PBK}" "${SNI}" "${TARGET}" "${SID}" "false" "ws")"
clash_content="${clash_content}
$(generate_clash_config "ws" "8888" "/ws" "" "none" "" "${PBK}" "${SNI}" "${TARGET}" "${SID}" "false" "ws-v6" "" "${V6}")"
clash_content="${clash_content}
$(generate_clash_config "grpc" "8888" "" "grpc-svc" "none" "" "${PBK}" "${SNI}" "${TARGET}" "${SID}" "false" "grpc")"
clash_content="${clash_content}
$(generate_clash_config "grpc" "8888" "" "grpc-svc" "none" "" "${PBK}" "${SNI}" "${TARGET}" "${SID}" "false" "grpc-v6" "" "${V6}")"

# --- structural assertions (always run) ------------------------------------
for name in "VLESS-${V4}-tcp-v4" "VLESS-${V6}-tcp-v6" "VLESS-${V6}-ws-v6" "VLESS-${V6}-grpc-v6"; do
    if [[ "${clash_content}" == *"- name: ${name}"* ]]; then
        ok "entry name present (${name})"
    else
        bad "entry name missing (${name})"
    fi
done

if [[ "${clash_content}" == *"server: '${V6}'"* ]]; then
    ok "IPv6 direct-IP server single-quoted (${V6})"
else
    bad "IPv6 direct-IP server not single-quoted"
fi
if [[ "${clash_content}" == *"server: ${V4}"* ]]; then
    ok "IPv4 direct-IP server present (${V4})"
else
    bad "IPv4 direct-IP server missing"
fi
if [[ "${clash_content}" == *"server: ${MOCK_HOST}"* ]]; then
    ok "domain server present (${MOCK_HOST})"
else
    bad "domain server missing"
fi

if [[ "${clash_content}" == *"servername: ${SNI}"* ]]; then
    ok "Reality entry has servername"
else
    bad "Reality entry missing servername"
fi
if [[ "${clash_content}" == *"reality-opts:"* && "${clash_content}" == *"public-key: ${PBK}"* && "${clash_content}" == *"short-id: ${SID}"* ]]; then
    ok "Reality entry has reality-opts (public-key/short-id)"
else
    bad "Reality entry reality-opts incomplete"
fi
if [[ "${clash_content}" == *"ws-opts:"* && "${clash_content}" == *"path: /ws"* ]]; then
    ok "None ws entry has ws-opts"
else
    bad "None ws entry missing ws-opts"
fi
if [[ "${clash_content}" == *"grpc-opts:"* && "${clash_content}" == *"grpc-service-name: grpc-svc"* ]]; then
    ok "None grpc entry has grpc-opts"
else
    bad "None grpc entry missing grpc-opts"
fi

# --- backend YAML parse ------------------------------------------------------
printf '%s\n' "${clash_content}" > "${TMP_ROOT}/clash.yaml"
if python3 -c 'import yaml' >/dev/null 2>&1; then
    if python3 -c '
import sys, yaml
data = yaml.safe_load(open(sys.argv[1]))
proxies = data["proxies"]
names = [p["name"] for p in proxies]
servers = [p["server"] for p in proxies]
for want in ("VLESS-203.0.113.10-tcp-v4", "VLESS-2001:db8::10-tcp-v6",
             "VLESS-2001:db8::10-ws-v6", "VLESS-2001:db8::10-grpc-v6",
             "VLESS-v4.example.com-tcp"):
    if want not in names:
        print("missing name " + want); sys.exit(1)
if "2001:db8::10" not in servers:
    print("missing v6 server"); sys.exit(1)
if "203.0.113.10" not in servers:
    print("missing v4 server"); sys.exit(1)
if "v4.example.com" not in servers:
    print("missing domain server"); sys.exit(1)
# reality / ws / grpc structure must be intact after round-trip
by_name = {p["name"]: p for p in proxies}
r = by_name["VLESS-v4.example.com-tcp"]
if r.get("servername") != "v4.example.com" or "reality-opts" not in r:
    print("reality entry structure lost"); sys.exit(1)
ws = by_name["VLESS-2001:db8::10-ws-v6"]
if "ws-opts" not in ws:
    print("ws entry structure lost"); sys.exit(1)
g = by_name["VLESS-2001:db8::10-grpc-v6"]
if "grpc-opts" not in g:
    print("grpc entry structure lost"); sys.exit(1)
print("ok")
' "${TMP_ROOT}/clash.yaml" 2>/dev/null | grep -q '^ok'; then
        ok "clash YAML parses with correct proxy list (Reality/ws/grpc, v4+v6)"
    else
        bad "clash YAML failed parser assertion"
    fi
else
    skip "Clash parser validation skipped (PyYAML unavailable)"
fi

echo
if [[ ${FAIL} -eq 0 ]]; then
    printf 'ALL Clash YAML tests PASSED (%d pass, %d skip)\n' "${PASS}" "${SKIP}"
else
    printf 'Clash YAML tests FAILED: %d pass, %d fail, %d skip\n' "${PASS}" "${FAIL}" "${SKIP}"
    exit 1
fi
