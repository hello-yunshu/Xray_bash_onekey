#!/bin/bash
# Regression tests for Reality+Nginx user-feedback fixes:
#   1. serverNames gets a minimal single-hostname input validation
#   2. stale/corrupt *.serverNames fragments self-heal on reinstall (no permanent
#      nginx -t block)
#   3. Reality privateKey is no longer printed to the terminal
#
# Run: bash .github/test/test_reality_nginx_feedback.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_DIR}" || exit 1

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok()  { PASS=$((PASS + 1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

# Source install.sh in test mode to load functions (no /etc side effects:
# _PURE_READONLY=1 keeps log() file writes disabled during source).
export _TEST_MODE=1
# shellcheck source=/dev/null
source ./install.sh

# --- sandbox ---
FAKE_NGINX_CONF_DIR="${TMP_ROOT}/etc/idleleo/conf/nginx"
mkdir -p "${FAKE_NGINX_CONF_DIR}"
nginx_conf_dir="${FAKE_NGINX_CONF_DIR}"

CAPTURE="${TMP_ROOT}/capture.txt"
: > "${CAPTURE}"

# Override output helpers so terminal display is captured (not written to files).
log() { :; }
log_echo() { printf '%s\n' "$*" >>"${CAPTURE}"; }
log_echo_secure() { printf '%s\n' "$*" >>"${CAPTURE}"; }
gettext() { printf '%s' "$1"; }
judge() { return 0; }

echo "============================================"
echo "  Reality+Nginx user-feedback regression"
echo "============================================"

echo "--- Section 1: serverNames single-hostname validation ---"
declare -a VALID=("www.lovelive-anime.jp" "bing.com" "cdn.example.com")
for h in "${VALID[@]}"; do
    if _validate_serverNames_hostname "${h}"; then
        ok "valid hostname accepted: ${h}"
    else
        bad "valid hostname rejected: ${h}"
    fi
done

declare -a INVALID=(
    ""
    "a.com b.com"
    "https://example.com"
    "example.com;"
    "example.com/foo"
    "a;b"
    "x&y"
    "a|b"
    "a{b}c"
    "hello#world"
    'a$b'
    'a`b'
    "a:b"
)
for h in "${INVALID[@]}"; do
    if _validate_serverNames_hostname "${h}"; then
        bad "invalid hostname accepted: [${h}]"
    else
        ok "invalid hostname rejected: [${h}]"
    fi
done

echo "--- Section 2: serverNames_set rejects bad input, accepts valid input ---"
serverNames=""
target="www.microsoft.com"
old_config_status="off"
change_reality="no"
target_reset=0
# First bad input "a.com b.com" must be rejected and re-prompted; "bing.com" wins.
# Use stdin redirection (not a pipe) so read_optimize's printf -v assignment
# persists in the current shell.
serverNames_set < <(printf 'y\na.com b.com\nbing.com\n') >/dev/null 2>&1
if [[ "${serverNames}" == "bing.com" ]]; then
    ok "serverNames_set re-prompts on invalid input (final=${serverNames})"
else
    bad "serverNames_set accepted invalid input: ${serverNames}"
fi

echo "--- Section 3: valid serverNames generates a valid Nginx fragment ---"
SN_DIR="${TMP_ROOT}/sn-frag"
mkdir -p "${SN_DIR}"
nginx_conf_dir="${SN_DIR}"
serverNames="www.lovelive-anime.jp"
nginx_reality_serverNames_add >/dev/null 2>&1
_got=$(cat "${SN_DIR}/www.lovelive-anime.jp.serverNames" 2>/dev/null)
if [[ "${_got}" == "www.lovelive-anime.jp reality;" ]]; then
    ok "serverNames fragment generated: ${_got}"
else
    bad "serverNames fragment mismatch: [${_got}]"
fi
nginx_conf_dir="${FAKE_NGINX_CONF_DIR}"

echo "--- Section 4: stale/corrupt fragment self-heal on reinstall ---"
# Reset the fragment dir.
rm -rf "${FAKE_NGINX_CONF_DIR}"
mkdir -p "${FAKE_NGINX_CONF_DIR}"
serverNames="example.com"
# Current fragment is corrupt (bad map parameter count) — must be regenerated.
printf 'example.com reality; garbage extra\n' > "${FAKE_NGINX_CONF_DIR}/example.com.serverNames"
# A stale bad fragment from a previous target — this is what breaks `nginx -t`.
printf 'old-target;\n' > "${FAKE_NGINX_CONF_DIR}/old-target.com.serverNames"
# A valid user-owned fragment must be preserved.
printf 'user.com reality;\n' > "${FAKE_NGINX_CONF_DIR}/user.com.serverNames"

# Mock the upstream Reality+Nginx install steps so a real install path runs.
validate_reality_reserved_ports() { :; }
nginx_exist_check() { :; }
nginx_systemd() { :; }
sni_guard_policy_choose() { :; }
nginx_reality_conf_add() { :; }
nginx_reality_servers_add() { :; }

if _apply_reality_nginx_install >/dev/null 2>&1; then
    ok "_apply_reality_nginx_install self-heals instead of being blocked"
else
    bad "_apply_reality_nginx_install failed"
fi

# nginx -t would pass only if every included *.serverNames fragment is valid.
_nginx_t_ok=1
for _f in "${FAKE_NGINX_CONF_DIR}"/*.serverNames; do
    if [[ -e "${_f}" ]] && ! _validate_serverNames_fragment "${_f}"; then
        _nginx_t_ok=0
        echo "    (invalid fragment detected: ${_f})"
    fi
done
if [[ ${_nginx_t_ok} == 1 ]]; then
    ok "all *.serverNames fragments are valid (nginx -t would pass)"
else
    bad "at least one *.serverNames fragment is still invalid"
fi

_got=$(cat "${FAKE_NGINX_CONF_DIR}/example.com.serverNames" 2>/dev/null)
if [[ "${_got}" == "example.com reality;" ]]; then
    ok "current fragment regenerated: ${_got}"
else
    bad "current fragment not regenerated: [${_got}]"
fi

if [[ -f "${FAKE_NGINX_CONF_DIR}/old-target.com.serverNames" ]]; then
    bad "stale corrupt fragment was not removed"
else
    ok "stale corrupt fragment removed"
fi

if [[ -f "${FAKE_NGINX_CONF_DIR}/user.com.serverNames" ]]; then
    ok "valid user fragment preserved"
else
    bad "valid user fragment was removed"
fi

echo "--- Section 5: Reality privateKey not printed to terminal ---"
FAKE_BIN="${TMP_ROOT}/bin"
mkdir -p "${FAKE_BIN}"
cat > "${FAKE_BIN}/xray" <<'XEOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "x25519" ]]; then
    echo "PrivateKey: <PRIVKEY_UNDERTEST_abcdef1234567890>"
    echo "PublicKey: <PUBKEY_UNDERTEST_0123456789abcdef>"
fi
exit 0
XEOF
chmod +x "${FAKE_BIN}/xray"
xray_bin_dir="${FAKE_BIN}"
old_config_status="off"
change_reality="no"
: > "${CAPTURE}"
keys_set < <(printf 'n\n') >/dev/null 2>&1
if ! grep -q "<PRIVKEY_UNDERTEST_abcdef1234567890>" "${CAPTURE}"; then
    ok "privateKey secret not printed to terminal"
else
    bad "privateKey secret leaked to terminal"
fi
if grep -q "已生成并保存（不显示）" "${CAPTURE}"; then
    ok "privateKey placeholder message shown"
else
    bad "privateKey placeholder message missing in terminal output"
fi
# publicKey must still be shown (needed by the client).
if grep -q "<PUBKEY_UNDERTEST_0123456789abcdef>" "${CAPTURE}"; then
    ok "publicKey still printed"
else
    bad "publicKey not printed"
fi

echo ""
echo "============================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================"
[[ ${FAIL} -eq 0 ]]