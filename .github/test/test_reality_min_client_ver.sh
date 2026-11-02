#!/usr/bin/env bash
#
# Stage 04: REALITY minClientVer repair.
#
# Xray 26.7.11 started treating an unset `realitySettings.minClientVer` as
# "require 26.3.27", which rejects clients that still report an older build
# (Mihomo/Clash report 1.8.2). Upstream: XTLS/Xray-core#6482.
#
# This suite covers:
#   A. every reality inbound missing the field gets the explicit value
#   B. a user-chosen value is never overwritten
#   C. configs without a reality inbound are left byte-identical
#   D. the repair is idempotent
#   E. a config that Xray rejects is rolled back byte for byte
#   F. relay nodes are untouched
#
# No root, no real Xray, no network: the Xray CLI is a controllable stub.
#
# Usage: bash .github/test/test_reality_min_client_ver.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
check() {
    local desc="$1"
    shift
    if "$@"; then ok "${desc}"; else bad "${desc}"; fi
}

[[ -f "${INSTALL_SH}" ]] || {
    echo "FATAL: ${INSTALL_SH} not found"
    exit 1
}

# ---- macOS portability: update_json_config relies on GNU `stat -c` ----------
if ! stat -c '%a' / >/dev/null 2>&1; then
    stat() {
        case "${1:-}" in
            -c)
                case "${2:-}" in
                    '%a') shift 2 && command stat -f '%Lp' "$@" ;;
                    '%u') shift 2 && command stat -f '%u' "$@" ;;
                    '%g') shift 2 && command stat -f '%g' "$@" ;;
                    '%s') shift 2 && command stat -f '%z' "$@" ;;
                    *) command stat "$@" ;;
                esac
                ;;
            *) command stat "$@" ;;
        esac
    }
fi

log_echo() { :; }
gettext() { printf '%s' "$1"; }
judge() { return 0; }
systemctl() { return 0; }
Error=""; RedBG=""; OK=""; GreenBG=""; Font=""
Warning=""; YellowBG=""; Green=""; Red=""; Info=""

export _TEST_MODE=1
# shellcheck source=/dev/null
source "${INSTALL_SH}" >/dev/null 2>&1 || true
unset _TEST_MODE

echo "============================================================"
echo "  Stage 04: REALITY minClientVer repair"
echo "============================================================"

idleleo_dir="${TMP_ROOT}/idleleo"
xray_bin_dir="${TMP_ROOT}/bin"
xray_conf_dir="${idleleo_dir}/conf/xray"
xray_conf="${xray_conf_dir}/config.json"
xray_install_config_file="${idleleo_dir}/conf/install_config.json"
geodata_dir="${idleleo_dir}/share/xray"
mkdir -p "${xray_conf_dir}" "${xray_bin_dir}" "${geodata_dir}"

info_extraction() {
    jq -r --arg k "$1" '.[$k] // empty' "${xray_install_config_file}" 2>/dev/null
}

# The function under test must exist before anything else is asserted.
if ! declare -f reality_min_client_ver_repair >/dev/null 2>&1; then
    bad "reality_min_client_ver_repair is missing from install.sh"
    printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
    exit 1
fi

# Xray stub: rc controlled by REALITY_TEST_RC, call count recorded.
cat >"${xray_bin_dir}/xray" <<'STUB'
#!/bin/sh
if [ "$1" = "run" ]; then
    n=$(( $(cat "${REALITY_TEST_COUNT_FILE:-/dev/null}" 2>/dev/null || echo 0) + 1 ))
    printf '%s' "${n}" >"${REALITY_TEST_COUNT_FILE}"
    exit "${REALITY_TEST_RC:-0}"
fi
echo "Xray 26.10.31 (stub)"
STUB
chmod +x "${xray_bin_dir}/xray"
export REALITY_TEST_COUNT_FILE="${TMP_ROOT}/calls.txt"
export REALITY_TEST_RC=0

write_config() { printf '%s\n' "$1" >"${xray_conf}"; }

reality_inbound='{"tag":"VLESS-Reality-in","streamSettings":{"security":"reality","realitySettings":{"target":"a.example:443","serverNames":["a.example"],"privateKey":"k","shortIds":["01"]}}}'
reality_inbound_with_ver='{"tag":"VLESS-Reality-in","streamSettings":{"security":"reality","realitySettings":{"target":"a.example:443","serverNames":["a.example"],"minClientVer":"2.0.0","privateKey":"k","shortIds":["01"]}}}'
plain_inbound='{"tag":"VLESS-ws-in","streamSettings":{"security":"none","wsSettings":{"path":"/ray/"}}}'

printf '%s\n' '--- A. missing minClientVer is filled in ---'
write_config "{\"inbounds\":[${reality_inbound},${plain_inbound}]}"
reality_min_client_ver_repair >/dev/null 2>&1
ver=$(jq -r '.inbounds[] | select(.tag == "VLESS-Reality-in") | .streamSettings.realitySettings.minClientVer' "${xray_conf}")
check "reality inbound receives minClientVer=1.0.0" test "${ver}" = "1.0.0"
has_ver=$(jq -r '.inbounds[] | select(.tag == "VLESS-ws-in") | (.streamSettings.realitySettings.minClientVer // "absent")' "${xray_conf}")
check "non-reality inbound is untouched" test "${has_ver}" = "absent"
check "config stays valid JSON" jq -e '.inbounds | length == 2' "${xray_conf}"

printf '%s\n' '--- B. an explicit value is never overwritten ---'
write_config "{\"inbounds\":[${reality_inbound_with_ver}]}"
reality_min_client_ver_repair >/dev/null 2>&1
ver=$(jq -r '.inbounds[0].streamSettings.realitySettings.minClientVer' "${xray_conf}")
check "user-chosen minClientVer is preserved" test "${ver}" = "2.0.0"

printf '%s\n' '--- C. configs without a reality inbound are untouched ---'
write_config "{\"inbounds\":[${plain_inbound}]}"
before=$(shasum "${xray_conf}" | awk '{print $1}')
reality_min_client_ver_repair >/dev/null 2>&1
after=$(shasum "${xray_conf}" | awk '{print $1}')
check "non-reality install is not modified" test "${before}" = "${after}"

printf '%s\n' '--- D. the repair is idempotent ---'
write_config "{\"inbounds\":[${reality_inbound}]}"
reality_min_client_ver_repair >/dev/null 2>&1
first=$(shasum "${xray_conf}" | awk '{print $1}')
reality_min_client_ver_repair >/dev/null 2>&1
second=$(shasum "${xray_conf}" | awk '{print $1}')
check "second run leaves the file byte-identical" test "${first}" = "${second}"

printf '%s\n' '--- E. a rejected config is rolled back byte for byte ---'
write_config "{\"inbounds\":[${reality_inbound}]}"
before=$(shasum "${xray_conf}" | awk '{print $1}')
REALITY_TEST_RC=1
export REALITY_TEST_RC
: >"${REALITY_TEST_COUNT_FILE}"
reality_min_client_ver_repair >/dev/null 2>&1
after=$(shasum "${xray_conf}" | awk '{print $1}')
check "failed config test restores the original bytes" test "${before}" = "${after}"
check "the Xray CLI was actually consulted" test -s "${REALITY_TEST_COUNT_FILE}"
REALITY_TEST_RC=0
export REALITY_TEST_RC

printf '%s\n' '--- F. relay nodes are never rewritten ---'
write_config "{\"inbounds\":[${reality_inbound}]}"
printf '%s' '{"role":"relay"}' >"${xray_install_config_file}"
node_role="relay"
before=$(shasum "${xray_conf}" | awk '{print $1}')
reality_min_client_ver_repair >/dev/null 2>&1
after=$(shasum "${xray_conf}" | awk '{print $1}')
check "relay role leaves the config alone" test "${before}" = "${after}"
node_role="node"
rm -f "${xray_install_config_file}"

printf '%s\n' '--- G. wiring: install and core-update paths call the repair ---'
if declare -f install_xray_reality | grep -q "reality_min_client_ver_repair"; then
    ok "install_xray_reality repairs the generated config"
else
    bad "install_xray_reality does not repair the generated config"
fi
if declare -f xray_update | grep -q "reality_min_client_ver_repair"; then
    ok "xray_update repairs existing reality configs before restarting"
else
    bad "xray_update does not repair existing reality configs"
fi
if jq -e '.inbounds[0].streamSettings.realitySettings.minClientVer == "1.0.0"' \
    "${REPO_DIR}/config/vless_reality.json" >/dev/null 2>&1; then
    ok "the shipped reality template carries the value"
else
    bad "the shipped reality template still omits minClientVer"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
