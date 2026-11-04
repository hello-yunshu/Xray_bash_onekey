#!/usr/bin/env bash
# Xray traffic-stats idempotency regression.
#
# Covers:
#   1. First enable merges api/stats/policy into the main config and removes
#      the downloaded status_config.json (it is a merge source, not live config).
#   2. A second enable with stats already present leaves the file byte-identical.
#   3. Enable -> disable -> enable converges to the first enabled bytes.
#   4. No duplicate top-level api/stats/policy keys remain in the main file.
#   5. xray -test when a real xray binary is available (JSON validation otherwise).

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true
unset _TEST_MODE

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

idleleo_dir="${TMP_ROOT}/idleleo"
xray_conf_dir="${idleleo_dir}/conf/xray"
xray_conf="${xray_conf_dir}/config.json"
xray_status_conf="${xray_conf_dir}/status_config.json"
xray_install_config_file="${idleleo_dir}/conf/install_config.json"
LOG_FILE="${idleleo_dir}/logs/install.log"
mkdir -p "${xray_conf_dir}" "${idleleo_dir}/logs" /var/log/xray
cp "${REPO_DIR}/config/vless_reality.json" "${xray_conf}"
# The repository template intentionally carries placeholders. When a real
# Xray binary is available, replace them with a valid test UUID/key/shortId so
# the final xray -test exercises the merged stats config, not template values.
if command -v xray >/dev/null 2>&1; then
    _fixture_uuid=$(xray uuid 2>/dev/null || true)
    _fixture_key=$(xray x25519 2>/dev/null | awk '/^PrivateKey:/ {print $2; exit}')
    if [[ -n "${_fixture_uuid}" && -n "${_fixture_key}" ]]; then
        jq --arg uuid "${_fixture_uuid}" --arg key "${_fixture_key}" \
            '.inbounds[0].settings.clients[0].id = $uuid
             | .inbounds[0].streamSettings.realitySettings.privateKey = $key
             | .inbounds[0].streamSettings.realitySettings.shortIds = ["0123456789abcdef"]' \
            "${xray_conf}" >"${xray_conf}.fixture" &&
            mv "${xray_conf}.fixture" "${xray_conf}"
        chmod 600 "${xray_conf}"
    fi
fi
printf '{"shell_version":"3.3.1"}\n' >"${xray_install_config_file}"

log_echo() { printf '%s\n' "$*"; }
service_stop() { :; }
service_start() { :; }
judge() {
    local ret=$?
    if [[ "$1" == "-r" || "$1" == "--return" ]]; then shift; fi
    local desc="$1"
    if [[ $# -gt 1 ]]; then "${@:2}"; ret=$?; fi
    [[ ${ret} -eq 0 ]]
}
download_json_file() { cp "${REPO_DIR}/config/status_config.json" "$2"; }
# Test-local atomic jq writer; avoids chown to the runner account.
update_json_config() {
    local file="$1"
    shift
    jq "$@" "${file}" >"${file}.tmp" && mv "${file}.tmp" "${file}"
}

enable() { printf 'y\ny\n' | xray_status_add; }
disable() { printf 'y\n' | xray_status_add; }
keep_enabled() { printf 'n\n' | xray_status_add; }

# 1. First enable
enable >/dev/null || bad "first enable failed"
[[ -f "${xray_conf}" ]] && ok "main config exists" || bad "main config missing"
[[ ! -f "${xray_status_conf}" ]] && ok "status_config merge artifact removed" || bad "status_config left behind"
[[ "$(jq -r '.api.services[0] // empty' "${xray_conf}")" == "StatsService" ]] && \
    ok "api StatsService present" || bad "api StatsService missing"
[[ "$(jq -r '.policy.system.statsInboundUplink // empty' "${xray_conf}")" == "true" ]] && \
    ok "policy stats enabled" || bad "policy stats missing"
first_hash=$(sha256sum "${xray_conf}" | awk '{print $1}')
cp "${xray_conf}" "${TMP_ROOT}/first-enabled.json"

# 2. Repeat enable while already enabled
keep_enabled >/dev/null || bad "repeat enable failed"
second_hash=$(sha256sum "${xray_conf}" | awk '{print $1}')
[[ "${first_hash}" == "${second_hash}" ]] && ok "repeat enable is byte-identical" || bad "repeat enable changed config"
diff -q "${TMP_ROOT}/first-enabled.json" "${xray_conf}" >/dev/null && \
    ok "literal diff empty after repeat enable" || bad "literal diff non-empty after repeat enable"
[[ ! -f "${xray_status_conf}" ]] && ok "no status artifact after repeat" || bad "status artifact after repeat"

# 3. Enable -> disable -> enable
disable >/dev/null || bad "disable failed"
[[ "$(jq -r '.api // empty' "${xray_conf}")" == "" ]] && ok "api removed on disable" || bad "api not removed"
[[ "$(jq -r '.stats // empty' "${xray_conf}")" == "" ]] && ok "stats removed on disable" || bad "stats not removed"
[[ "$(jq -r '.policy // empty' "${xray_conf}")" == "" ]] && ok "policy removed on disable" || bad "policy not removed"
enable >/dev/null || bad "re-enable failed"
third_hash=$(sha256sum "${xray_conf}" | awk '{print $1}')
[[ "${first_hash}" == "${third_hash}" ]] && ok "enable->disable->enable converges" || bad "re-enable bytes differ"
[[ ! -f "${xray_status_conf}" ]] && ok "no status artifact after re-enable" || bad "status artifact after re-enable"

# 4. No duplicate top-level keys in the main file
for key in '"api"' '"stats"' '"policy"'; do
    count=$(grep -c -- "^  ${key}" "${xray_conf}")
    [[ "${count}" -eq 1 ]] && ok "single ${key} key" || bad "duplicate ${key} key count=${count}"
done

# 5. Real xray -test when installed; otherwise JSON validation.
if command -v xray >/dev/null 2>&1; then
    xray -test -config "${xray_conf}" >/dev/null 2>&1 && ok "xray -test passed" || bad "xray -test failed"
else
    jq empty "${xray_conf}" >/dev/null 2>&1 && ok "config JSON valid (xray binary absent)" || bad "config JSON invalid"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
