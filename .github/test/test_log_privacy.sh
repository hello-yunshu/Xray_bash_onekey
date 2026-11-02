#!/usr/bin/env bash
# 3.3.1 H4: install.log and its directory are 0600/0700, and UUID mapping
# material is never persisted to the log (stdout-only).
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
log_dir="${TMP_ROOT}/logs"
LOG_FILE="${log_dir}/install.log"
mkdir -p "${log_dir}"
printf 'old\n' >"${LOG_FILE}"
chmod 644 "${LOG_FILE}" 2>/dev/null || true
enable_file_logging

mode=$(stat -c '%a' "${log_dir}" 2>/dev/null || echo missing)
[[ "${mode}" == "700" ]] && ok "log directory migrated to 0700" || bad "log directory mode=${mode}"
mode=$(stat -c '%a' "${LOG_FILE}" 2>/dev/null || echo missing)
[[ "${mode}" == "600" ]] && ok "install.log migrated to 0600" || bad "install.log mode=${mode}"

old_config_status="off"
change_user="yes"
mode_switch_reuse="no"
printf 'n\n' | UUID_set >"${TMP_ROOT}/uuid.out" 2>&1
UUID_GENERATED=$(grep -oE 'UUID: [0-9a-f-]{36}' "${TMP_ROOT}/uuid.out" | tail -1 | awk '{print $2}')
[[ -n "${UUID_GENERATED}" ]] && ok "UUID generated for test" || bad "UUID generation failed"
if grep -Fq "${UUID_GENERATED}" "${LOG_FILE}"; then
    bad "full UUID leaked into install.log"
else
    ok "full UUID not in install.log"
fi
if grep -Eq 'UUID 映射字符串: [a-z0-9]|UUID: [0-9a-f-]{36}' "${LOG_FILE}"; then
    bad "UUID mapping material leaked into install.log"
else
    ok "UUID mapping material not in install.log"
fi

mode_switch_reuse="yes"
UUID="11111111-1111-5111-8111-111111111111"
UUID_set >/dev/null 2>&1
if grep -Fq "${UUID}" "${LOG_FILE}"; then
    bad "mode-switch UUID leaked into install.log"
else
    ok "mode-switch UUID not in install.log"
fi

# Direct call on the install-success path. `basic_information` is what the
# installer runs after a successful install, so this covers the real logging
# side effect instead of only UUID_set.
echo "--- basic_information install-success path ---"
FAKE_IDC="fakeidc-logprivacy-123"
FAKE_UUID="22222222-2222-5222-8222-222222222222"
xray_info_file="${TMP_ROOT}/xray_info.inf"
tls_mode="None"
transport_mode="None"
shell_mode="test-mode"
ensure_reality_public_key() { :; }
none_mode_listen_address() { :; }
info_extraction() {
    case "$1" in
        idc) printf '%s\n' "${FAKE_IDC}" ;;
        id) printf '%s\n' "${FAKE_UUID}" ;;
        *) printf 'test\n' ;;
    esac
}
basic_information >/dev/null 2>&1
if grep -Fq "${FAKE_IDC}" "${xray_info_file}"; then
    ok "basic_information still prints the mapping string for the operator"
else
    bad "basic_information lost the mapping string"
fi
if grep -Fq "${FAKE_IDC}" "${LOG_FILE}"; then
    bad "basic_information leaked the mapping string into install.log"
else
    ok "basic_information does not leak the mapping string into install.log"
fi
if grep -Fq "${FAKE_UUID}" "${LOG_FILE}"; then
    bad "basic_information leaked the UUID into install.log"
else
    ok "basic_information does not leak the UUID into install.log"
fi
if grep -Eq '映射字符串: [A-Za-z0-9]' "${LOG_FILE}"; then
    bad "install.log still contains mapping-string material"
else
    ok "install.log contains no mapping-string material after basic_information"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
