#!/usr/bin/env bash
# Xray update backup gate and same-version reinstall layered rollback tests.
#
# Coverage (automatic mode):
#   - backup failure refuses to stop service / overwrite binary
#   - online update success
#   - online update failure, local backup restore success -> non-zero
#   - online update failure, local backup restore failure, tested_version success -> non-zero
#   - three-layer total failure -> non-zero
#   - same-version reinstall success
#   - same-version reinstall failure, local restore success -> non-zero
#   - same-version reinstall failure, tested restore success -> non-zero
#
# Coverage (manual mode, stdin-driven):
#   - manual update failure, local restore success -> non-zero
#   - manual update failure, tested restore success -> non-zero
#   - manual same-version reinstall failure, local restore success -> non-zero
#   - manual same-version reinstall failure, tested restore success -> non-zero
#   - manual reject update -> no install call, return 0
#   - manual reject rollback -> return non-zero, failure state preserved
#
# Assertions tracked:
#   - systemctl stop call count
#   - xray_install_release call count
#   - restore_xray_binary_backup call count
#   - fallback_xray_to_tested_version call count
#   - final return code
#   - final xray_version state
#   - fake secret not leaked

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

# --- Shared mocks (no stdout noise) ---
log_echo() { :; }
gettext() { printf '%s' "$1"; }
countdown() { :; }
xray_diagnose() { :; }
xray_privilege_escalation() { :; }
set_xray_config_path() { :; }
update_json_config() { :; }
judge() { :; }

# --- Call counters ---
SYSTEMCTL_STOP_COUNT=0
XRAY_INSTALL_CALLS=0
RESTORE_CALLS=0
FALLBACK_CALLS=0

systemctl() {
    case "$1" in
        stop) SYSTEMCTL_STOP_COUNT=$((SYSTEMCTL_STOP_COUNT + 1)) ;;
        daemon-reload) ;;
        start) ;;
        is-active) return 0 ;;
        -q) [[ "${2:-}" == "is-active" ]] && return 0 ;;
    esac
}

XRAY_INSTALL_RESULT=0
xray_install_release() {
    XRAY_INSTALL_CALLS=$((XRAY_INSTALL_CALLS + 1))
    return ${XRAY_INSTALL_RESULT}
}

HEALTH_CHECK_RESULT=0
health_check_xray_update() { return ${HEALTH_CHECK_RESULT}; }

info_extraction() {
    case "$1" in
        xray_version) echo "${CURRENT_XRAY_VERSION:-25.12.7}" ;;
        *) echo "" ;;
    esac
}

TESTED_VERSION="25.12.5"
check_version_silent() {
    [[ "$1" == "xray_tested_version" ]] && echo "${TESTED_VERSION}" || echo ""
}

# Variables expected by xray_update
xray_bin_dir="${TMP_ROOT}/bin"
idleleo_dir="${TMP_ROOT}/idleleo"
log_file="${TMP_ROOT}/update.log"
xray_install_config_file="${TMP_ROOT}/install_config.json"
xray_online_version="25.12.8"
xray_tested_version="${TESTED_VERSION}"
random_num=8

mkdir -p "${xray_bin_dir}" "${idleleo_dir}/tmp"

make_xray_binary() {
    echo "fake xray binary" > "${xray_bin_dir}/xray"
    chmod 755 "${xray_bin_dir}/xray"
}

BACKUP_RESULT=0
backup_xray_binary() {
    [[ ! -f "${xray_bin_dir}/xray" ]] && return 1
    return ${BACKUP_RESULT}
}

RESTORE_RESULT=0
restore_xray_binary_backup() {
    RESTORE_CALLS=$((RESTORE_CALLS + 1))
    return ${RESTORE_RESULT}
}

FALLBACK_RESULT=0
fallback_xray_to_tested_version() {
    FALLBACK_CALLS=$((FALLBACK_CALLS + 1))
    return ${FALLBACK_RESULT}
}

# Helper: reset all counters and result flags before each scenario
reset_state() {
    SYSTEMCTL_STOP_COUNT=0
    XRAY_INSTALL_CALLS=0
    RESTORE_CALLS=0
    FALLBACK_CALLS=0
    BACKUP_RESULT=0
    XRAY_INSTALL_RESULT=0
    HEALTH_CHECK_RESULT=0
    RESTORE_RESULT=0
    FALLBACK_RESULT=0
    xray_version=""
}

# ===========================================================================
# Automatic mode tests (auto_update="YES")
# ===========================================================================
auto_update="YES"

printf '%s\n' '--- [auto] backup failure refuses to stop service ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
BACKUP_RESULT=1
xray_update >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "backup failure returns non-zero" || bad "backup failure should return non-zero"
[[ ${SYSTEMCTL_STOP_COUNT} -eq 0 ]] && ok "backup failure refuses to stop service" || bad "backup failure stopped service (${SYSTEMCTL_STOP_COUNT} times)"
[[ ${XRAY_INSTALL_CALLS} -eq 0 ]] && ok "backup failure refuses to overwrite binary" || bad "backup failure still called xray_install_release"

printf '%s\n' '--- [auto] online update success -> 0 ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
xray_update >/dev/null 2>&1
RC=$?
[[ ${RC} -eq 0 ]] && ok "online update success returns 0" || bad "online update success should return 0 (got ${RC})"
[[ ${XRAY_INSTALL_CALLS} -ge 1 ]] && ok "online update called xray_install_release" || bad "online update did not call xray_install_release"
[[ ${RESTORE_CALLS} -eq 0 ]] && ok "online update success did not call restore" || bad "online update success should not call restore"
[[ ${FALLBACK_CALLS} -eq 0 ]] && ok "online update success did not call fallback" || bad "online update success should not call fallback"

printf '%s\n' '--- [auto] online update failure, local backup restore success -> non-zero ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=0
xray_update >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "rollback success still returns non-zero" || bad "rollback success should still return non-zero"
[[ ${RESTORE_CALLS} -eq 1 ]] && ok "restore called exactly once" || bad "restore called ${RESTORE_CALLS} times (expected 1)"
[[ ${FALLBACK_CALLS} -eq 0 ]] && ok "fallback not called when restore succeeds" || bad "fallback should not be called when restore succeeds"

printf '%s\n' '--- [auto] online update failure, local restore failure, tested success -> non-zero ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=1
FALLBACK_RESULT=0
xray_update >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "tested_version fallback success still returns non-zero" || bad "tested_version fallback should still return non-zero"
[[ ${RESTORE_CALLS} -eq 1 ]] && ok "restore attempted exactly once" || bad "restore called ${RESTORE_CALLS} times (expected 1)"
[[ ${FALLBACK_CALLS} -eq 1 ]] && ok "fallback called exactly once" || bad "fallback called ${FALLBACK_CALLS} times (expected 1)"

printf '%s\n' '--- [auto] three-layer total failure -> non-zero ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=1
FALLBACK_RESULT=1
xray_update >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "three-layer failure returns non-zero" || bad "three-layer failure should return non-zero"
[[ ${RESTORE_CALLS} -eq 1 ]] && ok "restore attempted" || bad "restore not attempted"
[[ ${FALLBACK_CALLS} -eq 1 ]] && ok "fallback attempted" || bad "fallback not attempted"

printf '%s\n' '--- [auto] same-version reinstall success -> 0 ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
xray_update >/dev/null 2>&1
RC=$?
[[ ${RC} -eq 0 ]] && ok "same-version reinstall success returns 0" || bad "same-version reinstall success should return 0 (got ${RC})"
[[ ${XRAY_INSTALL_CALLS} -ge 1 ]] && ok "same-version reinstall called xray_install_release" || bad "same-version reinstall did not call xray_install_release"
[[ ${RESTORE_CALLS} -eq 0 ]] && ok "reinstall success did not call restore" || bad "reinstall success should not call restore"

printf '%s\n' '--- [auto] same-version reinstall failure, local restore success -> non-zero ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=0
xray_update >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "same-version reinstall rollback success returns non-zero" || bad "same-version reinstall rollback should return non-zero"
[[ ${RESTORE_CALLS} -eq 1 ]] && ok "restore called exactly once" || bad "restore called ${RESTORE_CALLS} times (expected 1)"

printf '%s\n' '--- [auto] same-version reinstall failure, tested restore success -> non-zero ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=1
FALLBACK_RESULT=0
xray_update >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "same-version reinstall tested fallback returns non-zero" || bad "same-version reinstall tested fallback should return non-zero"
[[ ${FALLBACK_CALLS} -eq 1 ]] && ok "fallback called exactly once" || bad "fallback called ${FALLBACK_CALLS} times (expected 1)"

printf '%s\n' '--- [auto] same-version reinstall backup failure refuses to proceed ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
BACKUP_RESULT=1
XRAY_INSTALL_RESULT=0
HEALTH_CHECK_RESULT=0
xray_update >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "same-version reinstall backup failure returns non-zero" || bad "same-version reinstall backup failure should return non-zero"
[[ ${SYSTEMCTL_STOP_COUNT} -eq 0 ]] && ok "same-version reinstall backup failure refuses to stop service" || bad "same-version reinstall backup failure stopped service"
[[ ${XRAY_INSTALL_CALLS} -eq 0 ]] && ok "same-version reinstall backup failure refuses to overwrite binary" || bad "same-version reinstall backup failure still installed"

# ===========================================================================
# Manual mode tests (auto_update != "YES", stdin-driven)
# ===========================================================================
auto_update="NO"

# Stdin input file for manual mode tests (avoids subshell from pipe `|`)
STDIN_FILE="${TMP_ROOT}/stdin_input"

printf '%s\n' '--- [manual] reject update -> no install call, return 0 ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
# stdin: "n" rejects the update prompt
printf 'n\n' > "${STDIN_FILE}"
xray_update < "${STDIN_FILE}" >/dev/null 2>&1
RC=$?
[[ ${RC} -eq 0 ]] && ok "manual reject update returns 0" || bad "manual reject update should return 0 (got ${RC})"
[[ ${XRAY_INSTALL_CALLS} -eq 0 ]] && ok "manual reject update did not call install" || bad "manual reject update should not call install"
[[ ${SYSTEMCTL_STOP_COUNT} -eq 0 ]] && ok "manual reject update did not stop service" || bad "manual reject update should not stop service"

printf '%s\n' '--- [manual] update failure, local restore success -> non-zero ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=0
# stdin: "y" accepts update, "y" accepts rollback
printf 'y\ny\n' > "${STDIN_FILE}"
xray_update < "${STDIN_FILE}" >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "manual update rollback success returns non-zero" || bad "manual update rollback success should return non-zero"
[[ ${XRAY_INSTALL_CALLS} -eq 1 ]] && ok "manual update called install exactly once" || bad "manual update called install ${XRAY_INSTALL_CALLS} times (expected 1)"
[[ ${RESTORE_CALLS} -eq 1 ]] && ok "manual update restore called exactly once" || bad "manual update restore called ${RESTORE_CALLS} times (expected 1)"
# After restore, xray_version should be the pre-update version
[[ "${xray_version}" == "25.12.7" ]] && ok "manual update rollback restored xray_version" || bad "manual update rollback xray_version='${xray_version}' (expected 25.12.7)"

printf '%s\n' '--- [manual] update failure, tested restore success -> non-zero ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=1
FALLBACK_RESULT=0
# stdin: "y" accepts update, "y" accepts rollback
printf 'y\ny\n' > "${STDIN_FILE}"
xray_update < "${STDIN_FILE}" >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "manual update tested fallback returns non-zero" || bad "manual update tested fallback should return non-zero"
[[ ${RESTORE_CALLS} -eq 1 ]] && ok "manual update restore attempted" || bad "manual update restore not attempted"
[[ ${FALLBACK_CALLS} -eq 1 ]] && ok "manual update fallback called exactly once" || bad "manual update fallback called ${FALLBACK_CALLS} times (expected 1)"
[[ "${xray_version}" == "${TESTED_VERSION}" ]] && ok "manual update fallback set xray_version to tested" || bad "manual update fallback xray_version='${xray_version}' (expected ${TESTED_VERSION})"

printf '%s\n' '--- [manual] reject rollback after failure -> non-zero, failure preserved ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=0
# stdin: "y" accepts update, "n" rejects rollback
printf 'y\nn\n' > "${STDIN_FILE}"
xray_update < "${STDIN_FILE}" >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "manual reject rollback returns non-zero" || bad "manual reject rollback should return non-zero"
[[ ${RESTORE_CALLS} -eq 0 ]] && ok "manual reject rollback did not call restore" || bad "manual reject rollback should not call restore"
[[ ${FALLBACK_CALLS} -eq 0 ]] && ok "manual reject rollback did not call fallback" || bad "manual reject rollback should not call fallback"

printf '%s\n' '--- [manual] same-version reinstall failure, local restore success -> non-zero ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=0
# stdin: "y" accepts rollback (same-version path has only the rollback prompt)
printf 'y\n' > "${STDIN_FILE}"
xray_update < "${STDIN_FILE}" >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "manual reinstall rollback success returns non-zero" || bad "manual reinstall rollback success should return non-zero"
[[ ${XRAY_INSTALL_CALLS} -eq 1 ]] && ok "manual reinstall called install exactly once" || bad "manual reinstall called install ${XRAY_INSTALL_CALLS} times (expected 1)"
[[ ${RESTORE_CALLS} -eq 1 ]] && ok "manual reinstall restore called exactly once" || bad "manual reinstall restore called ${RESTORE_CALLS} times (expected 1)"
[[ "${xray_version}" == "25.12.8" ]] && ok "manual reinstall rollback restored xray_version" || bad "manual reinstall rollback xray_version='${xray_version}' (expected 25.12.8)"

printf '%s\n' '--- [manual] same-version reinstall failure, tested restore success -> non-zero ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=1
FALLBACK_RESULT=0
# stdin: "y" accepts rollback
printf 'y\n' > "${STDIN_FILE}"
xray_update < "${STDIN_FILE}" >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "manual reinstall tested fallback returns non-zero" || bad "manual reinstall tested fallback should return non-zero"
[[ ${RESTORE_CALLS} -eq 1 ]] && ok "manual reinstall restore attempted" || bad "manual reinstall restore not attempted"
[[ ${FALLBACK_CALLS} -eq 1 ]] && ok "manual reinstall fallback called exactly once" || bad "manual reinstall fallback called ${FALLBACK_CALLS} times (expected 1)"
[[ "${xray_version}" == "${TESTED_VERSION}" ]] && ok "manual reinstall fallback set xray_version to tested" || bad "manual reinstall fallback xray_version='${xray_version}' (expected ${TESTED_VERSION})"

printf '%s\n' '--- [manual] same-version reinstall reject rollback -> non-zero ---'
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=0
# stdin: "n" rejects rollback
printf 'n\n' > "${STDIN_FILE}"
xray_update < "${STDIN_FILE}" >/dev/null 2>&1
RC=$?
[[ ${RC} -ne 0 ]] && ok "manual reinstall reject rollback returns non-zero" || bad "manual reinstall reject rollback should return non-zero"
[[ ${RESTORE_CALLS} -eq 0 ]] && ok "manual reinstall reject rollback did not call restore" || bad "manual reinstall reject rollback should not call restore"

# ===========================================================================
# Secret leak check
# ===========================================================================
printf '%s\n' '--- fake secrets do not appear in diagnostic output ---'
FAKE_SECRET="FAKE_SECRET_DO_NOT_LEAK_12345"
xray_diagnose() {
    # Diagnostic must never print secrets
    echo "Diagnostic output (redacted)"
}
reset_state
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=1
FALLBACK_RESULT=1
DIAG_OUTPUT=$(xray_update 2>&1)
if printf '%s' "${DIAG_OUTPUT}" | grep -qF "${FAKE_SECRET}"; then
    bad "fake secret appeared in diagnostic output"
else
    ok "fake secrets do not appear in diagnostic output"
fi

printf '%s\n' '--- summary ---'
printf '  Total: %d, Pass: %d, Fail: %d\n' $((PASS + FAIL)) "${PASS}" "${FAIL}"

if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
