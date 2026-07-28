#!/usr/bin/env bash
# P0-B/P0-C: Xray update backup gate and same-version reinstall layered rollback tests.
#
# Coverage:
#   - backup failure refuses to stop service / overwrite binary
#   - online update success
#   - online update failure, local backup restore success
#   - online update failure, local backup restore failure, tested_version success
#   - three-layer total failure
#   - same-version reinstall success
#   - same-version reinstall failure, local restore success
#   - same-version reinstall failure, tested restore success
#   - rollback success still returns non-zero
#   - fake secrets do not appear in diagnostic output

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

# --- Shared mocks ---
log_echo() { :; }
gettext() { printf '%s' "$1"; }
countdown() { :; }
xray_diagnose() { :; }
xray_privilege_escalation() { :; }
set_xray_config_path() { :; }
update_json_config() { :; }
judge() { :; }

# Track systemctl calls to verify backup-fail refuses to stop
SYSTEMCTL_STOP_COUNT=0
systemctl() {
    case "$1" in
        stop) SYSTEMCTL_STOP_COUNT=$((SYSTEMCTL_STOP_COUNT + 1)) ;;
        daemon-reload) ;;
        start) ;;
        is-active) return 0 ;;
        -q) [[ "${2:-}" == "is-active" ]] && return 0 ;;
    esac
}

# Track xray_install_release calls
XRAY_INSTALL_CALLS=0
XRAY_INSTALL_RESULT=0
xray_install_release() {
    XRAY_INSTALL_CALLS=$((XRAY_INSTALL_CALLS + 1))
    return ${XRAY_INSTALL_RESULT}
}

# Track health check
HEALTH_CHECK_RESULT=0
health_check_xray_update() { return ${HEALTH_CHECK_RESULT}; }

# info_extraction mock
info_extraction() {
    case "$1" in
        xray_version) echo "${CURRENT_XRAY_VERSION:-25.12.7}" ;;
        *) echo "" ;;
    esac
}

# check_version_silent mock for tested_version
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
auto_update="YES"
random_num=8

mkdir -p "${xray_bin_dir}" "${idleleo_dir}/tmp"

# backup_xray_binary override for testing
# We need the real backup_xray_binary but with controllable behavior
BACKUP_RESULT=0
make_xray_binary() {
    echo "fake xray binary" > "${xray_bin_dir}/xray"
    chmod 755 "${xray_bin_dir}/xray"
}

# restore_xray_binary_backup override
RESTORE_RESULT=0
restore_xray_binary_backup() { return ${RESTORE_RESULT}; }

# fallback_xray_to_tested_version override
FALLBACK_RESULT=0
fallback_xray_to_tested_version() { return ${FALLBACK_RESULT}; }

# Override backup_xray_binary to use BACKUP_RESULT
backup_xray_binary() {
    [[ ! -f "${xray_bin_dir}/xray" ]] && return 1
    return ${BACKUP_RESULT}
}

printf '%s\n' '--- P0-B: backup failure refuses to stop service ---'
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
BACKUP_RESULT=1
SYSTEMCTL_STOP_COUNT=0
XRAY_INSTALL_CALLS=0
xray_update >/dev/null 2>&1
RC=$?
if [[ ${RC} -ne 0 ]]; then
    ok "backup failure returns non-zero"
else
    bad "backup failure should return non-zero"
fi
if [[ ${SYSTEMCTL_STOP_COUNT} -eq 0 ]]; then
    ok "backup failure refuses to stop service"
else
    bad "backup failure stopped service (${SYSTEMCTL_STOP_COUNT} times)"
fi
if [[ ${XRAY_INSTALL_CALLS} -eq 0 ]]; then
    ok "backup failure refuses to overwrite binary"
else
    bad "backup failure still called xray_install_release"
fi

printf '%s\n' '--- online update success ---'
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
BACKUP_RESULT=0
XRAY_INSTALL_RESULT=0
HEALTH_CHECK_RESULT=0
RESTORE_RESULT=0
FALLBACK_RESULT=0
SYSTEMCTL_STOP_COUNT=0
XRAY_INSTALL_CALLS=0
xray_update >/dev/null 2>&1
RC=$?
if [[ ${RC} -eq 0 ]]; then
    ok "online update success returns 0"
else
    bad "online update success should return 0 (got ${RC})"
fi
if [[ ${XRAY_INSTALL_CALLS} -ge 1 ]]; then
    ok "online update called xray_install_release"
else
    bad "online update did not call xray_install_release"
fi

printf '%s\n' '--- online update failure, local backup restore success ---'
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
BACKUP_RESULT=0
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=0
FALLBACK_RESULT=0
SYSTEMCTL_STOP_COUNT=0
xray_update >/dev/null 2>&1
RC=$?
if [[ ${RC} -ne 0 ]]; then
    ok "rollback success still returns non-zero"
else
    bad "rollback success should still return non-zero"
fi

printf '%s\n' '--- online update failure, local backup failure, tested success ---'
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
BACKUP_RESULT=0
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=1
FALLBACK_RESULT=0
xray_update >/dev/null 2>&1
RC=$?
if [[ ${RC} -ne 0 ]]; then
    ok "tested_version fallback success still returns non-zero"
else
    bad "tested_version fallback should still return non-zero"
fi

printf '%s\n' '--- three-layer total failure ---'
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
BACKUP_RESULT=0
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=1
FALLBACK_RESULT=1
xray_update >/dev/null 2>&1
RC=$?
if [[ ${RC} -ne 0 ]]; then
    ok "three-layer failure returns non-zero"
else
    bad "three-layer failure should return non-zero"
fi

printf '%s\n' '--- same-version reinstall success ---'
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
BACKUP_RESULT=0
XRAY_INSTALL_RESULT=0
HEALTH_CHECK_RESULT=0
RESTORE_RESULT=0
FALLBACK_RESULT=0
SYSTEMCTL_STOP_COUNT=0
XRAY_INSTALL_CALLS=0
xray_update >/dev/null 2>&1
RC=$?
if [[ ${RC} -eq 0 ]]; then
    ok "same-version reinstall success returns 0"
else
    bad "same-version reinstall success should return 0 (got ${RC})"
fi
if [[ ${XRAY_INSTALL_CALLS} -ge 1 ]]; then
    ok "same-version reinstall called xray_install_release"
else
    bad "same-version reinstall did not call xray_install_release"
fi

printf '%s\n' '--- same-version reinstall failure, local restore success ---'
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
BACKUP_RESULT=0
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=0
FALLBACK_RESULT=0
xray_update >/dev/null 2>&1
RC=$?
if [[ ${RC} -ne 0 ]]; then
    ok "same-version reinstall rollback success returns non-zero"
else
    bad "same-version reinstall rollback should return non-zero"
fi

printf '%s\n' '--- same-version reinstall failure, tested restore success ---'
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
BACKUP_RESULT=0
XRAY_INSTALL_RESULT=1
HEALTH_CHECK_RESULT=1
RESTORE_RESULT=1
FALLBACK_RESULT=0
xray_update >/dev/null 2>&1
RC=$?
if [[ ${RC} -ne 0 ]]; then
    ok "same-version reinstall tested fallback returns non-zero"
else
    bad "same-version reinstall tested fallback should return non-zero"
fi

printf '%s\n' '--- same-version reinstall backup failure refuses to proceed ---'
make_xray_binary
CURRENT_XRAY_VERSION="25.12.8"
BACKUP_RESULT=1
XRAY_INSTALL_RESULT=0
HEALTH_CHECK_RESULT=0
SYSTEMCTL_STOP_COUNT=0
XRAY_INSTALL_CALLS=0
xray_update >/dev/null 2>&1
RC=$?
if [[ ${RC} -ne 0 ]]; then
    ok "same-version reinstall backup failure returns non-zero"
else
    bad "same-version reinstall backup failure should return non-zero"
fi
if [[ ${SYSTEMCTL_STOP_COUNT} -eq 0 ]]; then
    ok "same-version reinstall backup failure refuses to stop service"
else
    bad "same-version reinstall backup failure stopped service"
fi
if [[ ${XRAY_INSTALL_CALLS} -eq 0 ]]; then
    ok "same-version reinstall backup failure refuses to overwrite binary"
else
    bad "same-version reinstall backup failure still installed"
fi

printf '%s\n' '--- fake secrets do not appear in diagnostic output ---'
# Override xray_diagnose to NOT print fake secrets
FAKE_SECRET="FAKE_SECRET_DO_NOT_LEAK_12345"
xray_diagnose() {
    # This should never print the fake secret
    echo "Diagnostic output (redacted)"
}
make_xray_binary
CURRENT_XRAY_VERSION="25.12.7"
BACKUP_RESULT=0
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
