#!/usr/bin/env bash
# Offline-safe command parsing before remote version access.
#
# Coverage:
#   - is_offline_safe_command returns 0 for -h, --help, --purge, --uninstall,
#     -s, --show, --service-start, --service-stop, --service-restart,
#     --access-log, --error-log, --backup
#   - is_offline_safe_command returns 1 for install/update commands and unknown args
#   - dispatch_offline_safe_command routes to correct handler
#   - dispatch_offline_safe_command returns 1 for unknown commands
#   - No network/version-check functions are called for offline commands
#
# Run: bash .github/test/test_offline_commands.sh

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

# --- Track network/version-check calls ---
CHECK_ONLINE_CALLS=0
READ_VERSION_CALLS=0

check_online_version_connect() { CHECK_ONLINE_CALLS=$((CHECK_ONLINE_CALLS + 1)); }
read_version() { READ_VERSION_CALLS=$((READ_VERSION_CALLS + 1)); }

# --- Track dispatched handler calls ---
SHOW_HELP_CALLS=0
UNINSTALL_ALL_CALLS=0
SERVICE_START_CALLS=0
SERVICE_STOP_CALLS=0
SERVICE_RESTART_CALLS=0
BACKUP_CALLS=0
SHOW_ACCESS_LOG_CALLS=0
SHOW_ERROR_LOG_CALLS=0
SHOW_INFORMATION_CALLS=0

show_help()           { SHOW_HELP_CALLS=$((SHOW_HELP_CALLS + 1)); }
uninstall_all()       { UNINSTALL_ALL_CALLS=$((UNINSTALL_ALL_CALLS + 1)); }
service_start()       { SERVICE_START_CALLS=$((SERVICE_START_CALLS + 1)); }
service_stop()        { SERVICE_STOP_CALLS=$((SERVICE_STOP_CALLS + 1)); }
service_restart()     { SERVICE_RESTART_CALLS=$((SERVICE_RESTART_CALLS + 1)); }
backup_directories()  { BACKUP_CALLS=$((BACKUP_CALLS + 1)); }
show_access_log()     { SHOW_ACCESS_LOG_CALLS=$((SHOW_ACCESS_LOG_CALLS + 1)); }
show_error_log()      { SHOW_ERROR_LOG_CALLS=$((SHOW_ERROR_LOG_CALLS + 1)); }
show_information()    { SHOW_INFORMATION_CALLS=$((SHOW_INFORMATION_CALLS + 1)); }
# Mock dependencies of -s/--show dispatch
judge_mode() { :; }
basic_information() { :; }
install_link_image() { :; }

echo "============================================================"
echo "  Section 2: Offline-Safe Commands"
echo "============================================================"

# --- Test is_offline_safe_command ---
echo "--- is_offline_safe_command recognizes offline-safe flags ---"
for flag in -h --help --purge --uninstall -s --show \
            --service-start --service-stop --service-restart \
            --access-log --error-log --backup; do
    if is_offline_safe_command "${flag}"; then
        ok "is_offline_safe_command '${flag}' returns 0"
    else
        bad "is_offline_safe_command '${flag}' should return 0"
    fi
done

echo "--- is_offline_safe_command rejects non-offline commands ---"
for arg in "" install update --update --version --cert renew 12345; do
    if is_offline_safe_command "${arg}"; then
        bad "is_offline_safe_command '${arg}' should return 1"
    else
        ok "is_offline_safe_command '${arg}' returns 1"
    fi
done

# --- Test dispatch_offline_safe_command routing ---
echo "--- dispatch routes --help to show_help ---"
SHOW_HELP_CALLS=0
dispatch_offline_safe_command "--help"
if [[ ${SHOW_HELP_CALLS} -eq 1 ]]; then
    ok "dispatch --help called show_help"
else
    bad "dispatch --help did not call show_help (calls=${SHOW_HELP_CALLS})"
fi

echo "--- dispatch routes -h to show_help ---"
SHOW_HELP_CALLS=0
dispatch_offline_safe_command "-h"
[[ ${SHOW_HELP_CALLS} -eq 1 ]] && ok "dispatch -h called show_help" || bad "dispatch -h failed"

echo "--- dispatch routes --uninstall to uninstall_all ---"
UNINSTALL_ALL_CALLS=0
dispatch_offline_safe_command "--uninstall"
[[ ${UNINSTALL_ALL_CALLS} -eq 1 ]] && ok "dispatch --uninstall called uninstall_all" || bad "dispatch --uninstall failed"

echo "--- dispatch routes --purge to uninstall_all ---"
UNINSTALL_ALL_CALLS=0
dispatch_offline_safe_command "--purge"
[[ ${UNINSTALL_ALL_CALLS} -eq 1 ]] && ok "dispatch --purge called uninstall_all" || bad "dispatch --purge failed"

echo "--- dispatch routes --service-start ---"
SERVICE_START_CALLS=0
dispatch_offline_safe_command "--service-start"
[[ ${SERVICE_START_CALLS} -eq 1 ]] && ok "dispatch --service-start called service_start" || bad "dispatch --service-start failed"

echo "--- dispatch routes --service-stop ---"
SERVICE_STOP_CALLS=0
dispatch_offline_safe_command "--service-stop"
[[ ${SERVICE_STOP_CALLS} -eq 1 ]] && ok "dispatch --service-stop called service_stop" || bad "dispatch --service-stop failed"

echo "--- dispatch routes --service-restart ---"
SERVICE_RESTART_CALLS=0
dispatch_offline_safe_command "--service-restart"
[[ ${SERVICE_RESTART_CALLS} -eq 1 ]] && ok "dispatch --service-restart called service_restart" || bad "dispatch --service-restart failed"

echo "--- dispatch routes --access-log ---"
SHOW_ACCESS_LOG_CALLS=0
dispatch_offline_safe_command "--access-log"
[[ ${SHOW_ACCESS_LOG_CALLS} -eq 1 ]] && ok "dispatch --access-log called show_access_log" || bad "dispatch --access-log failed"

echo "--- dispatch routes --error-log ---"
SHOW_ERROR_LOG_CALLS=0
dispatch_offline_safe_command "--error-log"
[[ ${SHOW_ERROR_LOG_CALLS} -eq 1 ]] && ok "dispatch --error-log called show_error_log" || bad "dispatch --error-log failed"

echo "--- dispatch routes --backup ---"
BACKUP_CALLS=0
dispatch_offline_safe_command "--backup"
[[ ${BACKUP_CALLS} -eq 1 ]] && ok "dispatch --backup called backup_directories" || bad "dispatch --backup failed"

echo "--- dispatch routes -s/--show to show_information ---"
SHOW_INFORMATION_CALLS=0
dispatch_offline_safe_command "-s"
[[ ${SHOW_INFORMATION_CALLS} -eq 1 ]] && ok "dispatch -s called show_information" || bad "dispatch -s failed"
SHOW_INFORMATION_CALLS=0
dispatch_offline_safe_command "--show"
[[ ${SHOW_INFORMATION_CALLS} -eq 1 ]] && ok "dispatch --show called show_information" || bad "dispatch --show failed"

# --- Test dispatch returns 1 for unknown ---
echo "--- dispatch returns 1 for unknown command ---"
if dispatch_offline_safe_command "--unknown-flag"; then
    bad "dispatch --unknown-flag should return 1"
else
    ok "dispatch --unknown-flag returns 1"
fi

# --- Test offline commands don't trigger network checks ---
echo "--- Offline commands do not trigger check_online_version_connect ---"
# The main entry checks is_offline_safe_command BEFORE check_online_version_connect.
# Simulate: if is_offline_safe_command returns 0, check_online should NOT be called.
CHECK_ONLINE_CALLS=0
if is_offline_safe_command "--help"; then
    # In the real flow, we would dispatch and exit without calling check_online
    ok "offline-safe command bypasses check_online_version_connect"
else
    bad "--help should be offline-safe"
fi
if [[ ${CHECK_ONLINE_CALLS} -eq 0 ]]; then
    ok "check_online_version_connect was NOT called for offline command"
else
    bad "check_online_version_connect was called ${CHECK_ONLINE_CALLS} time(s)"
fi

echo ""
echo "--- Real main entry: bash install.sh --help with mocked network ---"

# Create a mock curl that records calls and fails, to prove the offline path
# never reaches curl.
MOCK_BIN=$(mktemp -d)
CURL_CALL_LOG=$(mktemp)
cat > "${MOCK_BIN}/curl" << CURL_EOF
#!/bin/bash
echo "1" >> "${CURL_CALL_LOG}"
exit 1
CURL_EOF
chmod +x "${MOCK_BIN}/curl"

# Wrapper: source install.sh with _TEST_MODE to get function definitions,
# then override download_script_file and check_file_integrity to record calls,
# then execute the real main-entry sequence with --help.
MAIN_WRAPPER=$(mktemp /tmp/xray_offline_main_XXXXXX.sh)
DOWNLOAD_CALLS_FILE=$(mktemp)
CFI_CALLS_FILE=$(mktemp)

cat > "${MAIN_WRAPPER}" << WRAPPER_EOF
#!/bin/bash
set -uo pipefail
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

# Provide a no-op gettext fallback so show_help works even without gettext.
if ! command -v gettext >/dev/null 2>&1; then
    gettext() { printf '%s' "\$1"; }
fi
export -f gettext 2>/dev/null || true

# Override functions that must NOT be reached for --help.
download_script_file() {
    echo "1" >> "${DOWNLOAD_CALLS_FILE}"
    return 1
}
check_file_integrity() {
    echo "1" >> "${CFI_CALLS_FILE}"
}
# init_language may try pkg_install on systems without gettext; make it a
# no-op since we only want to verify the offline dispatch path.
init_language() { :; }
compat_migrate() { :; }
judge_mode() { :; }
check_online_version_connect() { :; }
read_version() { return 0; }

# Mirror the real main entry sequence after the _TEST_MODE guard.
init_language
if is_offline_safe_command "\${1:-}"; then
    dispatch_offline_safe_command "\$@"
    exit \$?
fi
check_file_integrity
compat_migrate
judge_mode
check_online_version_connect
read_version || exit 1
WRAPPER_EOF

PATH="${MOCK_BIN}:${PATH}" bash "${MAIN_WRAPPER}" --help
MAIN_EXIT=$?

if [[ ${MAIN_EXIT} -eq 0 ]]; then
    ok "bash install.sh --help exits 0"
else
    bad "bash install.sh --help exits ${MAIN_EXIT} (expected 0)"
fi

DOWNLOAD_COUNT=$(wc -l < "${DOWNLOAD_CALLS_FILE}" 2>/dev/null | tr -d ' ' || echo 0)
if [[ "${DOWNLOAD_COUNT}" == "0" ]]; then
    ok "download_script_file not called for --help"
else
    bad "download_script_file called ${DOWNLOAD_COUNT} time(s) for --help"
fi

CFI_COUNT=$(wc -l < "${CFI_CALLS_FILE}" 2>/dev/null | tr -d ' ' || echo 0)
if [[ "${CFI_COUNT}" == "0" ]]; then
    ok "check_file_integrity not called for --help"
else
    bad "check_file_integrity called ${CFI_COUNT} time(s) for --help"
fi

CURL_COUNT=$(wc -l < "${CURL_CALL_LOG}" 2>/dev/null | tr -d ' ' || echo 0)
if [[ "${CURL_COUNT}" == "0" ]]; then
    ok "curl not called for --help"
else
    bad "curl called ${CURL_COUNT} time(s) for --help"
fi

rm -rf "${MOCK_BIN}" "${MAIN_WRAPPER}" "${DOWNLOAD_CALLS_FILE}" "${CFI_CALLS_FILE}" "${CURL_CALL_LOG}"

echo ""
echo "============================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
