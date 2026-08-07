#!/usr/bin/env bash
# install.sh::uninstall_all() two-phase uninstall fault-injection tests.
#
# The host remove phase (uninstall_all) must route its REAL accumulated exit
# code into the Rill two-phase contract: prepare -> (host phase) -> post-verify
# -> commit/abort. This test targets uninstall_all directly (not the standalone
# rill_xray_agent_uninstall.sh) and injects failures at every critical step:
#
#   1. rxa_uninstall_prepare fails                -> return 1, no removal
#   2. stop_service_all fails                     -> aborts (commit must NOT run)
#   3. acme_cron_cleanup fails                    -> aborts
#   4. systemctl disable xray fails               -> aborts
#   5. xray_install_release remove --purge fails  -> aborts
#   6. Xray safe_rm (config dir) fails            -> aborts
#   7. systemctl disable nginx fails              -> aborts
#   8. Nginx safe_rm fails                        -> aborts
#   9. daemon-reload fails                        -> aborts
#  10. host post-verify fails                     -> aborts
#  11. all-success path                           -> commit
#
# Assertions:
#   - a failed host phase never routes to commit (must abort)
#   - successful host phase + post-verify routes to commit
#   - the real host rc is never masked by a trailing success log
#
# Design mirrors test_reinstall_call_chain.sh: _TEST_MODE=1 source install.sh,
# mock system commands, run the real uninstall_all function.
#
# Run: bash .github/test/test_install_uninstall_transaction.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

# --- quiet mocks: no stdout noise, no side effects ---
log_echo() { :; }
gettext() { printf '%s' "$1"; }

# uninstall_all branches on the OS id (from /etc/os-release); give it a value.
ID="${ID:-debian}"

# --- Control switches (set by each scenario) ---
PREPARE_FAIL=0
STOP_FAIL=0
ACME_FAIL=0
DISABLE_XRAY_FAIL=0
XRAY_REMOVE_FAIL=0
XRAY_RM_FAIL=0
DISABLE_NGINX_FAIL=0
NGINX_RM_FAIL=0
DAEMON_RELOAD_FAIL=0
POST_VERIFY_FAIL=0

# Record the last rc routed into rxa_uninstall_finish (the commit/abort gate).
# Written to a file because uninstall_all runs in a subshell.
FINISH_FILE="${TMP_DIR:-$(mktemp -d)}/finish.out"
RESET_FINISH() { : > "${FINISH_FILE}"; }
read_finish() { cat "${FINISH_FILE}" 2>/dev/null; }

# --- mock the host-removal dependencies so no real system/file is touched ---
stop_service_all()   { [[ ${STOP_FAIL} -eq 1 ]] && return 1; return 0; }
acme_cron_cleanup()  { [[ ${ACME_FAIL} -eq 1 ]] && return 1; return 0; }
systemctl() {
    case "${1:-}" in
        disable)
            case "${2:-}" in
                xray)  [[ ${DISABLE_XRAY_FAIL} -eq 1 ]] && return 1; return 0 ;;
                nginx) [[ ${DISABLE_NGINX_FAIL} -eq 1 ]] && return 1; return 0 ;;
            esac ;;
        daemon-reload) [[ ${DAEMON_RELOAD_FAIL} -eq 1 ]] && return 1; return 0 ;;
    esac
    return 0
}
xray_install_release() {
    # only the remove path is exercised by uninstall_all
    [[ ${XRAY_REMOVE_FAIL} -eq 1 ]] && return 1
    return 0
}
safe_rm() {
    local target="${2:-${1:-}}"
    # route by the sourcing call site: uninstall_xray removes config dir,
    # uninstall_nginx removes nginx dirs. Use the control flags by inspection.
    case "$target" in
        *"/conf/xray") [[ ${XRAY_RM_FAIL} -eq 1 ]] && return 1; return 0 ;;
        */nginx*)      [[ ${NGINX_RM_FAIL} -eq 1 ]] && return 1; return 0 ;;
    esac
    return 0
}
update_json_config() { return 0; }
safety_check() { :; }
check_file_integrity() { :; }

# --- Rill two-phase contract hooks (mock commit/abort to record routing) ---
rxa_uninstall_commit() { printf '0\n' > "${FINISH_FILE}"; return 0; }
rxa_uninstall_abort()  { printf '1\n' > "${FINISH_FILE}"; return 1; }
rxa_uninstall_finish() {
    if [[ "${1:-1}" == 0 ]]; then
        rxa_uninstall_commit
    else
        rxa_uninstall_abort
        return 1
    fi
}
rxa_host_post_verify() { [[ ${POST_VERIFY_FAIL} -eq 1 ]] && return 1; return 0; }

# uninstall_all reads two prompts (keep config / delete all scripts). Pre-set
# the variables and stub read so the "delete all scripts + keep config" branch
# is taken deterministically (that branch exercises the full post-verify path).
read() {
    if [[ "${2:-}" == "remove_config_fq" ]]; then
        return 0
    fi
    if [[ "${2:-}" == "remove_all_idleleo_file_fq" ]]; then
        return 0
    fi
    command read "$@"
}

# Force the delete-all branch (non-empty means "yes").
remove_config_fq="y"
remove_all_idleleo_file_fq="y"

# uninstall_all may traverse real paths during the delete-all branch; point the
# ones it actually touches at throwaway sandbox dirs.
SANDBOX="$(mktemp -d)"
trap 'rm -rf "${SANDBOX}"' EXIT
FINISH_FILE="${SANDBOX}/finish.out"
xray_bin_dir="${SANDBOX}/bin"
xray_conf_dir="${SANDBOX}/conf/xray"
nginx_dir="${SANDBOX}/nginx"
nginx_conf_dir="${SANDBOX}/conf/nginx"
xray_install_config_file="${SANDBOX}/install_config.json"
idleleo_commend_file="${SANDBOX}/idleleo"
idleleo_dir="${SANDBOX}/idleleo_dir"
idleleo_conf_dir="${SANDBOX}/idleleo_conf"
mkdir -p "${xray_bin_dir}" "${xray_conf_dir}" "${nginx_dir}" "${nginx_conf_dir}" "${idleleo_conf_dir}"
# uninstall_all only removes Xray when the binary is present (and Nginx when
# its dir exists); create both so the fault-injection paths exercise the real
# uninstall_xray/uninstall_nginx implementation.
touch "${xray_bin_dir}/xray"
printf 'x' > "${xray_install_config_file}"

reset_controls() {
    PREPARE_FAIL=0 STOP_FAIL=0 ACME_FAIL=0 DISABLE_XRAY_FAIL=0 XRAY_REMOVE_FAIL=0
    XRAY_RM_FAIL=0 DISABLE_NGINX_FAIL=0 NGINX_RM_FAIL=0 DAEMON_RELOAD_FAIL=0
    POST_VERIFY_FAIL=0
    : > "${FINISH_FILE}"
}

# run_uninstall_all: prepend a fake rxa_uninstall_prepare (control switch) and
# run uninstall_all in a subshell so its `exit` cannot kill the test.
run_uninstall_all() {
    (
        rxa_uninstall_prepare() { [[ ${PREPARE_FAIL} -eq 1 ]] && return 1; return 0; }
        uninstall_all
    )
    return $?
}

# ---------------------------------------------------------------------------
# Scenario 1: prepare fails -> return 1, no removal begins
# ---------------------------------------------------------------------------
reset_controls
PREPARE_FAIL=1
early_rc=0
early_rc=$(run_uninstall_all); early_rc=$?
if [[ "$early_rc" != 0 ]]; then
    ok "prepare failure exits non-zero"
else
    bad "prepare failure exits $early_rc (want non-zero)"
fi
[[ -z "$(read_finish)" ]] && ok "prepare failure never reaches commit/abort" || bad "prepare failure reached finish (finish=$(read_finish))"

# ---------------------------------------------------------------------------
# Scenario 2: stop_service_all fails -> aborts (never commits)
# ---------------------------------------------------------------------------
reset_controls
STOP_FAIL=1
rc=0; rc=$(run_uninstall_all); rc=$?
[[ "$rc" != 0 ]] && ok "stop_service_all failure exits non-zero" || bad "stop_service_all failure exits 0"
[[ "$(read_finish)" == "1" ]] && ok "stop_service_all failure routes to abort" || bad "stop_service_all failure routed finish=$(read_finish)"

# ---------------------------------------------------------------------------
# Scenario 3: acme_cron_cleanup fails -> aborts
# ---------------------------------------------------------------------------
reset_controls
ACME_FAIL=1
rc=0; rc=$(run_uninstall_all); rc=$?
[[ "$rc" != 0 ]] && ok "acme_cron_cleanup failure exits non-zero" || bad "acme_cron_cleanup failure exits 0"
[[ "$(read_finish)" == "1" ]] && ok "acme_cron_cleanup failure routes to abort" || bad "acme_cron_cleanup failure routed finish=$(read_finish)"

# ---------------------------------------------------------------------------
# Scenario 4: systemctl disable xray fails -> aborts
# ---------------------------------------------------------------------------
reset_controls
DISABLE_XRAY_FAIL=1
rc=0; rc=$(run_uninstall_all); rc=$?
[[ "$rc" != 0 ]] && ok "disable xray failure exits non-zero" || bad "disable xray failure exits 0"
[[ "$(read_finish)" == "1" ]] && ok "disable xray failure routes to abort" || bad "disable xray failure routed finish=$(read_finish)"

# ---------------------------------------------------------------------------
# Scenario 5: xray_install_release remove --purge fails -> aborts
# ---------------------------------------------------------------------------
reset_controls
XRAY_REMOVE_FAIL=1
rc=0; rc=$(run_uninstall_all); rc=$?
[[ "$rc" != 0 ]] && ok "xray remove failure exits non-zero" || bad "xray remove failure exits 0"
[[ "$(read_finish)" == "1" ]] && ok "xray remove failure routes to abort" || bad "xray remove failure routed finish=$(read_finish)"

# ---------------------------------------------------------------------------
# Scenario 6: Xray config dir safe_rm fails -> aborts
# ---------------------------------------------------------------------------
reset_controls
XRAY_RM_FAIL=1
rc=0; rc=$(run_uninstall_all); rc=$?
[[ "$rc" != 0 ]] && ok "xray config safe_rm failure exits non-zero" || bad "xray config safe_rm failure exits 0"
[[ "$(read_finish)" == "1" ]] && ok "xray config safe_rm failure routes to abort" || bad "xray config safe_rm failure routed finish=$(read_finish)"

# ---------------------------------------------------------------------------
# Scenario 7: systemctl disable nginx fails -> aborts
# ---------------------------------------------------------------------------
reset_controls
DISABLE_NGINX_FAIL=1
rc=0; rc=$(run_uninstall_all); rc=$?
[[ "$rc" != 0 ]] && ok "disable nginx failure exits non-zero" || bad "disable nginx failure exits 0"
[[ "$(read_finish)" == "1" ]] && ok "disable nginx failure routes to abort" || bad "disable nginx failure routed finish=$(read_finish)"

# ---------------------------------------------------------------------------
# Scenario 8: Nginx safe_rm fails -> aborts
# ---------------------------------------------------------------------------
reset_controls
NGINX_RM_FAIL=1
rc=0; rc=$(run_uninstall_all); rc=$?
[[ "$rc" != 0 ]] && ok "nginx safe_rm failure exits non-zero" || bad "nginx safe_rm failure exits 0"
[[ "$(read_finish)" == "1" ]] && ok "nginx safe_rm failure routes to abort" || bad "nginx safe_rm failure routed finish=$(read_finish)"

# ---------------------------------------------------------------------------
# Scenario 9: daemon-reload fails -> aborts
# ---------------------------------------------------------------------------
reset_controls
DAEMON_RELOAD_FAIL=1
rc=0; rc=$(run_uninstall_all); rc=$?
[[ "$rc" != 0 ]] && ok "daemon-reload failure exits non-zero" || bad "daemon-reload failure exits 0"
[[ "$(read_finish)" == "1" ]] && ok "daemon-reload failure routes to abort" || bad "daemon-reload failure routed finish=$(read_finish)"

# ---------------------------------------------------------------------------
# Scenario 10: host post-verify fails -> aborts (diagnostics retained)
# ---------------------------------------------------------------------------
reset_controls
POST_VERIFY_FAIL=1
rc=0; rc=$(run_uninstall_all); rc=$?
[[ "$rc" != 0 ]] && ok "post-verify failure exits non-zero" || bad "post-verify failure exits 0"
[[ "$(read_finish)" == "1" ]] && ok "post-verify failure routes to abort (never commits)" || bad "post-verify failure routed finish=$(read_finish)"

# ---------------------------------------------------------------------------
# Scenario 11: all-success -> host phase clean + post-verify pass -> commit
# ---------------------------------------------------------------------------
reset_controls
rc=0; rc=$(run_uninstall_all); rc=$?
[[ "$rc" == 0 ]] && ok "all-success uninstall exits 0" || bad "all-success uninstall exits $rc (want 0)"
[[ "$(read_finish)" == "0" ]] && ok "all-success routes to commit" || bad "all-success routed finish=$(read_finish)"

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" == 0 ]]