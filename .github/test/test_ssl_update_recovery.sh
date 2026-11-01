#!/usr/bin/env bash
#
# Stage 01 regression tests: scripts/ssl_update.sh must never leave a
# previously running Nginx down when certificate renewal fails, must not start
# a unit that was stopped before the run, and must pre-check its prerequisites
# before stopping anything.
#
# Everything runs against a temporary root with stubbed systemctl/acme.sh, so
# no real service is touched.
#
# Usage: bash .github/test/test_ssl_update_recovery.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="${REPO_DIR}/scripts/ssl_update.sh"

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

[[ -f "${SCRIPT}" ]] || { echo "FATAL: ${SCRIPT} not found"; exit 1; }

CASE_DIR=""
STUB_CERT_DIR=""
export STUB_CERT_DIR=""

unit_state() { cat "${CASE_DIR}/$1.state" 2>/dev/null || echo inactive; }
set_unit_state() { printf '%s\n' "$2" >"${CASE_DIR}/$1.state"; }

systemctl_log() { cat "${CASE_DIR}/systemctl.log" 2>/dev/null || true; }

systemctl() {
    printf '%s\n' "$*" >>"${CASE_DIR}/systemctl.log"
    local action="$1" unit="" arg
    for arg in "$@"; do unit="${arg}"; done
    case "${action}" in
    is-active)
        [[ "$(unit_state "${unit}")" == "active" ]] || return 3
        return 0
        ;;
    stop)
        if [[ "${unit}" == "nginx" && -f "${CASE_DIR}/fail_stop" ]]; then
            return 1
        fi
        set_unit_state "${unit}" inactive
        return 0
        ;;
    start)
        if [[ "${unit}" == "nginx" && -f "${CASE_DIR}/fail_start" ]]; then
            return 1
        fi
        set_unit_state "${unit}" active
        return 0
        ;;
    restart)
        if [[ "${unit}" == "nginx" && -f "${CASE_DIR}/fail_start" ]]; then
            return 1
        fi
        set_unit_state "${unit}" active
        return 0
        ;;
    esac
    return 0
}

getent() {
    [[ -f "${CASE_DIR}/missing_group" ]] && return 2
    return 0
}

chown() { return 0; }
chmod() { [[ -f "${CASE_DIR}/fail_chmod" ]] && return 1; return 0; }

write_acme_stub() {
    local acme_dir="${CASE_DIR}/acme"
    mkdir -p "${acme_dir}"
    cat >"${acme_dir}/acme.sh" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$STUB_CASE_DIR/acme.log"
case "$*" in
  *--installcert*)
    [ ! -f "$STUB_CASE_DIR/fail_installcert" ] || exit 1
    : >"$STUB_CERT_DIR/xray.crt"
    : >"$STUB_CERT_DIR/xray.key"
    ;;
  --cron*)
    [ ! -f "$STUB_CASE_DIR/fail_cron" ] || exit 1
    ;;
esac
exit 0
STUB
    /bin/chmod 755 "${acme_dir}/acme.sh"
}

# prepare_case <name> <nginx-state> [xray-state]
prepare_case() {
    local name="$1" nginx_state="$2" xray_state="${3:-active}"
    CASE_DIR="${TMP_ROOT}/${name}"
    rm -rf "${CASE_DIR}"
    mkdir -p "${CASE_DIR}/idleleo/conf" "${CASE_DIR}/idleleo/cert"
    printf '%s\n' "${nginx_state}" >"${CASE_DIR}/nginx.state"
    printf '%s\n' "${xray_state}" >"${CASE_DIR}/xray.state"
    : >"${CASE_DIR}/systemctl.log"
    printf '{"host":"example.com"}\n' >"${CASE_DIR}/idleleo/conf/install_config.json"
    : >"${CASE_DIR}/nginx.service"
    : >"${CASE_DIR}/xray.service"
    write_acme_stub
    export STUB_CASE_DIR="${CASE_DIR}"
    STUB_CERT_DIR="${CASE_DIR}/idleleo/cert"
    export STUB_CERT_DIR
    IDLELEO_DIR="${CASE_DIR}/idleleo"
    IDLELEO_CERT_DIR="${CASE_DIR}/idleleo/cert"
    IDLELEO_NGINX_UNIT="${CASE_DIR}/nginx.service"
    IDLELEO_XRAY_UNIT="${CASE_DIR}/xray.service"
    IDLELEO_ACME_HOME="${CASE_DIR}/acme"
    XRAY_UPDATE_LOCK_FILE="${CASE_DIR}/update.lock"
    IDLELEO_CERT_GROUP="idleleo-nginx"
    export IDLELEO_DIR IDLELEO_CERT_DIR IDLELEO_NGINX_UNIT IDLELEO_XRAY_UNIT \
        IDLELEO_ACME_HOME XRAY_UPDATE_LOCK_FILE IDLELEO_CERT_GROUP
}

run_update() {
    # Re-source so the module re-reads the case paths, then run main.
    # shellcheck source=/dev/null
    source "${SCRIPT}"
    ssl_update_main
}

echo "============================================================"
echo "  ssl_update.sh certificate renewal recovery tests"
echo "============================================================"

# ---- 1. installcert failure keeps a running Nginx running ----------
prepare_case installcert_fail active active
touch "${CASE_DIR}/fail_installcert"
run_update >/dev/null 2>"${CASE_DIR}/stderr"
rc=$?
[[ ${rc} -ne 0 ]] && ok "installcert failure returns non-zero" \
    || bad "installcert failure returned 0"
[[ "$(unit_state nginx)" == "active" ]] && ok "installcert failure restores a running Nginx" \
    || bad "installcert failure left Nginx stopped"
grep -q "installcert failed" "${CASE_DIR}/stderr" &&
    ok "installcert failure is reported on stderr" ||
    bad "installcert failure was not reported"

# ---- 2. permission failure keeps a running Nginx running -----------
prepare_case chmod_fail active active
touch "${CASE_DIR}/fail_chmod"
run_update >/dev/null 2>"${CASE_DIR}/stderr"
rc=$?
[[ ${rc} -ne 0 ]] && ok "certificate permission failure returns non-zero" \
    || bad "certificate permission failure returned 0"
[[ "$(unit_state nginx)" == "active" ]] && ok "certificate permission failure restores a running Nginx" \
    || bad "certificate permission failure left Nginx stopped"
grep -q "layered certificate permissions" "${CASE_DIR}/stderr" &&
    ok "permission failure is reported" || bad "permission failure was not reported"

# ---- 3. a stopped Nginx is never started on failure ----------------
prepare_case stopped_fail inactive active
touch "${CASE_DIR}/fail_installcert"
run_update >/dev/null 2>&1
rc=$?
[[ ${rc} -ne 0 ]] && ok "failure with an initially stopped Nginx returns non-zero" \
    || bad "failure with an initially stopped Nginx returned 0"
[[ "$(unit_state nginx)" == "inactive" ]] && ok "initially stopped Nginx stays stopped on failure" \
    || bad "initially stopped Nginx was started on failure"

# ---- 4. a stopped Nginx is never started on success ----------------
prepare_case stopped_ok inactive active
run_update >/dev/null 2>&1
rc=$?
[[ ${rc} -eq 0 ]] && ok "renewal succeeds with an initially stopped Nginx" \
    || bad "renewal failed with an initially stopped Nginx"
[[ "$(unit_state nginx)" == "inactive" ]] && ok "initially stopped Nginx stays stopped on success" \
    || bad "initially stopped Nginx was started on success"
if systemctl_log | grep -q "^start nginx"; then
    bad "no Nginx start was expected; got: $(systemctl_log | tr '\n' ';')"
else
    ok "no Nginx start command is issued for a stopped unit"
fi

# ---- 5. success path: one restart, Nginx serving again -------------
prepare_case success active active
run_update >/dev/null 2>"${CASE_DIR}/stderr"
rc=$?
[[ ${rc} -eq 0 ]] && ok "successful renewal returns 0" || bad "successful renewal returned ${rc}"
[[ "$(unit_state nginx)" == "active" ]] && ok "successful renewal leaves Nginx running" \
    || bad "successful renewal left Nginx stopped"
restarts=$(systemctl_log | grep -c "^restart xray$")
[[ "${restarts}" == "1" ]] && ok "Xray is restarted exactly once" \
    || bad "Xray restart count was ${restarts}, expected 1"
starts=$(systemctl_log | grep -c "^start nginx$")
[[ "${starts}" == "1" ]] && ok "Nginx is started exactly once" \
    || bad "Nginx start count was ${starts}, expected 1"
[[ -d "${CASE_DIR}/idleleo/ssl_update_running" ]] &&
    bad "ssl update lock directory was not cleaned up" ||
    ok "ssl update lock directory is cleaned up"

# ---- 6. inactive Xray is not started by the renewal ----------------
prepare_case xray_inactive active inactive
run_update >/dev/null 2>&1
if systemctl_log | grep -q "restart xray"; then
    bad "inactive Xray was restarted"
else
    ok "inactive Xray is left untouched"
fi

# ---- 7. preflight prevents stopping Nginx at all -------------------
prepare_case missing_group active active
touch "${CASE_DIR}/missing_group"
run_update >/dev/null 2>"${CASE_DIR}/stderr"
rc=$?
[[ ${rc} -ne 0 ]] && ok "missing certificate group fails the run" \
    || bad "missing certificate group was ignored"
if systemctl_log | grep -q "^stop nginx"; then
    bad "Nginx was stopped before the group pre-check"
else
    ok "Nginx is not stopped when a precondition is missing"
fi
[[ "$(unit_state nginx)" == "active" ]] && ok "Nginx keeps running after a pre-check failure" \
    || bad "Nginx stopped after a pre-check failure"

# ---- 8. unrecoverable Nginx start is reported with exit 2 ----------
prepare_case restart_fail active active
touch "${CASE_DIR}/fail_installcert" "${CASE_DIR}/fail_start"
run_update >/dev/null 2>"${CASE_DIR}/stderr"
rc=$?
[[ ${rc} -eq 2 ]] && ok "unrecoverable Nginx state returns exit code 2" \
    || bad "unrecoverable Nginx state returned ${rc}, expected 2"
grep -q "could not be restarted" "${CASE_DIR}/stderr" &&
    ok "unrecoverable Nginx state is reported clearly" ||
    bad "unrecoverable Nginx state was not reported"

# ---- 9. concurrent run is refused ---------------------------------
prepare_case locked active active
mkdir -p "${CASE_DIR}/idleleo/ssl_update_running"
run_update >/dev/null 2>"${CASE_DIR}/stderr"
rc=$?
[[ ${rc} -ne 0 ]] && ok "an in-flight renewal blocks a second run" \
    || bad "an in-flight renewal did not block a second run"
if systemctl_log | grep -q "^stop nginx"; then
    bad "a blocked run stopped Nginx"
else
    ok "a blocked run does not touch services"
fi
[[ "$(unit_state nginx)" == "active" ]] && ok "a blocked run leaves Nginx running" \
    || bad "a blocked run left Nginx stopped"

# ---- 10. shared update lock held by an install/update transaction --
prepare_case shared_lock active active
flock() { return 1; }
run_update >/dev/null 2>"${CASE_DIR}/stderr"
rc=$?
unset -f flock
[[ ${rc} -ne 0 ]] && ok "a held shared update lock aborts the renewal" \
    || bad "a held shared update lock did not abort the renewal"
grep -q "Another update process is holding" "${CASE_DIR}/stderr" &&
    ok "held shared update lock is reported" ||
    bad "held shared update lock was not reported"
if systemctl_log | grep -q "^stop nginx"; then
    bad "a lock-blocked run stopped Nginx"
else
    ok "a lock-blocked run does not stop Nginx"
fi

echo "============================================================"
echo "  PASS: ${PASS}  FAIL: ${FAIL}"
echo "============================================================"
[[ "${FAIL}" -eq 0 ]]
