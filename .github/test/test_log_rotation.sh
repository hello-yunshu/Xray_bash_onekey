#!/usr/bin/env bash
# Isolated regression tests for logrotate rule generation and cleanup failures.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
LOG_MESSAGES=()
PACKAGE_REQUESTS=()
log_echo() { LOG_MESSAGES+=("$*"); }
gettext() { printf '%s' "$1"; }
pkg_install() {
    PACKAGE_REQUESTS+=("$1")
    [[ "$1" == "logrotate" ]]
}
read() {
    if (($# == 1)); then auto_clean_logs_fq=y; else builtin read "$@"; fi
}
get_nginx_worker_user() { printf 'idleleo-nginx'; }
get_nginx_worker_group() { printf 'idleleo-nginx'; }
judge() {
    local desc ret=$?
    [[ "$1" == "-r" || "$1" == "--return" ]] && shift
    desc="$1"
    shift
    if (($#)); then "$@"; ret=$?; fi
    return "$ret"
}
systemctl() {
    printf '%s\n' "$*" >>"${SYSTEMCTL_TEST_CALLS}"
    [[ "$*" == 'enable --now logrotate.timer' ]]
}

mkdir -p "${TMP_ROOT}/bin" "${TMP_ROOT}/logrotate.d"
export LOGROTATE_CONFIG_PATH="${TMP_ROOT}/logrotate.d/xray_log_cleanup"
export LOGROTATE_TEST_CALLS="${TMP_ROOT}/logrotate.calls"
export SYSTEMCTL_TEST_CALLS="${TMP_ROOT}/systemctl.calls"
export nginx_dir="${TMP_ROOT}/nginx"
mkdir -p "${nginx_dir}/logs" "${nginx_dir}/conf"
cat >"${TMP_ROOT}/bin/logrotate" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == "--debug" && -s "$2" ]] || exit 1
printf '%s\n' "$2" >>"${LOGROTATE_TEST_CALLS}"
EOF
chmod +x "${TMP_ROOT}/bin/logrotate"
PATH="${TMP_ROOT}/bin:${PATH}"

printf 'Checking generated rotation rules...\n'
if setup_auto_clean_logs; then
    ok 'log rotation setup succeeds with an available timer'
else
    bad 'log rotation setup unexpectedly failed'
fi
if [[ -f "${LOGROTATE_CONFIG_PATH}" ]]; then
    ok 'configuration is installed at the requested path'
else
    bad 'configuration was not installed'
fi
if grep -Fq 'copytruncate' "${LOGROTATE_CONFIG_PATH}" &&
    grep -Fq 'sharedscripts' "${LOGROTATE_CONFIG_PATH}" &&
    grep -Fq 'create 640 idleleo-nginx idleleo-nginx' "${LOGROTATE_CONFIG_PATH}" &&
    grep -Fq "${nginx_dir}/sbin/nginx -s reopen" "${LOGROTATE_CONFIG_PATH}"; then
    ok 'Xray truncates safely and Nginx reopens logs with its worker owner'
else
    bad 'generated rules are missing copytruncate, ownership, or Nginx reopen'
fi
if [[ " ${PACKAGE_REQUESTS[*]} " == *" logrotate "* ]]; then
    ok 'logrotate package is requested'
else
    bad 'logrotate package was not requested'
fi
if grep -Fq 'enable --now logrotate.timer' "${SYSTEMCTL_TEST_CALLS}"; then
    ok 'logrotate timer is enabled'
else
    bad 'logrotate timer was not enabled'
fi
if [[ -s "${LOGROTATE_TEST_CALLS}" ]]; then
    ok 'generated configuration is validated before installation'
else
    bad 'logrotate validation was not invoked'
fi

printf 'Checking manual cleanup error reporting...\n'
mkdir -p "${TMP_ROOT}/blocked.log"
printf 'keep me' >"${TMP_ROOT}/good.log"
find() { printf '%s\0%s\0' "${TMP_ROOT}/blocked.log" "${TMP_ROOT}/good.log"; }
du() { :; }
countdown() { :; }
if clean_logs >/dev/null 2>&1; then
    ok 'cleanup completes while reporting files it could not truncate'
else
    bad 'one failed file incorrectly aborts the cleanup flow'
fi
if [[ ! -s "${TMP_ROOT}/good.log" ]]; then
    ok 'cleanup continues and clears later writable logs'
else
    bad 'cleanup stopped before clearing the writable log'
fi
if printf '%s\n' "${LOG_MESSAGES[@]}" | grep -Fq "${TMP_ROOT}/blocked.log" &&
    printf '%s\n' "${LOG_MESSAGES[@]}" | grep -Fq '部分文件未清理'; then
    ok 'failed path and summary are reported'
else
    bad 'failed paths or the failure count were not reported'
fi
if printf '%s\n' "${LOG_MESSAGES[@]}" | grep -Fq 'Is a directory'; then
    ok 'underlying filesystem error is included in the warning'
else
    bad 'underlying filesystem error was not captured'
fi

printf '\nResult: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ ${FAIL} -eq 0 ]]
