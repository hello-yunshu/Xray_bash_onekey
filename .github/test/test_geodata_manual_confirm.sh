#!/usr/bin/env bash
# color-test-fixture: asserts literal ESC bytes for the confirmation prompt.
# GeoData manual-refresh confirmation regression.
#
# Covers: bare Enter cancels (exit 1, no download/restart), y executes, the
# automation bypass works, the prompt names both files/dir/restart/duration,
# and the prompt is colour-safe in non-TTY / NO_COLOR / TERM=dumb.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "${HERE}/../.." && pwd)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/idleleo-geo-confirm.XXXXXX")
trap 'rm -rf "${TMP_ROOT}"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

if [[ "${1:-}" == "--pty-child" ]]; then
    export _TEST_MODE=1
    # shellcheck disable=SC1090
    source "${REPO_DIR}/install.sh"
    idleleo_dir="${TMP_ROOT}/idleleo"
    confirm_prompt_no "确认提示: 下载 geoip.dat、geosite.dat；会重启 Xray"
    IFS= read -r _ || true
    exit 0
fi

export _TEST_MODE=1
# shellcheck disable=SC1090
source "${REPO_DIR}/install.sh"
idleleo_dir="${TMP_ROOT}/idleleo"
xray_conf_dir="${idleleo_dir}/conf/xray"
tb_geo_dir="${idleleo_dir}/share/xray"
mkdir -p "${xray_conf_dir}" "${idleleo_dir}/logs"
# shellcheck disable=SC1090
source "${REPO_DIR}/scripts/traffic_blocker.sh"

log_echo() { printf '%s\n' "$*"; }
tb_geo_native_cron() { return 1; }
tb_geo_legacy_cron_lines() { return 1; }
tb_geo_manual_refresh_intro() { printf 'INTRO\n'; }
tb_geo_manual_refresh_finish() { printf 'FINISH rc=%s\n' "$1"; return "$1"; }
tb_geo_ensure_updater() { UPDATER_CALLS=$((UPDATER_CALLS + 1)); return 0; }

CALLS=0
UPDATER_CALLS=0
SYSTEMCTL_CALLS=0
tb_download_geo_file() {
    CALLS=$((CALLS + 1))
    printf 'DOWNLOAD %s\n' "$1"
    return 0
}
systemctl() {
    SYSTEMCTL_CALLS=$((SYSTEMCTL_CALLS + 1))
    return 0
}

# 1. Bare Enter cancels.
tb_update_all_geo <<<"" >"${TMP_ROOT}/cancel.out" 2>&1
RC=$?
[[ "${RC}" -eq 1 ]] && ok "bare Enter returns 1" || bad "bare Enter rc=${RC}"
[[ "${CALLS}" -eq 0 ]] && ok "bare Enter does not download" || bad "bare Enter downloaded"
[[ "${SYSTEMCTL_CALLS}" -eq 0 ]] && ok "cancel does not touch systemctl" || bad "cancel called systemctl"
grep -q 'geoip.dat' "${TMP_ROOT}/cancel.out" && grep -q 'geosite.dat' "${TMP_ROOT}/cancel.out" && \
    ok "prompt names both files" || bad "prompt omits a file"
grep -q "${tb_geo_dir}" "${TMP_ROOT}/cancel.out" && ok "prompt names the target directory" || bad "prompt omits directory"
grep -q '重启 Xray' "${TMP_ROOT}/cancel.out" && ok "prompt states the restart consequence" || bad "prompt omits restart"
grep -q '5–30' "${TMP_ROOT}/cancel.out" && ok "prompt states an approximate duration" || bad "prompt omits duration"
grep -q '已取消手动刷新' "${TMP_ROOT}/cancel.out" && ok "cancel is reported" || bad "cancel message missing"
grep -q $'\033' "${TMP_ROOT}/cancel.out" && bad "non-TTY prompt contains ESC" || ok "non-TTY prompt contains no ESC"

# 2. y executes (here-string keeps the function in this shell for counters).
tb_update_all_geo <<<"y" >"${TMP_ROOT}/last.out" 2>&1
Y_RC=$?
[[ "${Y_RC}" -eq 0 ]] && ok "y executes the refresh" || bad "y rc=${Y_RC}"
[[ "${CALLS}" -eq 1 ]] && ok "y calls the downloader once" || bad "y download count=${CALLS}"

BEFORE_CALLS=${CALLS}
GEO_REFRESH_ASSUME_YES=1 tb_update_all_geo </dev/null >/dev/null 2>&1
RC=$?
[[ "${RC}" -eq 0 ]] && ok "GEO_REFRESH_ASSUME_YES skips the prompt" || bad "automation bypass rc=${RC}"
[[ "${CALLS}" -eq $((BEFORE_CALLS + 1)) ]] && ok "automation bypass downloads" || bad "automation bypass skipped download"

# 4. Single-file menu path still confirms first.
BEFORE_CALLS=${CALLS}
tb_update_geo_file geoip.dat <<<"y" >"${TMP_ROOT}/last.out" 2>&1
RC=$?
[[ "${RC}" -eq 0 ]] && ok "single-file y executes" || bad "single-file y rc=${RC}"
[[ "${CALLS}" -eq $((BEFORE_CALLS + 1)) ]] && ok "single-file downloads" || bad "single-file did not download"

# 5. Legacy manual-updater path confirms before fetching the updater.
BEFORE_UPDATER=${UPDATER_CALLS}
tb_geo_run_manual_update <<<"" >"${TMP_ROOT}/last.out" 2>&1
RC=$?
[[ "${RC}" -eq 1 ]] && ok "manual updater cancel returns 1" || bad "manual updater cancel rc=${RC}"
[[ "${UPDATER_CALLS}" -eq "${BEFORE_UPDATER}" ]] && ok "cancel does not fetch the updater" || bad "cancel fetched the updater"

# 6. Colour safety.
if grep -q $'\033' "${TMP_ROOT}/last.out"; then
    bad "non-TTY prompt contains ESC"
else
    ok "non-TTY prompt contains no ESC"
fi

if command -v script >/dev/null 2>&1 && printf 'n\n' | script -q -c true /dev/null >/dev/null 2>&1; then
    printf 'n\n' | TERM=xterm-256color script -q -c "TERM=xterm-256color bash '$0' --pty-child" /dev/null >"${TMP_ROOT}/pty.out" 2>&1
    grep -q $'\033' "${TMP_ROOT}/pty.out" && ok "PTY prompt keeps colour" || bad "PTY prompt lost colour"
    printf 'n\n' | TERM=xterm-256color script -q -c "NO_COLOR=1 TERM=xterm-256color bash '$0' --pty-child" /dev/null >"${TMP_ROOT}/nocolor.out" 2>&1
    grep -q $'\033' "${TMP_ROOT}/nocolor.out" && bad "NO_COLOR prompt contains ESC" || ok "NO_COLOR prompt contains no ESC"
    printf 'n\n' | TERM=xterm-256color script -q -c "TERM=dumb bash '$0' --pty-child" /dev/null >"${TMP_ROOT}/dumb.out" 2>&1
    grep -q $'\033' "${TMP_ROOT}/dumb.out" && bad "TERM=dumb prompt contains ESC" || ok "TERM=dumb prompt contains no ESC"
    cat >"${TMP_ROOT}/countdown-child.sh" <<EOF
#!/usr/bin/env bash
_TEST_MODE=1
source "${REPO_DIR}/install.sh" >/dev/null 2>&1
countdown test
EOF
    for _mode in "NO_COLOR=1 TERM=xterm-256color" "TERM=dumb"; do
        # shellcheck disable=SC2086
        env $_mode script -q -c "bash '${TMP_ROOT}/countdown-child.sh'" /dev/null \
            >"${TMP_ROOT}/countdown.out" 2>&1
        if grep -q $'\033' "${TMP_ROOT}/countdown.out"; then
            bad "countdown emits ESC under ${_mode}"
        else
            ok "countdown is ESC-free under ${_mode}"
        fi
    done
else
    echo "  SKIP: script(1) PTY unavailable"
fi

# 7. The shared [y/N] reader and the backup-menu confirmations default to No.
confirm_no_answer "确认提示" <<<"" >/dev/null 2>&1
RC=$?
[[ "${RC}" -eq 1 ]] && ok "confirm_no_answer bare Enter returns 1" || bad "confirm_no_answer rc=${RC}"
confirm_no_answer "确认提示" <<<"y" >/dev/null 2>&1
RC=$?
[[ "${RC}" -eq 0 ]] && ok "confirm_no_answer y returns 0" || bad "confirm_no_answer y rc=${RC}"

RESTORE_CALLS=0
UNINSTALL_CALLS=0
CERT_CALLS=0
restore_directories() { RESTORE_CALLS=$((RESTORE_CALLS + 1)); }
uninstall_all() { UNINSTALL_CALLS=$((UNINSTALL_CALLS + 1)); }
delete_tls_key_and_crt() { CERT_CALLS=$((CERT_CALLS + 1)); }
menu_pause() { :; }
ssl_chainpath="${TMP_ROOT}/ssl"
mkdir -p "${ssl_chainpath}"

menu_action 35 <<<"" >/dev/null 2>&1
[[ "${RESTORE_CALLS}" -eq 0 ]] && ok "restore menu bare Enter does nothing" || bad "restore ran without confirmation"
menu_action 36 <<<"" >/dev/null 2>&1
[[ "${UNINSTALL_CALLS}" -eq 0 ]] && ok "uninstall menu bare Enter does nothing" || bad "uninstall ran without confirmation"
menu_action 37 <<<"" >/dev/null 2>&1
[[ "${CERT_CALLS}" -eq 0 ]] && ok "cert-clear menu bare Enter does nothing" || bad "cert clear ran without confirmation"

printf 'PASS=%s FAIL=%s\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
