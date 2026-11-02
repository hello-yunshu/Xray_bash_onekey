#!/usr/bin/env bash
# 3.3.1 H1: `-u` must never report success when it did not update.
# Covers non-TTY/EOF, TTY "n", TTY "y", and explicit --yes.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

[[ -f "${INSTALL_SH}" ]] || { echo "FATAL: install.sh missing"; exit 1; }

run_updater() {
    local case_name="$1"
    local base_version="3.3.0" target_version="3.3.1"
    local want_yes="off" want_allow_major="off"
    case "${case_name}" in
        noninteractive|tty-n|tty-y) ;;
        yes) want_yes="YES" ;;
        cross-yes)
            base_version="3.3.1"; target_version="3.4.0"; want_yes="YES"
            ;;
        cross-allow-only)
            base_version="3.3.1"; target_version="3.4.0"; want_allow_major="YES"
            ;;
        cross-allow)
            base_version="3.3.1"; target_version="3.4.0"
            want_yes="YES"; want_allow_major="YES"
            ;;
        *)
            printf 'unknown case: %s\n' "${case_name}" >&2
            return 2
            ;;
    esac
    local tmp
    tmp=$(mktemp -d)
    export _TEST_MODE=1
    # shellcheck source=/dev/null
    source "${INSTALL_SH}" >/dev/null 2>&1 || true
    unset _TEST_MODE

    idleleo_dir="${tmp}/idleleo"
    idleleo_conf_dir="${idleleo_dir}/conf"
    scripts_dir="${idleleo_dir}/scripts"
    shell_version_tmp="${idleleo_dir}/tmp/shell_version.tmp"
    idleleo="${idleleo_dir}/install.sh"
    idleleo_commend_file="${idleleo_dir}/idleleo"
    xray_install_config_file="${idleleo_conf_dir}/install_config.json"
    log_dir="${idleleo_dir}/logs"
    log_file="${log_dir}/install.log"
    mkdir -p "${idleleo_dir}/tmp" "${idleleo_conf_dir}" "${scripts_dir}" "${log_dir}"
    printf 'shell_version="%s"\nold\n' "${base_version}" >"${idleleo}"
    ln -sf "${idleleo}" "${idleleo_commend_file}"
    jq -n --arg v "${base_version}" '{shell_version:$v}' >"${xray_install_config_file}"

    shell_version="${base_version}"
    shell_online_version="${target_version}"
    shell_release_sha256=""
    auto_update=""
    update_assume_yes="${want_yes}"
    update_allow_major="${want_allow_major}"

    check_version() { printf 'test-details\n'; }
    rxa_update_title() { :; }
    rxa_stage_begin() { :; }
    rxa_stage_done() { :; }
    rxa_clear_screen() { :; }
    rxa_log_candidate_failure() { :; }
    rxa_sync_release_helpers() { return 0; }
    rxa_reconcile_release() { return 0; }
    update_json_config() { return 0; }
    rxa_download_main_candidate() {
        local candidate="$1"
        {
            printf '#!/usr/bin/env bash\n'
            printf 'shell_version="%s"\n' "${target_version}"
            printf 'xray_install_release() { :; }\n'
            printf 'read_version() { :; }\n'
            printf 'xray_update() { :; }\n'
        } >"${candidate}"
        return 0
    }
    rxa_replace_main_candidate() {
        local candidate="$1" destination="$2"
        cp -f "${candidate}" "${destination}"
        return 0
    }

    _update_sh_impl
    local rc=$?
    printf 'CASE=%s RC=%s SHELL=%s\n' "${case_name}" "${rc}" \
        "$(sed -n 's/^shell_version="\([0-9][0-9.]*\)"$/\1/p' "${idleleo}" | head -1)"
    printf '%s\n' "${rc}" >"${tmp}/rc"
    printf '%s\n' "$(sed -n 's/^shell_version="\([0-9][0-9.]*\)"$/\1/p' "${idleleo}" | head -1)" >"${tmp}/version"
    rm -rf "${tmp}" 2>/dev/null || true
    return "${rc}"
}

if [[ "${1:-}" == "__run" ]]; then
    run_updater "${2:?case}"
    exit $?
fi

echo "--- non-TTY / EOF ---"
out=$(bash "$0" __run noninteractive </dev/null 2>&1); rc=$?
if [[ ${rc} -ne 0 ]]; then ok "non-TTY -u returns non-zero"; else bad "non-TTY -u returned 0"; fi
if grep -Fq "未升级" <<<"${out}"; then ok "non-TTY prints 未升级"; else bad "non-TTY has no 未升级 message"; fi
if grep -Fq "CASE=noninteractive RC=1 SHELL=3.3.0" <<<"${out}"; then ok "non-TTY leaves version unchanged"; else bad "non-TTY changed version: ${out}"; fi

echo "--- TTY n ---"
if command -v script >/dev/null 2>&1; then
    out=$(printf 'n\n' | script -qec "bash '$0' __run tty-n" /dev/null 2>&1); rc=$?
    if [[ ${rc} -eq 0 ]]; then ok "TTY n returns 0 (intentional cancel)"; else bad "TTY n returned ${rc}"; fi
    if grep -Fq "已取消更新，未升级" <<<"${out}"; then ok "TTY n prints cancel"; else bad "TTY n cancel message missing"; fi
    if grep -Fq "SHELL=3.3.0" <<<"${out}"; then ok "TTY n leaves version unchanged"; else bad "TTY n changed version"; fi

    echo "--- TTY y ---"
    out=$(printf 'y\n' | script -qec "bash '$0' __run tty-y" /dev/null 2>&1); rc=$?
    if [[ ${rc} -eq 0 ]]; then ok "TTY y returns 0"; else bad "TTY y returned ${rc}"; fi
    if grep -Fq "SHELL=3.3.1" <<<"${out}"; then ok "TTY y updates to 3.3.1"; else bad "TTY y did not update: ${out}"; fi
else
    bad "script(1) unavailable; TTY cases not executed"
fi

echo "--- --yes without TTY (same minor) ---"
out=$(bash "$0" __run yes </dev/null 2>&1); rc=$?
if [[ ${rc} -eq 0 ]]; then ok "--yes returns 0"; else bad "--yes returned ${rc}"; fi
if grep -Fq "SHELL=3.3.1" <<<"${out}"; then ok "--yes updates to 3.3.1"; else bad "--yes did not update: ${out}"; fi

echo "--- --yes without TTY (cross minor) ---"
out=$(bash "$0" __run cross-yes </dev/null 2>&1); rc=$?
if [[ ${rc} -ne 0 ]]; then ok "cross-minor --yes returns non-zero"; else bad "cross-minor --yes returned 0"; fi
if grep -Fq "SHELL=3.3.1" <<<"${out}"; then ok "cross-minor --yes leaves version unchanged"; else bad "cross-minor --yes changed version: ${out}"; fi
if grep -Fq -- "--allow-major" <<<"${out}"; then ok "cross-minor --yes explains --allow-major"; else bad "cross-minor --yes has no --allow-major guidance"; fi

echo "--- --allow-major without --yes (cross minor, no TTY) ---"
out=$(bash "$0" __run cross-allow-only </dev/null 2>&1); rc=$?
if [[ ${rc} -ne 0 ]]; then ok "cross-minor --allow-major alone still needs --yes"; else bad "cross-minor --allow-major alone auto-confirmed"; fi
if grep -Fq "SHELL=3.3.1" <<<"${out}"; then ok "cross-minor --allow-major alone leaves version unchanged"; else bad "cross-minor --allow-major alone changed version: ${out}"; fi

echo "--- --yes --allow-major without TTY (cross minor) ---"
out=$(bash "$0" __run cross-allow </dev/null 2>&1); rc=$?
if [[ ${rc} -eq 0 ]]; then ok "cross-minor --yes --allow-major returns 0"; else bad "cross-minor --yes --allow-major returned ${rc}"; fi
if grep -Fq "SHELL=3.4.0" <<<"${out}"; then ok "cross-minor --yes --allow-major updates to 3.4.0"; else bad "cross-minor --yes --allow-major did not update: ${out}"; fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
