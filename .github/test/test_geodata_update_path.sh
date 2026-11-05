#!/usr/bin/env bash
# End-to-end test for the post-update GeoData migration.
#
# Simulates an old node (real /usr/local/share/xray tree, old project cron,
# no .geodata block) and runs the new updater with `-u --yes`. The updater
# replaces the main script, then invokes the installed script's internal
# migration command in the same run. The test asserts native geodata is active,
# only the project's cron is removed, and a hand-written cron entry survives.
# It then runs the startup hook again to prove idempotence.
#
# Stage 05b pins the real v3.3.2 script by SHA256 and asserts it has no
# same-run hook: a real 3.3.2 process can only migrate on its next start.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
check() {
    local desc="$1"
    shift
    if "$@"; then ok "${desc}"; else bad "${desc}"; fi
}
check_not() {
    local desc="$1"
    shift
    if "$@"; then bad "${desc}"; else ok "${desc}"; fi
}

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ROOT="${TMP_ROOT}/root"
IDLE="${ROOT}/etc/idleleo"
LOCAL="${ROOT}/usr/local"
SYSTEMD="${ROOT}/etc/systemd/system"
BIN="${ROOT}/usr/bin"
CRON_FILE="${TMP_ROOT}/crontab.txt"
GEO_COUNT="${TMP_ROOT}/geo-count.txt"
GEO_CHOWN_LOG="${TMP_ROOT}/chown.log"
SYSTEMCTL_LOG="${TMP_ROOT}/systemctl.log"
NEW_SH="${TMP_ROOT}/install-new.sh"
OLD_SH="${TMP_ROOT}/install-old.sh"
DEST="${IDLE}/install.sh"

mkdir -p "${IDLE}/conf/xray" "${IDLE}/scripts" "${IDLE}/logs" \
    "${LOCAL}/share/xray" "${LOCAL}/bin" "${SYSTEMD}" "${BIN}"

printf '{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[]}}\n' \
    >"${IDLE}/conf/xray/config.json"
printf 'IP\n' >"${LOCAL}/share/xray/geoip.dat"
printf 'SITE\n' >"${LOCAL}/share/xray/geosite.dat"
printf '0 3 * * 1 bash "%s"\n' "${IDLE}/scripts/geo_update.sh" >"${CRON_FILE}"
printf '0 4 * * * /usr/local/bin/hand-written-geo-job\n' >>"${CRON_FILE}"

cat >"${LOCAL}/bin/xray" <<'STUB'
#!/bin/sh
if [ "$1" = "run" ]; then
    n=$(( $(cat "${GEO_COUNT_FILE:-/dev/null}" 2>/dev/null || echo 0) + 1 ))
    printf '%s' "${n}" >"${GEO_COUNT_FILE:-/dev/null}" 2>/dev/null
    [ "${GEO_FAIL_TEST:-0}" = "1" ] && exit 1
    exit 0
fi
echo "Xray 26.10.31 (stub)"
STUB
chmod +x "${LOCAL}/bin/xray"

cat >"${SYSTEMD}/xray.service" <<UNIT
[Service]
User=root
ExecStart=${LOCAL}/bin/xray run -config ${IDLE}/conf/xray/config.json
UNIT

# Exportable shims: the post-update migration runs in a child bash process.
crontab() {
    case "${1:-}" in
        -l) cat "${CRON_FILE}" 2>/dev/null ;;
        -)
            cat >"${CRON_FILE}.incoming.$$" && mv -f "${CRON_FILE}.incoming.$$" "${CRON_FILE}"
            ;;
        *) return 1 ;;
    esac
}
RESTART_COUNT=0
systemctl() {
    printf '%s\n' "$*" >>"${SYSTEMCTL_LOG}"
    if [[ "${1:-}" == "restart" ]]; then
        RESTART_COUNT=$((RESTART_COUNT + 1))
    fi
    return 0
}
chown() {
    printf '%s %s\n' "$1" "$2" >>"${GEO_CHOWN_LOG}"
    return 0
}
export CRON_FILE GEO_COUNT_FILE="${GEO_COUNT}" GEO_CHOWN_LOG SYSTEMCTL_LOG
export -f crontab systemctl chown

# Build a runnable copy whose managed paths point at the test root, so the
# child process cannot touch the real /etc/idleleo or /usr/local.
python3 - "$INSTALL_SH" "$NEW_SH" "$OLD_SH" "$IDLE" "$LOCAL" "$SYSTEMD" <<'PY'
import pathlib
import sys

source, new, old, idle, local, systemd = sys.argv[1:7]
text = pathlib.Path(source).read_text(encoding="utf-8")
text = text.replace("/etc/idleleo", idle)
text = text.replace("/usr/local", local)
text = text.replace("/etc/systemd", systemd)
pathlib.Path(new).write_text(text, encoding="utf-8")
pathlib.Path(old).write_text(
    text.replace('shell_version="3.3.4"', 'shell_version="3.3.3"', 1),
    encoding="utf-8",
)
PY
cp "${OLD_SH}" "${DEST}"
chmod +x "${NEW_SH}" "${OLD_SH}" "${DEST}"

# Source the real script only for its functions; then redirect every global
# used by _update_sh_impl to the test root.
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${INSTALL_SH}" >/dev/null 2>&1 || true
unset _TEST_MODE

idleleo_dir="${IDLE}"
local_bin="${LOCAL}"
xray_bin_dir="${LOCAL}/bin"
xray_conf_dir="${IDLE}/conf/xray"
xray_conf="${xray_conf_dir}/config.json"
xray_install_config_file="${IDLE}/conf/install_config.json"
xray_systemd_file="${SYSTEMD}/xray.service"
idleleo="${DEST}"
idleleo_commend_file="${BIN}/idleleo"
scripts_dir="${IDLE}/scripts"
geo_update_file="${scripts_dir}/geo_update.sh"
geodata_dir="${IDLE}/share/xray"
log_dir="${IDLE}/logs"
LOG_FILE="${log_dir}/install.log"
shell_version_tmp="${IDLE}/tmp/shell_version.tmp"
mkdir -p "${IDLE}/tmp" "${BIN}"

shell_version="3.3.3"
shell_online_version="3.3.4"
auto_update="NO"
update_assume_yes="YES"
update_allow_major="NO"
shell_release_sha256=""

rxa_update_title() { :; }
rxa_stage_begin() { :; }
rxa_stage_done() { :; }
rxa_clear_screen() { :; }
check_version() { :; }
rxa_download_main_candidate() { cp "${NEW_SH}" "$1"; }
rxa_sync_release_helpers() { return 0; }
rxa_reconcile_release() { return 0; }

echo "============================================================"
echo "  Stage 05: -u migrates automatically in the same run"
echo "============================================================"

: >"${SYSTEMCTL_LOG}"
_update_sh_impl -u --yes >"${TMP_ROOT}/update.out" 2>&1
_update_rc=$?
check "the non-interactive -u --yes update exits 0" test "${_update_rc}" -eq 0
check "the update replaced the script with the downloaded version" \
    grep -q '^shell_version="3.3.4"' "${DEST}"

if [[ "$(id -u)" -eq 0 ]]; then
    check "-u writes the native geodata block in the same run" \
        jq -e '.geodata.cron == "0 3 * * 1" and (.geodata.assets | length == 2)' "${xray_conf}"
    check "-u replaces the old real asset directory with the managed symlink" \
        test -L "${LOCAL}/share/xray"
    check "-u points the symlink at the managed directory" \
        test "$(readlink "${LOCAL}/share/xray")" = "${geodata_dir}"
    check "-u removes only the project's old cron entry" \
        bash -c "! grep -qF '${geo_update_file}' '${CRON_FILE}'"
    check "-u preserves the hand-written cron entry" \
        grep -qF 'hand-written-geo-job' "${CRON_FILE}"
    check "-u restarts the active service for the migration" \
        grep -q '^restart xray$' "${SYSTEMCTL_LOG}"
else
    echo "  SKIP: same-run migration assertions need root (container covers them)"
    check "-u leaves migration to the startup hook when not root" \
        test "$(jq -c 'has("geodata")' "${xray_conf}")" = "false"
    check "-u keeps the old real asset directory when not root" \
        test -d "${LOCAL}/share/xray"
fi

# The next startup of the new script runs the startup hook.
geodata_migrate_legacy >"${TMP_ROOT}/startup.out" 2>&1
_startup_rc=$?
check "the next startup migration exits 0" test "${_startup_rc}" -eq 0
check "the next startup creates the managed symlink" \
    test -L "${LOCAL}/share/xray"
check "the next startup points the symlink at the managed directory" \
    test "$(readlink "${LOCAL}/share/xray")" = "${geodata_dir}"
check "the next startup writes the native geodata block" \
    jq -e '.geodata.cron == "0 3 * * 1" and (.geodata.assets | length == 2)' "${xray_conf}"
check "the next startup runs xray run -test" \
    test "$(cat "${GEO_COUNT}" 2>/dev/null || echo 0)" -ge 1
check "the next startup restarts the active service" \
    grep -q '^restart xray$' "${SYSTEMCTL_LOG}"
check "the next startup removes the project's old cron" \
    bash -c "! grep -qF '${geo_update_file}' '${CRON_FILE}'"
check "the hand-written cron entry is preserved" \
    grep -qF 'hand-written-geo-job' "${CRON_FILE}"
check "the migration failure marker is absent after success" \
    test ! -f "${IDLE}/geodata_migration.failed"

_cfg_after=$(cat "${xray_conf}")
_cron_after=$(cat "${CRON_FILE}")
geodata_migrate_legacy >/dev/null 2>&1
_second_rc=$?
check "the startup migration is idempotent" test "${_second_rc}" -eq 0
check "the second run does not rewrite the config" \
    test "$(cat "${xray_conf}")" = "${_cfg_after}"
check "the second run does not duplicate the cron table" \
    test "$(cat "${CRON_FILE}")" = "${_cron_after}"

# Failure path on the startup hook: restore the old layout, make
# `xray run -test` fail, and prove the old cron survives. The retry succeeds.
jq 'del(.geodata)' "${xray_conf}" >"${TMP_ROOT}/nogeo.json"
cp "${TMP_ROOT}/nogeo.json" "${xray_conf}"
rm -f "${LOCAL}/share/xray"
mkdir -p "${LOCAL}/share/xray"
cp "${geodata_dir}/geoip.dat" "${LOCAL}/share/xray/geoip.dat"
cp "${geodata_dir}/geosite.dat" "${LOCAL}/share/xray/geosite.dat"
printf '0 3 * * 1 bash "%s"\n' "${geo_update_file}" >>"${CRON_FILE}"

GEO_FAIL_TEST=1 geodata_migrate_legacy >/dev/null 2>&1
_fail_rc=$?
check "a failed xray -test makes the startup migration non-zero" \
    test "${_fail_rc}" -eq 1
check "the old cron survives a failed migration" \
    grep -qF "${geo_update_file}" "${CRON_FILE}"
check "the failed migration does not write .geodata" \
    test "$(jq -c 'has("geodata")' "${xray_conf}")" = "false"
check "the failed migration records a failure marker" \
    grep -q '^reason=native_state$' "${IDLE}/geodata_migration.failed"

geodata_migrate_legacy >/dev/null 2>&1
_retry_rc=$?
check "the retry after a failed migration succeeds" test "${_retry_rc}" -eq 0
check "the retry removes the old cron" \
    bash -c "! grep -qF '${geo_update_file}' '${CRON_FILE}'"
check "the retry writes the native block" \
    jq -e '.geodata.cron == "0 3 * * 1"' "${xray_conf}"
check "the retry clears the failure marker" \
    test ! -f "${IDLE}/geodata_migration.failed"

echo ""
echo "============================================================"
echo "  Stage 05b: real v3.3.2 cannot migrate in the same process"
echo "============================================================"
V332="${TMP_ROOT}/install-v3.3.2.sh"
V332_SHA="764ac1253591f1f9d46c1b69ac3ead593d2ea35012ffbf79f583ba993e5a5df4"
if command -v curl >/dev/null 2>&1 &&
    curl -fsSL --retry 2 --max-time 60 \
        "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/v3.3.2/install.sh" \
        -o "${V332}" 2>/dev/null; then
    if command -v sha256sum >/dev/null 2>&1; then
        got_sha=$(sha256sum "${V332}" | awk '{print $1}')
    else
        got_sha=$(shasum -a 256 "${V332}" | awk '{print $1}')
    fi
    check "downloaded real v3.3.2 matches its pinned SHA256" test "${got_sha}" = "${V332_SHA}"
    check_not "real v3.3.2 has no same-run migration hook" \
        grep -qF -- '--internal-geodata-migrate-legacy' "${V332}"
    check "the new script has the same-run migration hook" \
        grep -qF -- '--internal-geodata-migrate-legacy' "${INSTALL_SH}"
else
    echo "  SKIP: real v3.3.2 asset unavailable (network)"
fi

printf 'Result: %d passed, %d failed\n' "${PASS}" "${FAIL}"
echo "============================================================"
[[ "${FAIL}" -eq 0 ]] || exit 1
exit 0
