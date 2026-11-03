#!/usr/bin/env bash
# Backup/restore behaviour tests for the user-facing "全部文件" path.
#
# Covers:
#   1. --backup includes config, certs, Nginx tree, Xray binary and units.
#   2. A corrupt newest archive is rejected before touching the live tree.
#   3. The newest archive is selected by its 14-digit timestamp, not by ls order.
#   4. A truncated archive is rejected and the live marker is unchanged.
#   5. A successful restore reports script/config version drift.
#
# Runs without root: all paths are redirected into a temporary tree and
# restore_directories honours RESTORE_ROOT. Existing assertions in
# test_backup_permissions.sh are not modified.

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
nginx_dir="${TMP_ROOT}/nginx"
xray_bin_dir="${TMP_ROOT}/bin"
xray_systemd_file="${TMP_ROOT}/systemd/xray.service"
nginx_systemd_file="${TMP_ROOT}/systemd/nginx.service"
xray_conf_dir="${idleleo_dir}/conf/xray"
nginx_conf_dir="${idleleo_dir}/conf/nginx"
ssl_chainpath="${idleleo_dir}/cert"
xray_install_config_file="${idleleo_dir}/conf/install_config.json"
xray_info_file="${idleleo_dir}/info/xray_info.inf"
log_dir="${TMP_ROOT}/logs"
LOG_FILE="${log_dir}/install.log"

mkdir -p "${xray_conf_dir}" "${nginx_conf_dir}" "${ssl_chainpath}" \
    "${idleleo_dir}/info" "${idleleo_dir}/scripts" "${log_dir}" \
    "${xray_bin_dir}" "${xray_systemd_file%/*}" \
    "${nginx_dir}/conf" "${nginx_dir}/sbin" "${nginx_dir}/logs"

printf '{"shell_version":"3.3.1","id":"uuid-secret","privateKey":"priv-secret"}\n' >"${xray_install_config_file}"
printf '{"inbounds":[]}\n' >"${xray_conf_dir}/config.json"
printf -- '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n' >"${ssl_chainpath}/xray.key"
printf 'uuid=secret\n' >"${xray_info_file}"
printf '#!/bin/sh\nexit 0\n' >"${xray_bin_dir}/xray"
chmod +x "${xray_bin_dir}/xray"
printf '# main\n' >"${nginx_dir}/conf/nginx.conf"
printf '#!/bin/sh\nexit 0\n' >"${nginx_dir}/sbin/nginx"
chmod +x "${nginx_dir}/sbin/nginx"
printf '[Unit]\nDescription=xray\n' >"${xray_systemd_file}"
printf '[Unit]\nDescription=nginx\n' >"${nginx_systemd_file}"
cp "${REPO_DIR}/install.sh" "${idleleo_dir}/install.sh"

log_echo() { printf '%s\n' "$*"; }
gettext() { printf '%s' "$1"; }
countdown() { :; }
read_optimize() { printf -v "$2" '%s' "case"; }

# ---------------------------------------------------------------------------
# 1. Backup contents
# ---------------------------------------------------------------------------
# Old reinstall snapshots must not be nested into the user backup.
mkdir -p "${idleleo_dir}/backup/reinstall-old"
printf 'old snapshot\n' >"${idleleo_dir}/backup/reinstall-old/secret.txt"
backup_directories >/dev/null
rc=$?
[[ ${rc} -eq 0 ]] && ok "backup succeeds" || bad "backup failed rc=${rc}"
archive=$(ls -1 "${idleleo_dir}"/xray_bash_case_*.tar.gz 2>/dev/null | tail -1)
[[ -n "${archive}" ]] && ok "backup archive created" || bad "backup archive missing"
mode=$(stat -c '%a' "${archive}" 2>/dev/null || stat -f '%Lp' "${archive}" 2>/dev/null || echo missing)
[[ "${mode}" == "600" ]] && ok "backup archive mode 0600" || bad "backup archive mode=${mode}"
tar -tzf "${archive}" >"${TMP_ROOT}/archive.list" 2>/dev/null || true
grep -q '.backup_sha256sums.txt' "${TMP_ROOT}/archive.list" && \
    ok "backup contains checksum manifest" || bad "backup missing checksum manifest"
if grep -q 'reinstall-old/secret.txt' "${TMP_ROOT}/archive.list"; then
    bad "backup includes old reinstall snapshot"
else
    ok "backup excludes idleleo/backup"
fi
for expected in \
    "conf/install_config.json" \
    "cert/xray.key" \
    "info/xray_info.inf" \
    "bin/xray" \
    "systemd/xray.service" \
    "systemd/nginx.service" \
    "nginx/conf/nginx.conf"; do
    if grep -q -- "${expected}" "${TMP_ROOT}/archive.list"; then
        ok "backup contains ${expected}"
    else
        bad "backup missing ${expected}"
    fi
done

# ---------------------------------------------------------------------------
# 1b. Same name and same second must not overwrite an existing archive
# ---------------------------------------------------------------------------
date() { echo 20261103120000; }
collision="${idleleo_dir}/xray_bash_case_20261103120000.tar.gz"
printf 'ORIGINAL\n' >"${collision}"
backup_directories >/dev/null 2>&1
rc=$?
[[ ${rc} -ne 0 ]] && ok "existing archive is not overwritten" || bad "existing archive was overwritten"
[[ "$(cat "${collision}")" == "ORIGINAL" ]] && ok "collision archive content unchanged" || bad "collision archive content changed"
rm -f "${collision}"
unset -f date

# ---------------------------------------------------------------------------
# 2. Corrupt newest archive: reject before extraction
# ---------------------------------------------------------------------------
rm -f "${idleleo_dir}"/xray_bash_*.tar.gz
stage_valid="${TMP_ROOT}/stage-valid"
mkdir -p "${stage_valid}/etc/idleleo/info"
printf 'uuid=OLDER-VALID\n' >"${stage_valid}/etc/idleleo/info/xray_info.inf"
tar -czf "${idleleo_dir}/xray_bash_aaa_20250101000000.tar.gz" \
    -C "${stage_valid}" etc/idleleo/info/xray_info.inf
tar -czf "${idleleo_dir}/xray_bash_zzz_20260101000000.tar.gz" \
    -C "${stage_valid}" etc/idleleo/info/xray_info.inf 2>/dev/null || true
printf 'garbage\n' >"${idleleo_dir}/xray_bash_zzz_20260101000000.tar.gz"
chmod 600 "${idleleo_dir}"/xray_bash_*.tar.gz

RESTORE_ROOT="${TMP_ROOT}/root-corrupt"
mkdir -p "${RESTORE_ROOT}/etc/idleleo/info"
printf 'uuid=CURRENT-LIVE\n' >"${RESTORE_ROOT}/etc/idleleo/info/xray_info.inf"
output=$(RESTORE_ROOT="${RESTORE_ROOT}" restore_directories 2>&1)
rc=$?
[[ ${rc} -ne 0 ]] && ok "corrupt archive restore returns non-zero" || bad "corrupt archive restore returned 0"
[[ "${output}" == *"备份完整性校验失败"* ]] && ok "corrupt archive rejected before extraction" || bad "corrupt archive was not rejected"
[[ "$(cat "${RESTORE_ROOT}/etc/idleleo/info/xray_info.inf")" == "uuid=CURRENT-LIVE" ]] && ok "live tree untouched on corrupt archive" || bad "live tree changed on corrupt archive"

# ---------------------------------------------------------------------------
# 2b. A parseable archive with a bad per-file checksum must be rejected
# ---------------------------------------------------------------------------
rm -f "${idleleo_dir}"/xray_bash_*.tar.gz
stage_hash="${TMP_ROOT}/stage-hash"
mkdir -p "${stage_hash}/etc/idleleo/info"
printf 'uuid=GOOD\n' >"${stage_hash}/etc/idleleo/info/xray_info.inf"
good_hash=$(sha256sum "${stage_hash}/etc/idleleo/info/xray_info.inf" | awk '{print $1}')
printf '%s  %s\n' "${good_hash}" "etc/idleleo/info/xray_info.inf" >"${stage_hash}/etc/idleleo/.backup_sha256sums.txt"
printf 'uuid=BAD\n' >"${stage_hash}/etc/idleleo/info/xray_info.inf"
tar -czf "${idleleo_dir}/xray_bash_hash_20261103121000.tar.gz" -C "${stage_hash}" \
    etc/idleleo/.backup_sha256sums.txt etc/idleleo/info/xray_info.inf
chmod 600 "${idleleo_dir}/xray_bash_hash_20261103121000.tar.gz"
RESTORE_ROOT="${TMP_ROOT}/root-hash"
mkdir -p "${RESTORE_ROOT}/etc/idleleo/info"
printf 'uuid=CURRENT-LIVE\n' >"${RESTORE_ROOT}/etc/idleleo/info/xray_info.inf"
output=$(RESTORE_ROOT="${RESTORE_ROOT}" restore_directories 2>&1)
rc=$?
[[ ${rc} -ne 0 ]] && ok "checksum mismatch restore returns non-zero" || bad "checksum mismatch restore returned 0"
[[ "${output}" == *"备份完整性校验失败"* ]] && ok "checksum mismatch rejected before copy" || bad "checksum mismatch was not rejected"
[[ "$(cat "${RESTORE_ROOT}/etc/idleleo/info/xray_info.inf")" == "uuid=CURRENT-LIVE" ]] && ok "live tree untouched on checksum mismatch" || bad "live tree changed on checksum mismatch"

# ---------------------------------------------------------------------------
# 3. Newest selection by timestamp, not by ls order
# ---------------------------------------------------------------------------
rm -f "${idleleo_dir}"/xray_bash_*.tar.gz
stage_new="${TMP_ROOT}/stage-new"
stage_old="${TMP_ROOT}/stage-old"
mkdir -p "${stage_new}/etc/idleleo/info" "${stage_old}/etc/idleleo/info"
printf 'uuid=NEWEST-2026\n' >"${stage_new}/etc/idleleo/info/xray_info.inf"
printf 'uuid=OLDEST-2020\n' >"${stage_old}/etc/idleleo/info/xray_info.inf"
tar -czf "${idleleo_dir}/xray_bash_aaa_20261103130000.tar.gz" -C "${stage_new}" etc/idleleo/info/xray_info.inf
tar -czf "${idleleo_dir}/xray_bash_zzz_20200101000000.tar.gz" -C "${stage_old}" etc/idleleo/info/xray_info.inf
chmod 600 "${idleleo_dir}"/xray_bash_*.tar.gz

RESTORE_ROOT="${TMP_ROOT}/root-select"
mkdir -p "${RESTORE_ROOT}/etc/idleleo/info"
printf 'uuid=CURRENT-LIVE\n' >"${RESTORE_ROOT}/etc/idleleo/info/xray_info.inf"
output=$(RESTORE_ROOT="${RESTORE_ROOT}" restore_directories 2>&1)
rc=$?
[[ ${rc} -eq 0 ]] && ok "valid restore returns 0" || bad "valid restore rc=${rc}"
[[ "${output}" == *"xray_bash_aaa_20261103130000.tar.gz"* ]] && ok "newest timestamp archive selected" || bad "newest timestamp not selected"
[[ "$(cat "${RESTORE_ROOT}/etc/idleleo/info/xray_info.inf")" == "uuid=NEWEST-2026" ]] && ok "newest archive content restored" || bad "older archive content restored"

# ---------------------------------------------------------------------------
# 4. Truncated archive: reject, live marker unchanged
# ---------------------------------------------------------------------------
rm -f "${idleleo_dir}"/xray_bash_*.tar.gz
stage_trunc="${TMP_ROOT}/stage-trunc"
mkdir -p "${stage_trunc}/etc/idleleo"
printf 'uuid=TRUNCATED\n' >"${stage_trunc}/etc/idleleo/xray_info.inf"
head -c 1000000 /dev/urandom >"${stage_trunc}/etc/idleleo/big.bin"
tar -czf "${TMP_ROOT}/full.tgz" -C "${stage_trunc}" etc/idleleo/xray_info.inf etc/idleleo/big.bin
head -c 2000 "${TMP_ROOT}/full.tgz" >"${idleleo_dir}/xray_bash_trunc_20261103140000.tar.gz"
chmod 600 "${idleleo_dir}/xray_bash_trunc_20261103140000.tar.gz"
RESTORE_ROOT="${TMP_ROOT}/root-trunc"
mkdir -p "${RESTORE_ROOT}/etc/idleleo/info"
printf 'uuid=CURRENT-LIVE\n' >"${RESTORE_ROOT}/etc/idleleo/info/xray_info.inf"
output=$(RESTORE_ROOT="${RESTORE_ROOT}" restore_directories 2>&1)
rc=$?
[[ ${rc} -ne 0 ]] && ok "truncated archive restore returns non-zero" || bad "truncated archive restore returned 0"
[[ "$(cat "${RESTORE_ROOT}/etc/idleleo/info/xray_info.inf")" == "uuid=CURRENT-LIVE" ]] && ok "live tree untouched on truncated archive" || bad "live tree changed on truncated archive"

# ---------------------------------------------------------------------------
# 5. Successful restore reports script/config version drift
# ---------------------------------------------------------------------------
rm -f "${idleleo_dir}"/xray_bash_*.tar.gz
stage_ver="${TMP_ROOT}/stage-ver"
mkdir -p "${stage_ver}/etc/idleleo/conf" "${stage_ver}/etc/idleleo/info"
printf 'shell_version="3.3.1"\n' >"${stage_ver}/etc/idleleo/install.sh"
printf '{"shell_version":"3.3.0"}\n' >"${stage_ver}/etc/idleleo/conf/install_config.json"
printf 'uuid=VERSIONED\n' >"${stage_ver}/etc/idleleo/info/xray_info.inf"
tar -czf "${idleleo_dir}/xray_bash_ver_20261103150000.tar.gz" -C "${stage_ver}" \
    etc/idleleo/install.sh etc/idleleo/conf/install_config.json etc/idleleo/info/xray_info.inf
chmod 600 "${idleleo_dir}/xray_bash_ver_20261103150000.tar.gz"
RESTORE_ROOT="${TMP_ROOT}/root-ver"
mkdir -p "${RESTORE_ROOT}"
output=$(RESTORE_ROOT="${RESTORE_ROOT}" restore_directories 2>&1)
rc=$?
[[ ${rc} -eq 0 ]] && ok "versioned restore returns 0" || bad "versioned restore rc=${rc}"
[[ "${output}" == *"已恢复脚本版本: 3.3.1"* ]] && ok "restored script version reported" || bad "restored script version not reported"
[[ "${output}" == *"脚本与配置版本不一致"* ]] && ok "script/config version drift reported" || bad "version drift not reported"

# ---------------------------------------------------------------------------
# 6. Backup name cannot escape /etc/idleleo
# ---------------------------------------------------------------------------
read_optimize() { printf -v "$2" '%s' "../escape"; }
rm -f "${idleleo_dir}"/xray_bash_*.tar.gz
backup_directories >/dev/null 2>&1
rc=$?
[[ ${rc} -ne 0 ]] && ok "traversal backup name rejected" || bad "traversal backup name accepted"
if compgen -G "${TMP_ROOT}/escape_*.tar.gz" >/dev/null; then
    bad "backup escaped the idleleo directory"
else
    ok "no archive written outside idleleo"
fi

# ---------------------------------------------------------------------------
# 7. Cross-mode prune, permissions, daemon-reload and xray -test
# ---------------------------------------------------------------------------
# Restore targets use production-relative paths; the archive storage path
# stays in TMP_ROOT.
nginx_conf_dir="/etc/idleleo/conf/nginx"
xray_conf_dir="/etc/idleleo/conf/xray"
relay_stream_conf="/etc/idleleo/conf/nginx/relay-stream.conf"
xray_bin_dir="/usr/local/bin"
xray_conf="/etc/idleleo/conf/xray/config.json"

rm -f "${idleleo_dir}"/xray_bash_*.tar.gz
stage_mode="${TMP_ROOT}/stage-mode"
mkdir -p "${stage_mode}/etc/idleleo/conf/nginx" "${stage_mode}/etc/idleleo/conf/xray" \
    "${stage_mode}/etc/idleleo/cert" "${stage_mode}/usr/local/bin"
printf 'NEW-REALITY\n' >"${stage_mode}/etc/idleleo/conf/nginx/00-xray.conf"
printf '{"shell_version":"3.3.1","id":"uuid-secret"}\n' >"${stage_mode}/etc/idleleo/conf/install_config.json"
printf '{"inbounds":[]}\n' >"${stage_mode}/etc/idleleo/conf/xray/config.json"
printf 'CERT-KEY\n' >"${stage_mode}/etc/idleleo/cert/xray.key"
chmod 644 "${stage_mode}/etc/idleleo/conf/install_config.json" \
    "${stage_mode}/etc/idleleo/cert/xray.key"
cat >"${stage_mode}/usr/local/bin/xray" <<'EOF'
#!/bin/sh
if [ "$1" = "-test" ]; then echo "$@" >>"${XRAY_TEST_MARKER:-/tmp/xray-test-called}"; fi
exit 0
EOF
chmod +x "${stage_mode}/usr/local/bin/xray"
( cd "${stage_mode}" && sha256sum \
    etc/idleleo/conf/nginx/00-xray.conf \
    etc/idleleo/conf/install_config.json \
    etc/idleleo/conf/xray/config.json \
    etc/idleleo/cert/xray.key \
    usr/local/bin/xray ) >"${stage_mode}/etc/idleleo/.backup_sha256sums.txt"
tar -czf "${idleleo_dir}/xray_bash_mode_20261103122000.tar.gz" -C "${stage_mode}" \
    etc/idleleo/.backup_sha256sums.txt \
    etc/idleleo/conf/nginx/00-xray.conf \
    etc/idleleo/conf/install_config.json \
    etc/idleleo/conf/xray/config.json \
    etc/idleleo/cert/xray.key \
    usr/local/bin/xray
chmod 600 "${idleleo_dir}/xray_bash_mode_20261103122000.tar.gz"

RESTORE_ROOT="${TMP_ROOT}/root-mode"
mkdir -p "${RESTORE_ROOT}/etc/idleleo/conf/nginx" "${RESTORE_ROOT}/etc/idleleo/conf/xray"
printf 'TARGET-OLD\n' >"${RESTORE_ROOT}/etc/idleleo/conf/nginx/00-xray.conf"
printf 'TARGET-TLS-80\n' >"${RESTORE_ROOT}/etc/idleleo/conf/nginx/01-xray-80.conf"
printf 'TARGET-UPSTREAM\n' >"${RESTORE_ROOT}/etc/idleleo/conf/nginx/02-xray-server.conf"
printf 'TARGET-RELAY\n' >"${RESTORE_ROOT}/etc/idleleo/conf/nginx/relay-stream.conf"
printf 'USER-CUSTOM\n' >"${RESTORE_ROOT}/etc/idleleo/conf/nginx/99-user.conf"
SYSTEMCTL_MARKER="${TMP_ROOT}/systemctl.calls"
XRAY_TEST_MARKER="${TMP_ROOT}/xray-test.calls"
systemctl() { echo "$*" >>"${SYSTEMCTL_MARKER}"; }
output=$(SYSTEMCTL_MARKER="${SYSTEMCTL_MARKER}" XRAY_TEST_MARKER="${XRAY_TEST_MARKER}" \
    RESTORE_ROOT="${RESTORE_ROOT}" restore_directories 2>&1)
rc=$?
unset -f systemctl
[[ ${rc} -eq 0 ]] && ok "cross-mode restore returns 0" || bad "cross-mode restore rc=${rc}"
[[ -f "${RESTORE_ROOT}/etc/idleleo/conf/nginx/00-xray.conf" ]] && \
    ok "backup-managed file restored" || bad "backup-managed file missing"
[[ ! -f "${RESTORE_ROOT}/etc/idleleo/conf/nginx/01-xray-80.conf" ]] && \
    ok "target TLS 80 file pruned" || bad "target TLS 80 file remains"
[[ ! -f "${RESTORE_ROOT}/etc/idleleo/conf/nginx/02-xray-server.conf" ]] && \
    ok "target upstream file pruned" || bad "target upstream file remains"
[[ ! -f "${RESTORE_ROOT}/etc/idleleo/conf/nginx/relay-stream.conf" ]] && \
    ok "target relay file pruned" || bad "target relay file remains"
[[ -f "${RESTORE_ROOT}/etc/idleleo/conf/nginx/99-user.conf" ]] && \
    ok "user custom nginx file preserved" || bad "user custom nginx file deleted"
mode=$(stat -c '%a' "${RESTORE_ROOT}/etc/idleleo/conf/install_config.json" 2>/dev/null || stat -f '%Lp' "${RESTORE_ROOT}/etc/idleleo/conf/install_config.json")
[[ "${mode}" == "600" ]] && ok "restored config mode 0600" || bad "restored config mode=${mode}"
mode=$(stat -c '%a' "${RESTORE_ROOT}/etc/idleleo/cert/xray.key" 2>/dev/null || stat -f '%Lp' "${RESTORE_ROOT}/etc/idleleo/cert/xray.key")
[[ "${mode}" == "640" ]] && ok "restored private key mode 0640" || bad "restored private key mode=${mode}"
grep -q 'daemon-reload' "${SYSTEMCTL_MARKER}" 2>/dev/null && \
    ok "daemon-reload invoked" || bad "daemon-reload not invoked"
grep -q 'start' "${SYSTEMCTL_MARKER}" 2>/dev/null && \
    bad "restore started services unexpectedly" || ok "restore did not start services"
grep -q -- '-test' "${XRAY_TEST_MARKER}" 2>/dev/null && \
    ok "xray -test invoked" || bad "xray -test not invoked"

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
