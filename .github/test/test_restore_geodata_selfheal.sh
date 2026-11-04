#!/usr/bin/env bash
#
# Restore self-heal regression: old archives without the managed
# /usr/local/share/xray symlink must restore onto a fresh host without a
# reinstall, and a restore that cannot pass the real `xray run -test` must roll
# the layout back instead of leaving a half-healed tree.
#
# Fixtures are real tar.gz archives built by this script:
#   A. legacy layout: real /usr/local/share/xray + managed /etc/idleleo/share/xray
#   B. very old layout: no /usr/local/share/xray entry, managed data only
#   C. legacy tree only: /usr/local/share/xray data, managed target pre-seeded
#   D. invalid geodata: the healed layout cannot pass `xray run -test`
#
# The real Xray binary is taken from $XRAY_BIN (CI matrix) or PATH. Layout and
# rollback assertions still run without it; the read-through-symlink assertions
# are reported as SKIP instead of pretending to pass.
#
# Usage: bash .github/test/test_restore_geodata_selfheal.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"

PASS=0
FAIL=0
SKIP=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP: %s\n' "$1"; }
check() { if "$@"; then ok "$1"; else bad "$1"; fi; }

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

# Real binary: explicit override, standard install path, then PATH.
XRAY_REAL=""
for _candidate in "${XRAY_BIN:-}" /usr/local/bin/xray "$(command -v xray 2>/dev/null || true)"; do
    if [[ -n "${_candidate}" && -x "${_candidate}" ]]; then
        XRAY_REAL="${_candidate}"
        break
    fi
done

# ---- sandboxed environment (no root, no host service calls) ----------------
SYSTEMCTL_LOG="${TMP_ROOT}/systemctl.log"
systemctl() { printf '%s\n' "$*" >>"${SYSTEMCTL_LOG}"; }
countdown() { :; }
read_optimize() { printf -v "$2" '%s' "case"; }

export _TEST_MODE=1
# shellcheck source=/dev/null
source "${INSTALL_SH}" >/dev/null 2>&1 || true
unset _TEST_MODE

log_echo() { printf '%s\n' "$*"; }
gettext() { printf '%s' "$1"; }

# Restored-tree paths are production-relative, like the real restore.
idleleo_dir="${TMP_ROOT}/archives"
local_bin="/usr/local"
xray_bin_dir="/usr/local/bin"
xray_conf_dir="/etc/idleleo/conf/xray"
xray_conf="${xray_conf_dir}/config.json"
xray_install_config_file="/etc/idleleo/conf/install_config.json"
mkdir -p "${idleleo_dir}"

# Minimal but valid geodata (protobuf, base64-encoded so the test has no
# Python/protobuf dependency in minimal CI images). Both variants contain
# geoip:private and geosite:cn, so the restored config is valid; the variant
# CIDR/domain keeps the two fixture generations byte-distinct.
make_geo() {
    local dir="$1" variant="$2" geoip geosite
    mkdir -p "${dir}"
    case "${variant}" in
        1)
            geoip='Ch0KB1BSSVZBVEUSCAoECgAAABAIEggKBAoBAAAQEA=='
            geosite='Ch0KAkNOEhcIABITZml4dHVyZTEuZXhhbXBsZS5jbg=='
            ;;
        2)
            geoip='Ch0KB1BSSVZBVEUSCAoECgAAABAIEggKBAoCAAAQEA=='
            geosite='Ch0KAkNOEhcIABITZml4dHVyZTIuZXhhbXBsZS5jbg=='
            ;;
        *) return 1 ;;
    esac
    printf '%s' "${geoip}" | base64 -d >"${dir}/geoip.dat" || return 1
    printf '%s' "${geosite}" | base64 -d >"${dir}/geosite.dat" || return 1
}

make_bad_geo() {
    local dir="$1"
    mkdir -p "${dir}"
    printf 'not-a-protobuf-geodata\n' >"${dir}/geoip.dat"
    printf 'not-a-protobuf-geodata\n' >"${dir}/geosite.dat"
}

make_config() {
    local file="$1"
    mkdir -p "${file%/*}"
    cat >"${file}" <<'JSON'
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks"}],
  "outbounds": [{"tag": "direct", "protocol": "freedom"}],
  "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "domain": ["geosite:cn"], "outboundTag": "direct"}]}
}
JSON
}

# build_archive <name> <with-legacy-real-dir:0|1> <managed:variant|bad|none> <legacy:variant|bad>
build_archive() {
    local name="$1" with_legacy="$2" managed="$3" legacy="$4"
    local stage="${TMP_ROOT}/stage-${name}"
    rm -rf "${stage}"
    mkdir -p "${stage}/etc/idleleo/conf/xray" "${stage}/usr/local/bin"
    printf 'shell_version="3.3.1"\n' >"${stage}/etc/idleleo/install.sh"
    printf '{"shell_version":"3.3.1"}\n' >"${stage}/etc/idleleo/conf/install_config.json"
    make_config "${stage}/etc/idleleo/conf/xray/config.json"
    if [[ "${XRAY_REAL}" != "" ]]; then
        cp "${XRAY_REAL}" "${stage}/usr/local/bin/xray"
        chmod +x "${stage}/usr/local/bin/xray"
    else
        # Layout-only hosts still exercise the overlay; validation is skipped.
        printf '#!/bin/sh\nexit 0\n' >"${stage}/usr/local/bin/xray"
        chmod +x "${stage}/usr/local/bin/xray"
    fi
    case "${managed}" in
        none) ;;
        bad) make_bad_geo "${stage}/etc/idleleo/share/xray" ;;
        *) make_geo "${stage}/etc/idleleo/share/xray" "${managed}" ;;
    esac
    if [[ "${with_legacy}" == "1" ]]; then
        case "${legacy}" in
            bad) make_bad_geo "${stage}/usr/local/share/xray" ;;
            *) make_geo "${stage}/usr/local/share/xray" "${legacy}" ;;
        esac
    fi
    # Per-file manifest, same model as a real backup. It must be written after
    # every fixture file exists and must not include itself.
    (
        cd "${stage}" || exit 1
        find etc usr -type f ! -name '.backup_sha256sums.txt' -print0 |
            sort -z | xargs -0 sha256sum >etc/idleleo/.backup_sha256sums.txt
    ) || return 1
    rm -f "${idleleo_dir}"/xray_bash_*.tar.gz
    local -a paths=(etc/idleleo usr/local/bin/xray)
    [[ -d "${stage}/usr/local/share/xray" ]] && paths+=(usr/local/share/xray)
    ( cd "${stage}" && tar -czf "${idleleo_dir}/xray_bash_${name}_20240101000000.tar.gz" "${paths[@]}" ) || return 1
    chmod 600 "${idleleo_dir}/xray_bash_${name}_20240101000000.tar.gz"
}

fresh_root() {
    local root="$1"
    rm -rf "${root}"
    mkdir -p "${root}"
}

# Run the real binary with Xray's asset root pointed at the healed link. The
# OS follows the symlink, so this proves the data is reachable at the path the
# restored configuration expects.
probe_with_asset() {
    local root="$1"
    XRAY_LOCATION_ASSET="${root}/usr/local/share/xray" \
        "${root}/usr/local/bin/xray" run -test -config "${root}/etc/idleleo/conf/xray/config.json" >/dev/null 2>&1
}

# Stronger probe when running as root on Linux: chroot into the restored tree
# so Xray's default /usr/local/share/xray lookup itself resolves the symlink.
probe_chroot() {
    local root="$1" original rc
    original=$(readlink "${root}/usr/local/share/xray" 2>/dev/null || true)
    # The restored link is relocated into the temp root for host-side probes.
    # Inside chroot the canonical production target is the meaningful one, so
    # swap it for the duration of the probe and restore the fixture afterwards.
    ln -sfn /etc/idleleo/share/xray "${root}/usr/local/share/xray"
    chroot "${root}" /usr/local/bin/xray run -test \
        -config /etc/idleleo/conf/xray/config.json >/dev/null 2>&1
    rc=$?
    ln -sfn "${original}" "${root}/usr/local/share/xray"
    return "${rc}"
}

backup_dirs() {
    local root="$1"
    compgen -G "${root}/usr/local/share/xray.restore-backup.*" || true
}

echo "============================================================"
echo "  Restore GeoData layout self-heal (legacy archives)"
echo "============================================================"

# ---------------------------------------------------------------------------
# A + D. Real legacy directory -> merge, link, validate; repeat restore is
# idempotent (correct symlink state).
# ---------------------------------------------------------------------------
echo ""
echo "-- A. legacy real directory restores to a fresh root --"
build_archive legacy-real 1 1 2 || { echo "FATAL: fixture build failed"; exit 1; }
ROOT_A="${TMP_ROOT}/root-a"
fresh_root "${ROOT_A}"
output=$(RESTORE_ROOT="${ROOT_A}" SYSTEMCTL_LOG="${SYSTEMCTL_LOG}" restore_directories 2>&1)
rc=$?
[[ ${rc} -eq 0 ]] && ok "legacy archive restore returns 0" || bad "legacy archive restore rc=${rc}"
[[ -L "${ROOT_A}/usr/local/share/xray" ]] && ok "managed symlink created" || bad "managed symlink missing"
link_target=$(readlink "${ROOT_A}/usr/local/share/xray" 2>/dev/null || true)
[[ "${link_target}" == "${ROOT_A}/etc/idleleo/share/xray" ]] && \
    ok "symlink points at the managed asset directory" || bad "symlink target=${link_target}"
[[ -f "${ROOT_A}/etc/idleleo/share/xray/geoip.dat" && -f "${ROOT_A}/etc/idleleo/share/xray/geosite.dat" ]] && \
    ok "managed geodata present after heal" || bad "managed geodata missing"
backup_count=$(backup_dirs "${ROOT_A}" | wc -l | tr -d ' ')
[[ "${backup_count}" == "1" ]] && ok "legacy directory kept as one rollback copy" || bad "rollback copies=${backup_count}"
copied_ip=$(sha256sum "${ROOT_A}/etc/idleleo/share/xray/geoip.dat" 2>/dev/null | awk '{print $1}')
legacy_backup=$(backup_dirs "${ROOT_A}" | head -1)
[[ -f "${legacy_backup}/geoip.dat" ]] && ok "rollback copy holds the original legacy file" || bad "rollback copy missing original file"
[[ "${output}" == *"已将旧 GeoData 目录合并到"* ]] && ok "merge is reported" || bad "merge not reported"
[[ "${output}" == *"同名文件以目标目录为准"* ]] && ok "same-name policy is reported" || bad "same-name policy not reported"

if [[ "${XRAY_REAL}" != "" ]]; then
    probe_with_asset "${ROOT_A}"
    prc=$?
    [[ ${prc} -eq 0 ]] && ok "real xray reads geodata through the symlink (run -test rc=0)" || bad "real xray probe rc=${prc}"
    if [[ "$(id -u)" == "0" ]] && [[ "$(uname -s)" == "Linux" ]] && command -v chroot >/dev/null 2>&1; then
        probe_chroot "${ROOT_A}"
        crc=$?
        [[ ${crc} -eq 0 ]] && ok "chrooted default /usr/local/share/xray lookup passes" || bad "chrooted lookup rc=${crc}"
    else
        skip "chrooted default-lookup probe (needs root on Linux)"
    fi
    # Negative control: the same probe must fail when the files are not valid
    # geodata. This proves the PASS above really loaded the restored files.
    probe_copy="${TMP_ROOT}/probe-negative"
    rm -rf "${probe_copy}"
    mkdir -p "${probe_copy}"
    cp -a "${ROOT_A}/etc/idleleo/share/xray/." "${probe_copy}/"
    printf 'broken\n' >"${probe_copy}/geosite.dat"
    XRAY_LOCATION_ASSET="${probe_copy}" "${ROOT_A}/usr/local/bin/xray" run -test \
        -config "${ROOT_A}/etc/idleleo/conf/xray/config.json" >/dev/null 2>&1
    nrc=$?
    [[ ${nrc} -ne 0 ]] && ok "negative control: invalid geodata rejected (rc=${nrc})" || bad "negative control unexpectedly passed"
else
    skip "real Xray read-through-symlink assertions (set XRAY_BIN)"
fi

echo "-- A2. repeating the same restore is idempotent --"
output=$(RESTORE_ROOT="${ROOT_A}" SYSTEMCTL_LOG="${SYSTEMCTL_LOG}" restore_directories 2>&1)
rc=$?
[[ ${rc} -eq 0 ]] && ok "repeat restore returns 0" || bad "repeat restore rc=${rc}"
[[ -L "${ROOT_A}/usr/local/share/xray" ]] && ok "repeat restore keeps the symlink" || bad "repeat restore lost the symlink"
backup_count=$(backup_dirs "${ROOT_A}" | wc -l | tr -d ' ')
[[ "${backup_count}" == "1" ]] && ok "repeat restore does not create another rollback copy" || bad "rollback copies=${backup_count}"
copied_ip_after=$(sha256sum "${ROOT_A}/etc/idleleo/share/xray/geoip.dat" 2>/dev/null | awk '{print $1}')
[[ "${copied_ip}" == "${copied_ip_after}" ]] && ok "repeat restore keeps managed geodata unchanged" || bad "managed geodata changed"
if [[ "${XRAY_REAL}" != "" ]]; then
    probe_with_asset "${ROOT_A}"
    [[ $? -eq 0 ]] && ok "repeat restore still passes the real xray probe" || bad "repeat restore failed the real xray probe"
else
    skip "repeat real xray probe (set XRAY_BIN)"
fi

# ---------------------------------------------------------------------------
# B. No legacy entry at all, managed data restored -> state 2 (create link).
# ---------------------------------------------------------------------------
echo ""
echo "-- B. missing asset path with restored managed geodata --"
build_archive no-legacy-entry 0 1 none || { echo "FATAL: fixture build failed"; exit 1; }
ROOT_B="${TMP_ROOT}/root-b"
fresh_root "${ROOT_B}"
output=$(RESTORE_ROOT="${ROOT_B}" SYSTEMCTL_LOG="${SYSTEMCTL_LOG}" restore_directories 2>&1)
rc=$?
[[ ${rc} -eq 0 ]] && ok "archive without asset entry restores 0" || bad "archive without asset entry rc=${rc}"
[[ -L "${ROOT_B}/usr/local/share/xray" ]] && ok "symlink created from managed geodata" || bad "symlink not created"
[[ "${output}" == *"已创建 GeoData 资源目录软链"* ]] && ok "link creation is reported" || bad "link creation not reported"
if [[ "${XRAY_REAL}" != "" ]]; then
    probe_with_asset "${ROOT_B}"
    [[ $? -eq 0 ]] && ok "real xray reads the newly linked data" || bad "real xray probe failed for state 2"
else
    skip "state 2 real xray probe (set XRAY_BIN)"
fi

# ---------------------------------------------------------------------------
# C. Target already has geodata, legacy tree differs -> target wins.
# ---------------------------------------------------------------------------
echo ""
echo "-- C. target already has geodata; legacy file must not overwrite it --"
build_archive legacy-only 1 none 2 || { echo "FATAL: fixture build failed"; exit 1; }
ROOT_C="${TMP_ROOT}/root-c"
fresh_root "${ROOT_C}"
make_geo "${ROOT_C}/etc/idleleo/share/xray" 1
target_ip=$(sha256sum "${ROOT_C}/etc/idleleo/share/xray/geoip.dat" | awk '{print $1}')
target_site=$(sha256sum "${ROOT_C}/etc/idleleo/share/xray/geosite.dat" | awk '{print $1}')
output=$(RESTORE_ROOT="${ROOT_C}" SYSTEMCTL_LOG="${SYSTEMCTL_LOG}" restore_directories 2>&1)
rc=$?
[[ ${rc} -eq 0 ]] && ok "pre-seeded target restores 0" || bad "pre-seeded target rc=${rc}"
[[ -L "${ROOT_C}/usr/local/share/xray" ]] && ok "pre-seeded target gets the symlink" || bad "pre-seeded target missing symlink"
after_ip=$(sha256sum "${ROOT_C}/etc/idleleo/share/xray/geoip.dat" | awk '{print $1}')
after_site=$(sha256sum "${ROOT_C}/etc/idleleo/share/xray/geosite.dat" | awk '{print $1}')
[[ "${after_ip}" == "${target_ip}" && "${after_site}" == "${target_site}" ]] && \
    ok "existing managed geodata wins on filename collision" || bad "legacy file overwrote existing geodata"
legacy_backup=$(backup_dirs "${ROOT_C}" | head -1)
legacy_ip=$(sha256sum "${legacy_backup}/geoip.dat" | awk '{print $1}')
[[ "${legacy_ip}" != "${target_ip}" ]] && ok "legacy file is preserved in the rollback copy" || bad "legacy file not preserved"
if [[ "${XRAY_REAL}" != "" ]]; then
    probe_with_asset "${ROOT_C}"
    [[ $? -eq 0 ]] && ok "real xray reads the kept target data" || bad "real xray probe failed on target-wins case"
else
    skip "target-wins real xray probe (set XRAY_BIN)"
fi

# ---------------------------------------------------------------------------
# C2. Legacy tree with no managed target -> files are actually copied.
# ---------------------------------------------------------------------------
echo ""
echo "-- C2. legacy-only archive fills an empty managed directory --"
ROOT_C2="${TMP_ROOT}/root-c2"
fresh_root "${ROOT_C2}"
output=$(RESTORE_ROOT="${ROOT_C2}" SYSTEMCTL_LOG="${SYSTEMCTL_LOG}" restore_directories 2>&1)
rc=$?
[[ ${rc} -eq 0 ]] && ok "legacy-only archive restores 0" || bad "legacy-only archive rc=${rc}"
[[ -L "${ROOT_C2}/usr/local/share/xray" ]] && ok "legacy-only archive creates the symlink" || bad "legacy-only archive missing symlink"
[[ -f "${ROOT_C2}/etc/idleleo/share/xray/geoip.dat" && -f "${ROOT_C2}/etc/idleleo/share/xray/geosite.dat" ]] && \
    ok "legacy files are copied into the managed directory" || bad "legacy files were not copied"
backup_count=$(backup_dirs "${ROOT_C2}" | wc -l | tr -d ' ')
[[ "${backup_count}" == "1" ]] && ok "copied legacy tree keeps its rollback copy" || bad "rollback copies=${backup_count}"
if [[ "${XRAY_REAL}" != "" ]]; then
    probe_with_asset "${ROOT_C2}"
    [[ $? -eq 0 ]] && ok "real xray reads the copied legacy data" || bad "real xray probe failed on copy case"
else
    skip "copied-legacy real xray probe (set XRAY_BIN)"
fi

# ---------------------------------------------------------------------------
# D. Validation failure -> layout and config roll back, no half-healed tree.
# ---------------------------------------------------------------------------
echo ""
echo "-- D. failed xray -test rolls the heal back --"
build_archive invalid-geo 1 none bad || { echo "FATAL: fixture build failed"; exit 1; }
ROOT_D="${TMP_ROOT}/root-d"
fresh_root "${ROOT_D}"
config_before=$(sha256sum "${TMP_ROOT}/stage-invalid-geo/etc/idleleo/conf/xray/config.json" | awk '{print $1}')
output=$(RESTORE_ROOT="${ROOT_D}" SYSTEMCTL_LOG="${SYSTEMCTL_LOG}" restore_directories 2>&1)
rc=$?
if [[ "${XRAY_REAL}" != "" ]]; then
    [[ ${rc} -ne 0 ]] && ok "failed validation returns non-zero" || bad "failed validation returned 0"
    [[ "${output}" == *"GeoData 自愈后 Xray 配置自检失败"* ]] && ok "validation failure is reported" || bad "validation failure not reported"
    [[ ! -L "${ROOT_D}/usr/local/share/xray" ]] && ok "rollback removes the created symlink" || bad "symlink left behind"
    [[ -d "${ROOT_D}/usr/local/share/xray" ]] && ok "rollback restores the real legacy directory" || bad "legacy directory not restored"
    [[ -f "${ROOT_D}/usr/local/share/xray/geoip.dat" ]] && ok "rolled-back legacy data is intact" || bad "rolled-back legacy data missing"
    backup_count=$(backup_dirs "${ROOT_D}" | wc -l | tr -d ' ')
    [[ "${backup_count}" == "0" ]] && ok "rollback removes the rollback copy" || bad "rollback copy left behind"
    [[ ! -e "${ROOT_D}/etc/idleleo/share/xray/geoip.dat" ]] && \
        ok "rollback removes files copied into the managed directory" || bad "copied files left behind"
    [[ "${output}" == *"已回滚到恢复前状态"* ]] && ok "rollback is reported" || bad "rollback not reported"
    config_after=$(sha256sum "${ROOT_D}/etc/idleleo/conf/xray/config.json" | awk '{print $1}')
    [[ "${config_before}" == "${config_after}" ]] && ok "config is restored byte-for-byte" || bad "config changed after rollback"
else
    skip "validation-failure rollback assertions (set XRAY_BIN)"
fi

# ---------------------------------------------------------------------------
# E. Rescue actions never restart an inactive service or touch config on
# failure (they live in traffic_blocker.sh; covered here for the restore path).
# ---------------------------------------------------------------------------
echo ""
echo "-- E. restore never starts services --"
if grep -qE '(start|restart|stop)' "${SYSTEMCTL_LOG}" 2>/dev/null; then
    bad "restore invoked a service start/restart/stop"
else
    ok "restore never starts or restarts services"
fi

printf '\nSummary: PASS=%d FAIL=%d SKIP=%d\n' "${PASS}" "${FAIL}" "${SKIP}"
[[ ${FAIL} -eq 0 ]]
