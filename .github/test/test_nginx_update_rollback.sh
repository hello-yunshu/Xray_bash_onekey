#!/usr/bin/env bash
# P0-A regression tests for the real nginx_install transaction and rollback helpers.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh"

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
expect_fail() {
    local label="$1"
    shift
    if "$@"; then bad "${label} (unexpected success)"; else ok "${label}"; fi
}

log_echo() { :; }
gettext() { printf '%s' "$1"; }
ensure_idleleo_nginx_user() { return 0; }
modify_nginx_origin_conf() { return 0; }
verify_nginx_layered_permissions() { return 0; }
nginx_validate_binary_file() { return 0; }

TEST_CASE=""
BACKUP_SEEN_DURING_CONFIG_TEST=0

download_json_file() {
    local _url="$1"
    local dest="$2"
    local arch
    case "$(uname -m)" in
        x86_64) arch=x86 ;;
        *) arch=arm ;;
    esac
    [[ "${TEST_CASE}" == "manifest_download_failure" ]] && return 1
    if [[ "${TEST_CASE}" == "manifest_missing_sha" ]]; then
        printf '{"tag":"v%s","versions":{"nginx_build":"%s"},"assets":[{"arch":"%s","filename":"xray-nginx-custom-%s.tar.gz"}]}\n' \
            "${nginx_build_version}" "${nginx_build_version}" "${arch}" "${arch}" > "${dest}"
    else
        printf '{"tag":"v%s","versions":{"nginx_build":"%s"},"assets":[{"arch":"%s","filename":"xray-nginx-custom-%s.tar.gz","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}\n' \
            "${nginx_build_version}" "${nginx_build_version}" "${arch}" "${arch}" > "${dest}"
    fi
}

nginx_download_release_asset() {
    local _url="$1"
    local output="$2"
    local source_dir="${TMP_ROOT}/asset-${TEST_CASE}"
    rm -rf "${source_dir}"
    mkdir -p "${source_dir}/nginx/conf"
    printf 'events {}\nhttp {}\n' > "${source_dir}/nginx/conf/nginx.conf"

    case "${TEST_CASE}" in
        download_failure)
            return 1
            ;;
        invalid_tar)
            printf 'not a tar archive' > "${output}"
            ;;
        illegal_tar)
            python3 - "${output}" <<'PY'
import io
import sys
import tarfile
with tarfile.open(sys.argv[1], "w:gz") as tf:
    info = tarfile.TarInfo("nginx/../../escape")
    data = b"escape"
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))
PY
            ;;
        missing_binary)
            tar -czf "${output}" -C "${source_dir}" nginx
            ;;
        *)
            mkdir -p "${source_dir}/nginx/sbin"
            printf '#!/bin/sh\nexit 0\n' > "${source_dir}/nginx/sbin/nginx"
            chmod +x "${source_dir}/nginx/sbin/nginx"
            tar -czf "${output}" -C "${source_dir}" nginx
            ;;
    esac
}

nginx_verify_release_sha256() {
    [[ "${TEST_CASE}" != "sha_mismatch" ]]
}

apply_nginx_layered_permissions() {
    [[ "${TEST_CASE}" != "permission_failure" ]]
}

nginx_run_config_test() {
    if compgen -G "${nginx_dir}.pre-install.*" >/dev/null 2>&1; then
        BACKUP_SEEN_DURING_CONFIG_TEST=1
    fi
    [[ "${TEST_CASE}" != "config_test_failure" ]]
}

reset_install_tree() {
    nginx_dir="${TMP_ROOT}/nginx"
    nginx_conf_dir="${TMP_ROOT}/project-conf"
    ssl_chainpath="${TMP_ROOT}/cert"
    rm -rf "${nginx_dir}" "${nginx_dir}".pre-install.* "${nginx_conf_dir}" "${ssl_chainpath}"
    mkdir -p "${nginx_dir}/sbin" "${nginx_dir}/conf" "${nginx_conf_dir}" "${ssl_chainpath}"
    printf 'OLD_BINARY\n' > "${nginx_dir}/sbin/nginx"
    printf 'old config\n' > "${nginx_dir}/conf/nginx.conf"
    BACKUP_SEEN_DURING_CONFIG_TEST=0
    nginx_build_version="2026.07.28.7000"
}

printf '%s\n' '--- nginx_install failure propagation ---'
for TEST_CASE in \
    manifest_download_failure \
    manifest_missing_sha \
    download_failure \
    sha_mismatch \
    invalid_tar \
    illegal_tar \
    missing_binary
do
    reset_install_tree
    expect_fail "${TEST_CASE} returns instead of exiting the parent" nginx_install
    if grep -q OLD_BINARY "${nginx_dir}/sbin/nginx"; then
        ok "${TEST_CASE} preserves the previous directory"
    else
        bad "${TEST_CASE} damaged the previous directory"
    fi
done

for TEST_CASE in permission_failure config_test_failure; do
    reset_install_tree
    expect_fail "${TEST_CASE} triggers transaction failure" nginx_install
    if grep -q OLD_BINARY "${nginx_dir}/sbin/nginx"; then
        ok "${TEST_CASE} restores the previous directory"
    else
        bad "${TEST_CASE} did not restore the previous directory"
    fi
done

TEST_CASE=config_test_failure
reset_install_tree
expect_fail "config test failure remains non-zero" nginx_install
if [[ ${BACKUP_SEEN_DURING_CONFIG_TEST} -eq 1 ]]; then
    ok "pre-install backup exists until permission and nginx -t gates finish"
else
    bad "pre-install backup was deleted before nginx -t"
fi

printf '%s\n' '--- real local-backup restoration ---'
TEST_CASE=restore
nginx_dir="${TMP_ROOT}/restore/nginx"
backup_dir="${TMP_ROOT}/restore/nginx_backup"
mkdir -p "${nginx_dir}/conf" "${backup_dir}/conf"
printf 'NEW\n' > "${nginx_dir}/marker"
printf 'OLD\n' > "${backup_dir}/marker"
printf 'new user config\n' > "${nginx_dir}/conf/user.conf"
printf 'old user config\n' > "${backup_dir}/conf/user.conf"
xray_install_config_file="${TMP_ROOT}/restore/install_config.json"
printf '{"nginx_build_version":"new-version"}\n' > "${xray_install_config_file}"
service_stop() { return 0; }
service_start() { return 0; }
apply_nginx_layered_permissions() { return 0; }
verify_nginx_layered_permissions() { return 0; }
health_check_nginx_update() { return 0; }
update_json_config() {
    local config_file="$1"
    shift
    local tmp_file="${config_file}.tmp"
    jq "$@" "${config_file}" > "${tmp_file}" && mv "${tmp_file}" "${config_file}"
}
if rollback_nginx_update "${backup_dir}" "old-version" &&
   grep -q OLD "${nginx_dir}/marker" &&
   grep -q 'old user config' "${nginx_dir}/conf/user.conf" &&
   [[ "$(jq -r '.nginx_build_version' "${xray_install_config_file}")" == "old-version" ]]; then
    ok "Layer 1 restores the old directory, user config, and version record"
else
    bad "Layer 1 did not restore the exact old state"
fi

printf '%s\n' '--- new service activation failure ---'
apply_nginx_layered_permissions() { return 0; }
verify_nginx_layered_permissions() { return 0; }
service_start() { return 1; }
health_check_nginx_update() {
    bad "health check ran after service startup failed"
    return 0
}
expect_fail "new service startup failure is propagated" activate_nginx_update "443"

printf '%s\n' '--- layered rollback control flow ---'
RESTORE_RESULT=0
FALLBACK_RESULT=0
RESTORE_CALLS=0
FALLBACK_CALLS=0
UPDATE_CALLS=0
UPDATE_RESULT=0
STOP_CALLS=0
ORDER=""
restore_nginx_backup() {
    RESTORE_CALLS=$((RESTORE_CALLS + 1))
    ORDER="${ORDER} restore"
    return "${RESTORE_RESULT}"
}
fallback_nginx_to_tested_version() {
    FALLBACK_CALLS=$((FALLBACK_CALLS + 1))
    ORDER="${ORDER} fallback"
    return "${FALLBACK_RESULT}"
}
update_json_config() {
    UPDATE_CALLS=$((UPDATE_CALLS + 1))
    [[ "$*" == *"old-version"* ]] && return "${UPDATE_RESULT}"
    return 1
}
safe_rm() {
    ORDER="${ORDER} rm"
    rm -rf "$1"
}
systemctl() {
    [[ "${1:-}" == "stop" ]] && STOP_CALLS=$((STOP_CALLS + 1))
    return 0
}
nginx_diagnose() { ORDER="${ORDER} diagnose"; }

RESTORE_RESULT=0
FALLBACK_RESULT=1
RESTORE_CALLS=0
FALLBACK_CALLS=0
UPDATE_CALLS=0
ORDER=""
if rollback_nginx_update "${TMP_ROOT}/outer-backup" "old-version"; then
    [[ ${RESTORE_CALLS} -eq 1 && ${FALLBACK_CALLS} -eq 0 && ${UPDATE_CALLS} -eq 1 ]] \
        && ok "Layer 1 success prevents Layer 2" \
        || bad "Layer 1 success called the wrong layers"
else
    bad "Layer 1 success was reported as recovery failure"
fi

RESTORE_RESULT=1
FALLBACK_RESULT=0
UPDATE_RESULT=0
RESTORE_CALLS=0
FALLBACK_CALLS=0
ORDER=""
mkdir -p "${TMP_ROOT}/outer-backup"
if rollback_nginx_update "${TMP_ROOT}/outer-backup" "old-version"; then
    [[ ${RESTORE_CALLS} -eq 1 && ${FALLBACK_CALLS} -eq 1 ]] \
        && ok "Layer 1 failure calls Layer 2 exactly once" \
        || bad "Layer 2 attempt count is wrong"
    [[ "${ORDER}" == *"restore fallback rm"* ]] \
        && ok "outer backup is kept until tested fallback succeeds" \
        || bad "outer backup cleanup happened before fallback health"
else
    bad "Layer 2 success was reported as recovery failure"
fi

RESTORE_RESULT=0
FALLBACK_RESULT=0
UPDATE_RESULT=1
RESTORE_CALLS=0
FALLBACK_CALLS=0
if rollback_nginx_update "${TMP_ROOT}/outer-backup" "old-version"; then
    [[ ${RESTORE_CALLS} -eq 1 && ${FALLBACK_CALLS} -eq 1 ]] \
        && ok "Layer 1 version-record failure continues to Layer 2" \
        || bad "Layer 1 version-record failure skipped Layer 2"
else
    bad "Layer 2 recovery after version-record failure was reported as failure"
fi

RESTORE_RESULT=1
FALLBACK_RESULT=1
UPDATE_RESULT=0
RESTORE_CALLS=0
FALLBACK_CALLS=0
STOP_CALLS=0
ORDER=""
if rollback_nginx_update "${TMP_ROOT}/outer-backup" "old-version"; then
    bad "Layer 1 + Layer 2 failure returned success"
else
    [[ ${RESTORE_CALLS} -eq 1 && ${FALLBACK_CALLS} -eq 1 && ${STOP_CALLS} -eq 1 ]] \
        && ok "Layer 3 is reached once after both recovery layers fail" \
        || bad "Layer 3 control flow or attempt counts are wrong"
fi

RESTORE_RESULT=0
FALLBACK_RESULT=1
if recover_failed_nginx_update "${TMP_ROOT}/outer-backup" "old-version"; then
    bad "recovered service incorrectly turns the failed update into success"
else
    ok "failed update returns non-zero even after successful service recovery"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
