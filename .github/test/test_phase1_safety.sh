#!/usr/bin/env bash
# P1-C/P1-D and production diagnostic-redaction regression tests.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { :; }
gettext() { printf '%s' "$1"; }

printf '%s\n' '--- safe language.conf parsing ---'
valid_conf="${TMP_ROOT}/valid-language.conf"
printf 'LANG="zh_CN.UTF-8"\nLC_MESSAGES=en_US.UTF-8\n' > "${valid_conf}"
unset LANG LC_MESSAGES
if safe_source_language_conf "${valid_conf}" &&
   [[ "${LANG:-}" == "zh_CN.UTF-8" && "${LC_MESSAGES:-}" == "en_US.UTF-8" ]]; then
    ok "valid LANG and LC_MESSAGES are applied"
else
    bad "valid language.conf was not applied"
fi

malicious_conf="${TMP_ROOT}/malicious-language.conf"
marker="${TMP_ROOT}/must-not-exist"
printf 'LANG=en_US.UTF-8\nEVIL=$(touch %s)\n' "${marker}" > "${malicious_conf}"
unset LANG LC_MESSAGES
if safe_source_language_conf "${malicious_conf}"; then
    bad "mixed valid/malicious language.conf was accepted"
else
    ok "mixed valid/malicious language.conf is rejected as a unit"
fi
[[ ! -e "${marker}" ]] && ok "language.conf command substitution was not executed" ||
    bad "language.conf command substitution executed"
[[ -z "${LANG:-}" && -z "${LC_MESSAGES:-}" ]] &&
    ok "rejected language.conf does not partially change the environment" ||
    bad "rejected language.conf partially changed the environment"

printf '%s\n' '--- apt/dpkg lock waiting ---'
lock_file="${TMP_ROOT}/dpkg.lock"
touch "${lock_file}"
APT_LOCK_FILES="${lock_file}"
FUSER_CALLS=0
fuser() {
    FUSER_CALLS=$((FUSER_CALLS + 1))
    [[ ${FUSER_CALLS} -le 2 ]]
}
sleep() { :; }
if wait_for_apt_lock 5 && [[ ${FUSER_CALLS} -ge 3 ]]; then
    ok "apt lock wait succeeds only after the holder releases it"
else
    bad "apt lock wait did not observe holder release"
fi
[[ -e "${lock_file}" ]] && ok "apt lock file is never deleted" ||
    bad "apt lock file was deleted"

fuser() { return 0; }
if wait_for_apt_lock 2; then
    bad "apt lock timeout returned success"
else
    ok "apt lock timeout fails closed"
fi
[[ -e "${lock_file}" ]] && ok "timed-out apt lock file is preserved" ||
    bad "timed-out apt lock file was deleted"

printf '%s\n' '--- production diagnostic redaction ---'
secret_uuid="11111111-2222-3333-4444-555555555555"
secret_key="PRIVATE_KEY_TEST_abcdef"
secret_bearer="ordinaryBearerSecret123"
secret_pem_body="cGVtLXByaXZhdGUta2V5LXRlc3Q="
diagnostic=$(printf 'unlabelled %s\nprivateKey: %s\nAuthorization: Bearer %s\n-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n' \
    "${secret_uuid}" "${secret_key}" "${secret_bearer}" "${secret_pem_body}" | redact_diagnostic_text)
if printf '%s' "${diagnostic}" | grep -Fq "${secret_uuid}" ||
   printf '%s' "${diagnostic}" | grep -Fq "${secret_key}" ||
   printf '%s' "${diagnostic}" | grep -Fq "${secret_bearer}" ||
   printf '%s' "${diagnostic}" | grep -Fq "${secret_pem_body}"; then
    bad "production diagnostic redactor leaked a UUID, bearer token, or private key"
else
    ok "production diagnostic redactor removes UUID, bearer token, and private-key blocks"
fi

printf '%s\n' '--- pre-existing Nginx worker bootstrap ---'
nginx_dir="${TMP_ROOT}/existing-nginx"
mkdir -p "${nginx_dir}"
NGINX_USER_BOOTSTRAP_CALLS=0
ensure_idleleo_nginx_user() {
    NGINX_USER_BOOTSTRAP_CALLS=$((NGINX_USER_BOOTSTRAP_CALLS + 1))
}
get_nginx_worker_group() { printf '%s\n' 'idleleo-nginx'; }
apply_nginx_layered_permissions() { return 0; }
verify_nginx_layered_permissions() { return 0; }
if harden_config_permissions && [[ ${NGINX_USER_BOOTSTRAP_CALLS} -eq 1 ]]; then
    ok "existing Nginx tree bootstraps its dedicated worker before hardening"
else
    bad "existing Nginx tree was hardened without bootstrapping its worker"
fi

printf '%s\n' '--- pre-existing custom Nginx TLS bootstrap order ---'
nginx_dir="${TMP_ROOT}/existing-custom-nginx"
nginx_conf_dir="${TMP_ROOT}/existing-custom-conf"
mkdir -p "${nginx_dir}/sbin" "${nginx_dir}/conf" "${nginx_conf_dir}"
touch "${nginx_dir}/sbin/nginx"
printf 'events {}\nhttp {}\n' > "${nginx_dir}/conf/nginx.conf"
cp "${nginx_dir}/conf/nginx.conf" "${nginx_conf_dir}/nginx.default"
NGINX_BOOTSTRAP_ORDER=""
ensure_idleleo_nginx_user() {
    NGINX_BOOTSTRAP_ORDER="${NGINX_BOOTSTRAP_ORDER}user "
}
modify_nginx_origin_conf() {
    NGINX_BOOTSTRAP_ORDER="${NGINX_BOOTSTRAP_ORDER}config"
}
info_extraction() {
    [[ "$1" == "nginx_build_version" ]] && printf '%s\n' '2026.07.15.6961'
}
if nginx_exist_check && [[ "${NGINX_BOOTSTRAP_ORDER}" == "user config" ]]; then
    ok "existing custom Nginx creates its worker before TLS config preparation"
else
    bad "existing custom Nginx prepared TLS config before creating its worker"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
