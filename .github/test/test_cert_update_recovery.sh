#!/usr/bin/env bash
#
# Stage 01 regression tests for install.sh:cert_update_manuel():
#   - prerequisites are validated before any service is stopped
#   - a failed ACME/permission step restores the previous Xray state
#   - the renewal restarts the stack exactly once (no duplicate restarts)
#
# Usage: bash .github/test/test_cert_update_recovery.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

[[ -f "${INSTALL_SH}" ]] || { echo "FATAL: ${INSTALL_SH} not found"; exit 1; }

log_echo() { :; }
log_echo_secure() { :; }
gettext() { printf '%s' "$1"; }
judge() { return 0; }
Error=""; RedBG=""; OK=""; GreenBG=""; Font=""; Warning=""; YellowBG=""; Green=""; Red=""

export _TEST_MODE=1
# shellcheck source=/dev/null
source "${INSTALL_SH}" >/dev/null 2>&1 || true
unset _TEST_MODE

for fn in cert_update_manuel; do
    if ! declare -F "${fn}" >/dev/null 2>&1; then
        echo "FATAL: ${fn}() not defined after sourcing install.sh"
        exit 1
    fi
done

CALLS=""
xray_active="yes"
systemctl() {
    CALLS="${CALLS}$*;"
    case "$1" in
    is-active)
        [[ "${xray_active}" == "yes" ]] && return 0 || return 3
        ;;
    stop) xray_active="no" ;;
    start) xray_active="yes" ;;
    esac
    return 0
}

get_nginx_worker_group() { printf 'idleleo-nginx'; }
# The production pre-check probes the system group when getent exists. CI
# runners have getent and no idleleo-nginx group, so stub the probe; the
# macOS development host has no getent and skips it.
getent() { [[ "$1" == "group" && "$2" == "idleleo-nginx" ]]; }
info_extraction() { printf 'example.com'; }
apply_nginx_layered_permissions() { [[ "${FAIL_PERMS:-no}" != "yes" ]]; }
verify_nginx_layered_permissions() { return 0; }
service_restart() { CALLS="${CALLS}service_restart;"; return 0; }

ssl_chainpath="${TMP_ROOT}/cert"
mkdir -p "${ssl_chainpath}"
write_acme() {
    amce_sh_file="${TMP_ROOT}/acme.sh"
    cat >"${amce_sh_file}" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$CERT_TEST_LOG"
case "$*" in
  --cron*) [ ! -f "$CERT_TEST_DIR/fail_cron" ] || exit 1 ;;
  *--installcert*)
    [ ! -f "$CERT_TEST_DIR/fail_installcert" ] || exit 1
    : >"$CERT_TEST_DIR/cert/xray.crt"
    : >"$CERT_TEST_DIR/cert/xray.key"
    ;;
esac
exit 0
STUB
    chmod 755 "${amce_sh_file}"
    : >"${TMP_ROOT}/acme.log"
}

reset_case() {
    CALLS=""
    xray_active="${1:-yes}"
    FAIL_PERMS="no"
    rm -f "${TMP_ROOT}/fail_cron" "${TMP_ROOT}/fail_installcert"
    rm -f "${ssl_chainpath}/xray.crt" "${ssl_chainpath}/xray.key"
    write_acme
    export CERT_TEST_DIR="${TMP_ROOT}" CERT_TEST_LOG="${TMP_ROOT}/acme.log"
}

echo "============================================================"
echo "  manual certificate update recovery tests"
echo "============================================================"

# ---- 1. failed installcert restores a running Xray -----------------
reset_case yes
touch "${TMP_ROOT}/fail_installcert"
tls_mode="TLS"
cert_update_manuel >/dev/null 2>&1
rc=$?
[[ ${rc} -ne 0 ]] && ok "installcert failure returns non-zero" \
    || bad "installcert failure returned 0"
case "${CALLS}" in
*"start xray"*) ok "installcert failure restarts the previously running Xray" ;;
*) bad "installcert failure did not restore Xray; calls: ${CALLS}" ;;
esac
[[ "${xray_active}" == "yes" ]] && ok "Xray is running again after a failed renewal" \
    || bad "Xray was left stopped after a failed renewal"

# ---- 2. an initially stopped Xray stays stopped on failure ---------
reset_case no
touch "${TMP_ROOT}/fail_installcert"
tls_mode="TLS"
cert_update_manuel >/dev/null 2>&1
rc=$?
[[ ${rc} -ne 0 ]] && ok "failure with an initially stopped Xray returns non-zero" \
    || bad "failure with an initially stopped Xray returned 0"
case "${CALLS}" in
*"start xray"*) bad "an initially stopped Xray was started" ;;
*) ok "an initially stopped Xray is not started" ;;
esac

# ---- 3. success restarts the stack exactly once --------------------
reset_case yes
tls_mode="TLS"
cert_update_manuel >/dev/null 2>&1
rc=$?
[[ ${rc} -eq 0 ]] && ok "successful manual renewal returns 0" \
    || bad "successful manual renewal returned ${rc}"
count=$(printf '%s' "${CALLS}" | grep -o 'service_restart;' | wc -l | tr -d ' ')
[[ "${count}" == "1" ]] && ok "manual renewal restarts services exactly once" \
    || bad "service_restart was called ${count} times"
# The --reloadcmd stored in the acme.sh renewal config is replayed on every
# future automatic renewal, so it must not restart services itself.
if ! grep -q -- '--reloadcmd' "${TMP_ROOT}/acme.log"; then
    bad "installcert did not record a reload hook"
elif grep -- '--installcert' "${TMP_ROOT}/acme.log" | grep -q 'systemctl'; then
    bad "the acme.sh reload hook still restarts services"
else
    ok "the acme.sh reload hook only adjusts certificate permissions"
fi

# ---- 4. missing acme.sh aborts before touching services ------------
reset_case yes
rm -f "${amce_sh_file}"
tls_mode="TLS"
cert_update_manuel >/dev/null 2>&1
rc=$?
[[ ${rc} -ne 0 ]] && ok "missing acme.sh returns non-zero" \
    || bad "missing acme.sh returned 0"
case "${CALLS}" in
*"stop xray"*) bad "Xray was stopped before the acme.sh pre-check" ;;
*) ok "no service is stopped when acme.sh is missing" ;;
esac

# ---- 5. permission failure restores a running Xray -----------------
reset_case yes
tls_mode="TLS"
FAIL_PERMS="yes"
cert_update_manuel >/dev/null 2>&1
rc=$?
[[ ${rc} -ne 0 ]] && ok "certificate permission failure returns non-zero" \
    || bad "certificate permission failure returned 0"
[[ "${xray_active}" == "yes" ]] && ok "Xray keeps running after a permission failure" \
    || bad "Xray was left stopped after a permission failure"

# ---- 6. non-TLS mode is refused -----------------------------------
reset_case yes
tls_mode="Reality"
cert_update_manuel >/dev/null 2>&1
rc=$?
[[ ${rc} -ne 0 ]] && ok "non-TLS mode is refused" || bad "non-TLS mode was accepted"
case "${CALLS}" in
*"stop xray"*) bad "Xray was stopped for a refused mode" ;;
*) ok "refused mode does not stop Xray" ;;
esac

echo "============================================================"
echo "  PASS: ${PASS}  FAIL: ${FAIL}"
echo "============================================================"
[[ "${FAIL}" -eq 0 ]]
