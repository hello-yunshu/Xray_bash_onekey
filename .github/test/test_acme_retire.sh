#!/usr/bin/env bash
# S7-4 regression tests: acme.sh is retired from issuance/renewal and kept on
# disk for one release. Every native path must fail closed when the idleleo
# entry is missing, and the retained acme.sh must never be uninstalled.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { printf '%s\n' "$*" >&2; }
gettext() { printf '%s' "$1"; }

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

STUB_BIN="${TMP_ROOT}/bin"
mkdir -p "${STUB_BIN}"
IDLELEO_CALL_LOG="${TMP_ROOT}/idleleo.calls"
SYSTEMCTL_CALL_LOG="${TMP_ROOT}/systemctl.calls"
DOWNLOAD_MARKER="${TMP_ROOT}/download-used"
export IDLELEO_CALL_LOG SYSTEMCTL_CALL_LOG DOWNLOAD_MARKER

cat >"${STUB_BIN}/idleleo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${IDLELEO_CALL_LOG}"
if [[ "${FAKE_IDLELEO_RC:-0}" != "0" ]]; then
    exit "${FAKE_IDLELEO_RC}"
fi
exit 0
EOF
chmod +x "${STUB_BIN}/idleleo"

cat >"${STUB_BIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${SYSTEMCTL_CALL_LOG}"
exit 0
EOF
chmod +x "${STUB_BIN}/systemctl"

# Every case starts from empty stub logs so one case cannot hide a failure in
# the next one.
reset_logs() {
    : >"${IDLELEO_CALL_LOG}"
    : >"${SYSTEMCTL_CALL_LOG}"
    rm -f "${DOWNLOAD_MARKER}"
}

# A native ssl_install must never reach the acme.sh downloader. Record any call
# so the assertion can prove the download branch was not taken.
download_script_file() {
    : >"${DOWNLOAD_MARKER}"
    return 0
}

base_path=${PATH}
unset IDLELEO_ACME_LEGACY

printf '%s\n' '--- ssl_install default is native and offline ---'
reset_logs
if PATH="${STUB_BIN}:${base_path}" ssl_install </dev/null >/dev/null 2>&1 &&
    [[ ! -e "${DOWNLOAD_MARKER}" ]]; then
    ok "native ssl_install succeeds without downloading acme.sh"
else
    bad "native ssl_install failed or fell back to downloading acme.sh"
fi

printf '%s\n' '--- ssl_install fails closed without idleleo ---'
reset_logs
if PATH="${base_path}" ssl_install </dev/null >/dev/null 2>&1; then
    bad "ssl_install succeeded without idleleo on PATH"
else
    ok "native ssl_install fails closed when idleleo is missing"
fi

printf '%s\n' '--- acme() issues through idleleo ---'
ssl_chainpath="${TMP_ROOT}/cert"
idleleo_conf_dir="${TMP_ROOT}/conf"
mkdir -p "${ssl_chainpath}" "${idleleo_conf_dir}"
domain="example.com"
custom_email=""
get_nginx_worker_group() { printf '%s' "idleleo-nginx"; }
apply_nginx_layered_permissions() { return 0; }
verify_nginx_layered_permissions() { return 0; }
reset_logs
if PATH="${STUB_BIN}:${base_path}" acme </dev/null >/dev/null 2>&1 &&
    grep -q 'xray cert issue --domain example\.com' "${IDLELEO_CALL_LOG}" &&
    [[ $(grep -c '^stop nginx$' "${SYSTEMCTL_CALL_LOG}") -eq 1 ]]; then
    ok "native acme() calls 'xray cert issue --domain example.com' and stops nginx once"
else
    bad "native acme() did not use idleleo or the nginx stop count differs: $(cat "${IDLELEO_CALL_LOG}")"
fi

printf '%s\n' '--- acme() is really red when idleleo fails ---'
reset_logs
export FAKE_IDLELEO_RC=1
PATH="${STUB_BIN}:${base_path}" acme </dev/null >/dev/null 2>&1
acme_rc=$?
unset FAKE_IDLELEO_RC
if [[ ${acme_rc} -eq 0 ]]; then
    bad "acme() reported success although idleleo failed"
else
    ok "idleleo failure propagates out of acme()"
fi

printf '%s\n' '--- delete_tls_key_and_crt keeps acme.sh ---'
saved_home=${HOME}
HOME="${TMP_ROOT}/home-delete"
mkdir -p "${HOME}/.acme.sh/example.com_ecc"
: >"${HOME}/.acme.sh/acme.sh"
delete_tls_key_and_crt >/dev/null 2>&1
if [[ -f "${HOME}/.acme.sh/acme.sh" && ! -d "${HOME}/.acme.sh/example.com_ecc" ]]; then
    ok "per-domain state removed while ~/.acme.sh/acme.sh is retained"
else
    bad "delete_tls_key_and_crt removed the installed acme.sh or kept domain state"
fi
HOME=${saved_home}

printf '%s\n' '--- acme_cron_cleanup removes only the acme renewal line ---'
saved_home=${HOME}
HOME="${TMP_ROOT}/home-cron"
mkdir -p "${HOME}/.acme.sh"
CRON_FIXTURE="${TMP_ROOT}/root.crontab"
cat >"${CRON_FIXTURE}" <<'EOF'
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null
0 3 * * * /etc/idleleo/scripts/ssl_update.sh >/dev/null 2>&1
EOF
root_crontab_path() { printf '%s' "${CRON_FIXTURE}"; }
acme_cron_cleanup >/dev/null 2>&1
if ! grep -q 'acme\.sh.*--cron' "${CRON_FIXTURE}" &&
    grep -q 'ssl_update.sh' "${CRON_FIXTURE}" &&
    [[ -d "${HOME}/.acme.sh" ]]; then
    ok "acme cron line removed, ssl_update.sh kept and ~/.acme.sh retained"
else
    bad "acme_cron_cleanup removed the wrong crontab lines or deleted ~/.acme.sh"
fi
HOME=${saved_home}

# ssl_update.sh resets PATH to /bin:/sbin:...:~/bin, so its stubs must live in
# $HOME/bin and HOME itself is pointed at a throwaway directory.
setup_ssl_env() {
    local d=$1
    rm -rf "${d}"
    mkdir -p "${d}/idleleo/conf" "${d}/cert" "${d}/acme" "${d}/subhome/bin"
    printf '%s\n' '{"host":"example.com"}' >"${d}/idleleo/conf/install_config.json"
    : >"${d}/cert/xray.crt"
    : >"${d}/cert/xray.key"
    # A present nginx unit makes an accidental stop_nginx_for_renewal() call
    # observable in the systemctl stub log.
    : >"${d}/nginx.service"
    cp "${STUB_BIN}/idleleo" "${d}/subhome/bin/idleleo"
    cp "${STUB_BIN}/systemctl" "${d}/subhome/bin/systemctl"
    printf '#!/usr/bin/env bash\nexit 0\n' >"${d}/subhome/bin/getent"
    chmod +x "${d}/subhome/bin/"*
}

run_ssl_update() {
    local d=$1
    shift
    env -u IDLELEO_ACME_LEGACY \
        HOME="${d}/subhome" \
        IDLELEO_DIR="${d}/idleleo" \
        IDLELEO_CERT_DIR="${d}/cert" \
        IDLELEO_ACME_HOME="${d}/acme" \
        IDLELEO_CERT_GROUP=root \
        IDLELEO_XRAY_UNIT="${d}/xray.service.missing" \
        IDLELEO_NGINX_UNIT="${d}/nginx.service" \
        XRAY_UPDATE_LOCK_FILE="${d}/update.lock" \
        IDLELEO_CALL_LOG="${IDLELEO_CALL_LOG}" \
        SYSTEMCTL_CALL_LOG="${SYSTEMCTL_CALL_LOG}" \
        "$@" \
        bash "${REPO_DIR}/scripts/ssl_update.sh"
}

SSL_ENV="${TMP_ROOT}/ssl-native"
setup_ssl_env "${SSL_ENV}"

printf '%s\n' '--- ssl_update.sh renews natively without stopping nginx ---'
reset_logs
run_ssl_update "${SSL_ENV}" >/dev/null 2>"${TMP_ROOT}/ssl-native.err"
ssl_rc=$?
if [[ ${ssl_rc} -eq 0 ]] &&
    grep -q 'xray cert renew --domain example\.com' "${IDLELEO_CALL_LOG}" &&
    ! grep -q 'stop nginx' "${SYSTEMCTL_CALL_LOG}"; then
    ok "native renewal calls 'xray cert renew --domain example.com' and never stops nginx"
else
    bad "native renewal failed (rc=${ssl_rc}) or stopped nginx: $(cat "${TMP_ROOT}/ssl-native.err")"
fi

printf '%s\n' '--- ssl_update.sh is really red when idleleo fails ---'
reset_logs
run_ssl_update "${SSL_ENV}" FAKE_IDLELEO_RC=1 >/dev/null 2>"${TMP_ROOT}/ssl-fail.err"
ssl_rc=$?
if [[ ${ssl_rc} -ne 0 ]]; then
    ok "idleleo renew failure makes ssl_update.sh fail"
else
    bad "ssl_update.sh reported success although idleleo renew failed"
fi

printf '%s\n' '--- legacy renewal still requires acme.sh ---'
reset_logs
run_ssl_update "${SSL_ENV}" IDLELEO_ACME_LEGACY=1 >/dev/null 2>"${TMP_ROOT}/ssl-legacy.err"
ssl_rc=$?
if [[ ${ssl_rc} -ne 0 ]]; then
    ok "legacy renewal fails when IDLELEO_ACME_HOME has no acme.sh"
else
    bad "legacy renewal succeeded without an installed acme.sh"
fi

printf '%s\n' '--- source assertions ---'
if [[ $(grep -c 'get\.acme\.sh' "${REPO_DIR}/install.sh") -eq 1 ]]; then
    ok "get.acme.sh is referenced only by the legacy fallback branch"
else
    bad "get.acme.sh reference count changed: $(grep -n 'get\.acme\.sh' "${REPO_DIR}/install.sh")"
fi
if grep -q 'rm -rf "\$HOME/\.acme\.sh"' "${REPO_DIR}/install.sh"; then
    bad "install.sh still deletes ~/.acme.sh during cleanup"
else
    ok "install.sh never removes ~/.acme.sh"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
