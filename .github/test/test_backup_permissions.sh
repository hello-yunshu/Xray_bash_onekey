#!/usr/bin/env bash
# 3.3.1 H3+L8: backup archives must be 0600, and a tar failure must remove the
# partial archive and return non-zero instead of "备份成功".
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
log_dir="${TMP_ROOT}/logs"
LOG_FILE="${log_dir}/install.log"
mkdir -p "${idleleo_dir}/conf" "${log_dir}"
printf '{"id":"test-uuid","privateKey":"secret"}' >"${idleleo_dir}/conf/install_config.json"
printf 'old log\n' >"${LOG_FILE}"
chmod 644 "${LOG_FILE}" 2>/dev/null || true
log_echo() { printf '%s\n' "$*" >>"${TMP_ROOT}/log_echo.txt"; }
gettext() { printf '%s' "$1"; }
read_optimize() { backup_name="case"; }

# Existing archive migration: chmod 600 happens in enable_file_logging.
printf 'x' >"${idleleo_dir}/xray_bash_old_1.tar.gz"
chmod 644 "${idleleo_dir}/xray_bash_old_1.tar.gz"
enable_file_logging
mode=$(stat -c '%a' "${idleleo_dir}/xray_bash_old_1.tar.gz" 2>/dev/null || echo missing)
[[ "${mode}" == "600" ]] && ok "existing backup migrated to 0600" || bad "existing backup mode=${mode}"
mode=$(stat -c '%a' "${LOG_FILE}" 2>/dev/null || echo missing)
[[ "${mode}" == "600" ]] && ok "existing install.log migrated to 0600" || bad "existing log mode=${mode}"

# Successful backup with a permissive caller umask.
old_umask=$(umask)
umask 022
backup_directories
rc=$?
umask "${old_umask}"
[[ ${rc} -eq 0 ]] && ok "backup succeeds" || bad "backup failed rc=${rc}"
archive=$(ls -1 "${idleleo_dir}"/xray_bash_case_*.tar.gz 2>/dev/null | tail -1)
[[ -n "${archive}" ]] && ok "backup archive created" || bad "backup archive missing"
mode=$(stat -c '%a' "${archive}" 2>/dev/null || echo missing)
[[ "${mode}" == "600" ]] && ok "backup archive mode 0600" || bad "backup archive mode=${mode}"
tar -tzf "${archive}" >/dev/null 2>&1 && ok "backup archive readable" || bad "backup archive corrupt"
# The archive also carries /root/.acme.sh style account state; the operator must
# be told it contains an account private key, not just the Xray key pair.
if grep -q 'ACME 账户私钥' "${TMP_ROOT}/log_echo.txt" 2>/dev/null; then
    ok "backup warns that the archive contains the ACME account private key"
else
    bad "backup does not warn about the ACME account private key"
fi

# 0600 must actually deny another unprivileged account, not only look correct
# in stat output. Probe in a traversable directory so only the file mode is
# under test; a 0644 control proves the probe can read when allowed.
lowpriv_mode="none"
if [[ "$(id -u)" -eq 0 ]] && command -v runuser >/dev/null 2>&1 &&
    runuser -u nobody -- true >/dev/null 2>&1; then
    lowpriv_mode="runuser"
elif command -v sudo >/dev/null 2>&1 && sudo -n -u nobody true >/dev/null 2>&1; then
    lowpriv_mode="sudo"
fi
lowpriv_can_read() {
    case "${lowpriv_mode}" in
        runuser) runuser -u nobody -- test -r "$1" >/dev/null 2>&1 ;;
        sudo) sudo -n -u nobody test -r "$1" >/dev/null 2>&1 ;;
        *) return 2 ;;
    esac
}
if [[ "${lowpriv_mode}" != "none" ]]; then
    READ_PROBE="${TMP_ROOT}/read-probe"
    chmod 755 "${TMP_ROOT}"
    cp -p "${archive}" "${READ_PROBE}"
    chmod 644 "${READ_PROBE}"
    if lowpriv_can_read "${READ_PROBE}"; then
        ok "low-privilege read probe works with 0644"
    else
        bad "low-privilege read probe cannot read a 0644 file (probe invalid)"
    fi
    chmod 600 "${READ_PROBE}"
    if lowpriv_can_read "${READ_PROBE}"; then
        bad "a low-privilege account can read the 0600 backup probe"
    else
        ok "a low-privilege account cannot read the 0600 backup probe"
    fi
    rm -f "${READ_PROBE}"
else
    bad "low-privilege read not verified (no runuser/sudo path to nobody)"
fi

# Tar failure: inject a failing tar that first writes to the -czf target, so
# the test proves the half-written temp file is removed (an immediately failing
# tar never creates the partial file at all).
STUB="${TMP_ROOT}/bin"
mkdir -p "${STUB}"
cat >"${STUB}/tar" <<'EOF'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-czf" ]]; then
        out="$2"
        break
    fi
    shift
done
[[ -n "${out}" ]] && printf 'partial archive bytes' >"${out}"
exit 1
EOF
chmod +x "${STUB}/tar"
PATH="${STUB}:${PATH}"
export PATH
TMPDIR="${TMP_ROOT}/tmpdir"
export TMPDIR
mkdir -p "${TMPDIR}"
rm -f "${idleleo_dir}"/xray_bash_case_*.tar.gz
backup_directories
rc=$?
[[ ${rc} -ne 0 ]] && ok "tar failure returns non-zero" || bad "tar failure returned 0"
if compgen -G "${idleleo_dir}/xray_bash_case_*.tar.gz" >/dev/null; then
    bad "a final backup archive was left behind"
else
    ok "no final backup archive was left behind"
fi
if compgen -G "${TMPDIR}/xray-backup.*" >/dev/null; then
    bad "a half-written backup temp file was left behind"
else
    ok "the half-written backup temp file was removed"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
