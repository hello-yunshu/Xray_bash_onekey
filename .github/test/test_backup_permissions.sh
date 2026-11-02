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
log_echo() { :; }
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

# Tar failure: inject a failing tar and ensure no partial archive is left.
STUB="${TMP_ROOT}/bin"
mkdir -p "${STUB}"
cat >"${STUB}/tar" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "${STUB}/tar"
PATH="${STUB}:${PATH}"
export PATH
rm -f "${idleleo_dir}"/xray_bash_case_*.tar.gz
backup_directories
rc=$?
[[ ${rc} -ne 0 ]] && ok "tar failure returns non-zero" || bad "tar failure returned 0"
if compgen -G "${idleleo_dir}/xray_bash_case_*.tar.gz" >/dev/null; then
    bad "partial backup archive was left behind"
else
    ok "partial backup archive removed"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
