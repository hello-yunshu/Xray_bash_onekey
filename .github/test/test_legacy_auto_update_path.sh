#!/usr/bin/env bash
# 3.3.1 M6: regression coverage for the legacy 3.2.11 auto_update path.
# The legacy helper must fail closed and must not proceed to an Xray update
# when the Shell cross-minor step is refused.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT
root="${TMP_ROOT}/root"
mkdir -p "${root}/conf/xray" "${root}/logs" "${root}/scripts" "${root}/bin"
git -C "${REPO_DIR}" show v3.2.11:scripts/auto_update.sh >"${root}/scripts/auto_update.sh"
# The released helper hard-codes /etc/idleleo and the CDN URL. Rewrite only
# those constants into the disposable sandbox; the retry/version logic is the
# original v3.2.11 code.
sed -i "s#/etc/idleleo#${root}#g" "${root}/scripts/auto_update.sh"
sed -i "s#https://cdn.jsdelivr.net/gh/hello-yunshu/Xray_bash_onekey_api@main/xray_shell_versions.json#file://${root}/versions.json#g" \
    "${root}/scripts/auto_update.sh"
printf '%s' '{"shell_online_version":"3.3.0","xray_online_version":"26.10.31","nginx_build_online_version":"2026.10.15.7679"}' >"${root}/versions.json"
printf '#!/usr/bin/env bash\nshell_version="3.2.11"\nprintf "%%s\\n" "$*" >>"${INSTALL_LOG}"\nif [[ "$*" == "-u auto_update" ]]; then\n    echo "脚本版本差别过大, 跳过更新!" >>"${IDLELEO_LOG_DIR}/auto_update.log"\n    exit 1\nfi\nexit 0\n' >"${root}/install.sh"
chmod +x "${root}/install.sh"
printf '{}' >"${root}/conf/xray/config.json"
printf '3.2.11' >"${root}/release-managed.version"
printf '{"shell_version":"3.2.11","xray_version":"26.3.27"}' >"${root}/conf/install_config.json"

STUB_BIN="${TMP_ROOT}/bin"
mkdir -p "${STUB_BIN}"
cat >"${STUB_BIN}/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s' "${CDN_JSON}"
EOF
chmod +x "${STUB_BIN}/curl"
export IDLELEO_TEST_MODE=1
export IDLELEO_TEST_PATH="${STUB_BIN}:${PATH}"
export IDLELEO_DIR="${root}"
export IDLELEO_LOG_DIR="${root}/logs"
export IDLELEO_XRAY_BIN="${root}/bin/xray"
export IDLELEO_NGINX_DIR="${root}/nginx"
export INSTALL_LOG="${root}/calls.log"
export CDN_JSON='{"shell_online_version":"3.3.0","xray_online_version":"26.10.31","nginx_build_online_version":"2026.10.15.7679"}'
: >"${INSTALL_LOG}"

bash "${root}/scripts/auto_update.sh" >/dev/null 2>&1
rc=$?
[[ ${rc} -ne 0 ]] && ok "legacy auto_update exits non-zero on refused Shell jump" || bad "legacy auto_update exited 0"
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}"; then
    bad "legacy path proceeded to an Xray update after Shell refusal"
else
    ok "legacy path did not proceed to an Xray update after Shell refusal"
fi
if grep -Fq "Script update failed" "${root}/logs/auto_update.log"; then
    ok "legacy failure is logged"
else
    bad "legacy failure is not logged"
fi
if grep -Fq "脚本版本差别过大" "${root}/logs/auto_update.log"; then
    ok "legacy cross-minor refusal is logged"
else
    bad "legacy cross-minor refusal is not logged"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
