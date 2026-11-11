#!/usr/bin/env bash
# S6-1 regression tests: the TCP entry must use the project-owned idleleo tcp
# path and must never reach the network on its default branch.
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

NETWORK_MARKER="${TMP_ROOT}/network-used"
curl() {
    : >"${NETWORK_MARKER}"
    return 22
}

# The fake idleleo records every invocation and can be told to fail 'status'
# so the plan fallback is exercised.
cat >"${STUB_BIN}/idleleo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${IDLELEO_CALL_LOG}"
if [[ "${FAKE_IDLELEO_STATUS_FAIL:-0}" == "1" && "$1 $2" == "tcp status" ]]; then
    exit 3
fi
exit 0
EOF
chmod +x "${STUB_BIN}/idleleo"
export IDLELEO_CALL_LOG="${TMP_ROOT}/idleleo.calls"
: >"${IDLELEO_CALL_LOG}"

base_path=${PATH}

printf '%s\n' '--- default branch uses idleleo tcp and stays offline ---'
PATH="${STUB_BIN}:${base_path}"
rm -f "${NETWORK_MARKER}"
: >"${IDLELEO_CALL_LOG}"
if bbr_boost_sh </dev/null >/dev/null 2>&1 &&
    grep -q '^tcp status$' "${IDLELEO_CALL_LOG}" &&
    [[ ! -e "${NETWORK_MARKER}" ]]; then
    ok "default branch calls 'tcp status' with no network access"
else
    bad "default branch did not use idleleo tcp (or touched the network): $(cat "${IDLELEO_CALL_LOG}")"
fi

printf '%s\n' '--- status failure falls back to plan ---'
rm -f "${NETWORK_MARKER}"
: >"${IDLELEO_CALL_LOG}"
FAKE_IDLELEO_STATUS_FAIL=1 bbr_boost_sh </dev/null >/dev/null 2>&1
if grep -q '^tcp plan$' "${IDLELEO_CALL_LOG}" && [[ ! -e "${NETWORK_MARKER}" ]]; then
    ok "read-only fallback is 'tcp plan'"
else
    bad "status failure did not fall back to plan: $(cat "${IDLELEO_CALL_LOG}")"
fi

printf '%s\n' '--- apply branch passes the profile and confirmation ---'
rm -f "${NETWORK_MARKER}"
: >"${IDLELEO_CALL_LOG}"
if bbr_boost_sh "--apply" </dev/null >/dev/null 2>&1 &&
    grep -q '^tcp apply --profile bbr-fq --confirm$' "${IDLELEO_CALL_LOG}" &&
    [[ ! -e "${NETWORK_MARKER}" ]]; then
    ok "apply branch calls 'tcp apply --profile bbr-fq --confirm'"
else
    bad "apply branch did not invoke the managed profile: $(cat "${IDLELEO_CALL_LOG}")"
fi

printf '%s\n' '--- missing idleleo refuses instead of downloading ---'
rm -f "${NETWORK_MARKER}"
: >"${IDLELEO_CALL_LOG}"
if PATH="${base_path}" bbr_boost_sh </dev/null >/dev/null 2>&1; then
    bad "missing idleleo still returned success"
elif [[ -e "${NETWORK_MARKER}" ]]; then
    bad "missing idleleo fell back to downloading a script"
else
    ok "missing idleleo fails closed without network access"
fi

printf '%s\n' '--- legacy needs the typed confirmation ---'
rm -f "${NETWORK_MARKER}"
: >"${IDLELEO_CALL_LOG}"
PATH="${STUB_BIN}:${base_path}"
if printf 'no\n' | bbr_boost_sh "--legacy" >/dev/null 2>&1; then
    bad "legacy accepted a non-'legacy' answer"
elif [[ -e "${NETWORK_MARKER}" ]]; then
    bad "legacy downloaded the script before confirmation"
else
    ok "legacy without the typed confirmation is refused offline"
fi

printf '%s\n' '--- legacy no longer downloads tcp.sh ---'
rm -f "${NETWORK_MARKER}"
: >"${IDLELEO_CALL_LOG}"
PATH="${STUB_BIN}:${base_path}"
scripts_dir="${TMP_ROOT}/no-such-scripts"
if printf 'legacy\n' | bbr_boost_sh "--legacy" >/dev/null 2>&1; then
    bad "legacy succeeded without a local tcp.sh"
elif [[ -e "${NETWORK_MARKER}" ]]; then
    bad "legacy downloaded tcp.sh again"
else
    ok "legacy without a local tcp.sh fails closed and offline"
fi
if grep -q 'Linux-NetSpeed/master/tcp.sh' "${REPO_DIR}/install.sh"; then
    bad "install.sh still references the remote tcp.sh"
else
    ok "install.sh no longer carries a tcp.sh download URL"
fi

printf '%s\n' '--- menu 33 uses idleleo speedtest ---'
rm -f "${NETWORK_MARKER}"
: >"${IDLELEO_CALL_LOG}"
PATH="${STUB_BIN}:${base_path}" menu_action 33 </dev/null >/dev/null 2>&1 || true
if grep -q '^speedtest' "${IDLELEO_CALL_LOG}" && [[ ! -e "${NETWORK_MARKER}" ]]; then
    ok "menu 33 calls 'idleleo speedtest' without downloading anything"
else
    bad "menu 33 did not use idleleo speedtest: $(cat "${IDLELEO_CALL_LOG}")"
fi
if grep -q 'hello-yunshu/superspeed' "${REPO_DIR}/install.sh"; then
    bad "install.sh still references the superspeed download"
else
    ok "install.sh no longer carries a superspeed URL"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
