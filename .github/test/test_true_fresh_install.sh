#!/usr/bin/env bash
# True Fresh Install E2E for Issue #102.
# Starts from the user's top-level command on a zero-state host. It does not
# source install.sh, pre-create /etc/idleleo, or mock the candidate path.

set -uo pipefail
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
API_REPO_DIR="${API_REPO_DIR:-${REPO_DIR}/../Xray_bash_onekey_api}"
ARTIFACT_DIR="${E2E_ARTIFACT_DIR:-${RUNNER_TEMP:-/tmp}/xray-true-fresh-artifacts}"
FIXTURE_ROOT="$(mktemp -d)"
mkdir -p "${ARTIFACT_DIR}"
SERVER_LOG="${ARTIFACT_DIR}/release-server.log"
INSTALL_LOG="${ARTIFACT_DIR}/true-fresh-install.log"
RAW_SERVER_LOG="$(mktemp)"
RAW_INSTALL_LOG="$(mktemp)"
server_pid=""
cleanup() {
    [[ -n "${server_pid}" ]] && kill "${server_pid}" 2>/dev/null || true
    [[ -n "${server_pid}" ]] && wait "${server_pid}" 2>/dev/null || true
    rm -f "${RAW_SERVER_LOG}" "${RAW_INSTALL_LOG}"
    rm -rf "${FIXTURE_ROOT}"
}
trap cleanup EXIT

source "${REPO_DIR}/.github/test/redact.sh"
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
absent() {
    if [[ ! -e "$1" && ! -L "$1" ]]; then ok "$2 absent at start"; else bad "$2 already exists: $1"; fi
}

echo "=== True Fresh Install E2E (Issue #102) ==="
absent /etc/idleleo "/etc/idleleo"
absent /usr/bin/idleleo "/usr/bin/idleleo"
absent /usr/local/bin/xray "Xray binary"
absent /etc/systemd/system/xray.service "Xray systemd unit"
[[ ${FAIL} -eq 0 ]] || exit 1

VERSION=$(sed -n 's/^shell_version="\([0-9][0-9.]*\)"$/\1/p' "${REPO_DIR}/install.sh" | head -n1)
API_SOURCE="${API_REPO_DIR}/xray_shell_versions.json"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { bad "invalid Shell version"; exit 1; }
[[ -f "${API_SOURCE}" ]] || { bad "missing API metadata: ${API_SOURCE}"; exit 1; }

# Qualification uses a Release-shaped local fixture only because the candidate
# Release does not exist until after this required gate passes.
mkdir -p "${FIXTURE_ROOT}/releases/download/v${VERSION}" "${FIXTURE_ROOT}/raw/v${VERSION}"
cp "${REPO_DIR}/install.sh" "${FIXTURE_ROOT}/releases/download/v${VERSION}/install.sh"
[[ -d "${REPO_DIR}/config" ]] && cp -R "${REPO_DIR}/config" "${FIXTURE_ROOT}/raw/v${VERSION}/"
EXPECTED_SHA=$(sha256sum "${FIXTURE_ROOT}/releases/download/v${VERSION}/install.sh" | awk '{print $1}')
QUAL_API="${ARTIFACT_DIR}/xray_shell_versions.json"
jq --arg version "${VERSION}" --arg sha "${EXPECTED_SHA}" \
    '.shell_online_version=$version | .shell_release_sha256=$sha' \
    "${API_SOURCE}" >"${QUAL_API}" || { bad "could not create qualification metadata"; exit 1; }

SERVER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
python3 -m http.server "${SERVER_PORT}" --bind 127.0.0.1 --directory "${FIXTURE_ROOT}" \
    >"${RAW_SERVER_LOG}" 2>&1 &
server_pid=$!
for _ in $(seq 1 30); do
    curl -fsS "http://127.0.0.1:${SERVER_PORT}/releases/download/v${VERSION}/install.sh" -o /dev/null && break
    sleep 1
done
curl -fsS "http://127.0.0.1:${SERVER_PORT}/releases/download/v${VERSION}/install.sh" -o /dev/null || {
    bad "Release fixture did not start"; exit 1
}
ok "exact-version Release fixture is reachable"

ENTRY="${ARTIFACT_DIR}/entry-install.sh"
cp "${REPO_DIR}/install.sh" "${ENTRY}"
chmod 755 "${ENTRY}"
echo "--- execute the production top-level entry ---"
set +e
printf '%s\n' 2 14431 n n www.microsoft.com n n n n n n n n n | \
    sudo -E env XRAY_QUALIFICATION_MODE=1 \
        SHELL_RELEASE_BASE_OVERRIDE="http://127.0.0.1:${SERVER_PORT}" \
        XRAY_VERSIONS_FILE="${QUAL_API}" \
        bash "${ENTRY}" --install-reality >"${RAW_INSTALL_LOG}" 2>&1
install_rc=$?
set -e
if redact_text_for_diagnostics <"${RAW_INSTALL_LOG}" >"${INSTALL_LOG}" 2>/dev/null; then
    :
else
    bad "true-fresh install log redaction failed"
    : >"${INSTALL_LOG}"
fi
rm -f "${RAW_INSTALL_LOG}"
[[ ${install_rc} -eq 0 ]] && ok "top-level fresh install completed" || bad "top-level fresh install failed (rc=${install_rc})"

[[ -f /etc/idleleo/install.sh ]] && ok "managed Shell was created" || bad "managed Shell missing"
if [[ -L /usr/bin/idleleo && "$(readlink /usr/bin/idleleo)" == /etc/idleleo/install.sh ]]; then
    ok "idleleo command points to managed Shell"
else
    bad "idleleo command does not point to managed Shell"
fi
[[ -f /etc/idleleo/conf/install_config.json ]] && ok "install config was created" || bad "install config missing"
[[ -f /etc/idleleo/conf/xray/config.json ]] && ok "Xray config was created" || bad "Xray config missing"
[[ -x /usr/local/bin/xray ]] && ok "Xray binary was installed" || bad "Xray binary missing"

if [[ -f /etc/idleleo/install.sh ]]; then
    ACTUAL_SHA=$(sha256sum /etc/idleleo/install.sh | awk '{print $1}')
    [[ "${ACTUAL_SHA}" == "${EXPECTED_SHA}" ]] && ok "managed Shell SHA matches Release metadata" ||
        bad "managed Shell SHA mismatch"
fi
if grep -q "/releases/download/v${VERSION}/install.sh" "${RAW_SERVER_LOG}" &&
   ! grep -qE '/releases/download/v(/|//)install\.sh' "${RAW_SERVER_LOG}"; then
    ok "candidate request used an exact Release URL"
else
    bad "candidate request was not an exact Release URL"
fi

if [[ -x /usr/local/bin/xray && -f /etc/idleleo/conf/xray/config.json ]]; then
    if sudo /usr/local/bin/xray run -test -config /etc/idleleo/conf/xray/config.json \
        >"${ARTIFACT_DIR}/xray-config-test.txt" 2>&1; then
        ok "Xray config test passed"
    else
        bad "Xray config test failed"
    fi
fi
sudo systemctl is-active --quiet xray && ok "Xray service is active" || bad "Xray service is not active"
if [[ -f /etc/idleleo/conf/xray/config.json ]]; then
    PORT=$(jq -r '[.inbounds[]?.port] | map(select(type == "number")) | .[0] // empty' /etc/idleleo/conf/xray/config.json 2>/dev/null)
    if [[ -n "${PORT}" ]] && sudo ss -ltnH | awk -v p=":${PORT}" '$4 ~ p "$" { found=1 } END { exit !found }'; then
        ok "representative Xray port is listening"
    else
        bad "representative Xray port is not listening"
    fi
fi

if redact_text_for_diagnostics <"${RAW_SERVER_LOG}" >"${SERVER_LOG}" 2>/dev/null; then
    :
else
    bad "Release server log redaction failed"
    : >"${SERVER_LOG}"
fi
rm -f "${RAW_SERVER_LOG}"

if [[ ${FAIL} -ne 0 ]]; then
    sudo systemctl status xray --no-pager 2>&1 | redact_text_for_diagnostics >"${ARTIFACT_DIR}/systemctl-xray.txt" || true
    sudo journalctl -u xray --no-pager -n 80 2>&1 | redact_text_for_diagnostics >"${ARTIFACT_DIR}/journal-xray.txt" || true
    sudo tail -120 /etc/idleleo/logs/install.log 2>/dev/null | redact_text_for_diagnostics >"${ARTIFACT_DIR}/install-log.txt" || true
    sudo find /etc/idleleo -maxdepth 3 -type f -print 2>/dev/null | sort >"${ARTIFACT_DIR}/idleleo-tree.txt" || true
fi

echo "True Fresh Install E2E result: ${PASS} passed, ${FAIL} failed"
[[ ${FAIL} -eq 0 ]]
