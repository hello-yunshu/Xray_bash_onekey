#!/usr/bin/env bash
# Staged regression for the Xray-triggered Rill upgrade contract.
# It proves that --upgrade is accepted only for an installed payload, removes
# stale canonical code, preserves user state and preserves safe-disabled mode.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BOOTSTRAP="${REPO_DIR}/scripts/rill_xray_agent_bootstrap.sh"
ASSET="${REPO_DIR}/assets/rill-xray-agent-xray-bundle.tar.gz"
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

sha=$(sha256sum "${ASSET}" | awk '{print $1}')
stage="${TMP_ROOT}/stage"
if ! RILL_XRAY_AGENT_BUNDLE_FILE="${ASSET}" \
    RILL_XRAY_AGENT_BUNDLE_SHA256="${sha}" DESTDIR="${stage}" \
    bash "${BOOTSTRAP}" >/dev/null; then
    echo "FAIL: initial staged install"
    exit 1
fi

config="${stage}/etc/rill-xray-agent/config.json"
jq '.mode = "safe-disabled"' "${config}" > "${config}.tmp" && mv "${config}.tmp" "${config}"
printf 'user state\n' > "${stage}/var/lib/rill-xray-agent-runtime/user-state.txt"
printf 'legacy code\n' > "${stage}/opt/rill-xray-agent/bin/old-stale"
printf 'user-owned payload\n' > "${stage}/opt/rill-xray-agent/user-owned.txt"
mkdir -p "${stage}/var/lib/rill-xray-agent-rillml/current"
printf 'native\n' > "${stage}/var/lib/rill-xray-agent-rillml/current/rill-runtime"

if ! RILL_XRAY_AGENT_HOME="${stage}/etc/rill-xray-agent" \
    RILL_XRAY_AGENT_CONFIG="${config}" \
    RILL_XRAY_AGENT_BUNDLE_FILE="${ASSET}" \
    RILL_XRAY_AGENT_BUNDLE_SHA256="${sha}" DESTDIR="${stage}" \
    bash "${BOOTSTRAP}" --upgrade >/dev/null; then
    echo "FAIL: staged --upgrade"
    exit 1
fi

[[ ! -e "${stage}/opt/rill-xray-agent/bin/old-stale" ]] || { echo "FAIL: stale canonical code survived"; exit 1; }
[[ -f "${stage}/var/lib/rill-xray-agent-runtime/user-state.txt" ]] || { echo "FAIL: runtime state lost"; exit 1; }
[[ -f "${stage}/opt/rill-xray-agent/user-owned.txt" ]] || { echo "FAIL: user-owned payload lost"; exit 1; }
[[ -f "${stage}/var/lib/rill-xray-agent-rillml/current/rill-runtime" ]] || { echo "FAIL: RillML tree changed"; exit 1; }
[[ "$(jq -r '.mode' "${config}")" == safe-disabled ]] || { echo "FAIL: safe-disabled mode not preserved"; exit 1; }
echo "PASS: staged Rill upgrade cleans canonical code and preserves state/mode/RillML"
