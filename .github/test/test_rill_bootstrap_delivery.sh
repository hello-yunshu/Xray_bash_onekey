#!/usr/bin/env bash
# Current Xray bootstrap -> current Xray bundled asset delivery regression
# (R6 targeted smoke, CI-safe equivalent of the Docker qualification).
#
# Proves the REAL delivery pair consumable by a host:
#   scripts/rill_xray_agent_bootstrap.sh
#     + assets/rill-xray-agent-xray-bundle.tar.gz
# bootstrap performs SHA-256 verification, tar extraction, root-member
# validation, then invokes the REAL installer (staged via DESTDIR, so no
# systemd PID1 lifecycle is required here -- that was covered by R5).
#
# Run: bash .github/test/test_rill_bootstrap_delivery.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BOOTSTRAP="${REPO_DIR}/scripts/rill_xray_agent_bootstrap.sh"
ASSET="${REPO_DIR}/assets/rill-xray-agent-xray-bundle.tar.gz"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

[[ -f "${BOOTSTRAP}" ]]  || { echo "missing ${BOOTSTRAP}"; exit 99; }
[[ -f "${ASSET}" ]]      || { echo "missing ${ASSET}";   exit 99; }

EXPECTED=$(grep -o '^EXPECTED_SHA256=[0-9a-f]\{64\}' "${BOOTSTRAP}" | cut -d= -f2)
ACTUAL=$(sha256sum "${ASSET}" | awk '{print $1}')

if [[ -n "${EXPECTED}" && "${EXPECTED}" == "${ACTUAL}" ]]; then
    ok "bootstrap EXPECTED_SHA256 == asset sha256 (${ACTUAL})"
elif [[ -z "${EXPECTED}" ]]; then
    bad "bootstrap EXPECTED_SHA256 anchor missing"
else
    bad "bootstrap EXPECTED_SHA256 (${EXPECTED}) != asset (${ACTUAL})"
fi

export RILL_XRAY_AGENT_BUNDLE_FILE="${ASSET}"
export DESTDIR="${TMP_ROOT}/stage"

run_bootstrap_root() {
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        env RILL_XRAY_AGENT_BUNDLE_FILE="${ASSET}" DESTDIR="${TMP_ROOT}/stage" bash "${BOOTSTRAP}"
    else
        sudo -n env RILL_XRAY_AGENT_BUNDLE_FILE="${ASSET}" DESTDIR="${TMP_ROOT}/stage" bash "${BOOTSTRAP}"
    fi
}

if ! OUT=$(run_bootstrap_root 2>&1); then
    bad "bootstrap execution failed"
    echo "${OUT}"
else
    ok "bootstrap execution exit 0"
fi
echo "${OUT}" | grep -q "Rill Xray AI 运维助手已暂存安装到" \
    && ok "installer staged install completed" \
    || bad "installer staged install marker missing"
unset RILL_XRAY_AGENT_BUNDLE_FILE DESTDIR
if [[ -f "${TMP_ROOT}/stage/etc/rill-xray-agent/config.json" ]]; then
    chmod -R a+rX "${TMP_ROOT}/stage" 2>/dev/null || true
fi

STAGE="${TMP_ROOT}/stage"
for p in \
    "${STAGE}/etc/rill-xray-agent/config.json" \
    "${STAGE}/opt/rill-xray-agent/bin/rill-xray-agent" \
    "${STAGE}/opt/rill-xray-agent/bin/rill-xray-agent-agent" \
    "${STAGE}/opt/rill-xray-agent/bin/rill-xray-agent-runtime" \
    "${STAGE}/etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh" \
    "${STAGE}/etc/systemd/system/rill-xray-agent-runtime.service" \
    "${STAGE}/etc/systemd/system/rill-xray-agent-agent.service" \
    ; do
    if [[ -f "${p}" ]]; then
        ok "artifact present: ${p#${STAGE}/}"
    else
        bad "artifact missing: ${p#${STAGE}/}"
    fi
done

if python3 - "${STAGE}/etc/rill-xray-agent/config.json" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
wants = {"mode": "observe-only", "routeAssistEnabled": False,
         "boundedAutoAllowed": False, "localOnly": True}
for k, v in wants.items():
    if cfg.get(k) != v:
        raise SystemExit(f"config {k}={cfg.get(k)} want {v}")
PY
then
    ok "default config invariants (mode/routeAssist/boundedAuto/localOnly)"
else
    bad "default config invariants"
fi

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" == 0 ]]
