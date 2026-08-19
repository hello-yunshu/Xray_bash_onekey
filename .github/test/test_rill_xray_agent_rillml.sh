#!/usr/bin/env bash
# Batch D remote gate: RillML prebuilt runtime on the Xray host.
#
# Delivers the Rill payload through the canonical bootstrap (SHA-verified
# bundle -> real installer) and validates the best-effort RillML prebuilt
# runtime from the signed stable index (schema v3):
#   - the installer reports RillML handling (native enabled or clean fallback),
#   - the root-owned managed tree holds a verified native binary
#     (/var/lib/rill-xray-agent-rillml/current),
#   - the root CLI status is supported + available + version 1.2.x,
#   - the unprivileged read-only IPC surface reflects active + verified
#     (P0-16), and the binary is group-readable for the runtime user.
#
# Runs on a systemd host (the GitHub Actions five-mode runner) and requires
# root. Each Xray operational mode installs the same canonical payload, so the
# RillML native runtime must land and be reflected identically in every mode.
#
# Run: sudo bash .github/test/test_rill_xray_agent_rillml.sh
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BOOTSTRAP="${REPO_DIR}/scripts/rill_xray_agent_bootstrap.sh"
ASSET="${REPO_DIR}/assets/rill-xray-agent-xray-bundle.tar.gz"
MANAGER="/etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh"
RILLML_ROOT=/var/lib/rill-xray-agent-rillml

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

[[ -f "${BOOTSTRAP}" ]] || { echo "missing ${BOOTSTRAP}" >&2; exit 99; }
[[ -f "${ASSET}" ]]     || { echo "missing ${ASSET}"     >&2; exit 99; }

echo "=== RillML prebuilt runtime gate (Batch D) ==="

# --- canonical delivery identity ---
EXPECTED=$(grep -o '^EXPECTED_SHA256=[0-9a-f]\{64\}' "${BOOTSTRAP}" | cut -d= -f2)
ACTUAL=$(sha256sum "${ASSET}" | awk '{print $1}')
if [[ -n "${EXPECTED}" && "${EXPECTED}" == "${ACTUAL}" ]]; then
    ok "bootstrap EXPECTED_SHA256 == bundle sha256"
else
    bad "bootstrap EXPECTED_SHA256 (${EXPECTED:-missing}) != bundle (${ACTUAL})"
fi

# --- deliver the Rill payload + best-effort RillML (real install) ---
if ! OUT=$(env RILL_XRAY_AGENT_BUNDLE_FILE="${ASSET}" bash "${BOOTSTRAP}" 2>&1); then
    bad "rill payload bootstrap+install exit 0"
    printf '%s\n' "${OUT}" | tail -20
else
    ok "rill payload bootstrap+install exit 0"
fi
if grep -q 'RillML' <<<"${OUT}"; then
    ok "installer log mentions RillML handling"
else
    bad "installer log does not mention RillML"
fi

# shellcheck source=/dev/null
[[ -f "${MANAGER}" ]] && source "${MANAGER}"

# --- root-owned managed tree (root CLI is authoritative and offline) ---
if [[ -d "${RILLML_ROOT}/current" && -f "${RILLML_ROOT}/state.json" ]]; then
    ok "RillML managed tree: current/ + state.json"
else
    bad "RillML managed tree missing current/state.json"
fi
if [[ -x "${RILLML_ROOT}/current/rill-runtime" ]]; then
    ok "RillML native binary present + executable"
else
    bad "RillML native binary missing/not executable"
fi
if stat -c '%U:%G' "${RILLML_ROOT}/current/rill-runtime" 2>/dev/null | grep -q '^root:rill-xray-agent$'; then
    ok "RillML native binary owned root:rill-xray-agent"
else
    bad "RillML native binary not owned root:rill-xray-agent"
fi

# --- root CLI status (schema v3, 1.2.x) ---
# The CLI prints the bare `result` dict on success; accept the wrapped form too.
rillml_status_json() { rxa_rillml status 2>/dev/null; }
if rillml_status_json | python3 -c 'import json,sys
d=json.load(sys.stdin); r=d.get("result") or d
assert r.get("supported") and r.get("available"), r
assert r.get("current") and r.get("current",{}).get("version"), r' >/dev/null 2>&1; then
    ok "rillml status supported + available + current version"
else
    bad "rillml status not supported/available"
fi
if rillml_status_json | python3 -c 'import json,sys
d=json.load(sys.stdin); r=d.get("result") or d
assert r["current"]["version"].startswith("1.2"), r' >/dev/null 2>&1; then
    ok "rillml status version is 1.2.x"
else
    bad "rillml status version != 1.2.x"
fi

# --- read-only IPC surface (active + verified, P0-16) ---
# The runtime may need a moment to reflect the freshly activated runtime.
wait_rillml_ipc() {
    local i
    for ((i = 0; i < 20; i++)); do
        if rxa_runtime rillml-status 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin); d=d.get("result") or d
nr=d.get("nativeRuntime") or {}
assert nr.get("status") == "active" and nr.get("verified") is True, nr' >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}
if wait_rillml_ipc; then
    ok "rillml IPC surface active + verified (read-only)"
else
    bad "rillml IPC surface not active/verified"
fi

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" == 0 ]]
