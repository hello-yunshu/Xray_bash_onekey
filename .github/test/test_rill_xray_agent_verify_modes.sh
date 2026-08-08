#!/usr/bin/env bash
# P1-1 / P0-4-live: mode-aware live verification contract tests.
#
# The shared rxa_verify_live_contract used by the manager menu (Verify), the
# CLI (--rill-agent-verify), rill_xray_agent_verify.sh and CI must:
#   - require Runtime WAL mode == committed host config mode,
#   - require the Runtime to answer routeAssistEnabled=false and
#     boundedAutoAllowed=false in EVERY mode (including normal), fail-closed
#     when the Runtime answers with unsafe values, omits them, or is dead,
#   - pass for observe-only / normal / safe-disabled target states.
#
# Socket rules (runtime.sock always required; agent.sock required only with an
# active Agent and non-connectable in safe-disabled) run on the real sockets in
# the Docker PID1/systemd qualification; unit enablement/activity per mode is
# covered by test_mode_transaction.py (manager transaction). This file covers
# the Runtime-origin checks in an isolated sandbox.
#
# Run: bash .github/test/test_rill_xray_agent_verify_modes.sh (no root needed)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MANAGER="${REPO_ROOT}/scripts/rill_xray_agent_manager.sh"
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

HOME_DIR="${TMP_ROOT}/home"
CONFIG="${HOME_DIR}/config.json"
STATUS="${TMP_ROOT}/status.json"
MODE_FILE="${TMP_ROOT}/runtime-mode"
CLI="${TMP_ROOT}/cli"
mkdir -p "${HOME_DIR}"

cat > "${CLI}" <<'CLIEOF'
#!/usr/bin/env bash
case "${2:-}" in
    mode)
        printf '%s' "${3:-}" > "${RXA_CLI_MODE_FILE}"
        printf '{"ok":true,"result":{"mode":"%s"}}\n' "${3:-}"
        ;;
    config)
        mode=$(cat "${RXA_CLI_MODE_FILE}" 2>/dev/null || printf 'observe-only')
        printf '{"ok":true,"result":{"mode":"%s","routeAssistEnabled":%s,"boundedAutoAllowed":%s}}\n' \
            "$mode" "${RXA_CLI_ROUTE_ASSIST:-false}" "${RXA_CLI_BOUNDED_AUTO:-false}"
        ;;
    *) exit 66 ;;
esac
CLIEOF
chmod +x "${CLI}"

export RILL_XRAY_AGENT_HOME="${HOME_DIR}"
export RILL_XRAY_AGENT_CONFIG="${CONFIG}"
export RILL_XRAY_AGENT_CLI="${CLI}"
export RILL_XRAY_AGENT_STATUS="${STATUS}"
export RILL_XRAY_AGENT_NO_SYSTEMD=1
export RXA_CLI_MODE_FILE="${MODE_FILE}"
export RXA_CLI_ROUTE_ASSIST=false
export RXA_CLI_BOUNDED_AUTO=false

# The active-mode apply transaction refreshes the observation via the observer
# script; provide a sandbox observer that emits a valid fresh observation.
mkdir -p "${HOME_DIR}/scripts"
cat > "${HOME_DIR}/scripts/rill_xray_agent_observe.py" <<'OBS'
#!/usr/bin/env python3
import json, os, sys, time
out = os.environ.get("RILL_XRAY_AGENT_STATUS", "")
if not out:
    sys.exit(1)
payload = {"schemaVersion": 1, "capturedAtEpochSeconds": int(time.time()),
           "xrayConfig": {"present": False}, "services": {"xray": {"ok": False}}}
with open(out, "w") as stream:
    json.dump(payload, stream, sort_keys=True)
OBS
chmod +x "${HOME_DIR}/scripts/rill_xray_agent_observe.py"

fresh() {
    rm -f "${CONFIG}" "${STATUS}" "${MODE_FILE}"
    printf 'observe-only' > "${MODE_FILE}"
    : > "${STATUS}"
}

source "${MANAGER}"

# 0. Fresh install defaults to observe-only; apply + verify converge.
fresh
if rxa_apply_mode observe-only; then
    ok "apply observe-only on fresh state"
else
    bad "apply observe-only on fresh state"
fi
if rxa_verify_live_contract; then
    ok "verify passes in observe-only"
else
    bad "verify fails in observe-only"
fi

# 1. safe-disabled converges and verifies.
if rxa_apply_mode safe-disabled; then
    ok "apply safe-disabled"
else
    bad "apply safe-disabled"
fi
if rxa_verify_live_contract; then
    ok "verify passes in safe-disabled"
else
    bad "verify fails in safe-disabled"
fi

# 2. normal mode verifies (Route Assist must stay OFF there too).
if rxa_apply_mode normal; then
    ok "apply normal"
else
    bad "apply normal"
fi
if rxa_verify_live_contract; then
    ok "verify passes in normal"
else
    bad "verify fails in normal"
fi

# 3. Runtime routeAssist=true must fail the contract in every mode.
export RXA_CLI_ROUTE_ASSIST=true
if rxa_verify_live_contract; then
    bad "verify must fail when Runtime reports routeAssistEnabled=true"
else
    ok "verify fails when Runtime routeAssistEnabled=true"
fi
export RXA_CLI_ROUTE_ASSIST=false

# 4. Runtime boundedAlloWed=true must fail the contract.
export RXA_CLI_BOUNDED_AUTO=true
if rxa_verify_live_contract; then
    bad "verify must fail when Runtime reports boundedAutoAllowed=true"
else
    ok "verify fails when Runtime boundedAutoAllowed=true"
fi
export RXA_CLI_BOUNDED_AUTO=false

# 5. Runtime mode drifts from the committed config -> verify fails and the
#    same-mode repair reconciles the Runtime back to the committed mode.
if rxa_apply_mode observe-only; then
    ok "apply observe-only"
else
    bad "apply observe-only"
fi
printf 'normal' > "${MODE_FILE}"
if rxa_verify_live_contract; then
    bad "verify must fail when Runtime mode != committed config mode"
else
    ok "verify fails when Runtime mode != committed config mode"
fi
if rxa_apply_mode observe-only; then
    ok "same-mode repair reconciles Runtime drift"
else
    bad "same-mode repair failed to reconcile"
fi

# 6. Runtime CLI unresponsive -> verification fails closed.
CLI_SAVED="${RILL_XRAY_AGENT_CLI}"
cat > "${TMP_ROOT}/dead-cli" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "${TMP_ROOT}/dead-cli"
export RILL_XRAY_AGENT_CLI="${TMP_ROOT}/dead-cli"
if rxa_verify_live_contract; then
    bad "verify must fail when the Runtime CLI is unresponsive"
else
    ok "verify fails when Runtime CLI is unresponsive"
fi
export RILL_XRAY_AGENT_CLI="${CLI_SAVED}"

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" == 0 ]]