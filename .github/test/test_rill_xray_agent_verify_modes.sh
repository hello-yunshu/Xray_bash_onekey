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

# P0-8: rxa_apply_mode drives the ROOT execution policy (single authority)
# first. Provide a fake root-policy helper in the sandbox that tracks mode and
# routeStage, and fails closed when RXA_ROOT_POLICY_FAIL=1 (missing / corrupt
# helper probe).
ROOT_POLICY="${TMP_ROOT}/rill-xray-agent-root-policy"
ROOT_POLICY_STATE="${TMP_ROOT}/root-policy.state"
ROOT_POLICY_STAGE_STATE="${TMP_ROOT}/root-policy-stage.state"
printf 'observe-only' > "${ROOT_POLICY_STATE}"
printf 'observe' > "${ROOT_POLICY_STAGE_STATE}"
cat > "${ROOT_POLICY}" <<'RPEOF'
#!/usr/bin/env bash
# mimic: rill-xray-agent-root-policy <command> ...
STATE="${RXA_ROOT_POLICY_STATE}"
STAGE="${RXA_ROOT_POLICY_STAGE_STATE}"
cmd="$1"; shift
case "$cmd" in
    status)
        mode=$(cat "${STATE}" 2>/dev/null || printf 'observe-only')
        stage=$(cat "${STAGE}" 2>/dev/null || printf 'observe')
        printf '{"schemaVersion":1,"ok":true,"command":"status","policy":{"mode":"%s","routeStage":"%s","autoConfirmed":false,"executionEpoch":0}}\n' "$mode" "$stage"
        ;;
    mode)
        [[ "${RXA_ROOT_POLICY_FAIL:-0}" == 1 ]] && exit 1
        printf '%s' "${1:-}" > "${STATE}"
        printf '{"schemaVersion":1,"ok":true,"command":"mode"}\n'
        ;;
    safe-disable)
        [[ "${RXA_ROOT_POLICY_FAIL:-0}" == 1 ]] && exit 1
        printf '%s' 'safe-disabled' > "${STATE}"
        printf '{"schemaVersion":1,"ok":true,"command":"safe-disable"}\n'
        ;;
    route-stage)
        [[ "${RXA_ROOT_POLICY_FAIL:-0}" == 1 ]] && exit 1
        printf '%s' "${1:-}" > "${STAGE}"
        printf '{"schemaVersion":1,"ok":true,"command":"route-stage"}\n'
        ;;
    confirm-auto|revoke-auto|acknowledge-fuse)
        [[ "${RXA_ROOT_POLICY_FAIL:-0}" == 1 ]] && exit 1
        printf '{"schemaVersion":1,"ok":true,"command":"%s"}\n' "$cmd"
        ;;
    *) exit 66 ;;
esac
RPEOF
chmod +x "${ROOT_POLICY}"

export RILL_XRAY_AGENT_ROOT_POLICY_HELPER="${ROOT_POLICY}"
export RXA_ROOT_POLICY_STATE="${ROOT_POLICY_STATE}"
export RXA_ROOT_POLICY_STAGE_STATE="${ROOT_POLICY_STAGE_STATE}"
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

# 7. Socket rules (sandbox socket dir; NO_SYSTEMD stays 1 so only the socket
#    layer of the contract is exercised against REAL Unix sockets):
#    - runtime.sock must exist and CONNECT in every mode,
#    - normal / observe-only require agent.sock to exist and CONNECT,
#    - safe-disabled: agent.sock must be absent or REFUSE connection; a stale
#      inode that still ACCEPTS connections is a FAIL, an inode whose listener
#      is gone (CONNECT refused) is the expected stale-socket outcome.
SOCK_DIR="${TMP_ROOT}/sock"
mkdir -p "${SOCK_DIR}"
export RILL_XRAY_AGENT_SOCKET_DIR="${SOCK_DIR}"

sock_probe() {
    # 0 = connectable listener, else = refused/missing.
    python3 - "${SOCK_DIR}" "$1" <<'PY'
import socket, os, sys
path = os.path.join(sys.argv[1], sys.argv[2] + ".sock")
if not os.path.exists(path):
    sys.exit(3)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(path)
    s.close()
except Exception:
    sys.exit(4)
PY
}

socket_server() {
    # Bind+listen <name>.sock under SOCK_DIR; keep alive; record PID.
    python3 - "${SOCK_DIR}" "$1" <<'PY' &
import socket, sys, os
import time
base, name = sys.argv[1], sys.argv[2]
path = os.path.join(base, name + ".sock")
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(8)
with open(os.path.join(base, name + ".pid"), "w") as fh:
    fh.write(str(os.getpid()))
while True:
    try:
        conn, _ = s.accept()
        conn.close()
    except Exception:
        pass
PY
}

socket_stale() {
    # Create the socket inode with NO living listener (CONNECT must refuse).
    python3 - "${SOCK_DIR}" "$1" <<'PY'
import socket, os, sys
path = os.path.join(sys.argv[1], sys.argv[2] + ".sock")
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.close()
PY
}

socket_stop() {
    local pid_file="${SOCK_DIR}/$1.pid"
    [[ -f "${pid_file}" ]] && kill -9 "$(cat "${pid_file}")" 2>/dev/null
    rm -f "${pid_file}"
}

socket_wait_connected() {
    local name=$1 i=0
    while (( i < 50 )); do
        if sock_probe "$name"; then return 0; fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

socket_wait_refused() {
    local name=$1 i=0 rc
    while (( i < 50 )); do
        sock_probe "$name"
        rc=$?
        if (( rc != 0 )); then return 0; fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

# 7a. observe-only with both listeners live -> contract passes.
export RILL_XRAY_AGENT_SOCKET_DIR="${SOCK_DIR}"
socket_server runtime
socket_server agent
socket_wait_connected runtime || bad "runtime listener did not come up"
socket_wait_connected agent || bad "agent listener did not come up"
fresh
if rxa_apply_mode observe-only >/dev/null 2>&1; then
    ok "apply observe-only (socket sandbox)"
else
    bad "apply observe-only (socket sandbox)"
fi
if rxa_verify_live_contract; then
    ok "verify passes in observe-only with both sockets connectable"
else
    bad "verify fails in observe-only with both sockets connectable"
fi

# 7b. safe-disabled: runtime.sock must STAY connectable; a stale agent socket
#     inode whose listener is dead must be treated as PASS (CONNECT refused).
if rxa_apply_mode safe-disabled >/dev/null 2>&1; then
    ok "apply safe-disabled (socket sandbox)"
else
    bad "apply safe-disabled (socket sandbox)"
fi
socket_stop agent
socket_wait_refused agent || bad "agent listener did not die"
if rxa_verify_live_contract; then
    ok "verify passes in safe-disabled (runtime connected, stale agent.sock refused)"
else
    bad "verify fails in safe-disabled with stale agent socket"
fi

# 7c. safe-disabled with a LIVE agent listener -> MUST FAIL.
socket_server agent
socket_wait_connected agent || bad "agent listener did not come up"
if rxa_verify_live_contract; then
    bad "verify must fail in safe-disabled when agent.sock still accepts"
else
    ok "verify fails in safe-disabled with live agent.sock"
fi

# 7d. stale agent inode WITHOUT any listener is still PASS in safe-disabled.
socket_stop agent
socket_wait_refused agent || bad "agent listener did not die"
socket_stale agent
if rxa_verify_live_contract; then
    ok "verify passes in safe-disabled with fully stale agent.sock"
else
    bad "verify fails in safe-disabled with stale agent.sock"
fi

# 7e. normal requires both sockets connectable; missing agent.sock fails.
if rxa_apply_mode normal >/dev/null 2>&1; then
    ok "apply normal (socket sandbox)"
else
    bad "apply normal (socket sandbox)"
fi
rm -f "${SOCK_DIR}/agent.sock" "${SOCK_DIR}/agent.pid"
if rxa_verify_live_contract; then
    bad "verify must fail in normal when agent.sock is absent"
else
    ok "verify fails in normal with agent.sock absent"
fi
socket_server agent
socket_wait_connected agent || bad "agent listener did not come up"
if rxa_verify_live_contract; then
    ok "verify passes in normal with both sockets connectable"
else
    bad "verify fails in normal with both sockets connectable"
fi

# 7f. missing/unconnectable runtime.sock fails in EVERY mode.
socket_stop agent
socket_stop runtime
rm -f "${SOCK_DIR}/runtime.sock"
if rxa_verify_live_contract; then
    bad "verify must fail when runtime.sock is absent"
else
    ok "verify fails when runtime.sock absent"
fi

for _pid in "${SOCK_DIR}"/.pid "${SOCK_DIR}"/*.pid; do
    [[ -f "${_pid}" ]] && kill -9 "$(cat "${_pid}")" 2>/dev/null
done
rm -rf "${SOCK_DIR}"

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" == 0 ]]
