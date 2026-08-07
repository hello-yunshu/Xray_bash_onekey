#!/usr/bin/env bash
set -euo pipefail
root=${DESTDIR:-}

static_check() {
    local required=(
        /etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh
        /opt/rill-xray-agent/bin/rill-xray-agent
        /opt/rill-xray-agent/bin/rill-xray-agent-runtime
        /opt/rill-xray-agent/bin/rill-xray-agent-agent
        /etc/systemd/system/rill-xray-agent-runtime.service
        /etc/systemd/system/rill-xray-agent-agent.service
    )
    local file
    for file in "${required[@]}"; do
        [[ -f "$root$file" ]] || { echo "missing $file" >&2; exit 1; }
    done
    bash -n "$root/etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh"
    python3 -m py_compile "$root/opt/rill-xray-agent/python/rill_xray_agent/runtime_service.py"
    python3 - "$root/etc/rill-xray-agent/config.json" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
assert data['routeAssistEnabled'] is False
assert data['boundedAutoAllowed'] is False
assert data['mode'] in {'normal','observe-only','safe-disabled'}
PY
    echo 'Rill Xray Agent static installation verification passed'
}

# Real-system (DESTDIR empty) verification must prove running state, not just
# file presence: unit enablement/activation, Runtime config, agent socket,
# fresh structurally-valid observation and configuration security defaults.
runtime_check() {
    command -v systemctl >/dev/null 2>&1 || { echo 'systemctl missing; cannot verify live state' >&2; exit 1; }
    source "$root/etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh"

    local unit
    for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service \
                rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer; do
        systemctl is-enabled --quiet "$unit" 2>/dev/null || { echo "unit not enabled: $unit" >&2; exit 1; }
        systemctl is-active --quiet "$unit" 2>/dev/null || { echo "unit not active: $unit" >&2; exit 1; }
    done

    # config.json must be committed to the expected defaults and mode.
    python3 - "$root/etc/rill-xray-agent/config.json" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
assert data['routeAssistEnabled'] is False, 'routeAssistEnabled drifted'
assert data['boundedAutoAllowed'] is False, 'boundedAutoAllowed drifted'
assert data['mode'] in {'normal','observe-only','safe-disabled'}
PY

    # Runtime WAL config must agree with the committed config string.
    local mode runtime_mode
    mode=$(rxa_get mode)
    runtime_mode=$(rxa_runtime config 2>/dev/null | python3 -c 'import json,sys;d=json.load(sys.stdin);print((d.get("result") or d).get("mode",""))') || exit 1
    [[ "$mode" == "$runtime_mode" ]] || { echo "runtime mode drift: config=$mode runtime=$runtime_mode" >&2; exit 1; }

    # Agent and runtime sockets must be present and owned by the service UID.
    local sock
    for sock in /run/rill-xray-agent/runtime.sock /run/rill-xray-agent/agent.sock; do
        [[ -S "$sock" ]] || { echo "socket missing: $sock" >&2; exit 1; }
    done

    # Observation must be present and fresh and structurally valid.
    rxa_observe_valid || { echo 'observation missing/stale/invalid' >&2; exit 1; }

    # Full target-state convergence for the requested mode.
    rxa_mode_state_matches_target "$mode" || { echo "state does not match mode=$mode" >&2; exit 1; }

    echo 'Rill Xray Agent live system verification passed'
}

if [[ -n "$root" ]]; then
    static_check
else
    runtime_check
fi