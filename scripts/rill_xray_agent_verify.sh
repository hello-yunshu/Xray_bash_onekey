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
# file presence. It runs the SAME mode-aware live contract as the manager menu
# (Verify) and the CLI (--rill-agent-verify): committed config defaults,
# Runtime WAL mode, systemd unit states, sockets and observation freshness.
runtime_check() {
    command -v systemctl >/dev/null 2>&1 || { echo 'systemctl missing; cannot verify live state' >&2; exit 1; }
    source "$root/etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh"

    # Static unit enablement is checked first (the shared contract checks
    # activity per-mode); every integration unit must at least be enabled.
    local unit
    for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service \
                rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer; do
        systemctl is-enabled --quiet "$unit" 2>/dev/null || { echo "unit not enabled: $unit" >&2; exit 1; }
    done

    rxa_verify_live_contract || { echo 'Rill Xray Agent live system verification failed' >&2; exit 1; }

    echo 'Rill Xray Agent live system verification passed'
}

if [[ -n "$root" ]]; then
    static_check
else
    runtime_check
fi