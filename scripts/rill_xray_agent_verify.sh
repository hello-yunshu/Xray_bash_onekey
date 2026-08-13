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
        [[ -f "$root$file" ]] || { echo "缺少必要文件: $file" >&2; exit 1; }
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
    echo 'Rill Xray AI 运维助手静态安装校验通过'
}

# Real-system (DESTDIR empty) verification must prove running state, not just
# file presence. It runs the SAME mode-aware live contract as the manager menu
# (Verify) and the CLI (--rill-agent-verify): committed config defaults,
# Runtime WAL mode, per-mode systemd unit states, socket connectability and
# observation freshness. Live-state decisions belong to the shared contract;
# this script itself only keeps the static package checks.
runtime_check() {
    command -v systemctl >/dev/null 2>&1 || { echo '缺少 systemctl，无法校验实时运行状态' >&2; exit 1; }
    source "$root/etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh"

    rxa_verify_live_contract || { echo 'Rill Xray AI 运维助手实时运行校验失败' >&2; exit 1; }

    echo 'Rill Xray AI 运维助手实时运行校验通过'
}

if [[ -n "$root" ]]; then
    static_check
else
    runtime_check
fi
