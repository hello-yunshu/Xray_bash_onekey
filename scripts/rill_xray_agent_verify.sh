#!/usr/bin/env bash
set -euo pipefail
root=${DESTDIR:-}
required=(
  /etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh
  /opt/rill-xray-agent/bin/rill-xray-agent
  /opt/rill-xray-agent/bin/rill-xray-agent-runtime
  /opt/rill-xray-agent/bin/rill-xray-agent-agent
  /etc/systemd/system/rill-xray-agent-runtime.service
  /etc/systemd/system/rill-xray-agent-agent.service
)
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
