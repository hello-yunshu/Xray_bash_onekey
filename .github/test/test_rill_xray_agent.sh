#!/usr/bin/env bash
set -euo pipefail
bash -n scripts/rill_xray_agent_manager.sh
bash -n scripts/rill_xray_agent_install.sh
bash -n scripts/rill_xray_agent_uninstall.sh
python3 -m py_compile scripts/rill_xray_agent_observe.py
grep -q 'menu_item 9 "Rill Xray Agent"' install.sh
grep -q -- '--rill-agent-status' install.sh
echo 'Rill Xray Agent host integration checks passed'
