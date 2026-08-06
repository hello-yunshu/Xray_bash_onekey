#!/usr/bin/env bash
set -euo pipefail
bash -n scripts/rill_xray_agent_manager.sh
bash -n scripts/rill_xray_agent_install.sh
bash -n scripts/rill_xray_agent_uninstall.sh
python3 -m py_compile scripts/rill_xray_agent_observe.py
bash -n install.sh
grep -q 'menu_item 9 "Rill Xray Agent"' install.sh
grep -q -- '--rill-agent-status' install.sh
grep -q '^RILL_XRAY_AGENT_INTEGRATION_SCHEMA=' install.sh
# P0-5: updates download to a candidate, validate, then atomically replace.
grep -Fq 'install.sh.rxa-candidate.$$' install.sh
grep -Fq 'rxa_candidate_guard "${_candidate}"' install.sh
grep -Fq 'mv -f "${_candidate}" "${idleleo}"' install.sh
grep -q 'rxa_candidate_guard()' scripts/rill_xray_agent_manager.sh
# P0-6: mode switch is a four-party transaction with verification and rollback.
grep -q 'rxa_observe_fresh' scripts/rill_xray_agent_manager.sh
grep -q 'rxa_verify_runtime_mode' scripts/rill_xray_agent_manager.sh
grep -Fq 'rxa_runtime mode "$old"' scripts/rill_xray_agent_manager.sh
# P0-7: observation reads the real host Xray configuration.
grep -Fq 'RILL_XRAY_HOST_ROOT", "/etc/idleleo' scripts/rill_xray_agent_observe.py
grep -Fq 'PathChanged=/etc/idleleo/conf/xray/config.json' systemd/rill-xray-agent-xray-observe.path
grep -Fq 'Environment=RILL_XRAY_HOST_ROOT=/etc/idleleo' systemd/rill-xray-agent-xray-observe.service
echo 'Rill Xray Agent host integration checks passed'