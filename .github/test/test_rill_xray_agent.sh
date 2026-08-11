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
grep -q 'rxa_candidate_guard()' install.sh
grep -q 'rxa_candidate_guard()' scripts/rill_xray_agent_manager.sh
# P0-6: mode switch is a four-party transaction with verification and rollback.
grep -q 'rxa_observe_fresh' scripts/rill_xray_agent_manager.sh
grep -q 'rxa_verify_runtime_mode' scripts/rill_xray_agent_manager.sh
grep -Fq 'rxa_runtime mode "$old"' scripts/rill_xray_agent_manager.sh
# P0-7: observation reads the real host Xray configuration.
grep -Fq 'RILL_XRAY_HOST_ROOT", "/etc/idleleo' scripts/rill_xray_agent_observe.py
grep -Fq 'PathChanged=/etc/idleleo/conf/xray/config.json' systemd/rill-xray-agent-xray-observe.path
grep -Fq 'Environment=RILL_XRAY_HOST_ROOT=/etc/idleleo' systemd/rill-xray-agent-xray-observe.service
# P0-x: two-phase uninstall contract (prepare -> commit/abort).
grep -q 'rxa_uninstall_prepare()' scripts/rill_xray_agent_uninstall.sh
grep -q 'rxa_uninstall_remove_rill()' scripts/rill_xray_agent_uninstall.sh
grep -q 'rxa_uninstall_verify_host()' scripts/rill_xray_agent_uninstall.sh
grep -q 'rxa_uninstall_mark()' scripts/rill_xray_agent_uninstall.sh
grep -q 'rxa_uninstall_commit()' scripts/rill_xray_agent_uninstall.sh
grep -q 'rxa_uninstall_abort()' scripts/rill_xray_agent_uninstall.sh
grep -Fq -- '--purge' scripts/rill_xray_agent_uninstall.sh
grep -Fq 'rxa_uninstall_finish "$rxa_uninstall_rc"' install.sh
grep -Fq 'rxa_uninstall_prepare' install.sh
grep -Fq 'uninstall_xray || rxa_uninstall_rc=1' install.sh
grep -Fq 'uninstall_nginx --force || rxa_uninstall_rc=1' install.sh
grep -Fq 'exit "$?"' install.sh
bash .github/test/test_rill_xray_agent_uninstall.sh
# P1-1: real-implementation durable intent writer tests (prepared/commit/
# abort persistence failure + ordering; never mocks the durable writer).
bash .github/test/test_rill_uninstall_durability.sh
# P0-6: mode-aware host health check (only required components are checked).
bash .github/test/test_rill_xray_agent_healthy.sh
echo 'Rill Xray Agent host integration checks passed'