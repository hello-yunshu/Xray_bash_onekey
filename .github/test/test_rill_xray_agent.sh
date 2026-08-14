#!/usr/bin/env bash
set -euo pipefail
bash -n scripts/rill_xray_agent_manager.sh
bash -n scripts/rill_xray_agent_install.sh
bash -n scripts/rill_xray_agent_uninstall.sh
python3 -m py_compile scripts/rill_xray_agent_observe.py
bash -n install.sh
grep -q 'menu_item 9 "$(gettext "Rill Xray AI 运维助手")"' install.sh
grep -Fq -- '--rill-agent-install) rxa_dispatch install' install.sh
grep -q -- '--rill-agent-status' install.sh
grep -q '^RILL_XRAY_AGENT_INTEGRATION_SCHEMA=' install.sh
# P0-5: updates download to a candidate, validate, then atomically replace.
grep -Fq 'install.sh.rxa-candidate.$$' install.sh
grep -Fq 'rxa_download_main_candidate "${_candidate}"' install.sh
grep -Fq 'rxa_replace_main_candidate "${_candidate}" "${idleleo}"' install.sh
grep -Fq 'rxa_candidate_guard "${candidate}"' install.sh
grep -q 'rxa_candidate_guard()' install.sh
grep -q 'rxa_candidate_guard()' scripts/rill_xray_agent_manager.sh

# An older installed manager probes the new integration block with only
# menu_pause() available.  Exercise that exact manager -> candidate path: the
# new fallback menu must not loop on missing UI helpers, and expected negative
# uninstall probes must not leak alarming messages to the user's terminal.
# Keep the timeout so a regression fails quickly instead of hanging CI.
if ! python3 - "${PWD}/scripts/rill_xray_agent_manager.sh" "${PWD}/install.sh" <<'PY'
import os
import subprocess
import sys
import tempfile

manager, candidate = sys.argv[1:]
candidate_text = open(candidate, encoding="utf-8").read()
# Guards before the capability-floor release used these exact static anchors.
# Keep them inert but recognizable so a direct upgrade from those releases is
# not falsely rejected before the semantic probe can even run.
if "\nRILL_XRAY_AGENT_INTEGRATION_SCHEMA=1\n" not in "\n" + candidate_text:
    raise SystemExit("legacy schema-1 candidate anchor missing")
if 'menu_item 9 "Rill Xray Agent"' not in candidate_text:
    raise SystemExit("legacy menu candidate anchor missing")
with tempfile.TemporaryDirectory() as root:
    env = os.environ.copy()
    env.update({
        "RILL_XRAY_AGENT_HOME": os.path.join(root, "etc-rill"),
        "RILL_XRAY_AGENT_MANAGER": os.path.join(root, "etc-rill", "scripts", "manager.sh"),
        "RILL_XRAY_AGENT_STATE": os.path.join(root, "state"),
        "RILL_XRAY_AGENT_CONFIG": os.path.join(root, "config.json"),
        "_TEST_MODE": "1",
    })
    completed = subprocess.run(
        ["bash", "-c", 'source "$1"; rxa_candidate_guard "$2"', "_", manager, candidate],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"legacy candidate probe failed rc={completed.returncode}: {completed.stderr}"
        )
    if completed.stdout or completed.stderr:
        raise SystemExit(
            "legacy candidate probe leaked output: "
            + completed.stdout
            + completed.stderr
        )
PY
then
    echo 'legacy Rill candidate-guard compatibility failed' >&2
    exit 1
fi

# User-facing Rill copy describes product concepts instead of mechanically
# translating implementation class names. Protocol values remain unchanged.
localized_output="$({
    gettext() { printf '%s' "$1"; }
    # shellcheck source=/dev/null
    source scripts/rill_xray_agent_manager.sh
    rxa_status_json() { printf '%s\n' '{"mode":"observe-only"}'; }
    rxa_systemctl() { return 0; }
    rxa_get() { [[ ${1:-} == routeStage ]] && printf '%s\n' observe; }
    rxa_refresh_summary
    rxa_status_display
    menu_submenu_begin() { printf 'TITLE:%s\n' "$1"; }
    menu_item() { printf 'ITEM:%s\n' "$2"; }
    menu_blank() { :; }
    menu_footer() { :; }
    menu_read() { printf -v "$1" '%s' 0; }
    rxa_menu
} 2>&1)"
grep -Fq 'AI 判断: 仅观察' <<<"${localized_output}"
grep -Fq '工作模式: 仅观察' <<<"${localized_output}"
grep -Fq '服务: 运行中' <<<"${localized_output}"
grep -Fq '路由辅助: 关闭' <<<"${localized_output}"
if grep -Eq '代理:|运行时:|Route:|Assist' <<<"${localized_output}"; then
    echo 'Rill UI contains an ambiguous or mechanically translated label' >&2
    exit 1
fi
for label in '查看 AI 判断状态' '安装或修复 AI 判断引擎' '开启 AI 智能判断' \
    '切换到 AI 观察模式' '安全停用 AI 判断' '校验 AI 判断引擎' \
    '运行 AI 故障诊断' '卸载 Rill AI 引擎'; do
    grep -Fq "ITEM:${label}" <<<"${localized_output}"
done

diagnosis_output="$({
    gettext() { printf '%s' "$1"; }
    # shellcheck source=/dev/null
    source scripts/rill_xray_agent_manager.sh
    rxa_diagnose() {
        printf '%s\n' '{"result":{"diagnosisCode":"HEALTHY","confidenceBand":"high","canApply":false}}'
    }
    rxa_diagnose_display
})"
grep -Fq 'AI 判断: Xray 相关服务运行正常，未发现近期故障' <<<"${diagnosis_output}"
grep -Fq '判断置信度: 高' <<<"${diagnosis_output}"
grep -Fq '此结果仅提供判断建议，不会自动修改系统' <<<"${diagnosis_output}"

# Installation is explicitly opt-in because the AI judgment engine is still
# in testing. A blank/default response must fail closed.
set +e
install_notice_output="$({
    gettext() { printf '%s' "$1"; }
    # shellcheck source=/dev/null
    source scripts/rill_xray_agent_manager.sh
    printf '\n' | rxa_install_testing_confirm
} 2>&1)"
install_notice_rc=$?
set -e
[[ ${install_notice_rc} -ne 0 ]]
grep -Fq '目前仍处于测试阶段' <<<"${install_notice_output}"
grep -Fq '不能保证完全无故障' <<<"${install_notice_output}"
grep -Fq '默认仅启用 AI 观察模式' <<<"${install_notice_output}"
grep -Fq '已取消安装' <<<"${install_notice_output}"

{
    gettext() { printf '%s' "$1"; }
    # shellcheck source=/dev/null
    source scripts/rill_xray_agent_manager.sh
    RILL_XRAY_AGENT_ACCEPT_TEST_RISK=1 rxa_install_testing_confirm >/dev/null
}
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
# R6 delivery: current bootstrap consumes current bundled asset (SHA-match,
# extraction, root members, staged installer + config invariants). The
# installer requires EUID 0, so escalate like test_nginx_security.sh. The OI
# regression never replaces this mandatory delivery proof.
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    bash .github/test/test_rill_bootstrap_delivery.sh
else
    sudo bash .github/test/test_rill_bootstrap_delivery.sh
fi
# P0-6: mode-aware host health check (only required components are checked).
bash .github/test/test_rill_xray_agent_healthy.sh
echo 'Rill Xray Agent host integration checks passed'
