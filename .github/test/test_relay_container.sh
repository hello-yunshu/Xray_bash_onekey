#!/bin/bash
#
# Relay node container verification.
#
# This is the heavy, end-to-end counterpart to test_relay_node.sh (which is a
# pure function-level suite). It installs a real Nginx build from the project
# release, forwards real TCP traffic, and then walks the whole lifecycle:
# change target, change listen port, stop/start, invalid input, port conflict,
# nginx -t rollback, nginx update, uninstall, and the mixing guards.
#
# Requirements:
#   * root
#   * network access to the Nginx release assets
#   * a working systemctl. Inside a container use docker/fake-systemctl:
#       cp docker/fake-systemctl /usr/local/bin/systemctl
#   * apt-based distro with the runtime dependencies installable
#
# Typical run (arm64 host, project root as CWD):
#   docker run --rm --platform linux/arm64 -v "$PWD":/work -w /work \
#     <image-with-deps-and-fake-systemctl> bash .github/test/test_relay_container.sh
#
# Usage: test_relay_container.sh [all|lifecycle|guard]

set +u # install.sh relies on unset globals (auto_update et al.) being empty

MODE="${1:-all}"
case "${MODE}" in
all | lifecycle | guard) ;;
*)
    echo "Usage: $0 [all|lifecycle|guard]"
    exit 1
    ;;
esac

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_DIR}" || exit 1

PASS=0
FAIL=0

ok() {
    PASS=$((PASS + 1))
    echo "  ✅ PASS: $*"
}
bad() {
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: $*"
}
section() { echo ""; echo "--- $* ---"; }

if [[ "$(id -u)" != "0" ]]; then
    echo "This suite needs root (it installs Nginx and writes /etc/idleleo)."
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required before running this suite."
    exit 1
fi

mkdir -p /etc/idleleo/tmp /etc/idleleo/logs /etc/idleleo/info /etc/idleleo/conf /etc/idleleo/scripts
cp -f "${REPO_DIR}/install.sh" /etc/idleleo/install.sh
ln -sf /etc/idleleo/install.sh /usr/bin/idleleo
for sub in fail2ban_manager.sh traffic_blocker.sh file_manager.sh auto_update.sh ssl_update.sh geo_update.sh; do
    [[ -f "${REPO_DIR}/scripts/${sub}" ]] && cp -f "${REPO_DIR}/scripts/${sub}" "/etc/idleleo/scripts/${sub}"
done
if [[ -d "${REPO_DIR}/i18n/languages" ]]; then
    mkdir -p /etc/idleleo/languages
    cp -rf "${REPO_DIR}/i18n/languages/"* /etc/idleleo/languages/ 2>/dev/null || true
fi

export _TEST_MODE=1
# shellcheck disable=SC1091
source ./install.sh
init_language
read_version

BACKEND_A_PORT=15010
BACKEND_B_PORT=15011
RELAY_PORT=14400
RELAY_PORT_2=14401
CONFLICT_PORT=14402

start_backend() {
    local port="$1" tag="$2" root="/tmp/be-${2}"
    mkdir -p "${root}"
    printf '%s\n' "${tag}" >"${root}/index.html"
    (cd "${root}" && exec python3 -m http.server "${port}" --bind 127.0.0.1) >"/tmp/be-${tag}.log" 2>&1 &
    local i
    for ((i = 0; i < 40; i++)); do
        if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

probe_tag() {
    curl -sS --max-time 5 "http://127.0.0.1:${1}/index.html" 2>/dev/null | tr -d '\r\n'
}

port_listening() {
    ss -ltnH 2>/dev/null | awk -v p=":${1}" '$4 ~ p "$" { found = 1 } END { exit !found }'
}

wait_port() {
    local port="$1" i
    for ((i = 0; i < 40; i++)); do
        port_listening "${port}" && return 0
        sleep 0.25
    done
    return 1
}

wait_port_gone() {
    local port="$1" i
    for ((i = 0; i < 40; i++)); do
        port_listening "${port}" || return 0
        sleep 0.25
    done
    return 1
}

# ---------------------------------------------------------------------------
# Lifecycle: install -> target change -> listen change -> stop/start ->
#            invalid input -> port conflict -> rollback -> update -> uninstall
# ---------------------------------------------------------------------------
run_lifecycle() {
    echo "============================================"
    echo "  Relay lifecycle verification"
    echo "============================================"

    section "Phase 0: real relay wizard input handling"
    # A malformed host first, so the re-ask path is exercised too.
    printf 'bad..host\n127.0.0.1\n%s\n%s\nn\n' "${BACKEND_A_PORT}" "${RELAY_PORT}" >/tmp/wizard.in
    relay_wizard </tmp/wizard.in >/tmp/wizard.log 2>&1
    local _wizard_rc=$?
    [[ ${_wizard_rc} -eq 0 ]] && ok "wizard accepts a valid answer set" ||
        bad "wizard accepts a valid answer set (rc=${_wizard_rc})"
    [[ "${relay_backend_host}" == "127.0.0.1" ]] && ok "wizard stores the landing host" ||
        bad "wizard stores the landing host (got '${relay_backend_host}')"
    [[ "${relay_backend_port}" == "${BACKEND_A_PORT}" ]] && ok "wizard stores the landing port" ||
        bad "wizard stores the landing port"
    [[ "${relay_listen_port}" == "${RELAY_PORT}" ]] && ok "wizard stores the listen port" ||
        bad "wizard stores the listen port"
    [[ "${relay_listen_addr}" == "0.0.0.0" ]] && ok "wizard defaults the listen address to 0.0.0.0" ||
        bad "wizard defaults the listen address to 0.0.0.0"
    grep -q "落地服务器地址无效" /tmp/wizard.log &&
        ok "wizard re-asks after a malformed landing host" || bad "wizard re-asks after a malformed landing host"
    grep -q "不安装 Xray" /tmp/wizard.log &&
        ok "wizard states that no Xray is installed" || bad "wizard states that no Xray is installed"
    grep -q "REALITY 公钥/SNI/ShortId" /tmp/wizard.log &&
        ok "wizard states that client keys stay unchanged" || bad "wizard states that client keys stay unchanged"

    # read -p only prints its prompt on a terminal, so inspect the function body
    # instead of the log to prove the wizard stays scoped to relay questions.
    local _relay_wizard_body
    _relay_wizard_body=$(declare -f relay_wizard)
    printf '%s' "${_relay_wizard_body}" | grep -qF '落地服务器地址' &&
        ok "wizard asks for the landing host" || bad "wizard asks for the landing host"
    printf '%s' "${_relay_wizard_body}" | grep -qF '本机监听端口' &&
        ok "wizard asks for the listen port" || bad "wizard asks for the listen port"
    if printf '%s' "${_relay_wizard_body}" | grep -qE 'UUID_set|email_set|domain_check|ssl_judge_and_install|target_set|keys_set|shortIds_set'; then
        bad "wizard never asks for Xray/TLS parameters"
    else
        ok "wizard never asks for Xray/TLS parameters"
    fi
    if printf '%s' "${_relay_wizard_body}" | grep -qE 'xray_conf|privateKey|publicKey'; then
        bad "wizard never touches Xray keys or config"
    else
        ok "wizard never touches Xray keys or config"
    fi

    section "Phase 1: fresh relay install"
    # Interaction mocks for an unattended run: no public-IP probe, no firewall,
    # no cron side effects. The relay code paths themselves stay real.
    ip_check() {
        local_ip="192.0.2.10"
        ip_version="IPv4"
    }
    firewall_set() { :; }
    auto_update() { :; }
    acme_cron_update() { :; }
    setup_auto_clean_logs() { :; }
    show_information() { :; }
    relay_wizard() {
        relay_backend_host="127.0.0.1"
        relay_backend_port="${BACKEND_A_PORT}"
        relay_listen_port="${RELAY_PORT}"
        relay_listen_addr="0.0.0.0"
    }

    start_backend "${BACKEND_A_PORT}" backend-A || echo "  (warn) backend A failed to start"
    start_backend "${BACKEND_B_PORT}" backend-B || echo "  (warn) backend B failed to start"
    [[ "$(probe_tag "${BACKEND_A_PORT}")" == "backend-A" ]] &&
        ok "backend A answers directly" || bad "backend A answers directly"

    if (install_nginx_relay) >/tmp/relay-install.log 2>&1; then
        ok "install_nginx_relay returned 0"
    else
        bad "install_nginx_relay returned non-zero (see /tmp/relay-install.log)"
        tail -20 /tmp/relay-install.log
    fi
    wait_port "${RELAY_PORT}" && ok "relay entry port ${RELAY_PORT} is listening" ||
        bad "relay entry port ${RELAY_PORT} is listening"
    [[ "$(probe_tag "${RELAY_PORT}")" == "backend-A" ]] &&
        ok "traffic reaches backend A through the relay" ||
        bad "traffic reaches backend A through the relay (got '$(probe_tag "${RELAY_PORT}")')"

    section "Phase 2: role persistence and information output"
    node_role=""
    relay_backend_host=""
    relay_backend_port=""
    relay_listen_port=""
    relay_listen_addr=""
    relay_bootstrap_role >/dev/null 2>&1
    [[ "${node_role}" == "relay" ]] && ok "role reloads as relay from install_config.json" ||
        bad "role reloads as relay from install_config.json"
    [[ "${relay_backend_host}:${relay_backend_port}" == "127.0.0.1:${BACKEND_A_PORT}" ]] &&
        ok "target reloads from install_config.json" || bad "target reloads from install_config.json"
    [[ "${relay_listen_port}" == "${RELAY_PORT}" ]] && ok "listen port reloads" || bad "listen port reloads"

    relay_basic_information >/dev/null 2>&1
    local info_file="${xray_info_file}"
    if [[ -f "${info_file}" ]]; then
        ok "information file written"
        grep -q "127.0.0.1:${BACKEND_A_PORT}" "${info_file}" &&
            ok "information shows the landing target" || bad "information shows the landing target"
        grep -q "REALITY 公钥/SNI/ShortId" "${info_file}" &&
            ok "information tells clients keys stay unchanged" ||
            bad "information tells clients keys stay unchanged"
        grep -q "不代表 REALITY" "${info_file}" &&
            ok "information warns TCP reachability is not a REALITY handshake" ||
            bad "information warns TCP reachability is not a REALITY handshake"
        grep -qE "UUID|id:" "${info_file}" && bad "information must not mention UUID" ||
            ok "information has no UUID"
        [[ "$(stat -c '%a' "${info_file}")" == "600" ]] && ok "information file is 600" ||
            bad "information file is 600 (got $(stat -c '%a' "${info_file}"))"
    else
        bad "information file written"
    fi

    section "Phase 3: change landing target"
    if printf '127.0.0.1\n%s\n' "${BACKEND_B_PORT}" | (relay_modify_target) >/tmp/modify-target.log 2>&1; then
        ok "relay_modify_target returned 0"
    else
        bad "relay_modify_target returned 0"
        tail -10 /tmp/modify-target.log
    fi
    _relay_state_load >/dev/null 2>&1
    [[ "$(probe_tag "${RELAY_PORT}")" == "backend-B" ]] &&
        ok "traffic switched to backend B without touching the entry port" ||
        bad "traffic switched to backend B (got '$(probe_tag "${RELAY_PORT}")')"
    grep -qF "proxy_pass 127.0.0.1:${BACKEND_B_PORT};" "${relay_stream_conf}" &&
        ok "managed stream config points at the new target" || bad "managed stream config points at the new target"
    [[ "$(info_extraction relay_backend_port)" == "${BACKEND_B_PORT}" ]] &&
        ok "new target persisted in install_config.json" || bad "new target persisted in install_config.json"
    nginx_run_config_test >/dev/null 2>&1 &&
        ok "nginx -t passes after the target change" || bad "nginx -t passes after the target change"

    section "Phase 4: change listen port"
    if printf '%s\n' "${RELAY_PORT_2}" | (relay_modify_listen_port) >/tmp/modify-port.log 2>&1; then
        ok "relay_modify_listen_port returned 0"
    else
        bad "relay_modify_listen_port returned 0"
        tail -10 /tmp/modify-port.log
    fi
    _relay_state_load >/dev/null 2>&1
    wait_port "${RELAY_PORT_2}" && ok "new entry port ${RELAY_PORT_2} is listening" ||
        bad "new entry port ${RELAY_PORT_2} is listening"
    wait_port_gone "${RELAY_PORT}" && ok "old entry port ${RELAY_PORT} is closed" ||
        bad "old entry port ${RELAY_PORT} is closed"
    [[ "$(probe_tag "${RELAY_PORT_2}")" == "backend-B" ]] &&
        ok "traffic flows on the new entry port" || bad "traffic flows on the new entry port"

    section "Phase 5: stop / start"
    systemctl stop nginx >/dev/null 2>&1
    wait_port_gone "${RELAY_PORT_2}" && ok "stopping the relay closes the entry port" ||
        bad "stopping the relay closes the entry port"
    systemctl start nginx >/dev/null 2>&1
    wait_port "${RELAY_PORT_2}" && ok "starting the relay reopens the entry port" ||
        bad "starting the relay reopens the entry port"
    [[ "$(probe_tag "${RELAY_PORT_2}")" == "backend-B" ]] &&
        ok "forwarding survives a stop/start cycle" || bad "forwarding survives a stop/start cycle"

    section "Phase 6: invalid input rejection"
    local _rl_host="${relay_backend_host}" _rl_bport="${relay_backend_port}"
    local _rl_lport="${relay_listen_port}" _rl_laddr="${relay_listen_addr}"

    _expect_reject() {
        local desc="$1"
        if relay_validate_inputs >/dev/null 2>&1; then
            bad "rejects ${desc}"
        else
            ok "rejects ${desc}"
        fi
    }
    _restore_state() {
        relay_backend_host="${_rl_host}"
        relay_backend_port="${_rl_bport}"
        relay_listen_port="${_rl_lport}"
        relay_listen_addr="${_rl_laddr}"
    }

    relay_backend_host='127.0.0.1; rm -rf /'
    _expect_reject "a shell-injection landing host"
    relay_backend_host='evil$(id).example.com'
    _expect_reject "a command-substitution landing host"
    relay_backend_host='-bad.example.com'
    _expect_reject "a leading-hyphen landing host"
    relay_backend_host='bad..example.com'
    _expect_reject "a double-dot landing host"
    relay_backend_host=''
    _expect_reject "an empty landing host"
    _restore_state

    relay_backend_port='0'
    _expect_reject "landing port 0"
    relay_backend_port='70000'
    _expect_reject "landing port above 65535"
    relay_backend_port='abc'
    _expect_reject "a non-numeric landing port"
    _restore_state

    relay_listen_port='0'
    _expect_reject "listen port 0"
    _restore_state

    relay_listen_addr='999.1.1.1'
    _expect_reject "a malformed listen address"
    _restore_state
    relay_validate_inputs >/dev/null 2>&1 && ok "accepts the known-good current config" ||
        bad "accepts the known-good current config"

    section "Phase 7: listen port conflict is refused"
    (cd /tmp && exec python3 -m http.server "${CONFLICT_PORT}" --bind 127.0.0.1) >/tmp/conflict.log 2>&1 &
    local _i
    for _i in $(seq 1 40); do
        port_listening "${CONFLICT_PORT}" && break
        sleep 0.25
    done
    if printf '%s\n' "${CONFLICT_PORT}" | (relay_modify_listen_port) >/tmp/conflict-change.log 2>&1; then
        bad "modify_listen_port refuses an occupied port"
    else
        ok "modify_listen_port refuses an occupied port"
    fi
    _relay_state_load >/dev/null 2>&1
    [[ "${relay_listen_port}" == "${RELAY_PORT_2}" ]] &&
        ok "listen port rolls back after the conflict" || bad "listen port rolls back after the conflict"
    wait_port "${RELAY_PORT_2}" && ok "forwarding is untouched after the refused change" ||
        bad "forwarding is untouched after the refused change"
    pkill -f "http.server ${CONFLICT_PORT}" 2>/dev/null || true

    section "Phase 8: rollback when nginx -t fails"
    cp -p "${nginx_main_conf}" /tmp/nginx.conf.good
    cp -p "${relay_stream_conf}" /tmp/relay-stream.conf.good
    printf 'this_directive_does_not_exist_on;\n' >>"${nginx_main_conf}"
    relay_backend_host="127.0.0.1"
    relay_backend_port="${BACKEND_A_PORT}"
    if (relay_apply_change) >/tmp/rollback.log 2>&1; then
        bad "apply change fails when nginx -t rejects the config"
    else
        ok "apply change fails when nginx -t rejects the config"
    fi
    grep -q "已恢复原转发配置" /tmp/rollback.log && ok "rollback message is printed" || bad "rollback message is printed"
    cmp -s "${relay_stream_conf}" /tmp/relay-stream.conf.good &&
        ok "managed stream config rolled back to the previous content" ||
        bad "managed stream config rolled back to the previous content"
    cp -p /tmp/nginx.conf.good "${nginx_main_conf}"
    systemctl reload nginx >/dev/null 2>&1
    [[ "$(probe_tag "${RELAY_PORT_2}")" == "backend-B" ]] &&
        ok "forwarding keeps working after the rollback" || bad "forwarding keeps working after the rollback"

    section "Phase 9: nginx update keeps the relay config"
    update_json_config "${xray_install_config_file}" '.nginx_build_version = "0.0.0-old"' >/dev/null 2>&1
    _info_cache_invalidate 2>/dev/null || true
    # The point is not that the download succeeds; it is that the relay config
    # survives either outcome. A failed download must roll back cleanly.
    if (nginx_update_relay) >/tmp/nginx-update.log 2>&1; then
        ok "nginx_update_relay completed the update"
    elif grep -q "已成功回滚到之前的 Nginx 版本" /tmp/nginx-update.log; then
        ok "nginx_update_relay rolled back cleanly when the download failed"
    else
        bad "nginx_update_relay either updates or rolls back cleanly"
        tail -15 /tmp/nginx-update.log
    fi
    grep -qF "include ${relay_stream_conf};" "${nginx_main_conf}" &&
        ok "main config still includes the stream fragment after the update" ||
        bad "main config still includes the stream fragment after the update"
    [[ -f "${relay_stream_conf}" ]] && ok "stream fragment survived the update" ||
        bad "stream fragment survived the update"
    nginx_run_config_test >/dev/null 2>&1 &&
        ok "nginx -t passes after the update" || bad "nginx -t passes after the update"
    wait_port "${RELAY_PORT_2}" && ok "entry port is listening after the update" ||
        bad "entry port is listening after the update"
    [[ "$(probe_tag "${RELAY_PORT_2}")" == "backend-B" ]] &&
        ok "forwarding still works after the update" || bad "forwarding still works after the update"

    section "Phase 10: uninstall"
    printf 'y\nn\n' | (relay_uninstall) >/tmp/relay-uninstall.log 2>&1
    local _uninstall_rc=$?
    [[ ${_uninstall_rc} -eq 0 ]] && ok "relay_uninstall returned 0" ||
        bad "relay_uninstall returned 0 (rc=${_uninstall_rc})"
    tail -5 /tmp/relay-uninstall.log
    [[ -f "${relay_stream_conf}" ]] && bad "stream fragment removed" || ok "stream fragment removed"
    grep -qF "include ${relay_stream_conf};" "${nginx_main_conf}" 2>/dev/null &&
        bad "include removed from the main config" || ok "include removed from the main config"
    [[ -x "${nginx_dir}/sbin/nginx" ]] && bad "nginx uninstalled" || ok "nginx uninstalled"
    wait_port_gone "${RELAY_PORT_2}" && ok "entry port is closed after uninstall" ||
        bad "entry port is closed after uninstall"
    if [[ -f "${xray_install_config_file}" ]]; then
        [[ "$(jq -r '(.role // "none")' "${xray_install_config_file}")" == "none" ]] &&
            ok "install config no longer declares the relay role" ||
            bad "install config no longer declares the relay role"
    fi
    if [[ -x /usr/local/bin/xray ]] || [[ -f "${xray_conf}" ]]; then
        bad "relay never installed Xray"
    else
        ok "relay never installed Xray"
    fi
}

# ---------------------------------------------------------------------------
# Guards: a relay must not coexist with a node install, and a legacy XTLS ONLY
#         install must never be silently reinstalled.
# ---------------------------------------------------------------------------
run_guard() {
    echo ""
    echo "============================================"
    echo "  Relay / legacy guard verification"
    echo "============================================"

    # Keep the guard phases off the package manager.
    dependency_install() { :; }

    section "Guard A: Xray config present"
    mkdir -p "$(dirname "${xray_conf}")"
    printf '{"inbounds":[]}\n' >"${xray_conf}"
    node_role="relay"
    relay_backend_host="127.0.0.1"
    relay_backend_port="443"
    relay_listen_port="14410"
    relay_listen_addr="0.0.0.0"
    if (relay_preflight) >/tmp/guard-a.log 2>&1; then
        bad "relay_preflight refuses an existing Xray config"
    else
        ok "relay_preflight refuses an existing Xray config"
    fi
    grep -q "检测到 Xray 配置文件" /tmp/guard-a.log &&
        ok "rejection explains the Xray config conflict" || bad "rejection explains the Xray config conflict"
    grep -q "中转节点不安装 Xray" /tmp/guard-a.log &&
        ok "rejection explains the relay never installs Xray" || bad "rejection explains the relay never installs Xray"
    [[ -f "${xray_conf}" ]] && ok "existing Xray config was not modified" || bad "existing Xray config was not modified"
    rm -f "${xray_conf}"

    section "Guard B: managed Nginx site present"
    mkdir -p "${nginx_conf_dir}"
    printf 'server { listen 8080; }\n' >"${nginx_conf}"
    if (relay_preflight) >/tmp/guard-b.log 2>&1; then
        bad "relay_preflight refuses a managed Nginx site"
    else
        ok "relay_preflight refuses a managed Nginx site"
    fi
    grep -q "不能与普通节点或受管站点混装" /tmp/guard-b.log &&
        ok "rejection explains the mixing restriction" || bad "rejection explains the mixing restriction"
    [[ -f "${nginx_conf}" ]] && ok "existing managed site was not modified" || bad "existing managed site was not modified"
    rm -f "${nginx_conf}"

    section "Guard C: legacy XTLS ONLY install"
    node_role="node"
    legacy_xtls_only="on" # what judge_mode sets when tls == "XTLS"
    mkdir -p "$(dirname "${xray_install_config_file}")"
    jq -n '{tls: "XTLS", shell_mode: "XTLS ONLY", port: 443}' >"${xray_install_config_file}"
    _info_cache_invalidate 2>/dev/null || true
    if (old_config_exist_check) >/tmp/guard-c.log 2>&1; then
        bad "old_config_exist_check refuses a legacy XTLS ONLY reinstall"
    else
        ok "old_config_exist_check refuses a legacy XTLS ONLY reinstall"
    fi
    grep -q "该模式已取消" /tmp/guard-c.log &&
        ok "refusal names the removed XTLS mode" || bad "refusal names the removed XTLS mode"
    grep -q "现有配置与服务不会被改动" /tmp/guard-c.log &&
        ok "refusal promises the running install is left untouched" ||
        bad "refusal promises the running install is left untouched"
    [[ -f "${xray_install_config_file}" ]] && ok "legacy install config was not deleted" ||
        bad "legacy install config was not deleted"
    is_legacy_xtls_mode && ok "legacy XTLS mode is flagged for reporting" || bad "legacy XTLS mode is flagged for reporting"

    section "Guard D: clean host is allowed"
    rm -f "${xray_install_config_file}"
    _info_cache_invalidate 2>/dev/null || true
    if (relay_preflight) >/tmp/guard-d.log 2>&1; then
        ok "relay_preflight allows a clean host"
    else
        bad "relay_preflight allows a clean host"
        head -5 /tmp/guard-d.log
    fi
}

# Lifecycle first: it ends with an uninstall, so the guard phases start clean.
case "${MODE}" in
lifecycle) run_lifecycle ;;
guard) run_guard ;;
all)
    run_lifecycle
    run_guard
    ;;
esac

echo ""
echo "============================================"
echo "  Container verification results (${MODE})"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "============================================"

pkill -f "http.server 1501" 2>/dev/null || true
[[ ${FAIL} -eq 0 ]] || exit 1
exit 0
