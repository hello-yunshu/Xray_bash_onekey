#!/usr/bin/env bash
#
# Stage 02 regression tests.
#
# Two independent guarantees are covered:
#
#   A. The `XTLS ONLY` install profile is gone end to end (config template,
#      installer function, CLI flag, menu entry, docs), while the general
#      XTLS/Vision and Reality capabilities stay intact.
#   B. The new independent `relay` role installs a single-target Nginx Stream
#      TCP forwarder: input validation, config rendering, top-level include,
#      transactional apply with rollback, role persistence, preflight refusal,
#      and "never touches Xray" scoping.
#
# No root, no Nginx binary and no network access are required: the Nginx
# binary is replaced by a controllable `nginx_run_config_test` stub, and every
# managed path points into a throwaway temp root.
#
# Usage: bash .github/test/test_relay_node.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
check() {
    local desc="$1"
    shift
    if "$@"; then ok "${desc}"; else bad "${desc}"; fi
}
check_not() {
    local desc="$1"
    shift
    if "$@"; then bad "${desc}"; else ok "${desc}"; fi
}
# Function-body assertions: `declare -f` only sees names inside this shell, so
# never wrap these in `bash -c`.
fn_has() { declare -f "$1" 2>/dev/null | grep -qF -- "$2"; }
fn_lacks() { ! fn_has "$1" "$2"; }
fn_count() { declare -f "$1" 2>/dev/null | grep -cE -- "$2"; }
file_code_has() { grep -v '^[[:space:]]*#' "$1" | grep -qF -- "$2"; }

[[ -f "${INSTALL_SH}" ]] || {
    echo "FATAL: ${INSTALL_SH} not found"
    exit 1
}

# ---- environment stubs (must exist before sourcing) -------------------
log_echo() { :; }
gettext() { printf '%s' "$1"; }
judge() { return 0; }
systemctl() { return 0; }
Error=""
RedBG=""
OK=""
GreenBG=""
Font=""
Warning=""
YellowBG=""
Green=""
Red=""
Info=""

export _TEST_MODE=1
# shellcheck source=/dev/null
source "${INSTALL_SH}" >/dev/null 2>&1 || true
unset _TEST_MODE

echo "============================================================"
echo "  Stage 02: XTLS ONLY removal + relay node role"
echo "============================================================"

# ---- redirect every managed path into the temp root -------------------
idleleo_conf_dir="${TMP_ROOT}/conf"
nginx_conf_dir="${idleleo_conf_dir}/nginx"
relay_stream_conf="${nginx_conf_dir}/relay-stream.conf"
nginx_conf="${nginx_conf_dir}/00-xray.conf"
nginx_ssl_conf="${nginx_conf_dir}/01-xray-80.conf"
nginx_upstream_conf="${nginx_conf_dir}/02-xray-server.conf"
nginx_main_conf="${TMP_ROOT}/nginx/conf/nginx.conf"
xray_conf="${TMP_ROOT}/xray/config.json"
xray_install_config_file="${idleleo_conf_dir}/install_config.json"
mkdir -p "${nginx_conf_dir}" "${TMP_ROOT}/nginx/conf" "${TMP_ROOT}/xray"

# `info_extraction` relies on associative arrays (`declare -gA`), which bash 3.2
# (the macOS system shell) does not support. Replace the cached reader with a
# single-key jq read of the very same file: identical `// empty` semantics, no
# bash-version dependency, so this suite runs identically on dev hosts and CI.
info_extraction() {
    jq -r --arg k "$1" '.[$k] // empty' "${xray_install_config_file}" 2>/dev/null
}
_info_cache_invalidate() { :; }
_info_cache_load() { :; }

reset_paths() {
    rm -f "${nginx_conf}" "${nginx_ssl_conf}" "${nginx_upstream_conf}" \
        "${relay_stream_conf}" "${nginx_main_conf}" "${xray_install_config_file}" \
        "${xray_conf}" "${nginx_conf_dir}/03-isolate.conf" "${nginx_conf_dir}/03-decoy.conf"
    printf 'events { worker_connections 64; }\nhttp { include mime.types; }\n' >"${nginx_main_conf}"
    rm -rf "${TMP_ROOT}/lifecycle"
    mkdir -p "${TMP_ROOT}/lifecycle"
    _info_cache_invalidate 2>/dev/null || true
}

# Controllable stand-in for the real `nginx -t` call.
NGINX_TEST_RC=0
nginx_run_config_test() { return "${NGINX_TEST_RC}"; }
nginx_diagnose() { :; }
enable_process_systemd() { return 0; }
firewall_set() { return 0; }

echo ""
echo "-- A. XTLS ONLY profile removal --"
check_not "install_xray_xtls_only() is gone" declare -F install_xray_xtls_only
check_not "install_config_xtls_only() is gone" declare -F install_config_xtls_only
check_not "config/vless_xtls.json is deleted" test -e "${REPO_DIR}/config/vless_xtls.json"
check "CLI flag --install-xtls survives only as a rejection stub" \
    test "$(grep -c -- '--install-xtls' "${INSTALL_SH}")" = "1"
check "help no longer lists the -4 flag" \
    test "$(grep -c 'echo "  -4' "${INSTALL_SH}")" = "0"
check "CLI flag --install-relay exists" grep -qF -- '--install-relay' "${INSTALL_SH}"
check_not "apply_install_profile has no xtls_only branch" fn_has apply_install_profile xtls_only
check_not "install wizard presets have no xtls_only branch" fn_has install_wizard_preset xtls_only
check_not "installer code still offers XTLS ONLY" \
    bash -c "grep -v '^[[:space:]]*#' '${INSTALL_SH}' | grep -qF 'XTLS ONLY'"
check "installer menu offers 中转节点" grep -qF '中转节点' "${INSTALL_SH}"
check "first-level install menu routes to menu_install_relay" fn_has menu_install menu_install_relay
check "legacy XTLS reinstall is explicitly refused" fn_has old_config_exist_check is_legacy_xtls_mode
check "legacy XTLS detection helper exists" declare -F is_legacy_xtls_mode

# Stale notes/scripts that still pass the removed flag must get an explicit
# answer (and a non-zero rc) rather than silently landing in the main menu.
relay_cli_rejects_legacy_flag() {
    local rc=0
    list -4 >/dev/null 2>&1 || rc=$?
    [[ ${rc} -eq 1 ]]
}
check "stale -4 CLI flag is rejected" relay_cli_rejects_legacy_flag

relay_cli_dispatches_relay() {
    install_nginx_relay() { [[ "${node_role}" == "relay" && "${tls_mode}" == "None" ]]; }
    list --install-relay
    local rc=$?
    unset -f install_nginx_relay
    return ${rc}
}
check "--install-relay dispatches the relay role" relay_cli_dispatches_relay

echo ""
echo "-- A2. general XTLS/Vision and Reality capability preserved --"
check "Vision flow xtls-rprx-vision is still referenced" grep -qF 'xtls-rprx-vision' "${INSTALL_SH}"
check "Reality installer is untouched" declare -F install_xray_reality
check "Reality Nginx front-end is untouched" declare -F nginx_reality_conf_add
check "Reality settings builder is untouched" grep -qF 'realitySettings' "${INSTALL_SH}"
check_not "no XTLS ONLY reference survives in README" grep -qF 'XTLS ONLY' "${REPO_DIR}/README.md"

echo ""
echo "-- B1. relay role detection --"
node_role="node"
check_not "default role is not relay" is_relay_role
node_role="relay"
check "relay role is detected" is_relay_role
legacy_xtls_only="on"
check "legacy XTLS installs are detected" is_legacy_xtls_mode
legacy_xtls_only="off"
check_not "normal node installs are not flagged as legacy XTLS" is_legacy_xtls_mode
node_role="node"

echo ""
echo "-- B2. backend host validation --"
for host in 203.0.113.10 10.0.0.1 2001:db8::1 ::1 relay.example.com a-b.example.com; do
    relay_backend_host="${host}"
    check "accepts backend host ${host}" relay_is_valid_host "${host}"
done
for host in "" "443" "1.2.3.4; rm -rf /" "evil host" "evil}" 'evil"' "a..b" "-bad-" \
    "$(printf 'a%.0s' $(seq 1 254))"; do
    check_not "rejects backend host '${host:0:24}'" relay_is_valid_host "${host}"
done

echo ""
echo "-- B3. input validation --"
validate_case() {
    local host="$1" bport="$2" lport="$3" laddr="$4" expect="$5"
    relay_backend_host="${host}"
    relay_backend_port="${bport}"
    relay_listen_port="${lport}"
    relay_listen_addr="${laddr}"
    if relay_validate_inputs >/dev/null 2>&1; then
        [[ "${expect}" == "ok" ]]
    else
        [[ "${expect}" == "reject" ]]
    fi
}
check "valid IPv4 target accepted" validate_case 203.0.113.10 443 443 0.0.0.0 ok
check "valid IPv6 target accepted" validate_case 2001:db8::1 443 8443 :: ok
check "valid DNS target accepted" validate_case relay.example.com 443 443 0.0.0.0 ok
check "backend port 0 rejected" validate_case 203.0.113.10 0 443 0.0.0.0 reject
check "backend port 65536 rejected" validate_case 203.0.113.10 65536 443 0.0.0.0 reject
check "non-numeric backend port rejected" validate_case 203.0.113.10 abc 443 0.0.0.0 reject
check "listen port 0 rejected" validate_case 203.0.113.10 443 0 0.0.0.0 reject
check "invalid listen address rejected" validate_case 203.0.113.10 443 443 "not an ip" reject
check "empty backend host rejected" validate_case "" 443 443 0.0.0.0 reject

echo ""
echo "-- B4. stream config rendering --"
rendered=$(relay_render_stream_conf 0.0.0.0 8443 203.0.113.10 443)
check "renders the managed listen line" grep -qxF '        listen 0.0.0.0:8443;' <<<"${rendered}"
check "renders the single proxy_pass target" grep -qxF '        proxy_pass 203.0.113.10:443;' <<<"${rendered}"
check "declares exactly one stream context" test "$(grep -c '^stream {' <<<"${rendered}")" = "1"
check_not "never declares an http context" grep -q '^http' <<<"${rendered}"
check_not "does not enable PROXY protocol" grep -qi 'proxy_protocol' <<<"${rendered}"
check_not "does not terminate TLS" grep -qE 'ssl_|ssl_certificate' <<<"${rendered}"
check_not "does not reference reality" grep -qi 'reality' <<<"${rendered}"
check "keeps TCP sessions alive with keepalive" grep -qF 'proxy_socket_keepalive on;' <<<"${rendered}"

rendered6=$(relay_render_stream_conf :: 8443 2001:db8::2 443)
check "IPv6 listen address is bracketed" grep -qxF '        listen [::]:8443;' <<<"${rendered6}"
check "IPv6 backend target is bracketed" grep -qxF '        proxy_pass [2001:db8::2]:443;' <<<"${rendered6}"

echo ""
echo "-- B5. top-level include management --"
reset_paths
check "main conf accepts the managed include" nginx_relay_main_conf_prepare
check "include line is appended to the main conf" grep -qF "include ${relay_stream_conf};" "${nginx_main_conf}"
check "include is added exactly once" test "$(grep -cF "include ${relay_stream_conf};" "${nginx_main_conf}")" = "1"
nginx_relay_main_conf_prepare >/dev/null 2>&1
check "re-preparing does not duplicate the include" test "$(grep -cF "include ${relay_stream_conf};" "${nginx_main_conf}")" = "1"
check "include sits outside any http block" \
    test "$(grep -cE '^[[:space:]]*stream[[:space:]]*\{' "${nginx_main_conf}")" = "0"

reset_paths
printf 'events {}\nstream { server { listen 9000; proxy_pass 127.0.0.1:9001; } }\n' >"${nginx_main_conf}"
cp "${nginx_main_conf}" "${TMP_ROOT}/main.before"
check_not "refuses a main conf that already owns a stream block" nginx_relay_main_conf_prepare
check "refused prepare leaves the main conf untouched" \
    cmp -s "${nginx_main_conf}" "${TMP_ROOT}/main.before"

reset_paths
nginx_relay_main_conf_prepare >/dev/null 2>&1
nginx_relay_main_conf_remove >/dev/null 2>&1
check_not "include can be removed again" grep -qF "include ${relay_stream_conf};" "${nginx_main_conf}"
check_not "managed marker comment is removed too" grep -qF 'Xray_bash_onekey relay node (managed)' "${nginx_main_conf}"

echo ""
echo "-- B6. transactional apply and rollback --"
reset_paths
printf 'stream {\n    server {\n        listen 0.0.0.0:8443;\n        proxy_pass 203.0.113.10:443;\n    }\n}\n' \
    >"${TMP_ROOT}/new.conf"
NGINX_TEST_RC=0
check "apply succeeds when nginx -t passes" nginx_relay_apply_config "${TMP_ROOT}/new.conf"
check "applied content reaches the managed fragment" \
    grep -qF 'proxy_pass 203.0.113.10:443;' "${relay_stream_conf}"
cp "${relay_stream_conf}" "${TMP_ROOT}/applied.conf"

printf 'stream {\n    server {\n        listen 0.0.0.0:8443;\n        proxy_pass 198.51.100.7:443;\n    }\n}\n' \
    >"${TMP_ROOT}/bad.conf"
NGINX_TEST_RC=1
check_not "apply fails when nginx -t rejects the config" nginx_relay_apply_config "${TMP_ROOT}/bad.conf"
check "failed apply restores the previous forwarding" cmp -s "${relay_stream_conf}" "${TMP_ROOT}/applied.conf"
check_not "failed apply does not leave the rejected target behind" \
    grep -qF '198.51.100.7' "${relay_stream_conf}"

reset_paths
NGINX_TEST_RC=1
check_not "first-time apply failure is reported" nginx_relay_apply_config "${TMP_ROOT}/bad.conf"
check_not "first-time failure leaves no managed fragment" test -f "${relay_stream_conf}"
check_not "first-time failure leaves no dangling include" \
    grep -qF "include ${relay_stream_conf};" "${nginx_main_conf}"
NGINX_TEST_RC=0

echo ""
echo "-- B7. role persistence and re-detection --"
reset_paths
local_ip="203.0.113.10"
ip_version="IPv4"
network_mode="ipv4"
ipv4_address="203.0.113.10"
ipv6_address=""
shell_version="9.9.9"
nginx_build_version="2026.07.15.6961"
relay_backend_host="203.0.113.10"
relay_backend_port="443"
relay_listen_port="8443"
relay_listen_addr="0.0.0.0"
check "relay config write succeeds" relay_config_write
check "role is persisted as relay" test "$(jq -r '.role' "${xray_install_config_file}")" = "relay"
check "backend target is persisted" test "$(jq -r '.relay_backend_host' "${xray_install_config_file}")" = "203.0.113.10"
check "backend port is persisted" test "$(jq -r '.relay_backend_port' "${xray_install_config_file}")" = "443"
check "listen port is persisted" test "$(jq -r '.relay_listen_port' "${xray_install_config_file}")" = "8443"
check "listen address is persisted" test "$(jq -r '.relay_listen_addr' "${xray_install_config_file}")" = "0.0.0.0"
check "relay is recorded as enabled" test "$(jq -r '.relay_enabled' "${xray_install_config_file}")" = "on"
check "nginx build version is persisted" \
    test "$(jq -r '.nginx_build_version' "${xray_install_config_file}")" = "2026.07.15.6961"
check "relay config carries no xray_version" \
    test "$(jq -r 'has("xray_version")' "${xray_install_config_file}")" = "false"
check "relay config carries no UUID client" \
    test "$(jq -r 'has("id")' "${xray_install_config_file}")" = "false"

node_role="node"
shell_mode=""
tls_mode=""
transport_mode=""
relay_backend_host=""
relay_backend_port=""
relay_listen_port=""
relay_listen_addr=""
relay_enabled=""
port=""
_info_cache_invalidate 2>/dev/null || true
check "role is re-detected from install_config.json" relay_bootstrap_role
check "re-detected role is relay" test "${node_role}" = "relay"
check "re-detected backend host is restored" test "${relay_backend_host}" = "203.0.113.10"
check "re-detected listen port is restored" test "${relay_listen_port}" = "8443"
check "generic port mirrors the relay listen port" test "${port}" = "8443"
check "re-detected mode is not an Xray mode" test "${tls_mode}" = "None"

reset_paths
printf '{"shell_mode": "Reality", "tls": "Reality", "port": 443}\n' >"${xray_install_config_file}"
_info_cache_invalidate 2>/dev/null || true
node_role="node"
check_not "node config is not treated as relay" relay_bootstrap_role
check "node role stays node" test "${node_role}" = "node"

echo ""
echo "-- B8. preflight refusal (no mixing with a managed node) --"
reset_paths
check "clean host passes preflight" relay_preflight

reset_paths
printf '{"shell_mode": "Reality", "tls": "Reality"}\n' >"${xray_install_config_file}"
printf 'server { listen 443 ssl; }\n' >"${nginx_conf}"
printf '{"inbounds": []}\n' >"${xray_conf}"
_info_cache_invalidate 2>/dev/null || true
check_not "existing node install is refused" relay_preflight

reset_paths
printf 'server { listen 443 ssl; }\n' >"${nginx_conf}"
check_not "managed nginx site is refused" relay_preflight

reset_paths
printf '{"inbounds": []}\n' >"${xray_conf}"
check_not "pre-existing Xray config is refused" relay_preflight

reset_paths
printf '{"role": "relay", "relay_backend_host": "203.0.113.10", "relay_backend_port": 443, "relay_listen_port": 8443, "relay_listen_addr": "0.0.0.0", "relay_enabled": "on"}\n' \
    >"${xray_install_config_file}"
_info_cache_invalidate 2>/dev/null || true
check "reconfiguring the relay itself is allowed" relay_preflight

echo ""
echo "-- B9. relay path never touches Xray --"
check "install_nginx_relay does not install Xray" \
    test "$(declare -f install_nginx_relay | grep -cE 'install_xray_|UUID_set|xray_install\b')" = "0"
check "install_nginx_relay never writes an Xray config" \
    test "$(declare -f install_nginx_relay | grep -cF 'xray_conf')" = "0"
relay_funcs=$(declare -F | awk '{print $3}' | grep -E '^(relay_|nginx_relay_|install_nginx_relay$|_relay_)')
check "relay function family was found" test -n "${relay_funcs}"
leaks=0
while IFS= read -r fn; do
    [[ -n "${fn}" ]] || continue
    if declare -f "${fn}" | grep -qE 'install_xray_only|install_xray_ws|install_xray_reality|install_xray_ws_tls|UUID_set'; then
        echo "    leak: ${fn}"
        leaks=$((leaks + 1))
    fi
done <<<"${relay_funcs}"
check "no relay function calls Xray installation or UUID generation" test "${leaks}" = "0"
check "judge_mode hydrates the relay role" fn_has judge_mode _relay_state_load
check "uninstall branches to relay_uninstall" fn_has uninstall_all relay_uninstall
check "nginx update branches to nginx_update_relay" fn_has nginx_update nginx_update_relay
check "main menu branches to menu_relay_main" fn_has menu menu_relay_main
check "show/status branches to relay output" fn_has basic_information relay_basic_information
check "offline root mutations bootstrap the relay role" \
    fn_has dispatch_offline_root_mutation_command relay_bootstrap_role
check "relay menu exposes no Rill/Xray-agent entry" \
    test "$(fn_count menu_relay_main 'rill')" = "0"
check "relay menu exposes no UUID/user management" \
    test "$(fn_count menu_relay_main 'add_user|remove_user|show_user')" = "0"
check "client-side guidance states keys stay unchanged" \
    fn_has relay_basic_information 'REALITY 公钥/SNI/ShortId'
check "TCP reachability is not sold as a REALITY handshake" \
    fn_has relay_test_backend '不代表 REALITY/TLS 握手成功'

echo ""
echo "============================================================"
echo "  Result: ${PASS} passed, ${FAIL} failed"
echo "============================================================"

[[ ${FAIL} -eq 0 ]] || exit 1
exit 0
