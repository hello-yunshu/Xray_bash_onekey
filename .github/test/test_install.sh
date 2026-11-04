#!/bin/bash
# color-test-fixture: ANSI stripping in assertions is intentional test tooling.

MODE="${1:-}"

case "$MODE" in
relay | ws_grpc_xhttp | reality | reality_nginx | tls) ;;
*)
    echo "Usage: $0 <relay|ws_grpc_xhttp|reality|reality_nginx|tls>"
    exit 1
    ;;
esac

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
_TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${REPO_DIR}"

# Source unified redaction helpers (prevents secret leakage in CI)
# shellcheck source=redact.sh
source "${_TEST_DIR}/redact.sh"

echo "============================================"
echo "  Testing installation mode: ${MODE}"
echo "============================================"

mkdir -p /etc/idleleo/tmp /etc/idleleo/logs /etc/idleleo/info /etc/idleleo/conf /etc/idleleo/scripts
cp -f "${REPO_DIR}/install.sh" /etc/idleleo/install.sh
ln -sf /etc/idleleo/install.sh /usr/bin/idleleo

for sub in fail2ban_manager.sh traffic_blocker.sh file_manager.sh auto_update.sh ssl_update.sh geo_update.sh; do
    if [[ -f "${REPO_DIR}/scripts/${sub}" ]]; then
        cp -f "${REPO_DIR}/scripts/${sub}" "/etc/idleleo/scripts/${sub}"
    fi
done

if [[ -f "${REPO_DIR}/docker/docker-entrypoint.sh" ]]; then
    cp -f "${REPO_DIR}/docker/docker-entrypoint.sh" "/etc/idleleo/docker-entrypoint.sh"
fi

if [[ -d "${REPO_DIR}/i18n/languages" ]]; then
    mkdir -p /etc/idleleo/languages
    cp -rf "${REPO_DIR}/i18n/languages/"* /etc/idleleo/languages/ 2>/dev/null || true
fi

export _TEST_MODE=1
source ./install.sh

init_language
read_version

echo ""
echo "--- Pre-flight checks: verifying install.sh functions ---"

REQUIRED_INSTALL_FUNCS=(
    install_nginx_relay
    install_xray_ws_only
    install_xray_reality
    install_xray_ws_tls
)

MOCK_FUNCS=(
    port_set
    email_set
    UUID_set
    ip_check
    domain_check
    ssl_judge_and_install
    firewall_set
    show_information
    keys_set
    transport_choose
    ws_inbound_port_set
    grpc_inbound_port_set
    xhttp_inbound_port_set
    ws_path_set
    grpc_path_set
    xhttp_path_set
    target_set
    serverNames_set
    shortIds_set
    xray_reality_add_more_choose
    reality_balance_add_fq
    reality_nginx_add_fq
    tls_type
    old_config_exist_check
    relay_wizard
    vless_link_image_choice
    auto_update
    acme_cron_update
    setup_auto_clean_logs
)

PRECHECK_FAIL=0

for func in "${REQUIRED_INSTALL_FUNCS[@]}"; do
    if ! declare -f "$func" >/dev/null 2>&1; then
        echo "  ❌ Required install function '$func' not found in install.sh"
        PRECHECK_FAIL=$((PRECHECK_FAIL + 1))
    fi
done

for func in "${MOCK_FUNCS[@]}"; do
    if ! declare -f "$func" >/dev/null 2>&1; then
        echo "  ⚠️  Mock target '$func' not found in install.sh (may have been renamed)"
        PRECHECK_FAIL=$((PRECHECK_FAIL + 1))
    fi
done

if [[ ${PRECHECK_FAIL} -gt 0 ]]; then
    echo ""
    echo "❌ Pre-flight check failed (${PRECHECK_FAIL} issue(s))."
    echo "   install.sh may have changed function names without updating this test."
    exit 1
fi
echo "  ✅ All required functions and mock targets verified"

_CI_PORT=14431
_CI_XPORT=14432
_CI_GRPC_PORT=14433
_CI_XHTTP_PORT=14434
# Relay mode: Nginx Stream listens here and transparently forwards to a local
# TCP backend, so the CI run proves a real byte-level pass-through instead of
# only asserting that a config file exists.
_CI_RELAY_LISTEN_PORT=14435
_CI_RELAY_BACKEND_PORT=14436
_CI_RELAY_BACKEND_PID=""

judge() {
    local ret=$?
    if [[ "$1" == "-r" || "$1" == "--return" ]]; then
        shift
    fi
    local desc="$1"
    if [[ $# -gt 1 ]]; then
        "${@:2}"
        ret=$?
    fi
    if [[ $ret -eq 0 ]]; then
        log_echo "${OK} ${GreenBG} ${desc} $(gettext "完成") ${Font}"
    else
        log_echo "${Error} ${RedBG} ${desc} $(gettext "失败") ${Font}"
        return 1
    fi
    return $ret
}

port_set() { port=${_CI_PORT}; }

email_set() { custom_email="ci$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')@hey.run"; }

UUID_set() {
    UUID5_char="ci_$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    UUID="$(UUIDv5_tranc "${UUID5_char}")"
}

firewall_set() { :; }

auto_update() { :; }

acme_cron_update() { :; }

setup_auto_clean_logs() { :; }

vless_link_image_choice() { :; }

show_information() { :; }

old_config_exist_check() { :; }

ip_check() {
    local_ip=$(curl -s4 --connect-timeout 5 https://ifconfig.me 2>/dev/null || curl -s4 --connect-timeout 5 https://api.ipify.org 2>/dev/null || echo "127.0.0.1")
    ip_version="IPv4"
    echo "  [CI] ip_check: local_ip=${local_ip}, ip_version=${ip_version}"
}

transport_choose() {
    if [[ "${MODE}" == "ws_grpc_xhttp" ]]; then
        transport_mode="wsgRPCxhttp"
    else
        transport_mode="onlyws"
    fi
    _transport_set_shell_mode
}

ws_inbound_port_set() { xport=${_CI_XPORT}; }

grpc_inbound_port_set() {
    if is_grpc_mode; then
        gport=${_CI_GRPC_PORT}
    fi
}

xhttp_inbound_port_set() {
    if is_xhttp_mode; then
        xhttpport=${_CI_XHTTP_PORT}
    fi
}

ws_path_set() { path="ciws$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"; }

grpc_path_set() {
    if is_grpc_mode; then
        serviceName="cigrpc$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
}

xhttp_path_set() {
    if is_xhttp_mode; then
        xhttppath="cixhttp$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
}

target_set() { target="www.microsoft.com"; }

serverNames_set() { serverNames="www.microsoft.com"; }

keys_set() {
    local keys
    keys=$(${xray_bin_dir}/xray x25519 2>/dev/null | tr '\n' ' ')
    privateKey=$(echo "${keys}" | awk -F"PrivateKey: " '{print $2}' | awk '{print $1}')
    if echo "${keys}" | grep -q "Password (PublicKey): "; then
        password=$(echo "${keys}" | sed 's/.*Password (PublicKey): //' | awk '{print $1}')
    elif echo "${keys}" | grep -q "Password: "; then
        password=$(echo "${keys}" | awk -F"Password: " '{print $2}' | awk '{print $1}')
    elif echo "${keys}" | grep -q "PublicKey: "; then
        password=$(echo "${keys}" | awk -F"PublicKey: " '{print $2}' | awk '{print $1}')
    fi
    echo "  [CI] keys_set: privateKey=<redacted length=${#privateKey}>, password=<redacted length=${#password}>"
}

shortIds_set() {
    shortIds=$(openssl rand -hex 8)
    echo "  [CI] shortIds_set: shortIds=<redacted length=${#shortIds}>"
}

xray_reality_add_more_choose() {
    reality_add_more="off"
    transport_mode="None"
    xport="None"
    gport="None"
    xhttpport="None"
    path="None"
    serviceName="None"
    xhttppath="None"
}

reality_balance_add_fq() { reality_add_balance="off"; }

reality_nginx_add_fq() {
    if [[ "${MODE}" != "reality_nginx" ]]; then
        reality_add_nginx="off"
        return 0
    fi

    reality_add_nginx="on"
    reality_nginx_sni_guard="on"
    unknown_sni_policy="isolate"
    decoy_domain=""
    nginx_exist_check || return 1
    nginx_systemd || return 1
    nginx_reality_conf_add || return 1
    nginx_reality_servers_add || return 1
    nginx_reality_serverNames_add || return 1
}

domain_check() {
    domain="ci-test.example.com"
    local_ip="127.0.0.1"
    ip_version="IPv4"
    echo "  [CI] domain_check: domain=${domain}, local_ip=${local_ip}"
}

ssl_judge_and_install() {
    mkdir -p "${ssl_chainpath}"
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "${ssl_chainpath}/xray.key" \
        -out "${ssl_chainpath}/xray.crt" \
        -days 365 -subj "/CN=${domain}" 2>/dev/null
    # Root owns, worker group can read but NOT write.
    # Use non-recursive chown consistent with apply_nginx_layered_permissions() in install.sh.
    getent group idleleo-nginx >/dev/null 2>&1 || return 1
    chown -f "root:idleleo-nginx" "${ssl_chainpath}" || return 1
    chown -f "root:idleleo-nginx" "${ssl_chainpath}/xray.crt" "${ssl_chainpath}/xray.key" || return 1
    chmod -f 750 "${ssl_chainpath}" || return 1
    chmod -f 640 "${ssl_chainpath}/xray.crt" "${ssl_chainpath}/xray.key" || return 1
    echo "  [CI] ssl_judge_and_install: self-signed cert created for ${domain}"
}

tls_type() {
    if [[ -f "${nginx_conf}" ]]; then
        sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.3;/" "${nginx_conf}" 2>/dev/null || true
    fi
    if [[ -f "${nginx_systemd_file}" ]]; then
        systemctl restart nginx 2>/dev/null || true
    fi
    systemctl restart xray 2>/dev/null || true
    echo "  [CI] tls_type: set TLSv1.3 only"
}

# Relay wizard: answer the three relay questions without a TTY. The backend is a
# local TCP listener so the post-install probe proves real forwarding.
relay_wizard() {
    relay_backend_host="127.0.0.1"
    relay_backend_port="${_CI_RELAY_BACKEND_PORT}"
    relay_listen_port="${_CI_RELAY_LISTEN_PORT}"
    relay_listen_addr="0.0.0.0"
    echo "  [CI] relay_wizard: ${relay_listen_addr}:${relay_listen_port} -> ${relay_backend_host}:${relay_backend_port}"
}

# Local TCP backend used by relay mode. Plain HTTP keeps the check dependency
# free (no nc/socat required) and still exercises byte-level pass-through.
start_relay_backend() {
    local backend_root=/tmp/relay-ci-backend
    mkdir -p "${backend_root}"
    printf 'relay-ci-backend-ok\n' >"${backend_root}/index.html"
    (
        cd "${backend_root}" || exit 1
        exec python3 -m http.server "${_CI_RELAY_BACKEND_PORT}" --bind 127.0.0.1
    ) >/dev/null 2>&1 &
    _CI_RELAY_BACKEND_PID=$!
    wait_for_port "${_CI_RELAY_BACKEND_PORT}" 20 0.25
}

stop_relay_backend() {
    [[ -n "${_CI_RELAY_BACKEND_PID}" ]] || return 0
    kill "${_CI_RELAY_BACKEND_PID}" >/dev/null 2>&1 || true
    wait "${_CI_RELAY_BACKEND_PID}" 2>/dev/null || true
    _CI_RELAY_BACKEND_PID=""
}

port_is_listening() {
    local listen_port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltnH | awk -v port=":${listen_port}" '$4 ~ port "$" { found=1 } END { exit !found }'
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn | awk -v port=":${listen_port}" '$4 ~ port "$" { found=1 } END { exit !found }'
    elif command -v nc >/dev/null 2>&1; then
        nc -z -w 1 127.0.0.1 "${listen_port}" >/dev/null 2>&1
    else
        return 1
    fi
}

wait_for_port() {
    local listen_port="$1"
    local attempts="${2:-20}"
    local delay="${3:-0.25}"
    local i
    for ((i = 1; i <= attempts; i++)); do
        if port_is_listening "${listen_port}"; then
            return 0
        fi
        sleep "${delay}"
    done
    return 1
}

echo ""
echo "--- Starting installation for mode: ${MODE} ---"
INSTALL_EXIT_CODE=0
case "$MODE" in
relay)
    node_role="relay"
    shell_mode="Relay"
    tls_mode="None"
    transport_mode="None"
    start_relay_backend || echo "  [CI] WARN: relay TCP backend did not start"
    install_nginx_relay || INSTALL_EXIT_CODE=$?
    ;;
ws_grpc_xhttp)
    shell_mode="ws+gRPC+xHTTP ONLY"
    tls_mode="None"
    install_xray_ws_only || INSTALL_EXIT_CODE=$?
    ;;
reality | reality_nginx)
    shell_mode="Reality"
    tls_mode="Reality"
    install_xray_reality || INSTALL_EXIT_CODE=$?
    ;;
tls)
    shell_mode="Nginx+ws+TLS"
    tls_mode="TLS"
    install_xray_ws_tls || INSTALL_EXIT_CODE=$?
    ;;
esac

echo ""
echo "--- Installation for mode: ${MODE} exited with code: ${INSTALL_EXIT_CODE} ---"
echo ""

echo "=== Running post-install tests ==="

TEST_PASS=0
TEST_FAIL=0

assert_ok() {
    local diag_cmd=""
    if [[ "$1" == "--diag" ]]; then
        diag_cmd="$2"
        shift 2
    fi
    local desc="$1"
    shift
    if "$@"; then
        echo "  ✅ PASS: ${desc}"
        TEST_PASS=$((TEST_PASS + 1))
    else
        echo "  ❌ FAIL: ${desc}"
        TEST_FAIL=$((TEST_FAIL + 1))
        if [[ -n "${diag_cmd}" ]]; then
            echo "  ℹ️  Diagnostic:"
            eval "${diag_cmd}" 2>&1 | sed 's/^/     /'
        fi
    fi
}

qr_value() {
    jq -r --arg field "$1" '.[$field]' "${xray_install_config_file}"
}

config_value() {
    local tag="$1"
    local filter="$2"
    jq -r --arg tag "${tag}" ".inbounds[] | select(.tag == \$tag) | ${filter}" "${xray_conf}"
}

http_probe_has_status() {
    local url="$1"
    local status
    status=$(curl -ksS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 "${url}" 2>/dev/null || true)
    [[ ${status} =~ ^[1-5][0-9][0-9]$ ]]
}

https_probe_has_status() {
    local host="$1"
    local port="$2"
    local path="$3"
    local status
    status=$(curl -ksS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 \
        --resolve "${host}:${port}:127.0.0.1" "https://${host}:${port}/${path#/}" 2>/dev/null || true)
    [[ ${status} =~ ^[1-5][0-9][0-9]$ ]]
}

relay_probe_hits_backend() {
    local entry_port body
    entry_port=$(qr_value relay_listen_port)
    [[ -n "${entry_port}" && "${entry_port}" != "null" ]] || return 1
    body=$(curl -ksS --connect-timeout 3 --max-time 8 \
        "http://127.0.0.1:${entry_port}/index.html" 2>/dev/null) || return 1
    printf '%s' "${body}" | grep -q 'relay-ci-backend-ok'
}

assert_qr_matches_config() {
    local desc="$1"
    local qr_field="$2"
    local tag="$3"
    local config_filter="$4"
    assert_ok "${desc}" test "$(qr_value "${qr_field}")" = "$(config_value "${tag}" "${config_filter}")"
}

assert_ok "Install command exited successfully" test "${INSTALL_EXIT_CODE}" -eq 0
assert_ok --diag "ls -la \"${xray_install_config_file}\" 2>/dev/null; echo; redact_json_for_diagnostics \"${xray_install_config_file}\" 2>&1 | head -20" "Install config exists" test -f "${xray_install_config_file}"

if [[ "${MODE}" != "relay" ]]; then
    assert_ok --diag "ls -la ${xray_bin_dir}/xray 2>/dev/null; echo; file ${xray_bin_dir}/xray 2>/dev/null" "Xray binary exists" test -f "${xray_bin_dir}/xray"
    assert_ok --diag "ls -la \"${xray_conf}\" 2>/dev/null; echo; redact_json_for_diagnostics \"${xray_conf}\" 2>&1 | head -20" "Xray config exists" test -f "${xray_conf}"
    assert_ok --diag "cat ${xray_systemd_file} 2>/dev/null" "Xray systemd service exists" test -f "${xray_systemd_file}"
fi

echo ""
echo "--- Native GeoData checks ---"
if [[ "${MODE}" == "relay" ]]; then
    assert_ok "Relay installs no GeoData asset directory" \
        test ! -e "${idleleo_dir}/share/xray/geoip.dat"
else
    assert_ok --diag "jq -c '.geodata' \"${xray_conf}\" 2>/dev/null; echo; ls -la ${idleleo_dir}/share/xray 2>/dev/null" \
        "Config carries the native geodata schedule" \
        jq -e '.geodata.cron and (.geodata.assets | length == 2)' "${xray_conf}"
    assert_ok "Both geodata assets are HTTPS" \
        test "$(jq -r '[.geodata.assets[].url | startswith("https://")] | all' "${xray_conf}")" = "true"
    # `install -m 644` from the official installer must be answered by the
    # geodata permission step, otherwise the scheduled download cannot write.
    assert_ok --diag "ls -la ${idleleo_dir}/share/xray; echo; grep -h '^User' ${xray_systemd_file}" \
        "GeoData files are owned by the Xray service account" \
        test "$(stat -c '%U' "${idleleo_dir}/share/xray/geoip.dat")" = "$(sed -n 's/^[[:space:]]*User[[:space:]]*=[[:space:]]*//p' "${xray_systemd_file}" | tail -1)"
    assert_ok "GeoData files are group-writable for the service account" \
        test "$(stat -c '%a' "${idleleo_dir}/share/xray/geoip.dat")" = "660"
    assert_ok "The legacy external updater was not scheduled" \
        bash -c "! crontab -l 2>/dev/null | grep -q geo_update.sh"
fi

echo ""
echo "--- REALITY client-version compatibility ---"
case "${MODE}" in
reality | reality_nginx)
    # Xray 26.7.11 defaults an unset minClientVer to 26.3.27, which rejects
    # clients that still report an older build (upstream XTLS/Xray-core#6482).
    assert_ok --diag "jq -c '[.inbounds[] | select(.streamSettings.security == \"reality\") | .streamSettings.realitySettings]' \"${xray_conf}\" 2>/dev/null" \
        "REALITY inbound sets an explicit minClientVer" \
        test "$(jq -r '[.inbounds[] | select(.streamSettings.security == "reality") | .streamSettings.realitySettings.minClientVer] | unique | join(",")' "${xray_conf}")" = "1.0.0"
    ;;
*)
    echo "  ⏭️  SKIP: no REALITY inbound in this mode"
    ;;
esac

echo ""
echo "--- Xray config validation ---"
if [[ "${MODE}" == "relay" ]]; then
    echo "  ⏭️  SKIP: relay nodes never install Xray"
else
    if ${xray_bin_dir}/xray run -test -config "${xray_conf}" 2>&1; then
        echo "  ✅ PASS: Xray config is valid"
        TEST_PASS=$((TEST_PASS + 1))
    else
        echo "  ❌ FAIL: Xray config validation failed"
        TEST_FAIL=$((TEST_FAIL + 1))
    fi
fi

echo ""
echo "--- Service status checks ---"
if [[ "${MODE}" == "relay" ]]; then
    assert_ok --diag "systemctl status nginx 2>&1 | redact_text_for_diagnostics | head -15; echo; journalctl -u nginx --no-pager -n 10 2>&1 | redact_text_for_diagnostics" "Nginx service is active" systemctl is-active --quiet nginx
    assert_ok "Relay does not install the Xray systemd unit" test ! -f "${xray_systemd_file}"
    assert_ok "Relay does not install an Xray binary" test ! -f "${xray_bin_dir}/xray"
else
    assert_ok --diag "systemctl status xray 2>&1 | redact_text_for_diagnostics | head -15; echo; journalctl -u xray --no-pager -n 10 2>&1 | redact_text_for_diagnostics" "Xray service is active" systemctl is-active --quiet xray
fi

echo ""
echo "--- Listener checks ---"
case "${MODE}" in
relay)
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status nginx 2>&1 | head -10; echo; cat ${relay_stream_conf} 2>/dev/null" "Relay entry port is listening" wait_for_port "$(qr_value relay_listen_port)"
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20" "Relay TCP backend is listening" wait_for_port "${_CI_RELAY_BACKEND_PORT}"
    ;;
reality)
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status xray 2>&1 | head -10" "Main Xray port is listening" wait_for_port "$(qr_value port)"
    ;;
reality_nginx)
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status nginx 2>&1 | head -10" "Nginx Reality public port is listening" wait_for_port "$(qr_value port)"
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status xray 2>&1 | head -10" "Xray Reality backend port is listening" wait_for_port "$(config_value VLESS-Reality-in '.port')"
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status nginx 2>&1 | head -10" "SNI Guard isolate port is listening" wait_for_port 9403
    ;;
ws_grpc_xhttp)
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status xray 2>&1 | head -10" "ws inbound port is listening" wait_for_port "$(qr_value ws_port)"
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status xray 2>&1 | head -10" "gRPC inbound port is listening" wait_for_port "$(qr_value grpc_port)"
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status xray 2>&1 | head -10" "xHTTP inbound port is listening" wait_for_port "$(qr_value xhttp_port)"
    ;;
tls)
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status nginx 2>&1 | head -10" "Nginx public TLS port is listening" wait_for_port "$(qr_value port)"
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status xray 2>&1 | head -10" "Xray ws backend port is listening" wait_for_port "$(qr_value ws_port)"
    ;;
esac

echo ""
echo "--- Local HTTP probe checks ---"
case "${MODE}" in
relay)
    # Real byte-level pass-through: HTTP through the relay entry must reach the
    # local backend and return the backend body unchanged.
    assert_ok --diag "curl -ksS -o /tmp/relay-probe.body -w '%{http_code}' --connect-timeout 3 --max-time 8 http://127.0.0.1:$(qr_value relay_listen_port)/index.html 2>&1; echo; cat /tmp/relay-probe.body 2>/dev/null; echo; ss -ltnH 2>/dev/null | head -10; echo; tail -5 ${nginx_dir}/logs/error.log 2>/dev/null" \
        "Relay forwards TCP traffic to the backend" relay_probe_hits_backend
    ;;
ws_grpc_xhttp)
    assert_ok --diag "curl -ksS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 http://127.0.0.1:$(qr_value ws_port)/$(qr_value path) 2>&1; echo; ss -ltnH 2>/dev/null | head -10; echo; ps aux | grep -E '[x]ray' | head -5" "ws path returns an HTTP status" http_probe_has_status "http://127.0.0.1:$(qr_value ws_port)/$(qr_value path)"
    assert_ok --diag "curl -ksS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 http://127.0.0.1:$(qr_value xhttp_port)/$(qr_value xhttp_path) 2>&1; echo; ss -ltnH 2>/dev/null | head -10; echo; ps aux | grep -E '[x]ray' | head -5" "xHTTP path returns an HTTP status" http_probe_has_status "http://127.0.0.1:$(qr_value xhttp_port)/$(qr_value xhttp_path)"
    ;;
tls)
    assert_ok --diag "curl -ksS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 --resolve '$(qr_value host):$(qr_value port):127.0.0.1' 'https://$(qr_value host):$(qr_value port)/$(qr_value path)' 2>&1; echo; ss -ltnH 2>/dev/null | head -10; echo; ps aux | grep -E '[n]ginx' | head -5; echo; tail -5 /usr/local/nginx/logs/error.log 2>/dev/null | redact_text_for_diagnostics" "Nginx ws path returns an HTTPS status" https_probe_has_status "$(qr_value host)" "$(qr_value port)" "$(qr_value path)"
    ;;
esac

if [[ "${MODE}" == "tls" || "${MODE}" == "reality_nginx" || "${MODE}" == "relay" ]]; then
    assert_ok --diag "ls -la ${nginx_dir}/sbin/nginx 2>/dev/null; echo; file ${nginx_dir}/sbin/nginx 2>/dev/null; echo; ldd ${nginx_dir}/sbin/nginx 2>/dev/null" "Nginx binary exists" test -f "${nginx_dir}/sbin/nginx"
    if [[ "${MODE}" == "relay" ]]; then
        # A relay node owns the managed stream fragment only; it never gets a
        # server-block site config, so assert on the file it is supposed to own.
        assert_ok --diag "ls -la ${relay_stream_conf} 2>/dev/null; echo; cat ${relay_stream_conf} 2>/dev/null | redact_text_for_diagnostics | head -30" "Relay stream config exists" test -f "${relay_stream_conf}"
    else
        assert_ok --diag "ls -la ${nginx_conf} 2>/dev/null; echo; cat ${nginx_conf} 2>/dev/null | redact_text_for_diagnostics | head -30" "Nginx config exists" test -f "${nginx_conf}"
    fi
    assert_ok --diag "cat ${nginx_systemd_file} 2>/dev/null" "Nginx systemd service exists" test -f "${nginx_systemd_file}"
    assert_ok --diag "systemctl status nginx 2>&1 | redact_text_for_diagnostics | head -15; echo; journalctl -u nginx --no-pager -n 10 2>&1 | redact_text_for_diagnostics; echo; ps aux | grep -E '[n]ginx' | head -5" "Nginx service is active" systemctl is-active --quiet nginx
    assert_ok --diag "${nginx_dir}/sbin/nginx -t -c ${nginx_dir}/conf/nginx.conf 2>&1" "Nginx config is valid" "${nginx_dir}/sbin/nginx" -t -c "${nginx_dir}/conf/nginx.conf"
    assert_ok --diag "find ${nginx_dir} ${nginx_conf_dir} ${ssl_chainpath} -maxdepth 2 -printf '%M %u:%g %p\\n' 2>/dev/null | head -80" \
        "Nginx layered permissions pass the production verifier" verify_nginx_layered_permissions
fi

if [[ "${MODE}" == "tls" ]]; then
    assert_ok --diag "ls -la ${ssl_chainpath}/ 2>/dev/null; echo; openssl x509 -noout -subject -dates -in ${ssl_chainpath}/xray.crt 2>/dev/null" "SSL certificate exists" test -f "${ssl_chainpath}/xray.crt"
    assert_ok "SSL key exists" test -f "${ssl_chainpath}/xray.key"
fi

if [[ "${MODE}" == "reality" || "${MODE}" == "reality_nginx" ]]; then
    assert_ok "Reality target is set" test -n "${target}"
    assert_ok "Reality privateKey is set" test -n "${privateKey}"
    assert_ok "Reality publicKey is stored" test -n "$(qr_value publicKey)"
    assert_ok "Reality publicKey keeps legacy password compatibility" test "$(qr_value publicKey)" = "$(qr_value password)"
    assert_ok "Reality guard port 9403 is reserved" is_reality_reserved_port 9403
    assert_ok "Reality guard port 9404 is reserved" is_reality_reserved_port 9404
    assert_ok "Reality guard port 9443 is reserved" is_reality_reserved_port 9443
    assert_ok "Reality guard port 9444 is reserved" is_reality_reserved_port 9444
fi

echo ""
echo "--- QR/config consistency checks ---"
if [[ "${MODE}" == "relay" ]]; then
    echo "  ⏭️  SKIP: relay nodes have no UUID/QR payload"
else
    assert_ok "QR UUID matches Xray clients" jq -e --arg id "$(qr_value id)" '[.inbounds[].settings.clients[]?.id] as $ids | ($ids | length > 0) and ($ids | all(. == $id))' "${xray_conf}"
fi
case "${MODE}" in
relay)
    assert_ok "Relay role is recorded" test "$(qr_value role)" = "relay"
    assert_ok "Relay install config has no UUID" test "$(qr_value id)" = "null"
    assert_ok "Relay install config has no Xray version" test "$(qr_value xray_version)" = "null"
    assert_ok "Relay target matches the generated stream config" \
        grep -Fq "proxy_pass $(qr_value relay_backend_host):$(qr_value relay_backend_port);" "${relay_stream_conf}"
    assert_ok "Relay listen port matches the generated stream config" \
        grep -Fq "listen $(qr_value relay_listen_addr):$(qr_value relay_listen_port);" "${relay_stream_conf}"
    assert_ok "Nginx main config includes the managed stream fragment" \
        grep -qF "include ${relay_stream_conf};" "${nginx_main_conf}"
    assert_ok "Managed stream fragment stays a top-level include" \
        test "$(grep -cE '^[[:space:]]*stream[[:space:]]*\{' "${nginx_main_conf}")" = "0"
    assert_ok "Relay uses plain TCP pass-through without PROXY protocol" \
        test "$(grep -c 'proxy_protocol' "${relay_stream_conf}")" = "0"
    assert_ok "Relay does not terminate TLS" \
        test "$(grep -cE 'ssl_|reality' "${relay_stream_conf}")" = "0"
    ;;
reality)
    assert_qr_matches_config "Reality port matches config" port "VLESS-Reality-in" ".port"
    assert_qr_matches_config "Reality privateKey matches config" privateKey "VLESS-Reality-in" ".streamSettings.realitySettings.privateKey"
    assert_ok "Reality shortId is in config" jq -e --arg short_id "$(qr_value shortIds)" '.inbounds[] | select(.tag == "VLESS-Reality-in") | .streamSettings.realitySettings.shortIds | index($short_id)' "${xray_conf}"
    ;;
reality_nginx)
    assert_ok "Reality public port differs from protected backend" test "$(qr_value port)" != "$(config_value VLESS-Reality-in '.port')"
    assert_ok "Reality protected backend uses reserved port 9443" test "$(config_value VLESS-Reality-in '.port')" = "9443"
    assert_qr_matches_config "Reality privateKey matches config" privateKey "VLESS-Reality-in" ".streamSettings.realitySettings.privateKey"
    assert_ok "Reality shortId is in config" jq -e --arg short_id "$(qr_value shortIds)" '.inbounds[] | select(.tag == "VLESS-Reality-in") | .streamSettings.realitySettings.shortIds | index($short_id)' "${xray_conf}"
    assert_ok "SNI Guard defaults to isolate" test "$(qr_value unknown_sni_policy)" = "isolate"
    assert_ok "SNI Guard is enabled" test "$(qr_value reality_nginx_sni_guard)" = "on"
    assert_ok "Unknown SNI maps to deny" grep -Fq "default deny;" "${nginx_conf}"
    assert_ok "Deny upstream uses isolate listener" grep -Fq "server 127.0.0.1:9403;" "${nginx_conf}"
    assert_ok "Isolate listener config exists" test -f "${nginx_conf_dir}/03-isolate.conf"
    assert_ok "Isolate listener rejects TLS handshakes" grep -Fq "ssl_reject_handshake on;" "${nginx_conf_dir}/03-isolate.conf"
    ;;
ws_grpc_xhttp)
    assert_qr_matches_config "ws port matches config" ws_port "VLESS-ws-in" ".port"
    assert_qr_matches_config "ws path matches config" path "VLESS-ws-in" ".streamSettings.wsSettings.path | ltrimstr(\"/\")"
    assert_qr_matches_config "gRPC port matches config" grpc_port "VLESS-gRPC-in" ".port"
    assert_qr_matches_config "gRPC serviceName matches config" serviceName "VLESS-gRPC-in" ".streamSettings.grpcSettings.serviceName"
    assert_qr_matches_config "xHTTP port matches config" xhttp_port "VLESS-xhttp-in" ".port"
    assert_qr_matches_config "xHTTP path matches config" xhttp_path "VLESS-xhttp-in" ".streamSettings.xhttpSettings.path | ltrimstr(\"/\")"
    ;;
tls)
    assert_qr_matches_config "TLS ws backend port matches config" ws_port "VLESS-ws-in" ".port"
    assert_qr_matches_config "TLS ws path matches config" path "VLESS-ws-in" ".streamSettings.wsSettings.path | ltrimstr(\"/\")"
    ;;
esac

json_update_preserves_private_mode() {
    chmod 600 "${xray_install_config_file}" || return 1
    update_json_config "${xray_install_config_file}" '.ci_permission_probe = true' || return 1
    [[ "$(stat -c '%a' "${xray_install_config_file}")" == "600" ]] || return 1
    update_json_config "${xray_install_config_file}" 'del(.ci_permission_probe)' || return 1
    [[ "$(stat -c '%a' "${xray_install_config_file}")" == "600" ]]
}

reality_upgrade_defaults_are_safe() {
    local private_key_before inode_before inode_after
    private_key_before=$(qr_value privateKey)
    update_json_config "${xray_install_config_file}" \
        'del(.reality_nginx_sni_guard, .unknown_sni_policy, .decoy_domain)' || return 1
    ensure_reality_sni_guard_defaults || return 1
    [[ "$(qr_value privateKey)" == "${private_key_before}" ]] || return 1
    [[ "$(qr_value reality_nginx_sni_guard)" == "on" ]] || return 1
    [[ "$(qr_value unknown_sni_policy)" == "isolate" ]] || return 1
    [[ "$(qr_value decoy_domain)" == "" ]] || return 1
    inode_before=$(stat -c '%i' "${xray_install_config_file}") || return 1
    ensure_reality_sni_guard_defaults || return 1
    inode_after=$(stat -c '%i' "${xray_install_config_file}") || return 1
    [[ "${inode_before}" == "${inode_after}" ]]
}

relay_role_roundtrip() {
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
    relay_bootstrap_role || return 1
    [[ "${node_role}" == "relay" ]] || return 1
    [[ "${shell_mode}" == "$(gettext "中转节点")" ]] || return 1
    [[ -n "${relay_backend_host}" && -n "${relay_backend_port}" ]] || return 1
    [[ -n "${relay_listen_port}" ]] || return 1
    [[ "${port}" == "${relay_listen_port}" ]] || return 1
    is_relay_role
}

menu_box_layout_is_aligned() (
    local columns expected rendered plain line width
    for columns in 50 60 72 100 160; do
        export COLUMNS="${columns}"
        expected=$((columns - 4))
        ((expected > 60)) && expected=60
        ((expected < 52)) && expected=$((columns - 2))
        ((expected < 20)) && expected=20

        rendered="$(
            menu_title "$(gettext "主菜单") · idleleo"
            menu_divider "$(gettext "版本检测")"
            menu_fields "$(gettext "当前模式"): Nginx+ws+xHTTP+TLS" "$(gettext "当前语言"): C.UTF-8"
            menu_fields "$(gettext "脚本"): ${Green}[$(gettext "最新版")]${Font}" "Xray: ${Green}[$(gettext "最新版")]${Font}" "Nginx: ${Green}[$(gettext "最新版")]${Font}"
            menu_item 1 "Reality + Nginx"
            menu_blank
            menu_item 0 "$(gettext "返回")"
            menu_footer
        )"
        plain=$(printf '%s\n' "${rendered}" | sed $'s/\033\\[[0-9;]*m//g')
        while IFS= read -r line; do
            case "${line}" in
            ╭* | ├* | │* | ╰*)
                width=$(printf '%s' "${line}" | LC_ALL=C.UTF-8 wc -L | tr -d ' ')
                [[ "${width}" == "${expected}" ]] || return 1
                ;;
            esac
        done <<<"${plain}"
    done
)

menu_header_spacing_matches_density() (
    local columns rendered plain row_pattern
    for columns in 50 60 72 100; do
        export COLUMNS="${columns}"
        rendered="$(
            menu_prepare_width
            menu_spaced_fields \
                "$(gettext "当前模式"): Nginx+ws+xHTTP+TLS" \
                "$(gettext "当前语言"): C.UTF-8"
        )"
        plain=$(printf '%s\n' "${rendered}" | sed $'s/\033\\[[0-9;]*m//g')
        row_pattern=$(printf '%s\n' "${plain}" | awk '
            /^│[[:space:]]*│$/ { printf "B"; next }
            /^│/ { printf "D" }
        ')
        [[ ${row_pattern} =~ ^BD+B$ ]] || return 1

        rendered="$(
            menu_prepare_width
            menu_fields \
                "$(gettext "脚本"): [$(gettext "最新版")]" \
                "Xray: [$(gettext "最新版")]" \
                "Nginx: [$(gettext "最新版")]" \
                "$(gettext "AI 判断: 未安装")" \
                "$(gettext "服务: 未运行")" \
                "$(gettext "路由辅助: 关闭")"
        )"
        plain=$(printf '%s\n' "${rendered}" | sed $'s/\033\\[[0-9;]*m//g')
        row_pattern=$(printf '%s\n' "${plain}" | awk '
            /^│[[:space:]]*│$/ { printf "B"; next }
            /^│/ { printf "D" }
        ')
        [[ ${row_pattern} =~ ^D+$ ]] || return 1
    done
)

assert_ok "Install config is private" test "$(stat -c '%a' "${xray_install_config_file}")" = "600"
if [[ "${MODE}" != "relay" ]]; then
    assert_ok "Xray config is private" test "$(stat -c '%a' "${xray_conf}")" = "600"
fi
assert_ok "JSON updates preserve private mode" json_update_preserves_private_mode
assert_ok "Menu box layout stays aligned" menu_box_layout_is_aligned
assert_ok "Only the first header row keeps vertical breathing room" menu_header_spacing_matches_density
if [[ "${MODE}" == "reality" || "${MODE}" == "reality_nginx" ]]; then
    assert_ok "Reality upgrade defaults preserve existing config" reality_upgrade_defaults_are_safe
fi

if [[ "${MODE}" == "relay" ]]; then
    assert_ok "Relay stream config is private to root and the worker group" \
        test "$(stat -c '%a' "${relay_stream_conf}")" = "640"
    # Role must survive a fresh-process config load, so `idleleo` re-entry never
    # falls back to the Xray node code path on a relay host.
    assert_ok "Relay role is re-detected from install_config.json" relay_role_roundtrip
fi

if [[ "${MODE}" == "reality_nginx" ]]; then
    unknown_sni_policy="decoy"
    decoy_domain="missing-ci-decoy.example.com"
    rm -f "${ssl_chainpath}/decoy.key" "${ssl_chainpath}/decoy.crt" "${idleleo_dir}/decoy/index.html"
    assert_ok "Missing decoy artifacts fall back safely" nginx_reality_conf_add
    assert_ok "Missing decoy fallback selects isolate" test "${unknown_sni_policy}" = "isolate"
    assert_ok "Missing decoy fallback does not target 9444" grep -Fq "server 127.0.0.1:9403;" "${nginx_conf}"
    assert_ok "Nginx remains valid after decoy fallback" "${nginx_dir}/sbin/nginx" -t -c "${nginx_dir}/conf/nginx.conf"
fi

if [[ "${MODE}" == "ws_grpc_xhttp" ]]; then
    assert_ok "Install config transport mode is wsgRPCxhttp" test "$(jq -r '.transport_mode' "${xray_install_config_file}")" = "wsgRPCxhttp"
    assert_ok "gRPC inbound exists" jq -e '.inbounds[] | select(.tag == "VLESS-gRPC-in")' "${xray_conf}"
    assert_ok "xHTTP inbound exists" jq -e '.inbounds[] | select(.tag == "VLESS-xhttp-in")' "${xray_conf}"
    assert_ok "All transport inbounds are routed" jq -e '[.routing.rules[].inboundTag[]] | contains(["VLESS-ws-in", "VLESS-gRPC-in", "VLESS-xhttp-in"])' "${xray_conf}"
fi

echo ""
echo "--- Install config content check ---"
if [[ -f "${xray_install_config_file}" ]]; then
    echo "  shell_mode: $(jq -r '.shell_mode' "${xray_install_config_file}")"
    echo "  role: $(jq -r '.role // "node"' "${xray_install_config_file}")"
    echo "  tls_mode: $(jq -r '.tls' "${xray_install_config_file}")"
    echo "  transport_mode: $(jq -r '.transport_mode' "${xray_install_config_file}")"
    echo "  port: $(jq -r '.port' "${xray_install_config_file}")"
    if [[ "${MODE}" == "relay" ]]; then
        echo "  relay_target: $(jq -r '.relay_backend_host' "${xray_install_config_file}"):$(jq -r '.relay_backend_port' "${xray_install_config_file}")"
        echo "  relay_listen: $(jq -r '.relay_listen_addr' "${xray_install_config_file}"):$(jq -r '.relay_listen_port' "${xray_install_config_file}")"
        echo "  relay_enabled: $(jq -r '.relay_enabled' "${xray_install_config_file}")"
    else
        echo "  xray_version: $(jq -r '.xray_version' "${xray_install_config_file}")"
    fi
fi

echo ""
echo "============================================"
echo "  Test Results for mode: ${MODE}"
echo "  Passed: ${TEST_PASS}"
echo "  Failed: ${TEST_FAIL}"
echo "============================================"

if [[ ${TEST_FAIL} -gt 0 ]]; then
    if [[ "${MODE}" == "relay" ]]; then
        echo ""
        echo "--- Debug: Nginx service status (redacted) ---"
        systemctl status nginx 2>&1 | redact_text_for_diagnostics || true
        echo ""
        echo "--- Debug: relay stream config ---"
        cat "${relay_stream_conf}" 2>/dev/null || echo "(not found)"
        echo ""
        echo "--- Debug: Nginx error log (redacted) ---"
        tail -20 "${nginx_dir}/logs/error.log" 2>/dev/null | redact_text_for_diagnostics || echo "(no error log)"
    else
        echo ""
        echo "--- Debug: Xray service status (redacted) ---"
        systemctl status xray 2>&1 | redact_text_for_diagnostics || true
        echo ""
        echo "--- Debug: Xray error log (last 20 lines, redacted) ---"
        tail -20 /var/log/xray/error.log 2>/dev/null | redact_text_for_diagnostics || echo "(no error log)"
    fi
    if [[ "${MODE}" == "tls" || "${MODE}" == "reality_nginx" ]]; then
        echo ""
        echo "--- Debug: Nginx service status (redacted) ---"
        systemctl status nginx 2>&1 | redact_text_for_diagnostics || true
    fi
    stop_relay_backend
    exit 1
fi

stop_relay_backend

echo ""
echo "🎉 All tests passed for mode: ${MODE}"
exit 0
