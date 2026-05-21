#!/bin/bash

MODE="${1:-}"

case "$MODE" in
xtls_only | ws_grpc_xhttp | reality | tls) ;;
*)
    echo "Usage: $0 <xtls_only|ws_grpc_xhttp|reality|tls>"
    exit 1
    ;;
esac

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_DIR}"

echo "============================================"
echo "  Testing installation mode: ${MODE}"
echo "============================================"

mkdir -p /etc/idleleo/tmp /etc/idleleo/logs /etc/idleleo/info
cp -f "${REPO_DIR}/install.sh" /etc/idleleo/install.sh
ln -sf /etc/idleleo/install.sh /usr/bin/idleleo

for sub in fail2ban_manager.sh traffic_blocker.sh file_manager.sh auto_update.sh ssl_update.sh geo_update.sh docker-entrypoint.sh; do
    if [[ -f "${REPO_DIR}/${sub}" ]]; then
        cp -f "${REPO_DIR}/${sub}" "/etc/idleleo/${sub}"
    fi
done

if [[ -d "${REPO_DIR}/languages" ]]; then
    mkdir -p /etc/idleleo/languages
    cp -rf "${REPO_DIR}/languages/"* /etc/idleleo/languages/ 2>/dev/null || true
fi

export _TEST_MODE=1
source ./install.sh

init_language
read_version

echo ""
echo "--- Pre-flight checks: verifying install.sh functions ---"

REQUIRED_INSTALL_FUNCS=(
    install_xray_xtls_only
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
        transport_mode="all"
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
    echo "  [CI] keys_set: privateKey=${privateKey}, password=${password}"
}

shortIds_set() {
    shortIds=$(openssl rand -hex 8)
    echo "  [CI] shortIds_set: shortIds=${shortIds}"
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

reality_nginx_add_fq() { reality_add_nginx="off"; }

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
    chown -fR "nobody:$(id -gn nobody 2>/dev/null || echo nogroup)" "${ssl_chainpath}"/* 2>/dev/null || true
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

echo ""
echo "--- Starting installation for mode: ${MODE} ---"

INSTALL_EXIT_CODE=0
case "$MODE" in
xtls_only)
    shell_mode="XTLS ONLY"
    tls_mode="XTLS"
    install_xray_xtls_only || INSTALL_EXIT_CODE=$?
    ;;
ws_grpc_xhttp)
    shell_mode="ws+gRPC+xHTTP ONLY"
    tls_mode="None"
    install_xray_ws_only || INSTALL_EXIT_CODE=$?
    ;;
reality)
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

port_is_listening() {
    local listen_port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltnH | awk -v port=":${listen_port}" '$4 ~ port "$" { found=1 } END { exit !found }'
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn | awk -v port=":${listen_port}" '$4 ~ port "$" { found=1 } END { exit !found }'
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

qr_value() {
    jq -r --arg field "$1" '.[$field]' "${xray_qr_config_file}"
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

assert_qr_matches_config() {
    local desc="$1"
    local qr_field="$2"
    local tag="$3"
    local config_filter="$4"
    assert_ok "${desc}" test "$(qr_value "${qr_field}")" = "$(config_value "${tag}" "${config_filter}")"
}

assert_ok "Install command exited successfully" test "${INSTALL_EXIT_CODE}" -eq 0
assert_ok --diag "ls -la ${xray_bin_dir}/xray 2>/dev/null; echo; file ${xray_bin_dir}/xray 2>/dev/null" "Xray binary exists" test -f "${xray_bin_dir}/xray"
assert_ok --diag "ls -la ${xray_conf} 2>/dev/null; echo; jq . "${xray_conf}" 2>&1 | head -20" "Xray config exists" test -f "${xray_conf}"
assert_ok --diag "ls -la ${xray_qr_config_file} 2>/dev/null; echo; jq . "${xray_qr_config_file}" 2>&1 | head -20" "QR config exists" test -f "${xray_qr_config_file}"
assert_ok --diag "cat ${xray_systemd_file} 2>/dev/null" "Xray systemd service exists" test -f "${xray_systemd_file}"

echo ""
echo "--- Xray config validation ---"
if ${xray_bin_dir}/xray run -test -config "${xray_conf}" 2>&1; then
    echo "  ✅ PASS: Xray config is valid"
    TEST_PASS=$((TEST_PASS + 1))
else
    echo "  ❌ FAIL: Xray config validation failed"
    TEST_FAIL=$((TEST_FAIL + 1))
fi

echo ""
echo "--- Service status checks ---"
assert_ok --diag "systemctl status xray 2>&1 | head -15; echo; journalctl -u xray --no-pager -n 10 2>&1" "Xray service is active" systemctl is-active --quiet xray

echo ""
echo "--- Listener checks ---"
case "${MODE}" in
xtls_only | reality)
    assert_ok --diag "ss -ltnH 2>/dev/null | head -20; echo; systemctl status xray 2>&1 | head -10" "Main Xray port is listening" wait_for_port "$(qr_value port)"
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
ws_grpc_xhttp)
    assert_ok --diag "curl -ksS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 http://127.0.0.1:$(qr_value ws_port)/$(qr_value path) 2>&1; echo; ss -ltnH 2>/dev/null | head -10; echo; ps aux | grep -E '[x]ray' | head -5" "ws path returns an HTTP status" http_probe_has_status "http://127.0.0.1:$(qr_value ws_port)/$(qr_value path)"
    assert_ok --diag "curl -ksS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 http://127.0.0.1:$(qr_value xhttp_port)/$(qr_value xhttp_path) 2>&1; echo; ss -ltnH 2>/dev/null | head -10; echo; ps aux | grep -E '[x]ray' | head -5" "xHTTP path returns an HTTP status" http_probe_has_status "http://127.0.0.1:$(qr_value xhttp_port)/$(qr_value xhttp_path)"
    ;;
tls)
    assert_ok --diag "curl -ksS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 --resolve '$(qr_value host):$(qr_value port):127.0.0.1' 'https://$(qr_value host):$(qr_value port)/$(qr_value path)' 2>&1; echo; ss -ltnH 2>/dev/null | head -10; echo; ps aux | grep -E '[n]ginx' | head -5; echo; tail -5 /usr/local/nginx/logs/error.log 2>/dev/null" "Nginx ws path returns an HTTPS status" https_probe_has_status "$(qr_value host)" "$(qr_value port)" "$(qr_value path)"
    ;;
esac

if [[ "${MODE}" == "tls" ]]; then
    assert_ok --diag "ls -la ${nginx_dir}/sbin/nginx 2>/dev/null; echo; file ${nginx_dir}/sbin/nginx 2>/dev/null; echo; ldd ${nginx_dir}/sbin/nginx 2>/dev/null" "Nginx binary exists" test -f "${nginx_dir}/sbin/nginx"
    assert_ok --diag "ls -la ${nginx_conf} 2>/dev/null; echo; cat ${nginx_conf} 2>/dev/null | head -30" "Nginx config exists" test -f "${nginx_conf}"
    assert_ok --diag "cat ${nginx_systemd_file} 2>/dev/null" "Nginx systemd service exists" test -f "${nginx_systemd_file}"
    assert_ok --diag "systemctl status nginx 2>&1 | head -15; echo; journalctl -u nginx --no-pager -n 10 2>&1; echo; ps aux | grep -E '[n]ginx' | head -5" "Nginx service is active" systemctl is-active --quiet nginx
    assert_ok --diag "ls -la ${ssl_chainpath}/ 2>/dev/null; echo; openssl x509 -noout -subject -dates -in ${ssl_chainpath}/xray.crt 2>/dev/null" "SSL certificate exists" test -f "${ssl_chainpath}/xray.crt"
    assert_ok "SSL key exists" test -f "${ssl_chainpath}/xray.key"
fi

if [[ "${MODE}" == "reality" ]]; then
    assert_ok "Reality target is set" test -n "${target}"
    assert_ok "Reality privateKey is set" test -n "${privateKey}"
fi

echo ""
echo "--- QR/config consistency checks ---"
assert_ok "QR UUID matches Xray clients" jq -e --arg id "$(qr_value id)" '[.inbounds[].settings.clients[]?.id] as $ids | ($ids | length > 0) and ($ids | all(. == $id))' "${xray_conf}"
case "${MODE}" in
xtls_only)
    assert_qr_matches_config "XTLS port matches config" port "VLESS-XTLS-in" ".port"
    ;;
reality)
    assert_qr_matches_config "Reality port matches config" port "VLESS-Reality-in" ".port"
    assert_qr_matches_config "Reality privateKey matches config" privateKey "VLESS-Reality-in" ".streamSettings.realitySettings.privateKey"
    assert_ok "Reality shortId is in config" jq -e --arg short_id "$(qr_value shortIds)" '.inbounds[] | select(.tag == "VLESS-Reality-in") | .streamSettings.realitySettings.shortIds | index($short_id)' "${xray_conf}"
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

if [[ "${MODE}" == "ws_grpc_xhttp" ]]; then
    assert_ok "QR transport mode is all" test "$(jq -r '.transport_mode' "${xray_qr_config_file}")" = "all"
    assert_ok "gRPC inbound exists" jq -e '.inbounds[] | select(.tag == "VLESS-gRPC-in")' "${xray_conf}"
    assert_ok "xHTTP inbound exists" jq -e '.inbounds[] | select(.tag == "VLESS-xhttp-in")' "${xray_conf}"
    assert_ok "All transport inbounds are routed" jq -e '[.routing.rules[].inboundTag[]] | contains(["VLESS-ws-in", "VLESS-gRPC-in", "VLESS-xhttp-in"])' "${xray_conf}"
fi

echo ""
echo "--- QR config content check ---"
if [[ -f "${xray_qr_config_file}" ]]; then
    echo "  shell_mode: $(jq -r '.shell_mode' "${xray_qr_config_file}")"
    echo "  tls_mode: $(jq -r '.tls' "${xray_qr_config_file}")"
    echo "  transport_mode: $(jq -r '.transport_mode' "${xray_qr_config_file}")"
    echo "  port: $(jq -r '.port' "${xray_qr_config_file}")"
    echo "  xray_version: $(jq -r '.xray_version' "${xray_qr_config_file}")"
fi

echo ""
echo "============================================"
echo "  Test Results for mode: ${MODE}"
echo "  Passed: ${TEST_PASS}"
echo "  Failed: ${TEST_FAIL}"
echo "============================================"

if [[ ${TEST_FAIL} -gt 0 ]]; then
    echo ""
    echo "--- Debug: Xray service status ---"
    systemctl status xray 2>&1 || true
    echo ""
    echo "--- Debug: Xray error log (last 20 lines) ---"
    tail -20 /var/log/xray/error.log 2>/dev/null || echo "(no error log)"
    if [[ "${MODE}" == "tls" ]]; then
        echo ""
        echo "--- Debug: Nginx service status ---"
        systemctl status nginx 2>&1 || true
    fi
    exit 1
fi

echo ""
echo "🎉 All tests passed for mode: ${MODE}"
exit 0
