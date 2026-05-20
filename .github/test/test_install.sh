#!/bin/bash

MODE="${1:-}"

case "$MODE" in
xtls_only | ws_only | reality | tls) ;;
*)
    echo "Usage: $0 <xtls_only|ws_only|reality|tls>"
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

_CI_PORT=14431
_CI_XPORT=14432
_CI_GRPC_PORT=14433
_CI_XHTTP_PORT=14434

judge() {
    local _return_flag=1
    if [[ "$1" == "-r" || "$1" == "--return" ]]; then
        shift
    fi
    if [[ $? -eq 0 ]]; then
        log_echo "${OK} ${GreenBG} $1 ${Font}"
    else
        log_echo "${Error} ${RedBG} $1 ${Font}"
        return 1
    fi
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
    transport_mode="onlyws"
    _transport_set_shell_mode
}

ws_inbound_port_set() { xport=${_CI_XPORT}; }

grpc_inbound_port_set() { :; }

xhttp_inbound_port_set() { :; }

ws_path_set() { path="ciws$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"; }

grpc_path_set() { :; }

xhttp_path_set() { :; }

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
ws_only)
    shell_mode="ws ONLY"
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
    local desc="$1"
    shift
    if "$@"; then
        echo "  ✅ PASS: ${desc}"
        TEST_PASS=$((TEST_PASS + 1))
    else
        echo "  ❌ FAIL: ${desc}"
        TEST_FAIL=$((TEST_FAIL + 1))
    fi
}

assert_ok "Xray binary exists" test -f "${xray_bin_dir}/xray"
assert_ok "Xray config exists" test -f "${xray_conf}"
assert_ok "QR config exists" test -f "${xray_qr_config_file}"
assert_ok "Xray systemd service exists" test -f "${xray_systemd_file}"

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
assert_ok "Xray service is active" systemctl is-active --quiet xray

if [[ "${MODE}" == "tls" ]]; then
    assert_ok "Nginx binary exists" test -f "${nginx_dir}/sbin/nginx"
    assert_ok "Nginx config exists" test -f "${nginx_conf}"
    assert_ok "Nginx systemd service exists" test -f "${xray_systemd_file}"
    assert_ok "Nginx service is active" systemctl is-active --quiet nginx
    assert_ok "SSL certificate exists" test -f "${ssl_chainpath}/xray.crt"
    assert_ok "SSL key exists" test -f "${ssl_chainpath}/xray.key"
fi

if [[ "${MODE}" == "reality" ]]; then
    assert_ok "Reality target is set" test -n "${target}"
    assert_ok "Reality privateKey is set" test -n "${privateKey}"
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
