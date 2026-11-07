#!/bin/bash
# Regression: the generated xhttp Nginx location must carry an ACTIVE
# `client_max_body_size 0;`. Template defect introduced in 335f4d8c left it
# commented, so Nginx fell back to its 1m default and stream-one request
# bodies above ~1MB failed with 413 while the ws location stayed healthy.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_DIR}" || exit 1

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

# Keep sourcing side-effect free: no log file, no real Nginx tree.
log_file=/dev/null
LOG_FILE=/dev/null
export _TEST_MODE=1
# shellcheck source=/dev/null
source ./install.sh

PASS=0
FAIL=0
ok() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}
bad() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

# Inputs nginx_conf_add() reads: TLS with ws + xhttp enabled.
nginx_conf="${TMP_DIR}/00-xray.conf"
nginx_conf_dir="${TMP_DIR}"
nginx_dir="${TMP_DIR}/nginx"
idleleo_dir="/tmp/idleleo-nginx-template-test"
tls_mode="TLS"
transport_mode="TLS_ws_xhttp"
domain="example.com"
path="ws-path"
serviceName="grpc-svc"
xhttppath="xhttp-path"
save_originconf="Yes"
port=443
reality_add_nginx="off"
old_config_status="on"

nginx_conf_add

block_of() {
    awk -v loc="location $1" '
        index($0, loc) && $0 ~ "^[[:space:]]*location" { f = 1 }
        f { print }
        f && /^[[:space:]]*}/ { exit }
    ' "${nginx_conf}"
}

xhttp_block=$(block_of "/xhttp-path")
ws_block=$(block_of "/ws-path")

[[ -n "${xhttp_block}" ]] && ok "generated xhttp location exists" || bad "generated xhttp location missing"
[[ -n "${ws_block}" ]] && ok "generated ws location exists" || bad "generated ws location missing"

if grep -qE '^[[:space:]]*client_max_body_size[[:space:]]+0;' <<<"${xhttp_block}"; then
    ok "xhttp location has an active client_max_body_size 0"
else
    bad "xhttp location has no active client_max_body_size 0"
fi

if grep -qE '^[[:space:]]*#[[:space:]]*client_max_body_size' <<<"${xhttp_block}"; then
    bad "xhttp location still contains a commented client_max_body_size"
else
    ok "xhttp location has no commented client_max_body_size"
fi

if grep -qE '^[[:space:]]*grpc_pass[[:space:]]+grpc://xray-xhttp-server;' <<<"${xhttp_block}"; then
    ok "xhttp location proxies with grpc_pass"
else
    bad "xhttp location is not using grpc_pass"
fi

# proxy_buffering is an ngx_http_proxy_module directive. Leaving it active next
# to grpc_pass would be config that looks aligned but does nothing.
if grep -qE '^[[:space:]]*proxy_buffering[[:space:]]+off;' <<<"${xhttp_block}"; then
    bad "xhttp location has an active proxy_buffering that grpc_pass ignores"
else
    ok "xhttp location has no ineffective active proxy_buffering"
fi

if grep -qE '^[[:space:]]*client_max_body_size[[:space:]]+0;' <<<"${ws_block}"; then
    ok "ws location keeps the active client_max_body_size 0"
else
    bad "ws location lost its active client_max_body_size 0"
fi

echo "  Result: ${PASS} passed, ${FAIL} failed"
[[ ${FAIL} -eq 0 ]]
