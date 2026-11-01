#!/usr/bin/env bash
#
# Stage 01 regression tests: new ws/gRPC/xHTTP ONLY ("None" TLS mode) installs
# must not bind the VLESS plaintext inbounds to 0.0.0.0 by default, while
# existing installations keep the listen address already written in config.json.
#
# Usage: bash .github/test/test_ws_only_listen_address.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

[[ -f "${INSTALL_SH}" ]] || { echo "FATAL: ${INSTALL_SH} not found"; exit 1; }

log_echo() { :; }
gettext() { printf '%s' "$1"; }
judge() { return 0; }
Error=""; RedBG=""; OK=""; GreenBG=""; Font=""; Warning=""; YellowBG=""; Green=""; Red=""

export _TEST_MODE=1
# shellcheck source=/dev/null
source "${INSTALL_SH}" >/dev/null 2>&1 || true
unset _TEST_MODE

for fn in is_valid_listen_address resolve_ws_backend_listen_addr modify_listen_address; do
    if ! declare -F "${fn}" >/dev/null 2>&1; then
        echo "FATAL: ${fn}() not defined after sourcing install.sh"
        exit 1
    fi
done

# GNU stat (used by the real update_json_config) is unavailable on macOS dev
# hosts; apply the same jq filter in place instead.
update_json_config() {
    local config_file="$1" tmp_file
    shift
    [[ -f "${config_file}" ]] || return 1
    tmp_file=$(mktemp)
    if ! jq "$@" "${config_file}" >"${tmp_file}" 2>/dev/null; then
        rm -f "${tmp_file}"
        return 1
    fi
    mv "${tmp_file}" "${config_file}"
}

write_config() {
    local file="$1" listen="$2"
    cat >"${file}" <<EOF
{
  "inbounds": [
    {"tag": "VLESS-ws-in", "listen": "${listen}", "port": 10086,
     "streamSettings": {"network": "ws", "security": "none"}},
    {"tag": "VLESS-Reality-in", "listen": "0.0.0.0", "port": 443,
     "streamSettings": {"network": "raw", "security": "reality"}}
  ],
  "outbounds": [{"protocol": "freedom"}]
}
EOF
}

listen_of() {
    jq -r --arg tag "$2" 'first(.inbounds[]? | select(.tag == $tag) | .listen)' "$1"
}

echo "============================================================"
echo "  ws/gRPC/xHTTP ONLY listen-address baseline tests"
echo "============================================================"

# ---- 1. address validation ----------------------------------------
printf '  -- is_valid_listen_address --\n'
for addr in 127.0.0.1 0.0.0.0 10.0.0.2 255.255.255.255 ::1 2001:db8::1 fd00::/64 ""; do
    if [[ "${addr}" == "fd00::/64" || -z "${addr}" ]]; then
        is_valid_listen_address "${addr}" && bad "rejected malformed address '${addr}'" \
            || ok "malformed address '${addr}' is rejected"
    else
        is_valid_listen_address "${addr}" && ok "address '${addr}' is accepted" \
            || bad "address '${addr}' was rejected"
    fi
done
for addr in 256.1.1.1 1.2.3 "1.2.3.4.5" "host.example.com" "1..2.3" "1:2" "::1::2"; do
    is_valid_listen_address "${addr}" && bad "accepted invalid address '${addr}'" \
        || ok "invalid address '${addr}' is rejected"
done

# ---- 2. new None-mode install defaults to loopback -----------------
printf '  -- new install --\n'
conf="${TMP_ROOT}/config.json"
xray_conf="${conf}"
tls_mode="None"
transport_mode="onlyws"
ws_backend_listen_addr="127.0.0.1"
write_config "${conf}" "0.0.0.0"
modify_listen_address
got=$(listen_of "${conf}" VLESS-ws-in)
[[ "${got}" == "127.0.0.1" ]] && ok "new ws ONLY install listens on 127.0.0.1 (got ${got})" \
    || bad "new ws ONLY install listen address was ${got}"

# ---- 3. explicit trusted address is honoured -----------------------
ws_backend_listen_addr="10.10.0.5"
write_config "${conf}" "0.0.0.0"
modify_listen_address
got=$(listen_of "${conf}" VLESS-ws-in)
[[ "${got}" == "10.10.0.5" ]] && ok "explicit trusted address is applied (got ${got})" \
    || bad "explicit trusted address was ${got}"

# ---- 4. invalid override falls back to loopback --------------------
ws_backend_listen_addr="not-an-ip"
write_config "${conf}" "0.0.0.0"
modify_listen_address
got=$(listen_of "${conf}" VLESS-ws-in)
[[ "${got}" == "127.0.0.1" ]] && ok "invalid override falls back to 127.0.0.1 (got ${got})" \
    || bad "invalid override produced ${got}"

# ---- 5. empty override falls back to loopback ----------------------
ws_backend_listen_addr=""
write_config "${conf}" "0.0.0.0"
modify_listen_address
got=$(listen_of "${conf}" VLESS-ws-in)
[[ "${got}" == "127.0.0.1" ]] && ok "unset override falls back to 127.0.0.1 (got ${got})" \
    || bad "unset override produced ${got}"

# ---- 6. TLS mode keeps its loopback backend ------------------------
tls_mode="TLS"
transport_mode="onlyws"
ws_backend_listen_addr="10.10.0.5"
write_config "${conf}" "0.0.0.0"
modify_listen_address
got=$(listen_of "${conf}" VLESS-ws-in)
[[ "${got}" == "127.0.0.1" ]] && ok "TLS mode backend stays on 127.0.0.1 (got ${got})" \
    || bad "TLS mode backend listen address was ${got}"

# ---- 7. Realty mode is not rewritten by the new default ------------
tls_mode="Reality"
transport_mode="onlyws"
write_config "${conf}" "0.0.0.0"
modify_listen_address
got=$(listen_of "${conf}" VLESS-Reality-in)
[[ "${got}" == "0.0.0.0" ]] && ok "Reality inbound listen address is untouched (got ${got})" \
    || bad "Reality inbound listen address changed to ${got}"

# ---- 8. existing 0.0.0.0 config survives a keep-config run ---------
printf '  -- existing install --\n'
tls_mode="None"
transport_mode="onlyws"
ws_backend_listen_addr="127.0.0.1"
write_config "${conf}" "0.0.0.0"
reinstall_keep_config="on"
reinstall_operation="none"
change_port="no"
change_user="no"
change_transport="no"
change_inner_ports="no"
change_reality="no"
change_nginx_sni="no"
change_ws_path="no"
change_grpc_path="no"
change_xhttp_path="no"
xray_install_config_file="${TMP_ROOT}/install_config.json"
printf '{"shell_mode":"ws ONLY","tls":"None"}\n' >"${xray_install_config_file}"
xray_conf_add >/dev/null 2>&1
got=$(listen_of "${conf}" VLESS-ws-in)
[[ "${got}" == "0.0.0.0" ]] && ok "existing listen address is preserved by a keep-config run (got ${got})" \
    || bad "keep-config run rewrote the listen address to ${got}"

echo "============================================================"
echo "  PASS: ${PASS}  FAIL: ${FAIL}"
echo "============================================================"
[[ "${FAIL}" -eq 0 ]]
