#!/usr/bin/env bash
# Fresh-process dual-stack runtime state hydration regression tests.
#
# A fresh process starts with empty network_mode/ipv4_address/ipv6_address
# globals (script startup). These tests prove that ensure_network_runtime_state()
# -- the defensive hydration entry wired into judge_mode / install_link_image /
# show_user / add_user -- restores dual-stack state from install_config.json, so
# IPv6 direct-IP share links survive a script exit + re-run (--show / menus).
#
# Coverage:
#   - ensure_network_runtime_state hydrates globals from a dual config
#   - in-memory state already loaded is never overwritten
#   - install_link_image emits IPv4 + IPv6 links after hydration: Reality, XTLS,
#     None ws (dual configs)
#   - an ipv4-only config never emits an IPv6 link after restart
#   - multi-user links (second user) keep dual entries after hydration
#
# Run: bash .github/test/test_dual_stack_runtime.sh
# shellcheck disable=SC2154,SC2034

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { :; }
gettext() { printf '%s' "$1"; }

# --- mocks ---------------------------------------------------------------
# log_echo_secure stays real: install_link_image redirects the block (including
# share links) into $xray_info_file, which the tests capture.
info_reality_public_key() { printf '%s' 'REALITYPUBKEY'; }
reality_client_meta() { printf '%s' ''; }
ensure_reality_public_key() { return 0; }
qrencode() { cat; }
vless_urlquote() {
    local s="$1"
    s=${s//:/%3A}
    s=${s//\//%2F}
    printf '%s' "${s}"
}
info_ws_path() { printf '%s' 'ws'; }
info_grpc_serviceName() { printf '%s' 'grpc'; }
info_xhttp_path() { printf '%s' 'xhttp'; }
format_xhttp_path() { printf '%s' "${1:-}"; }

# --- dual install config, as written by a dual install --------------------
xray_install_config_file="${TMP_ROOT}/install_config.json"

# Faithful to a fresh process: all reads come straight from install_config.json
# via jq. (Not the in-script _info_cache path, which needs bash>=4 associative
# arrays; this keeps the test deterministic on macOS bash 3.2 as well.)
info_extraction() {
    jq -r ".${1} // empty" "${xray_install_config_file}" 2>/dev/null
}

write_dual_config() {
    cat > "${xray_install_config_file}" <<'EOF'
{"network_mode":"dual","ipv4_address":"203.0.113.10","ipv6_address":"2001:db8::10","id":"test-user","host":"203.0.113.10","port":"443","serverNames":"v4.example.com","target":"www.microsoft.com","shortIds":"abcd1234","spiderx_path":"/","ws_port":"8888","grpc_port":"8888","xhttp_port":"8888"}
EOF
}

# Simulate a fresh process: config present, runtime globals empty.
fresh_start() {
    write_dual_config
    network_mode=""
    ipv4_address=""
    ipv6_address=""
}

printf '%s\n' '--- ensure_network_runtime_state: hydration ---'
fresh_start
ensure_network_runtime_state
if [[ "${network_mode}" == "dual" && "${ipv4_address}" == "203.0.113.10" && "${ipv6_address}" == "2001:db8::10" ]]; then
    ok "fresh process hydrates network_mode/ipv4_address/ipv6_address"
else
    bad "hydration failed; mode=${network_mode} v4=${ipv4_address} v6=${ipv6_address}"
fi

printf '%s\n' '--- ensure_network_runtime_state: no overwrite of in-memory state ---'
fresh_start
network_mode="ipv4"; ipv4_address="198.51.100.7"; ipv6_address=""
ensure_network_runtime_state
if [[ "${network_mode}" == "ipv4" && "${ipv4_address}" == "198.51.100.7" ]]; then
    ok "in-memory state is not overwritten by hydration"
else
    bad "state overwritten; mode=${network_mode} v4=${ipv4_address}"
fi

printf '%s\n' '--- install_link_image after fresh-process hydration ---'

# Reality dual
fresh_start
tls_mode="Reality"; reality_add_more="off"
xray_info_file="${TMP_ROOT}/reality.inf"; rm -f "${xray_info_file}"
out=$(install_link_image 2>/dev/null; cat "${xray_info_file}" 2>/dev/null)
if [[ "${out}" == *"vless://test-user@203.0.113.10:443?security=reality"* && "${out}" == *"vless://test-user@[2001:db8::10]:443?security=reality"* ]]; then
    ok "fresh Reality dual keeps IPv4 + IPv6 links after restart"
else
    bad "fresh Reality dual lost a link; out=${out}"
fi

# XTLS dual
fresh_start
tls_mode="XTLS"
xray_info_file="${TMP_ROOT}/xtls.inf"; rm -f "${xray_info_file}"
out=$(install_link_image 2>/dev/null; cat "${xray_info_file}" 2>/dev/null)
if [[ "${out}" == *"vless://test-user@203.0.113.10:443?security=none"* && "${out}" == *"vless://test-user@[2001:db8::10]:443?security=none"* ]]; then
    ok "fresh XTLS dual keeps IPv4 + IPv6 links after restart"
else
    bad "fresh XTLS dual lost a link; out=${out}"
fi

# None ws dual (transport_mode drives is_ws_mode through the real helper)
fresh_start
tls_mode="None"; transport_mode="ws"
xray_info_file="${TMP_ROOT}/none.inf"; rm -f "${xray_info_file}"
out=$(install_link_image 2>/dev/null; cat "${xray_info_file}" 2>/dev/null)
if [[ "${out}" == *"vless://test-user@203.0.113.10:8888?path"* && "${out}" == *"vless://test-user@[2001:db8::10]:8888?path"* ]]; then
    ok "fresh None ws dual keeps IPv4 + IPv6 links after restart"
else
    bad "fresh None ws dual lost a link; out=${out}"
fi

# ipv4-only config -> no IPv6 link after restart
cat > "${xray_install_config_file}" <<'EOF'
{"network_mode":"ipv4","ipv4_address":"203.0.113.10","ipv6_address":"","id":"test-user","host":"203.0.113.10","port":"443","serverNames":"v4.example.com","target":"www.microsoft.com","shortIds":"abcd1234","spiderx_path":"/","ws_port":"8888","grpc_port":"8888","xhttp_port":"8888"}
EOF
info_extraction_all=$(jq -rc . "${xray_install_config_file}")
network_mode=""; ipv4_address=""; ipv6_address=""
tls_mode="Reality"; reality_add_more="off"
xray_info_file="${TMP_ROOT}/v4only.inf"; rm -f "${xray_info_file}"
out=$(install_link_image 2>/dev/null; cat "${xray_info_file}" 2>/dev/null)
if [[ "${out}" != *"@[2001:db8::10]:"* ]]; then
    ok "fresh ipv4-only config emits no IPv6 link"
else
    bad "ipv4-only config unexpectedly emitted an IPv6 link"
fi

printf '%s\n' '--- multi-user links after hydration ---'
fresh_start
ensure_network_runtime_state
user2="22222222-2222-3222-8222-222222222222"
u2_v4=$(generate_vless_link "${user2}" "reality")
u2_v6=$(generate_vless_link "${user2}" "reality" "${ipv6_address}")
if [[ "${u2_v4}" == *"@203.0.113.10:"* && "${u2_v6}" == *"${user2}@"* && "${u2_v6}" == *"@[2001:db8::10]:"* ]]; then
    ok "multi-user Reality link survives hydration with IPv6 entry"
else
    bad "multi-user Reality link broken after hydration; v6=${u2_v6}"
fi
u2_v4=$(generate_vless_link "${user2}" "xtls")
u2_v6=$(generate_vless_link "${user2}" "xtls" "${ipv6_address}")
if [[ "${u2_v4}" == *"@203.0.113.10:"* && "${u2_v6}" == *"@[2001:db8::10]:"* ]]; then
    ok "multi-user XTLS link survives hydration with IPv6 entry"
else
    bad "multi-user XTLS link broken after hydration; v6=${u2_v6}"
fi

echo
if [[ ${FAIL} -eq 0 ]]; then
    printf 'ALL dual-stack runtime tests PASSED (%d)\n' "${PASS}"
else
    printf 'dual-stack runtime tests FAILED: %d pass, %d fail\n' "${PASS}" "${FAIL}"
    exit 1
fi
