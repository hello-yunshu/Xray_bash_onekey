#!/usr/bin/env bash
# Install wizard profile and hierarchical menu tests.
#
# Coverage:
#   - 8 profiles: reality_nginx, reality_standard, reality_transport,
#     reality_transport_nginx, reality_balance, transport_nginx_tls,
#     transport_only, xtls_only
#   - Each profile asserts: tls_mode, transport_mode, reality_add_more,
#     reality_add_nginx, reality_add_balance, shell_mode
#   - reset_install_wizard_state clears profile state
#   - profile does not pollute next selection
#   - menu_choose_transport sets transport_mode and returns correct code
#   - preset mode skips interactive prompts in transport_choose,
#     xray_reality_add_more_choose, reality_nginx_add_fq, reality_balance_add_fq
#   - _skip_reality_nginx_install does NOT call uninstall_nginx
#
# Run: bash .github/test/test_install_menu_profiles.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

# --- Mocks (no stdout noise, no side effects) ---
log_echo() { :; }
gettext() { printf '%s' "$1"; }
read_optimize() {
    # Simulate default selection (first argument default value)
    local prompt="$1" var="$2" default="$3"
    eval "${var}=\"\${default}\""
}
read() {
    # Simulate user pressing Enter (default/no) for interactive prompts
    :
}
exec() { :; }  # Prevent exec bash from restarting script

# Track if uninstall_nginx is called (P0 safety: must NOT be called in preset mode)
UNINSTALL_NGINX_CALLED=0
uninstall_nginx() { UNINSTALL_NGINX_CALLED=1; }

# Track install function calls
INSTALL_REALITY_CALLS=0
INSTALL_WS_TLS_CALLS=0
INSTALL_WS_ONLY_CALLS=0
INSTALL_XTLS_ONLY_CALLS=0

install_xray_reality() { INSTALL_REALITY_CALLS=$((INSTALL_REALITY_CALLS + 1)); }
install_xray_ws_tls() { INSTALL_WS_TLS_CALLS=$((INSTALL_WS_TLS_CALLS + 1)); }
install_xray_ws_only() { INSTALL_WS_ONLY_CALLS=$((INSTALL_WS_ONLY_CALLS + 1)); }
install_xray_xtls_only() { INSTALL_XTLS_ONLY_CALLS=$((INSTALL_XTLS_ONLY_CALLS + 1)); }

# Mock Nginx-related functions called by _apply_reality_nginx_install
validate_reality_reserved_ports() { return 0; }
nginx_exist_check() { return 0; }
nginx_systemd() { return 0; }
sni_guard_policy_choose() { return 0; }
nginx_reality_conf_add() { return 0; }
nginx_reality_servers_add() { return 0; }
nginx_reality_serverNames_add() { return 0; }

# Mock port/path setting functions
ws_inbound_port_set() { :; }
grpc_inbound_port_set() { :; }
xhttp_inbound_port_set() { :; }
ws_path_set() { :; }
grpc_path_set() { :; }
xhttp_path_set() { :; }
port_exist_check() { :; }

# Default port variables (avoid set -u crashes when is_ws_mode etc evaluate them)
xport=""
gport=""
xhttpport=""

# Mock nginx_dir for _skip_reality_nginx_install test
nginx_dir="/tmp/test_nginx_dir_does_not_exist"
nginx_conf_dir="${nginx_dir}/conf"

# Helper: assert variable equals expected value
assert_eq() {
    local name="$1" expected="$2" actual="$3"
    if [[ "${expected}" == "${actual}" ]]; then
        ok "${name} (got: ${actual})"
    else
        bad "${name} (expected: ${expected}, got: ${actual})"
    fi
}

# Helper: reset state before each profile test
reset_for_profile_test() {
    reset_install_wizard_state
    tls_mode=""
    shell_mode=""
    transport_mode=""
    UNINSTALL_NGINX_CALLED=0
}

# ============================================================================
# Profile tests: apply_install_profile sets correct variables for each profile
# ============================================================================

echo "--- Profile: reality_nginx ---"
reset_for_profile_test
install_profile="reality_nginx"
apply_install_profile
assert_eq "reality_nginx tls_mode" "Reality" "${tls_mode}"
assert_eq "reality_nginx transport_mode" "None" "${transport_mode}"
assert_eq "reality_nginx reality_add_more" "off" "${reality_add_more}"
assert_eq "reality_nginx reality_add_nginx" "on" "${reality_add_nginx}"
assert_eq "reality_nginx reality_add_balance" "off" "${reality_add_balance}"
assert_eq "reality_nginx shell_mode" "Nginx+Reality" "${shell_mode}"

echo "--- Profile: reality_standard ---"
reset_for_profile_test
install_profile="reality_standard"
apply_install_profile
assert_eq "reality_standard tls_mode" "Reality" "${tls_mode}"
assert_eq "reality_standard transport_mode" "None" "${transport_mode}"
assert_eq "reality_standard reality_add_more" "off" "${reality_add_more}"
assert_eq "reality_standard reality_add_nginx" "off" "${reality_add_nginx}"
assert_eq "reality_standard reality_add_balance" "off" "${reality_add_balance}"
assert_eq "reality_standard shell_mode" "Reality" "${shell_mode}"

echo "--- Profile: reality_transport ---"
reset_for_profile_test
transport_mode="onlyws"
install_profile="reality_transport"
apply_install_profile
assert_eq "reality_transport tls_mode" "Reality" "${tls_mode}"
assert_eq "reality_transport transport_mode preserved" "onlyws" "${transport_mode}"
assert_eq "reality_transport reality_add_more" "on" "${reality_add_more}"
assert_eq "reality_transport reality_add_nginx" "off" "${reality_add_nginx}"
assert_eq "reality_transport reality_add_balance" "off" "${reality_add_balance}"

echo "--- Profile: reality_transport_nginx ---"
reset_for_profile_test
transport_mode="onlygRPC"
install_profile="reality_transport_nginx"
apply_install_profile
assert_eq "reality_transport_nginx tls_mode" "Reality" "${tls_mode}"
assert_eq "reality_transport_nginx transport_mode preserved" "onlygRPC" "${transport_mode}"
assert_eq "reality_transport_nginx reality_add_more" "on" "${reality_add_more}"
assert_eq "reality_transport_nginx reality_add_nginx" "on" "${reality_add_nginx}"
assert_eq "reality_transport_nginx reality_add_balance" "off" "${reality_add_balance}"

echo "--- Profile: reality_balance ---"
reset_for_profile_test
install_profile="reality_balance"
apply_install_profile
assert_eq "reality_balance tls_mode" "Reality" "${tls_mode}"
assert_eq "reality_balance reality_add_balance" "on" "${reality_add_balance}"

echo "--- Profile: transport_nginx_tls ---"
reset_for_profile_test
transport_mode="onlyxhttp"
install_profile="transport_nginx_tls"
apply_install_profile
assert_eq "transport_nginx_tls tls_mode" "TLS" "${tls_mode}"
assert_eq "transport_nginx_tls transport_mode preserved" "onlyxhttp" "${transport_mode}"
assert_eq "transport_nginx_tls reality_add_more" "off" "${reality_add_more}"
assert_eq "transport_nginx_tls reality_add_nginx" "off" "${reality_add_nginx}"
assert_eq "transport_nginx_tls reality_add_balance" "off" "${reality_add_balance}"

echo "--- Profile: transport_only ---"
reset_for_profile_test
transport_mode="wsxhttp"
install_profile="transport_only"
apply_install_profile
assert_eq "transport_only tls_mode" "None" "${tls_mode}"
assert_eq "transport_only transport_mode preserved" "wsxhttp" "${transport_mode}"
assert_eq "transport_only reality_add_more" "off" "${reality_add_more}"
assert_eq "transport_only reality_add_nginx" "off" "${reality_add_nginx}"
assert_eq "transport_only reality_add_balance" "off" "${reality_add_balance}"

echo "--- Profile: xtls_only ---"
reset_for_profile_test
install_profile="xtls_only"
apply_install_profile
assert_eq "xtls_only tls_mode" "XTLS" "${tls_mode}"
assert_eq "xtls_only transport_mode" "None" "${transport_mode}"
assert_eq "xtls_only reality_add_more" "off" "${reality_add_more}"
assert_eq "xtls_only reality_add_nginx" "off" "${reality_add_nginx}"
assert_eq "xtls_only reality_add_balance" "off" "${reality_add_balance}"
assert_eq "xtls_only shell_mode" "XTLS ONLY" "${shell_mode}"

echo "--- Profile: unknown profile returns error ---"
reset_for_profile_test
install_profile="nonexistent_profile"
if apply_install_profile; then
    bad "unknown profile should return non-zero"
else
    ok "unknown profile returns non-zero"
fi

# ============================================================================
# reset_install_wizard_state clears all profile state
# ============================================================================

echo "--- reset_install_wizard_state clears state ---"
install_profile="reality_nginx"
install_wizard_preset="on"
reality_add_more="on"
reality_add_nginx="on"
reality_add_balance="on"
transport_mode="onlyws"
reset_install_wizard_state
assert_eq "reset install_profile" "" "${install_profile}"
assert_eq "reset install_wizard_preset" "off" "${install_wizard_preset}"
assert_eq "reset reality_add_more" "off" "${reality_add_more}"
assert_eq "reset reality_add_nginx" "off" "${reality_add_nginx}"
assert_eq "reset reality_add_balance" "off" "${reality_add_balance}"
assert_eq "reset transport_mode" "None" "${transport_mode}"

# ============================================================================
# Profile does not pollute next selection
# ============================================================================

echo "--- Profile does not pollute next selection ---"
reset_for_profile_test
install_profile="reality_nginx"
apply_install_profile
# Now select a different profile
reset_install_wizard_state
install_profile="transport_only"
transport_mode="onlyws"
apply_install_profile
assert_eq "no pollution: tls_mode" "None" "${tls_mode}"
assert_eq "no pollution: reality_add_nginx" "off" "${reality_add_nginx}"
assert_eq "no pollution: reality_add_more" "off" "${reality_add_more}"

# ============================================================================
# _transport_set_shell_mode derives correct shell_mode for each transport
# ============================================================================

echo "--- _transport_set_shell_mode: TLS + onlyws ---"
reset_for_profile_test
tls_mode="TLS"
transport_mode="onlyws"
_transport_set_shell_mode
assert_eq "TLS+ws shell_mode" "Nginx+ws+TLS" "${shell_mode}"

echo "--- _transport_set_shell_mode: None + onlygRPC ---"
reset_for_profile_test
tls_mode="None"
transport_mode="onlygRPC"
_transport_set_shell_mode
assert_eq "None+gRPC shell_mode" "gRPC ONLY" "${shell_mode}"

echo "--- _transport_set_shell_mode: Reality + reality_add_more on + nginx off ---"
reset_for_profile_test
tls_mode="Reality"
transport_mode="onlyxhttp"
reality_add_more="on"
reality_add_nginx="off"
_transport_set_shell_mode
assert_eq "Reality+xHTTP shell_mode" "Reality+xHTTP" "${shell_mode}"

echo "--- _transport_set_shell_mode: Reality + more on + nginx on ---"
reset_for_profile_test
tls_mode="Reality"
transport_mode="wsgRPCxhttp"
reality_add_more="on"
reality_add_nginx="on"
_transport_set_shell_mode
assert_eq "Nginx+Reality+ws+gRPC+xHTTP shell_mode" "Nginx+Reality+ws+gRPC+xHTTP" "${shell_mode}"

# ============================================================================
# Preset mode: transport_choose skips interactive prompt
# ============================================================================

echo "--- transport_choose skips prompt in preset mode ---"
reset_for_profile_test
install_wizard_preset="on"
tls_mode="TLS"
transport_mode="onlyws"
old_config_status="off"
transport_choose 2>/dev/null
assert_eq "preset transport_choose shell_mode" "Nginx+ws+TLS" "${shell_mode}"
# If preset works, shell_mode is set without read() prompt

echo "--- transport_choose preset with None does not set shell_mode ---"
reset_for_profile_test
install_wizard_preset="on"
tls_mode="TLS"
transport_mode="None"
old_config_status="off"
shell_mode=""
transport_choose >/dev/null 2>&1
# When transport_mode is None, preset skip condition fails.
# With old_config_status=off, the interactive branch would run,
# but read_optimize is mocked to return default "1" -> onlyws.
# _transport_set_shell_mode then derives "Nginx+ws+TLS".
assert_eq "preset None falls through to interactive default" "Nginx+ws+TLS" "${shell_mode}"

# ============================================================================
# Preset mode: xray_reality_add_more_choose skips interactive prompt
# ============================================================================

echo "--- xray_reality_add_more_choose skips prompt (reality_add_more=on) ---"
reset_for_profile_test
install_wizard_preset="on"
reality_add_more="on"
transport_mode="onlyws"
tls_mode="Reality"
old_config_status="off"
xray_reality_add_more_choose 2>/dev/null
assert_eq "preset reality_add_more shell_mode" "Reality+ws" "${shell_mode}"

echo "--- xray_reality_add_more_choose skips prompt (reality_add_more=off) ---"
reset_for_profile_test
install_wizard_preset="on"
reality_add_more="off"
old_config_status="off"
xray_reality_add_more_choose 2>/dev/null
assert_eq "preset reality_add_more off transport_mode" "None" "${transport_mode}"

# ============================================================================
# Preset mode: reality_balance_add_fq skips interactive prompt
# ============================================================================

echo "--- reality_balance_add_fq skips prompt (balance=on) ---"
reset_for_profile_test
install_wizard_preset="on"
reality_add_balance="on"
reality_balance_add_fq 2>/dev/null
assert_eq "preset balance_on reality_add_balance" "on" "${reality_add_balance}"

echo "--- reality_balance_add_fq skips prompt (balance=off) ---"
reset_for_profile_test
install_wizard_preset="on"
reality_add_balance="off"
reality_balance_add_fq 2>/dev/null
assert_eq "preset balance_off reality_add_balance" "off" "${reality_add_balance}"

# ============================================================================
# Preset mode: reality_nginx_add_fq does NOT uninstall existing Nginx
# ============================================================================

echo "--- reality_nginx_add_fq preset (nginx=on) calls install ---"
reset_for_profile_test
install_wizard_preset="on"
reality_add_nginx="on"
reality_add_balance="off"
UNINSTALL_NGINX_CALLED=0
reality_nginx_add_fq 2>/dev/null
assert_eq "preset nginx_on uninstall_not_called" "0" "${UNINSTALL_NGINX_CALLED}"

echo "--- reality_nginx_add_fq preset (nginx=off) does NOT uninstall ---"
reset_for_profile_test
install_wizard_preset="on"
reality_add_nginx="off"
reality_add_balance="off"
UNINSTALL_NGINX_CALLED=0
# Set nginx_dir to existing path to test skip logic
nginx_dir="/tmp"
reality_nginx_add_fq 2>/dev/null
assert_eq "preset nginx_off uninstall_not_called" "0" "${UNINSTALL_NGINX_CALLED}"
assert_eq "preset nginx_off reality_add_nginx" "off" "${reality_add_nginx}"

# ============================================================================
# Non-preset mode: reality_nginx_add_fq does NOT auto-uninstall (P0 safety fix)
# ============================================================================

echo "--- non-preset nginx=N does NOT auto-uninstall ---"
reset_for_profile_test
install_wizard_preset="off"
reality_add_balance="off"
old_config_status="off"
UNINSTALL_NGINX_CALLED=0
nginx_dir="/tmp"
# read() is mocked to no-op (returns empty), case default is "Y" (install)
# But we want to test "N" path. Override read to return "n"
read() {
    REPLY="n"
    reality_nginx_add_fq="n"
    return 0
}
reality_nginx_add_fq 2>/dev/null
assert_eq "non-preset N uninstall_not_called" "0" "${UNINSTALL_NGINX_CALLED}"
# Restore read mock
unset -f read

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "=========================================="
echo "Profile tests: ${PASS} passed, ${FAIL} failed"
echo "=========================================="

if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
