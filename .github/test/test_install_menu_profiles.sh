#!/usr/bin/env bash
# Install wizard profile and hierarchical menu tests.
#
# Coverage:
#   - 9 profiles: reality_nginx, reality_standard, reality_transport,
#     reality_transport_nginx, reality_balance_primary,
#     reality_balance_secondary, transport_nginx_tls, transport_only,
#     xtls_only
#   - Each profile asserts: tls_mode, transport_mode, reality_add_more,
#     reality_add_nginx, reality_add_balance, reality_balance_role, shell_mode
#   - reset_install_wizard_state clears profile state (incl. reality_balance_role)
#   - profile does not pollute next selection
#   - real hierarchical menu state machine routes all 9 profiles, including
#     the fourth-level Reality balance role menu (primary/secondary/return)
#   - real menu input covers every return level, invalid input, confirmations,
#     narrow terminals, and non-TTY stdin
#   - preset mode skips interactive prompts in transport_choose,
#     xray_reality_add_more_choose, reality_nginx_add_fq, reality_balance_add_fq
#   - _skip_reality_nginx_install does NOT call uninstall_nginx
#   - balance primary triggers _apply_reality_nginx_install side effects;
#     balance secondary does NOT call nginx_reality_* config functions
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
# Track call counts so balance primary/secondary side-effect tests can assert.
NGINX_EXIST_CHECK_CALLS=0
NGINX_SYSTEMD_CALLS=0
NGINX_REALITY_CONF_ADD_CALLS=0
NGINX_REALITY_SERVERS_ADD_CALLS=0
NGINX_REALITY_SERVERNAMES_ADD_CALLS=0
validate_reality_reserved_ports() { return 0; }
nginx_exist_check() { NGINX_EXIST_CHECK_CALLS=$((NGINX_EXIST_CHECK_CALLS + 1)); return 0; }
nginx_systemd() { NGINX_SYSTEMD_CALLS=$((NGINX_SYSTEMD_CALLS + 1)); return 0; }
sni_guard_policy_choose() { return 0; }
nginx_reality_conf_add() { NGINX_REALITY_CONF_ADD_CALLS=$((NGINX_REALITY_CONF_ADD_CALLS + 1)); return 0; }
nginx_reality_servers_add() { NGINX_REALITY_SERVERS_ADD_CALLS=$((NGINX_REALITY_SERVERS_ADD_CALLS + 1)); return 0; }
nginx_reality_serverNames_add() { NGINX_REALITY_SERVERNAMES_ADD_CALLS=$((NGINX_REALITY_SERVERNAMES_ADD_CALLS + 1)); return 0; }

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
    NGINX_EXIST_CHECK_CALLS=0
    NGINX_SYSTEMD_CALLS=0
    NGINX_REALITY_CONF_ADD_CALLS=0
    NGINX_REALITY_SERVERS_ADD_CALLS=0
    NGINX_REALITY_SERVERNAMES_ADD_CALLS=0
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

echo "--- Profile: reality_balance_primary ---"
reset_for_profile_test
install_profile="reality_balance_primary"
apply_install_profile
assert_eq "reality_balance_primary tls_mode" "Reality" "${tls_mode}"
assert_eq "reality_balance_primary reality_add_balance" "on" "${reality_add_balance}"
assert_eq "reality_balance_primary reality_add_nginx" "on" "${reality_add_nginx}"
assert_eq "reality_balance_primary reality_add_more" "off" "${reality_add_more}"
assert_eq "reality_balance_primary transport_mode" "None" "${transport_mode}"
assert_eq "reality_balance_primary reality_balance_role" "primary" "${reality_balance_role}"
assert_eq "reality_balance_primary shell_mode" "Nginx+Reality+Balance" "${shell_mode}"

echo "--- Profile: reality_balance_secondary ---"
reset_for_profile_test
install_profile="reality_balance_secondary"
apply_install_profile
assert_eq "reality_balance_secondary tls_mode" "Reality" "${tls_mode}"
assert_eq "reality_balance_secondary reality_add_balance" "on" "${reality_add_balance}"
assert_eq "reality_balance_secondary reality_add_nginx" "off" "${reality_add_nginx}"
assert_eq "reality_balance_secondary reality_add_more" "off" "${reality_add_more}"
assert_eq "reality_balance_secondary transport_mode" "None" "${transport_mode}"
assert_eq "reality_balance_secondary reality_balance_role" "secondary" "${reality_balance_role}"
assert_eq "reality_balance_secondary shell_mode" "Reality+Balance" "${shell_mode}"

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
reality_balance_role="primary"
transport_mode="onlyws"
reset_install_wizard_state
assert_eq "reset install_profile" "" "${install_profile}"
assert_eq "reset install_wizard_preset" "off" "${install_wizard_preset}"
assert_eq "reset reality_add_more" "off" "${reality_add_more}"
assert_eq "reset reality_add_nginx" "off" "${reality_add_nginx}"
assert_eq "reset reality_add_balance" "off" "${reality_add_balance}"
assert_eq "reset reality_balance_role" "" "${reality_balance_role}"
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
# Balance profile side-effect tests (mock counters)
# Primary must trigger _apply_reality_nginx_install chain;
# Secondary must NOT call nginx_reality_* config functions and must NOT uninstall.
# ============================================================================

echo "--- balance primary triggers nginx reality side effects ---"
reset_for_profile_test
install_profile="reality_balance_primary"
apply_install_profile
install_wizard_preset="on"
reality_nginx_add_fq 2>/dev/null
assert_eq "primary nginx_exist_check called once" "1" "${NGINX_EXIST_CHECK_CALLS}"
assert_eq "primary nginx_systemd called once" "1" "${NGINX_SYSTEMD_CALLS}"
assert_eq "primary nginx_reality_conf_add called once" "1" "${NGINX_REALITY_CONF_ADD_CALLS}"
assert_eq "primary nginx_reality_servers_add called once" "1" "${NGINX_REALITY_SERVERS_ADD_CALLS}"
assert_eq "primary nginx_reality_serverNames_add called once" "1" "${NGINX_REALITY_SERVERNAMES_ADD_CALLS}"
assert_eq "primary uninstall_nginx not called" "0" "${UNINSTALL_NGINX_CALLED}"

echo "--- balance secondary skips nginx reality config, no uninstall ---"
reset_for_profile_test
install_profile="reality_balance_secondary"
apply_install_profile
install_wizard_preset="on"
UNINSTALL_NGINX_CALLED=0
nginx_dir="/tmp"
reality_nginx_add_fq 2>/dev/null
assert_eq "secondary nginx_exist_check not called" "0" "${NGINX_EXIST_CHECK_CALLS}"
assert_eq "secondary nginx_reality_conf_add not called" "0" "${NGINX_REALITY_CONF_ADD_CALLS}"
assert_eq "secondary nginx_reality_servers_add not called" "0" "${NGINX_REALITY_SERVERS_ADD_CALLS}"
assert_eq "secondary nginx_reality_serverNames_add not called" "0" "${NGINX_REALITY_SERVERNAMES_ADD_CALLS}"
assert_eq "secondary uninstall_nginx not called" "0" "${UNINSTALL_NGINX_CALLED}"
assert_eq "secondary reality_add_nginx stays off" "off" "${reality_add_nginx}"
assert_eq "secondary reality_balance_role" "secondary" "${reality_balance_role}"

# ============================================================================
# Balance config file round-trip test
# install_config_reality writes reality_balance_role; judge_mode reads it back.
# ============================================================================

echo "--- balance config file round-trip (primary) ---"
reset_for_profile_test
install_profile="reality_balance_primary"
apply_install_profile
# Stub dependencies used by install_config_reality / judge_mode
xray_install_config_file="$(mktemp)"
local_ip="127.0.0.1"
ip_version="4"
port=443
custom_email="test@example.com"
UUID5_char="idc123"
UUID="uuid-test"
target="www.example.com"
serverNames="www.example.com"
privateKey="priv"
password="pub"
shortIds="abc12345"
artxport=""; artgport=""; artxhttpport=""; artpath=""; artserviceName=""; artxhttppath=""
shell_version="v1"
xray_version="1.0.0"
nginx_build_version=""
_info_cache_invalidate() { :; }
update_json_config() { :; }  # nginx=on path skipped because nginx_build_version empty is fine
install_config_reality 2>/dev/null
assert_eq "config reality_add_balance written" "on" "$(jq -rc .reality_add_balance "${xray_install_config_file}")"
assert_eq "config reality_add_nginx written" "on" "$(jq -rc .reality_add_nginx "${xray_install_config_file}")"
assert_eq "config reality_balance_role written" "primary" "$(jq -rc .reality_balance_role "${xray_install_config_file}")"
assert_eq "config shell_mode written" "Nginx+Reality+Balance" "$(jq -rc .shell_mode "${xray_install_config_file}")"
# Round-trip: judge_mode reads config back into shell variables.
# Reset ALL shell-mode-relevant variables first so the test cannot pass on
# stale values left by apply_install_profile (previous false-positive root cause).
shell_mode="$(gettext "未安装")"
tls_mode="None"
transport_mode="None"
reality_add_more="off"
reality_add_nginx="off"
reality_add_balance="off"
reality_balance_role=""
info_extraction_all="$(jq -rc . "${xray_install_config_file}")"
info_extraction() { printf '%s' "${info_extraction_all}" | jq -rc --arg k "$1" '.[$k]'; }
judge_mode
assert_eq "roundtrip primary shell_mode" "Nginx+Reality+Balance" "${shell_mode}"
assert_eq "roundtrip primary reality_balance_role" "primary" "${reality_balance_role}"
assert_eq "roundtrip primary reality_add_nginx" "on" "${reality_add_nginx}"
assert_eq "roundtrip primary reality_add_balance" "on" "${reality_add_balance}"
rm -f "${xray_install_config_file}"
unset -f info_extraction update_json_config _info_cache_invalidate

# ============================================================================
# shell_mode config read-back tests (judge_mode round-trip)
#
# After script restart judge_mode must restore shell_mode for every
# non-transport install profile (transport_mode="None" in the config) and for
# the transport profiles. Each test writes a JSON config, resets ALL relevant
# shell variables to the not-installed defaults, then calls judge_mode and
# asserts the restored shell_mode.
# ============================================================================

# Helper: run judge_mode against a JSON config in the current shell.
# Resets ALL shell-mode-relevant variables to the not-installed defaults first
# so every case is a true round-trip (no stale values carried over from a
# previous test). Restored values are exposed via READBACK_* globals so callers
# can assert on shell_mode and any side-effect variable (e.g. reality_balance_role).
run_judge_mode_from_config() {
    local config_json="$1"
    xray_install_config_file="$(mktemp)"
    printf '%s' "${config_json}" > "${xray_install_config_file}"
    info_extraction_all="${config_json}"
    info_extraction() { printf '%s' "${info_extraction_all}" | jq -rc --arg k "$1" '.[$k]'; }
    shell_mode="$(gettext "未安装")"
    tls_mode="None"
    transport_mode="None"
    reality_add_more="off"
    reality_add_nginx="off"
    reality_add_balance="off"
    reality_balance_role=""
    judge_mode
    READBACK_SHELL_MODE="${shell_mode}"
    READBACK_BALANCE_ROLE="${reality_balance_role}"
    READBACK_TLS_MODE="${tls_mode}"
    READBACK_TRANSPORT_MODE="${transport_mode}"
    rm -f "${xray_install_config_file}"
    unset -f info_extraction
}

echo "--- readback: standard Reality ---"
run_judge_mode_from_config '{"tls":"Reality","transport_mode":"None","reality_add_more":"off","reality_add_nginx":"off","reality_add_balance":"off"}'
assert_eq "readback standard Reality shell_mode" "Reality" "${READBACK_SHELL_MODE}"

echo "--- readback: Reality + Nginx ---"
run_judge_mode_from_config '{"tls":"Reality","transport_mode":"None","reality_add_more":"off","reality_add_nginx":"on","reality_add_balance":"off"}'
assert_eq "readback Reality+Nginx shell_mode" "Nginx+Reality" "${READBACK_SHELL_MODE}"

echo "--- readback: Balance primary ---"
run_judge_mode_from_config '{"tls":"Reality","transport_mode":"None","reality_add_more":"off","reality_add_nginx":"on","reality_add_balance":"on","reality_balance_role":"primary"}'
assert_eq "readback Balance primary shell_mode" "Nginx+Reality+Balance" "${READBACK_SHELL_MODE}"
assert_eq "readback Balance primary role" "primary" "${READBACK_BALANCE_ROLE}"

echo "--- readback: Balance secondary ---"
run_judge_mode_from_config '{"tls":"Reality","transport_mode":"None","reality_add_more":"off","reality_add_nginx":"off","reality_add_balance":"on","reality_balance_role":"secondary"}'
assert_eq "readback Balance secondary shell_mode" "Reality+Balance" "${READBACK_SHELL_MODE}"
assert_eq "readback Balance secondary role" "secondary" "${READBACK_BALANCE_ROLE}"

echo "--- readback: XTLS ONLY ---"
run_judge_mode_from_config '{"tls":"XTLS","transport_mode":"None"}'
assert_eq "readback XTLS ONLY shell_mode" "XTLS ONLY" "${READBACK_SHELL_MODE}"

echo "--- readback: not installed ---"
run_judge_mode_from_config '{"tls":"None","transport_mode":"None"}'
assert_eq "readback not-installed shell_mode" "未安装" "${READBACK_SHELL_MODE}"

echo "--- readback: old config missing reality_balance_role (Balance primary) ---"
run_judge_mode_from_config '{"tls":"Reality","transport_mode":"None","reality_add_more":"off","reality_add_nginx":"on","reality_add_balance":"on"}'
assert_eq "readback old-config Balance primary shell_mode" "Nginx+Reality+Balance" "${READBACK_SHELL_MODE}"
assert_eq "readback old-config reality_balance_role empty" "" "${READBACK_BALANCE_ROLE}"

# Transport-mode regression: these must still derive correctly via the
# transport_label path (transport_mode != "None").
echo "--- readback regression: Nginx+ws+TLS ---"
run_judge_mode_from_config '{"tls":"TLS","transport_mode":"onlyws"}'
assert_eq "readback Nginx+ws+TLS shell_mode" "Nginx+ws+TLS" "${READBACK_SHELL_MODE}"

echo "--- readback regression: Reality+xHTTP ---"
run_judge_mode_from_config '{"tls":"Reality","transport_mode":"onlyxhttp","reality_add_more":"on","reality_add_nginx":"off","reality_add_balance":"off"}'
assert_eq "readback Reality+xHTTP shell_mode" "Reality+xHTTP" "${READBACK_SHELL_MODE}"

echo "--- readback regression: ws+gRPC+xHTTP ONLY ---"
run_judge_mode_from_config '{"tls":"None","transport_mode":"wsgRPCxhttp"}'
assert_eq "readback ws+gRPC+xHTTP ONLY shell_mode" "ws+gRPC+xHTTP ONLY" "${READBACK_SHELL_MODE}"

# ============================================================================
# Real menu state-machine tests
#
# These tests use the production menu_install/menu_install_reality/
# menu_install_transport/menu_choose_transport functions and production
# menu_read/read_optimize input handling. Only installation side effects and
# exec are mocked. Input is piped with a narrow COLUMNS value, so the same
# tests cover non-TTY and narrow-terminal behavior.
# ============================================================================

run_real_menu_flow() {
    local input="$1"
    local harness
    harness='
            export _TEST_MODE=1
            # shellcheck source=/dev/null
            source "$1" >/dev/null 2>&1 || true
            gettext() { printf "%s" "$1"; }
            install_xray_reality() {
                printf "ROUTE=reality PROFILE=%s TRANSPORT=%s\n" \
                    "$install_profile" "$transport_mode"
            }
            install_xray_ws_tls() {
                printf "ROUTE=tls PROFILE=%s TRANSPORT=%s\n" \
                    "$install_profile" "$transport_mode"
            }
            install_xray_ws_only() {
                printf "ROUTE=only PROFILE=%s TRANSPORT=%s\n" \
                    "$install_profile" "$transport_mode"
            }
            install_xray_xtls_only() {
                printf "ROUTE=xtls PROFILE=%s TRANSPORT=%s\n" \
                    "$install_profile" "$transport_mode"
            }
            exec() { :; }
            menu_install
        '
    if command -v timeout >/dev/null 2>&1; then
        printf '%b' "${input}" |
            COLUMNS=24 TERM=dumb timeout 5 bash -c "${harness}" \
                _ "${REPO_DIR}/install.sh" 2>&1
    elif command -v gtimeout >/dev/null 2>&1; then
        printf '%b' "${input}" |
            COLUMNS=24 TERM=dumb gtimeout 5 bash -c "${harness}" \
                _ "${REPO_DIR}/install.sh" 2>&1
    else
        printf '%b' "${input}" |
            COLUMNS=24 TERM=dumb bash -c "${harness}" \
                _ "${REPO_DIR}/install.sh" 2>&1
    fi
}

assert_output_contains() {
    local name="$1" expected="$2" output="$3"
    if [[ "${output}" == *"${expected}"* ]]; then
        ok "${name}"
    else
        bad "${name} (missing: ${expected})"
    fi
}

assert_output_not_contains() {
    local name="$1" unexpected="$2" output="$3"
    if [[ "${output}" != *"${unexpected}"* ]]; then
        ok "${name}"
    else
        bad "${name} (unexpected: ${unexpected})"
    fi
}

echo "--- real menu: Reality + Nginx ---"
MENU_OUTPUT=$(run_real_menu_flow '1\n1\n0\n0\n')
assert_output_contains "routes reality_nginx" \
    "ROUTE=reality PROFILE=reality_nginx TRANSPORT=None" "${MENU_OUTPUT}"

echo "--- real menu: standard Reality ---"
MENU_OUTPUT=$(run_real_menu_flow '1\n2\n0\n0\n')
assert_output_contains "routes reality_standard" \
    "ROUTE=reality PROFILE=reality_standard TRANSPORT=None" "${MENU_OUTPUT}"

echo "--- real menu: Reality + transport ---"
MENU_OUTPUT=$(run_real_menu_flow '1\n3\n5\n0\n0\n')
assert_output_contains "routes reality_transport" \
    "ROUTE=reality PROFILE=reality_transport TRANSPORT=wsgRPCxhttp" "${MENU_OUTPUT}"

echo "--- real menu: Reality + transport + Nginx ---"
MENU_OUTPUT=$(run_real_menu_flow '1\n4\n4\n0\n0\n')
assert_output_contains "routes reality_transport_nginx" \
    "ROUTE=reality PROFILE=reality_transport_nginx TRANSPORT=wsxhttp" "${MENU_OUTPUT}"

echo "--- real menu: Reality balance primary ---"
MENU_OUTPUT=$(run_real_menu_flow '1\n5\n1\n0\n0\n0\n')
assert_output_contains "routes reality_balance_primary" \
    "ROUTE=reality PROFILE=reality_balance_primary TRANSPORT=None" "${MENU_OUTPUT}"

echo "--- real menu: Reality balance secondary ---"
MENU_OUTPUT=$(run_real_menu_flow '1\n5\n2\n0\n0\n0\n')
assert_output_contains "routes reality_balance_secondary" \
    "ROUTE=reality PROFILE=reality_balance_secondary TRANSPORT=None" "${MENU_OUTPUT}"

echo "--- real menu: Reality balance role return does not install ---"
MENU_OUTPUT=$(run_real_menu_flow '1\n5\n0\n0\n0\n')
assert_output_not_contains "balance role return does not install" \
    "ROUTE=" "${MENU_OUTPUT}"

echo "--- real menu: Reality balance role invalid then primary ---"
MENU_OUTPUT=$(run_real_menu_flow '1\n5\n9\n1\n0\n0\n0\n')
assert_output_contains "balance role invalid then primary" \
    "ROUTE=reality PROFILE=reality_balance_primary TRANSPORT=None" "${MENU_OUTPUT}"

echo "--- real menu: Reality balance role return then choose standard ---"
MENU_OUTPUT=$(run_real_menu_flow '1\n5\n0\n2\n0\n0\n')
assert_output_contains "balance role return then standard" \
    "ROUTE=reality PROFILE=reality_standard TRANSPORT=None" "${MENU_OUTPUT}"
assert_output_not_contains "balance role return did not install balance" \
    "PROFILE=reality_balance" "${MENU_OUTPUT}"

echo "--- real menu: transport + Nginx + TLS ---"
MENU_OUTPUT=$(run_real_menu_flow '2\n1\n3\n0\n0\n')
assert_output_contains "routes transport_nginx_tls" \
    "ROUTE=tls PROFILE=transport_nginx_tls TRANSPORT=onlyxhttp" "${MENU_OUTPUT}"

echo "--- real menu: transport ONLY confirmation accepted ---"
MENU_OUTPUT=$(run_real_menu_flow '2\n2\ny\n2\n0\n0\n')
assert_output_contains "routes transport_only" \
    "ROUTE=only PROFILE=transport_only TRANSPORT=onlygRPC" "${MENU_OUTPUT}"
assert_output_contains "transport_only shows risk explanation" \
    "ONLY 模式主要用于中转、负载均衡后端或已有上层代理的环境" "${MENU_OUTPUT}"

echo "--- real menu: XTLS confirmation accepted ---"
MENU_OUTPUT=$(run_real_menu_flow '3\ny\n0\n')
assert_output_contains "routes xtls_only" \
    "ROUTE=xtls PROFILE=xtls_only TRANSPORT=None" "${MENU_OUTPUT}"

echo "--- real menu: advanced confirmations rejected ---"
MENU_OUTPUT=$(run_real_menu_flow '2\n2\nn\n0\n0\n')
assert_output_not_contains "transport_only rejection does not install" \
    "ROUTE=" "${MENU_OUTPUT}"
MENU_OUTPUT=$(run_real_menu_flow '3\nn\n0\n')
assert_output_not_contains "xtls rejection does not install" \
    "ROUTE=" "${MENU_OUTPUT}"

echo "--- real menu: every return level and invalid input ---"
MENU_OUTPUT=$(run_real_menu_flow '0\n')
assert_output_not_contains "main return does not install" "ROUTE=" "${MENU_OUTPUT}"
MENU_OUTPUT=$(run_real_menu_flow '1\n0\n0\n')
assert_output_not_contains "Reality return does not install" "ROUTE=" "${MENU_OUTPUT}"
MENU_OUTPUT=$(run_real_menu_flow '2\n0\n0\n')
assert_output_not_contains "transport return does not install" "ROUTE=" "${MENU_OUTPUT}"
MENU_OUTPUT=$(run_real_menu_flow '1\n3\n0\n0\n0\n')
assert_output_not_contains "transport chooser return does not install" \
    "ROUTE=" "${MENU_OUTPUT}"
MENU_OUTPUT=$(run_real_menu_flow '99\n0\n')
assert_output_not_contains "invalid input does not install" "ROUTE=" "${MENU_OUTPUT}"

echo "--- real menu: return then choose a different branch ---"
MENU_OUTPUT=$(run_real_menu_flow '1\n0\n2\n1\n1\n0\n0\n')
assert_output_contains "return does not pollute next branch" \
    "ROUTE=tls PROFILE=transport_nginx_tls TRANSPORT=onlyws" "${MENU_OUTPUT}"
assert_output_not_contains "returned Reality branch did not install" \
    "ROUTE=reality" "${MENU_OUTPUT}"

# ============================================================================
# Menu return-code propagation (P0-4)
#
# Every install entry must preserve the real install rc: 0 → success branch
# (exec), 1 → "安装失败, 原配置已恢复", 2 → "安装失败且自动恢复失败, 备份已保留".
# rc 2 must reach the caller — never flattened to 1. The harness runs the
# REAL menu functions with piped menu input; only install/exec/gettext/log_echo
# are mocked.
# ============================================================================
echo "--- menu rc propagation: direct menu_action entries ---"

run_menu_rc_flow() {
    local entry="$1" install_rc="$2" exec_mode="$3" input="$4"
    local harness
    harness='
            export _TEST_MODE=1
            # shellcheck source=/dev/null
            source "$1" >/dev/null 2>&1 || true
            gettext() { printf "%s" "$1"; }
            log_echo() { printf "MSG=%s\n" "$*"; }
            install_xray_reality() { printf "INSTALLED=reality\n"; return "${INSTALL_RC}"; }
            install_xray_ws_tls() { printf "INSTALLED=ws_tls\n"; return "${INSTALL_RC}"; }
            install_xray_ws_only() { printf "INSTALLED=ws_only\n"; return "${INSTALL_RC}"; }
            install_xray_xtls_only() { printf "INSTALLED=xtls_only\n"; return "${INSTALL_RC}"; }
            exec() {
                printf "EXEC_REACHED\n"
                if [[ "${EXEC_MODE}" == "exit" ]]; then exit 0; fi
            }
            INSTALL_RC='"${install_rc}"'
            EXEC_MODE='"${exec_mode}"'
            '"${entry}"'
            printf "RETURN=%s\n" "$?"
        '
    if command -v timeout >/dev/null 2>&1; then
        printf '%b' "${input}" |
            COLUMNS=24 TERM=dumb timeout 5 bash -c "${harness}" \
                _ "${REPO_DIR}/install.sh" 2>&1
    elif command -v gtimeout >/dev/null 2>&1; then
        printf '%b' "${input}" |
            COLUMNS=24 TERM=dumb gtimeout 5 bash -c "${harness}" \
                _ "${REPO_DIR}/install.sh" 2>&1
    else
        printf '%b' "${input}" |
            COLUMNS=24 TERM=dumb bash -c "${harness}" \
                _ "${REPO_DIR}/install.sh" 2>&1
    fi
}

for _rc in 0 1 2; do
    for _entry in 3 4; do
        _name="menu_action ${_entry} rc=${_rc}"
        if [[ ${_rc} -eq 0 ]]; then
            _out=$(run_menu_rc_flow "menu_action ${_entry}" 0 exit '')
            assert_output_contains "${_name}: success branch reached" "EXEC_REACHED" "${_out}"
            assert_output_not_contains "${_name}: no failure message" "安装失败" "${_out}"
        else
            _out=$(run_menu_rc_flow "menu_action ${_entry}" ${_rc} return '')
            assert_output_contains "${_name}: returns ${_rc}" "RETURN=${_rc}" "${_out}"
            assert_output_not_contains "${_name}: no exec on failure" "EXEC_REACHED" "${_out}"
            if [[ ${_rc} -eq 2 ]]; then
                assert_output_contains "${_name}: backup retained message" \
                    "自动恢复失败, 备份已保留" "${_out}"
            else
                assert_output_contains "${_name}: restored message" \
                    "安装失败, 原配置已恢复" "${_out}"
            fi
        fi
    done
    for _entry in 5 6; do
        _name="menu_action ${_entry} rc=${_rc}"
        if [[ ${_rc} -eq 0 ]]; then
            _out=$(run_menu_rc_flow "menu_action ${_entry}" 0 exit 'y\n')
            assert_output_contains "${_name}: success branch reached" "EXEC_REACHED" "${_out}"
            assert_output_not_contains "${_name}: no failure message" "安装失败" "${_out}"
        else
            _out=$(run_menu_rc_flow "menu_action ${_entry}" ${_rc} return 'y\n')
            assert_output_contains "${_name}: returns ${_rc}" "RETURN=${_rc}" "${_out}"
            assert_output_not_contains "${_name}: no exec on failure" "EXEC_REACHED" "${_out}"
            if [[ ${_rc} -eq 2 ]]; then
                assert_output_contains "${_name}: backup retained message" \
                    "自动恢复失败, 备份已保留" "${_out}"
            else
                assert_output_contains "${_name}: restored message" \
                    "安装失败, 原配置已恢复" "${_out}"
            fi
        fi
    done
done

echo "--- menu rc propagation: wizard entries ---"
# Reality standard (menu_install_reality case 2), balance primary (case 1),
# TLS transport (menu_install_transport case 1), ws ONLY (case 2), XTLS
# (menu_install case 3). Each must propagate rc 1/2 to the caller.
_out=$(run_menu_rc_flow "menu_install_reality" 1 return '2\n')
assert_output_contains "wizard reality standard rc=1: returns 1" "RETURN=1" "${_out}"
assert_output_contains "wizard reality standard rc=1: restored message" "原配置已恢复" "${_out}"
_out=$(run_menu_rc_flow "menu_install_reality" 2 return '2\n')
assert_output_contains "wizard reality standard rc=2: returns 2" "RETURN=2" "${_out}"
assert_output_contains "wizard reality standard rc=2: backup retained" "自动恢复失败, 备份已保留" "${_out}"

_out=$(run_menu_rc_flow "menu_install_reality_balance_role" 2 return '1\n')
assert_output_contains "wizard balance primary rc=2: returns 2" "RETURN=2" "${_out}"
assert_output_contains "wizard balance primary rc=2: backup retained" "自动恢复失败, 备份已保留" "${_out}"

_out=$(run_menu_rc_flow "menu_install_transport" 2 return '1\n3\n')
assert_output_contains "wizard TLS transport rc=2: returns 2" "RETURN=2" "${_out}"
assert_output_contains "wizard TLS transport rc=2: backup retained" "自动恢复失败, 备份已保留" "${_out}"

_out=$(run_menu_rc_flow "menu_install_transport" 2 return '2\ny\n2\n')
assert_output_contains "wizard ws ONLY rc=2: returns 2" "RETURN=2" "${_out}"
assert_output_contains "wizard ws ONLY rc=2: backup retained" "自动恢复失败, 备份已保留" "${_out}"

_out=$(run_menu_rc_flow "menu_install" 2 return '3\ny\n')
assert_output_contains "wizard xtls_only rc=2: returns 2" "RETURN=2" "${_out}"
assert_output_contains "wizard xtls_only rc=2: backup retained" "自动恢复失败, 备份已保留" "${_out}"

echo "--- menu translations are complete and non-fuzzy ---"
for lang in en fa fr ko ru; do
    po_file="${REPO_DIR}/i18n/po/${lang}.po"
    for msgid in \
        "选择传输协议" \
        "Reality 部署方式" \
        "无 Nginx、无 TLS" \
        "此模式主要用于流量中转或特殊部署，不建议普通用户使用" \
        "ONLY 模式主要用于中转、负载均衡后端或已有上层代理的环境" \
        "Reality 负载均衡角色" \
        "主服务器" \
        "安装 Nginx" \
        "二级服务器" \
        "仅提供 Reality 后端"
    do
        if awk -v expected="${msgid}" '
            $0 == "#, fuzzy" { fuzzy = 1; next }
            $0 == "msgid \"" expected "\"" {
                if (fuzzy) exit 1
                getline
                if ($0 == "msgstr \"\"") {
                    has_content = 0
                    while (getline > 0) {
                        if ($0 ~ /^"/) {
                            if ($0 != "\"\"") has_content = 1
                        } else {
                            break
                        }
                    }
                    if (!has_content) exit 1
                }
                found = 1
                exit 0
            }
            { fuzzy = 0 }
            END { if (!found) exit 1 }
        ' "${po_file}"; then
            ok "${lang}: translated ${msgid}"
        else
            bad "${lang}: missing, empty, or fuzzy translation for ${msgid}"
        fi
    done
done

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
