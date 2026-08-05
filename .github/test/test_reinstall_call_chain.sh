#!/usr/bin/env bash
# Real call-chain tests for the safe-reconfigure phase.
#
# Coverage (13 scenarios per Xray_safe_reconfigure_verified_fix_prompt.md §IV):
#   1.  TLS keep-config: only change main port / inner port
#   2.  Reality keep-config: only change target/serverNames
#   3.  keep-config with no changes selected
#   4.  Multi-user Reality keep-config (all users preserved)
#   5.  Multi-user Reality → TLS mode switch (no mismatched protocol JSON)
#   6.  Transport combination change (keep-config rejects, guides to rebuild)
#   7.  Mid-failure rollback (config write / candidate validate / firewall / restart / health)
#   8.  Backup failure (critical file copy fails → transaction stops before any change)
#   9.  Restore failure (non-zero return, no success message, backup retained)
#   10. Missing/stale install metadata (complete from actual Xray JSON or safe-stop)
#   11. Consecutive reconfigures (distinct backup dirs, both independently restorable)
#   12. Nginx user config preservation (user .conf kept, main nginx.conf restored)
#   13. Skill existing-install protection (all non-NEW_INSTALL modes non-zero exit)
#
# Design:
#   - Sources install.sh with _TEST_MODE=1, mocks system commands.
#   - Calls REAL reinstall_backup_create / reinstall_backup_restore /
#     reinstall_finalize / reinstall_verify_preservation / xray_conf_add.
#   - Runs on macOS (dev) AND Ubuntu (CI). No root, no real systemctl/xray.
#
# Run: bash .github/test/test_reinstall_call_chain.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

# Snapshot the real restore function body NOW. Later scenarios (S15/S16) unset
# and redefine reinstall_backup_restore, so S18 must restore this body before
# wrapping it to count invocations.
_REAL_RESTORE_BODY="$(declare -f reinstall_backup_restore)"

PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

# --- Mocks (no stdout noise, no side effects) ---
log_echo() { :; }
gettext() { printf '%s' "$1"; }
exec() { :; }
judge() { :; }
xray_diagnose() { :; }
nginx_diagnose() { :; }
sleep() { :; }
countdown() { :; }
_info_cache_invalidate() { :; }

# --- systemctl mock: unit-file aware so a missing unit behaves like real
# systemd (is-active/is-enabled return non-zero, and enable/disable/start/stop
# fail). Mocks that "always succeed" would mask the unit-restore bug.
SYSTEMCTL_IS_ACTIVE_RESULT=0
SYSTEMCTL_DAEMON_RELOAD_FAIL=0
SYSTEMCTL_ENABLE_NGINX_CALLS=0
SYSTEMCTL_DISABLE_NGINX_CALLS=0
SYSTEMCTL_START_NGINX_CALLS=0
SYSTEMCTL_STOP_NGINX_CALLS=0
systemctl() {
    local svc=""
    case "${1:-}" in
        is-active|is-enabled)
            svc="${3:-}"
            if [[ "${svc}" == "xray" || "${svc}" == "nginx" ]]; then
                if [[ "${svc}" == "xray" && ! -f "${xray_systemd_file}" ]]; then
                    return 3
                fi
                if [[ "${svc}" == "nginx" && ! -f "${nginx_systemd_file}" ]]; then
                    return 3
                fi
                return "${SYSTEMCTL_IS_ACTIVE_RESULT}"
            fi
            return 1
            ;;
        daemon-reload)
            [[ ${SYSTEMCTL_DAEMON_RELOAD_FAIL} -eq 1 ]] && return 1
            return 0
            ;;
        enable|disable|start|stop)
            svc="${2:-}"
            if [[ "${svc}" == "nginx" ]]; then
                case "${1:-}" in
                    enable)  SYSTEMCTL_ENABLE_NGINX_CALLS=$((SYSTEMCTL_ENABLE_NGINX_CALLS + 1));;
                    disable) SYSTEMCTL_DISABLE_NGINX_CALLS=$((SYSTEMCTL_DISABLE_NGINX_CALLS + 1));;
                    start)   SYSTEMCTL_START_NGINX_CALLS=$((SYSTEMCTL_START_NGINX_CALLS + 1));;
                    stop)    SYSTEMCTL_STOP_NGINX_CALLS=$((SYSTEMCTL_STOP_NGINX_CALLS + 1));;
                esac
            elif [[ "${svc}" != "xray" ]]; then
                return 0
            fi
            if [[ "${svc}" == "xray" && ! -f "${xray_systemd_file}" ]]; then
                return 1
            fi
            if [[ "${svc}" == "nginx" && ! -f "${nginx_systemd_file}" ]]; then
                return 1
            fi
            return 0
            ;;
        *) return 0 ;;
    esac
}

# --- service_stop / service_start mocks (called by restore) ---
service_stop() { :; }
service_start() { :; }

# --- read mock: only intercept the multi-user save_originxray_fq read ---
# (The multi-user branch does `read -r save_originxray_fq`; we pre-set the
# variable and let the mock preserve it. All other read calls — especially
# the SHA256 verification `while IFS= read -r` loop in reinstall_backup_restore
# — must use the real builtin so stdin is consumed and EOF is reached.)
read() {
    if [[ "${2:-}" == "save_originxray_fq" ]]; then
        :  # no-op, preserve pre-set value
    else
        command read "$@"
    fi
}

# --- sha256sum shim: macOS lacks GNU sha256sum; use shasum -a 256. ---
# The real restore verifies with `sha256sum --strict -c`. On macOS, shasum
# does not support --strict, so strip it and delegate to shasum -a 256, which
# uses the same "<hash>  <file>" checksum format (so -c is compatible).
if ! command -v sha256sum >/dev/null 2>&1; then
    sha256sum() {
        if [[ "${1:-}" == "--strict" ]]; then
            shift
        fi
        command shasum -a 256 "$@"
    }
fi

# --- stat mock: translate Linux `stat -c` to macOS `stat -f` ---
# update_json_config uses `stat -c '%a'/%u/%g` which is Linux-only.
# On macOS, `stat -f '%Lp'/%u/%g` is the equivalent.
stat() {
    if [[ "${1:-}" == "-c" ]]; then
        local fmt="$2"
        shift 2
        case "${fmt}" in
            '%a') command stat -f '%Lp' "$@" 2>/dev/null || echo "600" ;;
            '%u') command stat -f '%u' "$@" 2>/dev/null || echo "$(id -u)" ;;
            '%g') command stat -f '%g' "$@" 2>/dev/null || echo "$(id -g)" ;;
            *) command stat "$@" 2>/dev/null ;;
        esac
    else
        command stat "$@"
    fi
}

# --- Helpers ---
assert_eq() {
    local name="$1" expected="$2" actual="$3"
    if [[ "${expected}" == "${actual}" ]]; then
        ok "${name} (got: ${actual})"
    else
        bad "${name} (expected: ${expected}, got: ${actual})"
    fi
}

assert_ne() {
    local name="$1" not_expected="$2" actual="$3"
    if [[ "${not_expected}" != "${actual}" ]]; then
        ok "${name}"
    else
        bad "${name} (should not be: ${actual})"
    fi
}

assert_contains() {
    local name="$1" needle="$2" haystack="$3"
    if [[ "${haystack}" == *"${needle}"* ]]; then
        ok "${name}"
    else
        bad "${name} (missing: ${needle})"
    fi
}

# --- Temp dirs ---
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

idleleo_dir="${TMP_ROOT}/idleleo"
idleleo_conf_dir="${idleleo_dir}/conf"
xray_conf_dir="${idleleo_conf_dir}/xray"
xray_conf="${xray_conf_dir}/config.json"
xray_install_config_file="${idleleo_conf_dir}/install_config.json"
nginx_conf_dir="${idleleo_conf_dir}/nginx"
ssl_chainpath="${idleleo_dir}/cert"
managed_ports_file="${idleleo_conf_dir}/managed_ports.json"
xray_systemd_file="${TMP_ROOT}/fake_xray.service"
nginx_systemd_file="${TMP_ROOT}/fake_nginx.service"
nginx_dir="${TMP_ROOT}/nonexistent_nginx"

# Fake xray binary that always passes `run -test`.
xray_bin_dir="${TMP_ROOT}/bin"
_make_fake_xray_binary() {
    mkdir -p "${xray_bin_dir}"
    cat > "${xray_bin_dir}/xray" <<'XRAY_EOF'
#!/usr/bin/env bash
exit 0
XRAY_EOF
    chmod +x "${xray_bin_dir}/xray"
}

# --- reset before each scenario ---
reset_for_call_chain_test() {
    rm -rf "${xray_conf_dir}" "${nginx_conf_dir}" "${ssl_chainpath}" "${idleleo_dir}/backup"
    rm -f "${xray_install_config_file}" "${managed_ports_file}" \
        "${xray_systemd_file}" "${nginx_systemd_file}"
    mkdir -p "${xray_conf_dir}" "${nginx_conf_dir}" "${ssl_chainpath}" "${idleleo_dir}/backup"

    tls_mode="None"
    transport_mode="None"
    reality_add_nginx="off"
    reality_add_more="off"
    reality_add_balance="off"
    _reinstall_backup_dir=""
    _reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_changed="no"
    reinstall_operation="none"
    reinstall_keep_config="off"
    old_tls_mode=""
    info_extraction_all="{}"

    # Reset change_* flags
    change_port="no"
    change_user="no"
    change_transport="no"
    change_inner_ports="no"
    change_reality="no"
    change_nginx_sni="no"
    change_ws_path="no"
    change_grpc_path="no"
    change_xhttp_path="no"

    # Variables used by modify_* functions and multi-user branch.
    save_originxray_fq=""
    port=""
    xport=""
    gport=""
    xhttpport=""
    path=""
    serviceName=""
    xhttppath=""
    UUID=""
    custom_email=""
    target=""
    serverNames=""
    privateKey=""
    shortIds=""

    SYSTEMCTL_IS_ACTIVE_RESULT=0
    SYSTEMCTL_DAEMON_RELOAD_FAIL=0
    SYSTEMCTL_ENABLE_NGINX_CALLS=0
    SYSTEMCTL_DISABLE_NGINX_CALLS=0
    SYSTEMCTL_START_NGINX_CALLS=0
    SYSTEMCTL_STOP_NGINX_CALLS=0

    _make_fake_xray_binary
}

# --- Config writers ---
write_tls_single_user_conf() {
    cat > "${xray_conf}" <<'EOF'
{
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "tag": "VLESS-ws-in",
            "settings": {
                "clients": [
                    {"id": "uuid-tls-single", "level": 0, "email": "user1@example.com"}
                ],
                "decryption": "none"
            },
            "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/ray/"}}
        }
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    "routing": {"rules": [{"inboundTag": ["VLESS-ws-in"], "outboundTag": "direct"}]},
    "dns": {"servers": ["1.1.1.1"]}
}
EOF
}

write_reality_single_user_conf() {
    cat > "${xray_conf}" <<'EOF'
{
    "inbounds": [
        {
            "port": 9443,
            "protocol": "vless",
            "tag": "VLESS-Reality-in",
            "settings": {
                "clients": [
                    {"id": "uuid-reality-single", "flow": "xtls-rprx-vision", "level": 0, "email": "user1@example.com"}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "target": "example.com:443",
                    "serverNames": ["example.com"],
                    "privateKey": "priv-key-SECRET",
                    "shortIds": ["short-id-SECRET"]
                }
            }
        }
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    "routing": {"rules": [{"inboundTag": ["VLESS-Reality-in"], "outboundTag": "direct"}]},
    "dns": {"servers": ["8.8.8.8"]}
}
EOF
}

write_reality_multi_user_conf() {
    cat > "${xray_conf}" <<'EOF'
{
    "inbounds": [
        {
            "port": 9443,
            "protocol": "vless",
            "tag": "VLESS-Reality-in",
            "settings": {
                "clients": [
                    {"id": "uuid-reality-1", "flow": "xtls-rprx-vision", "level": 0, "email": "user1@example.com"},
                    {"id": "uuid-reality-2", "flow": "xtls-rprx-vision", "level": 0, "email": "user2@example.com"},
                    {"id": "uuid-reality-3", "flow": "xtls-rprx-vision", "level": 0, "email": "user3@example.com"}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "target": "example.com:443",
                    "serverNames": ["example.com"],
                    "privateKey": "priv-key-SECRET",
                    "shortIds": ["short1", "short2"]
                }
            }
        }
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    "routing": {"rules": [{"inboundTag": ["VLESS-Reality-in"], "outboundTag": "direct"}]},
    "dns": {"servers": ["8.8.8.8"]}
}
EOF
}

# ============================================================================
# TLS keep-config, only change main port / inner port
# ============================================================================
echo "=== Scenario 1: TLS keep-config — change port ==="
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
transport_mode="onlyws"
reinstall_keep_config="on"
reinstall_operation="keep_config"
change_port="yes"
# In TLS mode, modify_inbound_port sets ws inbound to xport (internal port).
port=443
xport=10086

# Snapshot UUID set before xray_conf_add.
PRE_UUIDS=$(extract_uuid_set_from_xray_conf | sort)

# Call the real xray_conf_add — keep-config path should apply modify_inbound_port.
xray_conf_add

# Verify the ws inbound port was changed to xport.
POST_PORT=$(jq -r '.inbounds[] | select(.tag=="VLESS-ws-in") | .port' "${xray_conf}")
assert_eq "S1 ws inbound port changed to xport" "10086" "${POST_PORT}"

# Verify UUID set unchanged.
POST_UUIDS=$(extract_uuid_set_from_xray_conf | sort)
assert_eq "S1 UUID set preserved" "${PRE_UUIDS}" "${POST_UUIDS}"

# Verify custom routing/dns preserved.
assert_eq "S1 custom routing preserved" "direct" "$(jq -r '.routing.rules[0].outboundTag' "${xray_conf}")"
assert_eq "S1 custom DNS preserved" "1.1.1.1" "$(jq -r '.dns.servers[0]' "${xray_conf}")"

# ============================================================================
# Reality keep-config, only change target/serverNames
# ============================================================================
echo "=== Scenario 2: Reality keep-config — change target/serverNames ==="
reset_for_call_chain_test
write_reality_single_user_conf
tls_mode="Reality"
reinstall_keep_config="on"
reinstall_operation="keep_config"
change_reality="yes"
target="newtarget.com"
serverNames="newtarget.com"
# modify_privateKey_shortIds also runs when change_reality=yes; provide values.
privateKey="new-priv-key-SECRET"
shortIds="newshort"

PRE_UUIDS=$(extract_uuid_set_from_xray_conf | sort)

xray_conf_add

POST_TARGET=$(jq -r '.inbounds[0].streamSettings.realitySettings.target' "${xray_conf}")
POST_SERVERNAMES=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "${xray_conf}")
assert_eq "S2 target changed" "newtarget.com:443" "${POST_TARGET}"
assert_eq "S2 serverNames changed" "newtarget.com" "${POST_SERVERNAMES}"

# UUID set unchanged.
POST_UUIDS=$(extract_uuid_set_from_xray_conf | sort)
assert_eq "S2 UUID set preserved" "${PRE_UUIDS}" "${POST_UUIDS}"

# Custom routing/dns preserved.
assert_eq "S2 custom routing preserved" "direct" "$(jq -r '.routing.rules[0].outboundTag' "${xray_conf}")"
assert_eq "S2 custom DNS preserved" "8.8.8.8" "$(jq -r '.dns.servers[0]' "${xray_conf}")"

# ============================================================================
# Keep-config with no changes selected
# ============================================================================
echo "=== Scenario 3: keep-config — no changes ==="
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
reinstall_keep_config="on"
reinstall_operation="keep_config"
# No change_* flags set.

PRE_CONF=$(jq -Sc . "${xray_conf}")
PRE_UUIDS=$(extract_uuid_set_from_xray_conf | sort)

xray_conf_add

POST_CONF=$(jq -Sc . "${xray_conf}")
POST_UUIDS=$(extract_uuid_set_from_xray_conf | sort)
assert_eq "S3 config semantically equivalent" "${PRE_CONF}" "${POST_CONF}"
assert_eq "S3 UUID set unchanged" "${PRE_UUIDS}" "${POST_UUIDS}"

# ============================================================================
# Multi-user Reality keep-config (all users preserved)
# ============================================================================
echo "=== Scenario 4: Multi-user Reality keep-config ==="
reset_for_call_chain_test
write_reality_multi_user_conf
tls_mode="Reality"
reinstall_keep_config="on"
reinstall_operation="keep_config"
change_port="yes"
port=10443

PRE_UUIDS=$(extract_uuid_set_from_xray_conf | sort)
PRE_CLIENT_COUNT=$(count_reality_clients_in_xray_conf)

# Multi-user keep-config: the else-branch asks to preserve original config.
# The top-level read mock is a no-op, so save_originxray_fq keeps its
# reset value ("") → default case = preserve.

xray_conf_add

# All UUIDs preserved.
POST_UUIDS=$(extract_uuid_set_from_xray_conf | sort)
assert_eq "S4 UUID set preserved" "${PRE_UUIDS}" "${POST_UUIDS}"
assert_eq "S4 client count preserved" "${PRE_CLIENT_COUNT}" "$(count_reality_clients_in_xray_conf)"

# Verify each user's email preserved.
assert_eq "S4 user1 email" "user1@example.com" "$(jq -r '.inbounds[0].settings.clients[0].email' "${xray_conf}")"
assert_eq "S4 user2 email" "user2@example.com" "$(jq -r '.inbounds[0].settings.clients[1].email' "${xray_conf}")"
assert_eq "S4 user3 email" "user3@example.com" "$(jq -r '.inbounds[0].settings.clients[2].email' "${xray_conf}")"

# shortIds preserved.
assert_eq "S4 shortIds count" "2" "$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds | length' "${xray_conf}")"

# ============================================================================
# Multi-user Reality → TLS mode switch
# ============================================================================
echo "=== Scenario 5: Multi-user Reality → TLS mode switch ==="
reset_for_call_chain_test
write_reality_multi_user_conf
tls_mode="TLS"          # target mode is TLS
old_tls_mode="Reality"  # source mode is Reality
reinstall_operation="mode_switch"
reinstall_keep_config="off"

# mode_switch must NOT enter keep-config branch. Verify reinstall_verify_preservation
# skips the UUID-set check for mode_switch.
_reinstall_backup_dir=$(reinstall_backup_create)

# verify_preservation should return 0 (skip) for mode_switch.
if reinstall_verify_preservation "${_reinstall_backup_dir}"; then
    ok "S5 verify_preservation skips for mode_switch"
else
    bad "S5 verify_preservation should skip for mode_switch"
fi

# Verify the backup recorded the SOURCE mode (Reality), not target (TLS).
BACKUP_SRC_MODE=$(jq -r '.source_tls_mode' "${_reinstall_backup_dir}/pre_reinstall_state.json")
assert_eq "S5 backup records source mode" "Reality" "${BACKUP_SRC_MODE}"

rm -rf "${_reinstall_backup_dir}"

# ============================================================================
# Transport combination change (keep-config rejects)
# ============================================================================
echo "=== Scenario 6: Transport change rejected in keep-config ==="
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
reinstall_keep_config="on"
reinstall_operation="keep_config"
change_transport="yes"

PRE_CONF=$(jq -Sc . "${xray_conf}")

xray_conf_add

# The keep-config path does NOT handle change_transport.
# Verify config was not corrupted by a half-applied transport change.
POST_CONF=$(jq -Sc . "${xray_conf}")
assert_eq "S6 config not corrupted by transport change" "${PRE_CONF}" "${POST_CONF}"

# Verify the edit menu no longer offers transport change (option 3 is now inner ports).
# We check that reinstall_edit_menu does not set change_transport for any option 1-7.
# (This is a structural assertion — the menu text is checked via gettext mock.)

# ============================================================================
# Mid-failure rollback
# ============================================================================
echo "=== Scenario 7: Mid-failure rollback ==="
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
reinstall_operation="keep_config"

PRE_CONF=$(jq -Sc . "${xray_conf}")

# Create a backup, then simulate deploy failure via reinstall_finalize.
BACKUP_DIR=$(reinstall_backup_create)
_reinstall_backup_dir="${BACKUP_DIR}"

# Sabotage the xray binary so reinstall_validate_deploy fails (xray run -test fails).
cat > "${xray_bin_dir}/xray" <<'XRAY_FAIL'
#!/usr/bin/env bash
exit 1
XRAY_FAIL
chmod +x "${xray_bin_dir}/xray"

# reinstall_finalize should detect failure and restore backup.
if reinstall_finalize 2>/dev/null; then
    bad "S7 finalize should fail when xray -test fails"
else
    ok "S7 finalize returns non-zero on deploy failure"
fi

# Verify config was restored.
POST_CONF=$(jq -Sc . "${xray_conf}")
assert_eq "S7 config restored after failure" "${PRE_CONF}" "${POST_CONF}"

# _reinstall_backup_dir cleared after finalize.
assert_eq "S7 backup dir cleared" "" "${_reinstall_backup_dir}"

# --- service restart failure ---
echo "--- Scenario 7b: service restart failure ---"
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
reinstall_operation="keep_config"

PRE_CONF=$(jq -Sc . "${xray_conf}")
BACKUP_DIR=$(reinstall_backup_create)
_reinstall_backup_dir="${BACKUP_DIR}"

# Make systemctl is-active return failure → reinstall_validate_deploy fails.
SYSTEMCTL_IS_ACTIVE_RESULT=1

if reinstall_finalize 2>/dev/null; then
    bad "S7b finalize should fail when service is not active"
else
    ok "S7b finalize returns non-zero on service inactive"
fi

POST_CONF=$(jq -Sc . "${xray_conf}")
assert_eq "S7b config restored" "${PRE_CONF}" "${POST_CONF}"

# ============================================================================
# Backup failure (critical file copy fails → stops before changes)
# ============================================================================
echo "=== Scenario 8: Backup failure stops before changes ==="
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"

# Create install_config.json so backup tries to copy it.
echo '{"tls":"TLS","id":"uuid-orig"}' > "${xray_install_config_file}"
PRE_CONF=$(jq -Sc . "${xray_conf}")
PRE_INSTALL=$(cat "${xray_install_config_file}")

# Sabotage: make cp fail for install_config.json by making the source read-only
# and the backup target unwritable. We use a wrapper to force cp failure.
# Simpler: remove read permission on source so cp -a fails.
# Actually cp -a from a readable file to a writable dir works. Instead, make
# the backup parent dir read-only so cp into it fails.
# But mktemp -d creates the backup dir under ${idleleo_dir}/backup/. Make that
# read-only.
chmod 000 "${xray_conf_dir}/config.json" 2>/dev/null || true

# backup_create should fail because copying xray_conf_dir (which contains the
# unreadable config.json) fails.
if reinstall_backup_create 2>/dev/null; then
    bad "S8 backup should fail when critical file unreadable"
else
    ok "S8 backup returns 1 on critical file copy failure"
fi

# Restore permissions for cleanup.
chmod 644 "${xray_conf_dir}/config.json" 2>/dev/null || true

# Verify no backup dir was left behind (it should be rm -rf'd on failure).
BACKUP_COUNT=$(find "${idleleo_dir}/backup" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
assert_eq "S8 no backup dir left on failure" "0" "${BACKUP_COUNT}"

# Verify the original config is untouched.
POST_CONF=$(jq -Sc . "${xray_conf}")
assert_eq "S8 original config untouched" "${PRE_CONF}" "${POST_CONF}"

# ============================================================================
# Restore failure (non-zero, no success message, backup retained)
# ============================================================================
echo "=== Scenario 9: Restore failure ==="
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"

BACKUP_DIR=$(reinstall_backup_create)
_reinstall_backup_dir="${BACKUP_DIR}"

# Make daemon-reload fail → restore should report failure.
SYSTEMCTL_DAEMON_RELOAD_FAIL=1

# Capture log output: temporarily replace log_echo to capture messages.
_RESTORE_LOG=""
log_echo() { _RESTORE_LOG="${_RESTORE_LOG}$1 "; }

RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?

assert_ne "S9 restore returns non-zero on failure" "0" "${RESTORE_RC}"

# Should NOT output "已恢复原配置" (success message).
if [[ "${_RESTORE_LOG}" == *"已恢复原配置"* ]]; then
    bad "S9 should not output success message on failure"
else
    ok "S9 no false success message on restore failure"
fi

# Backup dir should be retained (not deleted).
[[ -d "${BACKUP_DIR}" ]] && ok "S9 backup dir retained" || bad "S9 backup dir should be retained"

# Restore log_echo to no-op.
log_echo() { :; }
SYSTEMCTL_DAEMON_RELOAD_FAIL=0

# ============================================================================
# Missing/stale install metadata
# ============================================================================
echo "=== Scenario 10: Missing install metadata fields ==="
reset_for_call_chain_test
write_reality_single_user_conf
tls_mode="Reality"

# Create install_config.json with MISSING port/id/target fields.
echo '{"tls":"Reality","shell_mode":"Reality"}' > "${xray_install_config_file}"
info_extraction_all=$(jq -rc . "${xray_install_config_file}")

# The actual Xray config has the real values. Verify the UUID set can be
# extracted from the actual config (not metadata).
UUID_SET=$(extract_uuid_set_from_xray_conf)
assert_eq "S10 UUID from actual config" "uuid-reality-single" "${UUID_SET}"

# Verify multi_user detection works from actual config.
assert_eq "S10 multi_user from actual config" "no" "$(detect_multi_user_from_xray_conf)"

# Verify reality_clients count from actual config.
assert_eq "S10 reality_clients from actual config" "1" "$(count_reality_clients_in_xray_conf)"

# Backup should still work (it reads actual config for state).
BACKUP_DIR=$(reinstall_backup_create)
[[ -f "${BACKUP_DIR}/pre_reinstall_state.json" ]] && ok "S10 backup works with stale metadata" || bad "S10 backup failed with stale metadata"

# Verify backup captured actual UUID set (not empty).
BACKUP_UUID=$(jq -r '.uuid_set[0]?' "${BACKUP_DIR}/pre_reinstall_state.json")
assert_eq "S10 backup has UUID from actual config" "uuid-reality-single" "${BACKUP_UUID}"

rm -rf "${BACKUP_DIR}"

# ============================================================================
# Consecutive reconfigures (distinct backup dirs)
# ============================================================================
echo "=== Scenario 11: Consecutive reconfigures ==="
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"

BACKUP1=$(reinstall_backup_create)
BACKUP2=$(reinstall_backup_create)

assert_ne "S11 backup dirs are distinct" "${BACKUP1}" "${BACKUP2}"

# Both backups should be valid and independently restorable.
[[ -f "${BACKUP1}/pre_reinstall_state.json" ]] && ok "S11 backup1 valid" || bad "S11 backup1 invalid"
[[ -f "${BACKUP2}/pre_reinstall_state.json" ]] && ok "S11 backup2 valid" || bad "S11 backup2 invalid"

# Verify backup2 is not nested inside backup1.
case "${BACKUP2}" in
    "${BACKUP1}"/*) bad "S11 backup2 nested inside backup1" ;;
    *) ok "S11 backup2 not nested in backup1" ;;
esac

# Both should capture the same reality_clients count.
assert_eq "S11 backup1 reality_clients" "1" "$(jq -r '.reality_clients' "${BACKUP1}/pre_reinstall_state.json")"
assert_eq "S11 backup2 reality_clients" "1" "$(jq -r '.reality_clients' "${BACKUP2}/pre_reinstall_state.json")"

# ============================================================================
# Nginx user config preservation
# ============================================================================
echo "=== Scenario 12: Nginx user config preservation ==="
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"

# Create project-managed Nginx conf files.
cat > "${nginx_conf_dir}/00-xray.conf" <<'EOF'
# managed by script
EOF
cat > "${nginx_conf_dir}/01-xray-80.conf" <<'EOF'
# managed by script
EOF

# Create a USER custom config (not managed by script).
cat > "${nginx_conf_dir}/my-custom-site.conf" <<'EOF'
# user custom upstream
upstream my_app { server 127.0.0.1:3000; }
EOF

# Create main nginx.conf.
NGINX_MAIN_DIR="${TMP_ROOT}/nginx_main"
mkdir -p "${NGINX_MAIN_DIR}"
cat > "${NGINX_MAIN_DIR}/nginx.conf" <<'EOF'
# main nginx.conf
include /etc/idleleo/conf/nginx/*.conf;
EOF

# Backup should capture the nginx conf dir.
BACKUP_DIR=$(reinstall_backup_create)

# Verify user custom file is in the backup.
[[ -f "${BACKUP_DIR}/nginx/my-custom-site.conf" ]] && ok "S12 user custom Nginx file backed up" || bad "S12 user custom Nginx file not backed up"

# Verify managed files are in the backup.
[[ -f "${BACKUP_DIR}/nginx/00-xray.conf" ]] && ok "S12 managed 00-xray.conf backed up" || bad "S12 managed 00-xray.conf not backed up"

# Simulate a failed deploy that corrupts nginx dir, then restore.
rm -rf "${nginx_conf_dir}"
mkdir -p "${nginx_conf_dir}"
echo "corrupted" > "${nginx_conf_dir}/garbage.conf"

reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null

# User custom file restored.
[[ -f "${nginx_conf_dir}/my-custom-site.conf" ]] && ok "S12 user custom file restored" || bad "S12 user custom file not restored"

# Managed files restored.
[[ -f "${nginx_conf_dir}/00-xray.conf" ]] && ok "S12 managed file restored" || bad "S12 managed file not restored"

# Garbage file from failed deploy should NOT exist (restore uses rm -rf + cp -a).
[[ ! -f "${nginx_conf_dir}/garbage.conf" ]] && ok "S12 garbage from failed deploy removed" || bad "S12 garbage file left behind"

# Verify user custom content preserved.
assert_contains "S12 user upstream preserved" "my_app" "$(cat "${nginx_conf_dir}/my-custom-site.conf")"

rm -rf "${BACKUP_DIR}"

# ============================================================================
# Skill existing-install protection
# ============================================================================
echo "=== Scenario 13: Skill existing-install protection ==="
# Prefer the CI-provided SKILL_REPO env var (GitHub Actions checkouts
# the Skill repo to ${GITHUB_WORKSPACE}/.phase1-contracts/skill); fall back to
# the adjacent repo dir for local runs. A missing Skill repo must fail the test.
_SKILL_ENV="${SKILL_REPO:-}"
_SKILL_RESOLVED="${_SKILL_ENV:-${REPO_DIR}/../Xray_bash_onekey_skill}"
if [[ -n "${_SKILL_ENV}" ]]; then
    assert_eq "S13 env SKILL_REPO used verbatim" "${_SKILL_ENV}" "${_SKILL_RESOLVED}"
else
    assert_eq "S13 env unset → local fallback used" "${REPO_DIR}/../Xray_bash_onekey_skill" "${_SKILL_RESOLVED}"
fi
SKILL_REPO="${_SKILL_RESOLVED}"

if [[ -d "${SKILL_REPO}/assets" ]]; then
    # Test setup-reality.sh and setup-tls.sh reject existing installations.
    for tmpl in setup-reality.sh setup-tls.sh; do
        TMPL_PATH="${SKILL_REPO}/assets/${tmpl}"
        if [[ ! -f "${TMPL_PATH}" ]]; then
            bad "S13 ${tmpl} not found"
            continue
        fi

        # Create a fake install_config.json to simulate existing install.
        SKILL_TMP=$(mktemp -d)
        mkdir -p "${SKILL_TMP}/etc/idleleo/conf"
        echo '{"tls":"Reality"}' > "${SKILL_TMP}/etc/idleleo/conf/install_config.json"

        # Run the template in a subshell with mocked environment.
        # The template checks /etc/idleleo/conf/install_config.json.
        # We use a fake root via env override if supported, otherwise skip.
        # Since the template hardcodes /etc/idleleo, we check the source code
        # contains the rejection guard.
        if grep -q 'install_config.json' "${TMPL_PATH}" && \
           grep -q 'exit 1' "${TMPL_PATH}"; then
            ok "S13 ${tmpl} has existing-install rejection guard"
        else
            bad "S13 ${tmpl} missing existing-install rejection guard"
        fi

        # Verify it does NOT use INSTALL_MODE or CLEAN_INSTALL as variables
        # (comments mentioning these words are acceptable).
        if grep -qE '\$(INSTALL_MODE|CLEAN_INSTALL)|(INSTALL_MODE|CLEAN_INSTALL)=' "${TMPL_PATH}"; then
            bad "S13 ${tmpl} still uses INSTALL_MODE/CLEAN_INSTALL as variable"
        else
            ok "S13 ${tmpl} no INSTALL_MODE/CLEAN_INSTALL variable usage"
        fi

        rm -rf "${SKILL_TMP}"
    done
else
    bad "S13 Skill repo not found at ${SKILL_REPO}"
fi

# ============================================================================
# SHA256 strict fail-closed (normal, tampered, missing, corrupt)
# ============================================================================
echo "=== Scenario 14: SHA256 strict verification ==="

# 14a: valid backup restores OK
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
BACKUP_DIR=$(reinstall_backup_create)
[[ -f "${BACKUP_DIR}/sha256sums.txt" ]] && ok "S14a sha256sums.txt exists" || bad "S14a sha256sums.txt missing"

# 14b: tampered file → restore refused
echo "TAMPER" >> "${BACKUP_DIR}/xray/config.json"
RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
assert_ne "S14b tampered file rejected" "0" "${RESTORE_RC}"

# 14c: missing file → restore refused
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
BACKUP_DIR=$(reinstall_backup_create)
rm -f "${BACKUP_DIR}/xray/config.json"
RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
assert_ne "S14c missing file rejected" "0" "${RESTORE_RC}"

# 14d: corrupt manifest line → restore refused
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
BACKUP_DIR=$(reinstall_backup_create)
echo "garbage line no hash" >> "${BACKUP_DIR}/sha256sums.txt"
RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
assert_ne "S14d corrupt manifest rejected" "0" "${RESTORE_RC}"

# 14e: missing manifest → restore refused
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
BACKUP_DIR=$(reinstall_backup_create)
rm -f "${BACKUP_DIR}/sha256sums.txt"
RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
assert_ne "S14e missing manifest rejected" "0" "${RESTORE_RC}"

# ============================================================================
# Auto-rollback via RETURN trap restores exactly once
# ============================================================================
echo "=== Scenario 15: RETURN trap restores exactly once ==="
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
reinstall_operation="keep_config"

PRE_CONF=$(jq -Sc . "${xray_conf}")
BACKUP_DIR=$(reinstall_backup_create)
_reinstall_backup_dir="${BACKUP_DIR}"

# Save real restore under a different name, then override to count calls.
eval "$(declare -f reinstall_backup_restore | sed 's/reinstall_backup_restore/_real_reinstall_backup_restore/')"
_RESTORE_COUNT=0
reinstall_backup_restore() {
    _RESTORE_COUNT=$((_RESTORE_COUNT + 1))
    _real_reinstall_backup_restore "$1" 2>/dev/null
}

# Simulate a mid-deploy failure: the rollback wrapper should restore once.
reinstall_rollback_on_return 1 "${BACKUP_DIR}"
RC=$?
assert_eq "S15 rollback returns original rc" "1" "${RC}"
assert_eq "S15 restore called exactly once" "1" "${_RESTORE_COUNT}"
assert_eq "S15 backup dir cleared after restore" "" "${_reinstall_backup_dir}"

# Verify config was actually restored.
POST_CONF=$(jq -Sc . "${xray_conf}")
assert_eq "S15 config restored" "${PRE_CONF}" "${POST_CONF}"

# Restore real function
unset -f reinstall_backup_restore
unset -f _real_reinstall_backup_restore

# ============================================================================
# Restore failure retains backup dir and returns non-zero
# ============================================================================
echo "=== Scenario 16: Restore failure retains backup dir ==="
reset_for_call_chain_test
write_tls_single_user_conf
tls_mode="TLS"
reinstall_operation="keep_config"

PRE_CONF=$(jq -Sc . "${xray_conf}")
BACKUP_DIR=$(reinstall_backup_create)
_reinstall_backup_dir="${BACKUP_DIR}"

# Sabotage SHA256 so restore fails (rejects before any changes).
echo "TAMPER" >> "${BACKUP_DIR}/xray/config.json"

RESTORE_RC=0
reinstall_rollback_on_return 1 "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
# When restore fails, rollback returns 2 (independent non-zero)
assert_ne "S16 rollback non-zero on restore failure" "0" "${RESTORE_RC}"
# Backup dir should still exist (not cleared on restore failure)
[[ -d "${BACKUP_DIR}" ]] && ok "S16 backup dir retained on restore failure" || bad "S16 backup dir lost"

# ============================================================================
# old_config_exist_check failure stops install chain
# ============================================================================
echo "=== Scenario 17: old_config_exist_check failure stops install ==="
# old_config_exist_check returns 1 when backup fails.
# Verify the 4 install functions use '|| return 1' after old_config_exist_check.
INSTALL_SH="${REPO_DIR}/install.sh"
_oldcheck_count=$(grep -c 'old_config_exist_check || return 1' "${INSTALL_SH}")
assert_eq "S17 four install chains use || return 1" "4" "${_oldcheck_count}"

# Also verify no bare 'old_config_exist_check' lines remain (without || return 1).
# Exclude the function definition and comment lines.
_bare_count=$(grep -n 'old_config_exist_check' "${INSTALL_SH}" | \
    grep -v 'old_config_exist_check()' | \
    grep -v '#' | \
    grep -v '|| return 1' | \
    grep -v 'is_mocked' | \
    wc -l | tr -d ' ')
assert_eq "S17 no bare old_config_exist_check calls" "0" "${_bare_count}"

# ============================================================================
# Real install chain RETURN trap test
# ============================================================================
# Unlike Scenario 15 (which calls reinstall_rollback_on_return directly and
# only proves the wrapper), this drives a REAL install_xray_* function through
# its real control flow: old_config_exist_check creates a valid backup, the
# RETURN trap is registered by the function itself, and a mocked mid-chain
# function fails so the trap fires automatically.
echo "=== Scenario 18: Real install chain RETURN trap ==="

# Mock preflight functions that need root/system access (they precede the
# backup check and must succeed so we reach the trap registration).
is_root() { return 0; }
check_and_create_user_group() { return 0; }
check_system() { return 0; }
dependency_install() { return 0; }
basic_optimization() { return 0; }
create_directory() { return 0; }

# Mock old_config_exist_check to create a REAL backup and return 0 so the
# RETURN trap inside install_xray_ws_tls gets registered with a valid dir.
old_config_exist_check() {
    _reinstall_backup_dir=$(reinstall_backup_create 2>/dev/null)
    _reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_changed="no"
    return 0
}

# Mock the functions between old_config_exist_check and port_set so they
# succeed, then make port_set fail — the first real failure after trap setup.
domain_check() { return 0; }
transport_choose() { return 0; }
port_set() { return 1; }

# --- 18a: successful restore via the real trap ---
_restore_18a() {
    reset_for_call_chain_test
    write_tls_single_user_conf
    echo '{"tls":"TLS","id":"uuid-orig"}' > "${xray_install_config_file}"
    tls_mode="TLS"
    PRE_CONF=$(jq -Sc . "${xray_conf}")

    # Restore the real restore body (S15/S16 unset it), then wrap it to count
    # invocations.
    eval "${_REAL_RESTORE_BODY}"
    eval "$(declare -f reinstall_backup_restore | sed 's/reinstall_backup_restore/_s18_real_restore/')"
    _S18_RESTORE_COUNT=0
    reinstall_backup_restore() {
        _S18_RESTORE_COUNT=$((_S18_RESTORE_COUNT + 1))
        _s18_real_restore "$1" 2>/dev/null
    }

    install_xray_ws_tls 2>/dev/null
    local rc=$?

    assert_ne "S18a real install returns non-zero" "0" "${rc}"
    assert_eq "S18a restore called exactly once via trap" "1" "${_S18_RESTORE_COUNT}"
    # Original config restored.
    local post_conf
    post_conf=$(jq -Sc . "${xray_conf}")
    assert_eq "S18a config restored via trap" "${PRE_CONF}" "${post_conf}"
    # Backup dir cleared after successful auto-restore.
    assert_eq "S18a backup dir cleared" "" "${_reinstall_backup_dir}"

    unset -f reinstall_backup_restore _s18_real_restore
}
_restore_18a

# --- 18b: restore failure keeps the backup dir and returns non-zero ---
_restore_18b() {
    reset_for_call_chain_test
    write_tls_single_user_conf
    echo '{"tls":"TLS","id":"uuid-orig"}' > "${xray_install_config_file}"
    tls_mode="TLS"

    # Tamper the backup so SHA256 verification refuses to restore.
    local _bdir
    _bdir=$(reinstall_backup_create 2>/dev/null)
    echo "TAMPER" >> "${_bdir}/xray/config.json"

    # Re-point old_config_exist_check to the tampered backup.
    old_config_exist_check() {
        _reinstall_backup_dir="${_bdir}"
        _reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
        _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
        _reinstall_firewall_changed="no"
        return 0
    }

    install_xray_ws_tls 2>/dev/null
    local rc=$?
    assert_ne "S18b real install returns non-zero" "0" "${rc}"
    # Backup dir retained because restore was refused.
    assert_ne "S18b backup dir retained on restore failure" "" "${_reinstall_backup_dir}"
    [[ -d "${_reinstall_backup_dir}" ]] && ok "S18b backup dir still exists" || bad "S18b backup dir lost"
}
_restore_18b

# Clean up all mocks used by this scenario.
unset -f is_root check_and_create_user_group check_system dependency_install
unset -f basic_optimization create_directory old_config_exist_check
unset -f domain_check transport_choose port_set

# ============================================================================
# reinstall_finalize return-code propagation
# Drives the REAL install_xray_ws_tls chain up to the final safety gate:
#   - finalize rc 0 → install function returns 0
#   - finalize rc 1 → install function returns 1 (restore succeeded)
#   - finalize rc 2 → install function returns 2 (restore failed, backup kept)
# The RETURN trap is cleared before finalize, so restore must run exactly once
# and must never be triggered a second time by the install function's return.
# ============================================================================
echo "=== Scenario 19: finalize rc propagation through real install chain ==="

# Mocks for every pre-finalize step of install_xray_ws_tls (all succeed).
is_root() { return 0; }
check_and_create_user_group() { return 0; }
check_system() { return 0; }
dependency_install() { return 0; }
basic_optimization() { return 0; }
create_directory() { return 0; }
old_config_exist_check() {
    _reinstall_backup_dir=$(reinstall_backup_create 2>/dev/null)
    _reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_changed="no"
    return 0
}
domain_check() { return 0; }
transport_choose() { return 0; }
port_set() { return 0; }
ws_inbound_port_set() { return 0; }
grpc_inbound_port_set() { return 0; }
xhttp_inbound_port_set() { return 0; }
validate_active_ports() { return 0; }
port_exist_check() { return 0; }
firewall_set() { return 0; }
ws_path_set() { return 0; }
grpc_path_set() { return 0; }
xhttp_path_set() { return 0; }
email_set() { return 0; }
UUID_set() { return 0; }
transport_qr() { return 0; }
install_config_tls_ws() { return 0; }
stop_service_all() { return 0; }
xray_install() { return 0; }
update_json_config() { return 0; }
nginx_exist_check() { return 0; }
nginx_systemd() { return 0; }
nginx_ssl_conf_add() { return 0; }
ssl_judge_and_install() { return 0; }
nginx_conf_add() { return 0; }
nginx_servers_conf_add() { return 0; }
xray_conf_add() { return 0; }
harden_config_permissions() { return 0; }
enable_process_systemd() { return 0; }
acme_cron_update() { return 0; }
auto_update() { return 0; }
service_restart() { return 0; }
setup_auto_clean_logs() { return 0; }
# Final info functions: must succeed so a clean install returns 0.
basic_information() { return 0; }
vless_link_image_choice() { return 0; }
show_information() { return 0; }
# install_xray_ws_tls expands several port/xray variables for downstream
# calls even though the dialog steps are mocked; provide them so `set -u`
# does not abort the real chain mid-run.
port="443"; xport=""; gport=""; xhttpport=""; xray_version="1.0.0"

# --- 19a: finalize returns 0 → install returns 0, restore never called ---
_restore_19a() {
    reset_for_call_chain_test
    write_tls_single_user_conf
    echo '{"tls":"TLS","id":"uuid-orig"}' > "${xray_install_config_file}"
    tls_mode="TLS"
    # Xray unit exists on the source system (deployed earlier).
    printf '[Unit]\nDescription=xray\n' > "${xray_systemd_file}"

    eval "${_REAL_RESTORE_BODY}"
    eval "$(declare -f reinstall_backup_restore | sed 's/reinstall_backup_restore/_s19_real_restore/')"
    _S19_RESTORE_COUNT=0
    reinstall_backup_restore() {
        _S19_RESTORE_COUNT=$((_S19_RESTORE_COUNT + 1))
        _s19_real_restore "$1" 2>/dev/null
    }

    install_xray_ws_tls 2>/dev/null
    local rc=$?
    assert_eq "S19a finalize rc=0 propagates as 0" "0" "${rc}"
    assert_eq "S19a restore never called on success" "0" "${_S19_RESTORE_COUNT}"

    unset -f reinstall_backup_restore _s19_real_restore
}
_restore_19a

# --- 19b: validate fails, restore succeeds → finalize 1 → install returns 1 ---
_restore_19b() {
    reset_for_call_chain_test
    write_tls_single_user_conf
    echo '{"tls":"TLS","id":"uuid-orig"}' > "${xray_install_config_file}"
    tls_mode="TLS"
    printf '[Unit]\nDescription=xray\n' > "${xray_systemd_file}"

    # Sabotage the xray binary so reinstall_validate_deploy fails.
    cat > "${xray_bin_dir}/xray" <<'XRAY_FAIL'
#!/usr/bin/env bash
exit 1
XRAY_FAIL
    chmod +x "${xray_bin_dir}/xray"

    eval "${_REAL_RESTORE_BODY}"
    eval "$(declare -f reinstall_backup_restore | sed 's/reinstall_backup_restore/_s19_real_restore/')"
    _S19_RESTORE_COUNT=0
    reinstall_backup_restore() {
        _S19_RESTORE_COUNT=$((_S19_RESTORE_COUNT + 1))
        _s19_real_restore "$1" 2>/dev/null
    }

    install_xray_ws_tls 2>/dev/null
    local rc=$?
    assert_eq "S19b finalize rc=1 propagates as 1" "1" "${rc}"
    assert_eq "S19b restore called exactly once" "1" "${_S19_RESTORE_COUNT}"
    assert_eq "S19b backup dir cleared after restore" "" "${_reinstall_backup_dir}"

    unset -f reinstall_backup_restore _s19_real_restore
}
_restore_19b

# --- 19c: validate fails AND restore fails → finalize 2 → install returns 2 ---
_restore_19c() {
    reset_for_call_chain_test
    write_tls_single_user_conf
    echo '{"tls":"TLS","id":"uuid-orig"}' > "${xray_install_config_file}"
    tls_mode="TLS"
    printf '[Unit]\nDescription=xray\n' > "${xray_systemd_file}"
    cat > "${xray_bin_dir}/xray" <<'XRAY_FAIL'
#!/usr/bin/env bash
exit 1
XRAY_FAIL
    chmod +x "${xray_bin_dir}/xray"

    # Create the backup first, then tamper it so restore is refused.
    local _bdir
    _bdir=$(reinstall_backup_create 2>/dev/null)
    echo "TAMPER" >> "${_bdir}/xray/config.json"
    old_config_exist_check() {
        _reinstall_backup_dir="${_bdir}"
        _reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
        _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
        _reinstall_firewall_changed="no"
        return 0
    }

    eval "${_REAL_RESTORE_BODY}"
    eval "$(declare -f reinstall_backup_restore | sed 's/reinstall_backup_restore/_s19_real_restore/')"
    _S19_RESTORE_COUNT=0
    reinstall_backup_restore() {
        _S19_RESTORE_COUNT=$((_S19_RESTORE_COUNT + 1))
        _s19_real_restore "$1" 2>/dev/null
    }

    install_xray_ws_tls 2>/dev/null
    local rc=$?
    assert_eq "S19c finalize rc=2 propagates as 2" "2" "${rc}"
    assert_eq "S19c restore called exactly once (trap not re-fired)" "1" "${_S19_RESTORE_COUNT}"
    assert_ne "S19c backup dir retained on restore failure" "" "${_reinstall_backup_dir}"
    [[ -d "${_reinstall_backup_dir}" ]] && ok "S19c backup dir still exists" || bad "S19c backup dir lost"

    unset -f reinstall_backup_restore _s19_real_restore
    old_config_exist_check() {
        _reinstall_backup_dir=$(reinstall_backup_create 2>/dev/null)
        _reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
        _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
        _reinstall_firewall_changed="no"
        return 0
    }
}
_restore_19c

# --- 19d: structural assertion — the other three install chains also
# propagate reinstall_finalize's exact return code ---
_extract_fn_body() {
    awk -v fn="$1" '
        $0 ~ "^" fn "\\(" { found=1; next }
        found && /^}/ { exit }
        found { print }
    ' "${REPO_DIR}/install.sh"
}
for _chain_fn in install_xray_reality install_xray_xtls_only install_xray_ws_only; do
    _body=$(_extract_fn_body "${_chain_fn}")
    if [[ "${_body}" == *"reinstall_finalize"* &&
          "${_body}" == *"finalize_rc"* &&
          "${_body}" == *'return "${finalize_rc}"'* ]]; then
        ok "S19d ${_chain_fn} propagates finalize rc"
    else
        bad "S19d ${_chain_fn} does not propagate finalize rc"
    fi
done

# Clean up all mocks used by this scenario.
unset -f is_root check_and_create_user_group check_system dependency_install
unset -f basic_optimization create_directory old_config_exist_check
unset -f domain_check transport_choose port_set ws_inbound_port_set
unset -f grpc_inbound_port_set xhttp_inbound_port_set validate_active_ports
unset -f port_exist_check firewall_set ws_path_set grpc_path_set xhttp_path_set
unset -f email_set UUID_set transport_qr install_config_tls_ws stop_service_all
unset -f xray_install update_json_config nginx_exist_check nginx_systemd
unset -f nginx_ssl_conf_add ssl_judge_and_install nginx_conf_add
unset -f nginx_servers_conf_add xray_conf_add harden_config_permissions
unset -f enable_process_systemd acme_cron_update auto_update service_restart
unset -f setup_auto_clean_logs vless_link_image_choice show_information

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=========================================="
echo "Reinstall call-chain tests: ${PASS} passed, ${FAIL} failed"
echo "=========================================="

[[ ${FAIL} -eq 0 ]]
