#!/usr/bin/env bash
# Reinstall config preservation tests.
#
# Coverage (8 scenarios per the development prompt):
#   1. TLS single-user same-mode reinstall
#   2. TLS multi-user same-mode reinstall
#   3. Reality single-user same-mode reinstall
#   4. Reality multi-user same-mode reinstall
#   5. Custom routing/outbound preservation
#   6. Custom Nginx file preservation (managed_nginx_files, not wildcard)
#   7. Consecutive reinstall twice (idempotent finalize)
#   8. Mode switch failure recovery (backup → deploy fails → restore)
#
# Verifies:
#   - User counts (multi_user via detect_multi_user_from_xray_conf)
#   - UUID preservation
#   - Reality client mapping preservation (clients array)
#   - Custom JSON field preservation (custom_routing, third_party_marker, custom_dns)
#   - Custom Nginx file preservation (managed_nginx_files array, not wildcard)
#   - Certificate fingerprint preservation (backup/restore identical content)
#   - Service state (mocked systemctl)
#   - Key leakage prevention (no secrets on stdout)
#
# Design:
#   - Runs on macOS (dev) AND Ubuntu (CI). No root, no real systemctl/xray.
#   - Sources install.sh with _TEST_MODE=1, mocks system functions.
#   - Creates temp files for xray_conf, xray_install_config_file, nginx_conf_dir, etc.
#
# Run: bash .github/test/test_reinstall_preservation.sh

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
exec() { :; }
judge() { :; }
xray_diagnose() { :; }
nginx_diagnose() { :; }
sleep() { :; }
countdown() { :; }
# Avoid bash 3.2 associative-array quirks: invalidate is a no-op; tests use jq directly.
_info_cache_invalidate() { :; }

# --- systemctl mock: unit-file aware so a missing unit behaves like real
# systemd (is-active/is-enabled return non-zero, and enable/disable/start/stop
# fail). Mocks that "always succeed" would mask the P0-2 unit-restore bug.
SYSTEMCTL_CALLS=0
SYSTEMCTL_IS_ACTIVE_XRAY_CALLS=0
SYSTEMCTL_IS_ACTIVE_NGINX_CALLS=0
SYSTEMCTL_IS_ACTIVE_RESULT=0
SYSTEMCTL_ENABLE_NGINX_CALLS=0
SYSTEMCTL_DISABLE_NGINX_CALLS=0
SYSTEMCTL_START_NGINX_CALLS=0
SYSTEMCTL_STOP_NGINX_CALLS=0
# Simulate systemd still tracking a unit after its file was deleted
# (loaded/active/enabled linger): when a unit file is absent but the matching
# STUCK flag is set, is-active/is-enabled report success like a stale systemd.
SYSTEMCTL_STUCK_XRAY=0
SYSTEMCTL_STUCK_NGINX=0
systemctl() {
    local svc=""
    case "${1:-}" in
        is-active|is-enabled)
            SYSTEMCTL_CALLS=$((SYSTEMCTL_CALLS + 1))
            svc="${3:-}"
            if [[ "${svc}" == "xray" || "${svc}" == "nginx" ]]; then
                if [[ "${svc}" == "xray" && ! -f "${xray_systemd_file}" ]]; then
                    [[ ${SYSTEMCTL_STUCK_XRAY} -eq 1 ]] || return 3
                fi
                if [[ "${svc}" == "nginx" && ! -f "${nginx_systemd_file}" ]]; then
                    [[ ${SYSTEMCTL_STUCK_NGINX} -eq 1 ]] || return 3
                fi
                if [[ "${svc}" == "xray" ]]; then
                    SYSTEMCTL_IS_ACTIVE_XRAY_CALLS=$((SYSTEMCTL_IS_ACTIVE_XRAY_CALLS + 1))
                else
                    SYSTEMCTL_IS_ACTIVE_NGINX_CALLS=$((SYSTEMCTL_IS_ACTIVE_NGINX_CALLS + 1))
                fi
                return "${SYSTEMCTL_IS_ACTIVE_RESULT}"
            fi
            return 1
            ;;
        daemon-reload) return 0 ;;
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
        ok "${name} (got: ${actual})"
    else
        bad "${name} (unexpected: ${not_expected})"
    fi
}

assert_not_contains() {
    local name="$1" unexpected="$2" actual="$3"
    if [[ "${actual}" != *"${unexpected}"* ]]; then
        ok "${name}"
    else
        bad "${name} (unexpected: ${unexpected})"
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

# Fake xray binary that always passes `run -test`.
xray_bin_dir="${TMP_ROOT}/bin"
mkdir -p "${xray_bin_dir}"
_make_fake_xray_binary() {
    cat > "${xray_bin_dir}/xray" <<'XRAY_EOF'
#!/usr/bin/env bash
exit 0
XRAY_EOF
    chmod +x "${xray_bin_dir}/xray"
}
_make_fake_xray_binary

# nginx_dir points to a non-existent path so nginx -t / is-active checks are skipped.
nginx_dir="${TMP_ROOT}/nonexistent_nginx"

# --- crontab mock: stateful via CRONTAB_FILE, with write-failure injection.
# Uses the standard `crontab -l` / `crontab -` interface (never spool files),
# mirroring what install.sh must use for ACME cron restore.
CRONTAB_FILE="${TMP_ROOT}/crontab_state.txt"
: > "${CRONTAB_FILE}"
CRONTAB_WRITE_FAIL=0
crontab() {
    case "${1:-}" in
        -l) cat "${CRONTAB_FILE}" 2>/dev/null; return 0 ;;
        -)
            [[ ${CRONTAB_WRITE_FAIL} -eq 1 ]] && return 1
            # Buffer stdin first: a real `crontab -` only commits at EOF, but a
            # naive `cat > file` truncates immediately, racing with a concurrent
            # `crontab -l` on the other side of a pipe.
            local _cr_buf
            _cr_buf=$(cat)
            if [[ -n "${_cr_buf}" ]]; then
                printf '%s\n' "${_cr_buf}" > "${CRONTAB_FILE}"
            else
                : > "${CRONTAB_FILE}"
            fi
            return 0
            ;;
        *) return 0 ;;
    esac
}

# --- reset before each scenario ---
reset_for_reinstall_test() {
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
    info_extraction_all="{}"

    SYSTEMCTL_CALLS=0
    SYSTEMCTL_IS_ACTIVE_XRAY_CALLS=0
    SYSTEMCTL_IS_ACTIVE_NGINX_CALLS=0
    SYSTEMCTL_IS_ACTIVE_RESULT=0
    SYSTEMCTL_ENABLE_NGINX_CALLS=0
    SYSTEMCTL_DISABLE_NGINX_CALLS=0
    SYSTEMCTL_START_NGINX_CALLS=0
    SYSTEMCTL_STOP_NGINX_CALLS=0
    SYSTEMCTL_STUCK_XRAY=0
    SYSTEMCTL_STUCK_NGINX=0

    _make_fake_xray_binary
}

# --- xray_conf writers ---
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
                    {"id": "uuid-tls-single-SECRET", "level": 0, "email": "user1@example.com"}
                ],
                "decryption": "none"
            },
            "streamSettings": {"network": "ws", "security": "none"}
        }
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF
}

write_tls_multi_user_conf() {
    cat > "${xray_conf}" <<'EOF'
{
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "tag": "VLESS-ws-in",
            "settings": {
                "clients": [
                    {"id": "uuid-tls-multi-1-SECRET", "level": 0, "email": "user1@example.com"},
                    {"id": "uuid-tls-multi-2-SECRET", "level": 0, "email": "user2@example.com"}
                ],
                "decryption": "none"
            },
            "streamSettings": {"network": "ws", "security": "none"}
        }
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}]
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
                    {"id": "uuid-reality-single-SECRET", "flow": "xtls-rprx-vision", "level": 0, "email": "user1@example.com"}
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
    "outbounds": [{"protocol": "freedom", "tag": "direct"}]
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
                    {"id": "uuid-reality-1-SECRET", "flow": "xtls-rprx-vision", "level": 0, "email": "user1@example.com"},
                    {"id": "uuid-reality-2-SECRET", "flow": "xtls-rprx-vision", "level": 0, "email": "user2@example.com"},
                    {"id": "uuid-reality-3-SECRET", "flow": "xtls-rprx-vision", "level": 0, "email": "user3@example.com"}
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
    "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF
}

# ============================================================================
# Scenario 1: TLS single-user same-mode reinstall
# ============================================================================
echo "--- Scenario 1: TLS single-user same-mode reinstall ---"
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"

MULTI=$(detect_multi_user_from_xray_conf)
assert_eq "TLS single multi_user" "no" "${MULTI}"

# count_reality_clients_in_xray_conf counts ALL vless clients across inbounds
# (the function name is historical; it tracks total vless client count).
CLIENTS=$(count_reality_clients_in_xray_conf)
assert_eq "TLS single reality_clients" "1" "${CLIENTS}"

# _install_config_merge_write updates UUID but preserves custom fields.
echo '{"tls":"TLS","id":"uuid-tls-single-SECRET","custom_routing":"my-route","third_party_marker":"tool-X"}' > "${xray_install_config_file}"
info_extraction_all=$(jq -rc . "${xray_install_config_file}")

NEW_FIELDS=$(mktemp)
echo '{"id":"new-uuid-tls","shell_mode":"Nginx+ws+TLS"}' > "${NEW_FIELDS}"
_install_config_merge_write "${NEW_FIELDS}"
rm -f "${NEW_FIELDS}"

assert_eq "TLS single UUID updated" "new-uuid-tls" "$(jq -rc '.id' "${xray_install_config_file}")"
assert_eq "TLS single custom_routing preserved" "my-route" "$(jq -rc '.custom_routing' "${xray_install_config_file}")"
assert_eq "TLS single third_party_marker preserved" "tool-X" "$(jq -rc '.third_party_marker' "${xray_install_config_file}")"

# Backup captures pre-reinstall state.
BACKUP_DIR=$(reinstall_backup_create)
[[ -f "${BACKUP_DIR}/install_config.json" ]] && ok "TLS single backup has install_config.json" || bad "TLS single backup missing install_config.json"
[[ -f "${BACKUP_DIR}/pre_reinstall_state.json" ]] && ok "TLS single backup has pre_reinstall_state.json" || bad "TLS single backup missing pre_reinstall_state.json"
assert_eq "TLS single backup multi_user" "no" "$(jq -r '.multi_user' "${BACKUP_DIR}/pre_reinstall_state.json")"

# No secret leak from backup_create stdout.
CAPTURED=$(reinstall_backup_create 2>/dev/null)
assert_not_contains "TLS single no UUID leak" "uuid-tls-single-SECRET" "${CAPTURED}"

# ============================================================================
# Scenario 2: TLS multi-user same-mode reinstall
# ============================================================================
echo "--- Scenario 2: TLS multi-user same-mode reinstall ---"
reset_for_reinstall_test
write_tls_multi_user_conf
tls_mode="TLS"

MULTI=$(detect_multi_user_from_xray_conf)
assert_eq "TLS multi multi_user" "yes" "${MULTI}"

CLIENTS=$(count_reality_clients_in_xray_conf)
assert_eq "TLS multi reality_clients" "2" "${CLIENTS}"

# Multi-user preservation: custom fields survive merge.
echo '{"tls":"TLS","custom_routing":"multi-route","third_party_marker":"multi-tool"}' > "${xray_install_config_file}"
info_extraction_all=$(jq -rc . "${xray_install_config_file}")

NEW_FIELDS=$(mktemp)
echo '{"shell_mode":"Nginx+ws+TLS","port":443}' > "${NEW_FIELDS}"
_install_config_merge_write "${NEW_FIELDS}"
rm -f "${NEW_FIELDS}"

assert_eq "TLS multi custom_routing preserved" "multi-route" "$(jq -rc '.custom_routing' "${xray_install_config_file}")"
assert_eq "TLS multi third_party_marker preserved" "multi-tool" "$(jq -rc '.third_party_marker' "${xray_install_config_file}")"

# Backup captures multi_user=yes.
BACKUP_DIR=$(reinstall_backup_create)
assert_eq "TLS multi backup multi_user" "yes" "$(jq -r '.multi_user' "${BACKUP_DIR}/pre_reinstall_state.json")"

# ============================================================================
# Scenario 3: Reality single-user same-mode reinstall
# ============================================================================
echo "--- Scenario 3: Reality single-user same-mode reinstall ---"
reset_for_reinstall_test
write_reality_single_user_conf
tls_mode="Reality"

MULTI=$(detect_multi_user_from_xray_conf)
assert_eq "Reality single multi_user" "no" "${MULTI}"

CLIENTS=$(count_reality_clients_in_xray_conf)
assert_eq "Reality single reality_clients" "1" "${CLIENTS}"

# Preserve Reality client mapping (UUID, privateKey, custom_routing).
echo '{"tls":"Reality","id":"uuid-reality-single-SECRET","privateKey":"priv-key-SECRET","publicKey":"pub-key-SECRET","shortIds":"short-id-SECRET","custom_routing":"reality-route"}' > "${xray_install_config_file}"
info_extraction_all=$(jq -rc . "${xray_install_config_file}")

NEW_FIELDS=$(mktemp)
echo '{"shell_mode":"Reality","reality_add_more":"off"}' > "${NEW_FIELDS}"
_install_config_merge_write "${NEW_FIELDS}"
rm -f "${NEW_FIELDS}"

assert_eq "Reality single UUID preserved" "uuid-reality-single-SECRET" "$(jq -rc '.id' "${xray_install_config_file}")"
assert_eq "Reality single privateKey preserved" "priv-key-SECRET" "$(jq -rc '.privateKey' "${xray_install_config_file}")"
assert_eq "Reality single custom_routing preserved" "reality-route" "$(jq -rc '.custom_routing' "${xray_install_config_file}")"

# Backup captures reality_clients=1.
BACKUP_DIR=$(reinstall_backup_create)
assert_eq "Reality single backup reality_clients" "1" "$(jq -r '.reality_clients' "${BACKUP_DIR}/pre_reinstall_state.json")"

# ============================================================================
# Scenario 4: Reality multi-user same-mode reinstall
# ============================================================================
echo "--- Scenario 4: Reality multi-user same-mode reinstall ---"
reset_for_reinstall_test
write_reality_multi_user_conf
tls_mode="Reality"

MULTI=$(detect_multi_user_from_xray_conf)
assert_eq "Reality multi multi_user" "yes" "${MULTI}"

CLIENTS=$(count_reality_clients_in_xray_conf)
assert_eq "Reality multi reality_clients" "3" "${CLIENTS}"

# Reality client mapping preservation: all 3 UUIDs survive backup.
BACKUP_DIR=$(reinstall_backup_create)
assert_eq "Reality multi backup reality_clients" "3" "$(jq -r '.reality_clients' "${BACKUP_DIR}/pre_reinstall_state.json")"

# Verify all 3 UUIDs preserved in the xray_conf (client mapping intact).
UUID1=$(jq -r '.inbounds[0].settings.clients[0].id' "${xray_conf}")
UUID2=$(jq -r '.inbounds[0].settings.clients[1].id' "${xray_conf}")
UUID3=$(jq -r '.inbounds[0].settings.clients[2].id' "${xray_conf}")
assert_eq "Reality multi UUID1 preserved" "uuid-reality-1-SECRET" "${UUID1}"
assert_eq "Reality multi UUID2 preserved" "uuid-reality-2-SECRET" "${UUID2}"
assert_eq "Reality multi UUID3 preserved" "uuid-reality-3-SECRET" "${UUID3}"

# Verify client emails (mapping) preserved.
EMAIL1=$(jq -r '.inbounds[0].settings.clients[0].email' "${xray_conf}")
EMAIL3=$(jq -r '.inbounds[0].settings.clients[2].email' "${xray_conf}")
assert_eq "Reality multi email1 preserved" "user1@example.com" "${EMAIL1}"
assert_eq "Reality multi email3 preserved" "user3@example.com" "${EMAIL3}"

# ============================================================================
# Scenario 5: Custom routing/outbound preservation
# ============================================================================
echo "--- Scenario 5: Custom routing/outbound preservation ---"
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"

# install_config with nested custom routing, third-party marker, custom DNS.
echo '{"tls":"TLS","id":"uuid-orig","custom_routing":{"rules":[{"domain":["geosite:custom"],"outboundTag":"custom-out"}]},"third_party_marker":"tool-Y","custom_dns":{"servers":["1.2.3.4"]}}' > "${xray_install_config_file}"
info_extraction_all=$(jq -rc . "${xray_install_config_file}")

NEW_FIELDS=$(mktemp)
echo '{"id":"uuid-new","shell_mode":"Nginx+ws+TLS","port":443}' > "${NEW_FIELDS}"
_install_config_merge_write "${NEW_FIELDS}"
rm -f "${NEW_FIELDS}"

# New field overwrote old; unknown top-level fields preserved.
assert_eq "Custom routing UUID updated" "uuid-new" "$(jq -rc '.id' "${xray_install_config_file}")"
assert_eq "Custom routing outboundTag preserved" "custom-out" "$(jq -rc '.custom_routing.rules[0].outboundTag' "${xray_install_config_file}")"
assert_eq "Third party marker preserved" "tool-Y" "$(jq -rc '.third_party_marker' "${xray_install_config_file}")"
assert_eq "Custom DNS preserved" "1.2.3.4" "$(jq -rc '.custom_dns.servers[0]' "${xray_install_config_file}")"

# ============================================================================
# Scenario 6: Custom Nginx file preservation
# ============================================================================
echo "--- Scenario 6: Custom Nginx file preservation ---"
reset_for_reinstall_test

# managed_nginx_files array must contain the expected files (not a wildcard).
assert_eq "managed_nginx_files count" "5" "${#managed_nginx_files[@]}"
assert_eq "managed_nginx_files[0]" "00-xray.conf" "${managed_nginx_files[0]}"
assert_eq "managed_nginx_files[1]" "01-xray-80.conf" "${managed_nginx_files[1]}"
assert_eq "managed_nginx_files[2]" "02-xray-server.conf" "${managed_nginx_files[2]}"
assert_eq "managed_nginx_files[3]" "03-isolate.conf" "${managed_nginx_files[3]}"
assert_eq "managed_nginx_files[4]" "03-decoy.conf" "${managed_nginx_files[4]}"

# Create managed files + custom user files in nginx_conf_dir.
for f in "${managed_nginx_files[@]}"; do
    echo "managed content for ${f}" > "${nginx_conf_dir}/${f}"
done
echo "custom user site config" > "${nginx_conf_dir}/user-site.conf"
echo "custom stream config" > "${nginx_conf_dir}/99-user-stream.conf"

# Simulate the nginx_exist_check deletion loop (install.sh lines 3377-3380):
#   for _managed_file in "${managed_nginx_files[@]}"; do
#       rm -f "${nginx_conf_dir}/${_managed_file}"
#   done
# Only managed files are removed; user-added files are preserved.
local_managed_file=""
for local_managed_file in "${managed_nginx_files[@]}"; do
    rm -f "${nginx_conf_dir}/${local_managed_file}"
done

# Managed files removed.
for f in "${managed_nginx_files[@]}"; do
    if [[ ! -f "${nginx_conf_dir}/${f}" ]]; then
        ok "managed file ${f} removed"
    else
        bad "managed file ${f} should have been removed"
    fi
done

# Custom files preserved (NOT wildcard-deleted).
if [[ -f "${nginx_conf_dir}/user-site.conf" ]]; then
    ok "custom user-site.conf preserved"
else
    bad "custom user-site.conf was deleted (should be preserved)"
fi
if [[ -f "${nginx_conf_dir}/99-user-stream.conf" ]]; then
    ok "custom 99-user-stream.conf preserved"
else
    bad "custom 99-user-stream.conf was deleted (should be preserved)"
fi
assert_eq "user-site.conf content unchanged" "custom user site config" "$(cat "${nginx_conf_dir}/user-site.conf")"

# ============================================================================
# Scenario 7: Consecutive reinstall twice
# ============================================================================
echo "--- Scenario 7: Consecutive reinstall twice ---"
reset_for_reinstall_test
write_reality_multi_user_conf
tls_mode="Reality"
# The Xray unit exists on the source system (deployed earlier), so
# reinstall_validate_deploy sees xray as active via the mock.
printf '[Unit]\nDescription=xray\n' > "${xray_systemd_file}"

# First reinstall backup.
BACKUP1=$(reinstall_backup_create)
[[ -f "${BACKUP1}/pre_reinstall_state.json" ]] && ok "First backup created" || bad "First backup failed"

# Second reinstall backup (consecutive). Even if the timestamp matches and
# mkdir -p reuses the dir, the call must still succeed and produce a valid state.
BACKUP2=$(reinstall_backup_create)
[[ -f "${BACKUP2}/pre_reinstall_state.json" ]] && ok "Second backup created" || bad "Second backup failed"

# Both backups captured the same reality_clients count.
assert_eq "First backup reality_clients" "3" "$(jq -r '.reality_clients' "${BACKUP1}/pre_reinstall_state.json")"
assert_eq "Second backup reality_clients" "3" "$(jq -r '.reality_clients' "${BACKUP2}/pre_reinstall_state.json")"

# reinstall_finalize is idempotent: first call processes, second is a no-op.
_reinstall_backup_dir="${BACKUP1}"
if reinstall_finalize 2>/dev/null; then
    ok "First reinstall_finalize succeeded"
else
    bad "First reinstall_finalize should succeed"
fi
# _reinstall_backup_dir must be cleared after finalize.
assert_eq "backup_dir cleared after finalize" "" "${_reinstall_backup_dir}"

# Second call is a no-op (returns 0).
if reinstall_finalize 2>/dev/null; then
    ok "Second reinstall_finalize is no-op (returns 0)"
else
    bad "Second reinstall_finalize should be no-op"
fi

# ============================================================================
# Scenario 8: Mode switch failure recovery
# ============================================================================
echo "--- Scenario 8: Mode switch failure recovery ---"
reset_for_reinstall_test
write_reality_multi_user_conf
tls_mode="Reality"

# Snapshot before mode-switch attempt.
BACKUP_DIR=$(reinstall_backup_create)
_reinstall_backup_dir="${BACKUP_DIR}"

assert_eq "Mode switch backup multi_user" "yes" "$(jq -r '.multi_user' "${BACKUP_DIR}/pre_reinstall_state.json")"
assert_eq "Mode switch backup reality_clients" "3" "$(jq -r '.reality_clients' "${BACKUP_DIR}/pre_reinstall_state.json")"

# Save original xray_conf for content comparison.
ORIG_XRAY_CONF=$(cat "${xray_conf}")

# Simulate deploy failure: remove the fake xray binary so validate_deploy fails.
rm -f "${xray_bin_dir}/xray"

# reinstall_finalize must detect failure, restore backup, return non-zero.
if reinstall_finalize 2>/dev/null; then
    bad "Mode switch reinstall_finalize should fail (validate_deploy failure)"
else
    ok "Mode switch reinstall_finalize returns non-zero on failure"
fi

# Backup was restored: xray_conf content must match original.
RESTORED_XRAY_CONF=$(cat "${xray_conf}")
if [[ "${ORIG_XRAY_CONF}" == "${RESTORED_XRAY_CONF}" ]]; then
    ok "Mode switch xray_conf restored after failure"
else
    bad "Mode switch xray_conf not restored"
fi

# _reinstall_backup_dir cleared after finalize.
assert_eq "Mode switch backup_dir cleared" "" "${_reinstall_backup_dir}"

# Multi-user state preserved after restore.
MULTI=$(detect_multi_user_from_xray_conf)
assert_eq "Mode switch multi_user preserved after restore" "yes" "${MULTI}"
CLIENTS=$(count_reality_clients_in_xray_conf)
assert_eq "Mode switch reality_clients preserved after restore" "3" "${CLIENTS}"

# No secret leak during failure recovery.
RESTORE_OUTPUT=$(reinstall_backup_restore "${BACKUP_DIR}" 2>&1)
assert_not_contains "Mode switch no privateKey leak" "priv-key-SECRET" "${RESTORE_OUTPUT}"
assert_not_contains "Mode switch no UUID leak" "uuid-reality" "${RESTORE_OUTPUT}"

# ============================================================================
# Scenario 9: unit restore per manifest (P0-2)
# Source system: xray.service exists, nginx.service does NOT. A failed deploy
# creates a NEW nginx.service (and starts it). Rollback must delete the nginx
# unit file, must stop the just-created unit exactly once as cleanup, and must
# NEVER enable/disable/start it to re-adopt a unit the source system never had
# (those would wrongly re-create it or fail for a missing unit).
echo "--- Scenario 9: unit restore (xray existed, nginx absent) ---"
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
# Source system: xray.service exists, nginx.service does NOT.
printf '[Unit]\nDescription=xray\n' > "${xray_systemd_file}"
rm -f "${nginx_systemd_file}"

BACKUP_DIR=$(reinstall_backup_create 2>/dev/null)
assert_eq "S9 backup: xray.service existed" "true" "$(jq -r '.files["xray.service"]' "${BACKUP_DIR}/pre_reinstall_state.json")"
assert_eq "S9 backup: nginx.service absent" "false" "$(jq -r '.files["nginx.service"]' "${BACKUP_DIR}/pre_reinstall_state.json")"

# Failed deploy creates a NEW nginx unit (and would try to start it).
printf '[Unit]\nDescription=nginx\n' > "${nginx_systemd_file}"

RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
assert_eq "S9 restore returns 0" "0" "${RESTORE_RC}"
[[ -f "${xray_systemd_file}" ]] && ok "S9 xray unit restored" || bad "S9 xray unit missing"
[[ ! -f "${nginx_systemd_file}" ]] && ok "S9 nginx unit deleted" || bad "S9 nginx unit left behind"
assert_eq "S9 no 'disable nginx' call" "0" "${SYSTEMCTL_DISABLE_NGINX_CALLS}"
assert_eq "S9 deploy-created nginx stopped exactly once (cleanup)" "1" "${SYSTEMCTL_STOP_NGINX_CALLS}"
assert_eq "S9 no 'start nginx' call" "0" "${SYSTEMCTL_START_NGINX_CALLS}"
assert_eq "S9 no 'enable nginx' call" "0" "${SYSTEMCTL_ENABLE_NGINX_CALLS}"

# --- S9b: systemd still tracking the deleted unit → restore must FAIL ---
echo "--- Scenario 9b: stuck nginx unit (systemd linger) → restore fails ---"
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
printf '[Unit]\nDescription=xray\n' > "${xray_systemd_file}"
BACKUP_DIR=$(reinstall_backup_create 2>/dev/null)

# Failed deploy creates the nginx unit; restore will delete the file, but
# systemd (mock) still reports nginx as active/enabled afterwards.
printf '[Unit]\nDescription=nginx\n' > "${nginx_systemd_file}"
SYSTEMCTL_STUCK_NGINX=1
RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
SYSTEMCTL_STUCK_NGINX=0
assert_ne "S9b restore fails when systemd lingers on deleted unit" "0" "${RESTORE_RC}"
[[ ! -f "${nginx_systemd_file}" ]] && ok "S9b nginx unit file deleted" || bad "S9b nginx unit file left behind"
[[ -d "${BACKUP_DIR}" ]] && ok "S9b backup retained on failure" || bad "S9b backup dir lost"
rm -rf "${BACKUP_DIR}"

# ============================================================================
# Additional: reinstall_verify_preservation detects count change
# ============================================================================
echo "--- Additional: reinstall_verify_preservation detects count change ---"
reset_for_reinstall_test
write_reality_multi_user_conf
tls_mode="Reality"

BACKUP_DIR=$(reinstall_backup_create)
# Simulate a deploy that lost clients (3 -> 1).
write_reality_single_user_conf

if reinstall_verify_preservation "${BACKUP_DIR}" 2>/dev/null; then
    bad "verify_preservation should fail (3 -> 1 clients)"
else
    ok "verify_preservation detects client count change (3 -> 1)"
fi

# Multi-user state changed from yes to no.
MULTI=$(detect_multi_user_from_xray_conf)
assert_eq "After client loss multi_user" "no" "${MULTI}"

# verify_preservation is a no-op when no backup state file exists.
if reinstall_verify_preservation "${TMP_ROOT}/nonexistent_backup" 2>/dev/null; then
    ok "verify_preservation no-op on missing backup"
else
    bad "verify_preservation should return 0 on missing backup"
fi

# ============================================================================
# Additional: reinstall_validate_deploy service state (mocked systemctl)
# ============================================================================
echo "--- Additional: reinstall_validate_deploy service state ---"
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
# Unit file must exist so the mock reports the configured active state.
printf '[Unit]\nDescription=xray\n' > "${xray_systemd_file}"

# validate_deploy should succeed: xray binary passes, systemctl says active.
if reinstall_validate_deploy 2>/dev/null; then
    ok "validate_deploy succeeds (xray active)"
else
    bad "validate_deploy should succeed with mocked active xray"
fi
# systemctl is-active --quiet xray was called.
assert_eq "validate_deploy checked xray active" "1" "${SYSTEMCTL_IS_ACTIVE_XRAY_CALLS}"
# TLS mode but nginx_dir/sbin/nginx does not exist: nginx is-active NOT checked.
assert_eq "validate_deploy did not check nginx (no nginx binary)" "0" "${SYSTEMCTL_IS_ACTIVE_NGINX_CALLS}"

# validate_deploy fails when systemctl says xray is inactive.
SYSTEMCTL_IS_ACTIVE_RESULT=3
SYSTEMCTL_IS_ACTIVE_XRAY_CALLS=0
if reinstall_validate_deploy 2>/dev/null; then
    bad "validate_deploy should fail when xray is inactive"
else
    ok "validate_deploy fails when xray is inactive"
fi
SYSTEMCTL_IS_ACTIVE_RESULT=0

# ============================================================================
# Additional: Certificate fingerprint preservation
# ============================================================================
echo "--- Additional: Certificate fingerprint preservation ---"
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"

CERT_CONTENT="-----BEGIN CERTIFICATE----- FAKE_CERT_FINGERPRINT_12345 -----END CERTIFICATE-----"
KEY_CONTENT="-----BEGIN PRIVATE KEY----- FAKE_KEY_FINGERPRINT_67890 -----END PRIVATE KEY-----"
echo "${CERT_CONTENT}" > "${ssl_chainpath}/xray.crt"
echo "${KEY_CONTENT}" > "${ssl_chainpath}/xray.key"

BACKUP_DIR=$(reinstall_backup_create)

# Cert files backed up.
[[ -f "${BACKUP_DIR}/cert/xray.crt" ]] && ok "Cert backed up" || bad "Cert not backed up"
[[ -f "${BACKUP_DIR}/cert/xray.key" ]] && ok "Key backed up" || bad "Key not backed up"

# Simulate deploy failure: wipe cert files.
rm -f "${ssl_chainpath}/xray.crt" "${ssl_chainpath}/xray.key"

# Restore.
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null

# Cert files restored with identical content (fingerprint preserved).
RESTORED_CERT=$(cat "${ssl_chainpath}/xray.crt")
RESTORED_KEY=$(cat "${ssl_chainpath}/xray.key")
assert_eq "Cert fingerprint preserved" "${CERT_CONTENT}" "${RESTORED_CERT}"
assert_eq "Key fingerprint preserved" "${KEY_CONTENT}" "${RESTORED_KEY}"

# ============================================================================
# Scenario 10: backup metadata fail-closed (P0-6)
# Any failure while writing/validating the state manifest or checksum list
# must delete the incomplete backup, return 1 and echo nothing.
# ============================================================================
echo "--- Scenario 10: backup metadata fail-closed ---"

# --- 10a: manifest write failure (target path blocked) ---
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
echo '{"tls":"TLS","id":"uuid-orig"}' > "${xray_install_config_file}"
_FC_DIR="${idleleo_dir}/backup/reinstall-fixed"
mkdir -p "${_FC_DIR}/pre_reinstall_state.json"
mktemp() {
    mkdir -p "${_FC_DIR}"
    echo "${_FC_DIR}"
}
_FC_OUT=""
_FC_RC=0
_FC_OUT=$(reinstall_backup_create 2>/dev/null) || _FC_RC=$?
unset -f mktemp
assert_ne "S10a manifest write fail: backup_create non-zero" "0" "${_FC_RC}"
assert_eq "S10a manifest write fail: no backup dir echoed" "" "${_FC_OUT}"
[[ ! -e "${_FC_DIR}" ]] && ok "S10a manifest write fail: incomplete backup deleted" || bad "S10a manifest write fail: backup dir retained"

# --- 10b: manifest JSON validation failure (corrupt) ---
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
jq() {
    if [[ "${1:-}" == "empty" ]]; then
        return 1
    fi
    command jq "$@"
}
_FC_OUT=""
_FC_RC=0
_FC_OUT=$(reinstall_backup_create 2>/dev/null) || _FC_RC=$?
unset -f jq
assert_ne "S10b corrupt manifest: backup_create non-zero" "0" "${_FC_RC}"
assert_eq "S10b corrupt manifest: no backup dir echoed" "" "${_FC_OUT}"
_FC_LEFTOVER=$(find "${idleleo_dir}/backup" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
assert_eq "S10b corrupt manifest: incomplete backup deleted" "0" "${_FC_LEFTOVER}"

# --- 10c: checksum generation failure ---
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
find() { return 1; }
_FC_OUT=""
_FC_RC=0
_FC_OUT=$(reinstall_backup_create 2>/dev/null) || _FC_RC=$?
unset -f find
assert_ne "S10c checksum gen fail: backup_create non-zero" "0" "${_FC_RC}"
assert_eq "S10c checksum gen fail: no backup dir echoed" "" "${_FC_OUT}"
_FC_LEFTOVER=$(find "${idleleo_dir}/backup" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
assert_eq "S10c checksum gen fail: incomplete backup deleted" "0" "${_FC_LEFTOVER}"

# --- 10d: empty checksum list ---
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
find() { return 0; }
_FC_OUT=""
_FC_RC=0
_FC_OUT=$(reinstall_backup_create 2>/dev/null) || _FC_RC=$?
unset -f find
assert_ne "S10d empty checksums: backup_create non-zero" "0" "${_FC_RC}"
assert_eq "S10d empty checksums: no backup dir echoed" "" "${_FC_OUT}"
_FC_LEFTOVER=$(find "${idleleo_dir}/backup" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
assert_eq "S10d empty checksums: incomplete backup deleted" "0" "${_FC_LEFTOVER}"

# ============================================================================
# Scenario 11: ACME cron bidirectional restore (P0-4)
# yes → restore the script-managed task (no duplicates); no → remove a task
# the failed deploy added. User crontab lines are always preserved, and the
# standard `crontab -l` / `crontab -` interface is used (never spool files).
# ============================================================================
echo "--- Scenario 11: ACME cron bidirectional restore ---"
FAKE_HOME="${TMP_ROOT}/fakehome"
mkdir -p "${FAKE_HOME}/.acme.sh"
touch "${FAKE_HOME}/.acme.sh/acme.sh"

# --- 11a: was yes → deploy deleted the line → restored, no duplicates ---
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
old_tls_mode="TLS"
printf '%s\n' "0 3 * * * bash /usr/local/bin/ssl_update.sh" "30 4 * * * user-other-job" > "${CRONTAB_FILE}"

BACKUP_DIR=$(
    HOME="${FAKE_HOME}"
    reinstall_backup_create 2>/dev/null
)
assert_eq "S11a backup acme_cron=yes" "yes" "$(jq -r '.acme_cron' "${BACKUP_DIR}/pre_reinstall_state.json")"
[[ -f "${BACKUP_DIR}/acme_cron_line.txt" ]] && ok "S11a cron line backed up" || bad "S11a cron line not backed up"

# Failed deploy removed the ssl_update.sh line (user job stays).
printf '%s\n' "30 4 * * * user-other-job" > "${CRONTAB_FILE}"

RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
assert_eq "S11a restore returns 0" "0" "${RESTORE_RC}"
assert_eq "S11a ssl_update.sh count" "1" "$(grep -c "ssl_update.sh" "${CRONTAB_FILE}" 2>/dev/null || true)"
grep -q "user-other-job" "${CRONTAB_FILE}" && ok "S11a user cron preserved" || bad "S11a user cron lost"

# Restore again → must NOT duplicate.
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null
assert_eq "S11a no duplicate on re-restore" "1" "$(grep -c "ssl_update.sh" "${CRONTAB_FILE}" 2>/dev/null || true)"
rm -rf "${BACKUP_DIR}"

# --- 11b: was no → deploy added the line → removed, user jobs preserved ---
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
old_tls_mode="TLS"
printf '%s\n' "30 4 * * * user-other-job" > "${CRONTAB_FILE}"

BACKUP_DIR=$(
    HOME="${FAKE_HOME}"
    reinstall_backup_create 2>/dev/null
)
assert_eq "S11b backup acme_cron=no" "no" "$(jq -r '.acme_cron' "${BACKUP_DIR}/pre_reinstall_state.json")"

# Failed deploy ADDED the script-managed task.
printf '%s\n' "0 3 * * * bash /usr/local/bin/ssl_update.sh" "30 4 * * * user-other-job" > "${CRONTAB_FILE}"

RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
assert_eq "S11b restore returns 0" "0" "${RESTORE_RC}"
if grep -q "ssl_update.sh" "${CRONTAB_FILE}"; then
    bad "S11b ssl_update.sh still present after restore"
else
    ok "S11b ssl_update.sh removed"
fi
grep -q "user-other-job" "${CRONTAB_FILE}" && ok "S11b user cron preserved" || bad "S11b user cron lost"
rm -rf "${BACKUP_DIR}"

# --- 11c: was no, deploy added ONLY the managed line (last-line removal) ---
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
old_tls_mode="TLS"
: > "${CRONTAB_FILE}"

BACKUP_DIR=$(
    HOME="${FAKE_HOME}"
    reinstall_backup_create 2>/dev/null
)
printf '%s\n' "0 3 * * * bash /usr/local/bin/ssl_update.sh" > "${CRONTAB_FILE}"

RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
assert_eq "S11c last-line removal returns 0" "0" "${RESTORE_RC}"
[[ ! -s "${CRONTAB_FILE}" ]] && ok "S11c crontab emptied after removal" || bad "S11c crontab not emptied"
rm -rf "${BACKUP_DIR}"

# --- 11d: `crontab -` write failure → restore returns non-zero ---
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"
old_tls_mode="TLS"
printf '%s\n' "0 3 * * * bash /usr/local/bin/ssl_update.sh" > "${CRONTAB_FILE}"

BACKUP_DIR=$(
    HOME="${FAKE_HOME}"
    reinstall_backup_create 2>/dev/null
)
assert_eq "S11d backup acme_cron=yes" "yes" "$(jq -r '.acme_cron' "${BACKUP_DIR}/pre_reinstall_state.json")"
: > "${CRONTAB_FILE}"

CRONTAB_WRITE_FAIL=1
RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
CRONTAB_WRITE_FAIL=0
assert_ne "S11d restore non-zero when crontab write fails" "0" "${RESTORE_RC}"
[[ -d "${BACKUP_DIR}" ]] && ok "S11d backup retained on failure" || bad "S11d backup dir lost"
rm -rf "${BACKUP_DIR}"

# ============================================================================
# Scenario 12: firewall reverse-failure propagation (P0-3)
# Forward adds the first rule, fails on the second; the immediate new→old
# reverse ALSO fails → state must stay "pending", the transaction returns
# non-zero, and the global restore retries the reverse. When the retry fails
# too, restore returns non-zero and keeps the backup dir.
# ============================================================================
echo "--- Scenario 12: firewall reverse failure → pending → global retry ---"
reset_for_reinstall_test
write_tls_single_user_conf
tls_mode="TLS"

IPTABLES_RULES_FILE="${TMP_ROOT}/iptables_rules.txt"
: > "${IPTABLES_RULES_FILE}"
iptables() {
    local op="$1"
    local chain="$2"
    shift 2
    local proto="" port="" sport="" iface="" range=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p) proto="$2"; shift 2 ;;
            --dport)
                port="$2"
                if [[ "${port}" == *:* ]]; then range="${port}"; port=""; fi
                shift 2 ;;
            --sport) sport="$2"; shift 2 ;;
            -i|-o) iface="$2"; shift 2 ;;
            -j) shift 2 ;;
            *) shift ;;
        esac
    done
    local rule_key
    if [[ -n "${iface}" ]]; then
        rule_key="${chain}:${iface}"
    elif [[ -n "${range}" ]]; then
        rule_key="${chain}:${proto}:${range}"
    elif [[ -n "${sport}" ]]; then
        rule_key="${chain}:${proto}:sport:${sport}"
    else
        rule_key="${chain}:${proto}:${port}"
    fi
    case "${op}" in
        -C)
            grep -qxF "${rule_key}" "${IPTABLES_RULES_FILE}" 2>/dev/null
            return $?
            ;;
        -A|-I)
            if grep -qxF "${rule_key}" "${IPTABLES_RULES_FILE}" 2>/dev/null; then
                return 0
            fi
            echo "${rule_key}" >> "${IPTABLES_RULES_FILE}"
            return 0
            ;;
        -D)
            if grep -qxF "${rule_key}" "${IPTABLES_RULES_FILE}" 2>/dev/null; then
                local tmp
                tmp=$(grep -vxF "${rule_key}" "${IPTABLES_RULES_FILE}" || true)
                printf '%s\n' "${tmp}" > "${IPTABLES_RULES_FILE}"
                return 0
            fi
            return 1
            ;;
    esac
    return 0
}

# Old managed state: 443 INPUT+OUTPUT tcp+udp.
for _r in "INPUT:tcp:443" "INPUT:udp:443" "OUTPUT:tcp:sport:443" "OUTPUT:udp:sport:443"; do
    echo "${_r}" >> "${IPTABLES_RULES_FILE}"
done
echo '{"tcp":[443],"udp":[443]}' > "${managed_ports_file}"

BACKUP_DIR=$(reinstall_backup_create 2>/dev/null)

# Failure injection: forward adds 8443 OK then fails on 8444; the immediate
# new→old reverse starts by removing 8443, which is ALSO blocked, so the
# reverse cannot complete and the state must stay "pending".
eval "$(declare -f firewall_add_managed_port | sed 's/^firewall_add_managed_port/_s12_orig_fw_add/')"
eval "$(declare -f firewall_remove_managed_port | sed 's/^firewall_remove_managed_port/_s12_orig_fw_remove/')"
firewall_add_managed_port() {
    local proto="$1" port="$2"
    if [[ "${port}" == "8444" ]]; then
        return 1
    fi
    _s12_orig_fw_add "${proto}" "${port}"
}
firewall_remove_managed_port() {
    local proto="$1" port="$2"
    if [[ "${port}" == "8443" ]]; then
        return 1
    fi
    _s12_orig_fw_remove "${proto}" "${port}"
}

TX_RC=0
apply_managed_firewall_transaction \
    '{"tcp":[443],"udp":[443]}' '{"tcp":[8443,8444],"udp":[8443,8444]}' 2>/dev/null || TX_RC=$?
assert_ne "S12 transaction returns non-zero" "0" "${TX_RC}"
assert_eq "S12 state stays pending (not no)" "pending" "${_reinstall_firewall_changed}"
grep -qxF "INPUT:tcp:8443" "${IPTABLES_RULES_FILE}" && ok "S12 forward-added 8443 left (reverse failed)" || bad "S12 8443 missing"

# Global restore retries the reverse; still fails → non-zero + backup kept.
RESTORE_RC=0
reinstall_backup_restore "${BACKUP_DIR}" 2>/dev/null || RESTORE_RC=$?
assert_ne "S12 restore non-zero when reverse retry fails" "0" "${RESTORE_RC}"
[[ -d "${BACKUP_DIR}" ]] && ok "S12 backup retained" || bad "S12 backup dir lost"
unset -f firewall_add_managed_port _s12_orig_fw_add firewall_remove_managed_port _s12_orig_fw_remove
rm -rf "${BACKUP_DIR}"

# ============================================================================
# Additional: detect_multi_user edge cases
# ============================================================================
echo "--- Additional: detect_multi_user edge cases ---"

# No xray_conf file.
reset_for_reinstall_test
rm -f "${xray_conf}"
assert_eq "No config multi_user" "no" "$(detect_multi_user_from_xray_conf)"
assert_eq "No config reality_clients" "0" "$(count_reality_clients_in_xray_conf)"

# Empty inbounds.
echo '{"inbounds":[]}' > "${xray_conf}"
assert_eq "Empty inbounds multi_user" "no" "$(detect_multi_user_from_xray_conf)"
assert_eq "Empty inbounds reality_clients" "0" "$(count_reality_clients_in_xray_conf)"

# Two single-client vless inbounds: not multi-user, but 2 reality clients total.
echo '{"inbounds":[{"protocol":"vless","settings":{"clients":[{"id":"a"}]}},{"protocol":"vless","settings":{"clients":[{"id":"b"}]}}]}' > "${xray_conf}"
assert_eq "Two single-client inbounds multi_user" "no" "$(detect_multi_user_from_xray_conf)"
assert_eq "Two single-client inbounds reality_clients" "2" "$(count_reality_clients_in_xray_conf)"

# Non-vless inbound with many clients: detect_multi_user checks ALL inbounds
# (not vless-only), so vmess with 3 clients is still multi-user.
echo '{"inbounds":[{"protocol":"vmess","settings":{"clients":[{"id":"a"},{"id":"b"},{"id":"c"}]}}]}' > "${xray_conf}"
assert_eq "vmess multi-client multi_user" "yes" "$(detect_multi_user_from_xray_conf)"
# But count_reality_clients only counts vless clients, so vmess contributes 0.
assert_eq "vmess multi-client reality_clients" "0" "$(count_reality_clients_in_xray_conf)"

# ============================================================================
# Additional: Key leakage prevention across all reinstall functions
# ============================================================================
echo "--- Additional: Key leakage prevention ---"
reset_for_reinstall_test
write_reality_multi_user_conf
tls_mode="Reality"
echo '{"tls":"Reality","id":"uuid-leak-SECRET","privateKey":"priv-leak-SECRET","shortIds":"short-leak-SECRET"}' > "${xray_install_config_file}"
info_extraction_all=$(jq -rc . "${xray_install_config_file}")

# detect_multi_user / count_reality output only "yes"/"no" / numbers.
OUT1=$(detect_multi_user_from_xray_conf 2>&1)
assert_not_contains "detect_multi_user no leak" "SECRET" "${OUT1}"
OUT2=$(count_reality_clients_in_xray_conf 2>&1)
assert_not_contains "count_reality no leak" "SECRET" "${OUT2}"

# _install_config_merge_write produces no stdout.
NEW_FIELDS=$(mktemp)
echo '{"shell_mode":"Reality"}' > "${NEW_FIELDS}"
OUT3=$(_install_config_merge_write "${NEW_FIELDS}" 2>&1)
rm -f "${NEW_FIELDS}"
assert_not_contains "merge_write no leak" "SECRET" "${OUT3}"

# reinstall_backup_create echoes only the backup dir path.
OUT4=$(reinstall_backup_create 2>&1)
assert_not_contains "backup_create no leak" "SECRET" "${OUT4}"
assert_not_contains "backup_create no privateKey leak" "priv-leak-SECRET" "${OUT4}"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=========================================="
echo "Reinstall preservation tests: ${PASS} passed, ${FAIL} failed"
echo "=========================================="

if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
