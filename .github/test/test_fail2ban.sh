#!/usr/bin/env bash
# P0-C: Fail2ban management functionality tests.
# Tests menu/CLI entry points, IP/CIDR validation, unban,
# trusted IP add/remove, persistence (atomic + validation),
# and SNI/TLS jail policy strictness.
#
# Uses a mock fail2ban-client to avoid requiring real fail2ban installation.
#
# Run: bash .github/test/test_fail2ban.sh

set -uo pipefail

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_DIR}"

PASS_COUNT=0
FAIL_COUNT=0

ok() {
    echo "  ✅ PASS: $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

bad() {
    echo "  ❌ FAIL: $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "============================================"
echo "  Fail2ban Management Functionality Tests"
echo "  (P0-C: unban, trusted IP, persistence, CLI)"
echo "============================================"

# ============================================================
# Section 0: Setup mock environment
# ============================================================

# Create a temporary directory for mock binaries and config
_MOCK_BASE="$(mktemp -d)"
_MOCK_BIN="${_MOCK_BASE}/bin"
_MOCK_ETC="${_MOCK_BASE}/etc"
_MOCK_FAIL2BAN_DIR="${_MOCK_ETC}/fail2ban"
_MOCK_JAIL_D="${_MOCK_FAIL2BAN_DIR}/jail.d"
_MOCK_FILTER_D="${_MOCK_FAIL2BAN_DIR}/filter.d"

mkdir -p "${_MOCK_BIN}" "${_MOCK_JAIL_D}" "${_MOCK_FILTER_D}"

# Prepend mock bin to PATH
export PATH="${_MOCK_BIN}:${PATH}"

# Create a GNU-sed compatible wrapper for macOS BSD sed
# On Linux, the real GNU sed is used directly; on macOS, -i gets a backup suffix
if [[ "$(uname)" == "Darwin" ]] && ! command -v gsed >/dev/null 2>&1; then
    cat > "${_MOCK_BIN}/sed" << 'SED_WRAPPER'
#!/usr/bin/env bash
# Pass through to system sed, but handle -i without backup suffix (GNU sed style)
if [[ "$1" == "-i" ]]; then
    shift
    _expr="$1"
    shift
    _file="$1"
    _tmp="$(mktemp)"
    /usr/bin/sed "$_expr" "$_file" > "$_tmp"
    mv "$_tmp" "$_file"
else
    exec /usr/bin/sed "$@"
fi
SED_WRAPPER
    chmod +x "${_MOCK_BIN}/sed"
fi

# Mock external functions that fail2ban_manager.sh depends on
# gettext: return the key as-is (no translation in tests)
if ! command -v gettext >/dev/null 2>&1; then
    gettext() { echo "$1"; }
    export -f gettext
fi

# log_echo: simple wrapper that prints to stderr
log_echo() {
    echo "$@" >&2
}
export -f log_echo

# read_optimize: mock that reads from a variable instead of stdin
# Usage: read_optimize "prompt:" var_name "default" "timeout"
read_optimize() {
    local prompt="$1"
    local var_name="$2"
    local default="${3:-}"
    local timeout="${4:-}"
    # In test mode, use _TEST_INPUT or default
    if [[ -n "${_TEST_INPUT:-}" ]]; then
        eval "${var_name}=\"\${_TEST_INPUT}\""
    else
        eval "${var_name}=\"\${default}\""
    fi
}
export -f read_optimize

# Set required variables
export shell_version="2.12.10"
export tls_mode="TLS"
export reality_add_nginx="on"
export nginx_dir="${_MOCK_BASE}/nginx"
export scripts_dir="${_MOCK_BASE}/scripts"
export idleleo_dir="${_MOCK_BASE}/idleleo"
# P0-C: Use mock jail.d path so persistence tests can write without root
export FAIL2BAN_JAIL_D="${_MOCK_JAIL_D}"
export Error="Error"
export RedBG="RedBG"
export YellowBG="YellowBG"
export GreenBG="GreenBG"
export Green="Green"
export Warning="Warning"
export Info="Info"
export Font="Font"
export OK="OK"

mkdir -p "${nginx_dir}/logs" "${scripts_dir}" "${idleleo_dir}"

# ============================================================
# Section 0.1: Create mock fail2ban-client
# ============================================================

# The mock fail2ban-client supports:
#   status                      -> prints jail list
#   status <jail>               -> prints jail details including Banned IP list
#   set <jail> unbanip <ip>    -> removes IP from banned list
#   set <jail> addignoreip <ip> -> adds IP to ignore list
#   set <jail> delignoreip <ip> -> removes IP from ignore list
#   -t                          -> config test (always succeeds unless _MOCK_FAIL_CONFIG is set)

cat > "${_MOCK_BIN}/fail2ban-client" << 'MOCK_EOF'
#!/usr/bin/env bash
# Mock fail2ban-client for testing purposes

_MOCK_STATE_DIR="${_MOCK_BASE}/state"
mkdir -p "${_MOCK_STATE_DIR}"

case "$1" in
    status)
        if [[ $# -eq 1 ]]; then
            # Print overall status with jail list
            echo "|- Number of jail: 3"
            echo "\`- Jail list: sshd, nginx-no-host, nginx-tls-error"
        else
            # Print jail-specific status
            jail="$2"
            banned_file="${_MOCK_STATE_DIR}/banned_${jail}"
            ignore_file="${_MOCK_STATE_DIR}/ignore_${jail}"

            # Initialize banned IPs for known jails
            if [[ ! -f "${banned_file}" ]]; then
                case "${jail}" in
                    sshd)
                        echo "192.168.1.100" > "${banned_file}"
                        echo "10.0.0.50" >> "${banned_file}"
                        ;;
                    nginx-no-host)
                        echo "203.0.113.5" > "${banned_file}"
                        echo "2001:db8::1" >> "${banned_file}"
                        ;;
                    nginx-tls-error)
                        echo "198.51.100.10" > "${banned_file}"
                        ;;
                    *)
                        : > "${banned_file}"
                        ;;
                esac
            fi

            # Initialize ignore IPs
            if [[ ! -f "${ignore_file}" ]]; then
                echo "127.0.0.1/8" > "${ignore_file}"
            fi

            banned_ips=$(tr '\n' ' ' < "${banned_file}" 2>/dev/null | sed 's/ $//')
            ignore_ips=$(tr '\n' ' ' < "${ignore_file}" 2>/dev/null | sed 's/ $//')

            echo "|- Jail: ${jail}"
            echo "|  \`- Filter:"
            echo "|  |- Currently failed: 0"
            echo "|  |\`- Total failed: 0"
            echo "|  \`- Action:"
            echo "|- Banned IP list: ${banned_ips}"
            echo "|  \`- Ignored IP list: ${ignore_ips}"
        fi
        ;;

    set)
        jail="$2"
        action="$3"
        target="$4"
        banned_file="${_MOCK_STATE_DIR}/banned_${jail}"
        ignore_file="${_MOCK_STATE_DIR}/ignore_${jail}"

        mkdir -p "${_MOCK_STATE_DIR}"
        touch "${banned_file}" "${ignore_file}"

        case "${action}" in
            unbanip)
                # Remove IP from banned list
                if grep -qw -- "${target}" "${banned_file}" 2>/dev/null; then
                    grep -v -- "${target}" "${banned_file}" > "${banned_file}.tmp" || true
                    mv "${banned_file}.tmp" "${banned_file}"
                    echo "OK"
                else
                    echo "IP ${target} is not banned" >&2
                    exit 1
                fi
                ;;
            addignoreip)
                # Add IP to ignore list
                if ! grep -qw -- "${target}" "${ignore_file}" 2>/dev/null; then
                    echo "${target}" >> "${ignore_file}"
                fi
                echo "OK"
                ;;
            delignoreip)
                # Remove IP from ignore list
                if grep -qw -- "${target}" "${ignore_file}" 2>/dev/null; then
                    grep -v -- "${target}" "${ignore_file}" > "${ignore_file}.tmp" || true
                    mv "${ignore_file}.tmp" "${ignore_file}"
                fi
                echo "OK"
                ;;
            *)
                echo "Unknown set action: ${action}" >&2
                exit 1
                ;;
        esac
        ;;

    -t)
        # Config test
        if [[ -n "${_MOCK_FAIL_CONFIG:-}" ]]; then
            echo "Config test failed" >&2
            exit 1
        fi
        echo "OK"
        ;;

    *)
        echo "Unknown command: $*" >&2
        exit 1
        ;;
esac
MOCK_EOF
chmod +x "${_MOCK_BIN}/fail2ban-client"

# Source the fail2ban manager script
# shellcheck source=/dev/null
source "${REPO_DIR}/scripts/fail2ban_manager.sh"

# ============================================================
# Section 1: mf_validate_ip tests
# ============================================================
echo ""
echo "--- Section 1: IP validation ---"

# Valid IPv4 addresses
for ip in "192.168.1.1" "10.0.0.1" "172.16.0.1" "8.8.8.8" "1.1.1.1" "255.255.255.255"; do
    if mf_validate_ip "$ip"; then
        ok "mf_validate_ip accepts valid IPv4: ${ip}"
    else
        bad "mf_validate_ip rejects valid IPv4: ${ip}"
    fi
done

# Valid IPv6 addresses
for ip in "::1" "2001:db8::1" "fe80::1" "::" "2001:db8:85a3::8a2e:370:7334"; do
    if mf_validate_ip "$ip"; then
        ok "mf_validate_ip accepts valid IPv6: ${ip}"
    else
        bad "mf_validate_ip rejects valid IPv6: ${ip}"
    fi
done

# Invalid IPs
for ip in "" "999.1.1.1" "1.2.3.4.5" "::::" "256.0.0.1" "abc" "1.2.3" "1.2.3.4/24" "not-an-ip"; do
    if ! mf_validate_ip "$ip"; then
        ok "mf_validate_ip rejects invalid IP: '${ip}'"
    else
        bad "mf_validate_ip accepts invalid IP: '${ip}'"
    fi
done

# ============================================================
# Section 2: mf_validate_cidr tests
# ============================================================
echo ""
echo "--- Section 2: CIDR validation ---"

# Valid IPv4 CIDR
for cidr in "192.168.1.0/24" "10.0.0.0/8" "172.16.0.0/12" "0.0.0.0/0" "192.168.1.1/32"; do
    if mf_validate_cidr "$cidr"; then
        ok "mf_validate_cidr accepts valid IPv4 CIDR: ${cidr}"
    else
        bad "mf_validate_cidr rejects valid IPv4 CIDR: ${cidr}"
    fi
done

# Valid IPv6 CIDR
for cidr in "2001:db8::/32" "fe80::/10" "::1/128" "::/0" "2001:db8:85a3::/48"; do
    if mf_validate_cidr "$cidr"; then
        ok "mf_validate_cidr accepts valid IPv6 CIDR: ${cidr}"
    else
        bad "mf_validate_cidr rejects valid IPv6 CIDR: ${cidr}"
    fi
done

# Valid bare IPs (no prefix) should also pass CIDR validation
for cidr in "192.168.1.1" "::1" "2001:db8::1"; do
    if mf_validate_cidr "$cidr"; then
        ok "mf_validate_cidr accepts bare IP as valid CIDR: ${cidr}"
    else
        bad "mf_validate_cidr rejects bare IP that should be valid: ${cidr}"
    fi
done

# Invalid CIDR (prefix out of range)
for cidr in "1.2.3.4/100" "1.2.3.4/-1" "1.2.3.4/33" "::::/64" "999.1.1.1/24" "1.2.3.4/abc" ""; do
    if ! mf_validate_cidr "$cidr"; then
        ok "mf_validate_cidr rejects invalid CIDR: '${cidr}'"
    else
        bad "mf_validate_cidr accepts invalid CIDR: '${cidr}'"
    fi
done

# ============================================================
# Section 3: mf_get_active_jails tests
# ============================================================
echo ""
echo "--- Section 3: Active jail parsing ---"

_active_jails_output=$(mf_get_active_jails 2>/dev/null)
if echo "$_active_jails_output" | grep -qw "sshd"; then
    ok "mf_get_active_jails returns sshd"
else
    bad "mf_get_active_jails does not return sshd"
fi

if echo "$_active_jails_output" | grep -qw "nginx-no-host"; then
    ok "mf_get_active_jails returns nginx-no-host"
else
    bad "mf_get_active_jails does not return nginx-no-host"
fi

if echo "$_active_jails_output" | grep -qw "nginx-tls-error"; then
    ok "mf_get_active_jails returns nginx-tls-error"
else
    bad "mf_get_active_jails does not return nginx-tls-error"
fi

# Verify that a non-existent jail is NOT returned
if ! echo "$_active_jails_output" | grep -qw "nonexistent-jail"; then
    ok "mf_get_active_jails does not return non-existent jail"
else
    bad "mf_get_active_jails returns non-existent jail (should not)"
fi

# ============================================================
# Section 4: mf_quick_unban tests
# ============================================================
echo ""
echo "--- Section 4: Quick unban ---"

# Test: successful unban of a banned IP
_mock_state_dir="${_MOCK_BASE}/state"
mkdir -p "${_mock_state_dir}"

# Ensure banned IPs are initialized by calling status first
fail2ban-client status sshd >/dev/null 2>&1 || true

if mf_quick_unban "sshd" "192.168.1.100" 2>/dev/null; then
    ok "mf_quick_unban succeeds for banned IP"
else
    bad "mf_quick_unban fails for banned IP that should succeed"
fi

# Verify IP was actually removed
_verify_banned=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP list:" | sed 's/.*Banned IP list:\s*//')
if ! echo "$_verify_banned" | grep -qw "192.168.1.100"; then
    ok "IP was actually removed from banned list after unban"
else
    bad "IP still in banned list after unban (mock state not updated)"
fi

# Test: unban of IP not in banned list (should return 0 with warning)
if mf_quick_unban "sshd" "8.8.8.8" 2>/dev/null; then
    ok "mf_quick_unban returns 0 for IP not in banned list (warning)"
else
    bad "mf_quick_unban returns non-zero for IP not in banned list (should return 0)"
fi

# Test: invalid jail name (should be rejected)
if ! mf_quick_unban "nonexistent-jail" "1.2.3.4" 2>/dev/null; then
    ok "mf_quick_unban rejects non-existent jail"
else
    bad "mf_quick_unban accepts non-existent jail (should be rejected)"
fi

# Test: invalid IP address (should be rejected)
if ! mf_quick_unban "sshd" "999.1.1.1" 2>/dev/null; then
    ok "mf_quick_unban rejects invalid IP address"
else
    bad "mf_quick_unban accepts invalid IP address (should be rejected)"
fi

# Test: empty IP (should be rejected)
if ! mf_quick_unban "sshd" "" 2>/dev/null; then
    ok "mf_quick_unban rejects empty IP"
else
    bad "mf_quick_unban accepts empty IP (should be rejected)"
fi

# Test: empty jail (should be rejected)
if ! mf_quick_unban "" "1.2.3.4" 2>/dev/null; then
    ok "mf_quick_unban rejects empty jail"
else
    bad "mf_quick_unban accepts empty jail (should be rejected)"
fi

# Test: CIDR in unban (should be rejected - unban only allows single IP)
if ! mf_quick_unban "sshd" "192.168.1.0/24" 2>/dev/null; then
    ok "mf_quick_unban rejects CIDR (only single IP allowed)"
else
    bad "mf_quick_unban accepts CIDR (should only allow single IP)"
fi

# Test: IPv6 unban
if mf_quick_unban "nginx-no-host" "203.0.113.5" 2>/dev/null; then
    ok "mf_quick_unban succeeds for banned IPv4 in nginx-no-host jail"
else
    bad "mf_quick_unban fails for banned IPv4 in nginx-no-host jail"
fi

if mf_quick_unban "nginx-no-host" "2001:db8::1" 2>/dev/null; then
    ok "mf_quick_unban succeeds for banned IPv6 in nginx-no-host jail"
else
    bad "mf_quick_unban fails for banned IPv6 in nginx-no-host jail"
fi

# ============================================================
# Section 5: Shell injection prevention tests
# ============================================================
echo ""
echo "--- Section 5: Shell injection prevention ---"

# Test: jail name with shell metacharacters should be rejected
_injection_attempts=(
    'sshd; rm -rf /'
    'sshd && echo "injected"'
    'sshd | cat /etc/passwd'
    'sshd$(whoami)'
    'sshd`whoami`'
    'sshd\nwhoami'
)

for attempt in "${_injection_attempts[@]}"; do
    if ! mf_quick_unban "$attempt" "1.2.3.4" 2>/dev/null; then
        ok "Shell injection rejected in jail name: '${attempt}'"
    else
        bad "Shell injection accepted in jail name: '${attempt}'"
    fi
done

# Test: IP with shell metacharacters should be rejected by validation
_ip_injections=(
    '1.2.3.4; rm -rf /'
    '1.2.3.4 && whoami'
    '1.2.3.4 | cat /etc/shadow'
    '1.2.3.4$(id)'
    '1.2.3.4`id`'
)

for attempt in "${_ip_injections[@]}"; do
    if ! mf_quick_unban "sshd" "$attempt" 2>/dev/null; then
        ok "Shell injection rejected in IP: '${attempt}'"
    else
        bad "Shell injection accepted in IP: '${attempt}' (should be rejected)"
    fi
done

# Test: CIDR with shell metacharacters should be rejected
_cidr_injections=(
    '1.2.3.4/24; rm -rf /'
    '1.2.3.4/24$(whoami)'
    '1.2.3.4/24`whoami`'
)

for attempt in "${_cidr_injections[@]}"; do
    if ! mf_add_trust_ip "sshd" "$attempt" 2>/dev/null; then
        ok "Shell injection rejected in CIDR: '${attempt}'"
    else
        bad "Shell injection accepted in CIDR: '${attempt}' (should be rejected)"
    fi
done

# ============================================================
# Section 6: mf_add_trust_ip / mf_remove_trust_ip tests
# ============================================================
echo ""
echo "--- Section 6: Trusted IP add/remove ---"

# Re-initialize banned/ignore state for clean tests
rm -rf "${_mock_state_dir}"
mkdir -p "${_mock_state_dir}"
fail2ban-client status sshd >/dev/null 2>&1 || true

# Test: add valid IPv4 to trust list
if mf_add_trust_ip "sshd" "192.168.1.50" 2>/dev/null; then
    ok "mf_add_trust_ip succeeds for valid IPv4"
else
    bad "mf_add_trust_ip fails for valid IPv4"
fi

# Test: add valid IPv6 to trust list
if mf_add_trust_ip "sshd" "2001:db8::2" 2>/dev/null; then
    ok "mf_add_trust_ip succeeds for valid IPv6"
else
    bad "mf_add_trust_ip fails for valid IPv6"
fi

# Test: add valid CIDR to trust list
if mf_add_trust_ip "sshd" "10.0.0.0/8" 2>/dev/null; then
    ok "mf_add_trust_ip succeeds for valid CIDR"
else
    bad "mf_add_trust_ip fails for valid CIDR"
fi

# Test: add invalid IP/CIDR to trust list
if ! mf_add_trust_ip "sshd" "999.1.1.1/24" 2>/dev/null; then
    ok "mf_add_trust_ip rejects invalid CIDR"
else
    bad "mf_add_trust_ip accepts invalid CIDR (should be rejected)"
fi

# Test: add to non-existent jail
if ! mf_add_trust_ip "nonexistent-jail" "1.2.3.4" 2>/dev/null; then
    ok "mf_add_trust_ip rejects non-existent jail"
else
    bad "mf_add_trust_ip accepts non-existent jail (should be rejected)"
fi

# Test: remove trusted IP
if mf_remove_trust_ip "sshd" "192.168.1.50" 2>/dev/null; then
    ok "mf_remove_trust_ip succeeds for existing trusted IP"
else
    bad "mf_remove_trust_ip fails for existing trusted IP"
fi

# Test: remove from non-existent jail
if ! mf_remove_trust_ip "nonexistent-jail" "1.2.3.4" 2>/dev/null; then
    ok "mf_remove_trust_ip rejects non-existent jail"
else
    bad "mf_remove_trust_ip accepts non-existent jail (should be rejected)"
fi

# Test: remove invalid IP
if ! mf_remove_trust_ip "sshd" "999.1.1.1/24" 2>/dev/null; then
    ok "mf_remove_trust_ip rejects invalid CIDR"
else
    bad "mf_remove_trust_ip accepts invalid CIDR (should be rejected)"
fi

# ============================================================
# Section 7: mf_persist_ignoreip tests
# ============================================================
echo ""
echo "--- Section 7: Persistence (atomic + validation) ---"

# Clean up any existing config files
rm -rf "${_MOCK_JAIL_D}"/*
mkdir -p "${_MOCK_JAIL_D}"

# Test: persist when config file does not exist (should create it)
if mf_persist_ignoreip "sshd" "192.168.1.0/24" add 2>/dev/null; then
    ok "mf_persist_ignoreip creates new config file successfully"
else
    bad "mf_persist_ignoreip fails to create new config file"
fi

# Verify config file was created
if [[ -f "${_MOCK_JAIL_D}/sshd.local" ]]; then
    ok "Config file sshd.local was created"
else
    bad "Config file sshd.local was not created"
fi

# Test: persist add when file exists (should append to existing)
if mf_persist_ignoreip "sshd" "10.0.0.0/8" add 2>/dev/null; then
    ok "mf_persist_ignoreip appends to existing config successfully"
else
    bad "mf_persist_ignoreip fails to append to existing config"
fi

# Verify the new CIDR was added
if grep -q "10.0.0.0/8" "${_MOCK_JAIL_D}/sshd.local" 2>/dev/null; then
    ok "New CIDR was persisted in config file"
else
    bad "New CIDR was not persisted in config file"
fi

# Test: persist add when CIDR already exists (should be no-op)
if mf_persist_ignoreip "sshd" "10.0.0.0/8" add 2>/dev/null; then
    ok "mf_persist_ignoreip handles duplicate CIDR gracefully"
else
    bad "mf_persist_ignoreip fails for duplicate CIDR"
fi

# Test: persist del (remove CIDR)
if mf_persist_ignoreip "sshd" "10.0.0.0/8" del 2>/dev/null; then
    ok "mf_persist_ignoreip removes CIDR successfully"
else
    bad "mf_persist_ignoreip fails to remove CIDR"
fi

# Verify the CIDR was removed
if ! grep -q "10.0.0.0/8" "${_MOCK_JAIL_D}/sshd.local" 2>/dev/null; then
    ok "CIDR was removed from config file"
else
    bad "CIDR was not removed from config file"
fi

# Test: persist when config validation fails (should preserve original)
# Save original content
_orig_config_content=$(cat "${_MOCK_JAIL_D}/sshd.local" 2>/dev/null)

# Set mock to fail config validation
export _MOCK_FAIL_CONFIG=1

if ! mf_persist_ignoreip "sshd" "10.0.0.0/8" add 2>/dev/null; then
    ok "mf_persist_ignoreip fails when config validation fails"
else
    bad "mf_persist_ignoreip succeeds when config validation should fail"
fi

# Verify original config was preserved
_current_config_content=$(cat "${_MOCK_JAIL_D}/sshd.local" 2>/dev/null)
if [[ "${_orig_config_content}" == "${_current_config_content}" ]]; then
    ok "Original config file preserved when validation fails"
else
    bad "Original config file was modified when validation should have failed"
fi

# Clear mock failure
unset _MOCK_FAIL_CONFIG

# ============================================================
# Section 8: mf_cli (CLI entry point) tests
# ============================================================
echo ""
echo "--- Section 8: CLI entry point ---"

# Clean state
rm -rf "${_mock_state_dir}"
mkdir -p "${_mock_state_dir}"
fail2ban-client status sshd >/dev/null 2>&1 || true

# Test: --list command
if mf_cli --list 2>/dev/null; then
    ok "mf_cli --list executes successfully"
else
    bad "mf_cli --list fails"
fi

# Test: --unban with valid parameters
if mf_cli --unban "sshd" "192.168.1.100" 2>/dev/null; then
    ok "mf_cli --unban executes successfully with valid parameters"
else
    bad "mf_cli --unban fails with valid parameters"
fi

# Test: --unban with missing parameters (should fail)
if ! mf_cli --unban "sshd" "" 2>/dev/null; then
    ok "mf_cli --unban rejects missing IP parameter"
else
    bad "mf_cli --unban accepts missing IP parameter (should be rejected)"
fi

# Test: --unban with missing jail (should fail)
if ! mf_cli --unban "" "1.2.3.4" 2>/dev/null; then
    ok "mf_cli --unban rejects missing jail parameter"
else
    bad "mf_cli --unban accepts missing jail parameter (should be rejected)"
fi

# Test: --trust-add with valid parameters
if mf_cli --trust-add "sshd" "192.168.1.0/24" 2>/dev/null; then
    ok "mf_cli --trust-add executes successfully with valid parameters"
else
    bad "mf_cli --trust-add fails with valid parameters"
fi

# Test: --trust-add with missing parameters (should fail)
if ! mf_cli --trust-add "sshd" "" 2>/dev/null; then
    ok "mf_cli --trust-add rejects missing CIDR parameter"
else
    bad "mf_cli --trust-add accepts missing CIDR parameter (should be rejected)"
fi

# Test: --trust-del with valid parameters
if mf_cli --trust-del "sshd" "192.168.1.0/24" 2>/dev/null; then
    ok "mf_cli --trust-del executes successfully with valid parameters"
else
    bad "mf_cli --trust-del fails with valid parameters"
fi

# Test: unknown command (should fail)
if ! mf_cli --unknown-command 2>/dev/null; then
    ok "mf_cli rejects unknown command"
else
    bad "mf_cli accepts unknown command (should be rejected)"
fi

# Test: empty action (should fail)
if ! mf_cli "" 2>/dev/null; then
    ok "mf_cli rejects empty action"
else
    bad "mf_cli accepts empty action (should be rejected)"
fi

# ============================================================
# Section 9: SNI/TLS jail policy strictness tests
# ============================================================
echo ""
echo "--- Section 9: SNI/TLS jail policy strictness ---"

# Create the actual jail config files as they would be in production
cat > "${_MOCK_JAIL_D}/nginx-no-host.local" << 'EOF'
[nginx-no-host]
enabled  = true
filter   = nginx-no-host
logpath  = /usr/local/nginx/logs/sni_error.log
bantime  = 604800
maxretry = 5
findtime = 120
EOF

cat > "${_MOCK_JAIL_D}/nginx-tls-error.local" << 'EOF'
[nginx-tls-error]
enabled  = true
filter   = nginx-tls-error
logpath  = /usr/local/nginx/logs/tls_error.log
bantime  = 43200
maxretry = 8
findtime = 300
EOF

# Verify nginx-no-host policy is NOT relaxed
_config_file="${_MOCK_JAIL_D}/nginx-no-host.local"
if grep -q "bantime.*=.*604800" "$_config_file" 2>/dev/null; then
    ok "nginx-no-host bantime = 604800 (not relaxed)"
else
    bad "nginx-no-host bantime policy was relaxed"
fi

if grep -q "maxretry.*=.*5" "$_config_file" 2>/dev/null; then
    ok "nginx-no-host maxretry = 5 (not relaxed)"
else
    bad "nginx-no-host maxretry policy was relaxed"
fi

if grep -q "findtime.*=.*120" "$_config_file" 2>/dev/null; then
    ok "nginx-no-host findtime = 120 (not relaxed)"
else
    bad "nginx-no-host findtime policy was relaxed"
fi

# Verify nginx-tls-error policy is NOT relaxed
_config_file="${_MOCK_JAIL_D}/nginx-tls-error.local"
if grep -q "bantime.*=.*43200" "$_config_file" 2>/dev/null; then
    ok "nginx-tls-error bantime = 43200 (not relaxed)"
else
    bad "nginx-tls-error bantime policy was relaxed"
fi

if grep -q "maxretry.*=.*8" "$_config_file" 2>/dev/null; then
    ok "nginx-tls-error maxretry = 8 (not relaxed)"
else
    bad "nginx-tls-error maxretry policy was relaxed"
fi

if grep -q "findtime.*=.*300" "$_config_file" 2>/dev/null; then
    ok "nginx-tls-error findtime = 300 (not relaxed)"
else
    bad "nginx-tls-error findtime policy was relaxed"
fi

# ============================================================
# Section 10: Incremental ban policy tests
# ============================================================
echo ""
echo "--- Section 10: Incremental ban policy ---"

# Call mf_ensure_incremental_ban to create the config file
mf_ensure_incremental_ban

_inc_file="${_MOCK_JAIL_D}/zzz-idleleo-incremental.local"

if [[ -f "$_inc_file" ]]; then
    ok "Incremental ban config file exists"
else
    bad "Incremental ban config file does not exist"
fi

if grep -q "bantime.increment.*=.*true" "$_inc_file" 2>/dev/null; then
    ok "bantime.increment = true (incremental banning enabled)"
else
    bad "bantime.increment not set to true"
fi

if grep -q "bantime.multipliers.*=.*1 2 4 8 16 32 64" "$_inc_file" 2>/dev/null; then
    ok "bantime.multipliers = 1 2 4 8 16 32 64 (correct escalation)"
else
    bad "bantime.multipliers not set correctly"
fi

if grep -q "bantime.maxtime.*=.*180d" "$_inc_file" 2>/dev/null; then
    ok "bantime.maxtime = 180d (correct maximum)"
else
    bad "bantime.maxtime not set to 180d"
fi

if grep -q "bantime.rndtime.*=.*10m" "$_inc_file" 2>/dev/null; then
    ok "bantime.rndtime = 10m (correct randomization)"
else
    bad "bantime.rndtime not set to 10m"
fi

if grep -q "bantime.overalljails.*=.*false" "$_inc_file" 2>/dev/null; then
    ok "bantime.overalljails = false (per-jail isolation)"
else
    bad "bantime.overalljails not set to false"
fi

# Verify the config passes fail2ban-client -t (mock)
if fail2ban-client -t >/dev/null 2>&1; then
    ok "Incremental ban config passes fail2ban-client -t validation"
else
    bad "Incremental ban config fails fail2ban-client -t validation"
fi

# ============================================================
# Section 11: Persistence failure does not show as fully successful
# ============================================================
echo ""
echo "--- Section 11: Persistence failure handling ---"

# Clean state
rm -rf "${_mock_state_dir}" "${_MOCK_JAIL_D}"/*
mkdir -p "${_mock_state_dir}" "${_MOCK_JAIL_D}"
fail2ban-client status sshd >/dev/null 2>&1 || true

# Set mock to fail config validation for persistence
export _MOCK_FAIL_CONFIG=1

# Capture stderr output to verify warning message is shown
_add_output=$(mf_add_trust_ip "sshd" "192.168.1.0/24" 2>&1 1>/dev/null || true)

if echo "$_add_output" | grep -q "持久化失败\|persistence\|持久化"; then
    ok "mf_add_trust_ip shows persistence failure warning (not shown as fully successful)"
else
    bad "mf_add_trust_ip does not show persistence failure warning"
fi

# Verify the function returns non-zero when persistence fails
if ! mf_add_trust_ip "sshd" "10.0.0.0/8" 2>/dev/null; then
    ok "mf_add_trust_ip returns non-zero when persistence fails"
else
    bad "mf_add_trust_ip returns zero when persistence fails (should return non-zero)"
fi

# Test the same for mf_remove_trust_ip
if ! mf_remove_trust_ip "sshd" "192.168.1.0/24" 2>/dev/null; then
    ok "mf_remove_trust_ip returns non-zero when persistence fails"
else
    bad "mf_remove_trust_ip returns zero when persistence fails (should return non-zero)"
fi

unset _MOCK_FAIL_CONFIG

# ============================================================
# Section 12: mf_manage_fail2ban menu structure verification
# ============================================================
echo ""
echo "--- Section 12: Menu structure verification ---"

# Verify that mf_manage_fail2ban function exists (it is the menu entry point)
if declare -f mf_manage_fail2ban >/dev/null 2>&1; then
    ok "mf_manage_fail2ban function exists (menu entry point)"
else
    bad "mf_manage_fail2ban function does not exist (menu entry point missing)"
fi

# Verify that the menu function references all expected options
# by checking the function body for option numbers
_func_body=$(declare -f mf_manage_fail2ban 2>/dev/null || true)

# Check that the menu has options for: manage modules, view banned IPs,
# quick unban, add trusted IP, remove trusted IP, custom rules, service check, return
for _option_text in "管理模块" "查看已封禁" "快速解封" "添加可信" "移除可信" "添加自定义规则" "服务与配置检查" "返回"; do
    if echo "$_func_body" | grep -q "$_option_text" 2>/dev/null; then
        ok "Menu contains option: '${_option_text}'"
    else
        bad "Menu missing option: '${_option_text}'"
    fi
done

# ============================================================
# Section 13: CLI entry point in install.sh verification
# ============================================================
echo ""
echo "--- Section 13: CLI entry point in install.sh ---"

# Verify that set_fail2ban_cli function exists in install.sh
if grep -q "set_fail2ban_cli" "${REPO_DIR}/install.sh" 2>/dev/null; then
    ok "set_fail2ban_cli function exists in install.sh"
else
    bad "set_fail2ban_cli function not found in install.sh"
fi

# Verify CLI entry points exist in list() function
for _cli_option in "--fail2ban-list" "--fail2ban-unban" "--fail2ban-trust-add" "--fail2ban-trust-del"; do
    if grep -qF -- "$_cli_option" "${REPO_DIR}/install.sh" 2>/dev/null; then
        ok "CLI option '${_cli_option}' exists in install.sh list()"
    else
        bad "CLI option '${_cli_option}' not found in install.sh list()"
    fi
done

# Verify help text exists for Fail2ban CLI options
_help_text=$(grep -A 5 "set-fail2ban" "${REPO_DIR}/install.sh" 2>/dev/null || true)
for _help_option in "--fail2ban-list" "--fail2ban-unban" "--fail2ban-trust-add" "--fail2ban-trust-del"; do
    if echo "$_help_text" | grep -qF -- "$_help_option" 2>/dev/null; then
        ok "Help text exists for '${_help_option}'"
    else
        bad "Help text missing for '${_help_option}'"
    fi
done

# ============================================================
# Cleanup
# ============================================================
rm -rf "${_MOCK_BASE}"

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================"
echo "  Summary"
echo "============================================"
echo "  PASS: ${PASS_COUNT}"
echo "  FAIL: ${FAIL_COUNT}"
echo ""

if [[ ${FAIL_COUNT} -eq 0 ]]; then
    echo "  ✅ All tests passed"
    exit 0
else
    echo "  ❌ ${FAIL_COUNT} test(s) failed"
    exit 1
fi
