#!/usr/bin/env bash
# Section 3: read_optimize EOF and non-numeric input handling.
#
# Coverage:
#   - EOF (closed stdin) returns non-zero immediately
#   - Non-numeric input (abc, 1+1, 08#10, $((1))) is rejected when min/max given
#   - Empty input with default value uses the default
#   - Empty input without default re-prompts (simulated via second read)
#   - Numeric input within range succeeds
#   - Numeric input below min is rejected
#   - Numeric input above max is rejected
#   - Non-numeric input without min/max is accepted (free-form string)
#
# Run: bash .github/test/test_input_eof.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { :; }
gettext() { printf '%s' "$1"; }

# We need to override `read` to simulate user input.
# The test uses a queue of inputs that read consumes one by one.

# Input queue (global array)
declare -a INPUT_QUEUE=()
READ_EOF_AFTER=999  # after this many reads, simulate EOF

# Override read to consume from the queue.
# The real call is: IFS= read -r -p "${prompt}" user_input
# So args are: -r -p "prompt text" user_input
# The variable name is the LAST argument.
read() {
    if [[ ${#INPUT_QUEUE[@]} -eq 0 ]]; then
        # Simulate EOF
        return 1
    fi
    # The last argument is the variable name
    local _var="${!#}"
    # Pop the first element
    local _val="${INPUT_QUEUE[0]}"
    INPUT_QUEUE=("${INPUT_QUEUE[@]:1}")
    printf -v "${_var}" '%s' "${_val}"
    return 0
}

echo "============================================================"
echo "  Section 3: read_optimize EOF & Input Validation"
echo "============================================================"

# --- Test 1: EOF returns non-zero ---
echo "--- EOF (closed stdin) returns non-zero ---"
INPUT_QUEUE=()
# read returns 1 on empty queue (EOF)
if read_optimize "prompt: " test_var "NULL" 1 100; then
    bad "read_optimize should return non-zero on EOF"
else
    ok "read_optimize returns non-zero on EOF"
fi

# --- Test 2: Non-numeric input rejected (with min/max) ---
echo "--- Non-numeric 'abc' rejected ---"
INPUT_QUEUE=("abc" "50")
if read_optimize "prompt: " test_var "NULL" 1 100; then
    if [[ "${test_var}" == "50" ]]; then
        ok "read_optimize rejected 'abc' and accepted '50' on retry"
    else
        bad "read_optimize accepted 'abc' (got: ${test_var})"
    fi
else
    bad "read_optimize returned non-zero unexpectedly after retry input"
fi

# --- Test 3: '1+1' rejected ---
echo "--- Non-numeric '1+1' rejected ---"
INPUT_QUEUE=("1+1" "42")
if read_optimize "prompt: " test_var "NULL" 1 100; then
    if [[ "${test_var}" == "42" ]]; then
        ok "read_optimize rejected '1+1' and accepted '42' on retry"
    else
        bad "read_optimize accepted '1+1' (got: ${test_var})"
    fi
else
    bad "read_optimize returned non-zero unexpectedly"
fi

# --- Test 4: '08#10' rejected (bash arithmetic injection attempt) ---
echo "--- Non-numeric '08#10' rejected ---"
INPUT_QUEUE=("08#10" "42")
if read_optimize "prompt: " test_var "NULL" 1 100; then
    if [[ "${test_var}" == "42" ]]; then
        ok "read_optimize rejected '08#10' and accepted '42' on retry"
    else
        bad "read_optimize accepted '08#10' (got: ${test_var})"
    fi
else
    bad "read_optimize returned non-zero unexpectedly"
fi

# --- Test 5: '$((1))' rejected (command substitution attempt) ---
echo "--- Non-numeric '\$((1))' rejected ---"
INPUT_QUEUE=('$((1))' "42")
if read_optimize "prompt: " test_var "NULL" 1 100; then
    if [[ "${test_var}" == "42" ]]; then
        ok "read_optimize rejected '\$((1))' and accepted '42' on retry"
    else
        bad "read_optimize accepted '\$((1))' (got: ${test_var})"
    fi
else
    bad "read_optimize returned non-zero unexpectedly"
fi

# --- Test 6: Empty input with default uses default ---
echo "--- Empty input with default uses default ---"
INPUT_QUEUE=("")
if read_optimize "prompt: " test_var "443" 1 65535; then
    if [[ "${test_var}" == "443" ]]; then
        ok "read_optimize used default '443' for empty input"
    else
        bad "read_optimize did not use default (got: ${test_var})"
    fi
else
    bad "read_optimize returned non-zero for empty input with default"
fi

# --- Test 7: Empty input without default re-prompts ---
echo "--- Empty input without default re-prompts ---"
INPUT_QUEUE=("" "80")
if read_optimize "prompt: " test_var "NULL" 1 100; then
    if [[ "${test_var}" == "80" ]]; then
        ok "read_optimize re-prompted on empty (no default) and accepted '80'"
    else
        bad "read_optimize did not re-prompt correctly (got: ${test_var})"
    fi
else
    bad "read_optimize returned non-zero unexpectedly"
fi

# --- Test 8: Valid numeric input within range succeeds ---
echo "--- Valid numeric input within range succeeds ---"
INPUT_QUEUE=("8080")
if read_optimize "prompt: " test_var "NULL" 1 65535; then
    if [[ "${test_var}" == "8080" ]]; then
        ok "read_optimize accepted '8080'"
    else
        bad "read_optimize set wrong value (got: ${test_var})"
    fi
else
    bad "read_optimize returned non-zero for valid input '8080'"
fi

# --- Test 9: Input below min rejected ---
echo "--- Input below min (0) rejected ---"
INPUT_QUEUE=("0" "1")
if read_optimize "prompt: " test_var "NULL" 1 100; then
    if [[ "${test_var}" == "1" ]]; then
        ok "read_optimize rejected '0' (below min) and accepted '1'"
    else
        bad "read_optimize accepted '0' (got: ${test_var})"
    fi
else
    bad "read_optimize returned non-zero unexpectedly"
fi

# --- Test 10: Input above max rejected ---
echo "--- Input above max (101) rejected ---"
INPUT_QUEUE=("101" "100")
if read_optimize "prompt: " test_var "NULL" 1 100; then
    if [[ "${test_var}" == "100" ]]; then
        ok "read_optimize rejected '101' (above max) and accepted '100'"
    else
        bad "read_optimize accepted '101' (got: ${test_var})"
    fi
else
    bad "read_optimize returned non-zero unexpectedly"
fi

# --- Test 11: Non-numeric without min/max accepted (free-form) ---
echo "--- Free-form string without min/max accepted ---"
INPUT_QUEUE=("hello-world")
if read_optimize "prompt: " test_var "NULL"; then
    if [[ "${test_var}" == "hello-world" ]]; then
        ok "read_optimize accepted free-form 'hello-world' (no min/max)"
    else
        bad "read_optimize set wrong value (got: ${test_var})"
    fi
else
    bad "read_optimize returned non-zero for free-form input"
fi

# --- Test 12: install_xray_ws_tls fails when domain_check returns 1 ---
echo "--- install_xray_ws_tls: domain_check EOF → returns non-zero ---"
PORT_SET_CALLED=0
XRAY_INSTALL_CALLED=0
FIREWALL_SET_CALLED=0
port_set() { PORT_SET_CALLED=$((PORT_SET_CALLED + 1)); }
xray_install() { XRAY_INSTALL_CALLED=$((XRAY_INSTALL_CALLED + 1)); return 0; }
firewall_set() { FIREWALL_SET_CALLED=$((FIREWALL_SET_CALLED + 1)); }
# Mock all other functions to no-ops
is_root() { :; }; check_and_create_user_group() { :; }; check_system() { :; }
dependency_install() { :; }; basic_optimization() { :; }; create_directory() { :; }
old_config_exist_check() { :; }
# Make domain_check fail (simulates EOF or validation failure)
domain_check() { return 1; }
install_xray_ws_tls 2>/dev/null
ws_tls_rc=$?
if [[ ${ws_tls_rc} -ne 0 ]]; then
    ok "install_xray_ws_tls returns non-zero when domain_check fails (${ws_tls_rc})"
else
    bad "install_xray_ws_tls should return non-zero when domain_check fails"
fi
if [[ ${PORT_SET_CALLED} -eq 0 && ${XRAY_INSTALL_CALLED} -eq 0 && ${FIREWALL_SET_CALLED} -eq 0 ]]; then
    ok "install_xray_ws_tls: port_set/xray_install/firewall_set NOT called"
else
    bad "install_xray_ws_tls: downstream called (port=${PORT_SET_CALLED}, xray=${XRAY_INSTALL_CALLED}, fw=${FIREWALL_SET_CALLED})"
fi
unset -f domain_check port_set xray_install firewall_set

# --- Test 13: install_xray_reality fails when ip_check returns 1 ---
echo "--- install_xray_reality: ip_check EOF → returns non-zero ---"
PORT_SET_CALLED=0
XRAY_INSTALL_CALLED=0
FIREWALL_SET_CALLED=0
port_set() { PORT_SET_CALLED=$((PORT_SET_CALLED + 1)); }
xray_install() { XRAY_INSTALL_CALLED=$((XRAY_INSTALL_CALLED + 1)); return 0; }
firewall_set() { FIREWALL_SET_CALLED=$((FIREWALL_SET_CALLED + 1)); }
# Make ip_check fail (simulates EOF or validation failure)
ip_check() { return 1; }
install_xray_reality 2>/dev/null
reality_rc=$?
if [[ ${reality_rc} -ne 0 ]]; then
    ok "install_xray_reality returns non-zero when ip_check fails (${reality_rc})"
else
    bad "install_xray_reality should return non-zero when ip_check fails"
fi
if [[ ${PORT_SET_CALLED} -eq 0 && ${XRAY_INSTALL_CALLED} -eq 0 && ${FIREWALL_SET_CALLED} -eq 0 ]]; then
    ok "install_xray_reality: port_set/xray_install/firewall_set NOT called"
else
    bad "install_xray_reality: downstream called (port=${PORT_SET_CALLED}, xray=${XRAY_INSTALL_CALLED}, fw=${FIREWALL_SET_CALLED})"
fi
unset -f ip_check port_set xray_install firewall_set

echo ""
echo "============================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
