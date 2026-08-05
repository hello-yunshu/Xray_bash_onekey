#!/usr/bin/env bash
# Port safety — refuse occupied ports without killing processes.
#
# Coverage:
#   - port_exist_check returns non-zero when port is occupied by a non-project process
#   - no kill/kill -9/pkill/fuser -k is ever invoked
#   - systemctl stop is NOT called by port_exist_check
#   - the occupying process remains alive after the check
#   - port_exist_check returns 0 for a free port
#   - port_exist_check returns 1 for invalid (non-numeric) port format
#   - empty port argument returns 0 (no-op)
#   - port_listener_info outputs listener details without terminating
#
# Run: bash .github/test/test_port_safety.sh

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

# --- Track dangerous calls ---
KILL_CALLED=0
PKILL_CALLED=0
FUSER_KILL_CALLED=0
SYSTEMCTL_STOP_CALLED=0

kill()    { KILL_CALLED=$((KILL_CALLED + 1)); }
pkill()   { PKILL_CALLED=$((PKILL_CALLED + 1)); }
fuser()   {
    # Only flag if -k is passed (kill mode)
    [[ "$*" == *"-k"* ]] && FUSER_KILL_CALLED=$((FUSER_KILL_CALLED + 1))
}
systemctl() {
    [[ "$1" == "stop" ]] && SYSTEMCTL_STOP_CALLED=$((SYSTEMCTL_STOP_CALLED + 1))
}

# --- Mock lsof/ss to simulate an occupied port ---
# Simulate port 443 being occupied by a non-project process (e.g. a panel).
port_listener_info() {
    local port="$1"
    if [[ "${port}" == "443" ]]; then
        # Simulate a listener on 443 (a non-project process)
        printf 'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n'
        printf 'paneld   9999 root   10u  IPv4  12345      0t0  TCP *:https (LISTEN)\n'
        return 0
    elif [[ "${port}" == "8443" ]]; then
        printf 'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n'
        printf 'sshd     8888 root   5u   IPv4  12346      0t0  TCP *:8443 (LISTEN)\n'
        return 0
    fi
    return 1
}

echo "============================================================"
echo "  Section 1: Port Safety (no auto-kill)"
echo "============================================================"

# Test 1: Occupied port returns non-zero
echo "--- Occupied port 443 returns non-zero ---"
KILL_CALLED=0; PKILL_CALLED=0; FUSER_KILL_CALLED=0; SYSTEMCTL_STOP_CALLED=0
if port_exist_check "443"; then
    bad "port_exist_check 443 should return non-zero (occupied)"
else
    ok "port_exist_check 443 returns non-zero (occupied)"
fi

# Test 2: No kill/pkill/fuser -k called
echo "--- No kill/pkill/fuser -k invoked ---"
if [[ ${KILL_CALLED} -eq 0 ]]; then
    ok "kill was NOT called"
else
    bad "kill was called ${KILL_CALLED} time(s)"
fi
if [[ ${PKILL_CALLED} -eq 0 ]]; then
    ok "pkill was NOT called"
else
    bad "pkill was called ${PKILL_CALLED} time(s)"
fi
if [[ ${FUSER_KILL_CALLED} -eq 0 ]]; then
    ok "fuser -k was NOT called"
else
    bad "fuser -k was called ${FUSER_KILL_CALLED} time(s)"
fi

# Test 3: systemctl stop NOT called
echo "--- systemctl stop NOT called ---"
if [[ ${SYSTEMCTL_STOP_CALLED} -eq 0 ]]; then
    ok "systemctl stop was NOT called"
else
    bad "systemctl stop was called ${SYSTEMCTL_STOP_CALLED} time(s)"
fi

# Test 4: Free port returns 0
echo "--- Free port returns 0 ---"
# port_listener_info returns non-zero (no output) for port 9999
if port_exist_check "9999"; then
    ok "port_exist_check 9999 returns 0 (free)"
else
    bad "port_exist_check 9999 should return 0 (free)"
fi

# Test 5: Invalid (non-numeric) port returns 1
echo "--- Non-numeric port returns 1 ---"
if port_exist_check "abc"; then
    bad "port_exist_check 'abc' should return 1 (invalid format)"
else
    ok "port_exist_check 'abc' returns 1 (invalid format)"
fi

# Test 6: Empty port returns 0 (no-op)
echo "--- Empty port returns 0 (no-op) ---"
if port_exist_check ""; then
    ok "port_exist_check '' returns 0 (no-op)"
else
    bad "port_exist_check '' should return 0 (no-op)"
fi

# Test 7: Occupied by sshd also returns non-zero (no special-casing of services)
echo "--- Port occupied by sshd returns non-zero ---"
KILL_CALLED=0; SYSTEMCTL_STOP_CALLED=0
if port_exist_check "8443"; then
    bad "port_exist_check 8443 should return non-zero (sshd occupies)"
else
    ok "port_exist_check 8443 returns non-zero (sshd occupies)"
fi
if [[ ${KILL_CALLED} -eq 0 && ${SYSTEMCTL_STOP_CALLED} -eq 0 ]]; then
    ok "sshd was NOT killed or stopped"
else
    bad "sshd was killed or stopped (kill=${KILL_CALLED}, stop=${SYSTEMCTL_STOP_CALLED})"
fi

# Test 8: Static check — install.sh must not contain auto-kill patterns in port_exist_check
echo "--- Static: no kill/-9/pkill/fuser -k in port_exist_check body ---"
# Extract the port_exist_check function body and verify no kill patterns
port_func_body=$(sed -n '/^port_exist_check()/,/^}/p' "${REPO_DIR}/install.sh")
if printf '%s' "${port_func_body}" | grep -qE '\bkill\b|kill -9|pkill|fuser -k'; then
    bad "port_exist_check body contains kill/pkill/fuser -k"
else
    ok "port_exist_check body is free of kill/pkill/fuser -k"
fi

# Test 9: Third-party nginx (process named "nginx" but NOT from project path)
echo "--- Third-party nginx on port 443 → fail, no kill/stop ---"
KILL_CALLED=0; PKILL_CALLED=0; FUSER_KILL_CALLED=0; SYSTEMCTL_STOP_CALLED=0
# Override port_listener_info to simulate a third-party nginx process
port_listener_info() {
    local port="$1"
    if [[ "${port}" == "443" ]]; then
        printf 'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n'
        printf 'nginx    7777 root   6u   IPv4  12347      0t0  TCP *:https (LISTEN)\n'
        return 0
    fi
    return 1
}
# Mock readlink/cat so is_project_service_pid sees a non-project path
readlink() { echo "/usr/sbin/nginx"; }  # NOT /usr/local/nginx/sbin/nginx
cat() {
    case "$1" in
        /proc/7777/comm) echo "nginx";;
        /proc/7777/cgroup) echo "0::/system.slice/nginx.service";;
        *) return 1 ;;
    esac
}
if port_exist_check "443"; then
    bad "port_exist_check 443 should fail for third-party nginx"
else
    ok "port_exist_check 443 fails for third-party nginx"
fi
if [[ ${KILL_CALLED} -eq 0 && ${SYSTEMCTL_STOP_CALLED} -eq 0 ]]; then
    ok "third-party nginx NOT killed or stopped"
else
    bad "third-party nginx was killed/stopped (kill=${KILL_CALLED}, stop=${SYSTEMCTL_STOP_CALLED})"
fi
# Restore mocks
unset -f readlink cat
port_listener_info() {
    local port="$1"
    if [[ "${port}" == "443" ]]; then
        printf 'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n'
        printf 'paneld   9999 root   10u  IPv4  12345      0t0  TCP *:https (LISTEN)\n'
        return 0
    elif [[ "${port}" == "8443" ]]; then
        printf 'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n'
        printf 'sshd     8888 root   5u   IPv4  12346      0t0  TCP *:8443 (LISTEN)\n'
        return 0
    fi
    return 1
}

# Test 10: Project nginx (process from /usr/local/nginx/sbin/nginx) → allowed
echo "--- Project nginx on port 443 → allowed ---"
port_listener_info() {
    local port="$1"
    if [[ "${port}" == "443" ]]; then
        printf 'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n'
        printf 'nginx    5555 root   6u   IPv4  12348      0t0  TCP *:https (LISTEN)\n'
        return 0
    fi
    return 1
}
readlink() {
    [[ "$1" == "/proc/5555/exe" ]] && echo "/usr/local/nginx/sbin/nginx" || return 1
}
if port_exist_check "443"; then
    ok "port_exist_check 443 allows project nginx"
else
    bad "port_exist_check 443 should allow project nginx"
fi
unset -f readlink

# Test 11: Reality install does NOT call xray_install when port is occupied
echo "--- Reality port conflict → xray_install NOT called ---"
XRAY_INSTALL_CALLED=0
xray_install() { XRAY_INSTALL_CALLED=$((XRAY_INSTALL_CALLED + 1)); return 0; }
# Mock all other functions to no-ops
is_root() { :; }; check_and_create_user_group() { :; }; check_system() { :; }
dependency_install() { :; }; basic_optimization() { :; }; create_directory() { :; }
old_config_exist_check() { :; }; ip_check() { :; }
port_set() { port="443"; }; email_set() { :; }; UUID_set() { :; }
target_set() { :; }; serverNames_set() { :; }; shortIds_set() { :; }
spiderx_set() { :; }; xray_reality_add_more_choose() { :; }
validate_active_ports() { :; }
# Port 443 occupied by third-party
port_listener_info() {
    [[ "$1" == "443" ]] && printf 'nginx 7777 root 6u IPv4 12347 0t0 TCP *:https (LISTEN)\n' && return 0
    return 1
}
readlink() { echo "/usr/sbin/nginx"; }
install_xray_reality 2>/dev/null
rc=$?
if [[ ${XRAY_INSTALL_CALLED} -eq 0 ]]; then
    ok "xray_install NOT called when port is occupied"
else
    bad "xray_install was called ${XRAY_INSTALL_CALLED} time(s) despite port conflict"
fi
if [[ ${rc} -ne 0 ]]; then
    ok "install_xray_reality returns non-zero on port conflict (${rc})"
else
    bad "install_xray_reality should return non-zero on port conflict"
fi
unset -f readlink xray_install

echo ""
echo "============================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
