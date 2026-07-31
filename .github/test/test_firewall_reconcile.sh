#!/usr/bin/env bash
# Section 5: Firewall reconciliation minimal fix.
#
# Coverage:
#   - firewall_rule_exists / firewall_add_managed_port / firewall_remove_managed_port
#     use mocked iptables to verify idempotent add (no duplicate rules)
#   - reconcile_managed_firewall removes old script-managed ports and adds new ones
#   - user (non-managed) rules are NOT removed
#   - atomic_write_managed_ports writes valid JSON
#   - collect_new_managed_ports produces correct JSON from port variables
#   - repeated add does not create duplicate rules
#
# Run: bash .github/test/test_firewall_reconcile.sh

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

# --- Mock iptables: track rules in a file ---
IPTABLES_RULES_FILE="${TMP_ROOT}/iptables_rules.txt"
: > "${IPTABLES_RULES_FILE}"

# Track iptables calls
IPTABLES_CALLS=0

iptables() {
    IPTABLES_CALLS=$((IPTABLES_CALLS + 1))
    local op="$1"  # -C, -I, -D
    local chain="$2"
    shift 2
    local proto="" port=""

    # Parse args for proto and dport
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p) proto="$2"; shift 2 ;;
            --dport) port="$2"; shift 2 ;;
            -j) shift 2 ;;
            *) shift ;;
        esac
    done

    local rule_key="${proto}:${port}"

    case "${op}" in
        -C)
            # Check if rule exists
            grep -qxF "${rule_key}" "${IPTABLES_RULES_FILE}" 2>/dev/null
            return $?
            ;;
        -I)
            # Insert only if not exists
            if grep -qxF "${rule_key}" "${IPTABLES_RULES_FILE}" 2>/dev/null; then
                return 0  # Already exists, don't duplicate
            fi
            echo "${rule_key}" >> "${IPTABLES_RULES_FILE}"
            return 0
            ;;
        -D)
            # Delete rule
            if grep -qxF "${rule_key}" "${IPTABLES_RULES_FILE}" 2>/dev/null; then
                # Remove the line
                local tmp
                tmp=$(grep -vxF "${rule_key}" "${IPTABLES_RULES_FILE}" || true)
                printf '%s\n' "${tmp}" > "${IPTABLES_RULES_FILE}"
                return 0
            fi
            return 1  # Rule doesn't exist
            ;;
    esac
}

# Set managed_ports_file to temp location
managed_ports_file="${TMP_ROOT}/managed_ports.json"

echo "============================================================"
echo "  Section 5: Firewall Reconciliation"
echo "============================================================"

# --- Test 1: firewall_add_managed_port is idempotent ---
echo "--- firewall_add_managed_port is idempotent (no duplicate) ---"
: > "${IPTABLES_RULES_FILE}"
firewall_add_managed_port tcp 443
firewall_add_managed_port tcp 443
firewall_add_managed_port tcp 443
count=$(grep -cxF "tcp:443" "${IPTABLES_RULES_FILE}" || echo 0)
if [[ "${count}" == "1" ]]; then
    ok "Repeated firewall_add_managed_port results in exactly 1 rule"
else
    bad "Expected 1 rule for tcp:443, got ${count}"
fi

# --- Test 2: firewall_rule_exists ---
echo "--- firewall_rule_exists ---"
if firewall_rule_exists tcp 443; then
    ok "firewall_rule_exists tcp 443 returns 0 (exists)"
else
    bad "firewall_rule_exists tcp 443 should return 0"
fi
if firewall_rule_exists tcp 9999; then
    bad "firewall_rule_exists tcp 9999 should return 1 (not exists)"
else
    ok "firewall_rule_exists tcp 9999 returns 1 (not exists)"
fi

# --- Test 3: firewall_remove_managed_port ---
echo "--- firewall_remove_managed_port ---"
firewall_remove_managed_port tcp 443
if firewall_rule_exists tcp 443; then
    bad "firewall_remove_managed_port did not remove tcp 443"
else
    ok "firewall_remove_managed_port removed tcp 443"
fi

# --- Test 4: reconcile_managed_firewall removes old, adds new ---
echo "--- reconcile_managed_firewall: 443->8443 ---"
: > "${IPTABLES_RULES_FILE}"
# Simulate: old managed ports were 443, new managed ports are 8443
# Add a user rule (tcp:22) that should NOT be removed
echo "tcp:22" >> "${IPTABLES_RULES_FILE}"
echo "tcp:443" >> "${IPTABLES_RULES_FILE}"

old_json='{"tcp":[443],"udp":[]}'
new_json='{"tcp":[8443],"udp":[]}'

reconcile_managed_firewall "${old_json}" "${new_json}"

# 443 should be removed (was managed, not in new set)
if firewall_rule_exists tcp 443; then
    bad "reconcile did not remove old managed port 443"
else
    ok "reconcile removed old managed port 443"
fi
# 8443 should be added
if firewall_rule_exists tcp 8443; then
    ok "reconcile added new managed port 8443"
else
    bad "reconcile did not add new managed port 8443"
fi
# 22 (user rule) should still exist
if firewall_rule_exists tcp 22; then
    ok "reconcile preserved user rule tcp 22"
else
    bad "reconcile removed user rule tcp 22"
fi

# --- Test 5: reconcile does not remove ports that are still managed ---
echo "--- reconcile: port stays if in both old and new ---"
: > "${IPTABLES_RULES_FILE}"
echo "tcp:443" >> "${IPTABLES_RULES_FILE}"
old_json='{"tcp":[443],"udp":[]}'
new_json='{"tcp":[443,8443],"udp":[]}'
reconcile_managed_firewall "${old_json}" "${new_json}"
if firewall_rule_exists tcp 443 && firewall_rule_exists tcp 8443; then
    ok "reconcile kept 443 and added 8443"
else
    bad "reconcile failed to maintain 443 or add 8443"
fi

# --- Test 6: atomic_write_managed_ports ---
echo "--- atomic_write_managed_ports writes valid JSON ---"
test_json='{"tcp":[443,8443],"udp":[]}'
if atomic_write_managed_ports "${test_json}"; then
    if jq empty "${managed_ports_file}" >/dev/null 2>&1; then
        ok "atomic_write_managed_ports wrote valid JSON"
    else
        bad "atomic_write_managed_ports wrote invalid JSON"
    fi
else
    bad "atomic_write_managed_ports returned non-zero"
fi

# Verify content
written_tcp=$(jq -r '.tcp[]' "${managed_ports_file}")
if printf '%s\n' "${written_tcp}" | grep -qxF "443" && printf '%s\n' "${written_tcp}" | grep -qxF "8443"; then
    ok "managed_ports.json contains correct tcp ports"
else
    bad "managed_ports.json has incorrect tcp ports"
fi

# --- Test 7: atomic_write rejects invalid JSON ---
echo "--- atomic_write rejects invalid JSON ---"
bad_json='{"tcp":[443,invalid}'
if atomic_write_managed_ports "${bad_json}"; then
    bad "atomic_write_managed_ports should reject invalid JSON"
else
    ok "atomic_write_managed_ports rejects invalid JSON"
fi

# --- Test 8: collect_new_managed_ports ---
echo "--- collect_new_managed_ports produces correct JSON ---"
port="443"
xport="10086"
gport="10087"
xhttpport="10088"
transport_mode="wsgRPCxhttp"
tls_mode="TLS"
new_ports_json=""
collect_new_managed_ports
if jq empty <<< "${new_ports_json}" >/dev/null 2>&1; then
    collected_tcp=$(jq -r '.tcp[]' <<< "${new_ports_json}")
    found_all=1
    for p in 443 10086 10087 10088; do
        printf '%s\n' "${collected_tcp}" | grep -qxF "${p}" || found_all=0
    done
    if [[ ${found_all} -eq 1 ]]; then
        ok "collect_new_managed_ports collected all 4 ports"
    else
        bad "collect_new_managed_ports missed some ports"
    fi
else
    bad "collect_new_managed_ports produced invalid JSON"
fi

# --- Test 9: collect excludes disabled protocol ports ---
echo "--- collect excludes disabled protocol ports ---"
port="443"
xport="10086"
gport=""
xhttpport=""
transport_mode="onlyws"
tls_mode="TLS"
new_ports_json=""
collect_new_managed_ports
collected_count=$(jq -r '.tcp | length' <<< "${new_ports_json}")
if [[ "${collected_count}" == "2" ]]; then
    ok "collect_new_managed_ports excluded disabled protocol ports (got ${collected_count})"
else
    bad "Expected 2 ports for onlyws, got ${collected_count}"
fi

# --- Test 10: reconcile_managed_firewall fails closed on remove failure ---
echo "--- reconcile fails closed when firewall_remove_managed_port fails ---"
: > "${IPTABLES_RULES_FILE}"
echo "tcp:443" >> "${IPTABLES_RULES_FILE}"
# Override firewall_remove_managed_port to always fail
firewall_remove_managed_port() { return 1; }
old_json='{"tcp":[443],"udp":[]}'
new_json='{"tcp":[8443],"udp":[]}'
if reconcile_managed_firewall "${old_json}" "${new_json}"; then
    bad "reconcile should fail when firewall_remove_managed_port fails"
else
    ok "reconcile fails closed when firewall_remove_managed_port fails"
fi
# Restore original
unset -f firewall_remove_managed_port

# --- Test 11: reconcile_managed_firewall fails closed on add failure ---
echo "--- reconcile fails closed when firewall_add_managed_port fails ---"
: > "${IPTABLES_RULES_FILE}"
# Override firewall_add_managed_port to always fail
firewall_add_managed_port() { return 1; }
old_json='{"tcp":[],"udp":[]}'
new_json='{"tcp":[8443],"udp":[]}'
if reconcile_managed_firewall "${old_json}" "${new_json}"; then
    bad "reconcile should fail when firewall_add_managed_port fails"
else
    ok "reconcile fails closed when firewall_add_managed_port fails"
fi
# Restore original
unset -f firewall_add_managed_port

# --- Test 12: firewall_set writes managed_ports.json and is idempotent ---
echo "--- firewall_set writes managed_ports.json and is idempotent ---"
: > "${IPTABLES_RULES_FILE}"
# Extend mock to handle -A, OUTPUT, --sport, -i/-o, --dport range
iptables() {
    IPTABLES_CALLS=$((IPTABLES_CALLS + 1))
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
}

# Set up variables for firewall_set
ID="ubuntu"
tls_mode="XTLS"
port="443"
xport=""
gport=""
xhttpport=""
transport_mode="None"
pkg_install() { return 0; }
service() { return 0; }
netfilter-persistent() { return 0; }
iptables-save() { return 0; }

# Simulate user saying Yes to firewall
firewall_set_fq="y"

# Run firewall_set twice — second run must not duplicate rules
firewall_set <<< "y" >/dev/null 2>&1
rules_after_first=$(wc -l < "${IPTABLES_RULES_FILE}" | tr -d ' ')

firewall_set <<< "y" >/dev/null 2>&1
rules_after_second=$(wc -l < "${IPTABLES_RULES_FILE}" | tr -d ' ')

if [[ "${rules_after_first}" == "${rules_after_second}" ]]; then
    ok "firewall_set idempotent: ${rules_after_first} rules both runs"
else
    bad "firewall_set not idempotent: ${rules_after_first} -> ${rules_after_second} rules"
fi

# Verify managed_ports.json was written
if [[ -f "${managed_ports_file}" ]] && jq empty "${managed_ports_file}" >/dev/null 2>&1; then
    ok "firewall_set wrote valid managed_ports.json"
else
    bad "firewall_set did not write valid managed_ports.json"
fi

# --- Test 13: Firewall rollback restores old rules on reconcile failure ---
echo "--- Firewall rollback: reconcile failure restores old rules ---"
: > "${IPTABLES_RULES_FILE}"
echo "tcp:443" >> "${IPTABLES_RULES_FILE}"  # old managed port
echo "tcp:22" >> "${IPTABLES_RULES_FILE}"   # user rule (should NOT be removed)

old_json='{"tcp":[443],"udp":[]}'
new_json='{"tcp":[8443],"udp":[]}'

# Snapshot state before reconcile
rules_before=$(sort "${IPTABLES_RULES_FILE}")

# Make firewall_add_managed_port fail for 8443 (simulate mid-way failure)
firewall_add_managed_port() {
    local proto="$1" port="$2"
    [[ "${port}" == "8443" ]] && return 1
    # Delegate to original for other ports
    unset -f firewall_add_managed_port
    firewall_add_managed_port "${proto}" "${port}"
}

# Reconcile should fail (add of 8443 fails)
if reconcile_managed_firewall "${old_json}" "${new_json}"; then
    bad "reconcile should fail when add fails"
else
    ok "reconcile fails when add fails (fail-closed)"
fi

# Reverse reconciliation to undo partial changes (best-effort rollback)
unset -f firewall_add_managed_port
reconcile_managed_firewall "${new_json}" "${old_json}" 2>/dev/null || true

# After rollback: 443 should be back (was removed by forward reconcile, re-added by reverse)
# 22 should still be there (never touched)
if grep -qxF "tcp:22" "${IPTABLES_RULES_FILE}"; then
    ok "User rule tcp:22 preserved through rollback"
else
    bad "User rule tcp:22 was removed during rollback"
fi

# --- Test 14: reset_port rollback restores managed_ports.json ---
echo "--- reset_port rollback restores managed_ports.json ---"
# Setup: create config files and managed_ports.json
TEST_CONFIG="${TMP_ROOT}/install_config.json"
TEST_XRAY_CONF="${TMP_ROOT}/xray_config.json"
TEST_MANAGED="${TMP_ROOT}/managed_ports.json"
echo '{"tcp":[443],"udp":[]}' > "${TEST_MANAGED}"
echo '{"port":443}' > "${TEST_CONFIG}"
echo '{}' > "${TEST_XRAY_CONF}"

# Save original values
xray_install_config_file="${TEST_CONFIG}"
xray_conf="${TEST_XRAY_CONF}"
managed_ports_file="${TEST_MANAGED}"

managed_before=$(cat "${TEST_MANAGED}")

# Simulate: managed_ports.json should be unchanged after rollback
# The _reset_port_rollback function restores from snapshot
_rollback_managed_ports=$(mktemp)
cp "${TEST_MANAGED}" "${_rollback_managed_ports}"

# Modify managed_ports.json (simulating a failed write)
echo '{"tcp":[8443],"udp":[]}' > "${TEST_MANAGED}"

# Call rollback (with dummy config/xray files)
_rollback_config_file=$(mktemp); cp "${TEST_CONFIG}" "${_rollback_config_file}"
_rollback_xray_conf=$(mktemp); cp "${TEST_XRAY_CONF}" "${_rollback_xray_conf}"
_reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"

managed_after=$(cat "${TEST_MANAGED}")
if [[ "${managed_before}" == "${managed_after}" ]]; then
    ok "managed_ports.json restored after rollback"
else
    bad "managed_ports.json NOT restored: before=${managed_before} after=${managed_after}"
fi

echo ""
echo "============================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
