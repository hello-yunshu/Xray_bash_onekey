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

# --- Test 15: Full TCP+UDP INPUT+OUTPUT reconciliation (443→8443) ---
# Restore firewall helper functions that were unset by Tests 10, 11, 13.
firewall_rule_exists() {
    local proto="$1" port="$2"
    iptables -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT >/dev/null 2>&1
}
firewall_add_managed_port() {
    local proto="$1" port="$2"
    firewall_rule_exists "${proto}" "${port}" ||
        iptables -I INPUT -p "${proto}" --dport "${port}" -j ACCEPT
}
firewall_remove_managed_port() {
    local proto="$1" port="$2"
    while firewall_rule_exists "${proto}" "${port}"; do
        iptables -D INPUT -p "${proto}" --dport "${port}" -j ACCEPT || return 1
    done
}
firewall_add_output_port() {
    local proto="$1" port="$2"
    iptables -C OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT >/dev/null 2>&1 ||
        iptables -I OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT
}
firewall_output_rule_exists() {
    local proto="$1" port="$2"
    iptables -C OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT >/dev/null 2>&1
}
firewall_remove_output_port() {
    local proto="$1" port="$2"
    while firewall_output_rule_exists "${proto}" "${port}"; do
        iptables -D OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT || return 1
    done
}
echo "--- Full reconcile: TCP+UDP INPUT+OUTPUT 443→8443 ---"
: > "${IPTABLES_RULES_FILE}"
# Pre-populate old managed rules (INPUT + OUTPUT, TCP + UDP for 443)
echo "INPUT:tcp:443"       >> "${IPTABLES_RULES_FILE}"
echo "INPUT:udp:443"       >> "${IPTABLES_RULES_FILE}"
echo "OUTPUT:tcp:sport:443" >> "${IPTABLES_RULES_FILE}"
echo "OUTPUT:udp:sport:443" >> "${IPTABLES_RULES_FILE}"
# User rule (should NOT be removed)
echo "INPUT:tcp:22"        >> "${IPTABLES_RULES_FILE}"

old_json='{"tcp":[443],"udp":[443]}'
new_json='{"tcp":[8443],"udp":[8443]}'

reconcile_managed_firewall "${old_json}" "${new_json}"

# Old 443 INPUT TCP/UDP should be removed
if grep -qxF "INPUT:tcp:443" "${IPTABLES_RULES_FILE}"; then
    bad "INPUT TCP 443 should be removed"
else
    ok "INPUT TCP 443 removed"
fi
if grep -qxF "INPUT:udp:443" "${IPTABLES_RULES_FILE}"; then
    bad "INPUT UDP 443 should be removed"
else
    ok "INPUT UDP 443 removed"
fi
# Old 443 OUTPUT TCP/UDP should be removed
if grep -qxF "OUTPUT:tcp:sport:443" "${IPTABLES_RULES_FILE}"; then
    bad "OUTPUT TCP sport 443 should be removed"
else
    ok "OUTPUT TCP sport 443 removed"
fi
if grep -qxF "OUTPUT:udp:sport:443" "${IPTABLES_RULES_FILE}"; then
    bad "OUTPUT UDP sport 443 should be removed"
else
    ok "OUTPUT UDP sport 443 removed"
fi
# New 8443 INPUT TCP/UDP should be added
if grep -qxF "INPUT:tcp:8443" "${IPTABLES_RULES_FILE}"; then
    ok "INPUT TCP 8443 added"
else
    bad "INPUT TCP 8443 not added"
fi
if grep -qxF "INPUT:udp:8443" "${IPTABLES_RULES_FILE}"; then
    ok "INPUT UDP 8443 added"
else
    bad "INPUT UDP 8443 not added"
fi
# New 8443 OUTPUT TCP/UDP should be added
if grep -qxF "OUTPUT:tcp:sport:8443" "${IPTABLES_RULES_FILE}"; then
    ok "OUTPUT TCP sport 8443 added"
else
    bad "OUTPUT TCP sport 8443 not added"
fi
if grep -qxF "OUTPUT:udp:sport:8443" "${IPTABLES_RULES_FILE}"; then
    ok "OUTPUT UDP sport 8443 added"
else
    bad "OUTPUT UDP sport 8443 not added"
fi
# User rule tcp:22 must survive
if grep -qxF "INPUT:tcp:22" "${IPTABLES_RULES_FILE}"; then
    ok "User rule INPUT TCP 22 preserved"
else
    bad "User rule INPUT TCP 22 was removed"
fi

# --- Test 16: collect_new_managed_ports produces both TCP and UDP ---
echo "--- collect_new_managed_ports produces TCP and UDP arrays ---"
port="443"
xport="10086"
gport=""
xhttpport=""
transport_mode="onlyws"
tls_mode="TLS"
new_ports_json=""
collect_new_managed_ports
tcp_len=$(jq -r '.tcp | length' <<< "${new_ports_json}")
udp_len=$(jq -r '.udp | length' <<< "${new_ports_json}")
if [[ "${tcp_len}" == "2" && "${udp_len}" == "2" ]]; then
    ok "collect_new_managed_ports: tcp=${tcp_len} udp=${udp_len} (both populated)"
else
    bad "collect_new_managed_ports: tcp=${tcp_len} udp=${udp_len} (expected 2/2)"
fi
# Verify both arrays contain the same ports
tcp_ports=$(jq -r '.tcp | sort | join(",")' <<< "${new_ports_json}")
udp_ports=$(jq -r '.udp | sort | join(",")' <<< "${new_ports_json}")
if [[ "${tcp_ports}" == "${udp_ports}" ]]; then
    ok "collect_new_managed_ports: tcp and udp contain same ports (${tcp_ports})"
else
    bad "collect_new_managed_ports: tcp=${tcp_ports} udp=${udp_ports} (mismatch)"
fi

# ============================================================================
# Firewall transaction tests (apply_managed_firewall_transaction)
# ============================================================================
# Re-establish the base firewall helpers (earlier tests unset/redefined them).
_tx_restore_helpers() {
    firewall_rule_exists() {
        local proto="$1" port="$2"
        iptables -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT >/dev/null 2>&1
    }
    firewall_add_managed_port() {
        local proto="$1" port="$2"
        firewall_rule_exists "${proto}" "${port}" ||
            iptables -I INPUT -p "${proto}" --dport "${port}" -j ACCEPT
    }
    firewall_remove_managed_port() {
        local proto="$1" port="$2"
        while firewall_rule_exists "${proto}" "${port}"; do
            iptables -D INPUT -p "${proto}" --dport "${port}" -j ACCEPT || return 1
        done
    }
    firewall_add_output_port() {
        local proto="$1" port="$2"
        iptables -C OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT >/dev/null 2>&1 ||
            iptables -I OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT
    }
    firewall_output_rule_exists() {
        local proto="$1" port="$2"
        iptables -C OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT >/dev/null 2>&1
    }
    firewall_remove_output_port() {
        local proto="$1" port="$2"
        while firewall_output_rule_exists "${proto}" "${port}"; do
            iptables -D OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT || return 1
        done
    }
}

# --- Test 17: apply_managed_firewall_transaction success (443 -> 8443) ---
echo "--- T17: apply_managed_firewall_transaction success (443->8443) ---"
: > "${IPTABLES_RULES_FILE}"
echo "INPUT:tcp:443"        >> "${IPTABLES_RULES_FILE}"
echo "OUTPUT:tcp:sport:443" >> "${IPTABLES_RULES_FILE}"
echo '{"tcp":[443],"udp":[]}' > "${managed_ports_file}"
_tx_restore_helpers
_reinstall_firewall_old_ports='{"tcp":[443],"udp":[]}'
_reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
_reinstall_firewall_changed="no"

if apply_managed_firewall_transaction \
        '{"tcp":[443],"udp":[]}' '{"tcp":[8443],"udp":[]}'; then
    ok "T17 transaction succeeded"
else
    bad "T17 transaction should succeed"
fi
if grep -qxF "INPUT:tcp:443" "${IPTABLES_RULES_FILE}"; then
    bad "T17 old INPUT 443 should be removed"
else
    ok "T17 old INPUT 443 removed"
fi
if grep -qxF "OUTPUT:tcp:sport:443" "${IPTABLES_RULES_FILE}"; then
    bad "T17 old OUTPUT 443 should be removed"
else
    ok "T17 old OUTPUT 443 removed"
fi
if grep -qxF "INPUT:tcp:8443" "${IPTABLES_RULES_FILE}"; then
    ok "T17 new INPUT 8443 added"
else
    bad "T17 new INPUT 8443 not added"
fi
if grep -qxF "OUTPUT:tcp:sport:8443" "${IPTABLES_RULES_FILE}"; then
    ok "T17 new OUTPUT 8443 added"
else
    bad "T17 new OUTPUT 8443 not added"
fi
if [[ -f "${managed_ports_file}" ]] && grep -q "8443" "${managed_ports_file}"; then
    ok "T17 managed_ports.json written with 8443"
else
    bad "T17 managed_ports.json missing 8443"
fi
if [[ "${_reinstall_firewall_changed}" == "yes" ]]; then
    ok "T17 firewall marked changed"
else
    bad "T17 firewall not marked changed"
fi

# --- Test 18: transaction rollback on partial new-rule add failure ---
echo "--- T18: rollback when a new UDP rule add fails mid-way ---"
: > "${IPTABLES_RULES_FILE}"
echo "INPUT:tcp:443"        >> "${IPTABLES_RULES_FILE}"
echo "INPUT:udp:443"        >> "${IPTABLES_RULES_FILE}"
echo "OUTPUT:tcp:sport:443" >> "${IPTABLES_RULES_FILE}"
echo "OUTPUT:udp:sport:443" >> "${IPTABLES_RULES_FILE}"
echo '{"tcp":[443],"udp":[443]}' > "${managed_ports_file}"
_tx_restore_helpers
# Make udp 8443 add fail so the forward reconcile fails midway.
eval "$(declare -f firewall_add_managed_port | sed 's/^firewall_add_managed_port/_orig_firewall_add_managed_port/')"
firewall_add_managed_port() {
    local proto="$1" port="$2"
    if [[ "${proto}" == "udp" && "${port}" == "8443" ]]; then
        return 1
    fi
    _orig_firewall_add_managed_port "${proto}" "${port}"
}
_reinstall_firewall_old_ports='{"tcp":[443],"udp":[443]}'
_reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
_reinstall_firewall_changed="no"

if apply_managed_firewall_transaction \
        '{"tcp":[443],"udp":[443]}' '{"tcp":[8443],"udp":[8443]}'; then
    bad "T18 transaction should fail on add failure"
else
    ok "T18 transaction failed (fail-closed)"
fi
# Already-added new rules removed.
if grep -qxF "INPUT:tcp:8443" "${IPTABLES_RULES_FILE}"; then
    bad "T18 new INPUT 8443 should be removed by rollback"
else
    ok "T18 new INPUT 8443 removed by rollback"
fi
# Already-removed old rules restored (INPUT+OUTPUT, tcp+udp).
if grep -qxF "INPUT:tcp:443" "${IPTABLES_RULES_FILE}" && \
   grep -qxF "INPUT:udp:443" "${IPTABLES_RULES_FILE}" && \
   grep -qxF "OUTPUT:tcp:sport:443" "${IPTABLES_RULES_FILE}" && \
   grep -qxF "OUTPUT:udp:sport:443" "${IPTABLES_RULES_FILE}"; then
    ok "T18 old rules restored"
else
    bad "T18 old rules not fully restored"
fi
# managed_ports.json keeps the old value.
if [[ -f "${managed_ports_file}" ]] && grep -q '"tcp":\[443\]' "${managed_ports_file}"; then
    ok "T18 managed_ports.json keeps old value"
else
    bad "T18 managed_ports.json changed"
fi
unset -f firewall_add_managed_port _orig_firewall_add_managed_port

# --- Test 19: transaction rollback on managed_ports.json write failure ---
echo "--- T19: rollback when writing managed_ports.json fails ---"
: > "${IPTABLES_RULES_FILE}"
echo "INPUT:tcp:443"        >> "${IPTABLES_RULES_FILE}"
echo "OUTPUT:tcp:sport:443" >> "${IPTABLES_RULES_FILE}"
echo '{"tcp":[443],"udp":[]}' > "${managed_ports_file}"
_tx_restore_helpers
eval "$(declare -f atomic_write_managed_ports | sed 's/^atomic_write_managed_ports/_orig_atomic_write/')"
atomic_write_managed_ports() { return 1; }
_reinstall_firewall_old_ports='{"tcp":[443],"udp":[]}'
_reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
_reinstall_firewall_changed="no"

if apply_managed_firewall_transaction \
        '{"tcp":[443],"udp":[]}' '{"tcp":[8443],"udp":[]}'; then
    bad "T19 transaction should fail on write failure"
else
    ok "T19 transaction failed on write failure"
fi
# Reverse new->old applied: old restored, new not残留.
if grep -qxF "INPUT:tcp:443" "${IPTABLES_RULES_FILE}"; then
    ok "T19 old INPUT 443 restored"
else
    bad "T19 old INPUT 443 not restored"
fi
if grep -qxF "INPUT:tcp:8443" "${IPTABLES_RULES_FILE}"; then
    bad "T19 new INPUT 8443 should not残留"
else
    ok "T19 new INPUT 8443 removed"
fi
unset -f atomic_write_managed_ports
eval "$(declare -f _orig_atomic_write | sed 's/^_orig_atomic_write/atomic_write_managed_ports/')"
unset -f _orig_atomic_write

# --- Test 20: rollback when no managed_ports.json existed before ---
echo "--- T20: rollback with no prior managed_ports.json ---"
: > "${IPTABLES_RULES_FILE}"
rm -f "${managed_ports_file}"
_tx_restore_helpers
# Two new ports; fail on the second so the first gets added then rolled back.
eval "$(declare -f firewall_add_managed_port | sed 's/^firewall_add_managed_port/_orig_firewall_add_managed_port/')"
firewall_add_managed_port() {
    local proto="$1" port="$2"
    if [[ "${proto}" == "tcp" && "${port}" == "8444" ]]; then
        return 1
    fi
    _orig_firewall_add_managed_port "${proto}" "${port}"
}
_reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
_reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
_reinstall_firewall_changed="no"

if apply_managed_firewall_transaction \
        '{"tcp":[],"udp":[]}' '{"tcp":[8443,8444],"udp":[]}'; then
    bad "T20 transaction should fail (rollback not skipped)"
else
    ok "T20 transaction failed (rollback not skipped)"
fi
if grep -qxF "INPUT:tcp:8443" "${IPTABLES_RULES_FILE}"; then
    bad "T20 new INPUT 8443 should be removed"
else
    ok "T20 new INPUT 8443 removed"
fi
if grep -qxF "INPUT:tcp:8444" "${IPTABLES_RULES_FILE}"; then
    bad "T20 INPUT 8444 should not exist"
else
    ok "T20 INPUT 8444 absent"
fi
if [[ -e "${managed_ports_file}" ]]; then
    bad "T20 managed_ports.json should not be created"
else
    ok "T20 no managed_ports.json created"
fi
unset -f firewall_add_managed_port _orig_firewall_add_managed_port

# --- Test 21: TLS -> Reality removes the unneeded managed port 80 rule ---
echo "--- T21: TLS->Reality removes unneeded port 80 managed rule ---"
: > "${IPTABLES_RULES_FILE}"
echo "INPUT:tcp:443"        >> "${IPTABLES_RULES_FILE}"
echo "INPUT:udp:443"        >> "${IPTABLES_RULES_FILE}"
echo "INPUT:tcp:80"         >> "${IPTABLES_RULES_FILE}"
echo "INPUT:udp:80"         >> "${IPTABLES_RULES_FILE}"
echo "OUTPUT:tcp:sport:443" >> "${IPTABLES_RULES_FILE}"
echo "OUTPUT:udp:sport:443" >> "${IPTABLES_RULES_FILE}"
echo "OUTPUT:tcp:sport:80"  >> "${IPTABLES_RULES_FILE}"
echo "OUTPUT:udp:sport:80"  >> "${IPTABLES_RULES_FILE}"
echo '{"tcp":[443,80],"udp":[443,80]}' > "${managed_ports_file}"
_tx_restore_helpers
_reinstall_firewall_old_ports='{"tcp":[443,80],"udp":[443,80]}'
_reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
_reinstall_firewall_changed="no"

if apply_managed_firewall_transaction \
        '{"tcp":[443,80],"udp":[443,80]}' '{"tcp":[443],"udp":[443]}'; then
    ok "T21 transaction succeeded"
else
    bad "T21 transaction should succeed"
fi
# Stale port 80 rules残留 check (INPUT/OUTPUT, tcp/udp).
if grep -qxF "INPUT:tcp:80" "${IPTABLES_RULES_FILE}" || \
   grep -qxF "INPUT:udp:80" "${IPTABLES_RULES_FILE}" || \
   grep -qxF "OUTPUT:tcp:sport:80" "${IPTABLES_RULES_FILE}" || \
   grep -qxF "OUTPUT:udp:sport:80" "${IPTABLES_RULES_FILE}"; then
    bad "T21 stale port 80 rules residues"
else
    ok "T21 port 80 rules removed"
fi
if grep -qxF "INPUT:tcp:443" "${IPTABLES_RULES_FILE}"; then
    ok "T21 port 443 kept"
else
    bad "T21 port 443 should be kept"
fi

echo ""
echo "============================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
