#!/usr/bin/env bash
# IPv6-aware managed-firewall regression tests.
#
# Coverage:
#   - managed_fw_ipv6_enabled honors _MANAGED_FW_IPV6 override (1/0/auto)
#   - firewall_add_managed_port mirrors a rule onto BOTH ip6tables and iptables
#     when IPv6 management is enabled (idempotent on each family)
#   - firewall_rule_exists is satisfied only when the rule exists on every family
#   - firewall_remove_managed_port / firewall_remove_output_port remove from both
#   - reconcile_managed_firewall applies and rolls back on both families
#   - IPv4-only mode must NOT touch ip6tables
#
# Run: bash .github/test/test_firewall_ipv6.sh
# shellcheck disable=SC2034  # managed_ports_file is set for the helpers under test

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

# --- family-aware netfilter mocks -----------------------------------------
# Each family keeps its own rules file so we can assert mirroring precisely.
IPTABLES_V4_RULES="${TMP_ROOT}/rules.v4"
IPTABLES_V6_RULES="${TMP_ROOT}/rules.v6"
: > "${IPTABLES_V4_RULES}"
: > "${IPTABLES_V6_RULES}"

# Mock a netfilter binary against a per-family rules file. Shared dispatcher so
# both families behave identically; each keeps its own rules file.
_nf() {
    local rules_file="$1"
    shift
    local op="$1" chain="$2"
    shift 2
    local proto="" port=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p) proto="$2"; shift 2 ;;
            --dport) port="$2"; shift 2 ;;
            --sport) port="$2"; shift 2 ;;
            -j) shift 2 ;;
            *) shift ;;
        esac
    done
    local key="${proto}:${port:-${chain}}"
    case "${op}" in
        -C) grep -qxF "${key}" "${rules_file}" 2>/dev/null ;;
        -I|-A)
            grep -qxF "${key}" "${rules_file}" 2>/dev/null && return 0
            echo "${key}" >> "${rules_file}" ;;
        -D)
            if grep -qxF "${key}" "${rules_file}" 2>/dev/null; then
                local tmp
                tmp=$(grep -vxF "${key}" "${rules_file}" || true)
                printf '%s\n' "${tmp}" > "${rules_file}"
            else
                return 1
            fi ;;
    esac
}
iptables()  { _nf "${IPTABLES_V4_RULES}" "$@"; }
ip6tables() { _nf "${IPTABLES_V6_RULES}" "$@"; }

# Deterministic tool-availability control. The production command_available()
# probes the host PATH via `command -v`; on a CI runner with a real
# /usr/sbin/ip6tables, `unset -f ip6tables` is NOT enough to simulate a missing
# tool (the system binary would still be found). Mock the probe instead so a
# host-installed ip6tables can never leak into these test cases.
MOCK_MISSING_TOOLS=""   # space-separated tool names treated as unavailable
command_available() {
    local name="$1" _t
    for _t in ${MOCK_MISSING_TOOLS}; do
        [[ "${_t}" == "${name}" ]] && return 1
    done
    command -v "${name}" >/dev/null 2>&1
}

managed_ports_file="${TMP_ROOT}/managed_ports.json"

echo "============================================================"
echo "  IPv6-aware firewall management"
echo "============================================================"

# --- managed_fw_ipv6_enabled override ---
echo "--- managed_fw_ipv6_enabled override ---"
_MANAGED_FW_IPV6=1
if managed_fw_ipv6_enabled; then ok "_MANAGED_FW_IPV6=1 enables IPv6"; else bad "_MANAGED_FW_IPV6=1 should enable IPv6"; fi
_MANAGED_FW_IPV6=0
if managed_fw_ipv6_enabled; then bad "_MANAGED_FW_IPV6=0 should disable IPv6"; else ok "_MANAGED_FW_IPV6=0 disables IPv6"; fi
_MANAGED_FW_IPV6=auto
if managed_fw_ipv6_enabled; then ok "auto detects ip6tables (available)"; else bad "auto should detect ip6tables"; fi

# --- dual-stack add mirrors to both families ---
echo "--- dual-stack add mirrors to both families ---"
_MANAGED_FW_IPV6=1
firewall_add_managed_port tcp 443
firewall_add_managed_port tcp 443   # idempotent
if grep -qxF "tcp:443" "${IPTABLES_V4_RULES}"; then ok "iptables has tcp:443"; else bad "iptables missing tcp:443"; fi
if grep -qxF "tcp:443" "${IPTABLES_V6_RULES}"; then ok "ip6tables has tcp:443 (mirrored)"; else bad "ip6tables missing tcp:443"; fi
v4_count=$(grep -cxF "tcp:443" "${IPTABLES_V4_RULES}")
v6_count=$(grep -cxF "tcp:443" "${IPTABLES_V6_RULES}")
if [[ "${v4_count}" -eq 1 && "${v6_count}" -eq 1 ]]; then
    ok "no duplicate rule on either family (v4=${v4_count} v6=${v6_count})"
else
    bad "duplicate rules detected (v4=${v4_count} v6=${v6_count})"
fi
if firewall_rule_exists tcp 443; then ok "firewall_rule_exists satisfied on both families"; else bad "firewall_rule_exists should be satisfied"; fi

# --- OUTPUT mirroring ---
firewall_add_output_port udp 443
if grep -qxF "udp:443" "${IPTABLES_V6_RULES}"; then ok "ip6tables OUTPUT udp:443 mirrored"; else bad "ip6tables missing OUTPUT udp:443"; fi
if firewall_output_rule_exists udp 443; then ok "firewall_output_rule_exists satisfied"; else bad "firewall_output_rule_exists should be satisfied"; fi

# --- dual-stack remove from both families ---
echo "--- dual-stack remove from both families ---"
firewall_remove_managed_port tcp 443
if firewall_rule_exists tcp 443; then bad "rule should be removed from both families"; else ok "rule removed from both families"; fi
firewall_remove_output_port udp 443
if firewall_output_rule_exists udp 443; then bad "OUTPUT rule should be removed"; else ok "OUTPUT rule removed from both families"; fi

# --- reconcile applies + rolls back on both families ---
echo "--- reconcile applies + rolls back on both families ---"
_MANAGED_FW_IPV6=1
reconcile_managed_firewall '{"tcp":[],"udp":[]}' '{"tcp":["8443"],"udp":["8443"]}'
if grep -qxF "tcp:8443" "${IPTABLES_V4_RULES}" && grep -qxF "tcp:8443" "${IPTABLES_V6_RULES}"; then
    ok "reconcile added 8443 on both families"
else
    bad "reconcile did not add 8443 on both families"
fi
# rollback new -> old
reconcile_managed_firewall '{"tcp":["8443"],"udp":["8443"]}' '{"tcp":[],"udp":[]}'
if grep -qxF "tcp:8443" "${IPTABLES_V4_RULES}" || grep -qxF "tcp:8443" "${IPTABLES_V6_RULES}"; then
    bad "rollback left stale 8443 rule"
else
    ok "rollback removed 8443 on both families"
fi

# --- IPv4-only mode never touches ip6tables ---
echo "--- IPv4-only mode never touches ip6tables ---"
_MANAGED_FW_IPV6=0
: > "${IPTABLES_V6_RULES}"
firewall_add_managed_port tcp 443
if [[ -s "${IPTABLES_V6_RULES}" ]]; then bad "IPv4-only mode must not write ip6tables"; else ok "IPv4-only mode leaves ip6tables untouched"; fi
if grep -qxF "tcp:443" "${IPTABLES_V4_RULES}"; then ok "IPv4-only mode still manages iptables"; else bad "IPv4-only mode should manage iptables"; fi

# --- network_mode-driven family policy (production; no _MANAGED_FW_IPV6 override) ---
echo "--- network_mode-driven family policy (production) ---"
unset _MANAGED_FW_IPV6

# ipv4: only iptables touched
network_mode="ipv4"
: > "${IPTABLES_V4_RULES}"; : > "${IPTABLES_V6_RULES}"
firewall_add_managed_port tcp 443
if grep -qxF "tcp:443" "${IPTABLES_V4_RULES}"; then ok "ipv4 mode manages iptables"; else bad "ipv4 mode should manage iptables"; fi
if [[ -s "${IPTABLES_V6_RULES}" ]]; then bad "ipv4 mode must not touch ip6tables"; else ok "ipv4 mode leaves ip6tables untouched"; fi

# ipv6: only ip6tables touched
network_mode="ipv6"
: > "${IPTABLES_V4_RULES}"; : > "${IPTABLES_V6_RULES}"
firewall_add_managed_port tcp 443
if grep -qxF "tcp:443" "${IPTABLES_V6_RULES}"; then ok "ipv6 mode manages ip6tables"; else bad "ipv6 mode should manage ip6tables"; fi
if [[ -s "${IPTABLES_V4_RULES}" ]]; then bad "ipv6 mode must not touch iptables"; else ok "ipv6 mode leaves iptables untouched"; fi

# dual: both touched
network_mode="dual"
: > "${IPTABLES_V4_RULES}"; : > "${IPTABLES_V6_RULES}"
firewall_add_managed_port tcp 443
if grep -qxF "tcp:443" "${IPTABLES_V4_RULES}" && grep -qxF "tcp:443" "${IPTABLES_V6_RULES}"; then
    ok "dual mode manages both families"
else
    bad "dual mode should manage both families"
fi

# dual + no ip6tables -> fail closed (no silent single-family downgrade)
network_mode="dual"
MOCK_MISSING_TOOLS="ip6tables"
if managed_fw_require_families; then bad "dual with missing ip6tables must fail closed"; else ok "dual + no ip6tables fails closed"; fi
MOCK_MISSING_TOOLS=""

# ipv6 + no ip6tables -> fail
network_mode="ipv6"
MOCK_MISSING_TOOLS="ip6tables"
if managed_fw_require_families; then bad "ipv6 with missing ip6tables must fail"; else ok "ipv6 + no ip6tables fails"; fi
MOCK_MISSING_TOOLS=""

# ipv4 + no ip6tables -> fine (only iptables required)
network_mode="ipv4"
MOCK_MISSING_TOOLS="ip6tables"
if managed_fw_require_families; then ok "ipv4 + no ip6tables is fine"; else bad "ipv4 should not require ip6tables"; fi
MOCK_MISSING_TOOLS=""

# manual: conservative, iptables only
network_mode="manual"
: > "${IPTABLES_V4_RULES}"; : > "${IPTABLES_V6_RULES}"
firewall_add_managed_port tcp 443
if grep -qxF "tcp:443" "${IPTABLES_V4_RULES}" && [[ ! -s "${IPTABLES_V6_RULES}" ]]; then
    ok "manual mode manages iptables only (conservative)"
else
    bad "manual mode should manage iptables only"
fi

# rollback is family-consistent per network_mode
echo "--- family-consistent rollback by network_mode ---"
network_mode="dual"
: > "${IPTABLES_V4_RULES}"; : > "${IPTABLES_V6_RULES}"
reconcile_managed_firewall '{"tcp":[],"udp":[]}' '{"tcp":["8443"],"udp":["8443"]}'
if grep -qxF "tcp:8443" "${IPTABLES_V4_RULES}" && grep -qxF "tcp:8443" "${IPTABLES_V6_RULES}"; then
    ok "dual reconcile adds on both families"
else
    bad "dual reconcile missing a family"
fi
reconcile_managed_firewall '{"tcp":["8443"],"udp":["8443"]}' '{"tcp":[],"udp":[]}'
if grep -qxF "tcp:8443" "${IPTABLES_V4_RULES}" || grep -qxF "tcp:8443" "${IPTABLES_V6_RULES}"; then
    bad "dual rollback left stale rule"
else
    ok "dual rollback removes from both families"
fi

network_mode="ipv6"
: > "${IPTABLES_V4_RULES}"; : > "${IPTABLES_V6_RULES}"
reconcile_managed_firewall '{"tcp":[],"udp":[]}' '{"tcp":["8443"],"udp":["8443"]}'
if grep -qxF "tcp:8443" "${IPTABLES_V6_RULES}" && [[ ! -s "${IPTABLES_V4_RULES}" ]]; then
    ok "ipv6 reconcile only touches v6"
else
    bad "ipv6 reconcile touched v4 firewall"
fi
reconcile_managed_firewall '{"tcp":["8443"],"udp":["8443"]}' '{"tcp":[],"udp":[]}'
if grep -qxF "tcp:8443" "${IPTABLES_V6_RULES}"; then
    bad "ipv6 rollback left stale v6 rule"
else
    ok "ipv6 rollback removes v6 rule"
fi

network_mode="ipv4"
: > "${IPTABLES_V4_RULES}"; : > "${IPTABLES_V6_RULES}"
reconcile_managed_firewall '{"tcp":[],"udp":[]}' '{"tcp":["8443"],"udp":["8443"]}'
if grep -qxF "tcp:8443" "${IPTABLES_V4_RULES}" && [[ ! -s "${IPTABLES_V6_RULES}" ]]; then
    ok "ipv4 reconcile only touches v4"
else
    bad "ipv4 reconcile touched v6 firewall"
fi
reconcile_managed_firewall '{"tcp":["8443"],"udp":["8443"]}' '{"tcp":[],"udp":[]}'
if grep -qxF "tcp:8443" "${IPTABLES_V4_RULES}"; then
    bad "ipv4 rollback left stale v4 rule"
else
    ok "ipv4 rollback removes v4 rule"
fi

echo
if [[ ${FAIL} -eq 0 ]]; then
    printf 'ALL IPv6 firewall tests PASSED (%d)\n' "${PASS}"
else
    printf 'IPv6 firewall tests FAILED: %d pass, %d fail\n' "${PASS}" "${FAIL}"
    exit 1
fi