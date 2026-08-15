#!/usr/bin/env bash
# DNS multi-record behavior regression tests.
#
# Coverage (real resolve_domain_ips + classify_resolved_ips with a mocked dig):
#   - multiple A and multiple AAAA records are all returned
#   - duplicate records (same IP across resolvers) are deduplicated
#   - combined A+AAAA output is classified into resolved_ipv4s / resolved_ipv6s
#     without cross-contamination
#   - AAAA is queried via the IPv4-resolver path (transport decoupling), i.e.
#     the dig branch is exercised regardless of whether the host has IPv6
#
# Run: bash .github/test/test_dns_multi_record.sh
# shellcheck disable=SC2154  # resolved_ipv4s/resolved_ipv6s are written by classify_resolved_ips

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

# --- Mock dig: return multiple records per family, with duplicates ---
# dig is defined as a function so `command -v dig` resolves to it and the dig
# branch (the IPv4-resolver A/AAAA decoupled path) is the one under test.
dig() {
    local arg is_aaaa=0
    for arg in "$@"; do
        [[ "${arg}" == "AAAA" ]] && is_aaaa=1
    done
    if [[ ${is_aaaa} -eq 1 ]]; then
        printf '%s\n' "2001:db8::10" "2001:db8::99" "2001:db8::10"
    else
        printf '%s\n' "203.0.113.10" "203.0.113.55" "203.0.113.10"
    fi
}

# Confirm the dig branch is actually taken.
if command -v dig >/dev/null 2>&1; then
    ok "dig command resolved (function mock)"
else
    bad "dig mock not found by command -v"
fi

echo "--- resolve_domain_ips aggregates + dedups A/AAAA ---"
resolved=$(resolve_domain_ips "multi.example.com")
# Expect unique 4 addresses in deterministic order: A records then AAAA records.
expected="203.0.113.10
203.0.113.55
2001:db8::10
2001:db8::99"
if [[ "${resolved}" == "${expected}" ]]; then
    ok "resolve_domain_ips aggregates multiple A + AAAA and dedups duplicates"
else
    bad "resolve output mismatch: <<${resolved}>>"
fi
# No duplicates (each unique address appears exactly once).
for ip in 203.0.113.10 203.0.113.55 2001:db8::10 2001:db8::99; do
    n=$(printf '%s\n' "${resolved}" | grep -cxF "${ip}")
    if [[ "${n}" -eq 1 ]]; then ok "no duplicate for ${ip}"; else bad "duplicate/missing for ${ip} (count=${n})"; fi
done

echo "--- classify_resolved_ips splits A vs AAAA correctly ---"
classify_resolved_ips "${resolved}"
if [[ "${resolved_ipv4s}" == *"203.0.113.10"* && "${resolved_ipv4s}" == *"203.0.113.55"* && \
      ! "${resolved_ipv4s}" == *":"* ]]; then
    ok "all A records classified into resolved_ipv4s"
else
    bad "resolved_ipv4s wrong: '${resolved_ipv4s}'"
fi
if [[ "${resolved_ipv6s}" == *"2001:db8::10"* && "${resolved_ipv6s}" == *"2001:db8::99"* && \
      ! "${resolved_ipv6s}" == *"."* ]]; then
    ok "all AAAA records classified into resolved_ipv6s"
else
    bad "resolved_ipv6s wrong: '${resolved_ipv6s}'"
fi
# No cross-contamination.
if [[ "${resolved_ipv4s}" == *"2001:db8"* ]]; then bad "IPv6 leaked into resolved_ipv4s"; else ok "no IPv6 leak into resolved_ipv4s"; fi
if [[ "${resolved_ipv6s}" == *"203.0.113"* ]]; then bad "IPv4 leaked into resolved_ipv6s"; else ok "no IPv4 leak into resolved_ipv6s"; fi

echo
if [[ ${FAIL} -eq 0 ]]; then
    printf 'ALL DNS multi-record tests PASSED (%d)\n' "${PASS}"
else
    printf 'DNS multi-record tests FAILED: %d pass, %d fail\n' "${PASS}" "${FAIL}"
    exit 1
fi