#!/usr/bin/env bash
# Firewall cross-network-family transaction regression tests.
#
# The firewall reconcile/transaction must be family-aware: the OLD family set
# (from the previous network_mode) and the NEW family set (from the target
# network_mode) must be tracked and reconciled by set difference, so that
# transitions such as dual -> ipv4 clean the stale IPv6 managed rules even when
# the port set is unchanged. This file locks the defect with the mandatory
# matrix from the dual-stack final rectification checklist.
#
# Coverage (21-case checklist, firewall part 1-17):
#   Family transition (same port 443 -> 443, TCP):
#     [1] ipv4 443 -> dual 443
#     [2] dual 443 -> ipv4 443
#     [3] ipv6 443 -> dual 443
#     [4] dual 443 -> ipv6 443
#     [5] ipv4 443 -> ipv6 443
#     [6] ipv6 443 -> ipv4 443
#   Port + family simultaneously changed (443 -> 8443, TCP + UDP):
#     [7] dual 443 -> ipv4 8443
#     [8] ipv4 443 -> dual 8443
#     [9] dual 443 -> ipv6 8443
#     [10] ipv6 443 -> dual 8443
#   Rollback (failure injected in forward):
#     [11] dual 443 -> ipv4 8443 fails; final state restores dual 443
#     [12] ipv4 443 -> dual 443, IPv6 add fails; final keeps only ipv4 443
#   Persistence (union of old ∪ new families must be saved):
#     [13] dual -> ipv4: iptables-save AND ip6tables-save called
#     [14] dual -> ipv6: iptables-save AND ip6tables-save called
#   Backend unavailable (must never silently degrade):
#     [15] ipv4 mode + no ip6tables -> succeeds
#     [16] ipv6 mode + no ip6tables -> explicit fail
#     [17] dual mode + no ip6tables -> explicit fail (no silent ipv4-only)
#   Fresh-process runtime hydration ([18]-[21] Reality/XTLS/None/multi-user)
#   are covered by .github/test/test_dual_stack_runtime.sh (also mandatory CI).
#
# All netfilter interactions are mocked; this test never touches the host
# iptables/ip6tables.
#
# Run: bash .github/test/test_firewall_family_transition.sh
# shellcheck disable=SC2034,SC2154  # mocked/global state used by helpers under test

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

# Capture firewall warnings (persistence failure assertions below).
LOG_CAPTURE="${TMP_ROOT}/log.txt"
: > "${LOG_CAPTURE}"
log_echo() { printf '%s\n' "$*" >> "${LOG_CAPTURE}"; }
gettext()  { printf '%s' "$1"; }

# --- family-aware netfilter mocks -----------------------------------------
IPTABLES_V4_RULES="${TMP_ROOT}/rules.v4"
IPTABLES_V6_RULES="${TMP_ROOT}/rules.v6"
reset_rules() { : > "${IPTABLES_V4_RULES}"; : > "${IPTABLES_V6_RULES}"; }

# MOCK_FAIL_ADD="<family>:<proto>:<port>" makes the matching -I fail (used to
# inject a forward failure for the rollback cases). Empty = never fail.
MOCK_FAIL_ADD=""
_nf() {
    local family="$1" rules_file="$2"
    shift 2
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
            if [[ -n "${MOCK_FAIL_ADD:-}" && "${MOCK_FAIL_ADD}" == "${family}:${key}" ]]; then
                return 1
            fi
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
iptables()  { _nf "iptables"  "${IPTABLES_V4_RULES}" "$@"; }
ip6tables() { _nf "ip6tables" "${IPTABLES_V6_RULES}" "$@"; }

# Deterministic tool-availability probe mock (see test_firewall_ipv6.sh).
MOCK_MISSING_TOOLS=""
command_available() {
    local name="$1" _t
    for _t in ${MOCK_MISSING_TOOLS}; do
        [[ "${_t}" == "${name}" ]] && return 1
    done
    command -v "${name}" >/dev/null 2>&1
}

# --- persistence mocks -----------------------------------------------------
# Redirect targets are overridden to temp files so a mocked save binary never
# writes a real host path. Calls are counted for the persistence assertions.
FW_RULES_V4="${TMP_ROOT}/persist.v4"
FW_RULES_V6="${TMP_ROOT}/persist.v6"
ID="ubuntu"
SAVE_V4_CALLS=0
SAVE_V6_CALLS=0
iptables-save()  { SAVE_V4_CALLS=$((SAVE_V4_CALLS + 1)); printf 'MOCKED_V4\n'; }
ip6tables-save() { SAVE_V6_CALLS=$((SAVE_V6_CALLS + 1)); printf 'MOCKED_V6\n'; }

managed_ports_file="${TMP_ROOT}/managed_ports.json"

# --- rule-state helpers ----------------------------------------------------
v4_has()  { grep -qxF "$1" "${IPTABLES_V4_RULES}" 2>/dev/null; }
v6_has()  { grep -qxF "$1" "${IPTABLES_V6_RULES}" 2>/dev/null; }
v4_empty() { [[ ! -s "${IPTABLES_V4_RULES}" ]]; }
v6_empty() { [[ ! -s "${IPTABLES_V6_RULES}" ]]; }

J='{"tcp":["443"],"udp":[]}'
J8='{"tcp":["8443"],"udp":[]}'
B4="iptables"
B6="ip6tables"
B46="iptables ip6tables"

echo "============================================================"
echo "  Firewall cross-family transition (reconcile, explicit bins)"
echo "============================================================"

# --- [1] ipv4 443 -> dual 443 --------------------------------------------
reset_rules
reconcile_managed_firewall "${J}" "${J}" "${B4}" "${B46}"
if v4_has "tcp:443" && v6_has "tcp:443"; then ok "[1] ipv4 443 -> dual 443 opens IPv6"; else bad "[1] ipv4->dual did not add IPv6 443"; fi

# --- [2] dual 443 -> ipv4 443 (same port MUST still clean IPv6) -----------
reset_rules
reconcile_managed_firewall "${J}" "${J}" "${B46}" "${B4}"
if v4_has "tcp:443" && v6_empty; then ok "[2] dual 443 -> ipv4 443 cleans stale IPv6"; else bad "[2] dual->ipv4 left stale IPv6 rule"; fi

# --- [3] ipv6 443 -> dual 443 ---------------------------------------------
reset_rules
reconcile_managed_firewall "${J}" "${J}" "${B6}" "${B46}"
if v6_has "tcp:443" && v4_has "tcp:443"; then ok "[3] ipv6 443 -> dual 443 opens IPv4"; else bad "[3] ipv6->dual did not add IPv4 443"; fi

# --- [4] dual 443 -> ipv6 443 (same port MUST still clean IPv4) -----------
reset_rules
reconcile_managed_firewall "${J}" "${J}" "${B46}" "${B6}"
if v6_has "tcp:443" && v4_empty; then ok "[4] dual 443 -> ipv6 443 cleans stale IPv4"; else bad "[4] dual->ipv6 left stale IPv4 rule"; fi

# --- [5] ipv4 443 -> ipv6 443 ---------------------------------------------
reset_rules
reconcile_managed_firewall "${J}" "${J}" "${B4}" "${B6}"
if v6_has "tcp:443" && v4_empty; then ok "[5] ipv4 443 -> ipv6 443 migrates family"; else bad "[5] ipv4->ipv6 did not migrate rules"; fi

# --- [6] ipv6 443 -> ipv4 443 ---------------------------------------------
reset_rules
reconcile_managed_firewall "${J}" "${J}" "${B6}" "${B4}"
if v4_has "tcp:443" && v6_empty; then ok "[6] ipv6 443 -> ipv4 443 migrates family"; else bad "[6] ipv6->ipv4 did not migrate rules"; fi

# --- [7] dual 443 -> ipv4 8443 (port + family change) ---------------------
reset_rules
reconcile_managed_firewall "${J}" "${J8}" "${B46}" "${B4}"
if v4_has "tcp:8443" && ! v4_has "tcp:443" && v6_empty; then
    ok "[7] dual 443 -> ipv4 8443 removes 443, adds 8443, cleans IPv6"
else
    bad "[7] dual->ipv4 port+family transition incorrect"
fi

# --- [8] ipv4 443 -> dual 8443 --------------------------------------------
reset_rules
reconcile_managed_firewall "${J}" "${J8}" "${B4}" "${B46}"
if v4_has "tcp:8443" && ! v4_has "tcp:443" && v6_has "tcp:8443"; then
    ok "[8] ipv4 443 -> dual 8443 adds on both families"
else
    bad "[8] ipv4->dual port+family transition incorrect"
fi

# --- [9] dual 443 -> ipv6 8443 --------------------------------------------
reset_rules
reconcile_managed_firewall "${J}" "${J8}" "${B46}" "${B6}"
if v6_has "tcp:8443" && ! v6_has "tcp:443" && v4_empty; then
    ok "[9] dual 443 -> ipv6 8443 cleans IPv4, migrates to v6"
else
    bad "[9] dual->ipv6 port+family transition incorrect"
fi

# --- [10] ipv6 443 -> dual 8443 -------------------------------------------
reset_rules
reconcile_managed_firewall "${J}" "${J8}" "${B6}" "${B46}"
if v6_has "tcp:8443" && ! v6_has "tcp:443" && v4_has "tcp:8443"; then
    ok "[10] ipv6 443 -> dual 8443 adds on both families"
else
    bad "[10] ipv6->dual port+family transition incorrect"
fi

# --- UDP does not diverge (dual -> ipv4 with tcp+udp) ----------------------
echo "--- UDP family reconcile ---"
JU='{"tcp":["443"],"udp":["443"]}'
reset_rules
reconcile_managed_firewall "${JU}" "${JU}" "${B46}" "${B4}"
if v4_has "tcp:443" && v4_has "udp:443" && v6_empty; then
    ok "dual(tcp+udp 443) -> ipv4 cleans both v6 protocols"
else
    bad "dual->ipv4 UDP family reconcile diverged"
fi
JU8='{"tcp":["8443"],"udp":["8443"]}'
reset_rules
reconcile_managed_firewall "${JU}" "${JU8}" "${B4}" "${B46}"
if v4_has "tcp:8443" && v4_has "udp:8443" && ! v4_has "tcp:443" && v6_has "tcp:8443" && v6_has "udp:8443"; then
    ok "ipv4(tcp+udp 443) -> dual(tcp+udp 8443) adds both protocols on both families"
else
    bad "ipv4->dual UDP+TCP transition diverged"
fi

echo "============================================================"
echo "  Rollback (family-aware, failure injected in forward)"
echo "============================================================"

# --- [11] old dual 443 -> new ipv4 8443, forward fails --------------------
# Inject failure when the forward adds tcp:8443 on IPv4 (common-family add).
reset_rules
reconcile_managed_firewall "${J}" "${J}" "${B46}" "${B46}"   # seed old dual 443
if v4_has "tcp:443" && v6_has "tcp:443"; then ok "[11] seeded old dual 443"; else bad "[11] seed failed"; fi

MOCK_FAIL_ADD="iptables:tcp:8443"
if apply_managed_firewall_transaction "${J}" "${J8}" "${B46}" "${B4}"; then
    bad "[11] apply should have failed (forward injected)"
else
    ok "[11] apply returned failure on injected forward"
fi
MOCK_FAIL_ADD=""
if v4_has "tcp:443" && v6_has "tcp:443" && ! v4_has "tcp:8443" && ! v6_has "tcp:8443"; then
    ok "[11] rollback restores dual 443 (v4 restored, v6 restored, no 8443)"
else
    bad "[11] rollback did not restore dual 443 (v4=$(cat "${IPTABLES_V4_RULES}") v6=$(cat "${IPTABLES_V6_RULES}"))"
fi

# --- [12] old ipv4 443 -> new dual 443, IPv6 add fails ---------------------
reset_rules
reconcile_managed_firewall "${J}" "${J}" "${B4}" "${B4}"     # seed old ipv4 443
if v4_has "tcp:443"; then ok "[12] seeded old ipv4 443"; else bad "[12] seed failed"; fi

MOCK_FAIL_ADD="ip6tables:tcp:443"
if apply_managed_firewall_transaction "${J}" "${J}" "${B4}" "${B46}"; then
    bad "[12] apply should have failed (IPv6 add injected)"
else
    ok "[12] apply returned failure on injected IPv6 add"
fi
MOCK_FAIL_ADD=""
if v4_has "tcp:443" && v6_empty; then
    ok "[12] rollback leaves only old ipv4 443 (no residual IPv6 rule)"
else
    bad "[12] rollback left residual IPv6 rule (v6=$(cat "${IPTABLES_V6_RULES}"))"
fi

echo "============================================================"
echo "  Persistence (family union old ∪ new must be saved)"
echo "============================================================"

# --- [13] dual -> ipv4: both families must be persisted --------------------
SAVE_V4_CALLS=0; SAVE_V6_CALLS=0
persist13=$(firewall_persist_families "${B46}" "${B4}")
persist13=${persist13% }  # strip the trailing separator added by tr
if [[ "${persist13}" == "iptables ip6tables" ]]; then
    ok "[13] dual->ipv4 family union = iptables ip6tables"
else
    bad "[13] union wrong: '${persist13}'"
fi
firewall_persist_rules "${persist13}"
if [[ "${SAVE_V4_CALLS}" -ge 1 && "${SAVE_V6_CALLS}" -ge 1 ]]; then
    ok "[13] dual->ipv4 persists BOTH IPv4 and IPv6 (cleaned v6 must be saved)"
else
    bad "[13] persistence skipped a family (v4=${SAVE_V4_CALLS} v6=${SAVE_V6_CALLS})"
fi

# --- [14] dual -> ipv6: both families must be persisted --------------------
SAVE_V4_CALLS=0; SAVE_V6_CALLS=0
persist14=$(firewall_persist_families "${B46}" "${B6}")
persist14=${persist14% }  # strip the trailing separator added by tr
if [[ "${persist14}" == "iptables ip6tables" ]]; then
    ok "[14] dual->ipv6 family union = iptables ip6tables"
else
    bad "[14] union wrong: '${persist14}'"
fi
firewall_persist_rules "${persist14}"
if [[ "${SAVE_V4_CALLS}" -ge 1 && "${SAVE_V6_CALLS}" -ge 1 ]]; then
    ok "[14] dual->ipv6 persists BOTH IPv4 and IPv6 (cleaned v4 must be saved)"
else
    bad "[14] persistence skipped a family (v4=${SAVE_V4_CALLS} v6=${SAVE_V6_CALLS})"
fi

# --- persistence failure must warn (never silent success) ------------------
: > "${LOG_CAPTURE}"
iptables-save()  { SAVE_V4_CALLS=$((SAVE_V4_CALLS + 1)); return 1; }
ip6tables-save() { SAVE_V6_CALLS=$((SAVE_V6_CALLS + 1)); printf 'MOCKED_V6\n'; }
SAVE_V4_CALLS=0; SAVE_V6_CALLS=0
firewall_persist_rules "$(firewall_persist_families "${B46}" "${B4}")"
if grep -q "iptables" "${LOG_CAPTURE}" && grep -q "规则持久化失败" "${LOG_CAPTURE}"; then
    ok "IPv4 save failure surfaces a warning naming iptables (no silent success)"
else
    bad "IPv4 save failure was silent; log=$(cat "${LOG_CAPTURE}")"
fi
iptables-save()  { SAVE_V4_CALLS=$((SAVE_V4_CALLS + 1)); printf 'MOCKED_V4\n'; }
ip6tables-save() { SAVE_V6_CALLS=$((SAVE_V6_CALLS + 1)); printf 'MOCKED_V6\n'; }

echo "============================================================"
echo "  Backend unavailable (no silent degradation)"
echo "============================================================"

# --- [15] ipv4 mode + no ip6tables -> must succeed -------------------------
network_mode="ipv4"
MOCK_MISSING_TOOLS="ip6tables"
if managed_fw_require_families; then ok "[15] ipv4 + no ip6tables succeeds"; else bad "[15] ipv4 must not require ip6tables"; fi
MOCK_MISSING_TOOLS=""

# --- [16] ipv6 mode + no ip6tables -> explicit fail ------------------------
network_mode="ipv6"
MOCK_MISSING_TOOLS="ip6tables"
if managed_fw_require_families; then bad "[16] ipv6 + no ip6tables must fail"; else ok "[16] ipv6 + no ip6tables fails explicitly"; fi
MOCK_MISSING_TOOLS=""

# --- [17] dual mode + no ip6tables -> explicit fail (no silent ipv4-only) --
network_mode="dual"
MOCK_MISSING_TOOLS="ip6tables"
if managed_fw_require_families; then bad "[17] dual + no ip6tables must fail closed"; else ok "[17] dual + no ip6tables fails closed (no silent ipv4-only)"; fi
MOCK_MISSING_TOOLS=""

echo
if [[ ${FAIL} -eq 0 ]]; then
    printf 'ALL firewall family-transition tests PASSED (%d)\n' "${PASS}"
else
    printf 'firewall family-transition tests FAILED: %d pass, %d fail\n' "${PASS}" "${FAIL}"
    exit 1
fi
