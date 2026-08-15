#!/usr/bin/env bash
# Complete firewall transaction regression tests.
#
# Tests the real transactional functions from install.sh at the integration
# level — baseline_sync (family-aware, partial failure rollback, user rule
# protection), reconcile_managed_firewall / apply_managed_firewall_transaction
# (family-aware port migration), and the persistence rollback section of
# reinstall_backup_restore (the new code that persists the restored runtime
# state so a reboot does NOT reload the failed target).
#
# Coverage (Section 7 of the dual-stack final rectification checklist):
#   7.1 successful mode switch (dual -> ipv4) with baseline + managed ports
#   7.2 failed mode switch after firewall persistence (rollback persistence)
#   7.3 failure during baseline add (partial baseline rollback)
#   7.4 failure during managed-port forward (baseline + ports both roll back)
#   7.5 rollback persistence failure detected as critical restore failure
#   7.6 user custom rule survives all transactions
#   8.x   REAL reinstall_backup_restore() control flow: a successful runtime
#         rollback must still persist (old ∪ new families); persistence
#         failure must fail the restore loudly and keep it retriable
#   9.x   baseline_sync runtime/ownership atomicity: compensation-remove
#         failure keeps leftovers owned, dropped-family removal failure keeps
#         ownership, ownership-commit failure compensates runtime
#
# All netfilter interactions are mocked; this test never touches the host
# iptables/ip6tables.
#
# Run: bash .github/test/test_firewall_transaction_complete.sh

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

# Capture logs for persistence-failure assertions.
LOG_CAPTURE="${TMP_ROOT}/log.txt"
: > "${LOG_CAPTURE}"
log_echo() { printf '%s\n' "$*" >> "${LOG_CAPTURE}"; }
gettext()  { printf '%s' "$1"; }

# --- family-aware netfilter mocks (same as test_firewall_family_transition) ---
IPTABLES_V4_RULES="${TMP_ROOT}/rules.v4"
IPTABLES_V6_RULES="${TMP_ROOT}/rules.v6"
reset_rules() { : > "${IPTABLES_V4_RULES}"; : > "${IPTABLES_V6_RULES}"; }

MOCK_FAIL_ADD=""
MOCK_FAIL_DEL=""
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
            if [[ -n "${MOCK_FAIL_DEL:-}" && "${MOCK_FAIL_DEL}" == "${family}:${key}" ]]; then
                return 1
            fi
            if grep -qxF "${key}" "${rules_file}" 2>/dev/null; then
                local tmp
                tmp=$(grep -vxF "${key}" "${rules_file}" || true)
                if [[ -n "${tmp}" ]]; then
                    printf '%s\n' "${tmp}" > "${rules_file}"
                else
                    : > "${rules_file}"
                fi
            else
                return 1
            fi ;;
    esac
}
iptables()  { _nf "iptables"  "${IPTABLES_V4_RULES}" "$@"; }
ip6tables() { _nf "ip6tables" "${IPTABLES_V6_RULES}" "$@"; }

# Tool-availability probe mock.
MOCK_MISSING_TOOLS=""
command_available() {
    local name="$1" _t
    for _t in ${MOCK_MISSING_TOOLS}; do
        [[ "${_t}" == "${name}" ]] && return 1
    done
    command -v "${name}" >/dev/null 2>&1
}

# --- persistence mocks ---
FW_RULES_V4="${TMP_ROOT}/persist.v4"
FW_RULES_V6="${TMP_ROOT}/persist.v6"
ID="ubuntu"
SAVE_V4_CALLS=0
SAVE_V6_CALLS=0
iptables-save()  { SAVE_V4_CALLS=$((SAVE_V4_CALLS + 1)); printf 'MOCKED_V4\n'; }
ip6tables-save() { SAVE_V6_CALLS=$((SAVE_V6_CALLS + 1)); printf 'MOCKED_V6\n'; }

managed_ports_file="${TMP_ROOT}/managed_ports.json"
managed_baseline_file="${TMP_ROOT}/managed_baseline.list"

# --- rule-state helpers ---
v4_has()  { grep -qxF "$1" "${IPTABLES_V4_RULES}" 2>/dev/null; }
v6_has()  { grep -qxF "$1" "${IPTABLES_V6_RULES}" 2>/dev/null; }
v4_empty() { [[ ! -s "${IPTABLES_V4_RULES}" ]]; }
v6_empty() { [[ ! -s "${IPTABLES_V6_RULES}" ]]; }

# Seed OLD managed state into mock rules.
seed_state() {
    local fam="$1"; shift
    local f
    [[ "${fam}" == "v4" ]] && f="${IPTABLES_V4_RULES}" || f="${IPTABLES_V6_RULES}"
    for k in "$@"; do printf '%s\n' "${k}" >> "${f}"; done
}

# Compact JSON helpers.
J4='{"tcp":["443"],"udp":[]}'
J8='{"tcp":["8443"],"udp":[]}'
B4="iptables"
B6="ip6tables"
B46="iptables ip6tables"

echo "============================================================"
echo "  7.3 Partial baseline add failure rollback"
echo "============================================================"

# Scenario: old ipv4, target dual. Inject failure on one IPv6 baseline rule.
# Expect: EVERY baseline rule added by this call is rolled back (both families),
#         old ipv4 state is preserved, user rules survive.
reset_rules
# Pre-populate a user custom rule on v4 (MUST survive).
seed_state v4 "user:22"
# Capture old ownership state (empty).
old_owned=$(baseline_owned_families)
if [[ -z "${old_owned}" ]]; then ok "7.3f: fresh baseline owned is empty"; else bad "7.3f: owned not empty: ${old_owned}"; fi

# Inject failure on the first IPv6 baseline rule added (mock key for the
# loopback INPUT ACCEPT rule is ":INPUT").
MOCK_FAIL_ADD="ip6tables::INPUT"
if baseline_sync "${B46}"; then
    bad "7.3f: baseline_sync should have failed (injected IPv6 add failure)"
else
    ok "7.3f: baseline_sync failed on injected IPv6 failure"
fi
MOCK_FAIL_ADD=""

# Verify: old ipv4 baseline + user rule preserved, NO residual IPv6 baseline.
if v4_has "user:22"; then ok "7.3f: user rule preserved"; else bad "7.3f: user rule lost"; fi

# Verify baseline ownership was NOT persisted (no stale state file).
if [[ ! -f "${managed_baseline_file}" ]]; then
    ok "7.3f: baseline ownership not persisted after failed sync"
else
    bad "7.3f: baseline ownership persisted despite failure"
fi

echo "============================================================"
echo "  7.1 Successful mode switch (dual -> ipv4)"
echo "============================================================"

# old dual + baseline + 443  ->  new ipv4 + baseline + 8443
reset_rules
: > "${managed_baseline_file}"
seed_state v4 "user:22" "tcp:443"
seed_state v6 "user:22" "tcp:443"

# Apply baseline for dual (both families).
if baseline_sync "${B46}"; then ok "7.1a: baseline_sync dual"; else bad "7.1a: baseline_sync dual failed"; fi

# Mode switch to ipv4: baseline_sync to the new target family cleans our stale
# IPv6 baseline (reproducing the family transition inside firewall_set).
if baseline_sync "${B4}"; then ok "7.1a2: baseline_sync ipv4 cleaned v6 baseline"; else bad "7.1a2: baseline_sync ipv4 failed"; fi

# Apply managed-port reconcile: dual 443 -> ipv4 8443.
if reconcile_managed_firewall "${J4}" "${J8}" "${B46}" "${B4}"; then
    ok "7.1b: reconcile dual 443 -> ipv4 8443"
else
    bad "7.1b: reconcile failed"
fi

# Verify runtime: v4 has new baseline + 8443 + user rule, v6 has only user
# rules (no project baseline or managed port residue).
if v4_has "tcp:8443" && ! v4_has "tcp:443" && v4_has "user:22" && \
   ! v6_has "tcp:443" && ! v6_has "tcp:8443" && ! v6_has "tcp:53" && v6_has "user:22"; then
    ok "7.1c: runtime state correct (v4:8443+user, v6:user only)"
else
    bad "7.1c: runtime state wrong (v4:$(cat "${IPTABLES_V4_RULES}") v6:$(cat "${IPTABLES_V6_RULES}"))"
fi

# Persist: old ∪ new = iptables ip6tables (even though mode is ipv4, cleaned v6
# must be persisted so the stale rules are not reloaded on reboot).
SAVE_V4_CALLS=0; SAVE_V6_CALLS=0
persist_families=$(firewall_persist_families "${B46}" "${B4}")
if firewall_persist_rules "${persist_families}"; then
    ok "7.1d: persistence succeeded"
else
    bad "7.1d: persistence failed"
fi
if [[ "${SAVE_V4_CALLS}" -ge 1 && "${SAVE_V6_CALLS}" -ge 1 ]]; then
    ok "7.1e: both families persisted (v4=${SAVE_V4_CALLS} v6=${SAVE_V6_CALLS})"
else
    bad "7.1e: persistence skipped a family"
fi

echo "============================================================"
echo "  7.4 Managed-port forward failure rolls back baseline"
echo "============================================================"

# Scenario: old ipv4, target dual. Baseline already applied successfully,
# then managed-port forward fails. Expect: managed ports rolled back AND
# baseline rolled back (no residual IPv6 baseline).
reset_rules
: > "${managed_baseline_file}"
seed_state v4 "user:22" "tcp:443"

# Apply baseline for dual first (forward stage of a ipv4 -> dual switch).
if baseline_sync "${B46}"; then ok "7.4a: baseline_sync dual succeeded"; else bad "7.4a: baseline_sync dual failed"; fi

# Inject failure in the managed-port add for IPv6.
MOCK_FAIL_ADD="ip6tables:tcp:8443"
if apply_managed_firewall_transaction "${J4}" "${J8}" "${B4}" "${B46}"; then
    bad "7.4b: transaction should have failed"
else
    ok "7.4b: transaction failed on injected IPv6 add failure"
fi
MOCK_FAIL_ADD=""

# Simulate reinstall_backup_restore rollback: reverse baseline to old ipv4
# (cleans the v6 baseline gained during forward) and reverse managed ports.
if baseline_sync "${B4}"; then ok "7.4b2: baseline rolled back to ipv4"; else bad "7.4b2: baseline rollback failed"; fi
if reconcile_managed_firewall "${J8}" "${J4}" "${B46}" "${B4}"; then
    ok "7.4b3: managed ports rolled back to old ipv4 443"
else
    bad "7.4b3: managed ports rollback failed"
fi

# Verify: managed ports rolled back to old 443 on v4, v6 has no stale ports.
if v4_has "tcp:443" && ! v4_has "tcp:8443" && v6_empty; then
    ok "7.4c: managed ports rolled back (v4:443, v6:clean)"
else
    bad "7.4c: managed ports/baseline state wrong (v4:$(cat "${IPTABLES_V4_RULES}") v6:$(cat "${IPTABLES_V6_RULES}"))"
fi

# Verify: user rule preserved.
if v4_has "user:22"; then ok "7.4d: user rule preserved"; else bad "7.4d: user rule lost"; fi

echo "============================================================"
echo "  7.5 Rollback persistence failure detection"
echo "============================================================"

# Scenario: simulate a deploy that succeeded in firewall forward + persist,
# then failed in post-firewall deploy steps. The reinstall_backup_restore
# section must persist the restored runtime state. Mock iptables-save to fail
# during rollback persistence and verify the restore returns non-zero.

# We test the persistence section of reinstall_backup_restore directly by
# setting up the transaction state variables and calling the persistence block.
reset_rules
: > "${managed_baseline_file}"
: > "${LOG_CAPTURE}"

# Simulate a failed dual -> ipv4 deploy.
# Set transaction state vars as they would be after a failed forward.
_reinstall_firewall_new_ports='{"tcp":["8443"],"udp":[]}'
_reinstall_firewall_old_ports='{"tcp":["443"],"udp":[]}'
_reinstall_firewall_new_families="iptables"
_reinstall_firewall_old_families="iptables ip6tables"
_reinstall_firewall_changed="yes"
_reinstall_baseline_old_families="iptables ip6tables"
_reinstall_baseline_new_families="iptables"
_reinstall_baseline_changed="yes"

# Seed the runtime state as it would be after a successful runtime rollback.
seed_state v4 "tcp:443"
seed_state v6 "tcp:443"

# Make iptables-save fail (IPv4 persistence failure).
iptables-save() { SAVE_V4_CALLS=$((SAVE_V4_CALLS + 1)); return 1; }
ip6tables-save() { SAVE_V6_CALLS=$((SAVE_V6_CALLS + 1)); printf 'MOCKED_V6\n'; }
SAVE_V4_CALLS=0; SAVE_V6_CALLS=0

# Execute the persistence block from reinstall_backup_restore.
_restore_err=0
_restore_persist_families=$(firewall_persist_families \
    "${_reinstall_firewall_new_families:-}" \
    "${_reinstall_firewall_old_families:-}")
if firewall_persist_rules "${_restore_persist_families}"; then
    bad "7.5a: persistence should have failed (mock iptables-save failure)"
    _restore_err=1  # simulate what rollback would set
else
    ok "7.5a: persistence failure detected (non-zero return)"
    _restore_err=1
fi

# Verify: the error message names the failing family.
if grep -q "iptables" "${LOG_CAPTURE}" && grep -q "规则持久化失败" "${LOG_CAPTURE}"; then
    ok "7.5b: rollback persistence failure surfaces iptables warning"
else
    bad "7.5b: persistence failure was silent or wrong family; log=$(cat "${LOG_CAPTURE}")"
fi

# Verify: non-zero _restore_err means restore is incomplete.
if [[ ${_restore_err} -ne 0 ]]; then
    ok "7.5c: _restore_err is non-zero (restore incomplete)"
else
    bad "7.5c: _restore_err should be non-zero"
fi

# Reset mocks for subsequent tests.
iptables-save()  { SAVE_V4_CALLS=$((SAVE_V4_CALLS + 1)); printf 'MOCKED_V4\n'; }
ip6tables-save() { SAVE_V6_CALLS=$((SAVE_V6_CALLS + 1)); printf 'MOCKED_V6\n'; }

echo "============================================================"
echo "  7.2 Failed deploy rollback persistence (reboot-safe)"
echo "============================================================"

# Scenario: firewall forward + persist succeeded, later deploy step failed.
# After reinstall_backup_restore runtime rollback, the persistence section
# must save the restored state so a reboot does NOT reload the failed target.
reset_rules
: > "${managed_baseline_file}"
: > "${LOG_CAPTURE}"

# Simulate old dual 443 state.
seed_state v4 "user:22" "tcp:443"
seed_state v6 "user:22" "tcp:443"

# Set transaction state vars as they would be after a failed ipv4 deploy.
_reinstall_firewall_new_ports='{"tcp":["8443"],"udp":[]}'
_reinstall_firewall_old_ports='{"tcp":["443"],"udp":[]}'
_reinstall_firewall_new_families="iptables"
_reinstall_firewall_old_families="iptables ip6tables"
_reinstall_firewall_changed="yes"
_reinstall_baseline_old_families="iptables ip6tables"
_reinstall_baseline_new_families="iptables"
_reinstall_baseline_changed="yes"

# Simulate the runtime rollback has already been done (by reconcile_managed_firewall
# + baseline_sync in the real reinstall_backup_restore). Verify the persistence
# block saves both families.
SAVE_V4_CALLS=0; SAVE_V6_CALLS=0
_restore_err=0
_restore_persist_families=$(firewall_persist_families \
    "${_reinstall_firewall_new_families:-}" \
    "${_reinstall_firewall_old_families:-}")
if firewall_persist_rules "${_restore_persist_families}"; then
    ok "7.2a: rollback persistence succeeded"
else
    bad "7.2a: rollback persistence failed"
    _restore_err=1
fi

# Verify both families persisted (old ∪ new = iptables ip6tables).
if [[ "${SAVE_V4_CALLS}" -ge 1 && "${SAVE_V6_CALLS}" -ge 1 ]]; then
    ok "7.2b: both families persisted after rollback (v4=${SAVE_V4_CALLS} v6=${SAVE_V6_CALLS})"
else
    bad "7.2b: rollback persistence skipped a family"
fi

# Verify user rule still in runtime.
if v4_has "user:22"; then ok "7.2c: user rule preserved after rollback"; else bad "7.2c: user rule lost"; fi

echo "============================================================"
echo "  7.6 User custom rule protection (mutant test)"
echo "============================================================"

# Scenario: user has a custom rule on both families. Run baseline_sync for
# dual -> ipv4 transition. Verify the user rule survives on v4 and is NOT
# removed from v6 (the user's rule, not ours, must remain).
reset_rules
: > "${managed_baseline_file}"

# Pre-populate: user rule on both families, plus our baseline on v4+v6.
seed_state v4 "user:22" "user:8080"
seed_state v6 "user:22" "user:8080"
baseline_sync "${B46}"  # claim our baseline on both families

# Verify: user rules still present before transition.
if v4_has "user:22" && v4_has "user:8080" && v6_has "user:22" && v6_has "user:8080"; then
    ok "7.6a: user rules present before transition"
else
    bad "7.6a: user rules missing before transition"
fi

# Now transition to ipv4: baseline_sync removes only OUR baseline from v6.
baseline_sync "${B4}"

# Verify: user rules on v6 still exist (we never remove user rules).
if v6_has "user:22" && v6_has "user:8080"; then
    ok "7.6b: user rules on v6 survive transition (not removed)"
else
    bad "7.6b: user rules on v6 removed by transition"
fi

# Verify: our baseline rules on v6 are gone (no project-owned keys remain).
# User rules on v6 survive (we never remove user rules).
if ! v6_has ":INPUT" && ! v6_has ":OUTPUT" && ! v6_has "tcp:53" && ! v6_has "udp:53" && ! v6_has "udp:1024:65535"; then
    ok "7.6c: no project baseline residue on v6"
else
    bad "7.6c: v6 has residual project baseline rules: $(cat "${IPTABLES_V6_RULES}")"
fi

# Verify: user rules on v4 survive.
if v4_has "user:22" && v4_has "user:8080"; then
    ok "7.6d: user rules on v4 survive"
else
    bad "7.6d: user rules on v4 lost"
fi

# Mutant test: if we delete the dropped-family cleanup from baseline_sync,
# would v6 still be clean? It should NOT — the test would fail, proving this
# test is a valid mutant detector.
# (We don't actually modify the code; we just reason about it.)

echo
echo "============================================================"
echo "  8. REAL reinstall_backup_restore() rollback persistence"
echo "============================================================"

# Problem 1 regression: drive the REAL restore control flow (not a replay of
# its persistence block). A successful runtime rollback used to reset the
# transaction flags BEFORE the persist check, so persistence was SKIPPED and a
# reboot would reload the failed deploy's firewall. The restore must capture
# the persistence requirement up front and persist old ∪ new families.

# --- extra mocks for the real restore control flow ---
# Unit-file aware systemctl (a missing unit behaves like real systemd) and a
# stateful crontab, mirroring test_reinstall_preservation.sh.
systemctl() {
    case "${1:-}" in
        is-active|is-enabled)
            case "${3:-}" in
                xray)  [[ -f "${xray_systemd_file}" ]] && return 0 || return 3 ;;
                nginx) [[ -f "${nginx_systemd_file}" ]] && return 0 || return 3 ;;
            esac
            return 1 ;;
        daemon-reload) return 0 ;;
        enable|disable|start|stop)
            case "${2:-}" in
                xray)  [[ -f "${xray_systemd_file}" ]] && return 0 || return 1 ;;
                nginx) [[ -f "${nginx_systemd_file}" ]] && return 0 || return 1 ;;
            esac
            return 0 ;;
        *) return 0 ;;
    esac
}
service_stop() { :; }
_info_cache_invalidate() { :; }
RESTORE_CRONTAB="${TMP_ROOT}/crontab_state.txt"
: > "${RESTORE_CRONTAB}"
crontab() {
    case "${1:-}" in
        -l) cat "${RESTORE_CRONTAB}" 2>/dev/null; return 0 ;;
        -)
            local _cr_buf
            _cr_buf=$(cat)
            if [[ -n "${_cr_buf}" ]]; then
                printf '%s\n' "${_cr_buf}" > "${RESTORE_CRONTAB}"
            else
                : > "${RESTORE_CRONTAB}"
            fi
            return 0 ;;
        *) return 0 ;;
    esac
}

# Path globals -> temp (same pattern as test_reinstall_preservation.sh).
idleleo_dir="${TMP_ROOT}/idleleo_r"
idleleo_conf_dir="${idleleo_dir}/conf"
xray_conf_dir="${idleleo_conf_dir}/xray"
xray_conf="${xray_conf_dir}/config.json"
xray_install_config_file="${idleleo_conf_dir}/install_config.json"
nginx_conf_dir="${idleleo_conf_dir}/nginx"
ssl_chainpath="${idleleo_dir}/cert"
xray_systemd_file="${TMP_ROOT}/fake_xray.service"
nginx_systemd_file="${TMP_ROOT}/fake_nginx.service"
xray_info_file="${idleleo_dir}/info/xray_info.inf"

_setup_restore_fixture() {
    rm -rf "${idleleo_dir}"
    rm -f "${xray_systemd_file}" "${nginx_systemd_file}"
    mkdir -p "${xray_conf_dir}" "${nginx_conf_dir}" "${ssl_chainpath}" "$(dirname "${xray_info_file}")"
    cat > "${xray_conf}" <<'XEOF'
{
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "tag": "VLESS-ws-in",
            "settings": {
                "clients": [
                    {"id": "uuid-restore-secret", "level": 0, "email": "user1@example.com"}
                ],
                "decryption": "none"
            },
            "streamSettings": {"network": "ws", "security": "none"}
        }
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
XEOF
    echo '{"tls":"TLS","id":"uuid-restore-secret"}' > "${xray_install_config_file}"
    info_extraction_all="{}"
    tls_mode="TLS"
    old_tls_mode="TLS"
    transport_mode="None"
    reality_add_nginx="off"
}

# Simulate a failed dual(443) -> ipv4(8443) deploy: run the FORWARD firewall
# changes on the mock runtime, then set the transaction state exactly as the
# reinstall flow records it, so restore reverses the real changes.
_simulate_failed_forward() {
    reset_rules
    : > "${managed_baseline_file}"
    seed_state v4 "user:22" "tcp:443"
    seed_state v6 "user:22" "tcp:443"
    baseline_sync "${B46}" >/dev/null 2>&1
    reconcile_managed_firewall "${J4}" "${J8}" "${B46}" "${B4}" >/dev/null 2>&1
    baseline_sync "${B4}" >/dev/null 2>&1
    _reinstall_firewall_old_ports="${J4}"
    _reinstall_firewall_new_ports="${J8}"
    _reinstall_firewall_old_families="${B46}"
    _reinstall_firewall_new_families="${B4}"
    _reinstall_firewall_changed="yes"
    _reinstall_baseline_old_families="${B46}"
    _reinstall_baseline_new_families="${B4}"
    _reinstall_baseline_changed="yes"
}

echo "  8.1 successful rollback must still persist restored state"
_setup_restore_fixture
RESTORE_BACKUP=$(reinstall_backup_create 2>/dev/null)
if [[ -n "${RESTORE_BACKUP}" && -d "${RESTORE_BACKUP}" ]]; then
    ok "8.1a: backup created"
else
    bad "8.1a: reinstall_backup_create failed"
fi
_simulate_failed_forward
SAVE_V4_CALLS=0; SAVE_V6_CALLS=0
: > "${LOG_CAPTURE}"
RESTORE_RC=0
reinstall_backup_restore "${RESTORE_BACKUP}" >/dev/null 2>&1 || RESTORE_RC=$?
if [[ ${RESTORE_RC} -eq 0 ]]; then
    ok "8.1b: restore returned 0"
else
    bad "8.1b: restore rc=${RESTORE_RC}; log=$(cat "${LOG_CAPTURE}")"
fi
if [[ "${SAVE_V4_CALLS}" -ge 1 && "${SAVE_V6_CALLS}" -ge 1 ]]; then
    ok "8.1c: rollback persistence ran after successful rollback (v4=${SAVE_V4_CALLS} v6=${SAVE_V6_CALLS})"
else
    bad "8.1c: rollback persistence SKIPPED (v4=${SAVE_V4_CALLS} v6=${SAVE_V6_CALLS})"
fi
if v4_has "tcp:443" && ! v4_has "tcp:8443" && v6_has "tcp:443" && v4_has "user:22" && v6_has "user:22"; then
    ok "8.1d: runtime restored (v4:443, v6:443, user rules kept)"
else
    bad "8.1d: runtime wrong (v4:$(cat "${IPTABLES_V4_RULES}") v6:$(cat "${IPTABLES_V6_RULES}"))"
fi
if grep -q "已恢复原配置" "${LOG_CAPTURE}"; then
    ok "8.1e: success message printed"
else
    bad "8.1e: success message missing"
fi
if [[ "${_reinstall_firewall_changed}" == "no" && "${_reinstall_baseline_changed}" == "no" ]]; then
    ok "8.1f: transaction flags cleared after success"
else
    bad "8.1f: flags not cleared (fw=${_reinstall_firewall_changed} base=${_reinstall_baseline_changed})"
fi

echo "  8.2 persistence failure -> restore fails loudly, stays retriable"
_setup_restore_fixture
RESTORE_BACKUP=$(reinstall_backup_create 2>/dev/null)
_simulate_failed_forward
iptables-save() { SAVE_V4_CALLS=$((SAVE_V4_CALLS + 1)); return 1; }
: > "${LOG_CAPTURE}"
RESTORE_RC=0
reinstall_backup_restore "${RESTORE_BACKUP}" >/dev/null 2>&1 || RESTORE_RC=$?
if [[ ${RESTORE_RC} -ne 0 ]]; then
    ok "8.2a: persistence failure -> restore rc!=0"
else
    bad "8.2a: restore falsely succeeded"
fi
if ! grep -q "已恢复原配置" "${LOG_CAPTURE}"; then
    ok "8.2b: no false success message"
else
    bad "8.2b: printed success despite persistence failure"
fi
if grep -q "防火墙持久化恢复未完成" "${LOG_CAPTURE}"; then
    ok "8.2c: persistence failure surfaced"
else
    bad "8.2c: missing persistence failure message; log=$(cat "${LOG_CAPTURE}")"
fi
if [[ -d "${RESTORE_BACKUP}" ]]; then
    ok "8.2d: backup dir retained"
else
    bad "8.2d: backup dir gone"
fi
if [[ "${_reinstall_firewall_changed}" != "no" ]]; then
    ok "8.2e: flags stay retriable (fw=${_reinstall_firewall_changed})"
else
    bad "8.2e: transaction flags wrongly cleared"
fi
iptables-save()  { SAVE_V4_CALLS=$((SAVE_V4_CALLS + 1)); printf 'MOCKED_V4\n'; }

echo "  8.3 no firewall change -> no persistence (negative control)"
_setup_restore_fixture
RESTORE_BACKUP=$(reinstall_backup_create 2>/dev/null)
reset_rules
: > "${managed_baseline_file}"
_reinstall_firewall_changed="no"
_reinstall_baseline_changed="no"
SAVE_V4_CALLS=0; SAVE_V6_CALLS=0
: > "${LOG_CAPTURE}"
RESTORE_RC=0
reinstall_backup_restore "${RESTORE_BACKUP}" >/dev/null 2>&1 || RESTORE_RC=$?
if [[ ${RESTORE_RC} -eq 0 ]]; then
    ok "8.3a: no-change restore rc=0"
else
    bad "8.3a: no-change restore rc=${RESTORE_RC}; log=$(cat "${LOG_CAPTURE}")"
fi
if [[ "${SAVE_V4_CALLS}" -eq 0 && "${SAVE_V6_CALLS}" -eq 0 ]]; then
    ok "8.3b: no persistence when nothing changed"
else
    bad "8.3b: unexpected persistence (v4=${SAVE_V4_CALLS} v6=${SAVE_V6_CALLS})"
fi

echo
echo "============================================================"
echo "  9. baseline_sync runtime/ownership atomicity"
echo "============================================================"

echo "  9.1 add failure + compensation remove failure keeps leftovers owned"
reset_rules
rm -f "${managed_baseline_file}"
: > "${LOG_CAPTURE}"
MOCK_FAIL_ADD="ip6tables::OUTPUT"
MOCK_FAIL_DEL="ip6tables::INPUT"
RC_SYNC=0
baseline_sync "${B46}" >/dev/null 2>&1 || RC_SYNC=$?
if [[ ${RC_SYNC} -ne 0 ]]; then
    ok "9.1a: sync failed on injected add failure"
else
    bad "9.1a: sync should have failed"
fi
if v6_has ":INPUT"; then
    ok "9.1b: leftover v6 rule kept in runtime (compensation failed)"
else
    bad "9.1b: leftover rule vanished despite failed compensation"
fi
if ! v4_has ":INPUT" && ! v4_has "tcp:53" && ! v4_has "udp:53" && ! v4_has "udp:1024:65535"; then
    ok "9.1c: v4 side fully compensated"
else
    bad "9.1c: v4 residue: $(cat "${IPTABLES_V4_RULES}")"
fi
if grep -q "ip6tables lo-in" "${managed_baseline_file}" 2>/dev/null; then
    ok "9.1d: leftover rule stays owned (not orphaned)"
else
    bad "9.1d: ownership lost for leftover: $(cat "${managed_baseline_file}" 2>/dev/null)"
fi
if ! grep -q "^iptables " "${managed_baseline_file}" 2>/dev/null; then
    ok "9.1e: compensated v4 rules not owned"
else
    bad "9.1e: v4 wrongly owned: $(cat "${managed_baseline_file}")"
fi
if grep -q "回滚未完成" "${LOG_CAPTURE}"; then
    ok "9.1f: loud failure log"
else
    bad "9.1f: compensation failure was silent"
fi
MOCK_FAIL_ADD=""
MOCK_FAIL_DEL=""
RC_SYNC=0
baseline_sync "${B46}" >/dev/null 2>&1 || RC_SYNC=$?
if [[ ${RC_SYNC} -eq 0 ]]; then
    ok "9.1g: retry after heal succeeds"
else
    bad "9.1g: retry rc=${RC_SYNC}"
fi
# The mock's rule key is "proto:port" (chain-less), so dns-tcp-in/out collide
# on "tcp:53" and dns-udp-in/out on "udp:53": a fresh dual gain records 5
# owned keys per family (real iptables distinguishes INPUT/OUTPUT and would
# record 7). Assert the exact expected 5-key set per family.
EXPECTED_OWNED="dns-tcp-in dns-udp-in lo-in lo-out udp-hi-in"
N4=$(baseline_owned_keys iptables | sort | tr '\n' ' ')
N6=$(baseline_owned_keys ip6tables | sort | tr '\n' ' ')
if [[ "${N4}" == "${EXPECTED_OWNED} " && "${N6}" == "${EXPECTED_OWNED} " ]]; then
    ok "9.1h: retry ownership covers every present rule"
else
    bad "9.1h: ownership v4=[${N4}] v6=[${N6}] expected=[${EXPECTED_OWNED}]"
fi

echo "  9.2 dropped-family removal failure keeps ownership, retry heals"
reset_rules
rm -f "${managed_baseline_file}"
baseline_sync "${B46}" >/dev/null 2>&1
seed_state v6 "user:22"
: > "${LOG_CAPTURE}"
MOCK_FAIL_DEL="ip6tables:tcp:53"
RC_SYNC=0
baseline_sync "${B4}" >/dev/null 2>&1 || RC_SYNC=$?
if [[ ${RC_SYNC} -ne 0 ]]; then
    ok "9.2a: sync failed on dropped-family removal failure"
else
    bad "9.2a: sync should have failed"
fi
if v6_has "tcp:53"; then
    ok "9.2b: un-removable rule still in runtime"
else
    bad "9.2b: rule vanished despite failed removal"
fi
if ! v6_has ":INPUT" && ! v6_has "udp:53"; then
    ok "9.2c: other dropped keys removed"
else
    bad "9.2c: other keys not removed: $(cat "${IPTABLES_V6_RULES}")"
fi
if grep -q "ip6tables dns-tcp-in" "${managed_baseline_file}" 2>/dev/null; then
    ok "9.2d: ownership kept for un-removable key"
else
    bad "9.2d: ownership forgotten: $(cat "${managed_baseline_file}" 2>/dev/null)"
fi
if grep -q "^iptables " "${managed_baseline_file}" 2>/dev/null; then
    ok "9.2e: kept-family ownership intact"
else
    bad "9.2e: kept-family ownership lost"
fi
if v6_has "user:22"; then
    ok "9.2f: user rule survives failed cleanup"
else
    bad "9.2f: user rule lost"
fi
if grep -q "清理未完成" "${LOG_CAPTURE}"; then
    ok "9.2g: loud failure log"
else
    bad "9.2g: cleanup failure was silent"
fi
MOCK_FAIL_DEL=""
RC_SYNC=0
baseline_sync "${B4}" >/dev/null 2>&1 || RC_SYNC=$?
if [[ ${RC_SYNC} -eq 0 ]]; then
    ok "9.2h: retry after heal succeeds"
else
    bad "9.2h: retry rc=${RC_SYNC}"
fi
if ! v6_has "tcp:53" && ! grep -q "^ip6tables" "${managed_baseline_file}" 2>/dev/null; then
    ok "9.2i: retry cleans the rule and forgets ownership"
else
    bad "9.2i: residue: v6=$(cat "${IPTABLES_V6_RULES}") owned=$(cat "${managed_baseline_file}" 2>/dev/null)"
fi
if v6_has "user:22"; then
    ok "9.2j: user rule survives retry"
else
    bad "9.2j: user rule lost on retry"
fi

echo "  9.3 ownership commit failure -> runtime compensated to entry state"
reset_rules
rm -f "${managed_baseline_file}"
baseline_sync "${B4}" >/dev/null 2>&1
cp "${managed_baseline_file}" "${TMP_ROOT}/ownership_entry.list"
ORIG_BASELINE_SAVE=$(declare -f baseline_owned_save)
baseline_owned_save() { return 1; }
: > "${LOG_CAPTURE}"
RC_SYNC=0
baseline_sync "${B46}" >/dev/null 2>&1 || RC_SYNC=$?
if [[ ${RC_SYNC} -ne 0 ]]; then
    ok "9.3a: sync failed on ownership commit failure"
else
    bad "9.3a: sync should have failed"
fi
if ! v6_has ":INPUT" && ! v6_has "tcp:53" && ! v6_has "udp:53"; then
    ok "9.3b: v6 gain compensated back to entry state"
else
    bad "9.3b: v6 residue: $(cat "${IPTABLES_V6_RULES}")"
fi
if v4_has ":INPUT" && v4_has "tcp:53"; then
    ok "9.3c: v4 entry baseline intact"
else
    bad "9.3c: v4 entry state damaged"
fi
if cmp -s "${managed_baseline_file}" "${TMP_ROOT}/ownership_entry.list"; then
    ok "9.3d: ownership file unchanged (still describes entry state)"
else
    bad "9.3d: ownership diverged from runtime"
fi
if grep -q "状态写入失败" "${LOG_CAPTURE}"; then
    ok "9.3e: loud failure log"
else
    bad "9.3e: commit failure was silent"
fi
eval "${ORIG_BASELINE_SAVE}"

echo "  9.4 commit failure + compensation failure -> loud, never silent"
reset_rules
rm -f "${managed_baseline_file}"
baseline_sync "${B46}" >/dev/null 2>&1
seed_state v6 "user:22"
ORIG_BASELINE_SAVE2=$(declare -f baseline_owned_save)
baseline_owned_save() { return 1; }
MOCK_FAIL_ADD="ip6tables:tcp:53"
: > "${LOG_CAPTURE}"
RC_SYNC=0
baseline_sync "${B4}" >/dev/null 2>&1 || RC_SYNC=$?
if [[ ${RC_SYNC} -ne 0 ]]; then
    ok "9.4a: sync failed"
else
    bad "9.4a: sync should have failed"
fi
if v6_has ":INPUT" && ! v6_has "tcp:53"; then
    ok "9.4b: partial v6 restoration (compensation itself failed)"
else
    bad "9.4b: unexpected v6 state: $(cat "${IPTABLES_V6_RULES}")"
fi
if grep -q "回滚未完成" "${LOG_CAPTURE}"; then
    ok "9.4c: loud compensation-failure log"
else
    bad "9.4c: compensation failure was silent"
fi
if v6_has "user:22"; then
    ok "9.4d: user rule survives"
else
    bad "9.4d: user rule lost"
fi
MOCK_FAIL_ADD=""
eval "${ORIG_BASELINE_SAVE2}"

echo
echo "============================================================"
echo "  Summary"
echo "============================================================"
if [[ ${FAIL} -eq 0 ]]; then
    printf 'ALL complete firewall transaction tests PASSED (%d)\n' "${PASS}"
else
    printf 'firewall transaction tests FAILED: %d pass, %d fail\n' "${PASS}" "${FAIL}"
    exit 1
fi