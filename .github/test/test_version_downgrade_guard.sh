#!/usr/bin/env bash
#
# Stage 04 follow-up: a version that differs is not automatically a version that
# is newer.
#
# The update path used to compare versions with `test a != b`, so a reverted API
# release, a stale CDN copy or a hand-edited metadata file would reinstall an
# older Xray over a working one. This suite covers:
#
#   A. numeric dotted comparison (26.10.4 < 26.10.31, 26.10 == 26.10.0)
#   B. garbage is "not comparable", never "older" and never "newer"
#   C. xray_update refuses to move backwards and touches nothing
#   D. xray_update still updates when the target really is newer
#   E. the guard runs before any install/backup call in xray_update
#
# No root, no real Xray, no network: the service-control surface is stubbed.
#
# Usage: bash .github/test/test_version_downgrade_guard.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
suite() { printf '\n-- %s --\n' "$1"; }
check_eq() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

[[ -f "${INSTALL_SH}" ]] || {
    echo "FATAL: ${INSTALL_SH} not found"
    exit 1
}

LOG_OUT="${TMP_ROOT}/out.log"
: >"${LOG_OUT}"

gettext() { printf '%s' "$1"; }
judge() { return 0; }
countdown() { return 0; }
systemctl() { return 0; }
Error=""; RedBG=""; OK=""; GreenBG=""; Font=""
Warning=""; YellowBG=""; Green=""; Red=""; Info=""

export _TEST_MODE=1
# shellcheck source=/dev/null
source "${INSTALL_SH}" >/dev/null 2>&1 || true
unset _TEST_MODE

echo "============================================================"
echo "  Stage 04: version ordering / downgrade guard"
echo "============================================================"

# Stubs: this suite is about the decision, not about systemd or packaging.
# log_echo is redefined after sourcing because install.sh brings its own.
log_echo() { printf '%s\n' "$*" >>"${LOG_OUT}"; }
BACKUP_CALLS="${TMP_ROOT}/backup-calls"
: >"${BACKUP_CALLS}"
backup_xray_binary() { printf 'called\n' >>"${BACKUP_CALLS}"; return 0; }
systemctl() { return 0; }
xray_install_pinned_and_check() { return 0; }
xray_privilege_escalation() { return 0; }
set_xray_config_path() { return 0; }
health_check_xray_update() { return 0; }
xray_diagnose() { return 0; }
update_json_config() { return 0; }
rxa_reconfigure_enter() { return 0; }
rxa_reconfigure_leave() { return 0; }
info_extraction() {
    case "$1" in
        xray_version) printf '%s\n' "${TEST_CURRENT_XRAY:-}" ;;
        *) printf '\n' ;;
    esac
}

# ---------------------------------------------------------------------------
suite "A. numeric dotted comparison"
check_eq "26.10.31 is newer than 26.9.30" "$(version_compare 26.10.31 26.9.30)" "1"
check_eq "26.9.30 is older than 26.10.31" "$(version_compare 26.9.30 26.10.31)" "-1"
check_eq "26.10.31 equals itself" "$(version_compare 26.10.31 26.10.31)" "0"
check_eq "26.10.4 is older than 26.10.31 (string compare disagrees)" "$(version_compare 26.10.4 26.10.31)" "-1"
check_eq "26.10 equals 26.10.0" "$(version_compare 26.10 26.10.0)" "0"
check_eq "a leading v is ignored" "$(version_compare v26.10.31 26.10.31)" "0"
check_eq "leading zeros are decimal, not octal" "$(version_compare 026.010.031 26.10.31)" "0"
check_eq "four-component builds compare numerically" "$(version_compare 2026.10.15.7679 2026.10.15.7000)" "1"
check_eq "an empty side is not comparable" "$(version_compare "" 26.10.31)" ""
check_eq "a word is not comparable" "$(version_compare latest 26.10.31)" ""
check_eq "a trailing dot is not comparable" "$(version_compare 26.10. 26.10)" ""

version_compare latest 26.10.31 >/dev/null 2>&1
check_eq "not-comparable reports exit code 2" "$?" "2"
version_compare 26.10.31 latest >/dev/null 2>&1
check_eq "not-comparable reports exit code 2 (reversed)" "$?" "2"

# ---------------------------------------------------------------------------
suite "B. incomparable input is never older and never newer"
if version_gt "latest" "26.10.31"; then bad "a word counted as newer"; else ok "a word is not newer"; fi
if version_gt "26.10.31" "latest"; then bad "a real version counted as newer than garbage"; else ok "a version is not newer than garbage"; fi
if version_lt "latest" "26.10.31"; then bad "a word counted as older"; else ok "a word is not older"; fi
if version_lt "" "26.10.31"; then bad "an empty version counted as older"; else ok "an empty version is not older"; fi
if version_gt "26.10.31" "26.9.30"; then ok "a newer version is newer"; else bad "version_gt missed a real upgrade"; fi
if version_gt "26.9.30" "26.10.31"; then bad "version_gt accepted a real downgrade"; else ok "an older version is not newer"; fi

# ---------------------------------------------------------------------------
suite "C. xray_update refuses to move backwards"
: >"${BACKUP_CALLS}"
: >"${LOG_OUT}"
TEST_CURRENT_XRAY="26.10.31"
xray_online_version="26.9.30"
auto_update="YES"
xray_update
rc=$?
check_eq "the refused update returns success" "${rc}" "0"
if [[ -s "${BACKUP_CALLS}" ]]; then bad "a refused downgrade still backed up (and stopped the service)"; else ok "nothing was backed up or replaced"; fi
if grep -Fq "不执行降级" "${LOG_OUT}"; then ok "the refusal is reported to the user"; else bad "the refusal is silent"; fi
if grep -Fq "26.10.31" "${LOG_OUT}" && grep -Fq "26.9.30" "${LOG_OUT}"; then
    ok "the refusal names both versions"
else
    bad "the refusal does not say which versions are involved"
fi

# ---------------------------------------------------------------------------
suite "D. a genuinely newer target still updates"
: >"${BACKUP_CALLS}"
: >"${LOG_OUT}"
TEST_CURRENT_XRAY="26.10.4"
xray_online_version="26.10.31"
auto_update="YES"
xray_update
rc=$?
check_eq "the upgrade path returns success" "${rc}" "0"
if [[ -s "${BACKUP_CALLS}" ]]; then ok "the binary is backed up before installing"; else bad "the upgrade path never backed up"; fi
if grep -Fq "不执行降级" "${LOG_OUT}"; then bad "a real upgrade was refused as a downgrade"; else ok "a real upgrade is not refused"; fi

# ---------------------------------------------------------------------------
suite "E. the guard runs before any install or backup call"
body=$(sed -n '/^xray_update() {/,/^}/p' "${INSTALL_SH}")
guard_line=$(printf '%s\n' "${body}" | grep -n 'version_gt "${current_xray_version}" "${xray_online_version}"' | head -1 | cut -d: -f1)
install_line=$(printf '%s\n' "${body}" | grep -n 'xray_install_pinned_and_check' | head -1 | cut -d: -f1)
backup_line=$(printf '%s\n' "${body}" | grep -n 'backup_xray_binary' | head -1 | cut -d: -f1)
if [[ -n "${guard_line}" && -n "${install_line}" && "${guard_line}" -lt "${install_line}" ]]; then
    ok "the guard precedes the first install call"
else
    bad "the guard is missing or ordered after the install call (guard=${guard_line:-none}, install=${install_line:-none})"
fi
if [[ -n "${guard_line}" && -n "${backup_line}" && "${guard_line}" -lt "${backup_line}" ]]; then
    ok "the guard precedes the first backup call"
else
    bad "the guard is missing or ordered after the backup (guard=${guard_line:-none}, backup=${backup_line:-none})"
fi
# The `!=` gate that follows decides "update" vs "reinstall the same version".
# It is only safe because the guard above already removed the backwards case.
gate_line=$(printf '%s\n' "${body}" | grep -n 'current_xray_version} != ${xray_online_version}' | head -1 | cut -d: -f1)
if [[ -n "${gate_line}" && -n "${guard_line}" && "${guard_line}" -lt "${gate_line}" ]]; then
    ok "the guard runs before the update/reinstall gate"
else
    bad "the guard is missing or ordered after the update gate (guard=${guard_line:-none}, gate=${gate_line:-none})"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
