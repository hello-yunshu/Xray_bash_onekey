#!/bin/bash
#
# Regression tests for Xray config/log ownership vs. the actual systemd unit
# account.
#
# Xray-install changed its generated unit from User=nobody to User=xray
# (upstream b132ace). install.sh hardcoded config.json to nobody:600, so a
# service running as xray failed with status=23
# "failed to read config: /usr/local/etc/xray/config.json: permission denied".
#
# These tests assert that permission decisions follow the unit's User= value,
# including drop-in overrides, and that upgrades re-apply config ownership.
#
# Usage: bash .github/test/test_xray_service_user_permissions.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"

PASS=0
FAIL=0
SKIP=0

ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP+1)); echo "  SKIP: $1"; }

if [[ ! -f "${INSTALL_SH}" ]]; then
    echo "FATAL: install.sh not found at ${INSTALL_SH}"
    exit 1
fi

log_echo() { :; }
gettext()  { printf '%s' "$1"; }

Error=""; RedBG=""; OK=""; GreenBG=""; Font=""; Warning=""; YellowBG=""

_TEST_MODE=1
export _TEST_MODE
# shellcheck disable=SC1090
source "${INSTALL_SH}" >/dev/null 2>&1 || true
unset _TEST_MODE

for fn in xray_service_user xray_service_group harden_config_permissions xray_privilege_escalation; do
    if ! declare -F "${fn}" >/dev/null 2>&1; then
        echo "FATAL: ${fn}() not defined after sourcing install.sh"
        exit 1
    fi
done

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

UNIT_DIR="${TMP_DIR}/systemd"
UNIT_FILE="${UNIT_DIR}/xray.service"
mkdir -p "${UNIT_DIR}/xray.service.d"
xray_systemd_file="${UNIT_FILE}"
nginx_dir="${TMP_DIR}/no-nginx"
xray_conf="${TMP_DIR}/etc/xray/config.json"
mkdir -p "$(dirname "${xray_conf}")"
: > "${xray_conf}"

APPLY_LOG="${TMP_DIR}/apply.log"
FS_LOG="${TMP_DIR}/fs.log"
: > "${APPLY_LOG}"
: > "${FS_LOG}"

# Capture ownership decisions instead of touching real files.
apply_sensitive_file_permissions() {
    printf '%s|%s|%s\n' "$1" "$2" "${3:-600}" >> "${APPLY_LOG}"
    return 0
}
mkdir() { printf 'mkdir %s\n' "$*" >> "${FS_LOG}"; }
chown() { printf 'chown %s\n' "$*" >> "${FS_LOG}"; }
chmod() { :; }
find()  { :; }
# Directory access is exercised with real users by test_xray_runtime_permissions.sh.
xray_config_directory_permissions() { :; }

write_unit() {
    printf '[Service]\n%s\n' "$1" > "${UNIT_FILE}"
    : > "${UNIT_DIR}/xray.service.d/override.conf"
}
write_dropin() {
    printf '[Service]\n%s\n' "$1" > "${UNIT_DIR}/xray.service.d/override.conf"
}

echo "============================================================"
echo "  Xray systemd account ownership regression tests"
echo "============================================================"

# ---- 1. Unit parsing -------------------------------------------------
write_unit "User=nobody"
got=$(xray_service_user)
[[ "${got}" == "nobody" ]] && ok "base unit User=nobody resolved" \
    || bad "base unit User=nobody resolved (got '${got}')"

write_unit "User=nobody"
write_dropin "User=xray"
got=$(xray_service_user)
[[ "${got}" == "xray" ]] && ok "drop-in User=xray overrides base unit" \
    || bad "drop-in User=xray overrides base unit (got '${got}')"

write_unit "NoNewPrivileges=yes"
got=$(xray_service_user)
if id nobody >/dev/null 2>&1; then
    expected="nobody"
else
    expected="root"
fi
[[ "${got}" == "${expected}" ]] && ok "missing User= falls back to ${expected}" \
    || bad "missing User= falls back to ${expected} (got '${got}')"

got=$(xray_service_group "definitely-no-such-user-xyz")
[[ "${got}" == "definitely-no-such-user-xyz" ]] && ok "unknown account group falls back to its name" \
    || bad "unknown account group falls back to its name (got '${got}')"

# ---- 2. harden_config_permissions follows the unit account -----------
write_unit "User=nobody"
write_dropin "User=xray"
: > "${APPLY_LOG}"
harden_config_permissions >/dev/null 2>&1
if grep -qx "${xray_conf}|xray:xray|600" "${APPLY_LOG}"; then
    ok "harden_config_permissions owns config.json by unit user xray"
else
    bad "harden_config_permissions owns config.json by unit user xray; got: $(tr '\n' ';' < "${APPLY_LOG}")"
fi

# ---- 3. escalation re-applies ownership after installer switch -------
write_unit "User=nobody"
write_dropin "User=xray"
: > "${APPLY_LOG}"
: > "${FS_LOG}"
xray_privilege_escalation >/dev/null 2>&1
if grep -qx "${xray_conf}|xray:xray|600" "${APPLY_LOG}"; then
    ok "xray_privilege_escalation re-owns config.json for User=xray"
else
    bad "xray_privilege_escalation re-owns config.json for User=xray; got: $(tr '\n' ';' < "${APPLY_LOG}")"
fi
if grep -q "chown -fR xray:xray /var/log/xray/" "${FS_LOG}"; then
    ok "xray_privilege_escalation owns /var/log/xray by xray"
else
    bad "xray_privilege_escalation owns /var/log/xray by xray; got: $(tr '\n' ';' < "${FS_LOG}")"
fi

# ---- 4. root unit stays root, no log ownership churn -----------------
write_unit "User=root"
: > "${APPLY_LOG}"
: > "${FS_LOG}"
xray_privilege_escalation >/dev/null 2>&1
if grep -qx "${xray_conf}|root:root|600" "${APPLY_LOG}"; then
    ok "root unit keeps config.json owned by root"
else
    bad "root unit keeps config.json owned by root; got: $(tr '\n' ';' < "${APPLY_LOG}")"
fi
if grep -q "chown -fR root:root /var/log/xray/" "${FS_LOG}"; then
    ok "root unit repairs log ownership even with restricted capabilities"
else
    bad "root unit did not repair log ownership"
fi

echo "============================================================"
echo "  PASS: ${PASS}  FAIL: ${FAIL}  SKIP: ${SKIP}"
echo "============================================================"
[[ "${FAIL}" -eq 0 ]]
