#!/usr/bin/env bash
# Bootstrap dependency / error-propagation regression tests.
#
# Covers the confirmed P0 fixes without needing a real container:
#   13.2 multi-package pkg_install failure propagation
#   13.3 online/offline language init ordering (never installs before the
#        package-manager is known; offline never installs / never networks)
#   13.4 lazy config load (top-level source never calls jq; existing config is
#        never mis-cleared when jq is absent; load is idempotent)
#   13.10 candidate-guard failure-stage diagnostics (path/syntax/schema/
#        capability/menu-anchor/semantic-probe)
#
# Container-bound scenarios (13.1 fresh bootstrap, 13.6 offline-safety with
# curl/apt/yum dead, 13.8 fuser/lsof present/absent, 13.9 RPM family) are
# covered by the CI minimal-bootstrap matrix job, not here.
#
# Run: bash .github/test/test_bootstrap_dependencies.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

log_echo() { :; }
sleep() { :; }

# Override the real info_extraction to avoid touching the host install config
# during these tests. Save the real production function first so the 13.4
# public-entry test can restore it (T3 pattern: never unset -f a sourced fn).
_info_extraction_saved=$(declare -f info_extraction)
info_extraction() { printf '%s' "${info_extraction_all:-}"; }

echo "============================================================"
echo "  13.2: pkg_install multi-package failure propagation"
echo "============================================================"

gettext() { printf '%s' "$1"; }

pkg_install_judge() { printf ''; } # everything needs installing by default

INSTALL_CALLS=()
mock_ins_fail_b() {
    INSTALL_CALLS+=("$3")
    [[ "$3" == "pkgA" ]] && return 0
    return 1
}
INS="mock_ins_fail_b"

echo "--- partial failure: pkgA ok, pkgB fails ---"
INSTALL_CALLS=()
if pkg_install "pkgA,pkgB"; then
    bad "pkg_install should fail when pkgB install fails"
else
    ok "pkg_install returns non-zero on partial package failure"
fi
if [[ " ${INSTALL_CALLS[*]} " == *" pkgA "* && " ${INSTALL_CALLS[*]} " == *" pkgB "* ]]; then
    ok "both failing-needed packages were attempted (pkgA, pkgB)"
else
    bad "attempted installs not as expected: ${INSTALL_CALLS[*]}"
fi

echo "--- all-success installs ---"
INSTALL_CALLS=()
mock_ins_ok() { INSTALL_CALLS+=("$3"); return 0; }
INS="mock_ins_ok"
if pkg_install "jq,bc"; then
    ok "pkg_install returns 0 when all packages install"
else
    bad "pkg_install should succeed when all packages install"
fi
[[ ${#INSTALL_CALLS[@]} -eq 2 ]] && ok "both packages attempted" ||
    bad "expected 2 installs, got ${#INSTALL_CALLS[@]}"

echo "--- already-installed packages need no install ---"
INSTALL_CALLS=()
pkg_install_judge() { printf 'installed\n'; }
INS="mock_ins_ok"
if pkg_install "bc,curl"; then
    ok "pkg_install returns 0 when everything is already installed"
else
    bad "pkg_install should succeed when packages already installed"
fi
[[ ${#INSTALL_CALLS[@]} -eq 0 ]] && ok "no package-manager call made for installed deps" ||
    bad "expected zero installs, got ${#INSTALL_CALLS[@]}"

echo "============================================================"
echo "  13.3: language init does not install before INS is known"
echo "============================================================"

# init_package_manager must be pure (no package install, no network).
PKG_INSTALL_CALLS=0
pkg_install() { PKG_INSTALL_CALLS=$((PKG_INSTALL_CALLS + 1)); return 0; }
INIT_PM_PRE=$PKG_INSTALL_CALLS
init_package_manager
if [[ -n "${INS:-}" ]] && [[ ${PKG_INSTALL_CALLS} -eq ${INIT_PM_PRE} ]]; then
    ok "init_package_manager sets INS without installing packages"
else
    bad "init_package_manager is not pure (calls=${PKG_INSTALL_CALLS}, INS=${INS:-unset})"
fi

# offline mode with gettext absent must NOT call pkg_install (no -y, no network).
# T1: production abstracts detection into has_gettext_binary(); simulate "gettext
# absent" by mocking the helper. Prepending an empty dir to PATH would NOT be a
# valid fixture here because the runner's real gettext stays reachable via the
# rest of PATH, so `command -v gettext`/`type -P gettext` would still succeed.
# T3: save the original production function before mocking, then restore it
# after the mock block so the T1 test below (lines 135-152) still finds the
# real production helper. `unset -f` is NOT used because it would remove the
# production function entirely (the function was defined by sourced install.sh).
_has_gettext_binary_saved=$(declare -f has_gettext_binary)
has_gettext_binary() { return 1; } # gettext binary absent
PKG_INSTALL_CALLS=0
init_language offline >/dev/null 2>&1
RC=$?
if [[ ${PKG_INSTALL_CALLS} -eq 0 ]]; then
    ok "offline init_language with gettext absent performs zero package installs"
else
    bad "offline init_language called pkg_install (calls=${PKG_INSTALL_CALLS})"
fi

# online mode with gettext absent may install gettext, but only after INS is
# known (INS was set by init_package_manager above).
PKG_INSTALL_CALLS=0
init_language online >/dev/null 2>&1
if [[ ${PKG_INSTALL_CALLS} -eq 1 ]]; then
    ok "online init_language installs gettext only via the known package manager"
else
    bad "online init_language pkg_install calls=${PKG_INSTALL_CALLS} (expected 1)"
fi
# Restore the production has_gettext_binary function for subsequent tests.
eval "${_has_gettext_binary_saved}"
unset _has_gettext_binary_saved

# T1: has_gettext_binary must distinguish the in-script fallback FUNCTION from
# a real executable. A fallback function must never be reported as "installed".
GT_BIN="${TMP_ROOT}/gt-bin"
mkdir -p "${GT_BIN}"
gettext() { printf '%s' "$1"; } # in-script fallback function (as at top of install.sh)
if PATH="${GT_BIN}" has_gettext_binary; then
    bad "has_gettext_binary must not treat the fallback function as installed"
else
    ok "fallback gettext() function is not detected as a real binary"
fi
# A real executable on a controlled PATH IS detected (function + binary coexist).
printf '#!/bin/sh\nexit 0\n' > "${GT_BIN}/gettext"; chmod +x "${GT_BIN}/gettext"
if PATH="${GT_BIN}" has_gettext_binary; then
    ok "real gettext executable is detected by has_gettext_binary"
else
    bad "has_gettext_binary failed to detect a real gettext executable"
fi
rm -rf "${GT_BIN}"

echo "============================================================"
echo "  13.4: lazy config load (no top-level jq, never mis-clears)"
echo "============================================================"

CFG_DIR="${TMP_ROOT}/cfg"
mkdir -p "${CFG_DIR}"
VALID_CFG="${CFG_DIR}/install_config.json"
printf '{"port":12345,"network_mode":"dual"}\n' > "${VALID_CFG}"
BROKEN_CFG="${CFG_DIR}/broken.json"
printf 'not json\n' > "${BROKEN_CFG}"

# A config, jq present: lazy load parses it into info_extraction_all.
xray_install_config_file="${VALID_CFG}"
_info_extraction_loaded=0
info_extraction_all=""
read_config_status=""
# T2: use the production helper (type -P), never `command -v jq` (a shell
# function would fool command -v).
if has_jq_binary; then
    _lazy_load_info_extraction
    [[ -n "${info_extraction_all}" ]] && ok "lazy load populates info_extraction_all from config" ||
        bad "lazy load failed to read valid JSON config"
    # Idempotence: a second call must not re-read / clear.
    FIRST="${info_extraction_all}"
    _lazy_load_info_extraction
    [[ "${info_extraction_all}" == "${FIRST}" ]] && ok "lazy config load is idempotent (no re-read)" ||
        bad "lazy config load was not idempotent"
else
    ok "skipped jq-present parse check (jq not installed in this env)"
fi

# Malformed JSON with jq present: fail closed (read_config_status=0), file
# preserved, info_extraction_all NOT silently treated as an empty config.
if has_jq_binary; then
    xray_install_config_file="${BROKEN_CFG}"
    _info_extraction_loaded=0
    info_extraction_all="unset-marker"
    read_config_status=""
    if _lazy_load_info_extraction; then
        bad "lazy load should fail closed on malformed JSON"
    else
        ok "lazy load returns non-zero on malformed JSON (fail closed)"
    fi
    [[ "${read_config_status:-}" == "0" ]] && ok "malformed JSON sets read_config_status=0" ||
        bad "malformed JSON read_config_status='${read_config_status}' (expected 0)"
    [[ "${info_extraction_all}" == "" ]] && ok "malformed JSON leaves info_extraction_all empty" ||
        bad "malformed JSON response unexpected: '${info_extraction_all}'"
    [[ -f "${BROKEN_CFG}" ]] && ok "malformed config file is preserved (not deleted)" ||
        bad "malformed config file was deleted"
fi

# jq ABSENT + existing config: T2 requires this be simulated via the production
# helper (has_jq_binary), NOT a jq() shell function — a function is invisible to
# `type -P` and would leave the real binary reachable. Mock + restore exactly
# like the gettext fixture above (T3: never `unset -f` a sourced function).
_has_jq_binary_saved=$(declare -f has_jq_binary)
has_jq_binary() { return 1; } # jq executable absent
xray_install_config_file="${VALID_CFG}"
_info_extraction_loaded=0
info_extraction_all=""
read_config_status=""
if _lazy_load_info_extraction; then
    bad "jq-absent load should fail closed (dependency/config-read error)"
else
    ok "jq-absent + config present returns non-zero (fail closed)"
fi
[[ "${read_config_status:-}" == "0" ]] && ok "jq-absent path records read_config_status=0" ||
    bad "jq-absent path left read_config_status='${read_config_status}'"
[[ "${info_extraction_all}" == "" ]] && ok "jq-absent path does not fabricate config content" ||
    bad "jq-absent path leaked info_extraction_all='${info_extraction_all}'"
[[ -f "${VALID_CFG}" ]] && ok "existing config preserved when jq absent" ||
    bad "existing config was cleared when jq absent"
# Restore the production has_jq_binary function.
eval "${_has_jq_binary_saved}"
unset _has_jq_binary_saved

# Public entry (P0-1 fix): a malformed config read through the real
# info_extraction() must return failure, not be treated as an empty read.
if has_jq_binary; then
    xray_install_config_file="${BROKEN_CFG}"
    _info_extraction_loaded=0
    _info_cache_loaded=0
    info_extraction_all=""
    read_config_status=""
    eval "${_info_extraction_saved}" # restore the real production public entry
    if info_extraction "port"; then
        bad "info_extraction should fail on malformed config (public entry)"
    else
        ok "info_extraction returns non-zero on malformed config (public entry)"
    fi
    [[ "${read_config_status:-}" == "0" ]] && ok "malformed config sets read_config_status=0 via public entry" ||
        bad "malformed config left read_config_status='${read_config_status}' via public entry"
    info_extraction() { printf '%s' "${info_extraction_all:-}"; } # restore mock
fi

echo "============================================================"
echo "  13.5: P1-9 pkg_install call-site failure propagation"
echo "============================================================"

echo "============================================================"
echo "  13.6: Ubuntu 26.04 Nginx dependency compatibility"
echo "============================================================"

# Ubuntu 26.04 (Resolute) no longer publishes the legacy PCRE3 packages.
# The bundled Nginx is prebuilt, so its TLS path must not ask apt for any PCRE
# or zlib development package. Exercise the real dependency_install call path
# with a package-install recorder rather than relying on source-text matching.
_pkg_install_saved_13_6=$(declare -f pkg_install)
_judge_saved_13_6=$(declare -f judge)
_systemctl_saved_13_6=$(declare -f systemctl 2>/dev/null)
_root_crontab_path_saved_13_6=$(declare -f root_crontab_path)

DEPENDENCY_INSTALL_CALLS=()
pkg_install() {
    DEPENDENCY_INSTALL_CALLS+=("$1")
    return 0
}
judge() { return 0; }
systemctl() { return 0; }
root_crontab_path() { printf '%s\n' "${TMP_ROOT}/root-crontab"; }
ID="ubuntu"
VERSION_ID="26.04"
tls_mode="TLS"
if dependency_install; then
    ok "Ubuntu 26.04 TLS dependency installation completes"
else
    bad "Ubuntu 26.04 TLS dependency installation failed"
fi
if [[ " ${DEPENDENCY_INSTALL_CALLS[*]} " == *" iputils-ping "* ]]; then
    ok "Ubuntu 26.04 TLS path keeps the required ping dependency"
else
    bad "Ubuntu 26.04 TLS path did not request iputils-ping: ${DEPENDENCY_INSTALL_CALLS[*]}"
fi
if [[ " ${DEPENDENCY_INSTALL_CALLS[*]} " != *"libpcre3"* &&
      " ${DEPENDENCY_INSTALL_CALLS[*]} " != *"libpcre3-dev"* &&
      " ${DEPENDENCY_INSTALL_CALLS[*]} " != *"zlib1g-dev"* ]]; then
    ok "Ubuntu 26.04 TLS path has no obsolete PCRE3/zlib development dependency"
else
    bad "Ubuntu 26.04 TLS path requested obsolete dependency: ${DEPENDENCY_INSTALL_CALLS[*]}"
fi

# Restore sourced production functions before the remaining call-site tests.
eval "${_pkg_install_saved_13_6}"
eval "${_judge_saved_13_6}"
if [[ -n "${_systemctl_saved_13_6}" ]]; then
    eval "${_systemctl_saved_13_6}"
else
    unset -f systemctl 2>/dev/null
fi
eval "${_root_crontab_path_saved_13_6}"
unset _pkg_install_saved_13_6 _judge_saved_13_6 _systemctl_saved_13_6 _root_crontab_path_saved_13_6

# Verify that every REQUIRED pkg_install call site propagates failure.
# Each test mocks pkg_install to return 1 and checks that the wrapper
# function returns with a non-zero status and does not proceed.

# Save and mock pkg_install for required-call-site tests.
_pkg_install_saved_13_5=$(declare -f pkg_install)

echo "--- firewall_set requires iptables-services/persistent ---"
# Minimal mock: pkg_install fails, everything else stubs out.
pkg_install() { return 1; }
log_echo() { :; }
gettext() { printf '%s' "$1"; }
managed_fw_require_families() { return 0; }
baseline_sync() { return 0; }
baseline_owned_families() { echo ""; }
_managed_fw_bins() { echo ""; }
ensure_network_runtime_state() { :; }
reconcile_managed_firewall() { return 0; }
atomic_write_managed_ports() { return 0; }
if is_rpm_family; then
    # On RPM, iptables-services is expected to fail -> firewall_set returns 1.
    printf 'Y\n' | firewall_set >/dev/null 2>&1 && bad "firewall_set should fail on rpm pkg_install failure" ||
        ok "firewall_set fails when iptables-services install fails (rpm)"
else
    # On Debian, iptables-persistent is expected to fail -> firewall_set returns 1.
    printf 'Y\n' | firewall_set >/dev/null 2>&1 && bad "firewall_set should fail on deb pkg_install failure" ||
        ok "firewall_set fails when iptables-persistent install fails (debian)"
fi

echo "--- ssl_install requires socat ---"
pkg_install() { return 1; }
download_script_file() { return 0; }
judge() { :; }
idleleo_dir="${TMP_ROOT}/ssl"
mkdir -p "${idleleo_dir}/tmp"
ssl_install 2>/dev/null && bad "ssl_install should fail when socat install fails" ||
    ok "ssl_install fails when socat install fails"

echo "--- install_iftop degrades gracefully on optional pkg_install failure ---"
pkg_install() { return 1; }
check_system() { :; }
# Ensure iftop is not on PATH so the install path is exercised.
_install_iftop_path_saved="$PATH"
PATH="/tmp/nosuchdir"
install_iftop 2>/dev/null && bad "install_iftop should return 1 on pkg_install failure" ||
    ok "install_iftop returns 1 when iftop install fails (optional, warning logged)"
PATH="${_install_iftop_path_saved}"

# Restore the production pkg_install function.
eval "${_pkg_install_saved_13_5}"
unset _pkg_install_saved_13_5

echo "============================================================"
echo "  13.10: candidate-guard failure-stage diagnostics"
echo "============================================================"

GUARD_DIR="${TMP_ROOT}/guard"
mkdir -p "${GUARD_DIR}"

# path stage: nonexistent candidate
cand="${GUARD_DIR}/nonexistent.sh"
rm -f "${cand}"
rxa_candidate_guard "${cand}"
if rxa_candidate_guard "${cand}" >/dev/null 2>&1; then
    bad "guard should reject nonexistent candidate"
else
    [[ "${RILL_CANDIDATE_GUARD_STAGE}" == "path" ]] && ok "stage=path for missing candidate" ||
        bad "expected stage=path, got '${RILL_CANDIDATE_GUARD_STAGE}'"
fi

# syntax stage: invalid bash
cand="${GUARD_DIR}/syntax.sh"
printf '#!/usr/bin/env bash\nif [[\n' > "${cand}"
if rxa_candidate_guard "${cand}" >/dev/null 2>&1; then
    bad "guard should reject syntax-invalid candidate"
else
    [[ "${RILL_CANDIDATE_GUARD_STAGE}" == "syntax" ]] && ok "stage=syntax" ||
        bad "expected stage=syntax, got '${RILL_CANDIDATE_GUARD_STAGE}'"
fi

# schema stage: valid syntax, missing schema marker
cand="${GUARD_DIR}/schema.sh"
printf '#!/usr/bin/env bash\necho ok\n' > "${cand}"
if rxa_candidate_guard "${cand}" >/dev/null 2>&1; then
    bad "guard should reject candidate missing schema marker"
else
    [[ "${RILL_CANDIDATE_GUARD_STAGE}" == "schema" ]] && ok "stage=schema" ||
        bad "expected stage=schema, got '${RILL_CANDIDATE_GUARD_STAGE}'"
fi

# capability stage: all required capabilities present except timeline
cand="${GUARD_DIR}/capability.sh"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'RILL_XRAY_AGENT_INTEGRATION_SCHEMA=999' \
  'case x in' \
  '  --rill-agent-status) rxa_dispatch status ;;' \
  '  --rill-agent-verify) rxa_dispatch verify ;;' \
  '  --rill-agent-safe-disable) rxa_dispatch mode safe-disabled ;;' \
  '  --rill-agent-uninstall) rxa_dispatch uninstall ;;' \
  '  --rill-agent-diagnose) rxa_dispatch diagnose ;;' \
  'esac' > "${cand}"
if rxa_candidate_guard "${cand}" >/dev/null 2>&1; then
    bad "guard should reject candidate missing a required capability"
else
    [[ "${RILL_CANDIDATE_GUARD_STAGE}" == "capability" ]] && ok "stage=capability" ||
        bad "expected stage=capability, got '${RILL_CANDIDATE_GUARD_STAGE}'"
fi

# menu-anchor stage: passes capabilities but missing '9) rxa_menu'
cand="${GUARD_DIR}/menu.sh"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'RILL_XRAY_AGENT_INTEGRATION_SCHEMA=999' \
  'case x in' \
  '  --rill-agent-status) rxa_dispatch status ;;' \
  '  --rill-agent-verify) rxa_dispatch verify ;;' \
  '  --rill-agent-safe-disable) rxa_dispatch mode safe-disabled ;;' \
  '  --rill-agent-uninstall) rxa_dispatch uninstall ;;' \
  '  --rill-agent-diagnose) rxa_dispatch diagnose ;;' \
  '  --rill-agent-timeline) rxa_dispatch timeline ;;' \
  'esac' > "${cand}"
if rxa_candidate_guard "${cand}" >/dev/null 2>&1; then
    bad "guard should reject candidate missing menu anchor"
else
    [[ "${RILL_CANDIDATE_GUARD_STAGE}" == "menu-anchor" ]] && ok "stage=menu-anchor" ||
        bad "expected stage=menu-anchor, got '${RILL_CANDIDATE_GUARD_STAGE}'"
fi

# semantic-probe stage: passes all static checks but has no integration block
cand="${GUARD_DIR}/semantic.sh"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'RILL_XRAY_AGENT_INTEGRATION_SCHEMA=999' \
  'case x in' \
  '  --rill-agent-status) rxa_dispatch status ;;' \
  '  --rill-agent-verify) rxa_dispatch verify ;;' \
  '  --rill-agent-safe-disable) rxa_dispatch mode safe-disabled ;;' \
  '  --rill-agent-uninstall) rxa_dispatch uninstall ;;' \
  '  --rill-agent-diagnose) rxa_dispatch diagnose ;;' \
  '  --rill-agent-timeline) rxa_dispatch timeline ;;' \
  '  9) rxa_menu ;;' \
  'esac' > "${cand}"
if rxa_candidate_guard "${cand}" >/dev/null 2>&1; then
    bad "guard should reject candidate lacking the integration block"
else
    [[ "${RILL_CANDIDATE_GUARD_STAGE}" == "semantic-probe" ]] && ok "stage=semantic-probe (no block)" ||
        bad "expected stage=semantic-probe, got '${RILL_CANDIDATE_GUARD_STAGE}'"
fi

echo "============================================================"
echo "  13.9: RPM-family manager selection (never a hard-coded alias)"
echo "============================================================"

# rpm_package_manager must prefer a present dnf and fall back to yum; never a
# hard-coded alias (CentOS Stream 10+ has no yum binary).
FAM_BIN="${TMP_ROOT}/fam-bin"
mkdir -p "${FAM_BIN}"
SAVED_PATH="$PATH"

# dnf present -> dnf selected
printf '#!/bin/bash\nexit 0\n' > "${FAM_BIN}/dnf"; chmod +x "${FAM_BIN}/dnf"
if PATH="${FAM_BIN}:${SAVED_PATH}" rpm_package_manager | grep -qx 'dnf'; then
    ok "rpm_package_manager prefers dnf when present"
else
    bad "dnf present but not preferred: '$(PATH="${FAM_BIN}:${SAVED_PATH}" rpm_package_manager)'"
fi

# dnf absent, yum present -> yum selected
rm -f "${FAM_BIN}/dnf"
printf '#!/bin/bash\nexit 0\n' > "${FAM_BIN}/yum"; chmod +x "${FAM_BIN}/yum"
if PATH="${FAM_BIN}:${SAVED_PATH}" rpm_package_manager | grep -qx 'yum'; then
    ok "rpm_package_manager falls back to yum when dnf absent"
else
    bad "yum not selected when dnf absent"
fi

# Restore dnf for the selection/judge subtests below.
rm -f "${FAM_BIN}/yum"
printf '#!/bin/bash\nexit 0\n' > "${FAM_BIN}/dnf"; chmod +x "${FAM_BIN}/dnf"

# init_package_manager on an RPM-family ID selects dnf when present.
ID="centos"
if PATH="${FAM_BIN}:${SAVED_PATH}" bash -c '
    export _TEST_MODE=1
    FPATH="'"${FAM_BIN}"':'"${SAVED_PATH}"'"
    source "'"${REPO_DIR}"'/install.sh" >/dev/null 2>&1 || true
    export PATH="${FPATH}"
    ID=centos
    init_package_manager
    [ "${INS:-}" = "dnf" ]
'; then
    ok "init_package_manager selects dnf on an RPM family when dnf is on PATH"
else
    bad "init_package_manager did not select dnf on RPM family with dnf present"
fi
unset ID

# pkg_install_judge on an RPM family must query the selected manager, not dpkg.
if PATH="${FAM_BIN}:${SAVED_PATH}" bash -c '
    export _TEST_MODE=1
    source "'"${REPO_DIR}"'/install.sh" >/dev/null 2>&1 || true
    export PATH="'"${FAM_BIN}"':'"${SAVED_PATH}"'"
    ID=centos
    # The fake dnf records that it was invoked for a query.
    # NOTE: "$1"/"$2" live in a heredoc, so they need a backslash to survive one
    # extra expansion level. "${INS}" below is direct -c code (single-quoted by
    # the caller), so it must NOT be backslash-escaped here.
    cat > "'"${FAM_BIN}"'/dnf" <<EOF
#!/bin/bash
[ "\$1" = "list" ] && [ "\$2" = "installed" ] && echo "__rpm_probe__ 0.0-1 installed"
exit 0
EOF
    chmod +x "'"${FAM_BIN}"'/dnf"
    init_package_manager
    [ "${INS}" = "dnf" ] || exit 9
    pkg_install_judge "__rpm_probe__" | grep -q "__rpm_probe__"
'; then
    ok "RPM-family pkg_install_judge queries the selected INS (dnf), not dpkg"
else
    bad "RPM-family pkg_install_judge did not use the selected INS"
fi
export PATH="${SAVED_PATH}"

echo "============================================================"
echo "  Summary"
echo "============================================================"
echo "  PASS=${PASS} FAIL=${FAIL}"
[[ ${FAIL} -eq 0 ]]
