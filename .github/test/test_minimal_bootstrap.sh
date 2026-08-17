#!/usr/bin/env bash
# Minimal-bootstrap container test.
#
# Runs INSIDE a fresh minimal Docker container (Debian 12/13 slim, Ubuntu
# 24.04 minimal, CentOS Stream 10) that starts with almost no tooling, to prove
# the confirmed Bootstrap dependency closure genuinely works:
#   13.1 fresh bootstrap: python3/jq/bc/gettext may be absent, yet the
#        check_file_integrity prereq (bc,jq) is satisfiable via the real
#        package manager and the candidate guard then passes using real jq --
#        no python3-forced fake jq.
#   13.2 multi-package pkg_install failure propagation (real manager + mock).
#   13.8 apt-lock detection needs no fuser/lsof (uses the /proc scan).
#   13.9 RPM-family package query/install routes through the present manager
#        (dnf preferred on CentOS Stream 10+, yum fallback), never a hard-coded
#        alias, and never Debian dpkg on an RPM family.
#
# Invoked by the minimal-bootstrap CI job which mounts the repo read-only at
# $REPO_DIR and runs THIS file inside each container as root.
#
# Run (inside container): bash <repo-dir>/.github/test/test_minimal_bootstrap.sh

set -uo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
export _TEST_MODE=1
# shellcheck source=/dev/null
# shellcheck disable=SC1090
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
PASSED_REQS=0
PASSED_OFFLINE=0

ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { :; }
gettext() { printf '%s' "$1"; }

echo "============================================================"
echo "  13.1: fresh bootstrap dependency closure + metadata"
echo "============================================================"

# Load family metadata exactly the way install.sh computes it.
# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || { bad "cannot read /etc/os-release"; }
echo "  detected ID=${ID:-unknown} VERSION_ID=${VERSION_ID:-unknown}"

# Record the interesting presence matrix so CI proves this was a real minimal
# environment (no fabricated "all absent" claim).
PRESENCE=""
for tool in fuser lsof curl bc jq python3 gettext; do
    if command -v "${tool}" >/dev/null 2>&1; then
        PRESENCE="${PRESENCE}${tool}=present "
    else
        PRESENCE="${PRESENCE}${tool}=absent "
    fi
done
echo "  bootstrap-surroundings: ${PRESENCE}"

echo "--- init_package_manager is pure and selects a real manager ---"
PKG_CALLS=0
pkg_install() { PKG_CALLS=$((PKG_CALLS + 1)); return 0; }
PRE_PKG=${PKG_CALLS}
init_package_manager
if [[ -z "${INS:-}" ]]; then
    bad "init_package_manager did not set INS"
    exit 1
fi
if ! command -v "${INS}" >/dev/null 2>&1; then
    bad "INS=${INS} is not a present command"
    exit 1
fi
if [[ ${PKG_CALLS} -eq ${PRE_PKG} ]]; then
    ok "init_package_manager set INS=${INS} with zero package installs"
else
    bad "init_package_manager called pkg_install"
fi
if is_rpm_family; then
    [[ "${INS}" == "dnf" || "${INS}" == "yum" ]] && ok "rpm family INS=${INS} (dnf/yum)" ||
        bad "rpm family INS=${INS} (expected dnf or yum)"
else
    [[ "${INS}" == "apt" ]] && ok "non-rpm family INS=apt" ||
        bad "non-rpm family INS=${INS} (expected apt)"
fi
unset -f pkg_install

echo "--- pkg_install_judge routes to the correct family, not dpkg on RPM ---"
# The judge itself must use the family manager, so a mock manager is installed
# in PATH to prove it is invoked (and dpkg is NOT for an RPM family).
MOCK_BIN="$(mktemp -d)"
cat > "${MOCK_BIN}/pkg-call-log" <<EOF
EOF
if is_rpm_family; then
    # Create the selected INS as a recorder that reports one line whose leading
    # package name matches the judge's grep filter.
    cat > "${MOCK_BIN}/${INS}" <<PMEOF
#!/bin/bash
if [ "\${1}" = "list" ] && [ "\${2}" = "installed" ]; then
    echo "__rpm_probe_pkg__ 0.0-1 installed"
    exit 0
fi
exit 0
PMEOF
    chmod +x "${MOCK_BIN}/${INS}"
    # Guard: ensure this family manager is chosen, never dpkg.
    OUT=$(PATH="${MOCK_BIN}:${PATH}" pkg_install_judge "__rpm_probe_pkg__" 2>/dev/null)
    if [[ "${OUT}" == *"__rpm_probe_pkg__"* ]]; then
        ok "RPM-family pkg_install_judge used INS=${INS} (not dpkg)"
    else
        bad "RPM-family pkg_install_judge output='${OUT}' (expected the selected manager)"
    fi
else
    cat > "${MOCK_BIN}/dpkg" <<PMEOF
#!/bin/bash
if [ "\${1}" = "--get-selections" ]; then
    echo "__deb_probe_pkg__ install"
    exit 0
fi
exit 0
PMEOF
    chmod +x "${MOCK_BIN}/dpkg"
    OUT=$(PATH="${MOCK_BIN}:${PATH}" pkg_install_judge "__deb_probe_pkg__" 2>/dev/null)
    if [[ "${OUT}" == *"__deb_probe_pkg__"* ]]; then
        ok "Debian-family pkg_install_judge used dpkg (not the RPM manager)"
    else
        bad "Debian-family pkg_install_judge output='${OUT}' (expected dpkg)"
    fi
fi
rm -rf "${MOCK_BIN}"

echo "--- real prereq install: bc + jq (check_file_integrity dependency) ---"
# Refresh the package index for a genuinely fresh minimal image, then let
# install.sh's own pkg_install prove the multi-package closure on the real
# manager. On RPM family metadata refresh is `makecache` (fast); on Debian it
# is `apt-get update`, mirroring check_system on a fresh install.
if is_rpm_family; then
    "${INS}" makecache >/dev/null 2>&1 || "${INS}" -y install bc jq >/dev/null 2>&1 || true
else
    "${INS}" update >/dev/null 2>&1 || true
fi
if pkg_install "bc,jq"; then
    if command -v jq >/dev/null 2>&1 && command -v bc >/dev/null 2>&1; then
        ok "pkg_install 'bc,jq' succeeded and both are now present"
        PASSED_REQS=$((PASSED_REQS + 1))
    else
        bad "pkg_install reported success but bc/jq not on PATH"
    fi
else
    bad "pkg_install 'bc,jq' failed on ${ID} (dependency closure broken)"
fi

echo "--- candidate guard passes using real jq (fresh bootstrap, no fake python jq) ---"
# The guard is semantic: it bash -n's and runs the integration probe using the
# real jq installed above. It must pass when run against the repository's own
# install.sh (its own integration block is the reference implementation).
if ! command -v jq >/dev/null 2>&1; then
    skip_guard=1
else
    skip_guard=0
fi
if [[ ${skip_guard} -eq 1 ]]; then
    bad "candidate guard skipped: jq unavailable -- dependency closure not proven"
else
    if rxa_candidate_guard "${REPO_DIR}/install.sh"; then
        [[ -n "${RILL_CANDIDATE_GUARD_VERSION:-}" ]] &&
            ok "candidate guard PASSED (version=${RILL_CANDIDATE_GUARD_VERSION}, stage empty)"
        PASSED_REQS=$((PASSED_REQS + 1))
    else
        bad "candidate guard REJECTED own install.sh (stage=${RILL_CANDIDATE_GUARD_STAGE:-?} rc=${RILL_CANDIDATE_GUARD_RC:-?})"
    fi
fi

echo "============================================================"
echo "  13.2: multi-package failure propagation (real manager path)"
echo "============================================================"
# Mock only the manager binary to fail on one package; pkg_install itself is
# the real install.sh function, proving rc is not masked and no overall [OK].
MOCK_BIN="$(mktemp -d)"
FAIL_PKG_NAME="__xray_probe_fail_pkg__"
cat > "${MOCK_BIN}/${INS}" <<PMEOF
#!/bin/bash
if [ "\$3" = "${FAIL_PKG_NAME}" ]; then exit 1; fi
exit 0
PMEOF
chmod +x "${MOCK_BIN}/${INS}"
pkg_install_judge() { printf ''; } # treat everything as needing install
if PATH="${MOCK_BIN}:${PATH}" pkg_install "pkgA,${FAIL_PKG_NAME}"; then
    bad "pkg_install returned 0 although ${FAIL_PKG_NAME} install failed"
else
    ok "pkg_install returned non-zero when ${FAIL_PKG_NAME} install failed"
fi
rm -rf "${MOCK_BIN}"

echo "============================================================"
echo "  13.8: apt/dpkg lock detection without fuser/lsof"
echo "============================================================"
# The /proc fd scan replaces the fuser/lsof dependency. Verify the helper
# exists and behaves: a nonexistent path is never "held"; with no lock files
# present, wait_for_apt_lock returns immediately even if fuser/lsof are absent.
lock_dir="$(mktemp -d)"
if declare -F _proc_fd_path_held >/dev/null 2>&1; then
    ok "_proc_fd_path_held is defined"
    _proc_fd_path_held "${lock_dir}/nonexistent.lock" && \
        bad "nonexistent lock reported as held" || \
        ok "nonexistent path is not held"
    if wait_for_apt_lock 2; then
        ok "wait_for_apt_lock returns 0 with no lock files (fuser/lsof not needed)"
    else
        bad "wait_for_apt_lock failed with no lock files"
    fi
else
    bad "_proc_fd_path_held is not defined (apt-lock dependency fix missing)"
fi
rm -rf "${lock_dir}"

echo "============================================================"
echo "  13.6: offline-safe command classification (no network)"
echo "============================================================"
for flag in --help --uninstall --purge --show --service-start --service-stop \
            --service-restart --access-log --error-log --backup; do
    is_offline_safe_command "${flag}" && PASSED_OFFLINE=$((PASSED_OFFLINE + 1)) ||
        bad "is_offline_safe_command '${flag}' should be offline-safe"
done
[[ ${PASSED_OFFLINE:-0} -eq 10 ]] && ok "all 10 offline-safe flags recognized without network"

echo "============================================================"
echo "  Summary"
echo "============================================================"
echo "  PASS=${PASS} FAIL=${FAIL} prerequisite-closure=${PASSED_REQS}"
[[ ${FAIL} -eq 0 ]]