#!/bin/bash
#
# P1-B: Strict tar safety check tests for nginx_tar_safe_check().
#
# Verifies that the production function refuses:
#   - absolute paths
#   - parent traversal (..)
#   - entries outside nginx/ top-level
#   - symlinks pointing outside nginx/
#   - symlinks with absolute targets
#   - hardlinks pointing outside nginx/
#   - device files, FIFOs, sockets
#   - control characters in file names
#
# And verifies that a legitimate archive passes and extracts correctly.
#
# Usage: bash .github/test/test_nginx_tar_security.sh
# Exits 0 if all tests pass, 1 otherwise.

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

# ----------------------------------------------------------------
# Source install.sh with minimal mocking to expose nginx_tar_safe_check()
# ----------------------------------------------------------------
# We need: log_echo, gettext, color vars (Error, RedBG, OK, GreenBG, Font).
# Provide a no-op log_echo and a passthrough gettext so the function can run.
log_echo() { :; }
gettext()  { printf '%s' "$1"; }

# Color placeholders (unused by the function logic, only by log_echo output).
Error=""
RedBG=""
OK=""
GreenBG=""
Font=""

# Source the main script in a subshell-safe way: we only need function
# definitions, not execution. install.sh checks _TEST_MODE at the end and
# returns early when _TEST_MODE=1, so we set it before sourcing.
_TEST_MODE=1
export _TEST_MODE
# shellcheck disable=SC1090
source "${INSTALL_SH}" >/dev/null 2>&1 || true
unset _TEST_MODE

# Confirm the function was loaded.
if ! declare -F nginx_tar_safe_check >/dev/null 2>&1; then
    echo "FATAL: nginx_tar_safe_check() not defined after sourcing install.sh"
    exit 1
fi

echo "============================================================"
echo "  P1-B: nginx_tar_safe_check() security tests"
echo "============================================================"
echo ""

# Helper: create a safe archive with sbin/nginx ELF binary.
make_safe_archive() {
    local output="$1"
    local staging="$2"
    rm -rf "${staging}"
    mkdir -p "${staging}/nginx/sbin"
    # Create a minimal ELF binary stub (7f 45 4c 46 = 0x7f 'E' 'L' 'F').
    printf '\x7f\x45\x4c\x46' > "${staging}/nginx/sbin/nginx"
    chmod +x "${staging}/nginx/sbin/nginx"
    mkdir -p "${staging}/nginx/conf"
    echo "worker_processes 1;" > "${staging}/nginx/conf/nginx.conf"
    mkdir -p "${staging}/nginx/logs"
    tar -czf "${output}" -C "${staging}" nginx/ 2>/dev/null
}

# Test runner: runs a test in a subshell to keep variables local.
# Usage: run_test "test name" "setup_function" "expected_pass_or_reject"
#   expected_pass_or_reject: "pass" = safe_check should return 0
#                            "reject" = safe_check should return non-zero
run_test() {
    local name="$1"
    local setup_fn="$2"
    local expected="$3"

    local tmp
    tmp=$(mktemp -d)
    local archive="${tmp}/test.tar.gz"
    local staging="${tmp}/staging"
    local extract_dir="${tmp}/extract"
    mkdir -p "${extract_dir}"

    # Run setup function which should populate ${archive} and ${staging}.
    "${setup_fn}" "${archive}" "${staging}"

    local result=0
    nginx_tar_safe_check "${archive}" "${extract_dir}" >/dev/null 2>&1 || result=$?

    case "${expected}" in
        pass)
            if [[ ${result} -eq 0 ]]; then
                ok "${name}: accepted (expected pass)"
            else
                bad "${name}: rejected (expected pass) exit=${result}"
            fi
            ;;
        reject)
            if [[ ${result} -ne 0 ]]; then
                ok "${name}: rejected (expected reject)"
            else
                bad "${name}: accepted (expected reject)"
            fi
            ;;
    esac
    rm -rf "${tmp}"
}

# ----------------------------------------------------------------
echo "--- Section 1: safe archive passes ---"
# ----------------------------------------------------------------

setup_safe() {
    make_safe_archive "$1" "$2"
}
run_test "safe archive with sbin/nginx ELF binary" setup_safe pass

# Verify extraction correctness separately.
{
    _tmp=$(mktemp -d)
    _archive="${_tmp}/safe.tar.gz"
    _staging="${_tmp}/staging"
    _extract="${_tmp}/extract"
    mkdir -p "${_extract}"
    make_safe_archive "${_archive}" "${_staging}"
    if nginx_tar_safe_check "${_archive}" "${_extract}" >/dev/null 2>&1; then
        if [[ -f "${_extract}/nginx/sbin/nginx" && -f "${_extract}/nginx/conf/nginx.conf" ]]; then
            ok "safe archive extracted files correctly"
        else
            bad "safe archive did not extract expected files"
        fi
    else
        bad "safe archive was rejected, cannot verify extraction"
    fi
    rm -rf "${_tmp}"
}

# ----------------------------------------------------------------
echo "--- Section 2: absolute path is rejected ---"
# ----------------------------------------------------------------

# Use Python to craft an archive with an absolute path entry (tarfile
# allows setting arbitrary member names, including absolute paths).
setup_abs_path() {
    local archive="$1"
    local staging="$2"
    rm -rf "${staging}"
    mkdir -p "${staging}/nginx/sbin"
    printf '\x7f\x45\x4c\x46' > "${staging}/nginx/sbin/nginx"
    chmod +x "${staging}/nginx/sbin/nginx"
    python3 - "${archive}" "${staging}" <<'PYEOF'
import sys, tarfile, io, os
archive_path = sys.argv[1]
staging = sys.argv[2]
with tarfile.open(archive_path, "w:gz") as tf:
    # Add the safe nginx/ tree.
    for root, dirs, files in os.walk(staging + "/nginx"):
        for d in dirs:
            full = root + "/" + d
            arc = full[len(staging)+1:]
            tf.add(full, arc)
        for f in files:
            full = root + "/" + f
            arc = full[len(staging)+1:]
            tf.add(full, arc)
    # Add a malicious entry with an absolute path.
    info = tarfile.TarInfo(name="/evil_abs.txt")
    data = b"evil\n"
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))
PYEOF
}
run_test "archive with absolute path entry" setup_abs_path reject

# ----------------------------------------------------------------
echo "--- Section 3: parent traversal (..) is rejected ---"
# ----------------------------------------------------------------

setup_traversal() {
    local archive="$1"
    local staging="$2"
    rm -rf "${staging}"
    mkdir -p "${staging}/nginx/sbin"
    printf '\x7f\x45\x4c\x46' > "${staging}/nginx/sbin/nginx"
    chmod +x "${staging}/nginx/sbin/nginx"
    python3 - "${archive}" "${staging}" <<'PYEOF'
import sys, tarfile, io, os
archive_path = sys.argv[1]
staging = sys.argv[2]
with tarfile.open(archive_path, "w:gz") as tf:
    # Add the safe nginx/ tree.
    for root, dirs, files in os.walk(staging + "/nginx"):
        for d in dirs:
            full = os.path.join(root, d)
            arc = full[len(staging)+1:]
            tf.add(full, arc)
        for f in files:
            full = os.path.join(root, f)
            arc = full[len(staging)+1:]
            tf.add(full, arc)
    # Add a malicious entry with ../ traversal.
    info = tarfile.TarInfo(name="nginx/../evil_traversal.txt")
    data = b"evil\n"
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))
PYEOF
}
run_test "archive with ../ traversal entry" setup_traversal reject

# ----------------------------------------------------------------
echo "--- Section 4: non-nginx/ top-level entry is rejected ---"
# ----------------------------------------------------------------

setup_non_nginx_top() {
    local archive="$1"
    local staging="$2"
    rm -rf "${staging}"
    mkdir -p "${staging}/nginx/sbin"
    printf '\x7f\x45\x4c\x46' > "${staging}/nginx/sbin/nginx"
    chmod +x "${staging}/nginx/sbin/nginx"
    mkdir -p "${staging}/etc"
    echo "evil" > "${staging}/etc/passwd"
    tar -czf "${archive}" -C "${staging}" nginx/ etc/ 2>/dev/null
}
run_test "archive with non-nginx/ top-level entry" setup_non_nginx_top reject

# ----------------------------------------------------------------
echo "--- Section 5: symlink pointing outside nginx/ is rejected ---"
# ----------------------------------------------------------------

setup_symlink_out() {
    local archive="$1"
    local staging="$2"
    rm -rf "${staging}"
    mkdir -p "${staging}/nginx/sbin"
    printf '\x7f\x45\x4c\x46' > "${staging}/nginx/sbin/nginx"
    chmod +x "${staging}/nginx/sbin/nginx"
    ln -sf ../../../etc/passwd "${staging}/nginx/evil_link"
    tar -czf "${archive}" -C "${staging}" nginx/ 2>/dev/null
}
run_test "archive with symlink pointing outside nginx/" setup_symlink_out reject

# ----------------------------------------------------------------
echo "--- Section 6: symlink with absolute target is rejected ---"
# ----------------------------------------------------------------

setup_symlink_abs() {
    local archive="$1"
    local staging="$2"
    rm -rf "${staging}"
    mkdir -p "${staging}/nginx/sbin"
    printf '\x7f\x45\x4c\x46' > "${staging}/nginx/sbin/nginx"
    chmod +x "${staging}/nginx/sbin/nginx"
    ln -sf /etc/passwd "${staging}/nginx/abs_link"
    tar -czf "${archive}" -C "${staging}" nginx/ 2>/dev/null
}
run_test "archive with symlink absolute target" setup_symlink_abs reject

# ----------------------------------------------------------------
echo "--- Section 7: symlink pointing inside nginx/ is accepted ---"
# ----------------------------------------------------------------

setup_symlink_in() {
    local archive="$1"
    local staging="$2"
    rm -rf "${staging}"
    mkdir -p "${staging}/nginx/sbin"
    printf '\x7f\x45\x4c\x46' > "${staging}/nginx/sbin/nginx"
    chmod +x "${staging}/nginx/sbin/nginx"
    mkdir -p "${staging}/nginx/conf"
    echo "worker_processes 1;" > "${staging}/nginx/conf/nginx.conf"
    ln -sf ../conf/nginx.conf "${staging}/nginx/sbin/nginx.conf.link"
    tar -czf "${archive}" -C "${staging}" nginx/ 2>/dev/null
}
run_test "archive with safe internal symlink" setup_symlink_in pass

# ----------------------------------------------------------------
echo "--- Section 8: FIFO is rejected ---"
# ----------------------------------------------------------------

setup_fifo() {
    local archive="$1"
    local staging="$2"
    rm -rf "${staging}"
    mkdir -p "${staging}/nginx/sbin"
    printf '\x7f\x45\x4c\x46' > "${staging}/nginx/sbin/nginx"
    chmod +x "${staging}/nginx/sbin/nginx"
    mkfifo "${staging}/nginx/evil_fifo" 2>/dev/null || true
    if [[ ! -p "${staging}/nginx/evil_fifo" ]]; then
        # Cannot create FIFO — skip by making archive safe.
        make_safe_archive "${archive}" "${staging}"
        return
    fi
    tar -czf "${archive}" -C "${staging}" nginx/ 2>/dev/null
}

# Need to handle the skip case where FIFO creation fails.
{
    _tmp=$(mktemp -d)
    _archive="${_tmp}/fifo.tar.gz"
    _staging="${_tmp}/staging"
    rm -rf "${_staging}"
    mkdir -p "${_staging}/nginx/sbin"
    printf '\x7f\x45\x4c\x46' > "${_staging}/nginx/sbin/nginx"
    chmod +x "${_staging}/nginx/sbin/nginx"
    if mkfifo "${_staging}/nginx/evil_fifo" 2>/dev/null && [[ -p "${_staging}/nginx/evil_fifo" ]]; then
        tar -czf "${_archive}" -C "${_staging}" nginx/ 2>/dev/null
        _extract="${_tmp}/extract"
        mkdir -p "${_extract}"
        _result=0
        nginx_tar_safe_check "${_archive}" "${_extract}" >/dev/null 2>&1 || _result=$?
        if [[ ${_result} -ne 0 ]]; then
            ok "archive with FIFO rejected"
        else
            bad "archive with FIFO was accepted"
        fi
    else
        skip "could not create FIFO for test"
    fi
    rm -rf "${_tmp}"
}

# ----------------------------------------------------------------
echo "--- Section 9: device file is rejected (requires root) ---"
# ----------------------------------------------------------------

if [[ "$(id -u)" -ne 0 ]]; then
    skip "device file test requires root (cannot mknod without CAP_MKNOD)"
else
    {
        _tmp=$(mktemp -d)
        _archive="${_tmp}/device.tar.gz"
        _staging="${_tmp}/staging"
        rm -rf "${_staging}"
        mkdir -p "${_staging}/nginx/sbin"
        printf '\x7f\x45\x4c\x46' > "${_staging}/nginx/sbin/nginx"
        chmod +x "${_staging}/nginx/sbin/nginx"
        if mknod "${_staging}/nginx/evil_dev" c 1 3 2>/dev/null && [[ -e "${_staging}/nginx/evil_dev" ]]; then
            tar -czf "${_archive}" -C "${_staging}" nginx/ 2>/dev/null
            _extract="${_tmp}/extract"
            mkdir -p "${_extract}"
            _result=0
            nginx_tar_safe_check "${_archive}" "${_extract}" >/dev/null 2>&1 || _result=$?
            if [[ ${_result} -ne 0 ]]; then
                ok "archive with device file rejected"
            else
                bad "archive with device file was accepted"
            fi
        else
            skip "could not create device file for test"
        fi
        rm -rf "${_tmp}"
    }
fi

# ----------------------------------------------------------------
echo "--- Section 10: control character in file name is rejected ---"
# ----------------------------------------------------------------

{
    _tmp=$(mktemp -d)
    _archive="${_tmp}/ctrl.tar.gz"
    _staging="${_tmp}/staging"
    rm -rf "${_staging}"
    mkdir -p "${_staging}/nginx/sbin"
    printf '\x7f\x45\x4c\x46' > "${_staging}/nginx/sbin/nginx"
    chmod +x "${_staging}/nginx/sbin/nginx"
    if touch "${_staging}/nginx/evil$(printf '\t')name" 2>/dev/null; then
        tar -czf "${_archive}" -C "${_staging}" nginx/ 2>/dev/null
        _extract="${_tmp}/extract"
        mkdir -p "${_extract}"
        _result=0
        nginx_tar_safe_check "${_archive}" "${_extract}" >/dev/null 2>&1 || _result=$?
        if [[ ${_result} -ne 0 ]]; then
            ok "archive with control character in file name rejected"
        else
            bad "archive with control character in file name was accepted"
        fi
    else
        skip "filesystem rejected creation of file with control character"
    fi
    rm -rf "${_tmp}"
}

# ----------------------------------------------------------------
echo "--- Section 11: empty / unreadable archive is rejected ---"
# ----------------------------------------------------------------

{
    _tmp=$(mktemp -d)
    _archive="${_tmp}/empty.tar.gz"
    : > "${_archive}"
    _extract="${_tmp}/extract"
    mkdir -p "${_extract}"
    _result=0
    nginx_tar_safe_check "${_archive}" "${_extract}" >/dev/null 2>&1 || _result=$?
    if [[ ${_result} -ne 0 ]]; then
        ok "empty / invalid archive rejected"
    else
        bad "empty / invalid archive was accepted"
    fi
    rm -rf "${_tmp}"
}

# ----------------------------------------------------------------
echo "--- Section 12: archive without sbin/nginx passes safe_check ---"
# ----------------------------------------------------------------

# nginx_tar_safe_check validates tar safety only (paths, types, symlinks).
# The sbin/nginx structure check is the caller's responsibility (nginx_install).
# A safe archive without sbin/nginx should still pass the safe_check itself.
setup_no_sbin() {
    local archive="$1"
    local staging="$2"
    rm -rf "${staging}"
    mkdir -p "${staging}/nginx/conf"
    echo "worker_processes 1;" > "${staging}/nginx/conf/nginx.conf"
    tar -czf "${archive}" -C "${staging}" nginx/ 2>/dev/null
}
run_test "archive without sbin/nginx passes safe_check (structure check is caller's job)" setup_no_sbin pass

# ----------------------------------------------------------------
echo "--- Section 13: non-existent archive is rejected ---"
# ----------------------------------------------------------------

{
    _extract=$(mktemp -d)
    _result=0
    nginx_tar_safe_check "/nonexistent/archive.tar.gz" "${_extract}" >/dev/null 2>&1 || _result=$?
    if [[ ${_result} -ne 0 ]]; then
        ok "non-existent archive rejected"
    else
        bad "non-existent archive was accepted"
    fi
    rm -rf "${_extract}"
}

# ----------------------------------------------------------------
echo "--- Section 14: missing target_dir is rejected ---"
# ----------------------------------------------------------------

{
    _tmp=$(mktemp -d)
    _archive="${_tmp}/safe.tar.gz"
    _staging="${_tmp}/staging"
    make_safe_archive "${_archive}" "${_staging}"
    _result=0
    nginx_tar_safe_check "${_archive}" "" >/dev/null 2>&1 || _result=$?
    if [[ ${_result} -ne 0 ]]; then
        ok "missing target_dir rejected"
    else
        bad "missing target_dir was accepted"
    fi
    rm -rf "${_tmp}"
}

# ----------------------------------------------------------------
echo "--- Section 15: --no-same-owner is applied ---"
# ----------------------------------------------------------------

{
    _tmp=$(mktemp -d)
    _archive="${_tmp}/safe.tar.gz"
    _staging="${_tmp}/staging"
    make_safe_archive "${_archive}" "${_staging}"
    _extract="${_tmp}/extract"
    mkdir -p "${_extract}"
    if nginx_tar_safe_check "${_archive}" "${_extract}" >/dev/null 2>&1; then
        _current_uid=$(id -u)
        _extracted_uid=$(stat -c '%u' "${_extract}/nginx/sbin/nginx" 2>/dev/null || stat -f '%u' "${_extract}/nginx/sbin/nginx" 2>/dev/null)
        if [[ "${_extracted_uid}" == "${_current_uid}" ]]; then
            ok "extracted file owner is current user (--no-same-owner applied)"
        else
            bad "extracted file owner is ${_extracted_uid}, expected ${_current_uid}"
        fi
    else
        bad "safe archive was rejected, cannot verify owner"
    fi
    rm -rf "${_tmp}"
}

# ----------------------------------------------------------------
echo "--- Section 16: hardlink with target outside nginx/ ---"
# ----------------------------------------------------------------

{
    _tmp=$(mktemp -d)
    _archive="${_tmp}/hardlink.tar.gz"
    _staging="${_tmp}/staging"
    rm -rf "${_staging}"
    mkdir -p "${_staging}/nginx/sbin"
    printf '\x7f\x45\x4c\x46' > "${_staging}/nginx/sbin/nginx"
    chmod +x "${_staging}/nginx/sbin/nginx"
    # Create a file outside nginx/ and a hardlink inside nginx/ pointing to it.
    echo "target" > "${_staging}/target_outside"
    if ln "${_staging}/target_outside" "${_staging}/nginx/hardlink_inside" 2>/dev/null; then
        # Archive both: nginx/ and target_outside. The hardlink stored in tar
        # will reference "target_outside" which is outside nginx/.
        tar -czf "${_archive}" -C "${_staging}" target_outside nginx/ 2>/dev/null
        _extract="${_tmp}/extract"
        mkdir -p "${_extract}"
        _result=0
        nginx_tar_safe_check "${_archive}" "${_extract}" >/dev/null 2>&1 || _result=$?
        # Determine expected behavior by inspecting tar listing.
        _listing=$(tar -tvf "${_archive}" 2>/dev/null)
        if printf '%s\n' "${_listing}" | grep -Eq 'nginx/hardlink_inside.*link to .*target_outside|nginx/hardlink_inside -> .*target_outside'; then
            # Hardlink target is outside nginx/ — must be rejected.
            if [[ ${_result} -ne 0 ]]; then
                ok "hardlink pointing outside nginx/ rejected"
            else
                bad "hardlink pointing outside nginx/ was accepted"
            fi
        elif printf '%s\n' "${_listing}" | grep -Eq 'target_outside'; then
            # The non-nginx entry itself should trigger rejection.
            if [[ ${_result} -ne 0 ]]; then
                ok "archive with non-nginx/ top-level entry rejected (hardlink test path)"
            else
                bad "archive with non-nginx/ top-level entry accepted (hardlink test path)"
            fi
        else
            # Hardlink was stored as a regular file — safe, but we expected a link.
            skip "hardlink was stored as regular file (filesystem-dependent)"
        fi
    else
        skip "could not create hardlink for test"
    fi
    rm -rf "${_tmp}"
}

# ----------------------------------------------------------------
echo ""
echo "============================================================"
echo "  P1-B test summary"
echo "============================================================"
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""

if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
exit 0
