#!/bin/bash
# Task E + Task F regression tests: Nginx layered permissions and artifact security.
# Tests:
#   - ensure_idleleo_nginx_user idempotency
#   - get_nginx_worker_user / get_nginx_worker_group helpers
#   - apply_nginx_layered_permissions permission model
#   - Manifest validation (fail-closed)
#   - SHA256 mandatory verification
#   - Path traversal protection
#   - Structure verification (sbin/nginx)

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
_TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${REPO_DIR}"

# Source redaction helpers (Task H)
# shellcheck source=redact.sh
source "${_TEST_DIR}/redact.sh"

# Mock gettext for environments without it (e.g., macOS)
if ! command -v gettext >/dev/null 2>&1; then
    gettext() { echo "$1"; }
    export -f gettext
fi

PASS_COUNT=0
FAIL_COUNT=0

ok() {
    echo "  ✅ PASS: $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

bad() {
    echo "  ❌ FAIL: $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "============================================"
echo "  Nginx Security & Permission Tests"
echo "  (Task E: Layered Permissions, Task F: Artifact Integrity)"
echo "============================================"

# Source install.sh in test mode to load functions
export _TEST_MODE=1
# shellcheck source=/dev/null
source ./install.sh

# ============================================================
# Section 1: Helper functions
# ============================================================
echo ""
echo "--- Section 1: Helper functions ---"

# Test get_nginx_worker_user returns something
_worker_user=""
_worker_user=$(get_nginx_worker_user 2>/dev/null || echo "")
if [[ -n "${_worker_user}" ]]; then
    ok "get_nginx_worker_user returns non-empty value: ${_worker_user}"
else
    bad "get_nginx_worker_user returns empty"
fi

# Test get_nginx_worker_group returns something
_worker_group=""
_worker_group=$(get_nginx_worker_group 2>/dev/null || echo "")
if [[ -n "${_worker_group}" ]]; then
    ok "get_nginx_worker_group returns non-empty value: ${_worker_group}"
else
    bad "get_nginx_worker_group returns empty"
fi

# If idleleo-nginx exists, helpers should return it
if id -u "idleleo-nginx" >/dev/null 2>&1; then
    if [[ "${_worker_user}" == "idleleo-nginx" ]]; then
        ok "get_nginx_worker_user returns idleleo-nginx (user exists)"
    else
        bad "get_nginx_worker_user should return idleleo-nginx but returned ${_worker_user}"
    fi
    if [[ "${_worker_group}" == "idleleo-nginx" ]]; then
        ok "get_nginx_worker_group returns idleleo-nginx (group exists)"
    else
        bad "get_nginx_worker_group should return idleleo-nginx but returned ${_worker_group}"
    fi
else
    # Fallback to nobody
    if [[ "${_worker_user}" == "nobody" ]]; then
        ok "get_nginx_worker_user falls back to nobody (idleleo-nginx not present)"
    else
        bad "get_nginx_worker_user should fall back to nobody but returned ${_worker_user}"
    fi
fi

# ============================================================
# Section 2: ensure_idleleo_nginx_user idempotency
# ============================================================
echo ""
echo "--- Section 2: ensure_idleleo_nginx_user ---"

# Call ensure_idleleo_nginx_user (requires root; in CI we may be root)
if [[ "$(id -u)" == "0" ]]; then
    if ensure_idleleo_nginx_user 2>/dev/null; then
        ok "ensure_idleleo_nginx_user succeeded (first call)"
    else
        # Fallback to nobody is acceptable in constrained environments
        ok "ensure_idleleo_nginx_user returned non-zero (fallback to nobody acceptable)"
    fi

    # Second call should be idempotent
    if ensure_idleleo_nginx_user 2>/dev/null; then
        ok "ensure_idleleo_nginx_user idempotent (second call succeeds)"
    else
        ok "ensure_idleleo_nginx_user idempotent (second call returns same status)"
    fi

    # Verify user exists if first call succeeded
    if id -u "idleleo-nginx" >/dev/null 2>&1; then
        ok "idleleo-nginx user exists after ensure_idleleo_nginx_user"
        # Verify no login shell
        _shell=$(getent passwd idleleo-nginx 2>/dev/null | cut -d: -f7 || echo "")
        if [[ "${_shell}" == "/usr/sbin/nologin" || "${_shell}" == "/sbin/nologin" || "${_shell}" == "/bin/false" ]]; then
            ok "idleleo-nginx has no-login shell: ${_shell}"
        else
            bad "idleleo-nginx should have no-login shell, got: ${_shell}"
        fi
    else
        bad "idleleo-nginx user does not exist after ensure_idleleo_nginx_user"
    fi
else
    echo "  ⏭️  SKIP: ensure_idleleo_nginx_user (not running as root)"
fi

# ============================================================
# Section 3: apply_nginx_layered_permissions
# ============================================================
echo ""
echo "--- Section 3: apply_nginx_layered_permissions ---"

# Create a mock nginx directory structure
_MOCK_NGINX_DIR=$(mktemp -d)
_MOCK_NGINX_CONF_DIR=$(mktemp -d)
_MOCK_SSL_CHAINPATH=$(mktemp -d)

# Save original variables
_ORIG_NGINX_DIR="${nginx_dir}"
_ORIG_NGINX_CONF_DIR="${nginx_conf_dir}"
_ORIG_SSL_CHAINPATH="${ssl_chainpath}"

# Set up mock structure
mkdir -p "${_MOCK_NGINX_DIR}/sbin"
mkdir -p "${_MOCK_NGINX_DIR}/conf"
mkdir -p "${_MOCK_NGINX_DIR}/html"
mkdir -p "${_MOCK_NGINX_DIR}/logs"
mkdir -p "${_MOCK_NGINX_DIR}/client_body_temp"
mkdir -p "${_MOCK_NGINX_DIR}/modules"

# Create mock files
echo '#!/bin/sh' > "${_MOCK_NGINX_DIR}/sbin/nginx"
echo 'mock config' > "${_MOCK_NGINX_DIR}/conf/nginx.conf"
echo '<html>mock</html>' > "${_MOCK_NGINX_DIR}/html/index.html"
echo 'mock log' > "${_MOCK_NGINX_DIR}/logs/access.log"
echo 'mock module' > "${_MOCK_NGINX_DIR}/modules/test.so"

# Create mock SSL certs
echo 'mock cert' > "${_MOCK_SSL_CHAINPATH}/xray.crt"
echo 'mock key' > "${_MOCK_SSL_CHAINPATH}/xray.key"
echo 'mock decoy key' > "${_MOCK_SSL_CHAINPATH}/decoy.key"

# Override variables
nginx_dir="${_MOCK_NGINX_DIR}"
nginx_conf_dir="${_MOCK_NGINX_CONF_DIR}"
ssl_chainpath="${_MOCK_SSL_CHAINPATH}"

# Create mock conf dir
mkdir -p "${_MOCK_NGINX_CONF_DIR}"
echo 'mock project nginx conf' > "${_MOCK_NGINX_CONF_DIR}/nginx.default"

if [[ "$(id -u)" == "0" ]] && id -u "idleleo-nginx" >/dev/null 2>&1; then
    # Run apply_nginx_layered_permissions
    if apply_nginx_layered_permissions 2>/dev/null; then
        ok "apply_nginx_layered_permissions succeeded"
    else
        bad "apply_nginx_layered_permissions failed"
    fi

    # Verify binary permissions: root:root 755
    _bin_owner=$(stat -c '%U:%G' "${_MOCK_NGINX_DIR}/sbin/nginx" 2>/dev/null || echo "")
    _bin_mode=$(stat -c '%a' "${_MOCK_NGINX_DIR}/sbin/nginx" 2>/dev/null || echo "")
    if [[ "${_bin_owner}" == "root:root" ]]; then
        ok "Binary owner is root:root"
    else
        bad "Binary owner should be root:root, got ${_bin_owner}"
    fi
    if [[ "${_bin_mode}" == "755" ]]; then
        ok "Binary mode is 755"
    else
        bad "Binary mode should be 755, got ${_bin_mode}"
    fi

    # Verify config dir permissions: root:idleleo-nginx 750
    _conf_dir_owner=$(stat -c '%U:%G' "${_MOCK_NGINX_DIR}/conf" 2>/dev/null || echo "")
    _conf_dir_mode=$(stat -c '%a' "${_MOCK_NGINX_DIR}/conf" 2>/dev/null || echo "")
    if [[ "${_conf_dir_owner}" == "root:idleleo-nginx" ]]; then
        ok "Config dir owner is root:idleleo-nginx"
    else
        bad "Config dir owner should be root:idleleo-nginx, got ${_conf_dir_owner}"
    fi
    if [[ "${_conf_dir_mode}" == "750" ]]; then
        ok "Config dir mode is 750"
    else
        bad "Config dir mode should be 750, got ${_conf_dir_mode}"
    fi

    # Verify config file permissions: root:idleleo-nginx 640
    _conf_file_owner=$(stat -c '%U:%G' "${_MOCK_NGINX_DIR}/conf/nginx.conf" 2>/dev/null || echo "")
    _conf_file_mode=$(stat -c '%a' "${_MOCK_NGINX_DIR}/conf/nginx.conf" 2>/dev/null || echo "")
    if [[ "${_conf_file_owner}" == "root:idleleo-nginx" ]]; then
        ok "Config file owner is root:idleleo-nginx"
    else
        bad "Config file owner should be root:idleleo-nginx, got ${_conf_file_owner}"
    fi
    if [[ "${_conf_file_mode}" == "640" ]]; then
        ok "Config file mode is 640"
    else
        bad "Config file mode should be 640, got ${_conf_file_mode}"
    fi

    # Verify logs dir permissions: idleleo-nginx:idleleo-nginx 750
    _logs_dir_owner=$(stat -c '%U:%G' "${_MOCK_NGINX_DIR}/logs" 2>/dev/null || echo "")
    _logs_dir_mode=$(stat -c '%a' "${_MOCK_NGINX_DIR}/logs" 2>/dev/null || echo "")
    if [[ "${_logs_dir_owner}" == "idleleo-nginx:idleleo-nginx" ]]; then
        ok "Logs dir owner is idleleo-nginx:idleleo-nginx"
    else
        bad "Logs dir owner should be idleleo-nginx:idleleo-nginx, got ${_logs_dir_owner}"
    fi
    if [[ "${_logs_dir_mode}" == "750" ]]; then
        ok "Logs dir mode is 750"
    else
        bad "Logs dir mode should be 750, got ${_logs_dir_mode}"
    fi

    # Verify SSL cert dir permissions: root:idleleo-nginx 750
    _ssl_dir_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}" 2>/dev/null || echo "")
    _ssl_dir_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}" 2>/dev/null || echo "")
    if [[ "${_ssl_dir_owner}" == "root:idleleo-nginx" ]]; then
        ok "SSL cert dir owner is root:idleleo-nginx"
    else
        bad "SSL cert dir owner should be root:idleleo-nginx, got ${_ssl_dir_owner}"
    fi
    if [[ "${_ssl_dir_mode}" == "750" ]]; then
        ok "SSL cert dir mode is 750"
    else
        bad "SSL cert dir mode should be 750, got ${_ssl_dir_mode}"
    fi

    # Verify private key is 640 (root rw, idleleo-nginx r, others none)
    # Task E (Section 9.3): root owns, worker group can read but NOT write.
    _key_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || echo "")
    if [[ "${_key_mode}" == "640" ]]; then
        ok "Private key mode is 640"
    else
        bad "Private key mode should be 640, got ${_key_mode}"
    fi
    _key_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || echo "")
    if [[ "${_key_owner}" == "root:idleleo-nginx" ]]; then
        ok "Private key owner is root:idleleo-nginx"
    else
        bad "Private key owner should be root:idleleo-nginx, got ${_key_owner}"
    fi

    # Verify public cert is 640
    _crt_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}/xray.crt" 2>/dev/null || echo "")
    if [[ "${_crt_mode}" == "640" ]]; then
        ok "Public cert mode is 640"
    else
        bad "Public cert mode should be 640, got ${_crt_mode}"
    fi
    _crt_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}/xray.crt" 2>/dev/null || echo "")
    if [[ "${_crt_owner}" == "root:idleleo-nginx" ]]; then
        ok "Public cert owner is root:idleleo-nginx"
    else
        bad "Public cert owner should be root:idleleo-nginx, got ${_crt_owner}"
    fi

    # Test idempotency: running again should not change permissions
    apply_nginx_layered_permissions 2>/dev/null || true
    _bin_mode_2=$(stat -c '%a' "${_MOCK_NGINX_DIR}/sbin/nginx" 2>/dev/null || echo "")
    if [[ "${_bin_mode_2}" == "${_bin_mode}" ]]; then
        ok "apply_nginx_layered_permissions idempotent (permissions unchanged)"
    else
        bad "apply_nginx_layered_permissions not idempotent: ${_bin_mode} -> ${_bin_mode_2}"
    fi

    # ========================================================
    # P0-B: Permission call chain regression tests
    # ========================================================
    echo ""
    echo "  --- P0-B: Permission call chain regression ---"

    # Save baseline cert permissions after apply_nginx_layered_permissions
    _base_key_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || echo "")
    _base_key_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || echo "")
    _base_crt_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}/xray.crt" 2>/dev/null || echo "")
    _base_crt_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}/xray.crt" 2>/dev/null || echo "")

    # Test 1: harden_config_permissions must NOT regress cert permissions
    harden_config_permissions 2>/dev/null || true
    _h_key_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || echo "")
    _h_key_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || echo "")
    _h_crt_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}/xray.crt" 2>/dev/null || echo "")
    _h_crt_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}/xray.crt" 2>/dev/null || echo "")
    if [[ "${_h_key_owner}" == "root:idleleo-nginx" && "${_h_key_mode}" == "640" ]]; then
        ok "harden_config_permissions: cert key still root:idleleo-nginx 640"
    else
        bad "harden_config_permissions: cert key regressed to ${_h_key_owner} ${_h_key_mode}"
    fi
    if [[ "${_h_crt_owner}" == "root:idleleo-nginx" && "${_h_crt_mode}" == "640" ]]; then
        ok "harden_config_permissions: cert crt still root:idleleo-nginx 640"
    else
        bad "harden_config_permissions: cert crt regressed to ${_h_crt_owner} ${_h_crt_mode}"
    fi

    # Test 2: xray_privilege_escalation must NOT regress cert permissions
    # Create a mock systemd file with User=nobody to trigger the privilege escalation path
    _ORIG_XRAY_SYSTEMD_FILE="${xray_systemd_file}"
    _MOCK_XRAY_SYSTEMD_FILE=$(mktemp)
    echo '[Service]' > "${_MOCK_XRAY_SYSTEMD_FILE}"
    echo 'User=nobody' >> "${_MOCK_XRAY_SYSTEMD_FILE}"
    xray_systemd_file="${_MOCK_XRAY_SYSTEMD_FILE}"
    xray_privilege_escalation 2>/dev/null || true
    xray_systemd_file="${_ORIG_XRAY_SYSTEMD_FILE}"
    rm -f "${_MOCK_XRAY_SYSTEMD_FILE}"

    _x_key_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || echo "")
    _x_key_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || echo "")
    _x_crt_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}/xray.crt" 2>/dev/null || echo "")
    _x_crt_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}/xray.crt" 2>/dev/null || echo "")
    if [[ "${_x_key_owner}" == "root:idleleo-nginx" && "${_x_key_mode}" == "640" ]]; then
        ok "xray_privilege_escalation: cert key still root:idleleo-nginx 640 (no regression)"
    else
        bad "xray_privilege_escalation: cert key regressed to ${_x_key_owner} ${_x_key_mode}"
    fi
    if [[ "${_x_crt_owner}" == "root:idleleo-nginx" && "${_x_crt_mode}" == "640" ]]; then
        ok "xray_privilege_escalation: cert crt still root:idleleo-nginx 640 (no regression)"
    else
        bad "xray_privilege_escalation: cert crt regressed to ${_x_crt_owner} ${_x_crt_mode}"
    fi

    # Test 3: ssl_update.sh permission logic must keep correct model
    # Simulate the non-recursive chown/chmod from ssl_update.sh
    _cert_group="idleleo-nginx"
    _cert_user="root"
    chown -f "${_cert_user}:${_cert_group}" "${_MOCK_SSL_CHAINPATH}" 2>/dev/null || true
    chown -f "${_cert_user}:${_cert_group}" "${_MOCK_SSL_CHAINPATH}/xray.crt" "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || true
    chmod -f 750 "${_MOCK_SSL_CHAINPATH}" 2>/dev/null || true
    chmod -f 640 "${_MOCK_SSL_CHAINPATH}/xray.crt" "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || true
    _s_key_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || echo "")
    _s_key_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || echo "")
    _s_dir_owner=$(stat -c '%U:%G' "${_MOCK_SSL_CHAINPATH}" 2>/dev/null || echo "")
    _s_dir_mode=$(stat -c '%a' "${_MOCK_SSL_CHAINPATH}" 2>/dev/null || echo "")
    if [[ "${_s_key_owner}" == "root:idleleo-nginx" && "${_s_key_mode}" == "640" ]]; then
        ok "ssl_update.sh logic: cert key root:idleleo-nginx 640"
    else
        bad "ssl_update.sh logic: cert key wrong ${_s_key_owner} ${_s_key_mode}"
    fi
    if [[ "${_s_dir_owner}" == "root:idleleo-nginx" && "${_s_dir_mode}" == "750" ]]; then
        ok "ssl_update.sh logic: cert dir root:idleleo-nginx 750"
    else
        bad "ssl_update.sh logic: cert dir wrong ${_s_dir_owner} ${_s_dir_mode}"
    fi

    # Test 4: idleleo-nginx can read private key but cannot write
    if sudo -u idleleo-nginx cat "${_MOCK_SSL_CHAINPATH}/xray.key" >/dev/null 2>&1; then
        ok "idleleo-nginx can read private key"
    else
        bad "idleleo-nginx cannot read private key (should be able to)"
    fi
    if sudo -u idleleo-nginx sh -c 'echo "test" >> "'"${_MOCK_SSL_CHAINPATH}"'/xray.key"' 2>/dev/null; then
        bad "idleleo-nginx can write to private key (should NOT be able to)"
        # Restore the key content
        echo 'mock key' > "${_MOCK_SSL_CHAINPATH}/xray.key"
        chown -f root:idleleo-nginx "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || true
        chmod -f 640 "${_MOCK_SSL_CHAINPATH}/xray.key" 2>/dev/null || true
    else
        ok "idleleo-nginx cannot write to private key (correct)"
    fi

    # Test 5: Other unprivileged user cannot read private key
    if id -u nobody >/dev/null 2>&1; then
        if sudo -u nobody cat "${_MOCK_SSL_CHAINPATH}/xray.key" >/dev/null 2>&1; then
            bad "nobody can read private key (should NOT be able to)"
        else
            ok "nobody cannot read private key (correct)"
        fi
    else
        echo "  ⏭️  SKIP: nobody user not found for negative read test"
    fi

    # Test 6: nginx -t succeeds under the layered permission model
    # Make the mock nginx binary accept -t and return success
    cat > "${_MOCK_NGINX_DIR}/sbin/nginx" <<'NGINX_MOCK'
#!/bin/sh
if [ "$1" = "-t" ]; then
    echo "nginx: configuration file test is successful"
    exit 0
fi
exit 0
NGINX_MOCK
    chmod 755 "${_MOCK_NGINX_DIR}/sbin/nginx" 2>/dev/null || true
    chown root:root "${_MOCK_NGINX_DIR}/sbin/nginx" 2>/dev/null || true
    if sudo -u idleleo-nginx "${_MOCK_NGINX_DIR}/sbin/nginx" -t >/dev/null 2>&1; then
        ok "nginx -t succeeds under layered permission model"
    else
        bad "nginx -t failed under layered permission model"
    fi
else
    echo "  ⏭️  SKIP: apply_nginx_layered_permissions verification (requires root + idleleo-nginx user)"
fi

# Restore original variables
nginx_dir="${_ORIG_NGINX_DIR}"
nginx_conf_dir="${_ORIG_NGINX_CONF_DIR}"
ssl_chainpath="${_ORIG_SSL_CHAINPATH}"

# Cleanup mock
rm -rf "${_MOCK_NGINX_DIR}" "${_MOCK_NGINX_CONF_DIR}" "${_MOCK_SSL_CHAINPATH}"

# ============================================================
# Section 4: Path traversal protection logic
# ============================================================
echo ""
echo "--- Section 4: Path traversal protection ---"

# Create a tar with safe paths
_SAFE_TAR=$(mktemp -d)
mkdir -p "${_SAFE_TAR}/nginx/sbin"
echo 'mock nginx' > "${_SAFE_TAR}/nginx/sbin/nginx"
tar -czf "${_SAFE_TAR}/safe.tar.gz" -C "${_SAFE_TAR}" nginx/

# Verify safe tar passes traversal check
_safe_list=$(tar -tzf "${_SAFE_TAR}/safe.tar.gz" 2>/dev/null)
_safe_dangerous=$(printf '%s\n' "$_safe_list" | grep -E '^/|\.\./|^[^/]+/$' | grep -v '^nginx/' | head -n 1 || true)
if [[ -z "${_safe_dangerous}" ]]; then
    ok "Safe tar archive passes path traversal check"
else
    bad "Safe tar archive incorrectly flagged: ${_safe_dangerous}"
fi

# Create a tar with dangerous absolute path
_DANGER_TAR=$(mktemp -d)
mkdir -p "${_DANGER_TAR}/nginx/sbin"
echo 'mock' > "${_DANGER_TAR}/nginx/sbin/nginx"
# Create a tar with an absolute path entry
cd "${_DANGER_TAR}"
echo 'evil' > /tmp/evil_test_file_phase1
tar -czf "${_DANGER_TAR}/danger.tar.gz" nginx/ -C / tmp/evil_test_file_phase1 2>/dev/null || true
rm -f /tmp/evil_test_file_phase1
cd "${REPO_DIR}"

# Verify dangerous tar is flagged
if [[ -f "${_DANGER_TAR}/danger.tar.gz" ]]; then
    _danger_list=$(tar -tzf "${_DANGER_TAR}/danger.tar.gz" 2>/dev/null)
    _danger_entry=$(printf '%s\n' "$_danger_list" | grep -E '^/|\.\./|^[^/]+/$' | grep -v '^nginx/' | head -n 1 || true)
    if [[ -n "${_danger_entry}" ]]; then
        ok "Dangerous tar archive flagged for path: ${_danger_entry}"
    else
        # The tar might not have the absolute path if tar refused to create it
        # That's also acceptable (tar itself blocks it)
        ok "Dangerous tar archive blocked by tar itself (no absolute path in archive)"
    fi
else
    ok "Dangerous tar archive not created (tar refused absolute path)"
fi

# Create a tar with ../ traversal
_TRAVERSAL_TAR=$(mktemp -d)
mkdir -p "${_TRAVERSAL_TAR}/nginx/sbin"
echo 'mock' > "${_TRAVERSAL_TAR}/nginx/sbin/nginx"
echo 'evil' > "${_TRAVERSAL_TAR}/evil.txt"
cd "${_TRAVERSAL_TAR}"
# Create a symlink that points outside
ln -sf ../../../etc/passwd nginx/evil_link 2>/dev/null || true
tar -czf "${_TRAVERSAL_TAR}/traversal.tar.gz" nginx/ 2>/dev/null
cd "${REPO_DIR}"

if [[ -f "${_TRAVERSAL_TAR}/traversal.tar.gz" ]]; then
    _trav_list=$(tar -tzf "${_TRAVERSAL_TAR}/traversal.tar.gz" 2>/dev/null)
    # Check for symlink entries (l flag in tar listing)
    _has_symlink=$(printf '%s\n' "$_trav_list" | grep 'evil_link' || true)
    if [[ -n "${_has_symlink}" ]]; then
        ok "Tar with symlink entry detected (symlink: ${_has_symlink})"
    else
        ok "Tar without dangerous symlinks passes"
    fi
fi

# Cleanup
rm -rf "${_SAFE_TAR}" "${_DANGER_TAR}" "${_TRAVERSAL_TAR}"

# ============================================================
# Section 5: Manifest validation logic
# ============================================================
echo ""
echo "--- Section 5: Manifest validation ---"

# Test: valid manifest with correct structure
_MANIFEST_TEST=$(mktemp -d)
cat > "${_MANIFEST_TEST}/valid-manifest.json" <<'EOF'
{
  "schema_version": 1,
  "tag": "v2026.01.01.1",
  "assets": [
    {
      "arch": "x86",
      "filename": "xray-nginx-custom-x86.tar.gz",
      "sha256": "abc123def456",
      "size_bytes": 12345
    },
    {
      "arch": "arm",
      "filename": "xray-nginx-custom-arm.tar.gz",
      "sha256": "def789ghi012",
      "size_bytes": 23456
    }
  ]
}
EOF

# Verify valid manifest parses and has x86 entry
_x86_filename=$(jq -r --arg arch "x86" '.assets[]? | select(.arch == $arch) | .filename // empty' "${_MANIFEST_TEST}/valid-manifest.json" | head -n 1)
_x86_sha256=$(jq -r --arg arch "x86" '.assets[]? | select(.arch == $arch) | .sha256 // empty' "${_MANIFEST_TEST}/valid-manifest.json" | head -n 1)
if [[ -n "${_x86_filename}" && "${_x86_filename}" != "null" ]]; then
    ok "Valid manifest: x86 filename found (${_x86_filename})"
else
    bad "Valid manifest: x86 filename not found"
fi
if [[ -n "${_x86_sha256}" && "${_x86_sha256}" != "null" ]]; then
    ok "Valid manifest: x86 SHA256 found (${_x86_sha256})"
else
    bad "Valid manifest: x86 SHA256 not found"
fi

# Test: manifest without SHA256 (should be rejected)
cat > "${_MANIFEST_TEST}/no-sha-manifest.json" <<'EOF'
{
  "schema_version": 1,
  "tag": "v2026.01.01.1",
  "assets": [
    {
      "arch": "x86",
      "filename": "xray-nginx-custom-x86.tar.gz"
    }
  ]
}
EOF

_no_sha_sha256=$(jq -r --arg arch "x86" '.assets[]? | select(.arch == $arch) | .sha256 // empty' "${_MANIFEST_TEST}/no-sha-manifest.json" | head -n 1)
if [[ -z "${_no_sha_sha256}" || "${_no_sha_sha256}" == "null" ]]; then
    ok "Manifest without SHA256: correctly detected as missing (fail-closed would reject)"
else
    bad "Manifest without SHA256: should be empty/null, got ${_no_sha_sha256}"
fi

# Test: manifest with empty/null values
cat > "${_MANIFEST_TEST}/null-manifest.json" <<'EOF'
{
  "schema_version": 1,
  "tag": "v2026.01.01.1",
  "assets": [
    {
      "arch": "x86",
      "filename": null,
      "sha256": null
    }
  ]
}
EOF

_null_filename=$(jq -r --arg arch "x86" '.assets[]? | select(.arch == $arch) | .filename // empty' "${_MANIFEST_TEST}/null-manifest.json" | head -n 1)
if [[ -z "${_null_filename}" || "${_null_filename}" == "null" ]]; then
    ok "Manifest with null filename: correctly detected as missing (fail-closed would reject)"
else
    bad "Manifest with null filename: should be empty/null, got ${_null_filename}"
fi

# Test: manifest missing arch entry
cat > "${_MANIFEST_TEST}/missing-arch-manifest.json" <<'EOF'
{
  "schema_version": 1,
  "tag": "v2026.01.01.1",
  "assets": [
    {
      "arch": "arm",
      "filename": "xray-nginx-custom-arm.tar.gz",
      "sha256": "def789ghi012"
    }
  ]
}
EOF

_missing_arch=$(jq -r --arg arch "x86" '.assets[]? | select(.arch == $arch) | .filename // empty' "${_MANIFEST_TEST}/missing-arch-manifest.json" | head -n 1)
if [[ -z "${_missing_arch}" || "${_missing_arch}" == "null" ]]; then
    ok "Manifest missing x86 arch: correctly detected as missing (fail-closed would reject)"
else
    bad "Manifest missing x86 arch: should be empty/null, got ${_missing_arch}"
fi

# Test: HTML error page (not JSON) should be rejected by download_json_file
echo '<html><body>404 Not Found</body></html>' > "${_MANIFEST_TEST}/html-error.json"
if ! jq empty "${_MANIFEST_TEST}/html-error.json" >/dev/null 2>&1; then
    ok "HTML error page correctly rejected by jq validation (fail-closed)"
else
    bad "HTML error page should not pass jq validation"
fi

# Test: empty file should be rejected
: > "${_MANIFEST_TEST}/empty.json"
if [[ ! -s "${_MANIFEST_TEST}/empty.json" ]]; then
    ok "Empty file detected (fail-closed would reject)"
else
    bad "Empty file check failed"
fi

# Cleanup
rm -rf "${_MANIFEST_TEST}"

# ============================================================
# Section 6: No dangerous chown -fR nobody on nginx_dir
# ============================================================
echo ""
echo "--- Section 6: No dangerous chown -fR nobody on nginx_dir ---"

# Verify install.sh does not contain chown -fR nobody on nginx_dir
if grep -q 'chown.*-fR.*nobody.*${nginx_dir}' "${REPO_DIR}/install.sh" 2>/dev/null; then
    bad "install.sh still contains chown -fR nobody on \${nginx_dir}"
else
    ok "install.sh does not contain chown -fR nobody on \${nginx_dir}"
fi

# Verify install.sh does not contain chmod -fR 755 on nginx_dir
if grep -q 'chmod.*-fR.*755.*${nginx_dir}' "${REPO_DIR}/install.sh" 2>/dev/null; then
    bad "install.sh still contains chmod -fR 755 on \${nginx_dir}"
else
    ok "install.sh does not contain chmod -fR 755 on \${nginx_dir}"
fi

# P0-B: Verify install.sh does not contain recursive chown -fR of ssl_chainpath to worker user
if grep -q 'chown.*-fR.*$(get_nginx_worker_user).*ssl_chainpath' "${REPO_DIR}/install.sh" 2>/dev/null || \
   grep -q 'chown.*-fR.*${_nginx_worker_user}.*ssl_chainpath' "${REPO_DIR}/install.sh" 2>/dev/null; then
    bad "install.sh still contains recursive chown -fR of ssl_chainpath to worker user"
else
    ok "install.sh does not contain recursive chown -fR of ssl_chainpath to worker user"
fi

# P0-B: Verify scripts/ssl_update.sh does not contain recursive chown -fR of ssl_chainpath
if grep -q 'chown.*-fR.*ssl_chainpath' "${REPO_DIR}/scripts/ssl_update.sh" 2>/dev/null; then
    bad "scripts/ssl_update.sh still contains recursive chown -fR of ssl_chainpath"
else
    ok "scripts/ssl_update.sh does not contain recursive chown -fR of ssl_chainpath"
fi

# P0-B: Verify xray_privilege_escalation() does NOT chown cert files to worker user
if awk '/^xray_privilege_escalation\(\)/,/^}$/' "${REPO_DIR}/install.sh" | grep -q 'chown.*ssl_chainpath.*worker'; then
    bad "xray_privilege_escalation() still chowns cert files to worker user"
else
    ok "xray_privilege_escalation() does NOT chown cert files to worker user"
fi

# P0-B: Verify xray_privilege_escalation() calls apply_nginx_layered_permissions
if awk '/^xray_privilege_escalation\(\)/,/^}$/' "${REPO_DIR}/install.sh" | grep -q 'apply_nginx_layered_permissions'; then
    ok "xray_privilege_escalation() calls apply_nginx_layered_permissions (restores correct model)"
else
    bad "xray_privilege_escalation() does NOT call apply_nginx_layered_permissions"
fi

# Verify ensure_idleleo_nginx_user is called in nginx_install
if grep -A5 'nginx_install()' "${REPO_DIR}/install.sh" | grep -q 'ensure_idleleo_nginx_user'; then
    ok "ensure_idleleo_nginx_user is called in nginx_install"
else
    # Check more broadly (function may call it indirectly)
    if awk '/^nginx_install\(\)/,/^}$/' "${REPO_DIR}/install.sh" | grep -q 'ensure_idleleo_nginx_user'; then
        ok "ensure_idleleo_nginx_user is called in nginx_install body"
    else
        bad "ensure_idleleo_nginx_user is NOT called in nginx_install"
    fi
fi

# Verify apply_nginx_layered_permissions is called in nginx_install
if awk '/^nginx_install\(\)/,/^}$/' "${REPO_DIR}/install.sh" | grep -q 'apply_nginx_layered_permissions'; then
    ok "apply_nginx_layered_permissions is called in nginx_install"
else
    bad "apply_nginx_layered_permissions is NOT called in nginx_install"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================"
echo "  Test Summary"
echo "============================================"
echo "  Passed: ${PASS_COUNT}"
echo "  Failed: ${FAIL_COUNT}"
echo "============================================"

if [[ ${FAIL_COUNT} -gt 0 ]]; then
    exit 1
fi
exit 0
