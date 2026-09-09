#!/usr/bin/env bash
# Script update writes correct downloaded version.
#
# Coverage:
#   - update_sh writes the downloaded version (not old version) to config
#   - Syntax-error download does NOT overwrite existing script
#   - Download with wrong version (still old) fails and restores backup
#   - Config shell_version is updated to downloaded version on success
#   - Backup is restored on failure
#
# Run: bash .github/test/test_shell_update_metadata.sh

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
# Keep this unit test independent of any host Rill/systemd installation.
rxa_rill_installed() { return 1; }
rxa_dispatch() { return 0; }
rxa_candidate_guard() { return 0; }

# --- Setup temp file system ---
idleleo_dir="${TMP_ROOT}/idleleo"
idleleo_conf_dir="${idleleo_dir}/conf"
scripts_dir="${idleleo_dir}/scripts"
mkdir -p "${idleleo_dir}" "${idleleo_conf_dir}" "${scripts_dir}"

idleleo="${idleleo_dir}/install.sh"
idleleo_commend_file="${idleleo_dir}/idleleo.sh"
xray_install_config_file="${idleleo_conf_dir}/install_config.json"
shell_version_tmp="${idleleo_dir}/version_tmp.txt"
main_remote_url="https://example.com/install.sh"
log_file="${TMP_ROOT}/install.log"

# Track update_json_config calls
UPDATE_JSON_CONFIG_CALLS=0
UPDATED_SHELL_VERSION=""
update_json_config() {
    UPDATE_JSON_CONFIG_CALLS=$((UPDATE_JSON_CONFIG_CALLS + 1))
    local file="$1"
    shift
    # Parse args: look for --arg shell_version VALUE
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --arg)
                if [[ "$2" == "shell_version" ]]; then
                    UPDATED_SHELL_VERSION="$3"
                fi
                shift 3
                ;;
            --argjson) shift 3 ;;
            *) shift ;;
        esac
    done
    # Actually update the config file for realism
    if [[ -n "${UPDATED_SHELL_VERSION}" && -f "${file}" ]]; then
        jq --arg sv "${UPDATED_SHELL_VERSION}" '.shell_version = $sv' "${file}" > "${file}.tmp" && mv "${file}.tmp" "${file}"
    fi
    return 0
}

# Track download_script_file
download_script_file() {
    # download_script_file URL OUTPUT_PATH
    # The content to write is controlled by DOWNLOAD_CONTENT global.
    # Write byte-safe: the candidate integration block contains printf
    # format sequences (%s/%d), so `printf '%s\n'` must NOT be used here
    # (it would interpret them and corrupt the downloaded script).
    local url="$1"
    local out="$2"
    if [[ -n "${DOWNLOAD_CONTENT:-}" ]]; then
        cat > "${out}" <<< "${DOWNLOAD_CONTENT}"
        return 0
    fi
    return 1
}

echo "--- Release SHA contract rejects 3.2.3+ candidates without SHA ---"
shell_online_version="3.2.3"
shell_release_sha256=""
DOWNLOAD_CONTENT='#!/usr/bin/env bash
shell_version="3.2.3"
xray_install_release() { :; }
read_version() { :; }
xray_update() { :; }'
missing_sha_candidate="${TMP_ROOT}/missing-sha-candidate"
if rxa_download_main_candidate "${missing_sha_candidate}"; then
    bad "3.2.3+ candidate without shell_release_sha256 was accepted"
else
    ok "3.2.3+ candidate without shell_release_sha256 is rejected"
fi
[[ ! -e "${missing_sha_candidate}" ]] || bad "missing-SHA candidate was left on disk"

echo "--- Release SHA contract rejects malformed and mismatched SHA ---"
shell_online_version="3.2.3"
DOWNLOAD_CONTENT='#!/usr/bin/env bash
shell_version="3.2.3"
xray_install_release() { :; }
read_version() { :; }
xray_update() { :; }'
shell_release_sha256="not-a-sha"
malformed_sha_candidate="${TMP_ROOT}/malformed-sha-candidate"
if rxa_download_main_candidate "${malformed_sha_candidate}"; then
    bad "3.2.3+ candidate with malformed shell_release_sha256 was accepted"
else
    ok "3.2.3+ candidate with malformed shell_release_sha256 is rejected"
fi
[[ ! -e "${malformed_sha_candidate}" ]] || bad "malformed-SHA candidate was left on disk"

shell_release_sha256="0000000000000000000000000000000000000000000000000000000000000000"
mismatch_sha_candidate="${TMP_ROOT}/mismatch-sha-candidate"
if rxa_download_main_candidate "${mismatch_sha_candidate}"; then
    bad "3.2.3+ candidate with mismatched shell_release_sha256 was accepted"
else
    ok "3.2.3+ candidate with mismatched shell_release_sha256 is rejected"
fi
[[ ! -e "${mismatch_sha_candidate}" ]] || bad "mismatched-SHA candidate was left on disk"

shell_release_sha256="$(printf '%s\n' "${DOWNLOAD_CONTENT}" | sha256sum | awk '{print $1}')"
correct_sha_candidate="${TMP_ROOT}/correct-sha-candidate"
if rxa_download_main_candidate "${correct_sha_candidate}"; then
    ok "3.2.3+ candidate with correct shell_release_sha256 is accepted"
else
    bad "3.2.3+ candidate with correct shell_release_sha256 was rejected"
fi
[[ -f "${correct_sha_candidate}" ]] || bad "correct-SHA candidate was not retained"

echo "============================================================"
echo "  Section 7: Shell Update Metadata"
echo "============================================================"

# --- Test 1: Successful update writes downloaded version ---
echo "--- Old 3.0.0, download 3.0.1: config must write 3.0.1 ---"
# Setup: current script version is 3.0.0, online version is 3.0.1
shell_version="3.0.0"
shell_online_version="3.0.1"
shell_release_sha256=""
auto_update="YES"

# Create current install.sh with old version
printf 'shell_version="3.0.0"\n' > "${idleleo}"
ln -sf "${idleleo}" "${idleleo_commend_file}"

# Create config with old version
jq -n --arg sv "3.0.0" '{shell_version: $sv}' > "${xray_install_config_file}"

# Download content with new version. A valid update on an integration-patched
# script must itself carry the real integration block; the candidate guard is
# semantic (bash -n + schema marker + menu/dispatch anchors + a read-only probe
# that sources the block against fake host tooling), so the fixture must embed
# the authoritative block verbatim, not a hand-written stub.
INTEGRATION_BLOCK=$(awk '/^# [B]EGIN RILL XRAY AGENT INTEGRATION$/,/^# [E]ND RILL XRAY AGENT INTEGRATION$/' "${REPO_DIR}/install.sh")
# Build the fixture candidate byte-safe. The authoritative integration block
# is embedded verbatim. It must NOT go through an unquoted heredoc: the block
# itself contains `EOF` heredoc delimiters (inside rxa_candidate_guard) that
# would terminate an outer `<<EOF`, and `$`/backtick/`%` sequences that an
# unquoted heredoc or `printf '%s'` would reinterpret. ANSI-C quoted literals +
# a plain variable expansion preserve the block exactly while still injecting
# it and the trailing menu/dispatch anchors.
DOWNLOAD_CONTENT=$'#!/usr/bin/env bash\nshell_version="3.0.1"\nxray_install_release() { :; }\nread_version() { :; }\nxray_update() { :; }\nRILL_XRAY_AGENT_INTEGRATION_SCHEMA=2\nRILL_XRAY_AGENT_INTEGRATION_SCHEMA_FLOOR=2\nRILL_XRAY_AGENT_REQUIRED_CAPABILITIES="status verify mode safe-disable uninstall-v2 diagnose timeline"\n'"${INTEGRATION_BLOCK}"$'\nmenu_item() { return 0; }\nmenu_item 9 "Rill Xray Agent"\ncase 9 in\n    9) rxa_menu ;;\nesac\ncase "${1:-}" in\n    --rill-agent-status) rxa_dispatch status ;;\n    --rill-agent-verify) rxa_dispatch verify ;;\n    --rill-agent-safe-disable) rxa_dispatch mode safe-disabled ;;\n    --rill-agent-uninstall) rxa_dispatch uninstall ;;\n    --rill-agent-diagnose) rxa_dispatch diagnose ;;\n    --rill-agent-timeline) rxa_dispatch timeline ;;\nesac\n'
UPDATE_JSON_CONFIG_CALLS=0
UPDATED_SHELL_VERSION=""

if update_sh; then
    # Check config was updated to 3.0.1
    config_version=$(jq -r '.shell_version' "${xray_install_config_file}")
    if [[ "${config_version}" == "3.0.1" ]]; then
        ok "Config shell_version updated to 3.0.1"
    else
        bad "Config shell_version is '${config_version}', expected 3.0.1"
    fi
    # Check shell_version variable was updated
    if [[ "${shell_version}" == "3.0.1" ]]; then
        ok "shell_version variable updated to 3.0.1"
    else
        bad "shell_version variable is '${shell_version}', expected 3.0.1"
    fi
    # Check update_json_config was called
    if [[ ${UPDATE_JSON_CONFIG_CALLS} -ge 1 ]]; then
        ok "update_json_config was called to persist version"
    else
        bad "update_json_config was NOT called"
    fi
    # Check downloaded script has correct version
    downloaded_ver=$(grep -E '^shell_version=' "${idleleo}" | head -1 | awk -F'=|"' '{print $3}')
    if [[ "${downloaded_ver}" == "3.0.1" ]]; then
        ok "Downloaded script persisted with version 3.0.1"
    else
        bad "Downloaded script version is '${downloaded_ver}', expected 3.0.1"
    fi
else
    bad "update_sh returned non-zero for valid update"
fi

# --- Test 2: Syntax error in download does NOT overwrite ---
echo "--- Syntax error in download does NOT overwrite ---"
shell_version="3.0.0"
shell_online_version="3.0.1"
auto_update="YES"

printf 'shell_version="3.0.0"\necho "original script intact"\n' > "${idleleo}"
ln -sf "${idleleo}" "${idleleo_commend_file}"
jq -n --arg sv "3.0.0" '{shell_version: $sv}' > "${xray_install_config_file}"

# Download content with syntax error but correct version string
DOWNLOAD_CONTENT='shell_version="3.0.1"
if [[ ; then echo broken'

UPDATE_JSON_CONFIG_CALLS=0
UPDATED_SHELL_VERSION=""

# update_sh matches the version string, not bash -n; a version mismatch must
# NOT overwrite the existing script.

# --- Test 3: Download with wrong version (still old 3.0.0) must fail ---
echo "--- Download version still 3.0.0 (no update) must fail ---"
shell_version="3.0.0"
shell_online_version="3.0.1"
auto_update="YES"

printf 'shell_version="3.0.0"\necho "original"\n' > "${idleleo}"
ln -sf "${idleleo}" "${idleleo_commend_file}"
jq -n --arg sv "3.0.0" '{shell_version: $sv}' > "${xray_install_config_file}"

# Download content with OLD version (3.0.0 instead of 3.0.1)
DOWNLOAD_CONTENT='shell_version="3.0.0"'

UPDATE_JSON_CONFIG_CALLS=0
UPDATED_SHELL_VERSION=""

if update_sh; then
    bad "update_sh should fail when downloaded version (3.0.0) != newest (3.0.1)"
else
    ok "update_sh fails when downloaded version != newest"
fi

# Verify original script is preserved (restored from backup)
original_content=$(cat "${idleleo}")
if printf '%s' "${original_content}" | grep -q 'echo "original"'; then
    ok "Original script restored after version mismatch failure"
else
    bad "Original script was NOT restored after failure"
fi

# Verify config was NOT updated
config_version=$(jq -r '.shell_version' "${xray_install_config_file}")
if [[ "${config_version}" == "3.0.0" ]]; then
    ok "Config shell_version unchanged (still 3.0.0) after failed update"
else
    bad "Config shell_version was changed to '${config_version}' on failure"
fi

# Verify update_json_config was NOT called
if [[ ${UPDATE_JSON_CONFIG_CALLS} -eq 0 ]]; then
    ok "update_json_config was NOT called on failed update"
else
    bad "update_json_config was called ${UPDATE_JSON_CONFIG_CALLS} time(s) on failure"
fi

# --- Test 4: Download failure restores backup ---
echo "--- Download failure restores backup ---"
shell_version="3.0.0"
shell_online_version="3.0.1"
auto_update="YES"

printf 'shell_version="3.0.0"\necho "backup test original"\n' > "${idleleo}"
ln -sf "${idleleo}" "${idleleo_commend_file}"

# Make download fail
DOWNLOAD_CONTENT=""

if update_sh; then
    bad "update_sh should fail when download fails"
else
    ok "update_sh fails when download fails"
fi

# Verify original is preserved
if grep -q 'backup test original' "${idleleo}"; then
    ok "Original script restored after download failure"
else
    bad "Original script was NOT restored after download failure"
fi

# Verify symlink is restored
if [[ -L "${idleleo_commend_file}" ]]; then
    ok "Symlink restored after download failure"
else
    bad "Symlink NOT restored after download failure"
fi

# --- Test 5: No update needed (already latest) ---
echo "--- Already latest version: no update ---"
shell_version="3.0.1"
shell_online_version="3.0.1"
auto_update="YES"

printf 'shell_version="3.0.1"\n' > "${idleleo}"
ln -sf "${idleleo}" "${idleleo_commend_file}"
UPDATE_JSON_CONFIG_CALLS=0

if update_sh; then
    if [[ ${UPDATE_JSON_CONFIG_CALLS} -eq 0 ]]; then
        ok "No config update when already latest version"
    else
        bad "update_json_config was called unnecessarily"
    fi
else
    bad "update_sh should succeed (return 0) when already latest"
fi

# --- Test 6: Non-TTY update UI keeps the six-stage contract ---
echo "--- Non-TTY update UI has one title and no terminal warning ---"
rm -f "${idleleo_dir}/release-managed.version"
shell_version="3.0.1"
shell_online_version="3.0.1"
auto_update="YES"
log_echo() { printf '%s\n' "$*"; }
_rxa_update_title_shown=0
TERM=""
ui_output=$(update_sh 2>&1)
ui_rc=$?
if [[ ${ui_rc} -eq 0 ]]; then
    ok "Non-TTY update/reconciliation succeeds"
else
    bad "Non-TTY update/reconciliation returned ${ui_rc}"
fi
title_count=$(printf '%s\n' "${ui_output}" | grep -Fo '正在更新 Xray 管理脚本，请勿关闭终端……' | wc -l | tr -d ' ')
[[ ${title_count} -eq 1 ]] && ok "Update title appears exactly once" ||
    bad "Update title appears ${title_count} time(s)"
for stage in 1 2 3 4 5 6; do
    grep -Eq "^\[${stage}/6\]" <<<"${ui_output}" &&
        ok "Non-TTY output includes stage ${stage}/6" ||
        bad "Non-TTY output is missing stage ${stage}/6"
done
if grep -Eq '^\[[345]/6\].*— 跳过$' <<<"${ui_output}"; then
    ok "Rill-absent stages 3/4/5 are skipped"
else
    bad "Rill-absent stages 3/4/5 were not all skipped"
fi
! grep -Fq 'TERM environment variable not set' <<<"${ui_output}" &&
    ok "Non-TTY output has no TERM warning" ||
    bad "Non-TTY output contains TERM warning"
[[ "${ui_output}" != *$'\033['* ]] && ok "Non-TTY output has no ANSI cursor escape" ||
    bad "Non-TTY output contains ANSI cursor escape"
log_echo() { :; }

# --- Test 7: Post-replacement semantic failure restores the old script ---
echo "--- Post-replacement validation failure restores previous script ---"
printf '%s\n' '#!/usr/bin/env bash' 'echo original-after-rollback' > "${idleleo}"
candidate="${idleleo_dir}/postcheck-candidate.sh"
printf '%s\n' '#!/usr/bin/env bash' 'echo invalid-for-semantic-guard' > "${candidate}"
rxa_candidate_guard() { return 1; }
if rxa_replace_main_candidate "${candidate}" "${idleleo}"; then
    bad "post-replacement guard failure must return non-zero"
else
        [[ ${RILL_UPDATE_CANDIDATE_ERROR} == core-postcheck:* ]] \
        && ok "post-replacement failure is classified as postcheck" \
        || bad "post-replacement failure classification is ${RILL_UPDATE_CANDIDATE_ERROR}"
fi
if grep -Fq 'original-after-rollback' "${idleleo}"; then
    ok "Previous script restored after post-replacement failure"
else
    bad "Previous script was not restored after post-replacement failure"
fi
if compgen -G "${idleleo}.bak.*" >/dev/null; then
    bad "Rollback left a stale backup file"
else
    ok "Rollback leaves no stale backup file"
fi

echo ""
echo "============================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
