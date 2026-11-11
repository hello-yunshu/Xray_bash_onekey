#!/usr/bin/env bash
# S6-2 regression tests: every helper download is pinned to a sha256 from the
# Release manifest, and a mismatch must fail the download (nonzero, nothing
# written), not just log a line and install anyway.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { printf '%s\n' "$*" >&2; }
gettext() { printf '%s' "$1"; }

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq is unavailable"; exit 0; }
command -v sha256sum >/dev/null 2>&1 || { echo "SKIP: sha256sum is unavailable"; exit 0; }

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT
scripts_dir="${TMP_ROOT}/scripts"
mkdir -p "${scripts_dir}"

SCRIPT_BODY='#!/usr/bin/env bash
echo helper
'
printf '%s' "${SCRIPT_BODY}" >"${TMP_ROOT}/body.sh"
GOOD_SHA=$(sha256sum "${TMP_ROOT}/body.sh" | awk '{print $1}')
BAD_SHA='0000000000000000000000000000000000000000000000000000000000000000'

# curl is replaced by a local body writer so no test touches the network.
CURL_FAIL=0
curl() {
    [[ ${CURL_FAIL} == "0" ]] || return 22
    local dest="" prev=""
    for arg in "$@"; do
        if [[ "${prev}" == "-o" ]]; then dest="${arg}"; fi
        prev="${arg}"
    done
    [[ -n "${dest}" ]] || return 1
    cp "${TMP_ROOT}/body.sh" "${dest}"
}

# The manifest is injected directly; only its JSON shape matters here.
download_json_file() {
    local dest="$2"
    printf '%s' "${STUB_MANIFEST}" >"${dest}"
}

shell_release_asset_url() { printf 'https://example.invalid/%s/%s' "$1" "$2"; }

reset_manifest_cache() {
    _release_manifest_cache_version=""
    _release_manifest_cache_path=""
    rm -f "${TMP_ROOT}"/idleleo-release-manifest.* 2>/dev/null
}

with_manifest() { # $1 = helperScripts JSON object
    STUB_MANIFEST=$(jq -cn --argjson helpers "$1" '{
      schemaVersion: 1,
      version: "3.3.6",
      helperScripts: $helpers
    }')
    reset_manifest_cache
}

printf '%s\n' '--- pinned hash mismatch is fatal ---'
with_manifest "$(jq -cn --arg sha "${BAD_SHA}" '{("file_manager.sh"): $sha}')"
rm -f "${scripts_dir}/file_manager.sh"
if ensure_sub_script "file_manager.sh" "https://example.invalid/file_manager.sh" >/dev/null 2>&1; then
    bad "a helper whose body does not match the pinned hash was installed"
elif [[ -e "${scripts_dir}/file_manager.sh" ]]; then
    bad "a rejected helper still left a file behind"
else
    ok "hash mismatch returns nonzero and writes nothing"
fi

printf '%s\n' '--- pinned hash match installs ---'
with_manifest "$(jq -cn --arg sha "${GOOD_SHA}" '{("file_manager.sh"): $sha}')"
if ensure_sub_script "file_manager.sh" "https://example.invalid/file_manager.sh" >/dev/null 2>&1 &&
    [[ -s "${scripts_dir}/file_manager.sh" ]]; then
    ok "matching hash installs the helper"
else
    bad "matching hash was rejected"
fi

printf '%s\n' '--- an existing helper is re-hashed ---'
with_manifest "$(jq -cn --arg sha "${GOOD_SHA}" '{("file_manager.sh"): $sha}')"
printf '#!/usr/bin/env bash\ntampered\n' >"${scripts_dir}/file_manager.sh"
if ensure_sub_script "file_manager.sh" "https://example.invalid/file_manager.sh" >/dev/null 2>&1 &&
    [[ $(sha256sum "${scripts_dir}/file_manager.sh" | awk '{print $1}') == "${GOOD_SHA}" ]]; then
    ok "an existing helper with a stale hash is re-downloaded"
else
    bad "an existing helper with a stale hash was accepted or not replaced"
fi

printf '%s\n' '--- a failed re-download of a stale helper is fatal ---'
printf '#!/usr/bin/env bash\ntampered\n' >"${scripts_dir}/file_manager.sh"
CURL_FAIL=1
if ensure_sub_script "file_manager.sh" "https://example.invalid/file_manager.sh" >/dev/null 2>&1; then
    bad "a stale helper was kept when the re-download failed"
else
    ok "a failed re-download of a stale helper returns nonzero"
fi
CURL_FAIL=0

printf '%s\n' '--- direct download honours the pinned hash ---'
rm -f "${TMP_ROOT}/direct.sh"
if download_script_file "https://example.invalid/direct.sh" "${TMP_ROOT}/direct.sh" bash "${BAD_SHA}" >/dev/null 2>&1; then
    bad "download_script_file accepted a body that does not match the expected hash"
elif [[ -e "${TMP_ROOT}/direct.sh" ]]; then
    bad "download_script_file left a rejected body in place"
else
    ok "download_script_file rejects a mismatched body"
fi
if download_script_file "https://example.invalid/direct.sh" "${TMP_ROOT}/direct.sh" bash "${GOOD_SHA}" >/dev/null 2>&1 &&
    [[ -s "${TMP_ROOT}/direct.sh" ]]; then
    ok "download_script_file installs a matching body"
else
    bad "download_script_file rejected a matching body"
fi

printf '%s\n' '--- unpinned helper and the cutover ---'
saved_shell_version=${shell_version}
with_manifest '{}'
shell_version="3.3.6"
rm -f "${scripts_dir}/fail2ban_manager.sh"
if ensure_sub_script "fail2ban_manager.sh" "https://example.invalid/fail2ban_manager.sh" >/dev/null 2>&1; then
    ok "unpinned helper below the cutover installs with a warning"
else
    bad "unpinned helper below the cutover was rejected"
fi

with_manifest '{}'
shell_version="3.4.0"
rm -f "${scripts_dir}/traffic_blocker.sh"
if ensure_sub_script "traffic_blocker.sh" "https://example.invalid/traffic_blocker.sh" >/dev/null 2>&1; then
    bad "unpinned helper at the cutover was installed"
elif [[ -e "${scripts_dir}/traffic_blocker.sh" ]]; then
    bad "refused helper still left a file behind"
else
    ok "unpinned helper at 3.4.0 is refused"
fi
shell_version=${saved_shell_version}

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
