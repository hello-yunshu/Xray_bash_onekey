#!/usr/bin/env bash
# Focused regression for Issue #102.
#
# The test keeps the production check_file_integrity/rxa_download call chain,
# mocks only the package/network/replace edges, and proves that the Release
# metadata is available before the first immutable candidate URL is built.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

export _TEST_MODE=1
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { :; }
judge() { :; }
clear() { :; }

candidate_source="${TMP_ROOT}/candidate.sh"
printf '%s\n' '#!/usr/bin/env bash' 'shell_version="3.2.8"' 'xray_install_release() { :; }' >"${candidate_source}"
candidate_sha=$(sha256sum "${candidate_source}" | awk '{print $1}')
versions_file="${TMP_ROOT}/versions.json"
jq -n --arg sha "${candidate_sha}" \
    '{shell_online_version:"3.2.8", shell_release_sha256:$sha}' >"${versions_file}"
export XRAY_VERSIONS_FILE="${versions_file}"

idleleo_dir="${TMP_ROOT}/etc/idleleo"
idleleo="${idleleo_dir}/install.sh"
idleleo_commend_file="${TMP_ROOT}/usr/bin/idleleo"
scripts_dir="${idleleo_dir}/scripts"
mkdir -p "${TMP_ROOT}/etc" "${TMP_ROOT}/usr/bin"

ORDER=()
REQUESTED_URL=""
check_system() { ORDER+=(check_system); return 0; }
pkg_install() { ORDER+=(pkg_install); return 0; }
download_script_file() {
    REQUESTED_URL="$1"
    ORDER+=(download)
    cp "${candidate_source}" "$2"
    chmod +x "$2"
}
candidate_guard() { ORDER+=(candidate_guard); return 0; }
rxa_replace_main_candidate() { ORDER+=(replace); return 0; }
exec() { ORDER+=(exec); return 0; }

# Wrap the real helper so the ordering assertion observes its actual metadata
# validation and URL setup rather than a test-only replacement.
_metadata_definition="$(declare -f load_shell_release_metadata)"
eval "${_metadata_definition/load_shell_release_metadata/load_shell_release_metadata_real}"
load_shell_release_metadata() {
    ORDER+=(metadata)
    load_shell_release_metadata_real
}

check_file_integrity --install-reality

order=" ${ORDER[*]} "
if [[ "${order}" == *" pkg_install metadata download "* ]]; then
    ok "metadata loads after dependency bootstrap and before candidate download"
else
    bad "ordering was not dependency -> metadata -> candidate download: ${ORDER[*]}"
fi
if [[ "${REQUESTED_URL}" == *"/releases/download/v3.2.8/install.sh" &&
      "${REQUESTED_URL}" != *"/releases/download/v/install.sh" &&
      "${REQUESTED_URL}" != *"/releases/download/v//install.sh" ]]; then
    ok "candidate URL contains an exact Release version"
else
    bad "candidate URL was not exact: ${REQUESTED_URL}"
fi
if [[ "${shell_online_version}" == "3.2.8" &&
      "${shell_release_sha256}" == "${candidate_sha}" ]]; then
    ok "metadata exposes the expected version and SHA256"
else
    bad "metadata values were not loaded: version=${shell_online_version} sha=${shell_release_sha256}"
fi

printf '\nFocused bootstrap ordering result: %d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
