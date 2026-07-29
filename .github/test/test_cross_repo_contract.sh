#!/usr/bin/env bash
# Cross-repository Phase 1 contract verification. This test is read-only.

set -euo pipefail

MAIN_REPO="$(cd "$(dirname "$0")/../.." && pwd)"
API_REPO="${1:?API repository path is required}"
NGINX_REPO="${2:?Nginx repository path is required}"
SKILL_REPO="${3:?Skill repository path is required}"
VERSIONS_FILE="${API_REPO}/xray_shell_versions.json"
TESTED_FILE="${API_REPO}/tested_versions.json"

for file in "${VERSIONS_FILE}" "${TESTED_FILE}"; do
    jq empty "${file}"
done
(cd "${API_REPO}" && bash ./validate-json.sh)

for field in \
    nginx_build_online_version nginx_build_tested_version \
    xray_online_version xray_tested_version \
    shell_online_version shell_tested_version
do
    value=$(jq -r --arg field "${field}" '.[$field] // empty' "${VERSIONS_FILE}")
    [[ -n "${value}" ]] || {
        echo "Missing API field: ${field}" >&2
        exit 1
    }
done

tested_build=$(jq -r '.nginx_build_tested_version' "${VERSIONS_FILE}")
[[ "$(jq -r '.nginx_build' "${TESTED_FILE}")" == "${tested_build}" ]]
tag="v${tested_build}"

api_headers=()
if [[ -n "${GH_TOKEN:-}" ]]; then
    api_headers=(-H "Authorization: Bearer ${GH_TOKEN}")
fi

# P0-6: Fail-closed — tested Release MUST exist. A missing release means the
# tested_version cannot serve as a real rollback baseline, so CI must fail.
if ! release_json=$(curl -fsSL --retry 2 --connect-timeout 15 "${api_headers[@]}" \
    "https://api.github.com/repos/hello-yunshu/Xray_bash_onekey_Nginx/releases/tags/${tag}" 2>/dev/null); then
    echo "ERROR: Tested Nginx release ${tag} does not exist on GitHub (fail-closed)." >&2
    echo "ERROR: tested_version cannot serve as rollback baseline without a real Release." >&2
    exit 1
fi

if [[ "$(printf '%s' "${release_json}" | jq -r '.tag_name // empty')" != "${tag}" ]]; then
    echo "ERROR: Release tag for ${tag} does not match expected tag." >&2
    exit 1
fi

# Verify required assets exist in the release.
for asset in \
    release-manifest.json SHA256SUMS \
    xray-nginx-custom-x86.tar.gz xray-nginx-custom-arm.tar.gz
do
    printf '%s' "${release_json}" |
        jq -e --arg asset "${asset}" '.assets[]? | select(.name == $asset)' >/dev/null
done

# P0-8: Download manifest and SHA256SUMS to temp files for byte-exact SHA
# verification. Shell command substitution would strip trailing newlines and
# produce incorrect digests; file-based SHA matches the real Release asset bytes.
manifest_url=$(printf '%s' "${release_json}" | jq -r \
    '.assets[] | select(.name == "release-manifest.json") | .browser_download_url')
sha256sums_url=$(printf '%s' "${release_json}" | jq -r \
    '.assets[] | select(.name == "SHA256SUMS") | .browser_download_url')

manifest_file=$(mktemp)
sha256sums_file=$(mktemp)
trap 'rm -f "$manifest_file" "$sha256sums_file"' EXIT

curl -fsSL --retry 2 --connect-timeout 15 -o "$manifest_file" "$manifest_url"
curl -fsSL --retry 2 --connect-timeout 15 -o "$sha256sums_file" "$sha256sums_url"

# Verify manifest is valid JSON with correct tag, version, and x86/arm assets.
jq empty "$manifest_file"
jq -e --arg version "${tested_build}" --arg tag "${tag}" '
    .tag == $tag and
    .versions.nginx_build == $version and
    ([.assets[] | select(.arch == "x86" and
      .filename == "xray-nginx-custom-x86.tar.gz" and
      (.sha256 | test("^[0-9a-fA-F]{64}$")))] | length == 1) and
    ([.assets[] | select(.arch == "arm" and
      .filename == "xray-nginx-custom-arm.tar.gz" and
      (.sha256 | test("^[0-9a-fA-F]{64}$")))] | length == 1)
  ' "$manifest_file" >/dev/null

# P0-8: Verify SHA256SUMS has exactly one entry for each required file.
for req_file in xray-nginx-custom-x86.tar.gz xray-nginx-custom-arm.tar.gz release-manifest.json; do
    sum_count=$(awk -v f="$req_file" '$NF == f {c++} END {print c+0}' "$sha256sums_file")
    if [[ "$sum_count" -ne 1 ]]; then
        echo "ERROR: SHA256SUMS must have exactly one entry for ${req_file} (found ${sum_count})." >&2
        exit 1
    fi
done

# P0-8: Verify manifest x86/arm SHAs match SHA256SUMS exactly.
for arch in x86 arm; do
    manifest_filename=$(jq -r --arg arch "$arch" '.assets[] | select(.arch == $arch) | .filename' "$manifest_file")
    manifest_sha=$(jq -r --arg arch "$arch" '.assets[] | select(.arch == $arch) | .sha256' "$manifest_file")
    sum_sha=$(awk -v f="$manifest_filename" '$NF == f {print $1; exit}' "$sha256sums_file")
    if [[ "$(printf '%s' "$manifest_sha" | tr 'A-F' 'a-f')" != "$(printf '%s' "$sum_sha" | tr 'A-F' 'a-f')" ]]; then
        echo "ERROR: manifest ${arch} SHA does not match SHA256SUMS." >&2
        exit 1
    fi
done

# P0-8: Verify manifest file's actual byte-exact SHA matches SHA256SUMS record.
# This is the key check that catches trailing-newline mismatches.
manifest_recorded_sha=$(awk -v f="release-manifest.json" '$NF == f {print $1; exit}' "$sha256sums_file")
if command -v shasum >/dev/null 2>&1; then
    manifest_actual_sha=$(shasum -a 256 "$manifest_file" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
    manifest_actual_sha=$(sha256sum "$manifest_file" | awk '{print $1}')
else
    echo "ERROR: no SHA256 tool available (shasum/sha256sum)." >&2
    exit 1
fi
if [[ "$(printf '%s' "$manifest_recorded_sha" | tr 'A-F' 'a-f')" != "$(printf '%s' "$manifest_actual_sha" | tr 'A-F' 'a-f')" ]]; then
    echo "ERROR: SHA256SUMS manifest SHA (${manifest_recorded_sha}) does not match actual file bytes (${manifest_actual_sha})." >&2
    exit 1
fi

rm -f "$manifest_file" "$sha256sums_file"
trap - EXIT

echo "Tested Nginx release ${tag} verified (manifest + SHA256SUMS + assets + SHA consistency)."

grep -Fq 'releases/download/v${nginx_build_version}' "${MAIN_REPO}/install.sh"

# Prove the branch cleanup decision excludes the current known-good build.
# shellcheck source=/dev/null
source "${NGINX_REPO}/.github/scripts/release_cleanup.sh"
protected=$(parse_protected_versions \
    "$(jq -c . "${VERSIONS_FILE}")" "$(jq -c . "${TESTED_FILE}")" "")
fixture=$(jq -n --arg tested "${tag}" '[
    {id: 1, tag_name: "v2099.01.01.1", created_at: "2099-01-01T00:00:00Z"},
    {id: 2, tag_name: "v2098.01.01.1", created_at: "2098-01-01T00:00:00Z"},
    {id: 3, tag_name: "v2097.01.01.1", created_at: "2097-01-01T00:00:00Z"},
    {id: 4, tag_name: "v2096.01.01.1", created_at: "2096-01-01T00:00:00Z"},
    {id: 5, tag_name: "v2095.01.01.1", created_at: "2095-01-01T00:00:00Z"},
    {id: 6, tag_name: "v2094.01.01.1", created_at: "2094-01-01T00:00:00Z"},
    {id: 7, tag_name: $tested, created_at: "2025-01-01T00:00:00Z"}
  ]')
deletions=$(compute_releases_to_delete "${fixture}" "${protected}" 5)
if printf '%s' "${deletions}" | jq -e --arg tag "${tag}" '.[] | select(.tag_name == $tag)' >/dev/null; then
    echo "Cleanup contract would delete tested build ${tag}" >&2
    exit 1
fi

grep -Fq 'custom_email="${EMAIL}"' "${SKILL_REPO}/assets/setup-reality.sh"
grep -Fq 'custom_email="${EMAIL}"' "${SKILL_REPO}/assets/setup-tls.sh"
grep -Fq 'reality_add_more="off"' "${SKILL_REPO}/assets/setup-reality.sh"
grep -Fq 'transport_mode="None"' "${SKILL_REPO}/assets/setup-reality.sh"
! grep -Eq 'echo.*\$\{?(privateKey|shortIds|password|UUID)\b' \
    "${SKILL_REPO}/assets/setup-reality.sh" "${SKILL_REPO}/assets/setup-tls.sh"

echo "Cross-repository contracts verified (field alignment, cleanup logic, skill templates)."
