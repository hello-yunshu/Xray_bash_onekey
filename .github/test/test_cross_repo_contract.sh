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
release_json=$(curl -fsSL --retry 2 --connect-timeout 15 "${api_headers[@]}" \
    "https://api.github.com/repos/hello-yunshu/Xray_bash_onekey_Nginx/releases/tags/${tag}")
[[ "$(printf '%s' "${release_json}" | jq -r '.tag_name // empty')" == "${tag}" ]]

for asset in \
    release-manifest.json SHA256SUMS \
    xray-nginx-custom-x86.tar.gz xray-nginx-custom-arm.tar.gz
do
    printf '%s' "${release_json}" |
        jq -e --arg asset "${asset}" '.assets[]? | select(.name == $asset)' >/dev/null
done

manifest_url=$(printf '%s' "${release_json}" | jq -r \
    '.assets[] | select(.name == "release-manifest.json") | .browser_download_url')
manifest=$(curl -fsSL --retry 2 --connect-timeout 15 "${manifest_url}")
printf '%s' "${manifest}" | jq -e \
    --arg version "${tested_build}" --arg tag "${tag}" '
    .tag == $tag and
    .versions.nginx_build == $version and
    ([.assets[] | select(.arch == "x86" and
      .filename == "xray-nginx-custom-x86.tar.gz" and
      (.sha256 | test("^[0-9a-fA-F]{64}$")))] | length == 1) and
    ([.assets[] | select(.arch == "arm" and
      .filename == "xray-nginx-custom-arm.tar.gz" and
      (.sha256 | test("^[0-9a-fA-F]{64}$")))] | length == 1)
  ' >/dev/null

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

echo "Cross-repository contracts verified for tested Nginx ${tag}."
