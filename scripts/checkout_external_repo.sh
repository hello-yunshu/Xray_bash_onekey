#!/usr/bin/env bash
# Checkout an external repository with retries and readable diagnostics.
set -euo pipefail

repo=${1:?repository is required, e.g. hello-yunshu/Xray_bash_onekey_api}
ref=${2:?ref is required}
path=${3:?path is required}
attempts=${4:-4}
token=${GH_TOKEN:-}

for ((attempt = 1; attempt <= attempts; attempt++)); do
    status=""
    api_url="https://api.github.com/repos/${repo}/commits/${ref}"
    if [[ -n "${token}" ]]; then
        status=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer ${token}" \
            -H "Accept: application/vnd.github+json" \
            "${api_url}" || true)
    else
        status=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "Accept: application/vnd.github+json" \
            "${api_url}" || true)
    fi
    echo "external checkout repo=${repo} ref=${ref} attempt=${attempt}/${attempts} http=${status:-unavailable}"
    if [[ "${status}" != "200" ]]; then
        echo "external ref check failed repo=${repo} ref=${ref} http=${status:-unavailable}" >&2
        if (( attempt < attempts )); then sleep $((2 ** attempt)); fi
        continue
    fi

    rm -rf "${path}"
    mkdir -p "${path}"
    clone_url="https://github.com/${repo}.git"
    if [[ -n "${token}" ]]; then
        clone_url="https://x-access-token:${token}@github.com/${repo}.git"
    fi
    if git clone --quiet "${clone_url}" "${path}" \
        && git -C "${path}" fetch --quiet --depth 1 origin "${ref}" \
        && git -C "${path}" checkout --quiet FETCH_HEAD; then
        git -C "${path}" remote set-url origin "https://github.com/${repo}.git"
        echo "checked out repo=${repo} ref=${ref} path=${path}"
        exit 0
    fi
    echo "git checkout failed repo=${repo} ref=${ref} attempt=${attempt}/${attempts}" >&2
    if (( attempt < attempts )); then sleep $((2 ** attempt)); fi
done

echo "FAILED external checkout repo=${repo} ref=${ref} after ${attempts} attempts" >&2
echo "Diagnose: verify the repository exists, the ref is reachable, and the token can read it." >&2
exit 1
