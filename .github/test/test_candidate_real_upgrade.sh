#!/usr/bin/env bash

set -euo pipefail

base=${BASE_XRAY_VERSION:?BASE_XRAY_VERSION is required}
candidate=${XRAY_CANDIDATE_VERSION:?XRAY_CANDIDATE_VERSION is required}
repo=$(cd "$(dirname "$0")/../.." && pwd)

[[ "${base}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
[[ "${candidate}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1

echo "Installing production baseline Xray ${base}"
XRAY_CANDIDATE_VERSION="${base}" bash "${repo}/.github/test/test_install.sh" reality

echo "Upgrading the existing installation to candidate Xray ${candidate}"
XRAY_CANDIDATE_VERSION="${candidate}" bash "${repo}/install.sh" --xray-update auto_update

installed=$(/usr/local/bin/xray version 2>/dev/null | awk '/Xray/{print $2; exit}')
[[ "${installed}" == "${candidate}" ]] || {
    echo "ERROR: installed Xray ${installed:-empty} != candidate ${candidate}" >&2
    exit 1
}
[[ -s /etc/idleleo/conf/install_config.json ]] || exit 1
[[ -s /etc/idleleo/conf/xray/config.json ]] || exit 1
/usr/local/bin/xray run -test -config /etc/idleleo/conf/xray/config.json
systemctl is-active --quiet xray
echo "Real representative upgrade passed: ${base} -> ${candidate}"
