#!/usr/bin/env bash

set -euo pipefail

scenario=${1:?usage: $0 <fresh|reinstall|remove>}
target_version=${XRAY_TARGET_VERSION:?XRAY_TARGET_VERSION is required}
candidate_ref=${XRAY_CANDIDATE_INSTALLER_REF:?XRAY_CANDIDATE_INSTALLER_REF is required}
candidate_sha=${XRAY_CANDIDATE_INSTALLER_SHA256:?XRAY_CANDIDATE_INSTALLER_SHA256 is required}
current_ref=${XRAY_CURRENT_INSTALLER_REF:-}
current_sha=${XRAY_CURRENT_INSTALLER_SHA256:-}

[[ "${scenario}" == fresh || "${scenario}" == reinstall || "${scenario}" == remove ]] || exit 1
[[ "${target_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
[[ "${candidate_ref}" =~ ^[0-9a-f]{40}$ ]] || exit 1
[[ "${candidate_sha}" =~ ^[0-9a-f]{64}$ ]] || exit 1

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT

download_installer() {
    local ref=$1 expected_sha=$2 output=$3 actual_sha
    [[ "${ref}" =~ ^[0-9a-f]{40}$ ]] || return 1
    [[ "${expected_sha}" =~ ^[0-9a-f]{64}$ ]] || return 1
    curl -fsSL --connect-timeout 15 --max-time 60 \
        "https://raw.githubusercontent.com/XTLS/Xray-install/${ref}/install-release.sh" \
        -o "${output}"
    actual_sha=$(sha256sum "${output}" | awk '{print $1}')
    [[ "${actual_sha}" == "${expected_sha}" ]] || {
        echo "ERROR: installer SHA mismatch for ${ref}" >&2
        return 1
    }
    bash -n "${output}"
}

assert_xray_healthy() {
    local installed config=/usr/local/etc/xray/config.json
    [[ -x /usr/local/bin/xray ]] || return 1
    installed=$(/usr/local/bin/xray version 2>/dev/null | awk '/Xray/{print $2; exit}')
    [[ "${installed}" == "${target_version}" ]] || {
        echo "ERROR: installed Xray ${installed:-empty} != ${target_version}" >&2
        return 1
    }
    [[ -s "${config}" ]] || return 1
    /usr/local/bin/xray run -test -config "${config}"
    systemctl is-active --quiet xray
}

candidate_installer=${tmp}/candidate-install-release.sh
download_installer "${candidate_ref}" "${candidate_sha}" "${candidate_installer}"

case "${scenario}" in
fresh)
    bash "${candidate_installer}" install --version "v${target_version}"
    assert_xray_healthy
    ;;
reinstall)
    [[ "${current_ref}" =~ ^[0-9a-f]{40}$ ]] || exit 1
    [[ "${current_sha}" =~ ^[0-9a-f]{64}$ ]] || exit 1
    current_installer=${tmp}/current-install-release.sh
    download_installer "${current_ref}" "${current_sha}" "${current_installer}"
    bash "${current_installer}" install --version "v${target_version}"
    assert_xray_healthy
    bash "${candidate_installer}" install -f --version "v${target_version}"
    assert_xray_healthy
    ;;
remove)
    bash "${candidate_installer}" install --version "v${target_version}"
    assert_xray_healthy
    bash "${candidate_installer}" remove --purge
    [[ ! -e /usr/local/bin/xray ]]
    [[ ! -e /usr/local/etc/xray ]]
    ! systemctl is-active --quiet xray
    ;;
esac

echo "Installer candidate ${scenario} smoke passed"
