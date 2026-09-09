#!/usr/bin/env bash

set -uo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
export _TEST_MODE=1
source "${repo}/install.sh" >/dev/null 2>&1 || true

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT
idleleo_dir="${tmp}/idleleo"
mkdir -p "${idleleo_dir}/tmp"
log_echo() { :; }
printf '#!/usr/bin/env bash\nprintf executed >"$XRAY_INSTALLER_TEST_MARKER"\n' >"${tmp}/installer.sh"
chmod +x "${tmp}/installer.sh"
fixture_sha=$(sha256sum "${tmp}/installer.sh" | awk '{print $1}')
XRAY_INSTALLER_TEST_MARKER="${tmp}/executed"
export XRAY_INSTALLER_TEST_MARKER

download_script_file() { cp "${tmp}/installer.sh" "$2"; chmod +x "$2"; }
bash() {
    if [[ "${1:-}" == -n ]]; then
        command bash "$@"
    else
        command bash "$@"
    fi
}

xray_installer_ref=e741a4f56d368afbb9e5be3361b40c4552d3710d
xray_installer_sha256="${fixture_sha}"
if xray_install_release install -f --version v26.3.27 && [[ -f "${XRAY_INSTALLER_TEST_MARKER}" ]]; then
    echo 'PASS: valid installer ref and SHA execute'
else
    echo 'FAIL: valid installer metadata was rejected'
    exit 1
fi

rm -f "${XRAY_INSTALLER_TEST_MARKER}"
xray_installer_sha256=0000000000000000000000000000000000000000000000000000000000000000
if xray_install_release install -f --version v26.3.27; then
    echo 'FAIL: bad installer SHA was accepted'
    exit 1
fi
[[ ! -f "${XRAY_INSTALLER_TEST_MARKER}" ]] || { echo 'FAIL: bad SHA executed installer'; exit 1; }

xray_installer_ref=main
xray_installer_sha256="${fixture_sha}"
if xray_install_release install -f --version v26.3.27; then
    echo 'FAIL: mutable installer ref was accepted'
    exit 1
fi
echo 'Verified installer metadata regression passed'
