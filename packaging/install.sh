#!/bin/bash
# packaging/install.sh
#
# Controlled bootstrap for a NEW Go-managed installation. It never executes a
# floating remote script: it downloads one asset listed in a local manifest,
# verifies the pinned SHA-256 and the ELF header, then runs the Go installer.
#
# The manifest is a release asset, for example:
#   {"schemaVersion":1,"version":"0.1.0","url":"https://.../idleleo-linux-arm64",
#    "sha256":"<hex>"}
#
# Usage: packaging/install.sh [--manifest PATH] [--mode MODE] [--transport T]
#         [--domain HOST] [--fetch-only] [installer flags...]
set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
manifest="${IDLELEO_BOOTSTRAP_MANIFEST:-${script_dir}/bootstrap-manifest.json}"
fetch_only=off
installer_args=()

while [[ $# -gt 0 ]]; do
    case "$1" in
    --manifest)
        manifest="$2"
        shift 2
        ;;
    --fetch-only)
        fetch_only=on
        shift
        ;;
    *)
        installer_args+=("$1")
        shift
        ;;
    esac
done

if [[ "$(id -u)" != "0" ]]; then
    echo "root is required" >&2
    exit 2
fi
if [[ ! -r "${manifest}" ]]; then
    echo "missing bootstrap manifest: ${manifest}" >&2
    exit 2
fi

read_manifest() {
    python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],"") or "")' "${manifest}" "$1"
}

asset_url=$(read_manifest url) || asset_url=""
asset_sha=$(read_manifest sha256) || asset_sha=""
if [[ -z "${asset_url}" || -z "${asset_sha}" ]]; then
    echo "bootstrap manifest has no url/sha256" >&2
    exit 2
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/idleleo-bootstrap.XXXXXX")
trap 'rm -rf "${tmpdir}"' EXIT

if ! curl -fsSL --proto '=https,file' --connect-timeout 10 --max-time 300 \
    -o "${tmpdir}/idleleo" "${asset_url}"; then
    echo "download failed; nothing installed" >&2
    exit 1
fi
if ! echo "${asset_sha}  ${tmpdir}/idleleo" | sha256sum -c - >/dev/null 2>&1; then
    echo "sha256 mismatch; nothing installed" >&2
    exit 1
fi
if [[ "$(head -c 4 "${tmpdir}/idleleo" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]]; then
    echo "asset is not an ELF binary; nothing installed" >&2
    exit 1
fi

mkdir -p /opt/idleleo/bin
install -m 0755 "${tmpdir}/idleleo" /opt/idleleo/bin/idleleo
/opt/idleleo/bin/idleleo version >/dev/null

if [[ "${fetch_only}" == "on" ]]; then
    echo "/opt/idleleo/bin/idleleo"
    exit 0
fi

exec /opt/idleleo/bin/idleleo xray install --container "${installer_args[@]}"
