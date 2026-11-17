#!/usr/bin/env bash
# Fail-closed preflight for the version metadata that is about to be published.
#
# Usage: preflight_versions_signature.sh <versions.json> <install.sh>
#
# The cutover version and the trust anchor are read from install.sh, so the
# publisher cannot drift from the verifier. Below the cutover the metadata may
# stay unsigned (compatibility window); at or above it the JSON must carry an
# `ed25519:` signature that verifies against the embedded public key.
set -euo pipefail

json=${1:?usage: preflight_versions_signature.sh <versions.json> <install.sh>}
install_sh=${2:?usage: preflight_versions_signature.sh <versions.json> <install.sh>}

[[ -f ${json} ]] || { echo "preflight: missing metadata: ${json}" >&2; exit 1; }
[[ -f ${install_sh} ]] || { echo "preflight: missing installer: ${install_sh}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "preflight: jq is required" >&2; exit 1; }

cutover=$(sed -n 's/^versions_signature_required_from="\([0-9][0-9.]*\)"$/\1/p' "${install_sh}")
[[ -n ${cutover} ]] || {
    echo "preflight: versions_signature_required_from not found in ${install_sh}" >&2
    exit 1
}

version=$(jq -r '.shell_online_version // empty' "${json}")
[[ -n ${version} ]] || { echo "preflight: shell_online_version missing in ${json}" >&2; exit 1; }

# Prints -1/0/1; returns 2 when either side is not numeric-dotted.
#
# This must mirror install.sh::version_compare exactly. `sort -V` is not a
# substitute: it ranks 3.6 below 3.6.0 and 3.06.0 below 3.6.0, while install.sh
# pads the missing components with zero and parses `10#`, so both are equal to
# the cutover. A publisher that disagreed with the client here would happily
# publish unsigned metadata that every 3.6.0 client rejects.
version_compare() {
    local a="${1#v}" b="${2#v}"
    [[ ${a} =~ ^[0-9]+(\.[0-9]+)*$ && ${b} =~ ^[0-9]+(\.[0-9]+)*$ ]] || return 2
    local i n x y
    local -a av bv
    IFS='.' read -r -a av <<<"${a}"
    IFS='.' read -r -a bv <<<"${b}"
    n=${#av[@]}
    ((${#bv[@]} > n)) && n=${#bv[@]}
    for ((i = 0; i < n; i++)); do
        x=$((10#${av[i]:-0}))
        y=$((10#${bv[i]:-0}))
        if ((x > y)); then
            printf '1\n'
            return 0
        fi
        if ((x < y)); then
            printf -- '-1\n'
            return 0
        fi
    done
    printf '0\n'
}

if ! ordering=$(version_compare "${version}" "${cutover}"); then
    echo "preflight: shell_online_version '${version}' is not a numeric dotted version" >&2
    exit 1
fi

if [[ ${ordering} == "-1" ]]; then
    echo "preflight: shell ${version} is below the ${cutover} cutover; unsigned metadata is allowed"
    exit 0
fi

signature=$(jq -r '.metadata_signature // empty' "${json}")
[[ -n ${signature} ]] || {
    echo "preflight: shell ${version} >= ${cutover} but metadata_signature is missing" >&2
    exit 1
}
[[ ${signature} == ed25519:* ]] || {
    echo "preflight: metadata_signature must start with ed25519:" >&2
    exit 1
}

command -v openssl >/dev/null 2>&1 || { echo "preflight: openssl is required" >&2; exit 1; }
openssl pkeyutl -help 2>&1 | grep -q -- '-rawin' || {
    echo "preflight: openssl 3 (pkeyutl -rawin) is required" >&2
    exit 1
}

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

printf '%s' "$(jq -cS 'del(.metadata_signature)' "${json}")" >"${work}/message"
printf '%s' "${signature#ed25519:}" | openssl enc -base64 -d -A -out "${work}/signature" 2>/dev/null || {
    echo "preflight: metadata_signature is not valid base64" >&2
    exit 1
}
[[ $(wc -c <"${work}/signature" | tr -d '[:space:]') == "64" ]] || {
    echo "preflight: metadata_signature is not 64 bytes" >&2
    exit 1
}

python3 - "${install_sh}" >"${work}/pub.pem" <<'PY'
import re, sys

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"shell_versions_pubkey_pem='(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)'",
    text,
    re.S,
)
if not match:
    sys.exit("preflight: trust anchor shell_versions_pubkey_pem not found in install.sh")
print(match.group(1))
PY

openssl pkeyutl -verify -pubin -inkey "${work}/pub.pem" -rawin \
    -in "${work}/message" -sigfile "${work}/signature" >/dev/null 2>&1 || {
    echo "preflight: metadata_signature does not verify against the install.sh trust anchor" >&2
    exit 1
}

echo "preflight: shell ${version} carries a valid ed25519 metadata_signature"
