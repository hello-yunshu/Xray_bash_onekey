#!/usr/bin/env bash
# Fail-closed preflight for the Go release manifest that is about to be published.
#
# Usage: preflight_manifest_signature.sh <manifest.json> <signature.go>
#
# The trust anchor is read from internal/release/signature.go, so the publisher
# cannot drift from the verifier. Signing with a key that does not pair with
# that anchor would otherwise produce a release every client refuses at update
# time; this script turns that into a failed publish instead.
set -euo pipefail

json=${1:?usage: preflight_manifest_signature.sh <manifest.json> <signature.go>}
signature_go=${2:?usage: preflight_manifest_signature.sh <manifest.json> <signature.go>}

[[ -f ${json} ]] || { echo "preflight: missing manifest: ${json}" >&2; exit 1; }
[[ -f ${signature_go} ]] || { echo "preflight: missing verifier source: ${signature_go}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "preflight: jq is required" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "preflight: openssl is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "preflight: python3 is required" >&2; exit 1; }

signature=$(jq -r '.signature // empty' "${json}")
[[ -n ${signature} ]] || { echo "preflight: manifest has no signature" >&2; exit 1; }
[[ ${signature} == ed25519:* ]] || {
    echo "preflight: manifest signature must start with ed25519:" >&2
    exit 1
}

openssl pkeyutl -help 2>&1 | grep -q -- '-rawin' || {
    echo "preflight: openssl 3 (pkeyutl -rawin) is required" >&2
    exit 1
}

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

# Same canonical form internal/release signs: object without the signature
# member, keys sorted, no trailing newline.
printf '%s' "$(jq -cS 'del(.signature)' "${json}")" >"${work}/message"
printf '%s' "${signature#ed25519:}" | openssl enc -base64 -d -A -out "${work}/signature" 2>/dev/null || {
    echo "preflight: manifest signature is not valid base64" >&2
    exit 1
}
[[ $(wc -c <"${work}/signature" | tr -d '[:space:]') == "64" ]] || {
    echo "preflight: manifest signature is not 64 bytes" >&2
    exit 1
}

python3 - "${signature_go}" >"${work}/pub.pem" <<'PY'
import re, sys

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"releasePublicKeyPEM = `(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)`",
    text,
    re.S,
)
if not match:
    sys.exit("preflight: releasePublicKeyPEM not found in signature.go")
print(match.group(1))
PY

openssl pkeyutl -verify -pubin -inkey "${work}/pub.pem" -rawin \
    -in "${work}/message" -sigfile "${work}/signature" >/dev/null 2>&1 || {
    echo "preflight: manifest signature does not verify against the signature.go trust anchor" >&2
    exit 1
}

echo "preflight: manifest carries a valid ed25519 signature"
