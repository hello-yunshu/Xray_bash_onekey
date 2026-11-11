#!/usr/bin/env bash
# Sign a JSON document with Ed25519 and print it with an embedded signature.
#
# Usage: sign_json_ed25519.sh <input.json> <private-key.pem> [field]
#   field defaults to metadata_signature.
#
# Contract shared with install.sh and internal/release: the signed bytes are
# exactly the output of `jq -cS 'del(.["<field>"])'` with no trailing newline.
# Any change to that canonical form breaks verification, so every signer must
# go through this script.
set -euo pipefail

input=${1:?usage: sign_json_ed25519.sh <input.json> <private-key.pem> [field]}
key=${2:?usage: sign_json_ed25519.sh <input.json> <private-key.pem> [field]}
field=${3:-metadata_signature}

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }
[[ -f ${input} ]] || { echo "missing input: ${input}" >&2; exit 1; }
[[ -f ${key} ]] || { echo "missing private key: ${key}" >&2; exit 1; }

jq -e 'type == "object"' "${input}" >/dev/null 2>&1 || {
    echo "input is not a JSON object: ${input}" >&2
    exit 1
}

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

canonical=$(jq -cS --arg field "${field}" 'del(.[$field])' "${input}")
[[ -n ${canonical} ]] || { echo "canonical document is empty" >&2; exit 1; }
printf '%s' "${canonical}" >"${work}/message"
openssl pkeyutl -sign -inkey "${key}" -rawin -in "${work}/message" -out "${work}/signature"
signature=$(openssl enc -base64 -A -in "${work}/signature")

jq --arg field "${field}" --arg value "ed25519:${signature}" \
    '. + {($field): $value}' "${input}"
