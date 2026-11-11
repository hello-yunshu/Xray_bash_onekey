#!/usr/bin/env bash
# S6-3 regression tests: the remote version metadata is the trust root for every
# later download. Each injection below must return nonzero, not merely print an
# error, so a broken verifier cannot silently degrade into "accept everything".
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { printf '%s\n' "$*" >&2; }
gettext() { printf '%s' "$1"; }

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

if ! command -v openssl >/dev/null 2>&1 || ! openssl pkeyutl -help 2>&1 | grep -q -- '-rawin'; then
    echo "SKIP: openssl 3 (pkeyutl -rawin) is required to build the fixtures"
    exit 0
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq is unavailable"
    exit 0
fi

openssl genpkey -algorithm ed25519 -out "${TMP_ROOT}/key.pem" >/dev/null 2>&1
openssl pkey -in "${TMP_ROOT}/key.pem" -pubout -out "${TMP_ROOT}/pub.pem" >/dev/null 2>&1
export XRAY_QUALIFICATION_MODE=1
export IDLELEO_VERSIONS_PUBKEY_FILE="${TMP_ROOT}/pub.pem"

# These cases never touch the network: any curl call fails immediately.
curl() { return 22; }

sha_a='0730ad91000000000000000000000000000000000000000000000000000000aa'
sha_b='0730ad91000000000000000000000000000000000000000000000000000000bb'

unsigned_json() {
    jq -cn --arg sha "${sha_a}" '{
      shell_online_version: "3.3.6",
      shell_tested_version: "3.3.5",
      shell_release_sha256: $sha,
      xray_online_version: "26.3.27",
      xray_installer_ref: "e741a4f56d368afbb9e5be3361b40c4552d3710d",
      xray_installer_sha256: "7f70c95f6b418da8b4f4883343d602964915e28748993870fd554383afdbe555",
      nginx_build_online_version: "2026.06.17.6717"
    }'
}

# Loads one fixture through the production loader and records stderr separately.
load_json() {
    get_versions_all=""
    _get_versions_loaded=0
    XRAY_VERSIONS_FILE="$1" load_versions >/dev/null 2>"${TMP_ROOT}/stderr"
}

unsigned_json >"${TMP_ROOT}/meta.json"
"${REPO_DIR}/scripts/sign_json_ed25519.sh" \
    "${TMP_ROOT}/meta.json" "${TMP_ROOT}/key.pem" >"${TMP_ROOT}/meta.signed.json"

printf '%s\n' '--- valid signature is accepted ---'
if load_json "${TMP_ROOT}/meta.signed.json" &&
    [[ "$(printf '%s' "${get_versions_all}" | jq -r '.shell_online_version')" == "3.3.6" ]] &&
    [[ "$(printf '%s' "${get_versions_all}" | jq -r '.shell_release_sha256')" == "${sha_a}" ]]; then
    ok "signed metadata loads with unchanged field values"
else
    bad "signed metadata was rejected or altered: $(cat "${TMP_ROOT}/stderr")"
fi

printf '%s\n' '--- signature covers every field ---'
jq --arg sha "${sha_b}" '.shell_release_sha256 = $sha' \
    "${TMP_ROOT}/meta.signed.json" >"${TMP_ROOT}/meta.tampered.json"
if load_json "${TMP_ROOT}/meta.tampered.json"; then
    bad "metadata with an edited field but the original signature was accepted"
else
    ok "field tampering after signing is rejected"
fi

printf '%s\n' '--- corrupted signature bytes ---'
sig_b64=$(jq -r '.metadata_signature' "${TMP_ROOT}/meta.signed.json")
printf '%s' "${sig_b64#ed25519:}" | openssl enc -base64 -d -A -out "${TMP_ROOT}/sig.raw"
# Overwrite byte 0 with a value that is guaranteed to differ. Writing a fixed
# 0x00 made this case flaky: when the original byte was already zero the
# signature stayed valid and the test failed roughly once in 256 runs.
orig_byte=$(od -An -tu1 -N1 "${TMP_ROOT}/sig.raw" | tr -d '[:space:]')
if [[ ${orig_byte} -eq 255 ]]; then
    new_byte=0
else
    new_byte=$((orig_byte + 1))
fi
printf "\\$(printf '%03o' "${new_byte}")" |
    dd of="${TMP_ROOT}/sig.raw" bs=1 seek=0 conv=notrunc 2>/dev/null
flipped=$(openssl enc -base64 -A -in "${TMP_ROOT}/sig.raw")
jq --arg s "ed25519:${flipped}" '.metadata_signature = $s' \
    "${TMP_ROOT}/meta.signed.json" >"${TMP_ROOT}/meta.flipped.json"
if load_json "${TMP_ROOT}/meta.flipped.json"; then
    bad "a signature with a flipped byte was accepted"
else
    ok "corrupted signature is rejected"
fi

printf '%s\n' '--- truncated signature ---'
head -c 32 "${TMP_ROOT}/sig.raw" >"${TMP_ROOT}/sig.short"
short=$(openssl enc -base64 -A -in "${TMP_ROOT}/sig.short")
jq --arg s "ed25519:${short}" '.metadata_signature = $s' \
    "${TMP_ROOT}/meta.signed.json" >"${TMP_ROOT}/meta.short.json"
if load_json "${TMP_ROOT}/meta.short.json"; then
    bad "a truncated signature was accepted"
else
    ok "signature that is not 64 bytes is rejected"
fi

printf '%s\n' '--- unsupported algorithm prefix ---'
jq --arg s "rsa:${sig_b64#ed25519:}" '.metadata_signature = $s' \
    "${TMP_ROOT}/meta.signed.json" >"${TMP_ROOT}/meta.rsa.json"
if load_json "${TMP_ROOT}/meta.rsa.json"; then
    bad "a non-ed25519 signature prefix was accepted"
else
    ok "unknown signature algorithm is rejected"
fi

printf '%s\n' '--- compatibility window ---'
saved_shell_version=${shell_version}
shell_version="3.3.6"
if load_json "${TMP_ROOT}/meta.json"; then
    if grep -q '兼容期' "${TMP_ROOT}/stderr"; then
        ok "unsigned metadata below the cutover is accepted with a warning"
    else
        bad "unsigned metadata was accepted without the compatibility warning"
    fi
else
    bad "unsigned metadata below the cutover was rejected"
fi

shell_version="3.5.9"
if load_json "${TMP_ROOT}/meta.json"; then
    if grep -q '兼容期' "${TMP_ROOT}/stderr"; then
        ok "unsigned metadata below the deferred cutover is still accepted with a warning"
    else
        bad "unsigned metadata at 3.5.9 was accepted without the compatibility warning"
    fi
else
    bad "unsigned metadata at 3.5.9 was rejected; the cutover moved backwards"
fi

shell_version="3.6.0"
if load_json "${TMP_ROOT}/meta.json"; then
    bad "unsigned metadata at the cutover version was accepted"
else
    ok "unsigned metadata at 3.6.0 is rejected"
fi
shell_version=${saved_shell_version}

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
