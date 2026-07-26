#!/usr/bin/env bash
# Test suite for redaction helpers (Task H / Section 14.2 item 13).
# Verifies that fake UUID/privateKey/shortIds/password/share-link/token
# do NOT appear in redacted JSON or text output.
#
# Run: bash .github/test/test_redact.sh

set -u

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=redact.sh
source "${TEST_DIR}/redact.sh"

PASS=0
FAIL=0

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if printf '%s' "${haystack}" | grep -qF "${needle}"; then
        echo "  PASS: ${desc} (contains expected '${needle}')"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${desc} (expected to contain '${needle}')"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if printf '%s' "${haystack}" | grep -qF "${needle}"; then
        echo "  FAIL: ${desc} (must NOT contain '${needle}' but does)"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: ${desc} (does not contain '${needle}')"
        PASS=$((PASS + 1))
    fi
}

# Fake sensitive values (never real secrets)
FAKE_UUID="f4k3-uu1d-0000-aaaa-bbbbccccdddd"
FAKE_PRIVATE_KEY="FAKE_PRIV_KEY_abc123xyz789"
FAKE_PUBLIC_KEY="FAKE_PUB_KEY_def456uvw012"
FAKE_PASSWORD="FAKE_PASS_word098"
FAKE_SHORT_IDS="0123456789abcdef"
FAKE_HOST="fake.host.example.com"
FAKE_DOMAIN="fake.domain.example.com"
FAKE_EMAIL="fake@example.com"
FAKE_TOKEN="ghp_FAKEtoken00000000000000000000000000aa"
FAKE_SHARE_LINK="vless://${FAKE_UUID}@${FAKE_HOST}:443?path=%2Fciws&type=ws&security=reality&pbk=${FAKE_PUBLIC_KEY}&spx=%2F&sid=${FAKE_SHORT_IDS}#${FAKE_HOST}"

echo "============================================"
echo "  Testing redaction helpers"
echo "============================================"
echo ""

echo "--- Test: redact_json_for_diagnostics ---"
# Build a JSON document with sensitive fields at various nesting levels
JSON_INPUT=$(cat <<EOF
{
  "UUID": "${FAKE_UUID}",
  "privateKey": "${FAKE_PRIVATE_KEY}",
  "publicKey": "${FAKE_PUBLIC_KEY}",
  "password": "${FAKE_PASSWORD}",
  "shortIds": "${FAKE_SHORT_IDS}",
  "host": "${FAKE_HOST}",
  "domain": "${FAKE_DOMAIN}",
  "email": "${FAKE_EMAIL}",
  "shell_mode": "XTLS ONLY",
  "shell_version": "3.0.1",
  "nested": {
    "uuid": "${FAKE_UUID}",
    "id": "${FAKE_UUID}",
    "target": "${FAKE_HOST}",
    "serverNames": "${FAKE_HOST}",
    "decoy_domain": "${FAKE_DOMAIN}"
  },
  "inbounds": [
    {
      "tag": "VLESS-Reality-in",
      "settings": {
        "privateKey": "${FAKE_PRIVATE_KEY}",
        "shortIds": ["${FAKE_SHORT_IDS}"]
      }
    }
  ]
}
EOF
)

REDACTED_JSON=$(printf '%s' "${JSON_INPUT}" | redact_json_for_diagnostics)

# Sensitive values must not appear
assert_not_contains "JSON: UUID redacted" "${REDACTED_JSON}" "${FAKE_UUID}"
assert_not_contains "JSON: privateKey redacted" "${REDACTED_JSON}" "${FAKE_PRIVATE_KEY}"
assert_not_contains "JSON: publicKey redacted" "${REDACTED_JSON}" "${FAKE_PUBLIC_KEY}"
assert_not_contains "JSON: password redacted" "${REDACTED_JSON}" "${FAKE_PASSWORD}"
assert_not_contains "JSON: shortIds redacted" "${REDACTED_JSON}" "${FAKE_SHORT_IDS}"
assert_not_contains "JSON: host redacted" "${REDACTED_JSON}" "${FAKE_HOST}"
assert_not_contains "JSON: domain redacted" "${REDACTED_JSON}" "${FAKE_DOMAIN}"
assert_not_contains "JSON: email redacted" "${REDACTED_JSON}" "${FAKE_EMAIL}"
assert_not_contains "JSON: nested uuid redacted" "${REDACTED_JSON}" "${FAKE_UUID}"
assert_not_contains "JSON: nested privateKey in array redacted" "${REDACTED_JSON}" "${FAKE_PRIVATE_KEY}"

# Non-sensitive values must still be visible
assert_contains "JSON: shell_mode visible" "${REDACTED_JSON}" "XTLS ONLY"
assert_contains "JSON: shell_version visible" "${REDACTED_JSON}" "3.0.1"
assert_contains "JSON: tag visible" "${REDACTED_JSON}" "VLESS-Reality-in"

echo ""
echo "--- Test: redact_text_for_diagnostics ---"
TEXT_INPUT=$(cat <<EOF
[INFO] Starting xray with UUID: ${FAKE_UUID}
[DEBUG] privateKey=${FAKE_PRIVATE_KEY} publicKey=${FAKE_PUBLIC_KEY}
[DEBUG] password=${FAKE_PASSWORD} shortIds=${FAKE_SHORT_IDS}
[INFO] Connecting to host=${FAKE_HOST} domain=${FAKE_DOMAIN}
[INFO] Share link: ${FAKE_SHARE_LINK}
[INFO] Token: ${FAKE_TOKEN}
[INFO] User email=${FAKE_EMAIL} connected
EOF
)

REDACTED_TEXT=$(printf '%s' "${TEXT_INPUT}" | redact_text_for_diagnostics)

assert_not_contains "Text: UUID redacted" "${REDACTED_TEXT}" "${FAKE_UUID}"
assert_not_contains "Text: privateKey redacted" "${REDACTED_TEXT}" "${FAKE_PRIVATE_KEY}"
assert_not_contains "Text: publicKey redacted" "${REDACTED_TEXT}" "${FAKE_PUBLIC_KEY}"
assert_not_contains "Text: password redacted" "${REDACTED_TEXT}" "${FAKE_PASSWORD}"
assert_not_contains "Text: shortIds redacted" "${REDACTED_TEXT}" "${FAKE_SHORT_IDS}"
assert_not_contains "Text: host redacted" "${REDACTED_TEXT}" "${FAKE_HOST}"
assert_not_contains "Text: domain redacted" "${REDACTED_TEXT}" "${FAKE_DOMAIN}"
assert_not_contains "Text: share link redacted" "${REDACTED_TEXT}" "${FAKE_SHARE_LINK}"
assert_not_contains "Text: token redacted" "${REDACTED_TEXT}" "${FAKE_TOKEN}"
assert_not_contains "Text: email redacted" "${REDACTED_TEXT}" "${FAKE_EMAIL}"

# Non-sensitive context must still be visible
assert_contains "Text: INFO lines visible" "${REDACTED_TEXT}" "Starting xray"
assert_contains "Text: connection context visible" "${REDACTED_TEXT}" "Connecting to"
assert_contains "Text: user context visible" "${REDACTED_TEXT}" "connected"

echo ""
echo "--- Test: safe_print_config_summary ---"
# Create a temporary config file
TMP_CONFIG=$(mktemp)
cat > "${TMP_CONFIG}" <<EOF
{
  "shell_mode": "ws+gRPC+xHTTP ONLY",
  "transport_mode": "wsgRPCxhttp",
  "shell_version": "3.0.1",
  "xray_version": "25.12.8",
  "nginx_build_version": "2025.12.23",
  "UUID": "${FAKE_UUID}",
  "privateKey": "${FAKE_PRIVATE_KEY}",
  "publicKey": "${FAKE_PUBLIC_KEY}",
  "password": "${FAKE_PASSWORD}",
  "shortIds": "${FAKE_SHORT_IDS}",
  "host": "${FAKE_HOST}",
  "email": "${FAKE_EMAIL}"
}
EOF

SUMMARY=$(safe_print_config_summary "${TMP_CONFIG}")

assert_contains "Summary: mode visible" "${SUMMARY}" "ws+gRPC+xHTTP ONLY"
assert_contains "Summary: shell_version visible" "${SUMMARY}" "3.0.1"
assert_contains "Summary: xray_version visible" "${SUMMARY}" "25.12.8"
assert_contains "Summary: has_UUID true" "${SUMMARY}" "true"
assert_contains "Summary: has_privateKey true" "${SUMMARY}" "true"
assert_not_contains "Summary: UUID value redacted" "${SUMMARY}" "${FAKE_UUID}"
assert_not_contains "Summary: privateKey value redacted" "${SUMMARY}" "${FAKE_PRIVATE_KEY}"
assert_not_contains "Summary: host value redacted" "${SUMMARY}" "${FAKE_HOST}"

rm -f "${TMP_CONFIG}"

echo ""
echo "--- Test: empty/invalid input handling ---"
# Empty JSON should not crash
EMPTY_RESULT=$(echo '{}' | redact_json_for_diagnostics 2>/dev/null) && {
    assert_contains "Empty JSON: produces valid output" "${EMPTY_RESULT}" "{}"
} || {
    echo "  FAIL: Empty JSON should not crash"
    FAIL=$((FAIL + 1))
}

# Non-existent file should return failure
if redact_json_for_diagnostics "/nonexistent/file/path.json" 2>/dev/null; then
    echo "  FAIL: Non-existent file should return failure"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: Non-existent file returns failure"
    PASS=$((PASS + 1))
fi

# safe_print_config_summary on non-existent file
NOT_FOUND_SUMMARY=$(safe_print_config_summary "/nonexistent/file.json")
assert_contains "Summary: non-existent file returns not found" "${NOT_FOUND_SUMMARY}" "(not found)"

echo ""
echo "============================================"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "============================================"

if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
