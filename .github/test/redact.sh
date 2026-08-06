#!/usr/bin/env bash
# Unified redaction helpers for CI diagnostics and logs.
# Prevent UUID/privateKey/password/shortIds/share-links from leaking
# into CI output, artifacts, and diagnostic bundles.
#
# Usage:
#   source .github/test/redact.sh
#   redact_json_for_diagnostics /etc/idleleo/conf/install_config.json
#   redact_text_for_diagnostics /etc/idleleo/logs/install.log
#   safe_print_config_summary /etc/idleleo/conf/install_config.json

# Recursively redact sensitive fields in a JSON document.
# Reads from file (arg 1) or stdin, writes redacted JSON to stdout.
# Replaces values of known sensitive keys with "***", preserving structure.
redact_json_for_diagnostics() {
    local input
    if [[ $# -ge 1 && -n "$1" ]]; then
        input=$(cat "$1" 2>/dev/null) || return 1
    else
        input=$(cat)
    fi
    printf '%s' "$input" | jq '
        walk(
            if type == "object" then
                (if has("privateKey") then .privateKey = "***" else . end)
                | (if has("publicKey") then .publicKey = "***" else . end)
                | (if has("password") then .password = "***" else . end)
                | (if has("shortIds") then .shortIds = "***" else . end)
                | (if has("UUID") then .UUID = "***" else . end)
                | (if has("uuid") then .uuid = "***" else . end)
                | (if has("id") then .id = "***" else . end)
                | (if has("host") then .host = "***" else . end)
                | (if has("email") then .email = "***" else . end)
                | (if has("domain") then .domain = "***" else . end)
                | (if has("decoy_domain") then .decoy_domain = "***" else . end)
                | (if has("serverNames") then .serverNames = "***" else . end)
                | (if has("target") then .target = "***" else . end)
            else . end
        )
    ' 2>/dev/null || printf '%s\n' "*** JSON redaction failed, content suppressed for safety ***"
}

# Redact sensitive patterns from free-form text (log files, journalctl output).
# Reads from file (arg 1) or stdin, writes redacted text to stdout.
# Removes vless:// share links and key=value patterns for known sensitive keys.
redact_text_for_diagnostics() {
    local input
    if [[ $# -ge 1 && -n "$1" ]]; then
        input=$(cat "$1" 2>/dev/null) || return 1
    else
        input=$(cat)
    fi
    printf '%s' "$input" \
        | sed -E 's/vless:\/\/[A-Za-z0-9:@._-]+@[A-Za-z0-9.:]+[^ ]*/<vless link redacted>/g' \
        | sed -E 's/(privateKey[":= ]+)[A-Za-z0-9_-]+/\1<redacted>/gI' \
        | sed -E 's/(publicKey[":= ]+)[A-Za-z0-9_-]+/\1<redacted>/gI' \
        | sed -E 's/(password[":= ]+)[A-Za-z0-9_-]+/\1<redacted>/gI' \
        | sed -E 's/(shortIds?[":= ]+)[A-Za-z0-9_-]+/\1<redacted>/gI' \
        | sed -E 's/(UUID[":= ]+)[A-Za-z0-9-]+/\1<redacted>/gI' \
        | sed -E 's/(host[":= ]+)[A-Za-z0-9._-]+/\1<redacted>/gI' \
        | sed -E 's/(domain[":= ]+)[A-Za-z0-9._-]+/\1<redacted>/gI' \
        | sed -E 's/(decoy_domain[":= ]+)[A-Za-z0-9._-]+/\1<redacted>/gI' \
        | sed -E 's/(email[":= ]+)[A-Za-z0-9._@-]+/\1<redacted>/gI' \
        | sed -E 's/ghp_[A-Za-z0-9]{36,}/<github_token redacted>/g' \
        | sed -E 's/(token[":= ]+)[A-Za-z0-9_-]+/\1<redacted>/gI' \
        | sed -E 's/(Authorization[: ]+)[A-Za-z0-9._-]+/\1<redacted>/gI' \
        2>/dev/null || printf '%s\n' "*** text redaction failed, content suppressed for safety ***"
}

# Print a safe one-line summary of a config file (no sensitive values).
# Shows only mode, versions, and field-presence booleans.
safe_print_config_summary() {
    local file="$1"
    [[ -f "$file" ]] || { echo "(not found)"; return 0; }
    jq -r '
        "mode: \(.shell_mode // .mode // "unknown")",
        "transport_mode: \(.transport_mode // "unknown")",
        "shell_version: \(.shell_version // "unknown")",
        "xray_version: \(.xray_version // "unknown")",
        "nginx_build_version: \(.nginx_build_version // "unknown")",
        "has_UUID: \(.UUID // .uuid | type == "string")",
        "has_privateKey: \(.privateKey | type == "string")",
        "has_publicKey: \(.publicKey // .password | type == "string")",
        "has_shortIds: \(.shortIds | type == "string")",
        "has_host: \(.host | type == "string")",
        "has_email: \(.email | type == "string")"
    ' "$file" 2>/dev/null || echo "(failed to parse JSON)"
}
