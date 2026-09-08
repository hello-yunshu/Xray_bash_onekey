#!/usr/bin/env bash
set -euo pipefail
TMP=$(mktemp -d /tmp/rill-xray-agent.XXXXXX)
trap 'rm -rf "$TMP"' EXIT
EXPECTED_SHA256=${RILL_XRAY_AGENT_BUNDLE_SHA256:-}
BUNDLE=${RILL_XRAY_AGENT_BUNDLE_FILE:-}
if [[ -z "$BUNDLE" && -n "${RILL_XRAY_AGENT_BUNDLE_URL:-}" ]]; then
    BUNDLE="$TMP/bundle.tar.gz"
    curl -fsSL --connect-timeout 10 --max-time 120 --retry 2 \
      "$RILL_XRAY_AGENT_BUNDLE_URL" -o "$BUNDLE"
fi
[[ -n "$BUNDLE" && -f "$BUNDLE" ]] || { echo 'Rill bundle 未明确指定（需要 RILL_XRAY_AGENT_BUNDLE_FILE 或 RILL_XRAY_AGENT_BUNDLE_URL）' >&2; exit 64; }
[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo 'Rill bundle SHA-256 未明确指定' >&2; exit 64; }
actual=$(sha256sum "$BUNDLE" | awk '{print $1}')
[[ "$actual" == "$EXPECTED_SHA256" ]] || { echo 'Rill 安装包 SHA-256 校验不匹配' >&2; exit 65; }
mkdir "$TMP/tree"
tar -xzf "$BUNDLE" -C "$TMP/tree" --no-same-owner --no-same-permissions
for path in "$TMP/tree"/*; do
    case "$(basename "$path")" in scripts|systemd|rill_payload) ;; *) exit 65 ;; esac
done
bash "$TMP/tree/scripts/rill_xray_agent_install.sh" "$@"
