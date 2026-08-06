#!/usr/bin/env bash
set -euo pipefail
EXPECTED_SHA256=972da1a94a7666f18811089298d22742bf3859f2796351fc21721c75929eae36
RAW_BASE=${RILL_XRAY_AGENT_RAW_BASE:-https://raw.githubusercontent.com/hello-yunshu/rill-xray-agent/main/integrations/xray_bash_onekey}
TMP=$(mktemp -d /tmp/rill-xray-agent.XXXXXX)
trap 'rm -rf "$TMP"' EXIT
BUNDLE=${RILL_XRAY_AGENT_BUNDLE_FILE:-$TMP/bundle.tar.gz}
if [[ ! -f "$BUNDLE" ]]; then
    curl -fsSL --connect-timeout 10 --max-time 120 --retry 2 \
      "$RAW_BASE/assets/rill-xray-agent-xray-bundle.tar.gz" -o "$BUNDLE"
fi
actual=$(sha256sum "$BUNDLE" | awk '{print $1}')
[[ "$actual" == "$EXPECTED_SHA256" ]] || { echo 'bundle SHA-256 mismatch' >&2; exit 65; }
mkdir "$TMP/tree"
tar -xzf "$BUNDLE" -C "$TMP/tree" --no-same-owner --no-same-permissions
for path in "$TMP/tree"/*; do
    case "$(basename "$path")" in scripts|systemd|rill_payload) ;; *) exit 65 ;; esac
done
bash "$TMP/tree/scripts/rill_xray_agent_install.sh"
