#!/usr/bin/env bash
# Runs inside the disposable container. Sources the REAL install.sh in
# _TEST_MODE=1 and calls the same functions the Bash install flow calls for
# Reality balance primary/secondary. No interactive wizard, no service edits.
#
# Required env: BAL_ROLE (primary|secondary), BAL_OUT.
# Optional: BAL_PORT, BAL_SERVERNAME, BAL_TARGET, BAL_PRIVATE_KEY, BAL_SHORT_ID,
#           BAL_UUID, BAL_XRAY_BIN.
set -euo pipefail

ROLE="${BAL_ROLE:?BAL_ROLE required}"
OUT="${BAL_OUT:?BAL_OUT required}"
PORT="${BAL_PORT:-8443}"
SERVERNAME="${BAL_SERVERNAME:-www.cloudflare.com}"
TARGET="${BAL_TARGET:-www.cloudflare.com}"
PRIVATE_KEY="${BAL_PRIVATE_KEY:?BAL_PRIVATE_KEY required}"
SHORT_ID="${BAL_SHORT_ID:?BAL_SHORT_ID required}"
UUID_VALUE="${BAL_UUID:?BAL_UUID required}"
XRAY_BIN="${BAL_XRAY_BIN:-/seed/xray}"

mkdir -p "$OUT"
export _TEST_MODE=1 LANG=C.UTF-8 NO_COLOR=1 TERM=dumb
# shellcheck disable=SC1091
source /src/install.sh
# The repo template is loaded through the same download_json_file path the
# real installer uses, but from the local checkout instead of github.
shell_release_raw_base="file:///src"

# Use the same production paths the installer uses. The container is
# disposable, so this keeps the generated include/log paths byte-identical to a
# real deployment (and therefore comparable with the Go artifacts).
idleleo_dir="/etc/idleleo"
idleleo_conf_dir="$idleleo_dir/conf"
xray_conf_dir="$idleleo_conf_dir/xray"
nginx_conf_dir="$idleleo_conf_dir/nginx"
xray_conf="$xray_conf_dir/config.json"
nginx_conf="$nginx_conf_dir/00-xray.conf"
nginx_dir="/usr/local/nginx"
nginx_main_conf="$nginx_dir/conf/nginx.conf"
ssl_chainpath="$idleleo_dir/cert"
mkdir -p "$xray_conf_dir" "$nginx_conf_dir" "$nginx_dir/conf" "$nginx_dir/logs" \
    "$idleleo_dir/info" /var/log/xray

# ---- the variables apply_install_profile / the wizard would have set --------
tls_mode="Reality"
transport_mode="None"
reality_add_more="off"
reality_add_balance="on"
reality_balance_role="$ROLE"
if [[ "$ROLE" == "primary" ]]; then
    reality_add_nginx="on"
    shell_mode="Nginx+Reality+Balance"
else
    reality_add_nginx="off"
    shell_mode="Reality+Balance"
fi
port="$PORT"
xport="None"
gport="None"
xhttpport="None"
target="$TARGET"
serverNames="$SERVERNAME"
privateKey="$PRIVATE_KEY"
shortIds="$SHORT_ID"
UUID="$UUID_VALUE"
custom_email="me@hey.run"
unknown_sni_policy="isolate"
old_config_status="off"
local_ip="127.0.0.1"
save_originconf="No"

# ---- xray_conf_add template branch (Reality) -------------------------------
download_json_file "${shell_release_raw_base}/config/vless_reality.json" "$xray_conf"
modify_target_serverNames
modify_privateKey_shortIds
xray_reality_add_more
modify_email_address
modify_UUID
reality_min_client_ver_repair || true

# ---- nginx_reality_conf_add + fragment writers (primary only) -------------
if [[ "$ROLE" == "primary" ]]; then
    printf 'worker_processes  1;\n\nhttp {\n    include %s/*.conf;\n}\n' \
        "$nginx_conf_dir" >"$nginx_main_conf"
    _cleanup_stale_serverNames_fragments
    nginx_reality_conf_add
    nginx_reality_servers_add
    nginx_reality_serverNames_add
fi

# ---- capture -------------------------------------------------------------
mkdir -p "$OUT/runtime" "$OUT/nginx" "$OUT/fragments"
cp "$xray_conf" "$OUT/runtime/config.json"
chmod 600 "$OUT/runtime/config.json"
jq '(.inbounds[]?.streamSettings.realitySettings.privateKey?) = "REDACTED"
    | (.inbounds[]?.streamSettings.realitySettings.settings?.privateKey?) = "REDACTED"' \
    "$xray_conf" >"$OUT/runtime/config.sanitized.json"
jq -S . "$OUT/runtime/config.sanitized.json" >"$OUT/runtime/config.sorted.json"

if [[ "$ROLE" == "primary" ]]; then
    cp "$nginx_conf" "$OUT/nginx/00-xray.conf"
    cp "$nginx_main_conf" "$OUT/nginx/nginx.conf"
    cp "$idleleo_conf_dir/nginx/03-isolate.conf" "$OUT/fragments/03-isolate.conf"
    cp "$nginx_conf_dir/127.0.0.1.realityServers" "$OUT/fragments/127.0.0.1.realityServers"
    cp "$nginx_conf_dir/${serverNames}.serverNames" "$OUT/fragments/${serverNames}.serverNames"
fi

set +e
"$XRAY_BIN" -test -config "$xray_conf" >"$OUT/xray-test.log" 2>&1
test_rc=$?
set -e
public_key=$("$XRAY_BIN" x25519 -i "$PRIVATE_KEY" 2>/dev/null \
    | sed -n 's/^Password (PublicKey): //p' | awk '{print $1}')
nginx_sha=""
if [[ "$ROLE" == "primary" ]]; then
    nginx_sha=$(sha256sum "$nginx_conf" | awk '{print $1}')
fi

cat >"$OUT/facts.json" <<EOF
{
  "role": "$ROLE",
  "port": $PORT,
  "serverName": "$SERVERNAME",
  "target": "$TARGET:443",
  "uuid": "$UUID_VALUE",
  "publicKey": "$public_key",
  "xrayTestExit": $test_rc,
  "installSourceSha256": "$(sha256sum /src/install.sh | awk '{print $1}')",
  "runtimeSha256": "$(sha256sum "$xray_conf" | awk '{print $1}')",
  "nginxConfSha256": "$nginx_sha"
}
EOF
printf 'bash-generate role=%s xray_test_exit=%s\n' "$ROLE" "$test_rc"
exit "$test_rc"
