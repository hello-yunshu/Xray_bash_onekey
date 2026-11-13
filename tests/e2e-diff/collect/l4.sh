#!/usr/bin/env bash
# L4 connectivity probe: real client handshake through the installed server.
#
# Runs on the HOST. Derives a client config from the server runtime (inside the
# server container, so secrets never touch the evidence tree), starts a client
# container, and performs one HTTP business request through the proxy.
#
# The request targets http://example.com/ rather than a loopback origin: the
# installed runtime uses a freedom outbound that deliberately blackholes
# private/loopback destinations, so a local origin would always fail.
#
# Usage:
#   l4.sh <server-container> <client-container> <image> <network> \
#         <reality|tls> <domain> <xray-binary> <secret-dir> <evidence-out>
set -uo pipefail

SERVER="$1"
CLIENT="$2"
IMAGE="$3"
NETWORK="$4"
PROFILE="$5"
DOMAIN="$6"
XRAY_BIN="$7"
SECRET_DIR="$8"
OUT="$9"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_URL="${E2E_L4_URL:-http://example.com/}"
MARKER="${E2E_L4_MARKER:-Example Domain}"

mkdir -p "$OUT" "$SECRET_DIR"

fail() {
    printf '%s\n' "$*" | tee -a "$OUT/connectivity.log"
    python3 - "$OUT/connectivity.json" "$PROFILE" "$TARGET_URL" "$*" <<'PY'
import json
import sys
json.dump({'profile': sys.argv[2], 'target': sys.argv[3], 'ok': False, 'reason': sys.argv[4]},
          open(sys.argv[1], 'w'), indent=2, sort_keys=True)
PY
    exit 1
}

server_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SERVER")
[[ -n "$server_ip" ]] || fail "server container has no address"

# Derive the client config inside the server container.
docker exec "$SERVER" python3 /src/tests/e2e-diff/collect/client_config.py \
    --config /etc/idleleo/conf/xray/config.json \
    --mode "$PROFILE" \
    --server-address "$server_ip" \
    --server-port 443 \
    --domain "$DOMAIN" \
    --output /tmp/e2e-client.json >"$OUT/client-config.log" 2>&1 || fail "client config generation failed"
docker cp "$SERVER:/tmp/e2e-client.json" "$SECRET_DIR/client.json" >/dev/null 2>&1 || fail "cannot extract client config"
docker exec "$SERVER" rm -f /tmp/e2e-client.json

docker rm -f "$CLIENT" >/dev/null 2>&1 || true
docker run -d --name "$CLIENT" --network "$NETWORK" --label e2e.side=client \
    -v "$SECRET_DIR:/client" -v "$XRAY_BIN:/opt/xray/xray:ro" \
    --entrypoint sleep "$IMAGE" infinity >/dev/null || fail "cannot start client container"

docker cp "$SECRET_DIR/client.json" "$CLIENT:/client/client.json" >/dev/null 2>&1 || fail "cannot place client config"
docker exec -d "$CLIENT" sh -c '/opt/xray/xray run -c /client/client.json >/client/client.log 2>&1' || fail "cannot start client xray"
sleep 2
docker exec "$CLIENT" sh -c 'ss -lnt | grep -q 127.0.0.1:1080' || fail "client socks did not listen"

body=""
rc=1
for _ in $(seq 1 20); do
    set +e
    body=$(docker exec "$CLIENT" curl -sS --max-time 10 --socks5-hostname 127.0.0.1:1080 "$TARGET_URL" 2>"$OUT/curl.err")
    rc=$?
    set -e
    [[ $rc -eq 0 && "$body" == *"$MARKER"* ]] && break
    sleep 1
done

docker cp "$CLIENT:/client/client.log" "$OUT/client.log" >/dev/null 2>&1 || true
docker cp "$CLIENT:/client/curl.err" "$OUT/curl.err" >/dev/null 2>&1 || true

ok=false
[[ $rc -eq 0 && "$body" == *"$MARKER"* ]] && ok=true

python3 - "$OUT/connectivity.json" "$PROFILE" "$TARGET_URL" "$ok" "$rc" "$body" <<'PY'
import hashlib
import json
import sys

out, profile, target, ok, rc, body = sys.argv[1:7]
json.dump({
    'profile': profile,
    'target': target,
    'ok': ok == 'true',
    'curlExit': int(rc),
    'bodySha256': hashlib.sha256(body.encode()).hexdigest(),
    'bodyMatch': 'Example Domain' in body,
}, open(out, 'w'), indent=2, sort_keys=True)
PY

[[ "$ok" == true ]] || fail "business request failed (curl exit $rc, body bytes ${#body})"
echo "L4 ok ($PROFILE)"
