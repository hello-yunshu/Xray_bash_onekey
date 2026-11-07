#!/usr/bin/env bash
# Host launcher for the Phase 02 container E2E.
# Records the exact image digests, mounts and commands in the report.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GO="${GO:-go}"
if [[ ! -x "$(command -v "$GO" 2>/dev/null || true)" ]]; then
    GO=/tmp/gotoolchain/go/bin/go
fi
XRAY_BIN="${IDLELEO_XRAY_BIN:-/tmp/xray-26/xray}"
IMAGE="${IDLELEO_PHASE02_IMAGE:-idleleo-phase02-test:24.04}"
NGINX_IMAGE="${IDLELEO_NGINX_IMAGE:-nginx:1.27}"
BIN_OUT="${IDLELEO_BIN_OUT:-/tmp/idleleo-linux}"
NAME="idleleo-phase02-e2e-$$"
ORIGIN="idleleo-phase02-origin-$$"
NET="idleleo-phase02-net-$$"
WORK="$(mktemp -d /tmp/idleleo-p02-origin.XXXXXX)"

for f in "$XRAY_BIN" "$ROOT/tests/go-parity/phase02/Dockerfile"; do
    [[ -f "$f" ]] || { echo "missing $f" >&2; exit 2; }
done

echo "== building phase02 image =="
docker build -t "$IMAGE" -f "$ROOT/tests/go-parity/phase02/Dockerfile" "$ROOT/tests/go-parity/phase02"
IMAGE_ID=$(docker image inspect "$IMAGE" --format '{{.Id}}')
echo "image: $IMAGE"
echo "image-id: $IMAGE_ID"
echo "xray-bin: $XRAY_BIN sha256=$(sha256sum "$XRAY_BIN" | cut -d' ' -f1)"

echo "== building linux/arm64 idleleo =="
(cd "$ROOT" && GOOS=linux GOARCH=arm64 "$GO" build -o "$BIN_OUT" ./cmd/idleleo)

cleanup() {
    docker rm -f "$NAME" "$ORIGIN" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "== starting local HTTPS/2 GeoData origin =="
# A real geoip.dat is served locally: the generated routing rules include one
# geoip matcher, so a synthetic file would fail the post-download reload.
GEO_SRC="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
GEO_CACHE="${IDLELEO_GEO_CACHE:-/tmp/geoip-host.dat}"
if [[ -f "$GEO_CACHE" ]] && [[ "$(stat -f %z "$GEO_CACHE" 2>/dev/null || stat -c %s "$GEO_CACHE" 2>/dev/null || echo 0)" -gt 1000000 ]]; then
    cp "$GEO_CACHE" "$WORK/geoip.dat"
else
    for _ in 1 2 3 4; do
        docker run --rm -v "$WORK:/w" "$IMAGE" curl -fsSL -C - --retry 3 --retry-all-errors \
            --max-time 240 -o /w/geoip.dat "$GEO_SRC" || true
        ORIGIN_SIZE=$(stat -c %s "$WORK/geoip.dat" 2>/dev/null || stat -f %z "$WORK/geoip.dat" 2>/dev/null || echo 0)
        [[ "$ORIGIN_SIZE" -gt 1000000 ]] && break
    done
fi
ORIGIN_SIZE=$(stat -c %s "$WORK/geoip.dat" 2>/dev/null || stat -f %z "$WORK/geoip.dat")
[[ "$ORIGIN_SIZE" -gt 1000000 ]] || { echo "geoip.dat download failed" >&2; exit 1; }
docker run --rm -v "$WORK:/w" "$NGINX_IMAGE" sh -c '
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj /CN=geo-origin \
    -addext "subjectAltName=DNS:geo-origin" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -keyout /w/geo.key -out /w/geo.crt >/dev/null 2>&1
'
cat >"$WORK/nginx.conf" <<'EOF'
events {}
http {
    server {
        listen 443 ssl;
        http2 on;
        server_name geo-origin;
        ssl_certificate /w/geo.crt;
        ssl_certificate_key /w/geo.key;
        root /w;
        location = /geoip.dat { default_type application/octet-stream; }
    }
}
EOF
docker network create "$NET" >/dev/null
docker run -d --name "$ORIGIN" --network "$NET" --network-alias geo-origin \
    -v "$WORK:/w:ro" "$NGINX_IMAGE" nginx -c /w/nginx.conf -g 'daemon off;' >/dev/null
echo "origin: $ORIGIN ($NGINX_IMAGE) asset=$WORK/geoip.dat bytes=$ORIGIN_SIZE"

echo "== starting privileged systemd probe =="
docker run -d --name "$NAME" \
    --privileged --cgroupns=host --network "$NET" \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$BIN_OUT:/bin/idleleo:ro" \
    -v "$XRAY_BIN:/opt/xray/xray:ro" \
    -v "$WORK/geo.crt:/usr/local/share/ca-certificates/geo-origin.crt:ro" \
    -v "$ROOT/tests/go-parity/phase02/run_phase02.sh:/phase02/run_phase02.sh:ro" \
    "$IMAGE" >/dev/null

for i in $(seq 1 40); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    [[ "$state" == "running" || "$state" == "degraded" ]] && break
    sleep 1
done
echo "systemd: ${state:-not-ready}"
if [[ "$state" != "running" && "$state" != "degraded" ]]; then
    echo "systemd did not start" >&2
    docker logs "$NAME" | tail -20 >&2
    exit 1
fi

echo "== running Phase 02 E2E =="
set +e
docker exec -e GEO_ORIGIN_BYTES="$ORIGIN_SIZE" "$NAME" bash /phase02/run_phase02.sh
rc=$?
set -e
echo "phase02-exit=$rc"
exit "$rc"
