#!/usr/bin/env bash
# Host launcher for A2: run the REAL interactive Bash install in a disposable
# systemd container and capture the runtime config it deploys.
#
# Usage: bash tests/go-parity/a2/run_bash_real_install_container.sh reality raw
#        bash tests/go-parity/a2/run_bash_real_install_container.sh none ws+grpc+xhttp
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MODE="${1:-none}"
TRANSPORT="${2:-ws}"
EVIDENCE="${A2_EVIDENCE:-$ROOT/tests/go-parity/evidence/a2-2026-11-08}"
IMAGE="${A2_IMAGE:-idleleo-a2-bash:24.04}"
OUT="$EVIDENCE/${MODE}-${TRANSPORT//+/_}"
NAME="idleleo-a2-$$"

[[ "$MODE" == reality || "$MODE" == none ]] || {
    echo "mode must be reality or none (TLS needs a real ACME domain)" >&2
    exit 2
}
mkdir -p "$OUT"

echo "== building $IMAGE =="
docker build --pull=false -q -t "$IMAGE" -f "$ROOT/tests/go-parity/a2/Dockerfile" "$ROOT/tests/go-parity/a2" >/dev/null
IMAGE_ID=$(docker image inspect "$IMAGE" --format '{{.Id}}')
echo "image=$IMAGE image-id=$IMAGE_ID"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== starting disposable privileged systemd container =="
CACHE="$ROOT/tests/go-parity/.cache/a2"
mkdir -p "$CACHE"
docker run -d --name "$NAME" \
    --privileged --cgroupns=host \
    -v "$ROOT:/src:ro" \
    -v "$OUT:/out:rw" \
    -v "$CACHE:/seed:ro" \
    -e "A2_IMAGE_ID=$IMAGE_ID" \
    -e "LANG=C.UTF-8" -e "NO_COLOR=1" -e "TERM=dumb" \
    "$IMAGE" >/dev/null

for _ in $(seq 1 40); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    [[ "$state" == running || "$state" == degraded ]] && break
    sleep 1
done
echo "systemd=${state:-not-ready}"
[[ "$state" == running || "$state" == degraded ]] || {
    docker logs "$NAME" | tail -20 >&2
    exit 1
}

set +e
docker exec \
    -e LANG=C.UTF-8 -e NO_COLOR=1 -e TERM=dumb \
    -e A2_OUT=/out \
    -e A2_MODE="$MODE" \
    -e A2_TRANSPORT="$TRANSPORT" \
    -e A2_TARGET="${A2_TARGET:-www.cloudflare.com}" \
    -e A2_ADD_MORE="${A2_ADD_MORE:-n}" \
    -e A2_PORT_ANSWER="${A2_PORT_ANSWER:-}" \
    "$NAME" bash /src/tests/go-parity/a2/run_bash_real_install.sh
rc=$?
set -e
if [[ ! -f "$CACHE/xray" ]]; then
    docker cp "$NAME:/usr/local/bin/xray" "$CACHE/xray.tmp" >/dev/null 2>&1 \
        && chmod 0755 "$CACHE/xray.tmp" && mv "$CACHE/xray.tmp" "$CACHE/xray" || true
fi
echo "a2-install-exit=$rc"
exit "$rc"
