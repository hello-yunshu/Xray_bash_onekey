#!/usr/bin/env bash
# Runs OPS-23 (single-user UUID rotation) in a disposable systemd container.
# Usage: bash tests/e2e-diff/run_c5_uuid.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
# Evidence holds only observable output. The build/seed directory holds the
# idleleo and xray binaries, so it lives outside the repository.
EVID="${E2E_EVID:-$ROOT/tests/e2e-diff/evidence/c5-$RUN_ID}"
WORK="${E2E_WORK:-/tmp/e2e-c5-$RUN_ID}"
GO_IMAGE="${GO_IMAGE:-golang:1.27.4}"
IMAGE_TAG="${IMAGE_TAG:-idleleo-e2e:24.04}"
NAME="c5-uuid-$$"
XRAY_SRC="$ROOT/tests/go-parity/.cache/a2/xray"

mkdir -p "$WORK/seed" "$EVID"
echo "work=$WORK"

docker run --rm -v "$ROOT:/src:ro" -v "$WORK/seed:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
    "$GO_IMAGE" go build -buildvcs=false -trimpath -o /out/idleleo ./cmd/idleleo

if [[ ! -x "$XRAY_SRC" ]]; then
    echo "FATAL: xray binary missing at $XRAY_SRC" >&2
    exit 2
fi
cp "$XRAY_SRC" "$WORK/seed/xray"
chmod 0755 "$WORK/seed/xray"
chmod 0755 "$WORK/seed/idleleo"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock \
    -v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$EVID:/out" \
    "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null

for _ in $(seq 1 30); do
    docker exec "$NAME" systemctl is-system-running 2>/dev/null | grep -Eq 'running|degraded' && break
    sleep 1
done

docker exec "$NAME" bash -c \
    'install -m0755 /seed/xray /usr/local/bin/xray && install -m0755 /seed/idleleo /usr/local/bin/idleleo'

set +e
docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$NAME" bash -c \
    'idleleo xray install --binary /usr/local/bin/xray --mode reality --domain example.com --target example.com:443 --port 443 --container --json' \
    >"$EVID/install.json" 2>"$EVID/install.err"
install_rc=$?
set -e
echo "install_rc=$install_rc"
if [[ $install_rc -ne 0 ]]; then
    tail -20 "$EVID/install.err" || true
    exit 3
fi

set +e
docker exec -e E2E_OUT=/out -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$NAME" \
    bash /src/tests/e2e-diff/drivers/ops23_user_uuid.sh go
driver_rc=$?
set -e
echo "driver_rc=$driver_rc"

REPORT="$EVID/c5-uuid-go/checks.jsonl"
if [[ -f "$REPORT" ]]; then
    total=$(wc -l <"$REPORT" | tr -d ' ')
    failed=$(grep -c '"ok":false' "$REPORT" || true)
    echo "checks=$total failed=$failed"
    grep -o '"name":"[^"]*","ok":[a-z]*' "$REPORT" || true
fi
exit "$driver_rc"
