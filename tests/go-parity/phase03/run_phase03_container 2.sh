#!/usr/bin/env bash
# Host launcher for the Phase 03 Bridge container E2E. It pins and prints the
# exact image and binary digests that the report cites.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../lib/docker_common.sh
. "$ROOT/tests/go-parity/lib/docker_common.sh"
ARCH=$(docker_arch)
GO="${GO:-go}"
if [[ ! -x "$(command -v "$GO" 2>/dev/null || true)" ]]; then
    GO=/tmp/gotoolchain/go/bin/go
fi
XRAY_BIN=$(ensure_xray_bin "$ARCH")
IMAGE="${IDLELEO_PHASE03_IMAGE:-idleleo-phase03-test:24.04}"
BIN_DIR="${IDLELEO_PHASE03_BIN_DIR:-/tmp/idleleo-phase03-bin}"
NAME="idleleo-phase03-e2e-$$"

for f in "$XRAY_BIN" "$ROOT/tests/go-parity/phase03/Dockerfile"; do
    [[ -f "$f" ]] || { echo "missing $f" >&2; exit 2; }
done

echo "== building phase03 image =="
docker build -t "$IMAGE" -f "$ROOT/tests/go-parity/phase03/Dockerfile" "$ROOT/tests/go-parity/phase03"
IMAGE_ID=$(docker image inspect "$IMAGE" --format '{{.Id}}')
echo "image: $IMAGE"
echo "image-id: $IMAGE_ID"
echo "xray-bin: $XRAY_BIN arch=$ARCH sha256=$(host_sha256 "$XRAY_BIN")"

echo "== building linux/$ARCH idleleo and idleleo-recover =="
mkdir -p "$BIN_DIR"
(cd "$ROOT" && GOOS=linux GOARCH="$ARCH" "$GO" build -o "$BIN_DIR/idleleo" ./cmd/idleleo)
(cd "$ROOT" && GOOS=linux GOARCH="$ARCH" "$GO" build -o "$BIN_DIR/idleleo-recover" ./cmd/idleleo-recover)
echo "idleleo: $(host_sha256 "$BIN_DIR/idleleo")"
echo "idleleo-recover: $(host_sha256 "$BIN_DIR/idleleo-recover")"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

CGROUP_ARGS=()
while IFS= read -r arg; do CGROUP_ARGS+=("$arg"); done < <(cgroup_mount_args)

echo "== starting privileged systemd probe =="
docker run -d --name "$NAME" \
    --privileged --cgroupns=host \
    "${CGROUP_ARGS[@]+"${CGROUP_ARGS[@]}"}" \
    -v "$BIN_DIR:/work/bin:ro" \
    -v "$ROOT/install.sh:/work/install.sh:ro" \
    -v "$ROOT/packaging:/work/packaging:ro" \
    -v "$ROOT/tests/fixtures/legacy:/work/fixtures:ro" \
    -v "$XRAY_BIN:/opt/xray/xray:ro" \
    -v "$ROOT/tests/go-parity/phase03/run_phase03.sh:/phase03/run_phase03.sh:ro" \
    "$IMAGE" >/dev/null

state=""
for _ in $(seq 1 40); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    [[ "$state" == "running" || "$state" == "degraded" ]] && break
    sleep 1
done
echo "systemd: ${state:-not-ready}"
if [[ "$state" != "running" && "$state" != "degraded" ]]; then
    echo "systemd did not start" >&2
    docker logs "$NAME" | tail -30 >&2
    exit 1
fi

echo "== running Phase 03 E2E =="
set +e
docker exec "$NAME" bash /phase03/run_phase03.sh
rc=$?
set -e
echo "phase03-exit=$rc"
exit "$rc"
