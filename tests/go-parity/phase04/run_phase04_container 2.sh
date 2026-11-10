#!/usr/bin/env bash
# Host launcher for the Phase 04 qualification container. It builds distinct
# idleleo versions (0.2.0/0.3.0/0.4.0) so the real update channel can move a
# binary between versions, boots real systemd for cert/service evidence, and
# runs the pinned image.
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
IMAGE="${IDLELEO_PHASE04_IMAGE:-idleleo-phase04-test:24.04}"
BIN_DIR="${IDLELEO_PHASE04_BIN_DIR:-/tmp/idleleo-phase04-bin}"
EVID_DIR="${IDLELEO_PHASE04_EVIDENCE:-/tmp/idleleo-phase04-evidence}"
CONTAINER="${IDLELEO_PHASE04_CONTAINER:-idleleo-phase04-e2e}"
NAME="$CONTAINER-$$"
LDFLAGS_BASE="github.com/hello-yunshu/Xray_bash_onekey/internal/cli.Version"

echo "== building phase04 image =="
docker build -t "$IMAGE" -f "$ROOT/tests/go-parity/phase04/Dockerfile" "$ROOT/tests/go-parity/phase04"
IMAGE_ID=$(docker image inspect "$IMAGE" --format '{{.Id}}')
echo "image: $IMAGE"
echo "image-id: $IMAGE_ID"

echo "xray-bin: $XRAY_BIN arch=$ARCH sha256=$(host_sha256 "$XRAY_BIN")"

echo "== building linux/$ARCH idleleo versions =="
mkdir -p "$BIN_DIR" "$EVID_DIR"
(cd "$ROOT" && GOOS=linux GOARCH="$ARCH" "$GO" build -o "$BIN_DIR/idleleo-old" ./cmd/idleleo)
(cd "$ROOT" && GOOS=linux GOARCH="$ARCH" "$GO" build -ldflags "-X $LDFLAGS_BASE=0.3.0-phase04" -o "$BIN_DIR/idleleo-0.3.0" ./cmd/idleleo)
(cd "$ROOT" && GOOS=linux GOARCH="$ARCH" "$GO" build -ldflags "-X $LDFLAGS_BASE=0.4.0-phase04" -o "$BIN_DIR/idleleo-0.4.0" ./cmd/idleleo)
for f in idleleo-old idleleo-0.3.0 idleleo-0.4.0; do
    printf '%s sha256=%s\n' "$f" "$(host_sha256 "$BIN_DIR/$f")"
done

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

CGROUP_ARGS=()
while IFS= read -r arg; do CGROUP_ARGS+=("$arg"); done < <(cgroup_mount_args)

echo "== starting privileged systemd container =="
docker run -d --name "$NAME" \
    --privileged --cgroupns=host \
    "${CGROUP_ARGS[@]+"${CGROUP_ARGS[@]}"}" \
    -v "$BIN_DIR:/work/bin:ro" \
    -v "$ROOT/tests/go-parity/phase04/run_phase04.sh:/phase04/run_phase04.sh:ro" \
    -v "$ROOT/tests/go-parity/phase04/origin_server.py:/work/origin_server.py:ro" \
    -v "$XRAY_BIN:/usr/local/bin/xray:ro" \
    -v "$EVID_DIR:/work/evidence" \
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

echo "== running Phase 04 qualification =="
set +e
docker exec "$NAME" bash /phase04/run_phase04.sh
rc=$?
set -e
echo "phase04-exit=$rc"
if [[ $rc -ne 0 ]]; then
    docker exec "$NAME" journalctl -n 40 --no-pager 2>/dev/null || true
fi
exit "$rc"
