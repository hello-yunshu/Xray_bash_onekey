#!/usr/bin/env bash
# Run the preview qualification gate inside a reproducible systemd container.
#
#   ./run_preview_container.sh            # all features in preview_contract.json
#   ./run_preview_container.sh F01        # one feature while developing
#   KEEP_PREVIEW_CONTAINER=1 ...          # leave the container for inspection
#
# The host may be macOS (no Go, no Linux Xray): the binary is built with the
# golang image and Xray comes from docker_common.sh, exactly like Phase 01-04.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
export ROOT
# shellcheck source=../../../lib/docker_common.sh
source "$ROOT/tests/go-parity/lib/docker_common.sh"

ONLY=${1:-}
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/idleleo-preview.XXXXXX")
CID=""
IMAGE=idleleo-preview:latest

cleanup() {
    local rc=$?
    if [[ -n "$CID" && "${KEEP_PREVIEW_CONTAINER:-0}" != "1" ]]; then
        docker rm -f "$CID" >/dev/null 2>&1 || true
    elif [[ -n "$CID" ]]; then
        echo "container kept: $CID" >&2
    fi
    echo "preview evidence: $BUILD/evidence" >&2
    exit "$rc"
}
trap cleanup EXIT

mkdir -p "$BUILD/evidence"

echo "[1/4] build idleleo from $ROOT" >&2
docker run --rm \
    -v "$ROOT":/src -w /src \
    -v "$BUILD":/out \
    -e CGO_ENABLED=0 \
    golang:1.24 go build -trimpath -o /out/idleleo ./cmd/idleleo
chmod 0755 "$BUILD/idleleo"

echo "[2/4] resolve a Linux Xray for the Docker arch" >&2
XRAY=$(ensure_xray_bin "$(docker_arch)")
cp "$XRAY" "$BUILD/xray"
chmod 0755 "$BUILD/xray"

echo "[3/4] build the systemd fixture image" >&2
docker build -q -f "$ROOT/tests/go-parity/phase04/Dockerfile" -t "$IMAGE" \
    "$ROOT/tests/go-parity/phase04" >/dev/null
IMAGE_ID=$(docker images --format '{{.ID}}' "$IMAGE" | head -1)

echo "[4/4] start systemd container and run preview gate" >&2
# shellcheck disable=SC2046
CID=$(docker run -d --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock \
    $(cgroup_mount_args) \
    -v "$BUILD/idleleo:/work/bin/idleleo:ro" \
    -v "$BUILD/xray:/opt/xray/xray:ro" \
    -v "$ROOT:/work/repo:ro" \
    -v "$BUILD/evidence:/work/evidence" \
    "$IMAGE")

state=""
for _ in $(seq 1 60); do
    state=$(docker exec "$CID" systemctl is-system-running 2>/dev/null || true)
    if [[ "$state" == "running" || "$state" == "degraded" ]]; then
        break
    fi
    sleep 1
done
if [[ "$state" != "running" && "$state" != "degraded" ]]; then
    echo "systemd did not become ready: ${state:-no response}" >&2
    docker exec "$CID" journalctl --no-pager -n 40 >&2 || true
    exit 3
fi

args=(--go-bin /work/bin/idleleo --bash-repo /work/repo
      --container-evidence "image:$IMAGE_ID" --evidence /work/evidence)
if [[ -n "$ONLY" ]]; then
    args+=(--only "$ONLY")
fi

set +e
docker exec "$CID" python3 /work/repo/tests/go-parity/parity/scripts/check_preview_gate.py "${args[@]}"
rc=$?
set -e
if (( rc != 0 )); then
    echo "--- xray unit journal (last 40 lines) ---" >&2
    docker exec "$CID" journalctl -u xray --no-pager -n 40 >&2 || true
fi
exit "$rc"
