#!/usr/bin/env bash
# Real-root change acceptance inside a privileged systemd container.
#
#   ./run_realroot_container.sh
#   IDLELEO_REALROOT_EVIDENCE=/tmp/evidence ./run_realroot_container.sh
#   KEEP_REALROOT_CONTAINER=1 ...          # leave the container for inspection
#
# The host may be macOS: the manager is built with the pinned golang image and
# Xray comes from docker_common.sh, exactly like the preview gate. Nothing on
# the host is installed or modified; /etc/idleleo lives inside the container.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
export ROOT
# shellcheck source=../../lib/docker_common.sh
source "$ROOT/tests/go-parity/lib/docker_common.sh"

OUT=${IDLELEO_REALROOT_EVIDENCE:-$(mktemp -d "${TMPDIR:-/tmp}/idleleo-realroot-evidence.XXXXXX")}
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/idleleo-realroot-build.XXXXXX")
CID=""
IMAGE=idleleo-realroot:latest

cleanup() {
    local rc=$?
    if [[ -n "$CID" && "${KEEP_REALROOT_CONTAINER:-0}" != "1" ]]; then
        docker rm -f "$CID" >/dev/null 2>&1 || true
        rm -rf "$BUILD"
    elif [[ -n "$CID" ]]; then
        echo "container kept: $CID (build dir: $BUILD)" >&2
    else
        rm -rf "$BUILD"
    fi
    echo "realroot evidence: $OUT" >&2
    exit "$rc"
}
trap cleanup EXIT

mkdir -p "$OUT/evidence"

echo "[1/5] build idleleo from $ROOT" >&2
# A CI checkout is owned by another uid than the container user, so git refuses
# to inspect it; safe.directory plus -buildvcs=false keeps the build hermetic.
docker run --rm \
    -v "$ROOT":/src -w /src \
    -v "$BUILD":/out \
    -e CGO_ENABLED=0 \
    -e GIT_CONFIG_COUNT=1 \
    -e GIT_CONFIG_KEY_0=safe.directory \
    -e GIT_CONFIG_VALUE_0=/src \
    golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c go build -buildvcs=false -trimpath -o /out/idleleo ./cmd/idleleo
# go build already writes 0755; the file is container-owned on a CI checkout and
# cannot be chmod'ed by the runner user.

echo "[2/5] resolve a Linux Xray for the Docker arch" >&2
XRAY=$(ensure_xray_bin "$(docker_arch)")
cp "$XRAY" "$BUILD/xray"
chmod 0755 "$BUILD/xray"

echo "[3/5] build the systemd fixture image" >&2
docker build -q -f "$ROOT/tests/go-parity/phase04/Dockerfile" -t "$IMAGE" \
    "$ROOT/tests/go-parity/phase04" >/dev/null
IMAGE_ID=$(docker images --format '{{.ID}}' "$IMAGE" | head -1)

echo "[4/5] start privileged systemd container" >&2
# shellcheck disable=SC2046
CID=$(docker run -d --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock \
    $(cgroup_mount_args) \
    -v "$BUILD/idleleo:/work/bin/idleleo:ro" \
    -v "$BUILD/xray:/opt/xray/xray:ro" \
    -v "$ROOT:/work/repo:ro" \
    -v "$OUT/evidence:/work/evidence" \
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

echo "[5/5] run real-root change acceptance (image:$IMAGE_ID)" >&2
set +e
docker exec "$CID" python3 /work/repo/tests/go-parity/parity/realroot_change_checks.py
rc=$?
set -e
if (( rc != 0 )); then
    echo "--- xray unit journal (last 60 lines) ---" >&2
    docker exec "$CID" journalctl -u xray --no-pager -n 60 >&2 || true
    echo "--- idleleo audit log ---" >&2
    docker exec "$CID" cat /var/log/idleleo/system-writes.log >&2 || true
fi
exit "$rc"
