#!/usr/bin/env bash
# Runs the Phase 01 acceptance inside a digest-pinned Linux test image.
# Network is disabled inside the container: the harness must not fetch updates.
set -eu
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
IMAGE=${IDLELEO_TEST_IMAGE:-idleleo-phase01-test:1.27.4}
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -q -t "$IMAGE" - <"$REPO/tests/go-parity/phase01/Dockerfile" >/dev/null
fi
IMAGE_ID=$(docker image inspect "$IMAGE" --format '{{.Id}}')
XRAY_ARGS=()
if [ -n "${IDLELEO_XRAY_BIN:-}" ]; then
  XRAY_ARGS=(-v "$(cd "$(dirname "$IDLELEO_XRAY_BIN")" && pwd)/$(basename "$IDLELEO_XRAY_BIN"):/xray:ro" -e XRAY_BIN=/xray)
fi
exec docker run --rm --network=none \
  -v "$REPO:/src" -w /src \
  "${XRAY_ARGS[@]+"${XRAY_ARGS[@]}"}" \
  -e GOTOOLCHAIN=local \
  -e GOPROXY=off \
  -e PHASE01_IMAGE="$IMAGE $IMAGE_ID" \
  "$IMAGE" bash -c '
    if [ -n "${XRAY_BIN:-}" ]; then mkdir -p /var/log/xray; fi
    export PATH=/usr/local/go/bin:$PATH
    go build -trimpath -o /tmp/idleleo ./cmd/idleleo
    IDLELEO_BIN=/tmp/idleleo GO=/usr/local/go/bin/go REPO=/src \
      PHASE01_EVIDENCE=/src/tests/go-parity/phase01/evidence \
      bash tests/go-parity/phase01/run_phase01.sh
  '
