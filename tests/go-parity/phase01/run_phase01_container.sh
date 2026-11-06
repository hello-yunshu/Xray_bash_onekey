#!/usr/bin/env bash
# Runs the Phase 01 acceptance inside a digest-pinned Linux test image.
# Network is disabled inside the container: the harness must not fetch updates.
set -eu
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
IMAGE=${IDLELEO_TEST_IMAGE:-idleleo-phase01-test:1.24}
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -q -t "$IMAGE" - <"$REPO/tests/go-parity/phase01/Dockerfile" >/dev/null
fi
exec docker run --rm --network=none \
  -v "$REPO:/src" -w /src \
  -e GOTOOLCHAIN=local \
  "$IMAGE" bash -c '
    export PATH=/usr/local/go/bin:$PATH
    go build -trimpath -o /tmp/idleleo ./cmd/idleleo
    IDLELEO_BIN=/tmp/idleleo GO=/usr/local/go/bin/go REPO=/src \
      PHASE01_EVIDENCE=/src/tests/go-parity/phase01/evidence \
      bash tests/go-parity/phase01/run_phase01.sh
  '
