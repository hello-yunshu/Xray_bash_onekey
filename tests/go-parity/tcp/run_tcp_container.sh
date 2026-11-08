#!/usr/bin/env bash
# Run the Go-native TCP profile scenarios in a network-disabled, read-only
# container. Reads/writes are redirected into a disposable sandbox root, so the
# Docker VM kernel is not modified. Evidence level is DOCKER_MOCK_APPLY, not a
# host kernel acceptance.
#
# Usage: bash tests/go-parity/tcp/run_tcp_container.sh [REPO] [OUT]
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="${1:-$(cd "$DIR/../../.." && pwd -P)}"
REPO="$(cd "$REPO" && pwd -P)"
OUT="${2:-$REPO/.audit-tcp-native}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd -P)"
IMAGE="${TCP_IMAGE:-idleleo-phase01-test:1.24}"

[[ -f "$REPO/install.sh" && -f "$REPO/go.mod" ]] || {
  echo "ERROR: first argument must be a checkout with install.sh and go.mod" >&2
  exit 3
}
command -v docker >/dev/null || { echo "ERROR: Docker unavailable" >&2; exit 3; }
docker info >/dev/null
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  echo "ERROR: image $IMAGE not cached; build tests/go-parity/phase01/Dockerfile first" >&2
  exit 3
}

{
  echo "repo_commit=$(git -C "$REPO" rev-parse HEAD)"
  echo "repo_dirty=$(git -C "$REPO" status --porcelain | wc -l | tr -d ' ')"
  echo "image=$IMAGE"
  echo "image_id=$(docker image inspect "$IMAGE" --format '{{.Id}}')"
  echo "docker_arch=$(docker version --format '{{.Server.Arch}}')"
  echo "docker_version=$(docker version --format '{{.Server.Version}}')"
  echo "evidence_level=DOCKER_MOCK_APPLY"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel_note=apply/rollback are redirected to a sandbox root; the Docker VM kernel is not written"
} >"$OUT/environment.txt"

exec docker run --rm --network=none --read-only --tmpfs /tmp:rw,exec,size=1024m \
  -v "$REPO:/src:ro" -v "$OUT:/out" -w /src \
  -e GOTOOLCHAIN=local \
  "$IMAGE" bash /src/tests/go-parity/tcp/tcp_scenarios.sh /src /out
