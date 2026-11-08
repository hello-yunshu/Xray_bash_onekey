#!/usr/bin/env bash
# Run the Bash -> Go 98-case matrix in a disposable, network-disabled,
# read-only container. Never runs a full install or touches host sysctl.
#
# Usage: bash tests/go-parity/matrix/run_matrix_container.sh [REPO] [OUT]
#   REPO defaults to the repository root, OUT to $REPO/.audit-bash-go-matrix.
# Env:
#   MATRIX_BASE_IMAGE  locally cached image with go/python3/jq/git
#   MATRIX_IMAGE       result image tag (default xray-bash-go-matrix:local)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="${1:-$(cd "$DIR/../../.." && pwd -P)}"
REPO="$(cd "$REPO" && pwd -P)"
OUT="${2:-$REPO/.audit-bash-go-matrix}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd -P)"
IMAGE="${MATRIX_IMAGE:-xray-bash-go-matrix:local}"

[[ -f "$REPO/install.sh" && -f "$REPO/go.mod" ]] || {
  echo "ERROR: first argument must be a checkout with install.sh and go.mod" >&2
  exit 3
}
command -v docker >/dev/null || { echo "ERROR: Docker unavailable" >&2; exit 3; }
docker info >/dev/null

docker build --pull=false -q \
  --build-arg "BASE_IMAGE=${MATRIX_BASE_IMAGE:-golang:1.23-bookworm}" \
  -t "$IMAGE" -f "$DIR/Dockerfile" "$DIR" >/dev/null

{
  echo "repo_commit=$(git -C "$REPO" rev-parse HEAD)"
  echo "repo_dirty=$(git -C "$REPO" status --porcelain | wc -l | tr -d ' ')"
  echo "base_image=${MATRIX_BASE_IMAGE:-golang:1.23-bookworm}"
  echo "test_image=$(docker image inspect "$IMAGE" --format '{{.Id}}')"
  echo "docker_arch=$(docker version --format '{{.Server.Arch}}')"
  echo "docker_version=$(docker version --format '{{.Server.Version}}')"
  echo "bash_install_sha256=$(sha256sum "$REPO/install.sh" 2>/dev/null || shasum -a 256 "$REPO/install.sh")"
} >"$OUT/environment.txt"

docker run --rm --network=none --read-only --tmpfs /tmp:rw,exec,size=1024m \
  -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOTOOLCHAIN=local -e GOPROXY=off \
  -v "$REPO:/src:ro" -v "$OUT:/out:rw" -w /src \
  "$IMAGE" --repo /src --out /out
