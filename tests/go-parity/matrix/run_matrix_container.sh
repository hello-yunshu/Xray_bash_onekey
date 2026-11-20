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
# Snapshot tree state before creating the output directory: the evidence
# directory itself is untracked and must not inflate repo_dirty.
repo_commit="$(git -C "$REPO" rev-parse HEAD)"
repo_dirty="$(git -C "$REPO" status --porcelain | wc -l | tr -d ' ')"
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
  --build-arg "BASE_IMAGE=${MATRIX_BASE_IMAGE:-golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea}" \
  -t "$IMAGE" -f "$DIR/Dockerfile" "$DIR" >/dev/null

# Record only the digest and a repository-relative path: the checksum output
# embeds the caller's absolute path (and therefore the user name) by default.
install_sha="$(sha256sum "$REPO/install.sh" 2>/dev/null || shasum -a 256 "$REPO/install.sh")"
install_sha="${install_sha%% *}"

{
  echo "repo_commit=$repo_commit"
  echo "repo_dirty=$repo_dirty"
  echo "base_image=${MATRIX_BASE_IMAGE:-golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea}"
  echo "test_image=$(docker image inspect "$IMAGE" --format '{{.Id}}')"
  echo "docker_arch=$(docker version --format '{{.Server.Arch}}')"
  echo "docker_version=$(docker version --format '{{.Server.Version}}')"
  echo "bash_install_sha256=$install_sha"
  echo "bash_install_path=install.sh"
} >"$OUT/environment.txt"

docker run --rm --network=none --read-only --tmpfs /tmp:rw,exec,size=1024m \
  -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOTOOLCHAIN=local -e GOPROXY=off \
  -v "$REPO:/src:ro" -v "$OUT:/out:rw" -w /src \
  "$IMAGE" --repo /src --out /out
