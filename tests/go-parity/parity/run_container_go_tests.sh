#!/usr/bin/env bash
# Runs the Go tests that are gated on "real root inside a container". The
# GitHub VM is neither root nor a container, so these tests are skipped there;
# this script is the only place they actually execute. It fails when a gated
# test is skipped or does not report PASS, so a lost test cannot look green.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../../.." && pwd)
# These tests need only go, bash and useradd/groupadd, all of which ship in the
# official Go image. Avoiding a custom image keeps the job independent of apt.
image=${IDLELEO_TEST_IMAGE:-golang:1.27.4}

out=$(mktemp)
trap 'rm -f "$out"' EXIT

docker run --rm --network=none \
    -v "${repo}:/src" -w /src \
    -e GOFLAGS="-mod=vendor -buildvcs=false" \
    -e GOTOOLCHAIN=local \
    -e GOPROXY=off \
    "$image" bash -c '
    set -e
    go test ./internal/cli \
        -run "TestChangeRealRoot|TestChangeRefusesFaultOnRealRoot" -count=1 -v
' | tee "$out"

IDLELEO_GO_TEST_IMAGE="$image" bash "${repo}/tests/go-parity/deploy/run_deploy_owner_regression.sh" | tee -a "$out"

gated=(
    TestChangeRealRootIsRefusedWithoutContainerAck
    TestChangeRealRootIsRefusedWithoutEnvAck
    TestChangeRealRootRequiresManagerMetadata
    TestChangeRefusesFaultOnRealRoot
    TestRestoreRootXray0640ReadableByRuntimeUser
)

status=0
for name in "${gated[@]}"; do
    if grep -q -- "--- SKIP: ${name}" "$out"; then
        echo "container-go-tests: ${name} was skipped; gated coverage would be lost" >&2
        status=1
    elif ! grep -q -- "--- PASS: ${name}" "$out"; then
        echo "container-go-tests: ${name} did not report PASS" >&2
        status=1
    fi
done
if [ "$status" -ne 0 ]; then
    echo "container-go-tests: refusing to treat a skipped or missing gated test as success" >&2
    exit 1
fi
echo "container-go-tests: all ${#gated[@]} gated tests passed"
