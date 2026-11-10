#!/usr/bin/env bash
# B4 regression: a failed reinstall must restore root:xray 0640 ownership so the
# unprivileged User=xray can still read the config. Requires root and an xray
# account, so it runs in a disposable container rather than on the host.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../../.." && pwd)
image=${IDLELEO_GO_TEST_IMAGE:-idleleo-phase01-test:1.24}

docker run --rm --network=none \
    -v "${repo}:/src:ro" -w /src "${image}" sh -c '
    set -e
    groupadd -r xray 2>/dev/null || true
    useradd -r -g xray -s /usr/sbin/nologin xray 2>/dev/null || true
    go test ./internal/deploy \
        -run TestRestoreRootXray0640ReadableByRuntimeUser -count=1 -v
'
