#!/usr/bin/env bash
# Real Nginx + two real Xray Reality backends + real client in one disposable
# container. Verifies round-robin, primary survival on secondary failure,
# secondary rejoin after recovery, and unknown-SNI refusal.
#
# This is REAL_NGINX_REAL_XRAY_E2E (container), never a production acceptance.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(cd "$DIR/../../.." && pwd -P)"
EVIDENCE="${E2E_EVIDENCE:-$REPO/tests/go-parity/evidence/balance-e2e-$(date +%F)}"
IMAGE="${E2E_IMAGE:-idleleo-reality-e2e:local}"
TMP="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP"
    docker rm -f idleleo-reality-e2e-run >/dev/null 2>&1 || true
}
trap cleanup EXIT

[[ -x "$REPO/tests/go-parity/.cache/a2/xray" ]] || {
    echo "ERROR: cached real Xray binary missing" >&2
    exit 3
}
mkdir -p "$TMP/conf" "$TMP/nginx" "$TMP/out" "$TMP/www"
printf 'idleleo reality e2e\n' >"$TMP/www/index.html"

docker run --rm -v "$REPO:/src:ro" -v "$TMP:/out" -v /tmp/go-build-cache:/gocache \
    -e GOCACHE=/gocache -w /src golang:1.24 sh -c '
        set -e
        go build -o /out/idleleo ./cmd/idleleo
        python3 tests/go-parity/balance/gen_e2e_configs.py /out
    '

docker build -q -f "$DIR/e2e.Dockerfile" -t "$IMAGE" "$REPO" >/dev/null
rm -rf "$EVIDENCE"
mkdir -p "$EVIDENCE"

set +e
# Default bridge networking is required: Reality mimics a real public TLS
# target. This does not modify host networking or kernel settings.
docker run --rm --name idleleo-reality-e2e-run \
    -v "$TMP:/e2e" "$IMAGE" /entry.sh
RC=$?
set -e

cp "$TMP/out/assertions.log" "$TMP/out/summary.json" "$TMP/out/nginx-test.log" \
    "$TMP/out/unknown-sni.log" "$EVIDENCE/" 2>/dev/null || true
cp "$TMP/out/primary-access.log" "$TMP/out/secondary-access.log" "$EVIDENCE/" 2>/dev/null || true
cp "$TMP/out/probe.log" "$TMP/out/sec-monitor.log" "$EVIDENCE/" 2>/dev/null || true
cp "$TMP/out/primary.out" "$TMP/out/secondary.out" "$TMP/out/client.out" \
    "$TMP/out/primary-error.log" "$TMP/out/secondary-error.log" "$TMP/out/client-error.log" \
    "$TMP/out/nginx-error.log" "$EVIDENCE/" 2>/dev/null || true
cp "$TMP/identity.json" "$EVIDENCE/" 2>/dev/null || true
{
    echo "evidence=REAL_NGINX_REAL_XRAY_E2E"
    echo "container_only=1"
    echo "host_network_modified=0"
    echo "kernel_modified=0"
    echo "container_egress_required=1 (Reality target www.cloudflare.com:443)"
    echo "docker_exit=$RC"
    echo "image=$IMAGE"
} >"$EVIDENCE/environment.txt"

echo "e2e exit=$RC evidence=$EVIDENCE"
exit "$RC"
