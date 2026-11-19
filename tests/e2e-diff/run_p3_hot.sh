#!/usr/bin/env bash
# P3 real-machine runner: installs the Go manager in a systemd container and
# runs the experimental hot-user pilot (loopback API, real clients, restart,
# concurrency), the repair permission regression and the operator summary.
#
# Usage:
#   bash tests/e2e-diff/run_p3_hot.sh
#   E2E_KEEP=1 bash tests/e2e-diff/run_p3_hot.sh   # keep the container
#
# Evidence: tests/e2e-diff/evidence/goevo-p3-<run-id>/
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-$(date +%Y%m%d-%H%M)}"
EVID="$SUITE/evidence/goevo-p3-$RUN_ID"
WORK="${E2E_WORK:-/tmp/e2e-p3-$RUN_ID}"
IMAGE_TAG="${E2E_IMAGE_TAG:-idleleo-e2e:24.04}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
TRANSPORT="${E2E_TRANSPORT:-}"
NAME="e2e-$RUN_ID-go${TRANSPORT:+-$TRANSPORT}"
DOMAIN="${E2E_DOMAIN:-www.cloudflare.com}"
TARGET="${E2E_TARGET:-127.0.0.1:8443}"

source "$ROOT/tests/go-parity/lib/docker_common.sh"

mkdir -p "$EVID/container" "$WORK/seed"
log() { printf '%s\n' "$*" | tee -a "$EVID/run.log"; }

cleanup() {
    if [[ "${E2E_KEEP:-0}" != "1" ]]; then
        docker rm -f "$NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

log "run_id=$RUN_ID"
log "commit=$(git -C "$ROOT" rev-parse HEAD)"
log "image=$IMAGE_TAG"
if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
    log "building $IMAGE_TAG"
    docker build -q -t "$IMAGE_TAG" -f "$SUITE/image/Dockerfile" "$SUITE/image" >/dev/null || {
        log "FATAL: image build failed"
        exit 2
    }
fi
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE_TAG")
log "image_id=$IMAGE_ID"

ARCH=$(docker_arch) || exit 2

log "building idleleo"
docker run --rm -v "$ROOT:/src:ro" -v "$WORK/seed:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
    "$GO_IMAGE" go build -buildvcs=false -trimpath -o /out/idleleo ./cmd/idleleo || {
    log "FATAL: idleleo build failed"
    exit 2
}
log "idleleo_sha256=$(host_sha256 "$WORK/seed/idleleo")"

log "building the local TLS target"
docker run --rm -v "$SUITE/drivers:/src:ro" -v "$WORK/seed:/out" -w /src \
    -e CGO_ENABLED=0 -e GOPROXY=off -e GOTOOLCHAIN=local \
    "$GO_IMAGE" sh -c 'GOOS=linux GOARCH='"$ARCH"' go build -trimpath -o /out/p3-tls-target ./p3_tls_target.go' || {
    log "FATAL: TLS target build failed"
    exit 2
}

if [[ -x "$ROOT/tests/go-parity/.cache/a2/xray" ]]; then
    XRAY_BIN="$ROOT/tests/go-parity/.cache/a2/xray"
else
    XRAY_BIN=$(ensure_xray_bin "$ARCH") || exit 2
fi
log "arch=$ARCH"
cp "$XRAY_BIN" "$WORK/seed/xray"
chmod 0755 "$WORK/seed/xray"
log "xray_sha256=$(host_sha256 "$WORK/seed/xray") arch=$ARCH"

docker rm -f "$NAME" >/dev/null 2>&1 || true
# shellcheck disable=SC2046
docker run -d --name "$NAME" --hostname "$NAME" \
    --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
    $(cgroup_mount_args) \
    -v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$EVID/container:/out" \
    --label "e2e.run=$RUN_ID" --label "e2e.scenario=P3" \
    "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null || {
    log "FATAL: container start failed"
    exit 2
}
log "container=$NAME"

# The Reality target must be reachable before the installer probes it. Xray 26
# negotiates X25519MLKEM768 with the target, so the origin is the Go helper, not
# openssl. The loopback alias gives the authenticated tunnel a destination that
# the freedom outbound does not blackhole.
log "starting the local TLS target"
docker exec -e E2E_DOMAIN="$DOMAIN" "$NAME" bash -c '
set -e
install -m 0755 /seed/p3-tls-target /usr/local/bin/p3-tls-target
mkdir -p /etc/idleleo/p3
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3 \
    -subj "/CN=$E2E_DOMAIN" -addext "subjectAltName=DNS:$E2E_DOMAIN" \
    -keyout /etc/idleleo/p3/target.key -out /etc/idleleo/p3/target.crt >/dev/null 2>&1
nohup /usr/local/bin/p3-tls-target 127.0.0.1:8443 /etc/idleleo/p3/target.crt \
    /etc/idleleo/p3/target.key >/var/log/p3-tls-target.log 2>&1 &
for _ in $(seq 1 40); do
    (exec 3<>/dev/tcp/127.0.0.1/8443) 2>/dev/null && exit 0
    sleep 0.1
done
echo "TLS target did not listen" >&2
exit 1
' >>"$EVID/run.log" 2>&1 || {
    log "FATAL: local TLS target failed to start"
    exit 2
}

log "installing Go manager (reality${TRANSPORT:+, transport=$TRANSPORT})"
TRANSPORT_ARGS=()
if [[ -n "$TRANSPORT" ]]; then
    TRANSPORT_ARGS=(--transport "$TRANSPORT")
fi
docker exec -e E2E_OUT=/out/install -e E2E_PROFILE="reality${TRANSPORT:+-$TRANSPORT}" -e E2E_SCENARIO=P3 \
    -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET" -e E2E_PORT=443 \
    "$NAME" bash /src/tests/e2e-diff/drivers/go_install.sh \
    --binary /usr/local/bin/xray --mode reality --domain "$DOMAIN" \
    --target "$TARGET" --port 443 --container ${TRANSPORT_ARGS[@]+"${TRANSPORT_ARGS[@]}"} >>"$EVID/run.log" 2>&1
install_rc=$?
log "install_rc=$install_rc"
if [[ $install_rc -ne 0 ]]; then
    log "FATAL: install failed; driver skipped"
    log "evidence=$EVID"
    exit "$install_rc"
fi

log "running P3 driver"
docker exec -e E2E_OUT=/out/driver "$NAME" \
    bash /src/tests/e2e-diff/drivers/go_p3_hot.sh >>"$EVID/run.log" 2>&1
driver_rc=$?
log "driver_rc=$driver_rc"

python3 - "$EVID" "$RUN_ID" "$IMAGE_ID" "$(git -C "$ROOT" rev-parse HEAD)" \
    "$install_rc" "$driver_rc" <<'PY'
import json
import os
import sys

evid, run_id, image_id, commit, install_rc, driver_rc = sys.argv[1:7]
rows = []
path = os.path.join(evid, 'container', 'driver', 'assertions.txt')
if os.path.exists(path):
    for line in open(path):
        parts = line.rstrip('\n').split('\t', 1)
        if len(parts) == 2:
            rows.append(parts)
report = {
    'schemaVersion': 1,
    'runId': run_id,
    'commit': commit,
    'imageId': image_id,
    'installExit': int(install_rc),
    'driverExit': int(driver_rc),
    'passed': sum(1 for r in rows if r[0] == 'PASS'),
    'failed': sum(1 for r in rows if r[0] == 'FAIL'),
    'assertions': [{'result': r[0], 'label': r[1]} for r in rows],
}
json.dump(report, open(os.path.join(evid, 'run.json'), 'w'), indent=2, sort_keys=True)

md = ['# P3 hot-user pilot real-machine evidence', '',
      '- run-id: `%s`' % run_id,
      '- commit: `%s`' % commit,
      '- image id: `%s`' % image_id,
      '- install rc: %s' % install_rc,
      '- driver rc: %s' % driver_rc,
      '- assertions: %d pass / %d fail' % (report['passed'], report['failed']), '']
for result, label in rows:
    md.append('- **%s** %s' % (result, label))
open(os.path.join(evid, 'summary.md'), 'w').write('\n'.join(md) + '\n')
PY

log "evidence=${EVID#"$ROOT/"}"
if [[ $driver_rc -ne 0 ]]; then
    log "RESULT: FAIL"
    exit 1
fi
log "RESULT: PASS"
exit 0
