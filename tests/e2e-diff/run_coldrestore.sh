#!/usr/bin/env bash
# Cold-restore runner: installs the Go manager in container A, archives the
# managed state, destroys A, then restores that archive on a freshly installed
# container B with a new service account, and proves a real client works.
#
# Usage:
#   bash tests/e2e-diff/run_coldrestore.sh
#   E2E_KEEP=1 bash tests/e2e-diff/run_coldrestore.sh   # keep containers
#
# Evidence: tests/e2e-diff/evidence/goevo-coldrestore-<run-id>/
# The archive itself stays in a host temp directory and is deleted on exit: it
# carries private keys and must never be committed.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-$(date +%Y%m%d-%H%M)}"
EVID="$SUITE/evidence/goevo-coldrestore-$RUN_ID"
WORK="${E2E_WORK:-/tmp/e2e-coldrestore-$RUN_ID}"
HANDOFF="$WORK/handoff"
IMAGE_TAG="${E2E_IMAGE_TAG:-idleleo-e2e:24.04}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
DOMAIN="${E2E_DOMAIN:-www.cloudflare.com}"
TARGET="${E2E_TARGET:-127.0.0.1:8443}"
SOURCE="e2e-$RUN_ID-cold-source"
TARGET_NODE="e2e-$RUN_ID-cold-target"

source "$ROOT/tests/go-parity/lib/docker_common.sh"

mkdir -p "$EVID/source" "$EVID/target" "$WORK/seed" "$HANDOFF"
log() { printf '%s\n' "$*" | tee -a "$EVID/run.log"; }

cleanup() {
    if [[ "${E2E_KEEP:-0}" != "1" ]]; then
        docker rm -f "$SOURCE" "$TARGET_NODE" >/dev/null 2>&1 || true
        rm -rf "$HANDOFF"
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

start_node() { # start_node <name> <evidence-dir>
    local name=$1 out=$2
    docker rm -f "$name" >/dev/null 2>&1 || true
    # shellcheck disable=SC2046
    docker run -d --name "$name" --hostname "$name" \
        --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
        $(cgroup_mount_args) \
        -v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$out:/out" \
        -v "$HANDOFF:/handoff" \
        --label "e2e.run=$RUN_ID" --label "e2e.scenario=COLD-RESTORE" \
        "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null || return 1
}

start_tls_target() { # start_tls_target <name>
    local name=$1
    docker exec -e E2E_DOMAIN="$DOMAIN" "$name" bash -c '
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
    ' >>"$EVID/run.log" 2>&1
}

install_node() { # install_node <name>
    local name=$1
    docker exec -e E2E_OUT=/out/install -e E2E_PROFILE=reality -e E2E_SCENARIO=COLD-RESTORE \
        -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET" -e E2E_PORT=443 \
        "$name" bash /src/tests/e2e-diff/drivers/go_install.sh \
        --binary /usr/local/bin/xray --mode reality --domain "$DOMAIN" \
        --target "$TARGET" --port 443 --container >>"$EVID/run.log" 2>&1
}

run_driver() { # run_driver <name> <mode>
    local name=$1 mode=$2
    docker exec -e E2E_OUT=/out/driver -e E2E_DOMAIN="$DOMAIN" -e E2E_HANDOFF=/handoff \
        "$name" bash /src/tests/e2e-diff/drivers/go_coldrestore.sh "$mode" >>"$EVID/run.log" 2>&1
}

# --- source machine --------------------------------------------------------
log "source: starting $SOURCE"
start_node "$SOURCE" "$EVID/source" || { log "FATAL: source container failed"; exit 2; }
start_tls_target "$SOURCE" || { log "FATAL: source TLS target failed"; exit 2; }

log "source: installing Go manager"
if ! install_node "$SOURCE"; then
    log "FATAL: source install failed"
    exit 2
fi
log "source: driver"
run_driver "$SOURCE" source
source_rc=$?
log "source_driver_rc=$source_rc"

# Destroy the source machine before the restore. The archive is the only state
# that crosses the boundary.
log "source: destroying $SOURCE"
docker rm -f "$SOURCE" >/dev/null 2>&1 || true

# --- target machine --------------------------------------------------------
log "target: starting $TARGET_NODE"
start_node "$TARGET_NODE" "$EVID/target" || { log "FATAL: target container failed"; exit 2; }
start_tls_target "$TARGET_NODE" || { log "FATAL: target TLS target failed"; exit 2; }

log "target: installing a fresh Go manager (new keys and users)"
if ! install_node "$TARGET_NODE"; then
    log "FATAL: target install failed"
    exit 2
fi
log "target: driver"
run_driver "$TARGET_NODE" target
target_rc=$?
log "target_driver_rc=$target_rc"

python3 - "$EVID" "$RUN_ID" "$IMAGE_ID" "$(git -C "$ROOT" rev-parse HEAD)" \
    "$source_rc" "$target_rc" "$HANDOFF/archive.sha256" <<'PY'
import json
import os
import sys

evid, run_id, image_id, commit, source_rc, target_rc, archive_sha = sys.argv[1:8]
report = {'schemaVersion': 1, 'runId': run_id, 'commit': commit,
          'imageId': image_id, 'sourceDriverExit': int(source_rc),
          'targetDriverExit': int(target_rc), 'sides': {}}
rows = []
for side in ('source', 'target'):
    path = os.path.join(evid, side, 'driver', 'assertions.txt')
    side_rows = []
    if os.path.exists(path):
        for line in open(path):
            parts = line.rstrip('\n').split('\t', 1)
            if len(parts) == 2:
                side_rows.append(parts)
                rows.append((side, parts[0], parts[1]))
    report['sides'][side] = {
        'passed': sum(1 for r in side_rows if r[0] == 'PASS'),
        'failed': sum(1 for r in side_rows if r[0] == 'FAIL'),
        'assertions': [{'result': r[0], 'label': r[1]} for r in side_rows],
    }
try:
    report['archiveSHA256'] = open(archive_sha).read().strip()
except OSError:
    report['archiveSHA256'] = ''
json.dump(report, open(os.path.join(evid, 'run.json'), 'w'), indent=2, sort_keys=True)

md = ['# Cold restore real-machine evidence', '',
      '- run-id: `%s`' % run_id,
      '- commit: `%s`' % commit,
      '- image id: `%s`' % image_id,
      '- source driver rc: %s' % source_rc,
      '- target driver rc: %s' % target_rc,
      '- archive sha256: `%s`' % report['archiveSHA256'], '']
for side, result, label in rows:
    md.append('- **%s** [%s] %s' % (result, side, label))
open(os.path.join(evid, 'summary.md'), 'w').write('\n'.join(md) + '\n')
PY

log "evidence=${EVID#"$ROOT/"}"
if [[ $source_rc -ne 0 || $target_rc -ne 0 ]]; then
    log "RESULT: FAIL"
    exit 1
fi
log "RESULT: PASS"
exit 0
