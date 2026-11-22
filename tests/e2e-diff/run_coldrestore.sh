#!/usr/bin/env bash
# Cold-restore runner: installs the Go manager in container A, archives the
# managed state, destroys A, then restores that archive on a freshly installed
# container B with a new service account, and proves a real client works.
#
# Usage:
#   bash tests/e2e-diff/run_coldrestore.sh                     # all scenarios
#   E2E_SCENARIO=tls bash tests/e2e-diff/run_coldrestore.sh    # one scenario
#   E2E_KEEP=1 bash tests/e2e-diff/run_coldrestore.sh          # keep containers
#
# Scenarios: reality (default), tls, relay, multi.
# Evidence: tests/e2e-diff/evidence/goevo-coldrestore-<run-id>/<scenario>/
# The archive itself stays in a host temp directory and is deleted on exit: it
# carries private keys and must never be committed.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-$(date +%Y%m%d-%H%M)}"
EVID="$SUITE/evidence/goevo-coldrestore-$RUN_ID"
WORK="${E2E_WORK:-/tmp/e2e-coldrestore-$RUN_ID}"
SEED="$WORK/seed"
IMAGE_TAG="${E2E_IMAGE_TAG:-idleleo-e2e:24.04}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
DOMAIN="${E2E_DOMAIN:-www.cloudflare.com}"
SC_DOMAIN="${E2E_TLS_DOMAIN:-example.com}"
TARGET="${E2E_TARGET:-127.0.0.1:8443}"
RELAY_TARGET="${E2E_RELAY_TARGET:-1.2.3.4:18080}"
SCENARIOS="${E2E_SCENARIO:-${E2E_SCENARIOS:-reality tls relay multi}}"

source "$ROOT/tests/go-parity/lib/docker_common.sh"

mkdir -p "$EVID" "$SEED"
log() { printf '%s\n' "$*" | tee -a "$EVID/run.log"; }

cleanup() {
    if [[ "${E2E_KEEP:-0}" != "1" ]]; then
        for sc in $SCENARIOS; do
            docker rm -f "e2e-$RUN_ID-cold-source-$sc" "e2e-$RUN_ID-cold-target-$sc" >/dev/null 2>&1 || true
            rm -rf "$WORK/handoff-$sc"
        done
    fi
}
trap cleanup EXIT

log "run_id=$RUN_ID scenarios=$SCENARIOS"
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
docker run --rm -v "$ROOT:/src:ro" -v "$SEED:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
    "$GO_IMAGE" go build -buildvcs=false -trimpath -o /out/idleleo ./cmd/idleleo || {
    log "FATAL: idleleo build failed"
    exit 2
}
log "idleleo_sha256=$(host_sha256 "$SEED/idleleo")"

log "building the local TLS target"
docker run --rm -v "$SUITE/drivers:/src:ro" -v "$SEED:/out" -w /src \
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
cp "$XRAY_BIN" "$SEED/xray"
chmod 0755 "$SEED/xray"
log "xray_sha256=$(host_sha256 "$SEED/xray") arch=$ARCH"

# --- offline Nginx artifact cache -------------------------------------------
# TLS/relay/multi install a managed Nginx front. Seed the same verified cache
# the differential runner uses so a GitHub hiccup cannot decide a restore.
NGINX_BUILD="${E2E_NGINX_BUILD:-2026.10.15.7679}"
case "$ARCH" in
    amd64) NGINX_ARCH=x86 ;;
    arm64) NGINX_ARCH=arm ;;
    *) NGINX_ARCH="" ;;
esac
NGINX_ASSET="xray-nginx-custom-${NGINX_ARCH}.tar.gz"
NGINX_CACHE="${E2E_NGINX_CACHE:-$HOME/.cache/xray-audit/nginx/$NGINX_BUILD}"
NGINX_CACHE_ENVS=()

seed_nginx_cache() {
    local dest="$SEED/nginx"
    local manifest="$NGINX_CACHE/release-manifest.json"
    local tarball="$NGINX_CACHE/$NGINX_ASSET"
    [[ -n "$NGINX_ARCH" ]] || { log "nginx_cache=miss reason=unsupported-arch arch=$ARCH"; return 1; }
    mkdir -p "$dest" "$NGINX_CACHE"
    if [[ ! -f "$manifest" || ! -f "$tarball" ]]; then
        local base="https://github.com/hello-yunshu/Xray_bash_onekey_Nginx/releases/download/v$NGINX_BUILD"
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
            -o "$manifest.tmp" "$base/release-manifest.json" && mv "$manifest.tmp" "$manifest" || {
            rm -f "$manifest.tmp"; log "nginx_cache=miss reason=manifest-download-failed"; return 1; }
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 \
            -o "$tarball.tmp" "$base/$NGINX_ASSET" && mv "$tarball.tmp" "$tarball" || {
            rm -f "$tarball.tmp"; log "nginx_cache=miss reason=asset-download-failed"; return 1; }
    fi
    local want_sha got_sha
    want_sha=$(python3 - "$manifest" "$NGINX_ARCH" "$NGINX_ASSET" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
entry = next((a for a in data.get("assets") or []
              if a.get("arch") == sys.argv[2] and a.get("filename") == sys.argv[3]), None)
print((entry or {}).get("sha256") or "")
PY
)
    got_sha=$(host_sha256 "$tarball" 2>/dev/null || true)
    if [[ -z "$want_sha" || "$got_sha" != "$want_sha" ]]; then
        log "nginx_cache=miss reason=verify-failed"
        return 1
    fi
    cp "$manifest" "$dest/release-manifest.json"
    cp "$tarball" "$dest/$NGINX_ASSET"
    printf '{"nginx_build_online_version":"%s"}\n' "$NGINX_BUILD" >"$dest/versions.json"
    NGINX_CACHE_ENVS=(-e IDLELEO_NGINX_CACHE=/seed/nginx -e E2E_NGINX_BUILD="$NGINX_BUILD")
    log "nginx_cache=hit build=$NGINX_BUILD arch=$NGINX_ARCH tarball_sha256=$want_sha"
}

if seed_nginx_cache; then :; else
    NGINX_CACHE_ENVS=()
    log "nginx_cache=miss (TLS/relay/multi need a managed front)"
fi

start_node() { # start_node <name> <scenario> <evidence-dir>
    local name=$1 sc=$2 out=$3
    docker rm -f "$name" >/dev/null 2>&1 || true
    # shellcheck disable=SC2046
    docker run -d --name "$name" --hostname "$name" \
        --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
        $(cgroup_mount_args) \
        -v "$ROOT:/src:ro" -v "$SEED:/seed:ro" -v "$out:/out" \
        -v "$WORK/handoff-$sc:/handoff" \
        --label "e2e.run=$RUN_ID" --label "e2e.scenario=COLD-RESTORE-$sc" \
        "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null || return 1
}

start_tls_target() { # start_tls_target <name> <domain>
    local name=$1 domain=$2
    docker exec -e E2E_DOMAIN="$domain" "$name" bash -c '
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
    '
}

# Each container gets its own self-signed pair, so a restore must replace the
# target certificate with the source certificate (byte identity is asserted).
seed_cert() { # seed_cert <name> <domain>
    docker exec -e E2E_DOMAIN="$2" "$1" bash -c '
    mkdir -p /etc/idleleo/cert
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3 \
        -subj "/CN=$E2E_DOMAIN" -addext "subjectAltName=DNS:$E2E_DOMAIN" \
        -keyout /etc/idleleo/cert/xray.key -out /etc/idleleo/cert/xray.crt >/dev/null 2>&1
    chmod 0600 /etc/idleleo/cert/xray.key
    chmod 0644 /etc/idleleo/cert/xray.crt
    ' >>"$EVID/run.log" 2>&1
}

install_node() { # install_node <name> <scenario> <round> <evidence-dir> [relay-listen-port]
    local name=$1 sc=$2 round=$3 out=$4
    local relay_port="${5:-443}"
    local -a args=()
    local profile=tls domain="$SC_DOMAIN"
    case "$sc" in
        reality)
            profile=reality
            domain="$DOMAIN"
            args=(--mode reality --domain "$DOMAIN" --target "$TARGET" --port 443)
            ;;
        tls)
            args=(--mode tls --transport ws --domain "$SC_DOMAIN" \
                --cert /etc/idleleo/cert/xray.crt --cert-key /etc/idleleo/cert/xray.key \
                --port 9000 --public-port 443)
            ;;
        multi)
            args=(--mode tls --transport ws+grpc+xhttp --domain "$SC_DOMAIN" \
                --cert /etc/idleleo/cert/xray.crt --cert-key /etc/idleleo/cert/xray.key \
                --port 9000 --public-port 443)
            ;;
        relay)
            profile=relay
            args=(--role relay --target "$RELAY_TARGET" --listen-port "$relay_port" --listen 0.0.0.0)
            ;;
    esac
    local -a exec_env=(-e E2E_OUT=/out/install -e E2E_PROFILE="$profile" \
        -e E2E_SCENARIO="COLD-$sc" -e E2E_DOMAIN="$domain" -e E2E_ROUND="$round")
    if [[ "$sc" == "reality" ]]; then
        exec_env+=(-e E2E_TARGET="$TARGET" -e E2E_PORT=443)
    fi
    docker exec "${NGINX_CACHE_ENVS[@]+"${NGINX_CACHE_ENVS[@]}"}" \
        "${exec_env[@]}" "$name" bash /src/tests/e2e-diff/drivers/go_install.sh \
        --binary /usr/local/bin/xray "${args[@]}" --container >>"$EVID/run.log" 2>&1
}

run_driver() { # run_driver <name> <mode> <scenario> <evidence-dir>
    docker exec -e E2E_OUT=/out/driver -e E2E_DOMAIN="$DOMAIN" \
        -e E2E_SCENARIO="$3" -e E2E_HANDOFF=/handoff \
        "$1" bash /src/tests/e2e-diff/drivers/go_coldrestore.sh "$2" >>"$EVID/run.log" 2>&1
}

write_report() { # write_report <scenario> <evid> <source_rc> <target_rc>
    python3 - "$2" "$RUN_ID" "$IMAGE_ID" "$(git -C "$ROOT" rev-parse HEAD)" \
        "$3" "$4" "$WORK/handoff-$1/archive.sha256" "$1" <<'PY'
import json
import os
import sys

evid, run_id, image_id, commit, source_rc, target_rc, archive_sha, scenario = sys.argv[1:9]
report = {'schemaVersion': 1, 'runId': run_id, 'scenario': scenario, 'commit': commit,
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

md = ['# Cold restore real-machine evidence (%s)' % scenario, '',
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
}

run_scenario() { # run_scenario <scenario>
    local sc=$1
    local ev="$EVID/$sc"
    local source="e2e-$RUN_ID-cold-source-$sc" target="e2e-$RUN_ID-cold-target-$sc"
    mkdir -p "$ev/source" "$ev/target" "$WORK/handoff-$sc"

    log "[$sc] source: starting $source"
    if ! start_node "$source" "$sc" "$ev/source"; then
        log "[$sc] FATAL: source container failed"
        return 2
    fi
    if [[ "$sc" == "reality" ]]; then
        start_tls_target "$source" "$DOMAIN" || { log "[$sc] FATAL: source TLS target failed"; return 2; }
    elif [[ "$sc" == "tls" || "$sc" == "multi" ]]; then
        seed_cert "$source" "$SC_DOMAIN" || { log "[$sc] FATAL: source certificate failed"; return 2; }
    fi
    log "[$sc] source: installing Go manager"
    if ! install_node "$source" "$sc" 1 "$ev/source"; then
        log "[$sc] FATAL: source install failed"
        return 2
    fi
    log "[$sc] source: driver"
    run_driver "$source" source "$sc" "$ev/source"
    local source_rc=$?
    log "[$sc] source_driver_rc=$source_rc"
    log "[$sc] source: destroying $source"
    docker rm -f "$source" >/dev/null 2>&1 || true

    log "[$sc] target: starting $target"
    if ! start_node "$target" "$sc" "$ev/target"; then
        log "[$sc] FATAL: target container failed"
        return 2
    fi
    if [[ "$sc" == "reality" ]]; then
        start_tls_target "$target" "$DOMAIN" || { log "[$sc] FATAL: target TLS target failed"; return 2; }
    elif [[ "$sc" == "tls" || "$sc" == "multi" ]]; then
        seed_cert "$target" "$SC_DOMAIN" || { log "[$sc] FATAL: target certificate failed"; return 2; }
    fi
    log "[$sc] target: installing a fresh Go manager"
    # The target relay starts on a different listen port, so the restore is
    # proven by an observable port change instead of a byte comparison.
    local target_port=443
    [[ "$sc" == "relay" ]] && target_port=8443
    if ! install_node "$target" "$sc" 1 "$ev/target" "$target_port"; then
        log "[$sc] FATAL: target install failed"
        return 2
    fi
    log "[$sc] target: driver"
    run_driver "$target" target "$sc" "$ev/target"
    local target_rc=$?
    log "[$sc] target_driver_rc=$target_rc"

    write_report "$sc" "$ev" "$source_rc" "$target_rc"
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$target" >/dev/null 2>&1 || true
    [[ $source_rc -eq 0 && $target_rc -eq 0 ]]
}

overall=0
for sc in $SCENARIOS; do
    run_scenario "$sc" || overall=1
done

python3 - "$EVID" "$RUN_ID" <<'PY'
import json
import os
import sys

evid, run_id = sys.argv[1], sys.argv[2]
scenarios = {}
for name in sorted(os.listdir(evid)):
    path = os.path.join(evid, name, 'run.json')
    if os.path.isdir(os.path.join(evid, name)) and os.path.exists(path):
        data = json.load(open(path))
        scenarios[name] = {
            'sourceDriverExit': data.get('sourceDriverExit'),
            'targetDriverExit': data.get('targetDriverExit'),
            'archiveSHA256': data.get('archiveSHA256', ''),
        }
report = {'schemaVersion': 1, 'runId': run_id, 'scenarios': scenarios}
json.dump(report, open(os.path.join(evid, 'run.json'), 'w'), indent=2, sort_keys=True)
PY

log "evidence=${EVID#"$ROOT/"}"
if [[ $overall -ne 0 ]]; then
    log "RESULT: FAIL"
    exit 1
fi
log "RESULT: PASS"
exit 0
