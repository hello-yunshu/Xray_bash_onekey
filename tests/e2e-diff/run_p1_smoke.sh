#!/usr/bin/env bash
# P1 smoke runner: M1 (Reality/raw) and M4 (TLS/ws, self-signed) on both sides.
#
# Produces evidence/<run-id>/p1/{M1,M4}/{bash,go}/ and p1/smoke.md.
# No business verdict is produced here; this run proves the harness itself.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ROOT
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-$(date +%Y%m%d-%H%M)-$(git -C "$ROOT" rev-parse --short HEAD)}"
EVID="$SUITE/evidence/$RUN_ID/p1"
WORK="${E2E_WORK:-/tmp/e2e-$RUN_ID}"
IMAGE_TAG="${E2E_IMAGE_TAG:-idleleo-e2e:24.04}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
NET="e2e-$RUN_ID"
DOMAIN="${E2E_DOMAIN:-example.com}"
TARGET="${E2E_TARGET:-www.cloudflare.com}"
# Docker's embedded DNS forwards to the router and intermittently returns
# SERVFAIL for the GitHub hosts the installers download from. Resolve them with
# the host resolver up front and pin them via --add-host. E2E_GITHUB_IP
# overrides the github.com address when the local resolver returns a blackholed
# one. This only fixes name resolution for the test environment; it does not
# change either side's download logic.
GITHUB_IP="${E2E_GITHUB_IP:-}"

source "$ROOT/tests/go-parity/lib/docker_common.sh"

mkdir -p "$EVID" "$WORK/seed/cert" "$WORK/secret"
log() { printf '%s\n' "$*" | tee -a "$EVID/run.log"; }

PIN_ARGS=()
pin_host() {
    local h=$1 ip
    while read -r ip; do
        [[ -n "$ip" ]] && PIN_ARGS+=(--add-host "$h:$ip")
    done < <(dscacheutil -q host -a name "$h" 2>/dev/null | awk '/^ip_address:/{print $2}')
}
for h in raw.githubusercontent.com cdn.jsdelivr.net \
         objects.githubusercontent.com release-assets.githubusercontent.com; do
    pin_host "$h"
done
if [[ -n "$GITHUB_IP" ]]; then
    PIN_ARGS+=(--add-host "github.com:$GITHUB_IP")
else
    pin_host github.com
fi
log "host_pins=${PIN_ARGS[*]:-none}"

cleanup() {
    if [[ "${E2E_KEEP:-0}" != "1" ]]; then
        docker ps -aq --filter "label=e2e.run=$RUN_ID" | xargs -r docker rm -f >/dev/null 2>&1 || true
        docker network rm "$NET" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# --- image -----------------------------------------------------------------
log "building $IMAGE_TAG"
docker build -q -t "$IMAGE_TAG" -f "$SUITE/image/Dockerfile" "$SUITE/image" >/dev/null || {
    log "FATAL: image build failed"
    exit 2
}
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE_TAG")
log "image_id=$IMAGE_ID"

# --- go binary -------------------------------------------------------------
log "building idleleo from $ROOT (golang:1.27.4)"
docker run --rm -v "$ROOT:/src:ro" -v "$WORK/seed:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
    "$GO_IMAGE" go build -buildvcs=false -trimpath -o /out/idleleo ./cmd/idleleo || {
    log "FATAL: idleleo build failed"
    exit 2
}
log "idleleo_sha256=$(host_sha256 "$WORK/seed/idleleo")"

# --- xray binary -----------------------------------------------------------
# Seed the version pinned by the release manifest (the a2 cache carries it) so
# neither side re-downloads a newer Xray mid-install and both sides run the
# exact same binary. Fall back to docker_common's resolver if absent.
ARCH=$(docker_arch) || exit 2
if [[ -x "$ROOT/tests/go-parity/.cache/a2/xray" ]]; then
    XRAY_BIN="$ROOT/tests/go-parity/.cache/a2/xray"
    XRAY_SOURCE="a2-cache"
else
    XRAY_BIN=$(ensure_xray_bin "$ARCH") || exit 2
    XRAY_SOURCE="ensure_xray_bin"
fi
cp "$XRAY_BIN" "$WORK/seed/xray"
chmod 0755 "$WORK/seed/xray"
log "xray_sha256=$(host_sha256 "$WORK/seed/xray") arch=$ARCH source=$XRAY_SOURCE"

# --- self-signed certificate shared by both sides --------------------------
docker run --rm -v "$WORK/seed:/seed" "$IMAGE_TAG" bash -c \
    "openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=$DOMAIN' \
     -addext 'subjectAltName=DNS:$DOMAIN' \
     -keyout /seed/cert/xray.key -out /seed/cert/xray.crt >/dev/null 2>&1" || {
    log "FATAL: certificate generation failed"
    exit 2
}
log "cert_sha256=$(host_sha256 "$WORK/seed/cert/xray.crt")"

docker network create "$NET" >/dev/null || { log "FATAL: network create failed"; exit 2; }

start_server() {
    local name=$1 scenario=$2 side=$3
    docker rm -f "$name" >/dev/null 2>&1 || true
    mkdir -p "$EVID/$scenario/$side"
    # shellcheck disable=SC2046
    docker run -d --name "$name" --hostname "$name" --network "$NET" \
        --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
        "${PIN_ARGS[@]+"${PIN_ARGS[@]}"}" \
        $(cgroup_mount_args) \
        -v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$EVID/$scenario/$side:/out" \
        --label "e2e.run=$RUN_ID" --label "e2e.scenario=$scenario" --label "e2e.side=$side" \
        "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null || return 1
}

run_bash_side() {
    local scenario=$1 profile=$2 arg=$3 name="e2e-$RUN_ID-$1-bash"
    log "[$scenario/bash] starting $name"
    start_server "$name" "$scenario" bash || { log "[$scenario/bash] container start failed"; return 1; }
    docker exec -e E2E_OUT=/out -e E2E_PROFILE="$profile" -e E2E_ARG="$arg" \
        -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET" -e E2E_PORT=443 \
        "$name" bash /src/tests/e2e-diff/drivers/bash_install.sh >>"$EVID/run.log" 2>&1
    local rc=$?
    log "[$scenario/bash] install rc=$rc"
    if [[ $rc -eq 0 ]]; then
        bash "$SUITE/collect/l4.sh" "$name" "e2e-$RUN_ID-$scenario-bash-client" \
            "$IMAGE_TAG" "$NET" "$profile" "$DOMAIN" "$WORK/seed/xray" \
            "$WORK/secret/$scenario-bash" "$EVID/$scenario/bash/L4" >>"$EVID/run.log" 2>&1
        log "[$scenario/bash] l4 rc=$?"
        docker rm -f "e2e-$RUN_ID-$scenario-bash-client" >/dev/null 2>&1 || true
    else
        mkdir -p "$EVID/$scenario/bash/L4"
        printf 'install rc=%d; L4 skipped\n' "$rc" >"$EVID/$scenario/bash/L4/connectivity.txt"
    fi
    return 0
}

run_go_side() {
    local scenario=$1 profile=$2 name="e2e-$RUN_ID-$1-go"
    shift 2
    log "[$scenario/go] starting $name"
    start_server "$name" "$scenario" go || { log "[$scenario/go] container start failed"; return 1; }
    docker exec -e E2E_OUT=/out -e E2E_PROFILE="$profile" \
        "$name" bash /src/tests/e2e-diff/drivers/go_install.sh "$@" >>"$EVID/run.log" 2>&1
    local rc=$?
    log "[$scenario/go] install rc=$rc"
    if [[ $rc -eq 0 ]]; then
        bash "$SUITE/collect/l4.sh" "$name" "e2e-$RUN_ID-$scenario-go-client" \
            "$IMAGE_TAG" "$NET" "$profile" "$DOMAIN" "$WORK/seed/xray" \
            "$WORK/secret/$scenario-go" "$EVID/$scenario/go/L4" >>"$EVID/run.log" 2>&1
        log "[$scenario/go] l4 rc=$?"
        docker rm -f "e2e-$RUN_ID-$scenario-go-client" >/dev/null 2>&1 || true
    else
        mkdir -p "$EVID/$scenario/go/L4"
        printf 'install rc=%d; L4 skipped\n' "$rc" >"$EVID/$scenario/go/L4/connectivity.txt"
    fi
    return 0
}

# Go argv uses the same inputs as the Bash answers (domain/target/port) so L2
# compares like with like. `--binary` is mandatory (xrayInstall rejects an
# empty value), verified against `idleleo xray install --help`.
# E2E_ONLY="M4/go" reruns a single side into the existing evidence dir after a
# HARNESS-ERROR (transient download failure); omit it for a full run.
ONLY="${E2E_ONLY:-}"
want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }
want M1/bash && run_bash_side M1 reality -2
want M1/go && run_go_side M1 reality --binary /usr/local/bin/xray --mode reality \
    --domain "$TARGET" --target "$TARGET" --port 443 --container
want M4/bash && run_bash_side M4 tls -1
# --port is the loopback inbound port behind nginx; --public-port is the nginx
# listener. Using --port 443 for both makes xray and nginx fight over :443.
want M4/go && run_go_side M4 tls --binary /usr/local/bin/xray --mode tls --transport ws \
    --domain "$DOMAIN" --cert /etc/idleleo/cert/xray.crt \
    --cert-key /etc/idleleo/cert/xray.key --port 9000 --public-port 443 --container

# --- normalize (twice per artifact, prove stability) -----------------------
normalize_all() {
    local dir=$1
    mkdir -p "$dir/normalized"
    for artifact in "$dir/install.log" "$dir/manifest.json" "$dir/runtime.json" \
                    "$dir/config/config.sanitized.json"; do
        [[ -f "$artifact" ]] || continue
        base=$(basename "$artifact")
        python3 "$SUITE/collect/normalize.py" "$artifact" "$dir/normalized/$base.1" >/dev/null 2>&1 || continue
        python3 "$SUITE/collect/normalize.py" "$artifact" "$dir/normalized/$base.2" >/dev/null 2>&1 || continue
        if cmp -s "$dir/normalized/$base.1" "$dir/normalized/$base.2"; then
            rm -f "$dir/normalized/$base.2"
        else
            log "NORMALIZE-UNSTABLE $artifact"
        fi
    done
}

for scenario in M1 M4; do
    for side in bash go; do
        normalize_all "$EVID/$scenario/$side"
    done
done

# --- run.json + smoke.md ---------------------------------------------------
python3 - "$EVID" "$RUN_ID" "$IMAGE_ID" "$(git -C "$ROOT" rev-parse HEAD)" <<'PY'
import json
import os
import sys

evid, run_id, image_id, commit = sys.argv[1:5]
sides = {}
for scenario in ('M1', 'M4'):
    for side in ('bash', 'go'):
        base = os.path.join(evid, scenario, side)
        rc_path = os.path.join(base, 'rc.txt')
        try:
            rc = int(open(rc_path).read().strip())
        except (OSError, ValueError):
            rc = None
        conn_path = os.path.join(base, 'L4', 'connectivity.json')
        try:
            conn = json.load(open(conn_path))
        except (OSError, json.JSONDecodeError):
            conn = None
        sides['%s/%s' % (scenario, side)] = {
            'installExit': rc,
            'manifest': os.path.exists(os.path.join(base, 'manifest.json')),
            'runtime': os.path.exists(os.path.join(base, 'runtime.json')),
            'l4': conn,
        }
json.dump({'schemaVersion': 1, 'runId': run_id, 'commit': commit,
           'imageId': image_id, 'sides': sides},
          open(os.path.join(evid, 'run.json'), 'w'), indent=2, sort_keys=True)

rows = ['# P1 smoke', '',
        'run-id: `%s`' % run_id, '',
        '| scenario | side | install rc | manifest | runtime | L4 |',
        '|---|---|---|---|---|---|']
for key in sorted(sides):
    item = sides[key]
    scenario, side = key.split('/')
    l4 = item['l4']
    if l4 is None:
        l4_text = 'n/a'
    else:
        l4_text = 'PASS' if l4.get('ok') else 'FAIL (%s)' % l4.get('reason', 'unknown')
    rows.append('| %s | %s | %s | %s | %s | %s |' % (
        scenario, side, item['installExit'],
        'yes' if item['manifest'] else 'missing',
        'yes' if item['runtime'] else 'missing',
        l4_text))
rows += ['', 'L4 uses a real client container (separate netns) and one proxied',
         'HTTP request to http://example.com/; the server config blackholes',
         'private/loopback targets, so a loopback origin cannot be used.']
open(os.path.join(evid, 'smoke.md'), 'w').write('\n'.join(rows) + '\n')
PY

log "evidence=$EVID"
log "done"
