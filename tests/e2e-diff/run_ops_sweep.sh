#!/usr/bin/env bash
# OPS sweep: Go-side checks for CLI operations that the differential matrix
# lists but does not drive.
#
# This is single-sided evidence: it proves the Go command works against a real
# Go-installed runtime. It does not re-run the interactive Bash menu, so the
# matrix verdict for these rows stays "must-match" until a Bash driver exists.
#
# metadata export/import reads the Go metadata store, which only exists on a
# Go-managed root; that is the tree this sweep installs.
#
# Runs one container: Go install -> CLI operations -> uninstall. Every step
# records rc, stdout, stderr and, for --json commands, whether the output
# parses.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ROOT
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-ops-$(date +%Y%m%d-%H%M)-$(git -C "$ROOT" rev-parse --short HEAD)}"
EVID="$SUITE/evidence/$RUN_ID"
WORK="/tmp/e2e-$RUN_ID"
IMAGE_TAG="${E2E_IMAGE_TAG:-idleleo-e2e:24.04}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
DOMAIN="${E2E_DOMAIN:-example.com}"
PASS=0
FAIL=0

source "$ROOT/tests/go-parity/lib/docker_common.sh"

mkdir -p "$EVID" "$WORK/seed/cert"
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$EVID/run.log"; }
sha() { host_sha256 "$1"; }
assert() { # assert <0|1> <message>
    if [ "$1" -eq 0 ]; then
        PASS=$((PASS + 1)); printf 'PASS\t%s\n' "$2" | tee -a "$EVID/assertions.txt"
    else
        FAIL=$((FAIL + 1)); printf 'FAIL\t%s\n' "$2" | tee -a "$EVID/assertions.txt"
    fi
}

log "building idleleo"
docker run --rm -v "$ROOT:/src:ro" -v "$WORK/seed:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
    "$GO_IMAGE" bash -c 'go build -buildvcs=false -trimpath -o /out/idleleo ./cmd/idleleo &&
        go build -buildvcs=false -trimpath -o /out/idleleo-recover ./cmd/idleleo-recover' || {
    log "FATAL: build failed"; exit 2
}

ARCH=$(docker_arch) || exit 2
if [[ -x "$ROOT/tests/go-parity/.cache/a2/xray" ]]; then
    cp "$ROOT/tests/go-parity/.cache/a2/xray" "$WORK/seed/xray"
else
    ensure_xray_bin "$ARCH" >/dev/null || { log "FATAL: xray unavailable"; exit 2; }
    cp "$(ensure_xray_bin "$ARCH")" "$WORK/seed/xray"
fi
chmod 0755 "$WORK/seed/xray" "$WORK/seed/idleleo" "$WORK/seed/idleleo-recover"

docker run --rm -v "$WORK/seed:/seed" "$IMAGE_TAG" bash -c \
    "openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=$DOMAIN' \
     -addext 'subjectAltName=DNS:$DOMAIN' \
     -keyout /seed/cert/xray.key -out /seed/cert/xray.crt >/dev/null 2>&1" || {
    log "FATAL: certificate generation failed"; exit 2
}

C="e2e-$RUN_ID-server"
ORIGIN="e2e-$RUN_ID-origin"
NET="e2e-$RUN_ID-net"
docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$C" "$ORIGIN" >/dev/null 2>&1 || true

# OPS-23 (speedtest) and OPS-24 (geodata-refresh) need a reachable HTTP origin.
# It is a local nginx that serves the real GeoData pair from the audit cache and
# a fixed 1 MiB payload for the throughput probe; the Go code paths under test
# are unchanged, so this is a real network run rather than a stub.
GEO_SRC="${E2E_GEO_DIR:-$HOME/.cache/xray-audit/share/xray-bin}"
mkdir -p "$WORK/origin"
dd if=/dev/zero of="$WORK/origin/__down" bs=1048576 count=1 status=none
for name in geoip.dat geosite.dat; do
    [[ -f "$GEO_SRC/$name" ]] || {
        log "FATAL: real GeoData $GEO_SRC/$name is missing (set E2E_GEO_DIR)"; exit 2
    }
    cp "$GEO_SRC/$name" "$WORK/origin/$name"
done
( cd "$WORK/origin" && shasum -a 256 geoip.dat >geoip.dat.sha256sum \
    && shasum -a 256 geosite.dat >geosite.dat.sha256sum )
log "origin=nginx:1.27 geoip_sha256=$(awk '{print $1}' "$WORK/origin/geoip.dat.sha256sum")"
# shellcheck disable=SC2046
docker run -d --name "$C" --hostname "$C" --network "$NET" \
    --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
    $(cgroup_mount_args) \
    -v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$EVID:/out" \
    "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null || {
    log "FATAL: container start failed"; exit 2
}
for _ in $(seq 1 30); do
    [ "$(docker exec "$C" systemctl is-system-running 2>/dev/null)" = "running" ] && break
    sleep 1
done

docker run -d --name "$ORIGIN" --network "$NET" \
    -v "$WORK/origin:/usr/share/nginx/html:ro" nginx:1.27 >/dev/null || {
    log "FATAL: origin container start failed"; exit 2
}
for _ in $(seq 1 30); do
    docker exec "$C" curl -fsS "http://$ORIGIN/geoip.dat" -o /dev/null 2>/dev/null && break
    sleep 1
done
docker exec "$C" curl -fsS "http://$ORIGIN/geoip.dat" -o /dev/null 2>/dev/null || {
    log "FATAL: origin is not reachable from the test container"; exit 2
}

docker exec "$C" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
docker exec "$C" install -m 0755 /seed/idleleo-recover /usr/local/bin/idleleo-recover
docker exec "$C" install -m 0755 /seed/xray /usr/local/bin/xray
ENVS=(-e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY)

# The matrix rows below operate on a Go-managed root: metadata-driven commands
# refuse to invent state on a legacy Bash tree (correctly), so a Bash install
# would only measure the refusal, not the operation.
log "go install (reality)"
docker exec "${ENVS[@]}" "$C" /usr/local/bin/idleleo xray install \
    --binary /usr/local/bin/xray --mode reality --domain "$DOMAIN" \
    --target www.cloudflare.com --port 443 --container --json \
    >"$EVID/go-install.json" 2>"$EVID/go-install.err"
assert "$([ $? -eq 0 ] && echo 0 || echo 1)" "go install exits 0"

config_sha() {
    docker exec "$C" sha256sum /etc/idleleo/conf/xray/config.json 2>/dev/null | awk '{print $1}'
}
active_xray() {
    docker exec "$C" systemctl is-active xray 2>/dev/null | head -1
}
snap() { # snap <dir>
    mkdir -p "$EVID/$1"
    docker exec "$C" sh -c '
        jq -S . /etc/idleleo/conf/xray/config.json 2>/dev/null
    ' >"$EVID/$1/config.sorted.json"
    config_sha >"$EVID/$1/config.sha"
    active_xray >"$EVID/$1/active.txt"
}

# run_op <id> <json:0|1> <args...>
run_op() {
    local id=$1 json=$2; shift 2
    local out="$EVID/ops/$id"
    mkdir -p "$out"
    docker exec "${ENVS[@]}" "$C" /usr/local/bin/idleleo "$@" \
        >"$out/out.txt" 2>"$out/err.txt"
    local rc=$?
    echo "$rc" >"$out/rc"
    echo "$*" >"$out/argv"
    local jq_ok=1
    if [ "$json" = "1" ]; then
        jq -e . "$out/out.txt" >/dev/null 2>&1 && jq_ok=0
        echo "$jq_ok" >"$out/json.rc"
    fi
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "$id runs (rc=$rc): $*"
    if [ "$json" = "1" ]; then
        assert "$jq_ok" "$id returns parseable JSON"
    fi
    return 0
}

# run_refusal <id> <expected-rc> <needle> <args...>
# Records a documented refusal: the command must exit with the expected code
# and explain why. Used where the runtime lacks the prerequisite (stats API).
run_refusal() {
    local id=$1 want=$2 needle=$3; shift 3
    local out="$EVID/ops/$id"
    mkdir -p "$out"
    docker exec "${ENVS[@]}" "$C" /usr/local/bin/idleleo "$@" \
        >"$out/out.txt" 2>"$out/err.txt"
    local rc=$?
    echo "$rc" >"$out/rc"
    echo "$*" >"$out/argv"
    assert "$([ "$rc" -eq "$want" ] && echo 0 || echo 1)" "$id refuses with rc=$want (got $rc): $*"
    assert "$(grep -q "$needle" "$out/err.txt" && echo 0 || echo 1)" "$id explains the missing prerequisite"
    return 0
}

snap pre
log "running OPS sweep"

# --service takes the apply hook, not a unit name: the change engine runs
# "<hook> apply" after committing the config.
HOOK=/usr/local/bin/e2e-service-apply
docker exec "$C" sh -c "printf '#!/bin/sh\nexec systemctl restart xray\n' >$HOOK && chmod 0755 $HOOK"

run_op OPS-01 1 xray user list --path /etc/idleleo/conf/xray/config.json --json
run_op OPS-02 1 xray user add --sandbox / --email e2e@example.com --uuid 11111111-2222-3333-4444-555555555555 \
    --validator /usr/local/bin/xray --service "$HOOK" --container --json
run_op OPS-03 1 xray user remove --sandbox / --email e2e@example.com \
    --validator /usr/local/bin/xray --service "$HOOK" --container --json
run_op OPS-11 1 show --json
run_op OPS-12 0 service logs --unit xray --lines 5
run_op OPS-13 0 service logs --unit nginx --lines 5
# stats only answers once the loopback API is enabled; enabling it is itself
# part of the operator flow these rows describe.
run_op OPS-14a 1 xray api enable --sandbox / --validator /usr/local/bin/xray --service "$HOOK" --container --json
# The install does not configure stats/api.listen, so these rows are refusals:
# the command must say exactly that instead of returning an empty result.
run_refusal OPS-14 3 "stats/api.listen is not configured" stats --json
run_refusal OPS-20 3 "stats/api.listen is not configured" stats --json
run_op OPS-15 0 service restart --container
assert "$([ "$(active_xray)" = "active" ] && echo 0 || echo 1)" "OPS-15 xray active after restart"
run_op OPS-18 1 tcp status --json
run_op OPS-22 1 xray logs clean --yes --container --json
# OPS-23/24 read the local origin started above. Both commands keep their real
# network path (HTTP GET), so the assertions cover transport and verification,
# not just flag parsing.
run_op OPS-23 1 speedtest --server "http://$ORIGIN" --bytes 1048576 --samples 1 --json
assert "$(grep -q '"downMbps"' "$EVID/ops/OPS-23/out.txt" && echo 0 || echo 1)" \
    "OPS-23 reports a measured throughput"
assert "$(grep -q '"bytes": 1048576' "$EVID/ops/OPS-23/out.txt" && echo 0 || echo 1)" \
    "OPS-23 read the full 1 MiB payload"
run_op OPS-24a 1 schedule install --interval 3600 --geodata-url "http://$ORIGIN" --container --json
# The sweep restarts xray many times within seconds, so systemd's default
# start-rate limit (5 starts / 10s) can trip before the job's own restart. That
# is a harness artefact, not a product default: clearing the transient limit
# lets the geodata job perform its real restart. Production units are unchanged.
docker exec "$C" systemctl reset-failed xray >/dev/null 2>&1 || true
printf 'note=systemd start-limit state cleared before the geodata restart\n' \
    >>"$EVID/ops/OPS-24a/out.txt"
run_op OPS-24 1 schedule run --job geodata-refresh --json
assert "$(grep -q '"result": "ok"' "$EVID/ops/OPS-24/out.txt" && echo 0 || echo 1)" \
    "OPS-24 geodata-refresh reports ok"
for name in geoip.dat geosite.dat; do
    want=$(awk '{print $1}' "$WORK/origin/$name.sha256sum")
    got=$(docker exec "$C" sha256sum "/etc/idleleo/share/xray/$name" 2>/dev/null | awk '{print $1}')
    assert "$([ "$want" = "$got" ] && echo 0 || echo 1)" \
        "OPS-24 wrote verified $name (sha256=$got)"
done
# OPS-16 is the read-only certificate view. It must report the real lifetime of
# the installed certificate and confirm renewal is not due, without contacting a
# CA (a dry run never writes or downloads).
docker exec "$C" sh -c "mkdir -p /etc/idleleo/cert && openssl req -x509 -newkey rsa:2048 -nodes \
    -days 3650 -subj '/CN=$DOMAIN' -addext 'subjectAltName=DNS:$DOMAIN' \
    -keyout /etc/idleleo/cert/xray.key -out /etc/idleleo/cert/xray.crt" >/dev/null 2>&1
run_op OPS-16 1 xray cert renew --dry-run --domain "$DOMAIN" --webroot /etc/idleleo/conf \
    --cert-out /etc/idleleo/cert/xray.crt --key-out /etc/idleleo/cert/xray.key --json
assert "$(grep -q '"notAfter"' "$EVID/ops/OPS-16/out.txt" && echo 0 || echo 1)" \
    "OPS-16 reports the certificate expiry"
assert "$(grep -q '"due": false' "$EVID/ops/OPS-16/out.txt" && echo 0 || echo 1)" \
    "OPS-16 reports renewal is not due"
run_op OPS-25 0 metadata export --out /tmp/e2e-metadata.json
run_op OPS-29 1 rill status --json
run_op OPSS-01 1 schedule status --json
run_op OPS-17a 1 update status --json
# Import never overwrites an existing single source of truth; the successful
# Bash-tree import (where install_config.json is the only metadata) is measured
# by run_r1_upgrade.sh's R2 path.
run_refusal OPS-26 3 "already exists" metadata import --from install_config.json --container
run_op OPS-28 1 xray uninstall --purge --container --json
assert "$([ "$(active_xray)" != "active" ] && echo 0 || echo 1)" "OPS-28 xray stops after uninstall"
assert "$(docker exec "$C" sh -c '[ ! -e /etc/idleleo/conf/xray/config.json ] && echo 0 || echo 1')" \
    "OPS-28 runtime config is removed by --purge"

log "run_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "$PASS PASS / $FAIL FAIL"
[[ "${E2E_KEEP:-0}" == "1" ]] || {
    docker rm -f "$C" "$ORIGIN" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
}
[ "$FAIL" -eq 0 ]
