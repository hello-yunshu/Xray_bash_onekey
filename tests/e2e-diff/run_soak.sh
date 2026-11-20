#!/usr/bin/env bash
# 30-minute soak for a fresh Reality install.
#
# One privileged systemd container, a real Go install, then 30 one-minute
# samples. Every sample is a live observation: unit active, config test, the
# inbound port still listening, no unit restart, RSS under the cap. Any failed
# sample is a BLOCKER with its iteration index; a dead container or a missing
# observation is a HARNESS-ERROR.
#
# Env:
#   E2E_SOAK_ITERATIONS   samples (default 30)
#   E2E_SOAK_INTERVAL     seconds between samples (default 60)
#   E2E_SOAK_RSS_MB       RSS cap in MiB (default 512)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-soak-$(date +%Y%m%d-%H%M)-$(git -C "$ROOT" rev-parse --short HEAD)}"
EVID="$SUITE/evidence/$RUN_ID/soak"
WORK="/tmp/e2e-$RUN_ID"
IMAGE_TAG="${E2E_IMAGE_TAG:-idleleo-e2e:24.04}"
IMAGE_DOCKERFILE="${E2E_IMAGE_DOCKERFILE:-$SUITE/image/Dockerfile}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
ITERATIONS="${E2E_SOAK_ITERATIONS:-30}"
INTERVAL="${E2E_SOAK_INTERVAL:-60}"
RSS_MB="${E2E_SOAK_RSS_MB:-512}"
DOMAIN="${E2E_DOMAIN:-example.com}"
TARGET="${E2E_TARGET:-www.cloudflare.com}"

source "$ROOT/tests/go-parity/lib/docker_common.sh"

if [[ -d "$EVID" && -n "$(ls -A "$EVID" 2>/dev/null)" ]]; then
    echo "FATAL: $EVID already holds evidence; choose a new E2E_RUN_ID" >&2
    exit 2
fi
mkdir -p "$EVID" "$WORK/seed/cert"
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$EVID/run.log"; }

NAME="e2e-$RUN_ID-soak"
NET="e2e-$RUN_ID-soak"
cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "run_id=$RUN_ID iterations=$ITERATIONS interval=${INTERVAL}s"
docker build -q -t "$IMAGE_TAG" -f "$IMAGE_DOCKERFILE" "$SUITE/image" >/dev/null || {
    log "FATAL: image build failed"; exit 2
}
docker run --rm -v "$ROOT:/src:ro" -v "$WORK/seed:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
    "$GO_IMAGE" go build -buildvcs=false -trimpath -o /out/idleleo ./cmd/idleleo || {
    log "FATAL: idleleo build failed"; exit 2
}

ARCH=$(docker_arch) || exit 2
if [[ -x "$ROOT/tests/go-parity/.cache/a2/xray" ]]; then
    XRAY_BIN="$ROOT/tests/go-parity/.cache/a2/xray"
else
    XRAY_BIN=$(ensure_xray_bin "$ARCH") || exit 2
fi
cp "$XRAY_BIN" "$WORK/seed/xray"
chmod 0755 "$WORK/seed/xray"

docker network create "$NET" >/dev/null || exit 2
# shellcheck disable=SC2046
docker run -d --name "$NAME" --hostname "$NAME" --network "$NET" \
    --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
    $(cgroup_mount_args) \
    -v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$EVID:/out" \
    "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null || {
    log "FATAL: container start failed"; exit 2
}

for _ in $(seq 1 60); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    [[ "$state" == "running" || "$state" == "degraded" ]] && break
    sleep 1
done

docker exec "$NAME" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
docker exec "$NAME" install -m 0755 /seed/xray /usr/local/bin/xray
docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$NAME" \
    idleleo xray install --binary /usr/local/bin/xray --mode reality \
    --domain "$DOMAIN" --target "$TARGET" --port 443 --container --json \
    >"$EVID/install.json" 2>"$EVID/install.err"
install_rc=$?
echo "$install_rc" >"$EVID/install.rc"
if [[ "$install_rc" -ne 0 ]]; then
    log "FATAL: install rc=$install_rc"
    exit 2
fi

failed_iteration=""
failed_reason=""
iterations=0
for i in $(seq 1 "$ITERATIONS"); do
    iterations=$i
    active=$(docker exec "$NAME" systemctl is-active xray 2>/dev/null || true)
    test_rc=0
    docker exec "$NAME" /usr/local/bin/xray -test \
        -config /etc/idleleo/conf/xray/config.json >/dev/null 2>&1 || test_rc=$?
    listen=$(docker exec "$NAME" sh -c 'ss -lnt 2>/dev/null | grep -c ":443 "' | tr -d '[:space:]')
    restarts=$(docker exec "$NAME" systemctl show -p NRestarts --value xray 2>/dev/null | tr -d '[:space:]')
    pid=$(docker exec "$NAME" systemctl show -p MainPID --value xray 2>/dev/null | tr -d '[:space:]')
    rss_kb=0
    if [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 0 ]]; then
        rss_kb=$(docker exec "$NAME" sh -c "awk '/^VmRSS:/{print \$2}' /proc/$pid/status 2>/dev/null" | tr -d '[:space:]')
        rss_kb=${rss_kb:-0}
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$i" "$active" "$test_rc" "$listen" "$restarts" "$pid" "$rss_kb" >>"$EVID/samples.tsv"

    reason=""
    [[ "$active" == "active" ]] || reason="unit is not active"
    [[ "$test_rc" -eq 0 ]] || reason="xray -test rc=$test_rc"
    [[ "$listen" -ge 1 ]] || reason="port 443 is not listening"
    [[ -n "$restarts" && "$restarts" -eq 0 ]] || reason="unit restarted (NRestarts=$restarts)"
    [[ "$rss_kb" -lt $((RSS_MB * 1024)) ]] || reason="RSS ${rss_kb}KiB exceeds ${RSS_MB}MiB"
    if [[ -n "$reason" ]]; then
        failed_iteration=$i
        failed_reason=$reason
        log "iter=$i FAIL: $reason"
        break
    fi
    log "iter=$i ok active=$active test=0 listen=$listen rss=${rss_kb}KiB"
    [[ "$i" -lt "$ITERATIONS" ]] && sleep "$INTERVAL"
done

if [[ -n "$failed_iteration" ]]; then
    verdict="BLOCKER"
elif [[ "$iterations" -eq "$ITERATIONS" ]]; then
    verdict="PASS"
else
    verdict="HARNESS-ERROR"
fi

python3 - "$EVID/soak.json" "$verdict" "$iterations" "$ITERATIONS" \
    "$failed_iteration" "$failed_reason" "$INTERVAL" "$RSS_MB" <<'PY'
import json
import sys

out, verdict, iterations, expected, failed_iter, reason, interval, rss = sys.argv[1:]
report = {
    "verdict": verdict,
    "iterations": int(iterations),
    "expectedIterations": int(expected),
    "intervalSeconds": int(interval),
    "rssCapMiB": int(rss),
    "failedIteration": int(failed_iter) if failed_iter else None,
    "firstFailureReason": reason or None,
    "checks": ["unit active", "xray -test rc=0", "port 443 listening",
               "NRestarts==0", "RSS under cap"],
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(verdict)
PY

log "verdict=$verdict iterations=$iterations/$ITERATIONS"
[[ "$verdict" == "PASS" ]]
