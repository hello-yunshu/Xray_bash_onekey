#!/usr/bin/env bash
# 30-minute soak for a fresh Reality install.
#
# One privileged systemd container, a real Go install, then 31 one-minute
# samples (elapsed monotonic time must reach at least 1800s). Every sample is a
# live observation: unit active, config test, the inbound port still listening,
# no unit restart, RSS under the cap, and a real business request through an
# independent client container (Reality handshake + HTTP GET).
#
# After the soak, a second container runs the real idleleo-schedule.timer on a
# short interval against a local GeoData origin and must record at least two
# completed cycles.
#
# Any failed sample is a BLOCKER with its iteration index; a dead container or a
# missing observation is a HARNESS-ERROR.
#
# Env:
#   E2E_SOAK_ITERATIONS   samples (default 31)
#   E2E_SOAK_INTERVAL     seconds between samples (default 60)
#   E2E_SOAK_MIN_SECONDS  minimum monotonic duration (default 1800)
#   E2E_SOAK_RSS_MB       RSS cap in MiB (default 512)
#   E2E_SCHED_INTERVAL    timer interval for the cycle check (default 15)
#   E2E_KEEP=1            keep only this run's containers/network for diagnosis
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-soak-$(date +%Y%m%d-%H%M)-$(git -C "$ROOT" rev-parse --short HEAD)}"
EVID="$SUITE/evidence/$RUN_ID/soak"
WORK="/tmp/e2e-$RUN_ID"
IMAGE_TAG="${E2E_IMAGE_TAG:-idleleo-e2e:24.04}"
IMAGE_DOCKERFILE="${E2E_IMAGE_DOCKERFILE:-$SUITE/image/Dockerfile}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
ITERATIONS="${E2E_SOAK_ITERATIONS:-31}"
INTERVAL="${E2E_SOAK_INTERVAL:-60}"
MIN_SECONDS="${E2E_SOAK_MIN_SECONDS:-1800}"
RSS_MB="${E2E_SOAK_RSS_MB:-512}"
DOMAIN="${E2E_DOMAIN:-example.com}"
TARGET="${E2E_TARGET:-www.cloudflare.com}"
TARGET_URL="${E2E_L4_URL:-http://example.com/}"
TARGET_MARKER="${E2E_L4_MARKER:-Example Domain}"
SCHED_INTERVAL="${E2E_SCHED_INTERVAL:-15}"
GEO_SRC="${E2E_GEO_DIR:-$HOME/.cache/xray-audit/share/xray-bin}"

source "$ROOT/tests/go-parity/lib/docker_common.sh"

if [[ -d "$EVID" && -n "$(ls -A "$EVID" 2>/dev/null)" ]]; then
    echo "FATAL: $EVID already holds evidence; choose a new E2E_RUN_ID" >&2
    exit 2
fi
mkdir -p "$EVID" "$WORK/seed/cert" "$WORK/secret"
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$EVID/run.log"; }

NAME="e2e-$RUN_ID-soak"
CLIENT="e2e-$RUN_ID-soak-client"
SCHED="e2e-$RUN_ID-sched"
ORIGIN="e2e-$RUN_ID-origin"
NET="e2e-$RUN_ID-soak"
cleanup() {
    if [[ "${E2E_KEEP:-0}" == "1" ]]; then
        log "cleanup=kept containers/network for diagnosis"
    else
        docker rm -f "$NAME" "$CLIENT" "$SCHED" "$ORIGIN" >/dev/null 2>&1 || true
        docker network rm "$NET" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

log "run_id=$RUN_ID iterations=$ITERATIONS interval=${INTERVAL}s min=${MIN_SECONDS}s"
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

# Real GeoData for the schedule-cycle container. The same cache feeds the ops
# sweep; a missing cache is a harness error, not something to fake.
mkdir -p "$WORK/origin"
for name in geoip.dat geosite.dat; do
    [[ -f "$GEO_SRC/$name" ]] || { log "FATAL: real GeoData $GEO_SRC/$name is missing"; exit 2; }
    cp "$GEO_SRC/$name" "$WORK/origin/$name"
done
( cd "$WORK/origin" && shasum -a 256 geoip.dat >geoip.dat.sha256sum \
    && shasum -a 256 geosite.dat >geosite.dat.sha256sum )

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

# --- independent client container -------------------------------------------
server_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")
docker exec "$NAME" python3 /src/tests/e2e-diff/collect/client_config.py \
    --config /etc/idleleo/conf/xray/config.json --mode reality --transport auto \
    --server-address "$server_ip" --server-port 443 --domain "$DOMAIN" \
    --output /tmp/e2e-client.json >"$EVID/client-config.log" 2>&1 || {
    log "FATAL: client config generation failed"; exit 2
}
docker cp "$NAME:/tmp/e2e-client.json" "$WORK/secret/client.json" >/dev/null 2>&1 || {
    log "FATAL: cannot extract client config"; exit 2
}
docker exec "$NAME" rm -f /tmp/e2e-client.json
docker run -d --name "$CLIENT" --network "$NET" -v "$WORK/secret:/client" \
    -v "$WORK/seed/xray:/opt/xray/xray:ro" --entrypoint sleep "$IMAGE_TAG" infinity >/dev/null || {
    log "FATAL: client container start failed"; exit 2
}
docker exec -d "$CLIENT" sh -c '/opt/xray/xray run -c /client/client.json >/client/client.log 2>&1'
sleep 2
docker exec "$CLIENT" sh -c 'ss -lnt | grep -q 127.0.0.1:1080' || {
    log "FATAL: client socks did not listen"
    docker cp "$CLIENT:/client/client.log" "$EVID/client.log" >/dev/null 2>&1 || true
    exit 2
}

failed_iteration=""
failed_reason=""
iterations=0
elapsed=0
client_ok=0
client_fail=0
start_epoch=$(date +%s)
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
    body="$WORK/body.$i"
    l4_rc=0
    docker exec "$CLIENT" curl -sS --max-time 10 --socks5-hostname 127.0.0.1:1080 \
        "$TARGET_URL" >"$body" 2>/dev/null || l4_rc=$?
    l4_bytes=$(wc -c <"$body" | tr -d '[:space:]')
    l4_ok=0
    [[ "$l4_rc" -eq 0 && -s "$body" ]] && grep -q "$TARGET_MARKER" "$body" && l4_ok=1
    rm -f "$body"
    if [[ "$l4_ok" -eq 1 ]]; then client_ok=$((client_ok + 1)); else client_fail=$((client_fail + 1)); fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$i" "$active" "$test_rc" "$listen" "$restarts" "$pid" "$rss_kb" \
        "$l4_ok" "$l4_rc" "$l4_bytes" >>"$EVID/samples.tsv"

    reason=""
    [[ "$active" == "active" ]] || reason="unit is not active"
    [[ "$test_rc" -eq 0 ]] || reason="xray -test rc=$test_rc"
    [[ "$listen" -ge 1 ]] || reason="port 443 is not listening"
    [[ -n "$restarts" && "$restarts" -eq 0 ]] || reason="unit restarted (NRestarts=$restarts)"
    [[ "$rss_kb" -lt $((RSS_MB * 1024)) ]] || reason="RSS ${rss_kb}KiB exceeds ${RSS_MB}MiB"
    [[ "$l4_ok" -eq 1 ]] || reason="client business request failed (curl rc=$l4_rc, bytes=$l4_bytes)"
    if [[ -n "$reason" ]]; then
        failed_iteration=$i
        failed_reason=$reason
        log "iter=$i FAIL: $reason"
        break
    fi
    log "iter=$i ok active=$active test=0 listen=$listen rss=${rss_kb}KiB l4=ok/${l4_bytes}B"
    [[ "$i" -lt "$ITERATIONS" ]] && sleep "$INTERVAL"
done
end_epoch=$(date +%s)
elapsed=$((end_epoch - start_epoch))
log "elapsed=${elapsed}s client_ok=$client_ok client_fail=$client_fail"

# --- two real schedule cycles ------------------------------------------------
sched_ok=0
sched_runs=0
timer_state=""
if [[ -z "$failed_iteration" ]]; then
    log "schedule cycle check (interval=${SCHED_INTERVAL}s)"
    docker run -d --name "$ORIGIN" --network "$NET" \
        -v "$WORK/origin:/usr/share/nginx/html:ro" nginx:1.27 >/dev/null 2>&1 || true
    # shellcheck disable=SC2046
    docker run -d --name "$SCHED" --hostname "$SCHED" --network "$NET" \
        --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
        $(cgroup_mount_args) \
        -v "$WORK/seed:/seed:ro" -v "$EVID:/out" \
        "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
        state=$(docker exec "$SCHED" systemctl is-system-running 2>/dev/null || true)
        [[ "$state" == "running" || "$state" == "degraded" ]] && break
        sleep 1
    done
    for _ in $(seq 1 30); do
        docker exec "$SCHED" curl -fsS "http://$ORIGIN/geoip.dat" -o /dev/null 2>/dev/null && break
        sleep 1
    done
    docker exec "$SCHED" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    # The unit uses ExecStart=/usr/bin/idleleo, matching the production layout.
    docker exec "$SCHED" install -m 0755 /seed/idleleo /usr/bin/idleleo
    docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$SCHED" \
        idleleo schedule install --interval "$SCHED_INTERVAL" \
        --geodata-url "http://$ORIGIN" --container --json \
        >"$EVID/schedule-install.json" 2>"$EVID/schedule-install.err" || true
    : >"$EVID/schedule-runs.tsv"
    for _ in $(seq 1 90); do
        docker exec "$SCHED" sh -c 'cat /var/lib/idleleo/schedule/state.json 2>/dev/null' \
            >"$EVID/schedule-state.json"
        sched_runs=$(sed -n 's/.*"runs": \([0-9][0-9]*\).*/\1/p' "$EVID/schedule-state.json" | head -1)
        sched_runs=${sched_runs:-0}
        printf '%s\t%s\n' "$(date +%s)" "$sched_runs" >>"$EVID/schedule-runs.tsv"
        [[ "$sched_runs" -ge 2 ]] && break
        sleep 2
    done
    timer_state=$(docker exec "$SCHED" systemctl is-active idleleo-schedule.timer 2>/dev/null || true)
    docker exec "$SCHED" systemctl list-timers idleleo-schedule.timer --no-pager \
        >"$EVID/schedule-timer.txt" 2>&1 || true
    docker exec "$SCHED" journalctl -u idleleo-schedule.service --no-pager -n 100 \
        >"$EVID/schedule-journal.txt" 2>&1 || true
    docker exec "$SCHED" sh -c 'cat /etc/idleleo/conf/xray/../schedule/jobs.json 2>/dev/null' \
        >"$EVID/schedule-jobs.json" 2>/dev/null || true
    geo_ok=0
    if docker exec "$SCHED" sh -c '[ -s /etc/idleleo/share/xray/geoip.dat ] && [ -s /etc/idleleo/share/xray/geosite.dat ]'; then
        geo_ok=1
    fi
    log "schedule timer=$timer_state runs=$sched_runs geodata=$geo_ok"
    if [[ "$timer_state" == "active" && "$sched_runs" -ge 2 && "$geo_ok" -eq 1 ]] &&
        grep -q '"result": "ok"' "$EVID/schedule-state.json"; then
        sched_ok=1
    fi
fi

if [[ -n "$failed_iteration" ]]; then
    # Preserve enough runtime evidence to distinguish a transient public-origin
    # timeout from a failed Xray/client process. This diagnostic retry is never
    # counted as a soak sample and cannot turn the failed run green.
    docker exec "$CLIENT" sh -c 'curl -sv --max-time 10 --socks5-hostname 127.0.0.1:1080 "$1" -o /dev/null' \
        sh "$TARGET_URL" >"$EVID/post-failure-client-curl.out" \
        2>"$EVID/post-failure-client-curl.err" || true
    docker exec "$CLIENT" sh -c 'ps -ef; ss -lntp' \
        >"$EVID/post-failure-client-processes.txt" 2>&1 || true
    docker exec "$CLIENT" cat /client/client.log \
        >"$EVID/post-failure-client-xray.log" 2>&1 || true
    docker exec "$NAME" journalctl -u xray --no-pager -n 300 \
        >"$EVID/post-failure-server-xray.log" 2>&1 || true
    docker exec "$NAME" sh -c 'ss -s; ss -tnp; systemctl show xray -p MainPID -p NRestarts -p ActiveState' \
        >"$EVID/post-failure-server-state.txt" 2>&1 || true
    verdict="BLOCKER"
elif [[ "$iterations" -ne "$ITERATIONS" ]]; then
    verdict="HARNESS-ERROR"
elif [[ "$elapsed" -lt "$MIN_SECONDS" ]]; then
    verdict="BLOCKER"
    failed_reason="soak elapsed ${elapsed}s < ${MIN_SECONDS}s"
elif [[ "$sched_ok" -ne 1 ]]; then
    verdict="BLOCKER"
    failed_reason="schedule timer did not complete two real cycles (runs=$sched_runs timer=$timer_state)"
else
    verdict="PASS"
fi

python3 - "$EVID/soak.json" "$verdict" "$iterations" "$ITERATIONS" \
    "$failed_iteration" "$failed_reason" "$INTERVAL" "$RSS_MB" "$elapsed" \
    "$MIN_SECONDS" "$client_ok" "$client_fail" "$sched_runs" "$timer_state" <<'PY'
import json
import sys

(out, verdict, iterations, expected, failed_iter, reason, interval, rss,
 elapsed, minimum, client_ok, client_fail, sched_runs, timer_state) = sys.argv[1:]
report = {
    "verdict": verdict,
    "iterations": int(iterations),
    "expectedIterations": int(expected),
    "intervalSeconds": int(interval),
    "elapsedSeconds": int(elapsed),
    "minimumSeconds": int(minimum),
    "rssCapMiB": int(rss),
    "failedIteration": int(failed_iter) if failed_iter else None,
    "firstFailureReason": reason or None,
    "clientProbes": {"ok": int(client_ok), "failed": int(client_fail)},
    "scheduleCycles": {"runs": int(sched_runs or 0), "timer": timer_state or None},
    "checks": ["unit active", "xray -test rc=0", "port 443 listening",
               "NRestarts==0", "RSS under cap",
               "client Reality handshake + HTTP business request",
               "two real idleleo-schedule.timer cycles"],
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(verdict)
PY

log "verdict=$verdict iterations=$iterations/$ITERATIONS elapsed=${elapsed}s"
[[ "$verdict" == "PASS" ]]
