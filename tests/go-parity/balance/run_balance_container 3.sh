#!/usr/bin/env bash
# Host launcher for the Reality balance parity package.
#
#   bash tests/go-parity/balance/run_balance_container.sh
#
# 1. Builds the current Go CLI from this checkout.
# 2. Starts a disposable privileged systemd container (same base image family
#    as the A2 real-install capture) with nginx + stream module.
# 3. Sources the REAL install.sh in _TEST_MODE=1 and calls the exact functions
#    the Bash install flow uses for balance primary/secondary.
# 4. Runs the Go CLI with identical parameters, xray -test both configs, and
#    compares runtime fields + Nginx stream conf + fragments.
# 5. Runs a local two-backend Nginx simulation (DOCKER_BALANCE_SIMULATED).
#
# This never touches the host network, kernel, services or a real VPS.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EVIDENCE="${BAL_EVIDENCE:-$ROOT/tests/go-parity/evidence/balance-2026-11-08}"
IMAGE="${BAL_IMAGE:-idleleo-balance-bash:local}"
NAME="idleleo-balance-$$"
PORT="${BAL_PORT:-8443}"
SERVERNAME="${BAL_SERVERNAME:-www.cloudflare.com}"
UUID_VALUE="${BAL_UUID:-7a4ab30c-b199-4840-a31e-316f4f73a72b}"
PRIVATE_KEY="${BAL_PRIVATE_KEY:-cFjnUzA0KtGoZSiwzExPSO42onRY7GBR1B0QeKeAm00}"
SHORT_ID="${BAL_SHORT_ID:-d4615130bbd45453}"

mkdir -p "$EVIDENCE/bin"
echo "== building Go CLI from $ROOT =="
docker run --rm --tmpfs /tmp:rw,exec,size=1024m \
    -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOTOOLCHAIN=local -e GOPROXY=off \
    -v "$ROOT:/src:ro" -v "$EVIDENCE:/out:rw" -w /src \
    --entrypoint bash xray-bash-go-matrix:local -lc '
        export PATH=/usr/local/go/bin:$PATH
        go build -trimpath -o /out/bin/idleleo-go ./cmd/idleleo
    '
echo "go_binary=$EVIDENCE/bin/idleleo-go"

echo "== building $IMAGE =="
docker build --pull=false -q -t "$IMAGE" -f "$ROOT/tests/go-parity/balance/Dockerfile" \
    "$ROOT/tests/go-parity/balance" >/dev/null

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== starting disposable systemd container =="
docker run -d --name "$NAME" \
    --privileged --cgroupns=host \
    -v "$ROOT:/src:ro" \
    -v "$EVIDENCE:/out:rw" \
    -v "$ROOT/tests/go-parity/.cache/a2:/seed:ro" \
    -e LANG=C.UTF-8 -e NO_COLOR=1 -e TERM=dumb \
    "$IMAGE" >/dev/null

state=""
for _ in $(seq 1 40); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    [[ "$state" == running || "$state" == degraded ]] && break
    sleep 1
done
echo "systemd=${state:-not-ready}"
[[ "$state" == running || "$state" == degraded ]] || {
    docker logs "$NAME" | tail -20 >&2
    exit 1
}

common_env=(
    -e LANG=C.UTF-8 -e NO_COLOR=1 -e TERM=dumb
    -e BAL_PORT="$PORT" -e BAL_SERVERNAME="$SERVERNAME"
    -e BAL_UUID="$UUID_VALUE" -e BAL_PRIVATE_KEY="$PRIVATE_KEY"
    -e BAL_SHORT_ID="$SHORT_ID"
    -e BAL_XRAY_BIN=/seed/xray -e BAL_GO_BIN=/out/bin/idleleo-go
)

rc=0
for role in primary secondary; do
    echo "== Bash generate: $role =="
    mkdir -p "$EVIDENCE/$role"
    : >"$EVIDENCE/$role/result.txt"
    docker exec "${common_env[@]}" -e BAL_ROLE="$role" -e BAL_OUT="/out/$role/bash" \
        "$NAME" bash /src/tests/go-parity/balance/bash_generate.sh \
        >"$EVIDENCE/$role/bash.log" 2>&1 || role_rc=$?
    role_rc=${role_rc:-0}
    printf 'bash_generate_exit=%s\n' "$role_rc" >>"$EVIDENCE/$role/result.txt"
    [[ "$role_rc" -eq 0 ]] || rc=1
    unset role_rc
done

echo "== Go generate + xray -test + compare =="
docker exec "${common_env[@]}" -e BAL_OUT=/out "$NAME" \
    bash /src/tests/go-parity/balance/go_generate_compare.sh \
    >"$EVIDENCE/go-compare.log" 2>&1 || rc=1

echo "== Nginx two-backend simulation (DOCKER_BALANCE_SIMULATED) =="
docker exec "${common_env[@]}" -e BAL_OUT=/out "$NAME" \
    bash /src/tests/go-parity/balance/run_nginx_sim.sh \
    >"$EVIDENCE/nginx-sim.log" 2>&1 || rc=1

echo "== results =="
for role in primary secondary; do
    echo "-- $role --"
    cat "$EVIDENCE/$role/result.txt"
    cat "$EVIDENCE/$role/compare.log" 2>/dev/null || true
done
echo "-- nginx sim --"
cat "$EVIDENCE/primary/sim/result.txt" 2>/dev/null || cat "$EVIDENCE/nginx-sim.log"
exit "$rc"
