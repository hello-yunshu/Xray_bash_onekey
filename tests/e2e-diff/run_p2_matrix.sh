#!/usr/bin/env bash
# P2 runner: M1-M10 x {bash,go} x 2 rounds (fresh + repeat install).
#
# Concurrency unit is one scenario (both sides run sequentially inside it), with
# a dedicated docker network per scenario. At most E2E_CONCURRENCY scenarios run
# at once.
#
# Round 1 is the primary evidence. Round 2 is the idempotency round and lives in
# <side>/round2. Go round 2 uses --keep-config explicitly; bash round 2 takes the
# interactive keep-config path. Both sides must report rc=0 for round 2.
#
# M3 and M10 are first-class Go scenarios: the Go installer now adds a
# transport alongside Reality and installs a real relay (managed Nginx stream)
# instead of being recorded as a capability gap.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ROOT
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-$(date +%Y%m%d-%H%M)-$(git -C "$ROOT" rev-parse --short HEAD)}"
EVID="$SUITE/evidence/$RUN_ID/p2"
WORK="/tmp/e2e-$RUN_ID"
IMAGE_TAG="${E2E_IMAGE_TAG:-idleleo-e2e:24.04}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
DOMAIN="${E2E_DOMAIN:-example.com}"
TARGET="${E2E_TARGET:-www.cloudflare.com}"
LOCAL_IP="${E2E_LOCAL_IP:-127.0.0.1}"
RELAY_HOST="${E2E_RELAY_HOST:-origin.example.com}"
RELAY_PORT="${E2E_RELAY_PORT:-443}"
CONCURRENCY="${E2E_CONCURRENCY:-5}"
ONLY="${E2E_ONLY:-}"
PEBBLE_IMAGE="${E2E_PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}"
PEBBLE_TEST="$WORK/pebble-test"
PEBBLE_CONFIG="$SUITE/../go-parity/acme/pebble-config.json"

source "$ROOT/tests/go-parity/lib/docker_common.sh"

mkdir -p "$EVID" "$WORK/seed/cert" "$WORK/secret"
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$EVID/run.log"; }

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
if [[ -n "${E2E_GITHUB_IP:-}" ]]; then
    PIN_ARGS+=(--add-host "github.com:$E2E_GITHUB_IP")
else
    pin_host github.com
fi

matrix_get() {
    python3 - "$SUITE/matrix.json" "$1" "$2" <<'PY'
import json, sys
matrix = json.load(open(sys.argv[1]))
sid, path = sys.argv[2], sys.argv[3]
scenario = next(x for x in matrix['install'] if x['id'] == sid)
cur = scenario
for part in path.split('.'):
    if not isinstance(cur, dict):
        cur = None
        break
    cur = cur.get(part)
if cur is None or cur == "":
    print("")
elif isinstance(cur, bool):
    print("true" if cur else "false")
elif isinstance(cur, (list, dict)):
    print(json.dumps(cur, ensure_ascii=False))
else:
    print(cur)
PY
}

json_list() {
    python3 -c 'import json,sys; print("\n".join(str(x) for x in json.loads(sys.argv[1])))' "$1"
}

# edit_get reads one field from matrix.json's `edits` section (E1/E2).
edit_get() {
    python3 - "$SUITE/matrix.json" "$1" "$2" <<'PY'
import json, sys
matrix = json.load(open(sys.argv[1]))
entry = next(x for x in matrix['edits'] if x['id'] == sys.argv[2])
cur = entry
for part in sys.argv[3].split('.'):
    if not isinstance(cur, dict):
        cur = None
        break
    cur = cur.get(part)
if cur is None or cur == "":
    print("")
elif isinstance(cur, bool):
    print("true" if cur else "false")
elif isinstance(cur, (list, dict)):
    print(json.dumps(cur, ensure_ascii=False))
else:
    print(cur)
PY
}

# --- prerequisites ---------------------------------------------------------
log "run_id=$RUN_ID"
docker build -q -t "$IMAGE_TAG" -f "$SUITE/image/Dockerfile" "$SUITE/image" >/dev/null || {
    log "FATAL: image build failed"; exit 2
}
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE_TAG")
log "image_id=$IMAGE_ID"

log "building idleleo"
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
log "xray_sha256=$(host_sha256 "$WORK/seed/xray") idleleo_sha256=$(host_sha256 "$WORK/seed/idleleo")"

docker run --rm -v "$WORK/seed:/seed" "$IMAGE_TAG" bash -c \
    "openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=$DOMAIN' \
     -addext 'subjectAltName=DNS:$DOMAIN' \
     -keyout /seed/cert/xray.key -out /seed/cert/xray.crt >/dev/null 2>&1" || {
    log "FATAL: certificate generation failed"; exit 2
}

# OPS-21 needs geoip.dat/geosite.dat even when the environment has no egress.
# Seed them from a cache when one exists; the driver copies them into the
# install and the apply path then proves the missing-file refusal is not
# silently replaced by a download.
GEO_CACHE="${E2E_GEO_DIR:-$HOME/.cache/xray-audit/share/xray-bin}"
mkdir -p "$WORK/seed/geo"
for name in geoip.dat geosite.dat; do
    if [[ -f "$GEO_CACHE/$name" ]]; then
        cp "$GEO_CACHE/$name" "$WORK/seed/geo/$name"
        log "seeded_geo=$name sha256=$(host_sha256 "$WORK/seed/geo/$name")"
    fi
done

python3 - "$SUITE/matrix.json" >"$EVID/run.json" <<PY
import json
matrix = json.load(open("$SUITE/matrix.json"))
print(json.dumps({
    "runId": "$RUN_ID",
    "commit": "$(git -C "$ROOT" rev-parse HEAD)",
    "branch": "$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)",
    "imageId": "$IMAGE_ID",
    "matrixFrozenAt": matrix.get("frozenAt"),
    "decisions": matrix.get("decisions"),
}, indent=2, sort_keys=True))
PY

# --- argv verification evidence (T1) --------------------------------------
write_argv_verify() {
    local out="$EVID/argv-verify.md" tmpc="p2-argv-$RUN_ID"
    docker rm -f "$tmpc" >/dev/null 2>&1 || true
    docker run -d --name "$tmpc" -v "$WORK/seed:/seed:ro" "$IMAGE_TAG" sleep infinity >/dev/null || return 1
    docker exec "$tmpc" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    docker exec "$tmpc" mkdir -p /tmp/probe
    {
        echo "# Go argv verification ($RUN_ID)"
        echo
        echo "方法：\`idleleo <cmd> --help\` 只输出总览，无法逐 flag 核实。改用两条硬证据："
        echo "1) 未知 flag 会被 checkFlags 拒绝（rc=2, \`unknown flag: X\`）；"
        echo "2) \`idleleo xray generate\` 不写系统路径，能验证 mode/transport 组合。"
        echo
        for sid in M1 M2 M3 M4 M5 M6 M7 M8 M9 M10; do
            local argv_json; argv_json=$(matrix_get "$sid" go.argv)
            echo "## $sid"
            echo
            echo '```'
            if [[ -z "$argv_json" ]]; then
                echo "install argv: null"
            else
                echo "install argv: $(json_list "$argv_json" | tr '\n' ' ')"
            fi
            echo '```'
            echo
        done
        echo "## generate probes"
        echo
        echo '```'
        while IFS='|' read -r label args; do
            echo "### $label"
            docker exec "$tmpc" sh -c "idleleo xray generate $args --out /tmp/g.json --force >/tmp/probe.out 2>&1; rc=\$?; tail -3 /tmp/probe.out; echo rc=\$rc" 2>&1
        done <<'PROBES'
M1|--mode reality --domain www.cloudflare.com --target www.cloudflare.com --port 443
M2|--mode reality-nginx --domain www.cloudflare.com --target www.cloudflare.com --port 443
M2-alias|--mode reality --nginx-bin /usr/local/nginx/sbin/nginx --domain www.cloudflare.com --target www.cloudflare.com --port 443
M3|--mode reality --transport ws --domain www.cloudflare.com --target www.cloudflare.com --port 443
M4|--mode tls --transport ws --domain example.com
M5|--mode tls --transport grpc --domain example.com
M6|--mode tls --transport xhttp --domain example.com
M7|--mode tls --transport ws+grpc+xhttp --domain example.com
M9|--mode none --transport ws --listen 0.0.0.0 --allow-non-loopback
PROBES
        echo '```'
        echo
        echo "## relay conf probe (M10)"
        echo
        echo '```'
        docker exec "$tmpc" sh -c "idleleo xray relay --target origin.example.com:443 --listen-port 443 --out /tmp/relay.conf" 2>&1 | tail -3
        docker exec "$tmpc" cat /tmp/relay.conf 2>/dev/null || true
        echo '```'
        echo
        echo "M10 install argv 走真实安装路径验证（见 M10/go/install.rc 与 L4），不在探针容器里拉取 Nginx。"
    } >"$out"
    docker rm -f "$tmpc" >/dev/null 2>&1 || true
    log "argv-verify written"
}
write_argv_verify

# --- helpers ---------------------------------------------------------------
# SERVER_EXTRA_ARGS is set by the scenario before start_server (M8 mounts the
# Pebble CA/cert tree). Each scenario runs in its own subshell, so the global
# stays scoped to that scenario.
SERVER_EXTRA_ARGS=()

start_server() {
    local name=$1 sid=$2 side=$3 out=$4 net=$5
    docker rm -f "$name" >/dev/null 2>&1 || true
    mkdir -p "$out"
    # shellcheck disable=SC2046
    docker run -d --name "$name" --hostname "$name" --network "$net" \
        --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
        "${PIN_ARGS[@]+"${PIN_ARGS[@]}"}" $(cgroup_mount_args) \
        "${SERVER_EXTRA_ARGS[@]+"${SERVER_EXTRA_ARGS[@]}"}" \
        -v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$out:/out" \
        --label "e2e.run=$RUN_ID" --label "e2e.scenario=$sid" --label "e2e.side=$side" \
        "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null
}

# --- Pebble ACME sidecar (M8) ----------------------------------------------
# The image is distroless: /test is extracted with docker cp, not exec. The
# directory TLS cert already carries DNS:pebble, so no custom CA is needed;
# PEBBLE_VA_ALWAYS_VALID skips the challenge dial (nginx listens on :443, not
# Pebble's httpPort :5002).
prepare_pebble_assets() {
    if [[ -f "$PEBBLE_TEST/certs/pebble.minica.pem" ]]; then
        return 0
    fi
    mkdir -p "$PEBBLE_TEST"
    local cid
    cid=$(docker create "$PEBBLE_IMAGE") || return 1
    if ! docker cp "$cid:/test/." "$PEBBLE_TEST/" >/dev/null 2>&1; then
        docker rm "$cid" >/dev/null 2>&1 || true
        return 1
    fi
    docker rm "$cid" >/dev/null 2>&1 || true
    [[ -f "$PEBBLE_TEST/certs/pebble.minica.pem" ]]
}

start_pebble() {
    local sid=$1 net=$2 name="e2e-$RUN_ID-$sid-pebble"
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" --network "$net" --network-alias pebble \
        -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_AUTHZREUSE=0 \
        -v "$PEBBLE_TEST/certs:/test/certs:ro" \
        -v "$PEBBLE_CONFIG:/conf/pebble-config.json:ro" \
        --entrypoint /app "$PEBBLE_IMAGE" -config /conf/pebble-config.json -strict >/dev/null
}

wait_pebble() {
    local net=$1
    for _ in $(seq 1 30); do
        if docker run --rm --network "$net" -v "$PEBBLE_TEST/certs:/test/certs:ro" \
            "$IMAGE_TAG" curl -fsS --max-time 3 \
            --cacert /test/certs/pebble.minica.pem https://pebble:14000/dir >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

l4_transports() {
    case $1 in
        M1|M2) echo "reality" ;;
        M3) echo "reality ws" ;;
        M4) echo "ws" ;;
        M5) echo "grpc" ;;
        M6) echo "xhttp" ;;
        M7) echo "ws grpc xhttp" ;;
        M8) echo "ws" ;;
        M9) echo "ws" ;;
        *) echo "" ;;
    esac
}

run_l4() {
    local sid=$1 side=$2 server=$3 out=$4 net=$5 profile=$6 round=$7
    if [[ "$round" == "2" ]]; then
        out="$out/round2"
        mkdir -p "$out"
    fi
    local transport
    for transport in $(l4_transports "$sid"); do
        local client="e2e-$RUN_ID-$sid-$side-r$round-$transport"
        local secret="$WORK/secret/$sid-$side-r$round-$transport"
        E2E_L4_URL="http://example.com/" E2E_L4_MARKER="Example Domain" \
            bash "$SUITE/collect/l4.sh" "$server" "$client" "$IMAGE_TAG" "$net" \
                "$profile" "$DOMAIN" "$WORK/seed/xray" "$secret" "$out/L4/$transport" \
                "$transport" >"$out/L4-$transport.log" 2>&1
        local rc=$?
        echo "{\"transport\":\"$transport\",\"rc\":$rc}" >>"$out/L4/round$round.jsonl" \
            || true
    done
}

start_relay_origin() {
    local sid=$1 net=$2 origin="e2e-$RUN_ID-$sid-origin"
    docker rm -f "$origin" >/dev/null 2>&1 || true
    # The origin must be up before the relay install: Nginx resolves the
    # backend hostname when it loads the config, and origin.example.com would
    # otherwise resolve to a public address instead of the docker alias.
    docker run -d --name "$origin" --network "$net" --network-alias "$RELAY_HOST" \
        "$IMAGE_TAG" bash -c \
        "mkdir -p /origin && printf 'Example Domain relay-ok\n' >/origin/index.html && cd /origin && python3 -m http.server $RELAY_PORT --bind 0.0.0.0" \
        >/dev/null
    sleep 2
}

relay_l4() {
    local sid=$1 side=$2 server=$3 out=$4 net=$5 round=$6
    if [[ "$round" == "2" ]]; then
        out="$out/round2"
        mkdir -p "$out"
    fi
    local client="e2e-$RUN_ID-$sid-$side-r$round-relay"
    docker rm -f "$client" >/dev/null 2>&1 || true
    docker run --rm --network "$net" --name "$client" "$IMAGE_TAG" \
        bash -c "curl -fsS --max-time 10 http://$server:$RELAY_PORT/" \
        >"$out/L4-relay.out" 2>"$out/L4-relay.err"
    local rc=$?
    if ! grep -q "relay-ok" "$out/L4-relay.out" 2>/dev/null; then
        rc=3
    fi
    echo "{\"transport\":\"relay\",\"rc\":$rc}" >"$out/L4-relay.json"
}

run_bash_round() {
    local sid=$1 net=$2 server=$3 out=$4 round=$5 prev=$6 profile=$7 arg=$8 menu=$9 transport=${10}
    local target_out="/out"
    if [[ "$round" == "2" ]]; then
        target_out="/out/round2"
        out="$out/round2"
        mkdir -p "$out"
    fi
    local envs=(-e E2E_OUT="$target_out" -e E2E_ROUND="$round" -e E2E_SCENARIO="$sid"
                -e E2E_PROFILE="$profile" -e E2E_ARG="$arg" -e E2E_MENU="$menu"
                -e E2E_TRANSPORT="$transport" -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET"
                -e E2E_PORT=443 -e E2E_LOCAL_IP="$LOCAL_IP" -e E2E_RELAY_HOST="$RELAY_HOST"
                -e E2E_RELAY_PORT="$RELAY_PORT" -e E2E_PREV_OUT="/out"
                -e E2E_TIMEOUT="${E2E_TIMEOUT:-900}")
    # Round 2 tests config idempotency, not live takeover. Bash reinstall
    # replaces the binary before its port guard, so the still-running service
    # is no longer recognised and the guard rejects its own port. Stop the
    # services first on both sides so round 2 starts from a clean service state.
    if [[ "$round" == "2" ]]; then
        docker exec "$server" sh -c 'systemctl stop xray >/dev/null 2>&1; systemctl stop nginx >/dev/null 2>&1; true'
    fi
    local acme_envs=()
    if [[ "$sid" == "M8" ]]; then
        acme_envs=(-e SSL_CERT_FILE=/test/certs/pebble.minica.pem
                   -e IDLELEO_ACME_DIRECTORY=https://pebble:14000/dir
                   -e E2E_ACME=1)
    fi
    docker exec "${envs[@]}" "${acme_envs[@]+"${acme_envs[@]}"}" "$server" \
        bash /src/tests/e2e-diff/drivers/bash_install.sh
    echo $? >"$out/install.rc"
}

run_go_round() {
    local sid=$1 server=$2 out=$3 round=$4 prev=$5 profile=$6; shift 6
    local -a argv=("$@")
    local target_out="/out"
    if [[ "$round" == "2" ]]; then
        target_out="/out/round2"
        out="$out/round2"
        mkdir -p "$out"
    fi
    if [[ "$round" == "2" ]]; then
        docker exec "$server" sh -c 'systemctl stop xray >/dev/null 2>&1; systemctl stop nginx >/dev/null 2>&1; true'
    fi
    local driver="go_install.sh" acme_envs=()
    if [[ "$(matrix_get "$sid" go.driver)" == "acme" ]]; then
        driver="go_acme.sh"
        acme_envs=(-e SSL_CERT_FILE=/test/certs/pebble.minica.pem
                   -e IDLELEO_ACME_DIRECTORY=https://pebble:14000/dir)
    fi
    docker exec -e E2E_OUT="$target_out" -e E2E_ROUND="$round" -e E2E_SCENARIO="$sid" \
        -e E2E_PROFILE="$profile" -e E2E_PREV_OUT=/out \
        "${acme_envs[@]+"${acme_envs[@]}"}" \
        "$server" bash "/src/tests/e2e-diff/drivers/$driver" "${argv[@]}"
    echo $? >"$out/install.rc"
}

scenario_job() {
    local sid=$1
    local net="e2e-$RUN_ID-$sid"
    local eligible; eligible=$(matrix_get "$sid" eligible)
    local base="$EVID/$sid"
    mkdir -p "$base"
    if [[ "$eligible" != "true" ]]; then
        { echo "# $sid: HARNESS-BLOCKED"; echo; echo "$(matrix_get "$sid" notes)"; } >"$base/HARNESS-BLOCKED.md"
        log "[$sid] HARNESS-BLOCKED (ineligible)"
        return
    fi
    docker network create "$net" >/dev/null 2>&1 || true
    log "[$sid] start"

    SERVER_EXTRA_ARGS=()
    if [[ "$sid" == "M8" ]]; then
        if ! prepare_pebble_assets || ! start_pebble "$sid" "$net" || ! wait_pebble "$net"; then
            {
                echo "# $sid: HARNESS-BLOCKED"
                echo
                echo "Pebble sidecar failed to start; see docker logs e2e-$RUN_ID-$sid-pebble."
            } >"$base/HARNESS-BLOCKED.md"
            docker logs "e2e-$RUN_ID-$sid-pebble" >"$base/pebble-boot.log" 2>&1 || true
            docker rm -f "e2e-$RUN_ID-$sid-pebble" >/dev/null 2>&1 || true
            docker network rm "$net" >/dev/null 2>&1 || true
            log "[$sid] HARNESS-BLOCKED (pebble)"
            return
        fi
        SERVER_EXTRA_ARGS=(-v "$PEBBLE_TEST/certs:/test/certs:ro")
        log "[$sid] pebble ready"
    fi

    local profile go_argv_json bash_arg bash_menu bash_transport
    go_argv_json=$(matrix_get "$sid" go.argv)
    bash_arg=""; bash_menu=""; bash_transport="1"
    case $sid in
        M1) profile=reality; bash_arg="-2" ;;
        M2|M3) profile=reality ;;
        M4|M5|M6|M7|M8) profile=tls; bash_arg="-1" ;;
        M9) profile=none ;;
        M10) profile=relay; bash_arg="--install-relay" ;;
        *) profile=reality ;;
    esac
    case $sid in
        M4) bash_transport=1 ;;
        M5) bash_transport=2 ;;
        M6) bash_transport=3 ;;
        M7) bash_transport=5 ;;
        M3) bash_transport=1 ;;
        M8) bash_transport=1 ;;
    esac
    bash_menu=$(matrix_get "$sid" bash.menu)
    [[ -n "$(matrix_get "$sid" bash.transport)" ]] && bash_transport=$(matrix_get "$sid" bash.transport)

    if [[ "$profile" == "relay" ]]; then
        start_relay_origin "$sid" "$net"
    fi

    # ---- bash side ----
    local bserver="e2e-$RUN_ID-$sid-bash" bout="$base/bash"
    if start_server "$bserver" "$sid" bash "$bout" "$net"; then
        run_bash_round "$sid" "$net" "$bserver" "$bout" 1 "" "$profile" "$bash_arg" "$bash_menu" "$bash_transport"
        if [[ "$profile" == "relay" ]]; then relay_l4 "$sid" bash "$bserver" "$bout" "$net" 1; else
            run_l4 "$sid" bash "$bserver" "$bout" "$net" "$profile" 1
        fi
        run_bash_round "$sid" "$net" "$bserver" "$bout" 2 "$bout" "$profile" "$bash_arg" "$bash_menu" "$bash_transport"
        if [[ "$profile" == "relay" ]]; then relay_l4 "$sid" bash "$bserver" "$bout" "$net" 2; else
            run_l4 "$sid" bash "$bserver" "$bout" "$net" "$profile" 2
        fi
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bout/result.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    # ---- go side ----
    local gserver="e2e-$RUN_ID-$sid-go" gout="$base/go"
    if [[ -z "$go_argv_json" ]]; then
        mkdir -p "$gout"; echo '{"status":"harness-error","reason":"no go argv"}' >"$gout/result.json"
    elif start_server "$gserver" "$sid" go "$gout" "$net"; then
        GO_ARGV=()
        while IFS= read -r line; do GO_ARGV+=("$line"); done < <(json_list "$go_argv_json")
        run_go_round "$sid" "$gserver" "$gout" 1 "" "$profile" "${GO_ARGV[@]}"
        if [[ "$profile" == "relay" ]]; then relay_l4 "$sid" go "$gserver" "$gout" "$net" 1; else
            run_l4 "$sid" go "$gserver" "$gout" "$net" "$profile" 1
        fi
        run_go_round "$sid" "$gserver" "$gout" 2 "$gout" "$profile" "${GO_ARGV[@]}"
        if [[ "$profile" == "relay" ]]; then relay_l4 "$sid" go "$gserver" "$gout" "$net" 2; else
            run_l4 "$sid" go "$gserver" "$gout" "$net" "$profile" 2
        fi
    else
        mkdir -p "$gout"; echo '{"status":"harness-error","reason":"container start failed"}' >"$gout/result.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker rm -f "e2e-$RUN_ID-$sid-origin" >/dev/null 2>&1 || true
    docker rm -f "e2e-$RUN_ID-$sid-pebble" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
    log "[$sid] done"
}

# --- config edit scenarios (Go only) ---------------------------------------
run_edit_l4() {
    local eid=$1 server=$2 out=$3 label=$4 net=$5
    local profile="${6:-reality}" transport="${7:-reality}"
    local client="e2e-$RUN_ID-$eid-go-$label"
    local secret="$WORK/secret/$eid-$label"
    mkdir -p "$out/edit"
    # E4's driver exports the throwaway CA that signed its local origin; the
    # post-edit client container has to trust the same chain.
    local extra_ca=""
    [[ -f "$out/edit/local-ca.crt" ]] && extra_ca="$out/edit/local-ca.crt"
    # Pin whatever Nginx is configured to serve now: E5 swaps the pair, so the
    # default path would make the post-edit client reject the new certificate.
    local cert_pin="/etc/idleleo/cert/xray.crt" live=""
    live=$(docker exec "$server" sh -c \
        "awk '/ssl_certificate[[:space:]]/{print \$2; exit}' /etc/idleleo/conf/nginx/00-xray.conf 2>/dev/null" |
        tr -d ';' | head -1) || true
    [[ -n "$live" ]] && cert_pin="$live"
    E2E_EXTRA_CA="$extra_ca" E2E_L4_CERT="$cert_pin" \
        E2E_L4_URL="http://example.com/" E2E_L4_MARKER="Example Domain" \
        bash "$SUITE/collect/l4.sh" "$server" "$client" "$IMAGE_TAG" "$net" \
            "$profile" "$DOMAIN" "$WORK/seed/xray" "$secret" "$out/edit/L4-$label" "$transport" \
            >"$out/edit/L4-$label.log" 2>&1
}

edit_job() {
    local eid=$1
    local net="e2e-$RUN_ID-$eid"
    local base="$EVID/$eid"
    local gout="$base/go"
    mkdir -p "$gout"
    # Older runs can leave empty e2e networks behind; Docker Desktop runs out of
    # address pools long before that is obvious, and `docker run` then fails
    # with "network ... not found". Only remove ones with no containers.
    local stale count
    while IFS= read -r stale; do
        [[ -n "$stale" ]] || continue
        count=$(docker network inspect -f '{{len .Containers}}' "$stale" 2>/dev/null || echo 1)
        if [[ "$count" == "0" ]]; then
            docker network rm "$stale" >/dev/null 2>&1 || true
        fi
    done < <(docker network ls --format '{{.Name}}' | grep '^e2e-' || true)
    docker network create "$net" >/dev/null 2>&1 || true
    for _ in 1 2 3 4 5; do
        docker network inspect "$net" >/dev/null 2>&1 && break
        docker network create "$net" >/dev/null 2>&1 || sleep 1
    done
    if ! docker network inspect "$net" >/dev/null 2>&1; then
        log "[$eid] FATAL: cannot create network $net"
    fi
    log "[$eid] start"
    local base_sid go_argv_json edit_argv_json l4_profile l4_transport
    base_sid=$(edit_get "$eid" base)
    go_argv_json=$(matrix_get "$base_sid" go.argv)
    edit_argv_json=$(edit_get "$eid" go.argv)
    l4_profile=$(edit_get "$eid" l4Profile 2>/dev/null || true)
    l4_transport=$(edit_get "$eid" l4Transport 2>/dev/null || true)
    [[ -n "$l4_profile" ]] || l4_profile="reality"
    [[ -n "$l4_transport" ]] || l4_transport="reality"
    local gserver="e2e-$RUN_ID-$eid-go"
    if start_server "$gserver" "$eid" go "$gout" "$net"; then
        GO_ARGV=()
        while IFS= read -r line; do GO_ARGV+=("$line"); done < <(json_list "$go_argv_json")
        run_go_round "$base_sid" "$gserver" "$gout" 1 "" "$l4_profile" "${GO_ARGV[@]}"
        run_edit_l4 "$eid" "$gserver" "$gout" before "$net" "$l4_profile" "$l4_transport"
        EDIT_ARGV=()
        while IFS= read -r line; do EDIT_ARGV+=("$line"); done < <(json_list "$edit_argv_json")
        local driver="go_edit.sh"
        local driver_args=("${EDIT_ARGV[@]}")
        if [[ "$eid" == "E5" || "$eid" == "E6" ]]; then
            driver="go_edit_tls.sh"
            driver_args=("$eid" "${EDIT_ARGV[@]}")
        elif [[ "$eid" == "E7" || "$eid" == "E8" ]]; then
            driver="go_edit_reality.sh"
            driver_args=("$eid" "${EDIT_ARGV[@]}")
        fi
        docker exec -e E2E_OUT=/out -e E2E_SCENARIO="$eid" "$gserver" \
            bash "/src/tests/e2e-diff/drivers/$driver" "${driver_args[@]}"
        run_edit_l4 "$eid" "$gserver" "$gout" after "$net" "$l4_profile" "$l4_transport"
        echo 0 >"$gout/install.rc"
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$gout/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
    log "[$eid] done"
}

# --- ops scenarios (real execution only) -----------------------------------
# An OPS row is only rendered PASS when both sides were observed in the same
# container run. OPS-19 (Fail2ban) is the only one with an execution path
# today; every other OPS row stays unproven and is reported as NOT-RUN.
F2B_JAIL="${E2E_F2B_JAIL:-nginx-badbots}"
F2B_BAN_IP="${E2E_F2B_BAN_IP:-203.0.113.7}"

# The Nginx jails are gated on the log files existing, on both sides.
f2b_seed_logs() {
    docker exec "$1" bash -c \
        'mkdir -p /usr/local/nginx/logs && touch /usr/local/nginx/logs/access.log \
         /usr/local/nginx/logs/error.log /usr/local/nginx/logs/sni_error.log \
         /usr/local/nginx/logs/tls_error.log'
}

# One bash-side install.sh sub-command; stdout is the observation.
ops_bash_cli() {
    local server=$1 out=$2 name=$3; shift 3
    docker exec -e XRAY_VERSIONS_FILE=/etc/idleleo/versions.json "$server" \
        bash /etc/idleleo/install.sh "$@" >"$out/$name.out" 2>&1
    echo $? >"$out/$name.rc"
}

# One Go-side sub-command; stdout stays JSON for the verdict parser.
ops_go_cli() {
    local server=$1 out=$2 name=$3; shift 3
    docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY \
        "$server" idleleo "$@" >"$out/$name.out" 2>"$out/$name.err"
    echo $? >"$out/$name.rc"
}

# ops19_verdict turns the two observation sets into ops.json. Missing evidence
# is HARNESS-ERROR, an observation mismatch is BLOCKER, never PASS.
ops19_verdict() {
    local base=$1
    python3 - "$base" "$F2B_JAIL" "$F2B_BAN_IP" <<'PY'
import json, os, sys

base, jail, ip = sys.argv[1], sys.argv[2], sys.argv[3]
bash_dir, go_dir = os.path.join(base, "bash"), os.path.join(base, "go")


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def read_rc(path):
    raw = read_text(path)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def read_json(path):
    raw = read_text(path)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def bash_jails(text):
    for line in (text or "").splitlines():
        idx = line.find("Jail list:")
        if idx >= 0:
            value = line[idx + len("Jail list:"):]
            return [part.strip() for part in value.split(",") if part.strip()]
    return []


def go_jails(data):
    return [entry.get("name") for entry in (data or {}).get("jails", []) if entry.get("name")]


def go_banned(data):
    out = []
    for entry in (data or {}).get("jails", []):
        out.extend(entry.get("bannedIPs") or [])
    return out


reasons = []
bash_install_rc = read_rc(os.path.join(bash_dir, "f2b-install.rc"))
go_install_rc = read_rc(os.path.join(go_dir, "01-install.rc"))
bash_list_before = read_text(os.path.join(bash_dir, "04-list-before.out"))
bash_list_after = read_text(os.path.join(bash_dir, "06-list-after.out"))
go_status = read_json(os.path.join(go_dir, "02-status.out"))
go_before = read_json(os.path.join(go_dir, "04-banned-before.out"))
go_after = read_json(os.path.join(go_dir, "06-banned-after.out"))
bash_unban_rc = read_rc(os.path.join(bash_dir, "05-unban.rc"))
go_unban = read_json(os.path.join(go_dir, "05-unban.out"))

harness = []
if bash_install_rc is None:
    harness.append("missing bash fail2ban install rc")
if go_install_rc is None:
    harness.append("missing go fail2ban install rc")
if bash_install_rc == 124 or go_install_rc == 124:
    harness.append("driver rc=124")
if bash_list_before is None or bash_list_after is None:
    harness.append("missing bash --fail2ban-list observation")
if go_status is None or go_before is None or go_after is None:
    harness.append("missing go fail2ban observation")
if bash_unban_rc is None or go_unban is None:
    harness.append("missing unban observation")

b_jails, g_jails = bash_jails(bash_list_before), go_jails(go_status)
b_before = ip in (bash_list_before or "")
g_before = ip in go_banned(go_before)
b_unbanned = bash_unban_rc == 0
g_unbanned = (go_unban or {}).get("unbanned") is True
b_after = ip in (bash_list_after or "")
g_after = ip in go_banned(go_after)

if harness:
    verdict = "HARNESS-ERROR"
    reasons = harness
else:
    if bash_install_rc != 0:
        reasons.append("bash fail2ban install rc=%d" % bash_install_rc)
    if go_install_rc != 0:
        reasons.append("go fail2ban install rc=%d" % go_install_rc)
    if jail not in b_jails:
        reasons.append("bash jail set missing %s" % jail)
    if jail not in g_jails:
        reasons.append("go jail set missing %s" % jail)
    if not b_before:
        reasons.append("bash ban observation missing %s" % ip)
    if not g_before:
        reasons.append("go ban observation missing %s" % ip)
    if not b_unbanned:
        reasons.append("bash unban failed (rc=%s)" % bash_unban_rc)
    if not g_unbanned:
        reasons.append("go unban not confirmed")
    if b_after:
        reasons.append("bash still bans %s after unban" % ip)
    if g_after:
        reasons.append("go still bans %s after unban" % ip)
    verdict = "BLOCKER" if reasons else "PASS"

report = {
    "id": "OPS-19",
    "verdict": verdict,
    "bothInstallRc": {"bash": bash_install_rc, "go": go_install_rc},
    "jails": {"bash": b_jails, "go": g_jails},
    "bannedBefore": bool(b_before and g_before),
    "unbanned": bool(b_unbanned and g_unbanned),
    "bannedAfter": bool(b_after or g_after),
    "observations": {
        "bash": {"bannedBefore": b_before, "unbanned": b_unbanned, "bannedAfter": b_after},
        "go": {"bannedBefore": g_before, "unbanned": g_unbanned, "bannedAfter": g_after},
    },
    "jail": jail,
    "banIp": ip,
    "reasons": reasons,
}
with open(os.path.join(base, "ops.json"), "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(verdict)
PY
}

ops19_job() {
    local oid=OPS-19
    local net="e2e-$RUN_ID-$oid"
    local base="$EVID/$oid" bdir="$EVID/$oid/bash" gdir="$EVID/$oid/go"
    mkdir -p "$bdir" "$gdir"
    docker network create "$net" >/dev/null 2>&1 || true
    log "[$oid] start"

    # ---- bash side ----
    local bserver="e2e-$RUN_ID-$oid-bash"
    if start_server "$bserver" "$oid" bash "$bdir" "$net"; then
        # Bash only writes the Nginx jails when reality_add_nginx=on, which the
        # reality-nginx (M2) install sets; reuse the existing round driver.
        run_bash_round M2 "$net" "$bserver" "$bdir" 1 "" reality "" "1>1>1" "1"
        f2b_seed_logs "$bserver"
        docker exec -e E2E_LOG=/out/f2b-menu.log -e E2E_TIMEOUT="${E2E_TIMEOUT:-900}" \
            -e XRAY_VERSIONS_FILE=/etc/idleleo/versions.json "$bserver" \
            expect -f /src/tests/e2e-diff/drivers/bash_f2b.exp \
            >"$bdir/f2b-install.out" 2>&1
        echo $? >"$bdir/f2b-install.rc"
        docker exec "$bserver" fail2ban-client set "$F2B_JAIL" banip "$F2B_BAN_IP" \
            >"$bdir/03-ban.out" 2>&1
        echo $? >"$bdir/03-ban.rc"
        ops_bash_cli "$bserver" "$bdir" 04-list-before --fail2ban-list
        ops_bash_cli "$bserver" "$bdir" 05-unban --fail2ban-unban "$F2B_JAIL" "$F2B_BAN_IP"
        ops_bash_cli "$bserver" "$bdir" 06-list-after --fail2ban-list
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    # ---- go side ----
    local gserver="e2e-$RUN_ID-$oid-go"
    if start_server "$gserver" "$oid" go "$gdir" "$net"; then
        docker exec "$gserver" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
        f2b_seed_logs "$gserver"
        ops_go_cli "$gserver" "$gdir" 01-install fail2ban install --container --json
        ops_go_cli "$gserver" "$gdir" 02-status fail2ban status --json
        docker exec "$gserver" fail2ban-client set "$F2B_JAIL" banip "$F2B_BAN_IP" \
            >"$gdir/03-ban.out" 2>&1
        echo $? >"$gdir/03-ban.rc"
        ops_go_cli "$gserver" "$gdir" 04-banned-before fail2ban banned --jail "$F2B_JAIL" --json
        ops_go_cli "$gserver" "$gdir" 05-unban fail2ban unban --jail "$F2B_JAIL" --ip "$F2B_BAN_IP" --json
        ops_go_cli "$gserver" "$gdir" 06-banned-after fail2ban banned --jail "$F2B_JAIL" --json
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$gdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true

    log "[$oid] verdict=$(ops19_verdict "$base")"
}

# --- traffic-block ops (OPS-21) -------------------------------------------
# Both sides are observed on a live install: a real Reality client sends the
# control and the blocked targets through the proxy. PASS needs the control
# side to keep working (example.com 200 + marker), each blocked type refused
# quickly, and on Go also the post-`config edit` routing comparison.
OPS21_BASH_CHECKS="baselineControl applyRcZero rulesAdded fallbackDirect noCatchAllBlocked controlAfterApply adsBlocked privateBlocked countryBlocked offRcZero offRestored controlAfterOff"
OPS21_GO_CHECKS="$OPS21_BASH_CHECKS customListConfigured customRuleApplied customListKept customRuleRemoved editRcZero editUuidApplied editRoutingIdentical editOwnedRulesKept editUserRuleKept editBlockReported controlAfterEdit adsBlockedAfterEdit"

ops21_verdict() {
    local base=$1
    python3 - "$base" "$OPS21_BASH_CHECKS" "$OPS21_GO_CHECKS" <<'PY'
import json, os, sys

base, bash_required, go_required = sys.argv[1], sys.argv[2].split(), sys.argv[3].split()
sides = {"bash": os.path.join(base, "bash", "block-bash", "result.json"),
         "go": os.path.join(base, "go", "block-go", "result.json")}
required = {"bash": bash_required, "go": go_required}

results, harness, reasons = {}, [], []
for side, path in sides.items():
    harness_path = os.path.join(base, side, "harness.json")
    if os.path.exists(harness_path):
        try:
            harness.append("%s: %s" % (side, json.load(open(harness_path)).get("reason", "harness error")))
        except (OSError, json.JSONDecodeError):
            harness.append("%s: harness.json is unreadable" % side)
        continue
    try:
        with open(path, encoding="utf-8") as fh:
            results[side] = json.load(fh)
    except (OSError, json.JSONDecodeError):
        harness.append("missing %s result.json" % side)
        continue
    checks = {c["name"]: c["ok"] for c in results[side].get("checks", [])}
    missing = [name for name in required[side] if name not in checks]
    if missing:
        harness.append("%s is missing checks: %s" % (side, ", ".join(missing)))
    # A control probe that never reaches the origin proves nothing: every
    # "blocked" outcome would then be indistinguishable from a broken tunnel.
    if checks.get("baselineControl") is not True:
        harness.append("%s never reached the control origin before blocking" % side)
    failed = [name for name, ok in checks.items() if not ok and name != "baselineControl"]
    if failed:
        reasons.append("%s failed: %s" % (side, ", ".join(sorted(failed))))

if harness:
    verdict = "HARNESS-ERROR"
else:
    verdict = "BLOCKER" if reasons else "PASS"

def brief(side):
    checks = {c["name"]: c["ok"] for c in (results.get(side) or {}).get("checks", [])}
    side_harness = [r for r in harness if r.startswith(side + ":")]
    status = (results.get(side) or {}).get("status")
    if side_harness:
        status = "HARNESS-ERROR"
    return {"status": status,
            "reasons": side_harness,
            "failed": (results.get(side) or {}).get("failed", []),
            "checks": checks}

report = {
    "id": "OPS-21",
    "verdict": verdict,
    "reasons": harness + reasons,
    "sides": {side: brief(side) for side in sides},
}
with open(os.path.join(base, "ops.json"), "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(verdict)
PY
}

ops21_egress() {
    docker run --rm "$IMAGE_TAG" sh -c 'curl -4 -fsS --max-time 6 ip.me >/dev/null 2>&1'
}

ops21_job() {
    local oid=OPS-21
    local net="e2e-$RUN_ID-$oid"
    local base="$EVID/$oid" bdir="$EVID/$oid/bash" gdir="$EVID/$oid/go"
    mkdir -p "$bdir" "$gdir"
    docker network create "$net" >/dev/null 2>&1 || true
    log "[$oid] start"

    # The control target is served from inside each server container: this host
    # has no egress and cross-container traffic is unreliable. The driver binds
    # 11.0.0.2/32 to lo there — a public (DoD) range on purpose, so geoip:private
    # and geoip:cn never match it. Blocked targets match routing rules before any
    # dial, so they need no origin either.
    local control_ip=11.0.0.2

    # ---- bash side: M1 reality install, then traffic_blocker.sh ----
    # The bash installer needs egress twice (public-IP lookup and GeoData), so
    # a network-less host is recorded as HARNESS-ERROR instead of a fake FAIL.
    local bserver="e2e-$RUN_ID-$oid-bash"
    if ! ops21_egress; then
        log "[$oid] bash skipped: container network has no egress"
        python3 - "$bdir/harness.json" <<'PY'
import json, sys
json.dump({"status": "harness-error",
           "reason": "container network has no egress; the bash installer cannot resolve its public IP or fetch geoip.dat/geosite.dat"},
          open(sys.argv[1], "w"), indent=2)
PY
    elif start_server "$bserver" "$oid" bash "$bdir" "$net"; then
        run_bash_round M1 "$net" "$bserver" "$bdir" 1 "" reality "-2" "" "1"
        docker exec -e E2E_OUT=/out -e E2E_CONTROL_HOST="$control_ip" -e E2E_CONTROL_PORT=80 \
            "$bserver" bash /src/tests/e2e-diff/drivers/ops21_block.sh bash \
            >"$bdir/block.out" 2>&1
        echo $? >"$bdir/block.rc"
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    # ---- go side: M1-equivalent install, then idleleo xray block ----
    local gserver="e2e-$RUN_ID-$oid-go"
    if start_server "$gserver" "$oid" go "$gdir" "$net"; then
        local -a iargv=(xray install --binary /usr/local/bin/xray --mode reality
                        --domain "$TARGET" --target "$TARGET" --port 443 --container)
        run_go_round "$oid" "$gserver" "$gdir" 1 "" reality "${iargv[@]}"
        docker exec -e E2E_OUT=/out -e E2E_CONTROL_HOST="$control_ip" -e E2E_CONTROL_PORT=80 \
            -e E2E_BLOCK_NO_PROBE=1 \
            "$gserver" bash /src/tests/e2e-diff/drivers/ops21_block.sh go \
            >"$gdir/block.out" 2>&1
        echo $? >"$gdir/block.rc"
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$gdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true

    log "[$oid] verdict=$(ops21_verdict "$base")"
}

# --- load-balancer ops (OPS-09 / OPS-31) ----------------------------------
# Both rows are observed on two real installs: bash creates the backend through
# the interactive menu (2>3>1 -> file_manager.sh), Go through
# `idleleo xray balance add/remove`. The verdict compares the on-disk fragment
# and the documented list output; a missing side is HARNESS-ERROR, a mismatch
# is BLOCKER, never PASS.
BALANCE_HOST="${E2E_BALANCE_HOST:-10.99.0.7}"
BALANCE_PORT="${E2E_BALANCE_PORT:-9447}"
BALANCE_WEIGHT="${E2E_BALANCE_WEIGHT:-60}"

# nginx_snapshot writes "== <file>" plus its body for every *.<suffix> fragment.
nginx_snapshot() {
    local server=$1 suffix=$2 out=$3
    docker exec "$server" bash -c \
        'cd /etc/idleleo/conf/nginx 2>/dev/null || exit 0
         shopt -s nullglob
         for f in *.'"$suffix"'; do
             [ -f "$f" ] || continue
             printf "== %s\n" "$f"
             cat "$f"
         done' >"$out" 2>&1 || true
}

# backend_index prints the 1-based position of <host>.<suffix> in the sorted
# file list file_manager.sh shows, so the remove phase picks the right row.
# Prints 0 when the file is absent, which makes the verdict a BLOCKER.
backend_index() {
    local server=$1 suffix=$2 name="$3.$2"
    docker exec "$server" bash -c \
        'cd /etc/idleleo/conf/nginx || exit 1
         shopt -s nullglob
         n=1
         for f in *.'"$suffix"'; do
             if [ "$f" = "'"$name"'" ]; then echo "$n"; exit 0; fi
             n=$((n+1))
         done
         echo 0' 2>/dev/null
}

ops_bash_fm() {
    local server=$1 out=$2 phase=$3 upstream=$4 idx=$5
    local host="${6:-$BALANCE_HOST}" port="${7:-$BALANCE_PORT}"
    local weight="${8:-$BALANCE_WEIGHT}" tag="${9:-$phase}"
    docker exec -e E2E_LOG="/out/fm-$tag.log" -e E2E_PHASE="$phase" \
        -e E2E_UPSTREAM="$upstream" -e E2E_BACKEND_HOST="$host" \
        -e E2E_BACKEND_PORT="$port" -e E2E_BACKEND_WEIGHT="$weight" \
        -e E2E_BACKEND_INDEX="$idx" -e E2E_TIMEOUT="${E2E_TIMEOUT:-900}" \
        -e XRAY_VERSIONS_FILE=/etc/idleleo/versions.json "$server" \
        expect -f /src/tests/e2e-diff/drivers/bash_fm_balance.exp \
        >"$out/fm-$tag.out" 2>&1
    echo $? >"$out/fm-$tag.rc"
}

ops_balance_verdict() {
    local base=$1 oid=$2 upstream=$3 suffix=$4
    python3 - "$base" "$oid" "$upstream" "$suffix" "$BALANCE_HOST" "$BALANCE_PORT" \
        "$BALANCE_WEIGHT" <<'PY'
import json, os, sys

base, oid, upstream, suffix, host, port, weight = sys.argv[1:8]
port, weight = int(port), int(weight)
bash_dir, go_dir = os.path.join(base, "bash"), os.path.join(base, "go")


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def read_rc(path):
    raw = read_text(path)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def read_json(path):
    raw = read_text(path)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def snapshot(path):
    text = read_text(path)
    if text is None:
        return None
    files, cur = {}, None
    for line in text.splitlines():
        if line.startswith("== "):
            cur = line[3:].strip()
            files[cur] = []
        elif cur is not None:
            files[cur].append(line)
    return {name: "\n".join(body).strip() for name, body in files.items()}


def backend_lines(files):
    out = []
    for body in (files or {}).values():
        for line in body.splitlines():
            line = line.strip()
            if not (line.startswith("server ") and line.endswith(";")):
                continue
            parts = line[:-1].split()
            addr = parts[1] if len(parts) > 1 else "-"
            w = next((p for p in parts[2:] if p.startswith("weight=")), "weight=?")
            out.append("%s %s" % (addr, w))
    return sorted(out)


def go_backends(data):
    return [b for b in ((data or {}).get("backends") or []) if isinstance(b, dict)]


expected = "server %s:%d weight=%d max_fails=2 fail_timeout=10;" % (host, port, weight)
name = "%s.%s" % (host, suffix)

b_install = read_rc(os.path.join(bash_dir, "install.rc"))
g_install = read_rc(os.path.join(go_dir, "install.rc"))
b_add_rc = read_rc(os.path.join(bash_dir, "fm-add.rc"))
b_rm_rc = read_rc(os.path.join(bash_dir, "fm-remove.rc"))
g_add_rc = read_rc(os.path.join(go_dir, "02-balance-add.rc"))
g_rm_rc = read_rc(os.path.join(go_dir, "04-balance-remove.rc"))
b_add_log = read_text(os.path.join(bash_dir, "fm-add.log"))
b_rm_log = read_text(os.path.join(bash_dir, "fm-remove.log"))
b_add_files = snapshot(os.path.join(bash_dir, "files-after-add.txt"))
b_rm_files = snapshot(os.path.join(bash_dir, "files-after-remove.txt"))
g_add_files = snapshot(os.path.join(go_dir, "files-after-add.txt"))
g_rm_files = snapshot(os.path.join(go_dir, "files-after-remove.txt"))
g_list_add = read_json(os.path.join(go_dir, "03-balance-list-after-add.out"))
g_list_rm = read_json(os.path.join(go_dir, "05-balance-list-after-remove.out"))

harness = []
for label, value in (
        ("bash install rc", b_install), ("go install rc", g_install),
        ("bash add rc", b_add_rc), ("bash remove rc", b_rm_rc),
        ("go add rc", g_add_rc), ("go remove rc", g_rm_rc)):
    if value is None:
        harness.append("missing %s" % label)
    elif value == 124:
        harness.append("driver rc=124 (%s)" % label)
for label, value in (
        ("bash add transcript", b_add_log), ("bash remove transcript", b_rm_log),
        ("bash files after add", b_add_files), ("bash files after remove", b_rm_files),
        ("go files after add", g_add_files), ("go files after remove", g_rm_files),
        ("go balance list after add", g_list_add), ("go balance list after remove", g_list_rm)):
    if value is None:
        harness.append("missing %s" % label)

reasons = []
if harness:
    verdict = "HARNESS-ERROR"
    reasons = harness
else:
    if b_install != 0:
        reasons.append("bash install rc=%d" % b_install)
    if g_install != 0:
        reasons.append("go install rc=%d" % g_install)
    if b_add_rc != 0:
        reasons.append("bash file_manager add rc=%d" % b_add_rc)
    if b_rm_rc != 0:
        reasons.append("bash file_manager remove rc=%d" % b_rm_rc)
    if g_add_rc != 0:
        reasons.append("go balance add rc=%d" % g_add_rc)
    if g_rm_rc != 0:
        reasons.append("go balance remove rc=%d" % g_rm_rc)
    if name not in b_add_files:
        reasons.append("bash did not write %s" % name)
    elif b_add_files[name] != expected:
        reasons.append("bash %s content=%r want=%r" % (name, b_add_files[name], expected))
    if name not in g_add_files:
        reasons.append("go did not write %s" % name)
    elif g_add_files[name] != expected:
        reasons.append("go %s content=%r want=%r" % (name, g_add_files[name], expected))
    if name not in (b_add_log or ""):
        reasons.append("bash list output never shows %s" % name)
    if "已创建" not in (b_add_log or ""):
        reasons.append("bash never reported 已创建")
    if name in b_rm_files:
        reasons.append("bash still has %s after remove" % name)
    if name in g_rm_files:
        reasons.append("go still has %s after remove" % name)
    if name not in (b_rm_log or ""):
        reasons.append("bash remove transcript never names %s" % name)
    if "已删除" not in (b_rm_log or ""):
        reasons.append("bash never reported 已删除")
    g_add = [(b.get("host"), b.get("port")) for b in go_backends(g_list_add)]
    g_rm = [(b.get("host"), b.get("port")) for b in go_backends(g_list_rm)]
    if (host, port) not in g_add:
        reasons.append("go balance list does not show %s:%d after add" % (host, port))
    if (host, port) in g_rm:
        reasons.append("go balance list still shows %s:%d after remove" % (host, port))
    verdict = "BLOCKER" if reasons else "PASS"

report = {
    "id": oid,
    "verdict": verdict,
    "upstream": upstream,
    "bashMenu": "2>3>1",
    "backend": {"host": host, "port": port, "weight": weight},
    "expectedLine": expected,
    "bothInstallRc": {"bash": b_install, "go": g_install},
    "addRc": {"bash": b_add_rc, "go": g_add_rc},
    "removeRc": {"bash": b_rm_rc, "go": g_rm_rc},
    "backends": {"bash": backend_lines(b_add_files), "go": backend_lines(g_add_files)},
    "files": {
        "bash": {
            "dir": "/etc/idleleo/conf/nginx",
            "suffix": suffix,
            "created": sorted(b_add_files),
            "content": b_add_files,
            "afterRemove": sorted(b_rm_files),
        },
        "go": {
            "dir": "/etc/idleleo/conf/nginx",
            "suffix": suffix,
            "created": sorted(g_add_files),
            "content": g_add_files,
            "afterRemove": sorted(g_rm_files),
        },
    },
    "list": {
        "bash": {"showsBackend": name in (b_add_log or ""),
                 "reportsCreated": "已创建" in (b_add_log or ""),
                 "reportsDeleted": "已删除" in (b_rm_log or "")},
        "go": {"afterAdd": go_backends(g_list_add), "afterRemove": go_backends(g_list_rm)},
    },
    "reasons": reasons,
}
with open(os.path.join(base, "ops.json"), "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(verdict)
PY
}

ops_balance_job() {
    local oid=$1 upstream=$2 suffix=$3 kind=$4
    local net="e2e-$RUN_ID-$oid"
    local base="$EVID/$oid" bdir="$EVID/$oid/bash" gdir="$EVID/$oid/go"
    mkdir -p "$bdir" "$gdir"
    docker network create "$net" >/dev/null 2>&1 || true
    log "[$oid] start upstream=$upstream"

    # ---- bash side: real install, then real menu 2>3>1 ----
    local bserver="e2e-$RUN_ID-$oid-bash"
    if start_server "$bserver" "$oid" bash "$bdir" "$net"; then
        if [[ "$kind" == "tls" ]]; then
            # M4 (tls-ws) install: same entry/answers as the M4 matrix row.
            run_bash_round M4 "$net" "$bserver" "$bdir" 1 "" tls "-1" "" 1
        else
            # Reality 负载均衡 primary: menu 1>1>5 (role) >1 (主服务器).
            run_bash_round M2 "$net" "$bserver" "$bdir" 1 "" reality "" "1>1>5>1" 1
        fi
        ops_bash_fm "$bserver" "$bdir" add "$upstream" 1
        nginx_snapshot "$bserver" "$suffix" "$bdir/files-after-add.txt"
        local b_idx; b_idx=$(backend_index "$bserver" "$suffix" "$BALANCE_HOST")
        ops_bash_fm "$bserver" "$bdir" remove "$upstream" "${b_idx:-0}"
        nginx_snapshot "$bserver" "$suffix" "$bdir/files-after-remove.txt"
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    # ---- go side: real install, then balance add/list/remove ----
    local gserver="e2e-$RUN_ID-$oid-go"
    if start_server "$gserver" "$oid" go "$gdir" "$net"; then
        docker exec "$gserver" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
        local -a iargv
        if [[ "$kind" == "tls" ]]; then
            iargv=(xray install --binary /usr/local/bin/xray --mode tls --transport ws
                   --domain "$DOMAIN" --cert /etc/idleleo/cert/xray.crt
                   --cert-key /etc/idleleo/cert/xray.key --port 9000 --public-port 443
                   --container)
            run_go_round "$oid" "$gserver" "$gdir" 1 "" tls "${iargv[@]}"
        else
            iargv=(xray install --binary /usr/local/bin/xray --mode reality-balance
                   --role primary --domain "$TARGET" --target "$TARGET" --port 443
                   --container)
            run_go_round "$oid" "$gserver" "$gdir" 1 "" reality "${iargv[@]}"
        fi
        ops_go_cli "$gserver" "$gdir" 01-balance-list-before \
            xray balance list --upstream "$upstream" --json
        ops_go_cli "$gserver" "$gdir" 02-balance-add \
            xray balance add --upstream "$upstream" --host "$BALANCE_HOST" \
            --port "$BALANCE_PORT" --weight "$BALANCE_WEIGHT" --container --json
        nginx_snapshot "$gserver" "$suffix" "$gdir/files-after-add.txt"
        ops_go_cli "$gserver" "$gdir" 03-balance-list-after-add \
            xray balance list --upstream "$upstream" --json
        ops_go_cli "$gserver" "$gdir" 04-balance-remove \
            xray balance remove --upstream "$upstream" --host "$BALANCE_HOST" \
            --port "$BALANCE_PORT" --container --json
        nginx_snapshot "$gserver" "$suffix" "$gdir/files-after-remove.txt"
        ops_go_cli "$gserver" "$gdir" 05-balance-list-after-remove \
            xray balance list --upstream "$upstream" --json
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$gdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true

    log "[$oid] verdict=$(ops_balance_verdict "$base" "$oid" "$upstream" "$suffix")"
}

# --- passive failover ops (OPS-32) ----------------------------------------
# Two upstreams are exercised, both with real traffic through the managed
# Nginx front:
#   ws       HTTP through the TLS server block; a marker body names the peer.
#   reality  raw TLS 1.3 ClientHello through the stream block; a marker reply
#            names the peer. The stream peers are plain TCP, so this proves
#            nginx's peer selection and passive removal, not Reality/VLESS.
# One peer is killed with SIGKILL and nginx must retry every request onto the
# survivor while `max_fails=2 fail_timeout=10` removes the dead peer.
#
# Every install already owns a loopback upstream fragment (127.0.0.1.<suffix>).
# The harness deletes it identically on both sides so the upstream under test
# contains exactly backend-a/backend-b. This is not a shortcut around a check:
# `xray balance remove` refuses the loopback on purpose (it is the install's own
# front), so there is no menu/CLI path that would give a symmetric comparison.
OPS32_A_HOST="${E2E_OPS32_A_HOST:-backend-a}"
OPS32_A_PORT="${E2E_OPS32_A_PORT:-9001}"
OPS32_B_HOST="${E2E_OPS32_B_HOST:-backend-b}"
OPS32_B_PORT="${E2E_OPS32_B_PORT:-9002}"
OPS32_WEIGHT="${E2E_OPS32_WEIGHT:-50}"
OPS32_PUBLIC_PORT="${E2E_OPS32_PUBLIC_PORT:-443}"
OPS32_WARMUP="${E2E_OPS32_WARMUP:-20}"
OPS32_BURST="${E2E_OPS32_BURST:-60}"
OPS32_STEADY="${E2E_OPS32_STEADY:-24}"
OPS32_STEADY_INTERVAL="${E2E_OPS32_STEADY_INTERVAL:-0.5}"
OPS32_RECOVERY="${E2E_OPS32_RECOVERY:-120}"
OPS32_RECOVERY_INTERVAL="${E2E_OPS32_RECOVERY_INTERVAL:-0.5}"
# Stable recovery: the trailing run of A must be at least this long. First-A
# alone is a sampling point when only some workers removed the dead peer.
OPS32_STABLE_MIN="${E2E_OPS32_STABLE_MIN:-3}"

# ops32_state records one key per line so the verdict knows the wall-clock
# boundaries of each phase without re-deriving them from the transcripts.
ops32_state() {
    local out=$1 key=$2 value=$3
    printf '%s\t%s\n' "$key" "$value" >>"$out/state.tsv"
}

# The ws location is whatever the install generated (Bash randomises the path,
# Go defaults to /ray/), so it is read back from 00-xray.conf, never guessed.
ops32_ws_location() {
    docker exec "$1" bash -c \
        "awk '/location[ \t]/{loc=\$0} /proxy_pass http:\\/\\/xray-ws-server;/{print loc; exit}' \
         /etc/idleleo/conf/nginx/00-xray.conf" 2>/dev/null |
        awk '{print $2}' | sed 's/[ {].*//'
}

ops32_error_log() {
    local path
    path=$(docker exec "$1" bash -c \
        "grep -m1 -oE '^[[:space:]]*error_log[[:space:]]+[^;]+' /usr/local/nginx/conf/nginx.conf 2>/dev/null |
         awk '{print \$2}'" 2>/dev/null)
    echo "${path:-/usr/local/nginx/logs/error.log}"
}

# Marker backends bind 127.0.0.1 and are reachable through /etc/hosts, so the
# upstream host names stay in the config exactly as the product wrote them.
ops32_hosts() {
    local server=$1
    docker exec "$server" bash -c \
        "grep -qw $OPS32_A_HOST /etc/hosts || echo '127.0.0.1 $OPS32_A_HOST' >> /etc/hosts
         grep -qw $OPS32_B_HOST /etc/hosts || echo '127.0.0.1 $OPS32_B_HOST' >> /etc/hosts"
}

ops32_port_open() {
    docker exec "$1" python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(1)
sys.exit(0 if s.connect_ex(('127.0.0.1', $2)) == 0 else 1)"
}

ops32_start_backend() {
    local server=$1 marker=$2 port=$3 log=$4 driver="${5:-ops32_backend.py}"
    docker exec -d "$server" bash -c \
        "echo \$\$ > /out/$log.pid; exec python3 /src/tests/e2e-diff/drivers/$driver \
         $marker $port /out/$log.log"
    local i=0
    while (( i < 100 )); do
        ops32_port_open "$server" "$port" && return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

ops32_kill_backend() {
    local server=$1 log=$2 port=$3
    docker exec "$server" bash -c "kill -9 \$(cat /out/$log.pid)" >/dev/null 2>&1 || true
    local i=0
    while (( i < 100 )); do
        ops32_port_open "$server" "$port" || return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

ops32_probe() {
    local server=$1 host=$2 path=$3 file=$4 phase=$5 count=$6 interval=$7
    local stop_body="${8:-}"
    docker exec "$server" bash /src/tests/e2e-diff/drivers/ops32_probe.sh \
        "$host" "$path" "/out/$file" "$phase" "$count" "$interval" "$stop_body"
}

# Drops the install's own loopback fragment (see the block comment above) and
# snapshots the upstream before and after, so the removal is visible evidence
# rather than an unexplained edit.
ops32_drop_loopback() {
    local server=$1 out=$2 suffix=$3
    nginx_snapshot "$server" "$suffix" "$out/servers-before-drop.txt"
    docker exec "$server" bash -c \
        "cat /etc/idleleo/conf/nginx/127.0.0.1.$suffix 2>/dev/null" \
        >"$out/loopback-fragment.txt" 2>&1
    docker exec "$server" rm -f "/etc/idleleo/conf/nginx/127.0.0.1.$suffix"
    docker exec "$server" systemctl reload nginx >"$out/nginx-reload.out" 2>&1
    echo $? >"$out/nginx-reload.rc"
    nginx_snapshot "$server" "$suffix" "$out/servers-after-drop.txt"
}

# ops32_side drives warmup -> kill A -> burst + steady -> restart A -> recovery
# and snapshots the Nginx error log after every phase.
ops32_side() {
    local server=$2 out=$3 loc=$4 errlog=$5
    local state="$out/state.tsv"
    : >"$state"
    printf '%s\n' "$loc" >"$out/location.txt"
    printf '%s\n' "$errlog" >"$out/error-log-path.txt"

    # warmup: both peers must be selected before anything is killed
    ops32_state "$out" runStart "$(date +%s)"
    ops32_state "$out" runStartUtc "$(docker exec "$server" date +'%Y/%m/%d %H:%M:%S')"
    ops32_probe "$server" "$DOMAIN" "$loc" probe-warmup.tsv warmup \
        "$OPS32_WARMUP" 0
    docker exec "$server" cat "$errlog" >"$out/error-after-warmup.log" 2>/dev/null

    # kill: SIGKILL, not SIGSTOP, so the TCP handshake is refused
    ops32_state "$out" killStart "$(date +%s)"
    ops32_kill_backend "$server" backend-a "$OPS32_A_PORT" ||
        ops32_state "$out" killFailed 1
    ops32_probe "$server" "$DOMAIN" "$loc" probe-outage-burst.tsv outage-burst \
        "$OPS32_BURST" 0
    ops32_probe "$server" "$DOMAIN" "$loc" probe-outage-steady.tsv outage-steady \
        "$OPS32_STEADY" "$OPS32_STEADY_INTERVAL"
    docker exec "$server" cat "$errlog" >"$out/error-after-outage.log" 2>/dev/null

    # recovery: restart and poll until A answers again. Nginx also decays the
    # peer's effective weight on failure, so A can take longer than
    # fail_timeout to win a round-robin slot again; the local probe shows A was
    # really serving before that ramp is blamed on the removal logic.
    ops32_state "$out" restartStart "$(date +%s)"
    ops32_start_backend "$server" A "$OPS32_A_PORT" backend-a ||
        ops32_state "$out" restartFailed 1
    ops32_state "$out" restartReady "$(date +%s)"
    docker exec "$server" curl -s --max-time 2 \
        "http://127.0.0.1:$OPS32_A_PORT/restart-check" \
        >"$out/backend-a-restart-check.txt" 2>&1
    # Full window: do not stop at the first A. Stable-A is judged from the
    # trailing run of this transcript, so early A responses stay in the data.
    ops32_probe "$server" "$DOMAIN" "$loc" probe-recovery.tsv recovery \
        "$OPS32_RECOVERY" "$OPS32_RECOVERY_INTERVAL"
    docker exec "$server" cat "$errlog" >"$out/error-after-recovery.log" 2>/dev/null
    docker exec "$server" systemctl is-active nginx >"$out/nginx-active.txt" 2>&1
    docker exec "$server" bash -c '/usr/local/nginx/sbin/nginx -v' \
        >"$out/nginx-version.txt" 2>&1
    for marker in a b; do
        docker exec "$server" cat "/out/backend-$marker.log" \
            >"$out/backend-$marker.log" 2>/dev/null || true
    done
}

# ops32_reality_probe drives the stream front. The ClientHello is generated by
# the probe itself because nginx only routes on a parsed SNI + TLS 1.3.
ops32_reality_probe() {
    local server=$1 sni=$2 file=$3 phase=$4 count=$5 interval=$6
    local stop_body="${7:-}"
    docker exec "$server" python3 \
        /src/tests/e2e-diff/drivers/ops32_reality_probe.py \
        "$sni" "$OPS32_PUBLIC_PORT" "/out/$file" "$phase" "$count" "$interval" "$stop_body"
}

# ops32_reality_side is the stream twin of ops32_side. It records the same
# phase boundaries and snapshots the same error log, but the probe is a raw
# connection and the restart check is a TCP connect (a Reality handshake cannot
# be spoken by the harness, and the marker peer does not terminate TLS).
ops32_reality_side() {
    local server=$2 out=$3 sni=$4 errlog=$5
    local state="$out/state.tsv"
    : >"$state"
    printf '%s\n' "$sni" >"$out/location.txt"
    printf '%s\n' "$errlog" >"$out/error-log-path.txt"

    ops32_state "$out" runStart "$(date +%s)"
    ops32_state "$out" runStartUtc "$(docker exec "$server" date +'%Y/%m/%d %H:%M:%S')"
    ops32_reality_probe "$server" "$sni" probe-warmup.tsv warmup "$OPS32_WARMUP" 0
    docker exec "$server" cat "$errlog" >"$out/error-after-warmup.log" 2>/dev/null

    ops32_state "$out" killStart "$(date +%s)"
    ops32_kill_backend "$server" backend-a "$OPS32_A_PORT" ||
        ops32_state "$out" killFailed 1
    ops32_reality_probe "$server" "$sni" probe-outage-burst.tsv outage-burst \
        "$OPS32_BURST" 0
    ops32_reality_probe "$server" "$sni" probe-outage-steady.tsv outage-steady \
        "$OPS32_STEADY" "$OPS32_STEADY_INTERVAL"
    docker exec "$server" cat "$errlog" >"$out/error-after-outage.log" 2>/dev/null

    ops32_state "$out" restartStart "$(date +%s)"
    ops32_start_backend "$server" A "$OPS32_A_PORT" backend-a ops32_reality_backend.py ||
        ops32_state "$out" restartFailed 1
    ops32_state "$out" restartReady "$(date +%s)"
    if ops32_port_open "$server" "$OPS32_A_PORT"; then
        printf 'A\n' >"$out/backend-a-restart-check.txt"
    else
        printf '<closed>\n' >"$out/backend-a-restart-check.txt"
    fi
    # Full window: see ops32_side.
    ops32_reality_probe "$server" "$sni" probe-recovery.tsv recovery \
        "$OPS32_RECOVERY" "$OPS32_RECOVERY_INTERVAL"
    docker exec "$server" cat "$errlog" >"$out/error-after-recovery.log" 2>/dev/null
    docker exec "$server" systemctl is-active nginx >"$out/nginx-active.txt" 2>&1
    docker exec "$server" bash -c '/usr/local/nginx/sbin/nginx -v' \
        >"$out/nginx-version.txt" 2>&1
    for marker in a b; do
        docker exec "$server" cat "/out/backend-$marker.log" \
            >"$out/backend-$marker.log" 2>/dev/null || true
    done
}

ops32_verdict() {
    local base=$1 mode=$2 suffix=$3
    # The analyzer is a standalone driver so the same code recomputes evidence
    # recorded by earlier runs instead of only applying to new runs.
    python3 "$SUITE/drivers/ops32_analyze.py" \
        "$base" "$mode" "$suffix" "$OPS32_A_HOST" "$OPS32_A_PORT" \
        "$OPS32_B_HOST" "$OPS32_B_PORT" "$OPS32_WEIGHT" \
        "$OPS32_RECOVERY" "$OPS32_RECOVERY_INTERVAL" "$OPS32_STABLE_MIN"
}

ops32_ws_job() {
    local oid=OPS-32
    local net="e2e-$RUN_ID-$oid-ws"
    local base="$EVID/$oid/ws" bdir="$EVID/$oid/ws/bash" gdir="$EVID/$oid/ws/go"
    mkdir -p "$bdir" "$gdir"
    docker network create "$net" >/dev/null 2>&1 || true
    log "[$oid] start upstream=ws"

    # ---- bash side: real M4 (tls-ws) install + real menu adds ----
    local bserver="e2e-$RUN_ID-$oid-ws-bash"
    if start_server "$bserver" "$oid" bash "$bdir" "$net"; then
        run_bash_round M4 "$net" "$bserver" "$bdir" 1 "" tls "-1" "" 1
        local bloc; bloc=$(ops32_ws_location "$bserver")
        local berr; berr=$(ops32_error_log "$bserver")
        ops32_hosts "$bserver"
        if ops32_start_backend "$bserver" A "$OPS32_A_PORT" backend-a &&
           ops32_start_backend "$bserver" B "$OPS32_B_PORT" backend-b; then
            ops_bash_fm "$bserver" "$bdir" add ws 1 "$OPS32_A_HOST" \
                "$OPS32_A_PORT" "$OPS32_WEIGHT" "add-$OPS32_A_HOST"
            ops_bash_fm "$bserver" "$bdir" add ws 1 "$OPS32_B_HOST" \
                "$OPS32_B_PORT" "$OPS32_WEIGHT" "add-$OPS32_B_HOST"
            nginx_snapshot "$bserver" wsServers "$bdir/files-after-add.txt"
            ops32_drop_loopback "$bserver" "$bdir" wsServers
            ops32_side bash "$bserver" "$bdir" "$bloc" "$berr"
        else
            echo '{"status":"harness-error","reason":"marker backends did not start"}' \
                >"$bdir/harness.json"
        fi
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    # ---- go side: real tls-ws install + real balance add ----
    local gserver="e2e-$RUN_ID-$oid-ws-go"
    if start_server "$gserver" "$oid" go "$gdir" "$net"; then
        docker exec "$gserver" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
        local -a iargv=(xray install --binary /usr/local/bin/xray --mode tls
                        --transport ws --domain "$DOMAIN"
                        --cert /etc/idleleo/cert/xray.crt
                        --cert-key /etc/idleleo/cert/xray.key
                        --port 9000 --public-port 443 --container)
        run_go_round "$oid" "$gserver" "$gdir" 1 "" tls "${iargv[@]}"
        local gloc; gloc=$(ops32_ws_location "$gserver")
        local gerr; gerr=$(ops32_error_log "$gserver")
        ops32_hosts "$gserver"
        if ops32_start_backend "$gserver" A "$OPS32_A_PORT" backend-a &&
           ops32_start_backend "$gserver" B "$OPS32_B_PORT" backend-b; then
            ops_go_cli "$gserver" "$gdir" "add-$OPS32_A_HOST" \
                xray balance add --upstream ws --host "$OPS32_A_HOST" \
                --port "$OPS32_A_PORT" --weight "$OPS32_WEIGHT" --container --json
            ops_go_cli "$gserver" "$gdir" "add-$OPS32_B_HOST" \
                xray balance add --upstream ws --host "$OPS32_B_HOST" \
                --port "$OPS32_B_PORT" --weight "$OPS32_WEIGHT" --container --json
            nginx_snapshot "$gserver" wsServers "$gdir/files-after-add.txt"
            ops32_drop_loopback "$gserver" "$gdir" wsServers
            ops_go_cli "$gserver" "$gdir" balance-list \
                xray balance list --upstream ws --json
            ops32_side go "$gserver" "$gdir" "$gloc" "$gerr"
        else
            echo '{"status":"harness-error","reason":"marker backends did not start"}' \
                >"$gdir/harness.json"
        fi
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$gdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true

    log "[$oid/ws] verdict=$(ops32_verdict "$base" http wsServers)"
}

# ops32_reality_job repeats the drill on the stream upstream S2 actually added
# for Reality balance. The probe speaks a real ClientHello so `ssl_preread`
# can route it, but the peers are plain TCP markers: see the limitations block
# the verdict writes.
ops32_reality_job() {
    local oid=OPS-32
    local net="e2e-$RUN_ID-$oid-reality"
    local base="$EVID/$oid/reality" bdir="$EVID/$oid/reality/bash" gdir="$EVID/$oid/reality/go"
    mkdir -p "$bdir" "$gdir"
    docker network create "$net" >/dev/null 2>&1 || true
    log "[$oid] start upstream=reality"

    # ---- bash side: real reality-balance primary install + menu adds ----
    local bserver="e2e-$RUN_ID-$oid-reality-bash"
    if start_server "$bserver" "$oid" bash "$bdir" "$net"; then
        run_bash_round M2 "$net" "$bserver" "$bdir" 1 "" reality "" "1>1>5>1" 1
        local berr; berr=$(ops32_error_log "$bserver")
        ops32_hosts "$bserver"
        if ops32_start_backend "$bserver" A "$OPS32_A_PORT" backend-a \
               ops32_reality_backend.py &&
           ops32_start_backend "$bserver" B "$OPS32_B_PORT" backend-b \
               ops32_reality_backend.py; then
            ops_bash_fm "$bserver" "$bdir" add reality 1 "$OPS32_A_HOST" \
                "$OPS32_A_PORT" "$OPS32_WEIGHT" "add-$OPS32_A_HOST"
            ops_bash_fm "$bserver" "$bdir" add reality 1 "$OPS32_B_HOST" \
                "$OPS32_B_PORT" "$OPS32_WEIGHT" "add-$OPS32_B_HOST"
            nginx_snapshot "$bserver" realityServers "$bdir/files-after-add.txt"
            ops32_drop_loopback "$bserver" "$bdir" realityServers
            ops32_reality_side bash "$bserver" "$bdir" "$TARGET" "$berr"
        else
            echo '{"status":"harness-error","reason":"marker backends did not start"}' \
                >"$bdir/harness.json"
        fi
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    # ---- go side: real reality-balance primary install + balance add ----
    local gserver="e2e-$RUN_ID-$oid-reality-go"
    if start_server "$gserver" "$oid" go "$gdir" "$net"; then
        docker exec "$gserver" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
        local -a iargv=(xray install --binary /usr/local/bin/xray
                        --mode reality-balance --role primary --domain "$TARGET"
                        --target "$TARGET" --port 443 --container)
        run_go_round "$oid" "$gserver" "$gdir" 1 "" reality "${iargv[@]}"
        local gerr; gerr=$(ops32_error_log "$gserver")
        ops32_hosts "$gserver"
        if ops32_start_backend "$gserver" A "$OPS32_A_PORT" backend-a \
               ops32_reality_backend.py &&
           ops32_start_backend "$gserver" B "$OPS32_B_PORT" backend-b \
               ops32_reality_backend.py; then
            ops_go_cli "$gserver" "$gdir" "add-$OPS32_A_HOST" \
                xray balance add --upstream reality --host "$OPS32_A_HOST" \
                --port "$OPS32_A_PORT" --weight "$OPS32_WEIGHT" --container --json
            ops_go_cli "$gserver" "$gdir" "add-$OPS32_B_HOST" \
                xray balance add --upstream reality --host "$OPS32_B_HOST" \
                --port "$OPS32_B_PORT" --weight "$OPS32_WEIGHT" --container --json
            nginx_snapshot "$gserver" realityServers "$gdir/files-after-add.txt"
            ops32_drop_loopback "$gserver" "$gdir" realityServers
            ops_go_cli "$gserver" "$gdir" balance-list \
                xray balance list --upstream reality --json
            ops32_reality_side go "$gserver" "$gdir" "$TARGET" "$gerr"
        else
            echo '{"status":"harness-error","reason":"marker backends did not start"}' \
                >"$gdir/harness.json"
        fi
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$gdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true

    log "[$oid/reality] verdict=$(ops32_verdict "$base" stream realityServers)"
}

# ops32_merge folds the per-upstream verdicts into one OPS-32 record. The row is
# only PASS when both upstreams pass; a single HARNESS-ERROR anywhere keeps the
# whole row HARNESS-ERROR so a broken harness never reads as a product pass.
ops32_merge() {
    local base=$1
    python3 - "$base" <<'PY'
import json
import os
import sys

base = sys.argv[1]


def load(name):
    try:
        with open(os.path.join(base, name, "ops.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


upstreams = {"ws": load("ws"), "reality": load("reality")}
report = {"id": "OPS-32", "name": "后端故障摘除", "upstreams": upstreams}
missing = [name for name, rep in upstreams.items() if rep is None]
if missing:
    report["verdict"] = "HARNESS-ERROR"
    report["reasons"] = ["missing upstream verdict: %s" % ", ".join(sorted(missing))]
else:
    verdicts = {name: rep.get("verdict") for name, rep in upstreams.items()}
    reasons = ["%s: %s" % (name, reason)
               for name in sorted(upstreams)
               for reason in (upstreams[name].get("reasons") or [])]
    if "HARNESS-ERROR" in verdicts.values():
        report["verdict"] = "HARNESS-ERROR"
    elif any(value != "PASS" for value in verdicts.values()):
        report["verdict"] = "BLOCKER"
    else:
        report["verdict"] = "PASS"
    report["reasons"] = reasons
    report["upstreamVerdicts"] = verdicts
report["bothInstallRc"] = {
    side: ", ".join("%s=%s" % (name, (rep or {}).get("bothInstallRc", {}).get(side))
                    for name, rep in sorted(upstreams.items()))
    for side in ("bash", "go")
}
with open(os.path.join(base, "ops.json"), "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(report["verdict"])
PY
}

ops32_job() {
    local oid=OPS-32
    local base="$EVID/$oid"
    mkdir -p "$base"
    ops32_ws_job
    ops32_reality_job
    log "[$oid] verdict=$(ops32_merge "$base")"
}


ops_job() {
    case $1 in
        OPS-19) ops19_job ;;
        OPS-21) ops21_job ;;
        OPS-09) ops_balance_job OPS-09 ws wsServers tls ;;
        OPS-31) ops_balance_job OPS-31 reality realityServers reality ;;
        OPS-32) ops32_job ;;
        *) log "[$1] no execution path in this runner; not claiming a verdict" ;;
    esac
}

# --- scheduler -------------------------------------------------------------
SIDS=()
for sid in M1 M2 M3 M4 M5 M6 M7 M8 M9 M10; do
    if [[ -n "$ONLY" ]]; then
        case ",$ONLY," in *,${sid},*) ;; *) continue ;; esac
    fi
    SIDS+=("$sid")
done

# Batches of at most CONCURRENCY scenarios; macOS ships bash 3.2, which has no
# `wait -n`, so batches are the portable equivalent.
i=0
while (( i < ${#SIDS[@]} )); do
    batch=("${SIDS[@]:i:CONCURRENCY}")
    for sid in "${batch[@]}"; do
        scenario_job "$sid" &
    done
    wait
    i=$((i + CONCURRENCY))
done

# Config-edit scenarios are Go-only and run after the install matrix; they
# reuse a real M1 install from the same runner build.
EIDS=()
for eid in E1 E2 E3 E4 E5 E6 E7 E8; do
    if [[ -n "$ONLY" ]]; then
        case ",$ONLY," in *,$eid,*) ;; *) continue ;; esac
    fi
    EIDS+=("$eid")
done
if (( ${#EIDS[@]} > 0 )); then
    for eid in "${EIDS[@]}"; do
        edit_job "$eid" &
    done
    wait
fi

# OPS scenarios run after E*. OPS-19 (Fail2ban), OPS-21 (流量阻断),
# OPS-09 (Nginx 负载均衡), OPS-31 (Reality 负载均衡) and OPS-32 (后端故障摘除)
# have real execution paths; every other OPS row is reported NOT-RUN rather than
# silently inheriting its declared verdict.
OIDS=()
for oid in OPS-19 OPS-21 OPS-09 OPS-31 OPS-32; do
    if [[ -z "$ONLY" ]]; then
        OIDS+=("$oid")
    else
        case ",$ONLY," in *",${oid},"*) OIDS+=("$oid") ;; esac
    fi
done
if (( ${#OIDS[@]} > 0 )); then
    for oid in "${OIDS[@]}"; do
        ops_job "$oid"
    done
fi

# Record what this run actually executed. report.py treats a non-empty `only`
# as a partial run and renders everything outside this scope as NOT-RUN, so an
# E2E_ONLY subset can never be mistaken for a full-matrix verdict later.
SCOPE_INSTALLS="$(IFS=,; printf '%s' "${SIDS[*]-}")"
SCOPE_EDITS="$(IFS=,; printf '%s' "${EIDS[*]-}")"
SCOPE_OPS="$(IFS=,; printf '%s' "${OIDS[*]-}")"
python3 - "$EVID/scope.json" "$RUN_ID" "$ONLY" \
    "$SCOPE_INSTALLS" "$SCOPE_EDITS" "$SCOPE_OPS" <<'PY'
import json
import sys

out, run_id, only, installs, edits, ops = sys.argv[1:7]
split = lambda text: [item for item in text.split(",") if item]
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"runId": run_id, "only": only,
               "installs": split(installs), "edits": split(edits),
               "ops": split(ops), "sides": ["bash", "go"]},
              fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
PY
log "scope: installs=[$SCOPE_INSTALLS] edits=[$SCOPE_EDITS] ops=[$SCOPE_OPS]"

BASELINE="${E2E_BASELINE:-$SUITE/evidence/clean-run01-d5f17dc/p2}"
BASELINE_ARGS=()
[[ -d "$BASELINE" ]] && BASELINE_ARGS=(--baseline "$BASELINE")

python3 "$SUITE/compare/report.py" --evidence "$EVID" --matrix "$SUITE/matrix.json" \
    --diffs "$SUITE/expected_diffs.json" "${BASELINE_ARGS[@]}" >/dev/null 2>&1 || \
    log "report generation failed"

log "P2 finished: $EVID"
