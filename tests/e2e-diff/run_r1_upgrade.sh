#!/usr/bin/env bash
# R1/R2 migration runner: take over a real Bash installation in place.
#
# R1: Bash install (M1 reality, M4 TLS+ws) -> `idleleo xray install --keep-config`
#     must keep the runtime config, certificate, unit, ports and live traffic.
# R2: Bash install -> `idleleo bridge audit/prepare/validate/activate` must take
#     over the same tree without rewriting it.
#
# Each scenario uses one container per path, so the R2 container is still in the
# Bash state when the bridge runs. Every step records rc/stdout/stderr; a failed
# assertion is evidence, not a reason to abort the remaining scenarios.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-$(date +%Y%m%d-%H%M)-$(git -C "$ROOT" rev-parse --short HEAD)}"
EVID="$SUITE/evidence/$RUN_ID/r1"
WORK="/tmp/e2e-$RUN_ID"
IMAGE_TAG="${E2E_IMAGE_TAG:-idleleo-e2e:24.04}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
DOMAIN="${E2E_DOMAIN:-example.com}"
TARGET="${E2E_TARGET:-www.cloudflare.com}"
ONLY="${E2E_ONLY:-M1,M4}"
PATHS="${E2E_PATHS:-both}"

source "$ROOT/tests/go-parity/lib/docker_common.sh"

mkdir -p "$EVID" "$WORK/seed/cert" "$WORK/secret"
: >"$EVID/assertions.txt"
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$EVID/run.log"; }
assert() { # assert <ok:0|1> <label>
    if [ "$1" -eq 0 ]; then
        printf 'PASS\t%s\n' "$2" >>"$EVID/assertions.txt"
    else
        printf 'FAIL\t%s\n' "$2" >>"$EVID/assertions.txt"
    fi
}
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

log "building idleleo"
docker run --rm -v "$ROOT:/src:ro" -v "$WORK/seed:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
    "$GO_IMAGE" bash -c 'go build -buildvcs=false -trimpath -o /out/idleleo ./cmd/idleleo &&
        go build -buildvcs=false -trimpath -o /out/idleleo-recover ./cmd/idleleo-recover' || {
    log "FATAL: idleleo build failed"; exit 2
}

ARCH=$(docker_arch) || exit 2
if [[ -x "$ROOT/tests/go-parity/.cache/a2/xray" ]]; then
    cp "$ROOT/tests/go-parity/.cache/a2/xray" "$WORK/seed/xray"
else
    ensure_xray_bin "$ARCH" >/dev/null || { log "FATAL: xray binary unavailable"; exit 2; }
    cp "$(ensure_xray_bin "$ARCH")" "$WORK/seed/xray"
fi
chmod 0755 "$WORK/seed/xray" "$WORK/seed/idleleo" "$WORK/seed/idleleo-recover"
log "idleleo_sha256=$(sha "$WORK/seed/idleleo") recover_sha256=$(sha "$WORK/seed/idleleo-recover") xray_sha256=$(sha "$WORK/seed/xray")"

docker run --rm -v "$WORK/seed:/seed" "$IMAGE_TAG" bash -c \
    "openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=$DOMAIN' \
     -addext 'subjectAltName=DNS:$DOMAIN' \
     -keyout /seed/cert/xray.key -out /seed/cert/xray.crt >/dev/null 2>&1" || {
    log "FATAL: certificate generation failed"; exit 2
}

python3 - "$EVID/run.json" <<PY
import json
print(json.dumps({
    "runId": "$RUN_ID",
    "commit": "$(git -C "$ROOT" rev-parse HEAD)",
    "branch": "$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)",
    "imageTag": "$IMAGE_TAG",
    "scenarios": "$ONLY",
}, indent=2, sort_keys=True), file=open("$EVID/run.json", "w"))
PY

start_server() { # start_server <name> <out> <net>
    local name=$1 out=$2 net=$3
    docker rm -f "$name" >/dev/null 2>&1 || true
    mkdir -p "$out"
    # shellcheck disable=SC2046
    docker run -d --name "$name" --hostname "$name" --network "$net" \
        --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
        $(cgroup_mount_args) \
        -v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$out:/out" \
        "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null
    for _ in $(seq 1 60); do
        local st
        st=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
        [[ "$st" == running || "$st" == degraded ]] && return 0
        sleep 1
    done
    return 1
}

# snap writes hashes and the sanitized config, never the raw secrets.
snap() { # snap <container> <host-out-dir>
    local c=$1 out=$2
    docker exec "$c" sh -c '
        set -u
        mkdir -p /tmp/snap
        for f in /etc/idleleo/conf/xray/config.json /etc/idleleo/cert/xray.crt \
                 /etc/idleleo/cert/xray.key /etc/systemd/system/xray.service; do
            [ -f "$f" ] && sha256sum "$f"
        done >/tmp/snap/sha.txt
        find /etc/systemd/system -name "nginx*.service" -maxdepth 1 2>/dev/null \
            | sort | while read -r u; do sha256sum "$u"; done >>/tmp/snap/sha.txt
        jq "(.inbounds[]?.streamSettings.realitySettings.privateKey?) = \"REDACTED\"
            | (.inbounds[]?.settings.clients[]?.id?) = \"REDACTED\"" \
            /etc/idleleo/conf/xray/config.json 2>/dev/null >/tmp/snap/config.sanitized.json \
            || true
        jq -S . /tmp/snap/config.sanitized.json >/tmp/snap/config.sorted.json 2>/dev/null || true
        { systemctl is-active xray 2>/dev/null || true
          systemctl is-active nginx 2>/dev/null || true
        } >/tmp/snap/active.txt
        ss -ltn 2>/dev/null | awk "NR>1{print \$4}" | sort >/tmp/snap/ports.txt
        crontab -l 2>/dev/null >/tmp/snap/cron.txt || : >/tmp/snap/cron.txt
        /usr/local/bin/xray -test -config /etc/idleleo/conf/xray/config.json \
            >/tmp/snap/xray-test.log 2>&1; echo $? >/tmp/snap/xray-test.rc
        if [ -x /usr/local/nginx/sbin/nginx ]; then
            /usr/local/nginx/sbin/nginx -t >/tmp/snap/nginx-test.log 2>&1
        else
            printf "no-nginx\n" >/tmp/snap/nginx-test.log
        fi
        echo $? >/tmp/snap/nginx-test.rc
    ' >/dev/null 2>&1
    mkdir -p "$out"
    docker cp "$c:/tmp/snap/." "$out/" >/dev/null 2>&1 || true
}

run_l4() { # run_l4 <scenario> <container> <out-dir> <net> <profile> <transport> <label>
    local sid=$1 c=$2 out=$3 net=$4 profile=$5 transport=$6 label=$7
    local client="e2e-$RUN_ID-$sid-$label"
    bash "$SUITE/collect/l4.sh" "$c" "$client" "$IMAGE_TAG" "$net" \
        "$profile" "$DOMAIN" "$WORK/seed/xray" "$WORK/secret/$sid-$label" \
        "$out/L4-$label" "$transport" >"$out/L4-$label.log" 2>&1
    echo $? >"$out/L4-$label.rc"
}

# --- R1: Bash install -> Go --keep-config takeover --------------------------
# Takes --mode/--domain/--target because the installer always generates a
# candidate (only the runtime config is preserved), and reality generation
# refuses to run without a server name.
run_r1() { # run_r1 <sid> <profile> <bash-arg> <l4-profile> <l4-transport> <go-args...>
    local sid=$1 profile=$2 barg=$3 l4p=$4 l4t=$5
    shift 5
    local -a goargs=("$@")
    local net="e2e-$RUN_ID-$sid-r1-net" c="e2e-$RUN_ID-$sid-r1"
    local out="$EVID/$sid/R1"
    docker network create "$net" >/dev/null 2>&1 || true
    log "[$sid/R1] start"
    if ! start_server "$c" "$out/bash" "$net"; then
        log "[$sid/R1] container failed"; assert 1 "$sid R1 container started"; return
    fi

    docker exec -e E2E_OUT=/out -e E2E_ROUND=1 -e E2E_SCENARIO="$sid" \
        -e E2E_PROFILE="$profile" -e E2E_ARG="$barg" -e E2E_MENU="" \
        -e E2E_TRANSPORT=1 -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET" \
        -e E2E_PORT=443 -e E2E_LOCAL_IP=127.0.0.1 \
        "$c" bash /src/tests/e2e-diff/drivers/bash_install.sh
    local brc=$?
    echo "$brc" >"$out/bash.rc"
    assert $([ "$brc" -eq 0 ] && echo 0 || echo 1) "$sid R1 bash install exits 0 (rc=$brc)"
    [ "$brc" -eq 0 ] || { docker rm -f "$c" >/dev/null 2>&1; return; }

    snap "$c" "$out/pre"
    run_l4 "$sid" "$c" "$out" "$net" "$l4p" "$l4t" pre
    local l4pre; l4pre=$(cat "$out/L4-pre.rc")
    assert $([ "$l4pre" -eq 0 ] && echo 0 || echo 1) "$sid R1 traffic works before takeover (rc=$l4pre)"

    docker exec "$c" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$c" \
        /usr/local/bin/idleleo xray install --keep-config --binary /usr/local/bin/xray \
        --container --json "${goargs[@]}" >"$out/takeover.json" 2>"$out/takeover.err"
    local grc=$?
    echo "$grc" >"$out/takeover.rc"
    assert $([ "$grc" -eq 0 ] && echo 0 || echo 1) "$sid R1 go install --keep-config exits 0 (rc=$grc)"
    snap "$c" "$out/post"

    local same_sorted same_bytes same_cert same_ports same_cron
    same_sorted=$(cmp -s "$out/pre/config.sorted.json" "$out/post/config.sorted.json" && echo 0 || echo 1)
    same_bytes=$(python3 - "$out/pre/sha.txt" "$out/post/sha.txt" <<'PY'
import sys
def cfg(p):
    for line in open(p):
        h, f = line.split(maxsplit=1)
        if f.strip().endswith('/etc/idleleo/conf/xray/config.json'):
            return h
    return ''
print(0 if cfg(sys.argv[1]) and cfg(sys.argv[1]) == cfg(sys.argv[2]) else 1)
PY
)
    same_cert=$(python3 - "$out/pre/sha.txt" "$out/post/sha.txt" <<'PY'
import sys
def get(p):
    out={}
    for line in open(p):
        h,f=line.split(maxsplit=1)
        f=f.strip()
        if f.endswith('/cert/xray.crt') or f.endswith('/cert/xray.key'):
            out[f]=h
    return out
a,b=get(sys.argv[1]),get(sys.argv[2])
print(0 if a and a==b else 1)
PY
)
    same_ports=$(cmp -s "$out/pre/ports.txt" "$out/post/ports.txt" && echo 0 || echo 1)
    same_cron=$(cmp -s "$out/pre/cron.txt" "$out/post/cron.txt" && echo 0 || echo 1)
    assert "$same_sorted" "$sid R1 runtime config is semantically unchanged"
    assert "$same_bytes"  "$sid R1 runtime config bytes are unchanged"
    if [ "$l4p" = "tls" ]; then
        assert "$same_cert" "$sid R1 certificate and key are untouched"
        assert $([[ "$(cat "$out/post/nginx-test.rc")" == "0" ]] && echo 0 || echo 1) \
            "$sid R1 nginx config still validates"
    fi
    assert $([[ "$(cat "$out/post/xray-test.rc")" == "0" ]] && echo 0 || echo 1) \
        "$sid R1 xray config still validates"
    assert $([ "$(sed -n 1p "$out/post/active.txt")" = "active" ] && echo 0 || echo 1) \
        "$sid R1 xray stays active"
    assert "$same_ports" "$sid R1 listening ports are unchanged"
    assert "$same_cron"  "$sid R1 cron table is unchanged"

    run_l4 "$sid" "$c" "$out" "$net" "$l4p" "$l4t" post
    assert $([ "$(cat "$out/L4-post.rc")" -eq 0 ] && echo 0 || echo 1) \
        "$sid R1 traffic works after takeover (rc=$(cat "$out/L4-post.rc"))"

    docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$c" \
        /usr/local/bin/idleleo status --json >"$out/status.json" 2>"$out/status.err"
    echo $? >"$out/status.rc"
    assert $([ "$(cat "$out/status.rc")" -eq 0 ] && echo 0 || echo 1) "$sid R1 status exits 0"
    assert $(jq -e '.installed == true' "$out/status.json" >/dev/null 2>&1 && echo 0 || echo 1) \
        "$sid R1 status reports an installed runtime"
    # U6: the adopted runtime classification must match what Bash installed.
    local want_tls want_tr
    case "$l4p" in
        reality) want_tls=Reality want_tr=raw ;;
        tls) want_tls=TLS want_tr=$l4t ;;
        *) want_tls="" want_tr="" ;;
    esac
    if [ -n "$want_tls" ]; then
        assert $(jq -e --arg t "$want_tls" --arg n "$want_tr" \
            '.tls == $t and .transport == $n' "$out/status.json" >/dev/null 2>&1 && echo 0 || echo 1) \
            "$sid R1 status classification is ${want_tls}/${want_tr}"
    fi

    [[ "${E2E_KEEP:-0}" == "1" ]] || { docker rm -f "$c" >/dev/null 2>&1; docker network rm "$net" >/dev/null 2>&1; }
}

# --- R2: Bash install -> bridge takeover ------------------------------------
run_r2() { # run_r2 <sid> <profile> <bash-arg> <l4-profile> <l4-transport>
    local sid=$1 profile=$2 barg=$3 l4p=$4 l4t=$5
    local net="e2e-$RUN_ID-$sid-r2-net" c="e2e-$RUN_ID-$sid-r2"
    local out="$EVID/$sid/R2"
    docker network create "$net" >/dev/null 2>&1 || true
    log "[$sid/R2] start"
    if ! start_server "$c" "$out/bash" "$net"; then
        log "[$sid/R2] container failed"; assert 1 "$sid R2 container started"; return
    fi
    docker exec -e E2E_OUT=/out -e E2E_ROUND=1 -e E2E_SCENARIO="$sid" \
        -e E2E_PROFILE="$profile" -e E2E_ARG="$barg" -e E2E_MENU="" \
        -e E2E_TRANSPORT=1 -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET" \
        -e E2E_PORT=443 -e E2E_LOCAL_IP=127.0.0.1 \
        "$c" bash /src/tests/e2e-diff/drivers/bash_install.sh
    local brc=$?
    echo "$brc" >"$out/bash.rc"
    assert $([ "$brc" -eq 0 ] && echo 0 || echo 1) "$sid R2 bash install exits 0 (rc=$brc)"
    [ "$brc" -eq 0 ] || { docker rm -f "$c" >/dev/null 2>&1; return; }

    snap "$c" "$out/pre"
    docker exec "$c" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    docker exec "$c" install -m 0755 /seed/idleleo-recover /usr/local/bin/idleleo-recover
    local -a envs=(-e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY)
    local step
    for step in audit prepare validate activate status; do
        local -a args=()
        case $step in
            audit) args=(bridge audit --json) ;;
            # --recovery is mandatory for activation and --acknowledge-custom is
            # the documented Bash->Go promotion flow (install.sh uses both):
            # a Bash tree carries files the Go plan does not own.
            prepare) args=(bridge prepare --candidate /usr/local/bin/idleleo \
                --recovery /usr/local/bin/idleleo-recover --acknowledge-custom --container --json) ;;
            validate) args=(bridge validate --xray /usr/local/bin/xray --container --json) ;;
            activate) args=(bridge activate --container --json) ;;
            status) args=(bridge status --json) ;;
        esac
        if [ "$step" = "validate" ] && [ "$profile" = "tls" ]; then
            args=(bridge validate --xray /usr/local/bin/xray --nginx /usr/local/nginx/sbin/nginx --container --json)
        fi
        docker exec "${envs[@]}" "$c" /usr/local/bin/idleleo "${args[@]}" \
            >"$out/bridge-$step.json" 2>"$out/bridge-$step.err"
        echo $? >"$out/bridge-$step.rc"
        assert $([ "$(cat "$out/bridge-$step.rc")" -eq 0 ] && echo 0 || echo 1) \
            "$sid R2 bridge $step exits 0 (rc=$(cat "$out/bridge-$step.rc"))"
    done

    snap "$c" "$out/post"
    local same_sorted same_ports
    same_sorted=$(cmp -s "$out/pre/config.sorted.json" "$out/post/config.sorted.json" && echo 0 || echo 1)
    same_ports=$(cmp -s "$out/pre/ports.txt" "$out/post/ports.txt" && echo 0 || echo 1)
    assert "$same_sorted" "$sid R2 runtime config is semantically unchanged"
    assert "$same_ports"  "$sid R2 listening ports are unchanged"
    assert $([ "$(sed -n 1p "$out/post/active.txt")" = "active" ] && echo 0 || echo 1) \
        "$sid R2 xray stays active"
    assert $(jq -e '.state == "COMMITTED"' "$out/bridge-status.json" >/dev/null 2>&1 && echo 0 || echo 1) \
        "$sid R2 bridge status reports a committed migration"
    run_l4 "$sid" "$c" "$out" "$net" "$l4p" "$l4t" post
    assert $([ "$(cat "$out/L4-post.rc")" -eq 0 ] && echo 0 || echo 1) \
        "$sid R2 traffic works after activation (rc=$(cat "$out/L4-post.rc"))"

    [[ "${E2E_KEEP:-0}" == "1" ]] || { docker rm -f "$c" >/dev/null 2>&1; docker network rm "$net" >/dev/null 2>&1; }
}

run_paths() { # run_paths <sid> <args...> -- respects E2E_PATHS
    local sid=$1; shift
    case ",$PATHS," in
        *,both,*) run_r1 "$sid" "$@"; run_r2 "$sid" "$@" ;;
        *,r1,*)   run_r1 "$sid" "$@" ;;
        *,r2,*)   run_r2 "$sid" "$@" ;;
    esac
}

log "run_start=$(date -u +%Y-%m-%dT%H:%M:%SZ) only=$ONLY paths=$PATHS"
case ",$ONLY," in *,M1,*) run_paths M1 reality -2 reality reality \
    --mode reality --domain "$DOMAIN" --target "$TARGET" --port 443 ;; esac
case ",$ONLY," in *,M4,*) run_paths M4 tls -1 tls ws \
    --mode tls --transport ws --domain "$DOMAIN" --port 443 ;; esac
log "run_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s PASS\n%s FAIL\n' \
    "$(grep -c '^PASS' "$EVID/assertions.txt")" "$(grep -c '^FAIL' "$EVID/assertions.txt")" | tee -a "$EVID/run.log"
