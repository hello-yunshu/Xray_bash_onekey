#!/usr/bin/env bash
# R1/R2 migration runner: take over a real Bash installation in place.
#
# R1: Bash install (M1 reality, M4 TLS+ws) -> `idleleo xray install --keep-config`
#     must keep the runtime config, certificate, unit, ports and live traffic.
# R2: Bash install -> `idleleo bridge audit/prepare/validate/activate` must take
#     over the same tree without rewriting it.
# INJ: matrix.json upgrade.injections I1/I2/I4 on the Bash tree plus I3 on a
#     clean container; a refused takeover must name the broken input and leave
#     the running installation untouched.
#
# E2E_PATHS selects what runs: both (default: r1+r2+inj), r1, r2, or inj.
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

# The Bash TLS install downloads a managed Nginx. Seed the verified offline
# cache so a GitHub CDN hiccup cannot fail the takeover matrix.
NGINX_BUILD="${E2E_NGINX_BUILD:-2026.10.15.7679}"
case "$(docker_arch)" in
    amd64) NGINX_ARCH=x86 ;;
    arm64) NGINX_ARCH=arm ;;
    *) NGINX_ARCH="" ;;
esac
NGINX_ASSET="xray-nginx-custom-${NGINX_ARCH}.tar.gz"
NGINX_CACHE="${E2E_NGINX_CACHE:-$HOME/.cache/xray-audit/nginx/$NGINX_BUILD}"
NGINX_ENVS=()
if [[ -n "$NGINX_ARCH" && -f "$NGINX_CACHE/release-manifest.json" && -f "$NGINX_CACHE/$NGINX_ASSET" ]]; then
    mkdir -p "$WORK/seed/nginx"
    cp "$NGINX_CACHE/release-manifest.json" "$WORK/seed/nginx/"
    cp "$NGINX_CACHE/$NGINX_ASSET" "$WORK/seed/nginx/"
    printf '{"nginx_build_online_version":"%s"}\n' "$NGINX_BUILD" >"$WORK/seed/nginx/versions.json"
    NGINX_ENVS=(-e IDLELEO_NGINX_CACHE=/seed/nginx -e E2E_NGINX_BUILD="$NGINX_BUILD")
fi
# The Bash installer also fetches its Xray config template from the release raw
# tree. Seed the tracked templates so a raw.githubusercontent.com timeout cannot
# turn a takeover regression into a false failure; the installer still validates
# the JSON it reads.
mkdir -p "$WORK/seed/release/config"
for _tpl in vless_reality.json vless_tls.json; do
    if [[ -f "$ROOT/config/$_tpl" ]]; then
        cp "$ROOT/config/$_tpl" "$WORK/seed/release/config/$_tpl"
    fi
done
if [[ "$(ls -A "$WORK/seed/release/config" 2>/dev/null | wc -l)" -gt 0 ]]; then
    NGINX_ENVS+=(-e IDLELEO_RELEASE_CACHE=/seed/release)
fi
# Historical migration: point the driver at a real older installer (mounted as
# /seed/historical.sh) instead of the tracked one. No snapshot is fabricated.
if [[ -n "${E2E_HISTORICAL_INSTALLER:-}" ]]; then
    install -m 0755 "$E2E_HISTORICAL_INSTALLER" "$WORK/seed/historical.sh"
    # The driver must install from the mounted historical copy, not the
    # tracked install.sh; otherwise the run silently tests the current shell.
    export E2E_INSTALL_SRC="${E2E_INSTALL_SRC:-/seed/historical.sh}"
fi
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

    docker exec "${NGINX_ENVS[@]}" \
        -e E2E_OUT=/out -e E2E_ROUND=1 -e E2E_SCENARIO="$sid" \
        -e E2E_PROFILE="$profile" -e E2E_ARG="$barg" -e E2E_MENU="" \
        -e E2E_INSTALL_SRC="${E2E_INSTALL_SRC:-}" \
        -e E2E_TRANSPORT=1 -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET" \
        -e E2E_PORT=443 -e E2E_LOCAL_IP=127.0.0.1 \
        "$c" bash /src/tests/e2e-diff/drivers/bash_install.sh
    local brc=$?
    echo "$brc" >"$out/bash.rc"
    assert "$([ "$brc" -eq 0 ] && echo 0 || echo 1)" "$sid R1 bash install exits 0 (rc=$brc)"
    [ "$brc" -eq 0 ] || { docker rm -f "$c" >/dev/null 2>&1; return; }

    snap "$c" "$out/pre"
    run_l4 "$sid" "$c" "$out" "$net" "$l4p" "$l4t" pre
    local l4pre; l4pre=$(cat "$out/L4-pre.rc")
    assert "$([ "$l4pre" -eq 0 ] && echo 0 || echo 1)" "$sid R1 traffic works before takeover (rc=$l4pre)"

    docker exec "$c" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$c" \
        /usr/local/bin/idleleo xray install --keep-config --binary /usr/local/bin/xray \
        --container --json "${goargs[@]}" >"$out/takeover.json" 2>"$out/takeover.err"
    local grc=$?
    echo "$grc" >"$out/takeover.rc"
    assert "$([ "$grc" -eq 0 ] && echo 0 || echo 1)" "$sid R1 go install --keep-config exits 0 (rc=$grc)"
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
        assert "$([[ "$(cat "$out/post/nginx-test.rc")" == "0" ]] && echo 0 || echo 1)" \
            "$sid R1 nginx config still validates"
    fi
    assert "$([[ "$(cat "$out/post/xray-test.rc")" == "0" ]] && echo 0 || echo 1)" \
        "$sid R1 xray config still validates"
    assert "$([ "$(sed -n 1p "$out/post/active.txt")" = "active" ] && echo 0 || echo 1)" \
        "$sid R1 xray stays active"
    assert "$same_ports" "$sid R1 listening ports are unchanged"
    assert "$same_cron"  "$sid R1 cron table is unchanged"

    run_l4 "$sid" "$c" "$out" "$net" "$l4p" "$l4t" post
    assert "$([ "$(cat "$out/L4-post.rc")" -eq 0 ] && echo 0 || echo 1)" \
        "$sid R1 traffic works after takeover (rc=$(cat "$out/L4-post.rc"))"

    docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$c" \
        /usr/local/bin/idleleo status --json >"$out/status.json" 2>"$out/status.err"
    echo $? >"$out/status.rc"
    assert "$([ "$(cat "$out/status.rc")" -eq 0 ] && echo 0 || echo 1)" "$sid R1 status exits 0"
    assert "$(jq -e '.installed == true' "$out/status.json" >/dev/null 2>&1 && echo 0 || echo 1)" \
        "$sid R1 status reports an installed runtime"
    # U6: the adopted runtime classification must match what Bash installed.
    local want_tls want_tr
    case "$l4p" in
        reality) want_tls=Reality want_tr=raw ;;
        tls) want_tls=TLS want_tr=$l4t ;;
        *) want_tls="" want_tr="" ;;
    esac
    if [ -n "$want_tls" ]; then
        assert "$(jq -e --arg t "$want_tls" --arg n "$want_tr" \
            '.tls == $t and .transport == $n' "$out/status.json" >/dev/null 2>&1 && echo 0 || echo 1)" \
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
    docker exec "${NGINX_ENVS[@]}" \
        -e E2E_OUT=/out -e E2E_ROUND=1 -e E2E_SCENARIO="$sid" \
        -e E2E_PROFILE="$profile" -e E2E_ARG="$barg" -e E2E_MENU="" \
        -e E2E_INSTALL_SRC="${E2E_INSTALL_SRC:-}" \
        -e E2E_TRANSPORT=1 -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET" \
        -e E2E_PORT=443 -e E2E_LOCAL_IP=127.0.0.1 \
        "$c" bash /src/tests/e2e-diff/drivers/bash_install.sh
    local brc=$?
    echo "$brc" >"$out/bash.rc"
    assert "$([ "$brc" -eq 0 ] && echo 0 || echo 1)" "$sid R2 bash install exits 0 (rc=$brc)"
    [ "$brc" -eq 0 ] || { docker rm -f "$c" >/dev/null 2>&1; return; }

    snap "$c" "$out/pre"
    docker exec "$c" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    docker exec "$c" install -m 0755 /seed/idleleo-recover /usr/local/bin/idleleo-recover
    local -a envs=(-e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY ${NGINX_ENVS[@]+"${NGINX_ENVS[@]}"})
    # Fault injection: a prepare that hits ENOSPC must leave no journal, plan,
    # snapshot or entry change behind, and a clean prepare must then succeed.
    docker exec "${envs[@]}" "$c" /usr/local/bin/idleleo bridge prepare \
        --candidate /usr/local/bin/idleleo --recovery /usr/local/bin/idleleo-recover \
        --acknowledge-custom --fault disk-full --container --json \
        >"$out/fault-diskfull.json" 2>"$out/fault-diskfull.err"
    local frc=$?
    echo "$frc" >"$out/fault-diskfull.rc"
    assert "$([ "$frc" -eq 13 ] && echo 0 || echo 1)" \
        "$sid R2 disk-full prepare exits 13 (rc=$frc)"
    snap "$c" "$out/fault"
    assert "$(cmp -s "$out/pre/config.sorted.json" "$out/fault/config.sorted.json" && echo 0 || echo 1)" \
        "$sid R2 disk-full leaves the runtime config untouched"
    assert "$(cmp -s "$out/pre/sha.txt" "$out/fault/sha.txt" && echo 0 || echo 1)" \
        "$sid R2 disk-full leaves config, certs and units untouched"
    assert "$(docker exec "$c" sh -c \
        '[ ! -e /var/lib/idleleo/bridge/journal.json ] && [ ! -e /var/lib/idleleo/bridge/plan.json ] && echo 0 || echo 1')" \
        "$sid R2 disk-full leaves no journal or plan"
    local step
    # OPS-26 on the tree it exists for: a Bash install carries
    # install_config.json but no Go metadata store, so this import is the
    # legacy migration path. It must create the store and leave the runtime
    # config byte-identical; the bridge steps afterwards then run with metadata
    # already in place, which Prepare backs up instead of ignoring.
    local mpre mpost
    mpre=$(docker exec "$c" sha256sum /etc/idleleo/conf/xray/config.json | awk '{print $1}')
    docker exec "${envs[@]}" "$c" /usr/local/bin/idleleo metadata import \
        --from install_config.json --container >"$out/metadata-import.out" 2>"$out/metadata-import.err"
    local mrc=$?
    mpost=$(docker exec "$c" sha256sum /etc/idleleo/conf/xray/config.json | awk '{print $1}')
    assert "$([ "$mrc" -eq 0 ] && echo 0 || echo 1)" \
        "$sid OPS-26 metadata import from a Bash tree (rc=$mrc)"
    assert "$(docker exec "$c" sh -c '[ -f /etc/idleleo/v1/metadata.json ] && echo 0 || echo 1')" \
        "$sid OPS-26 import creates the Go metadata store"
    assert "$([ -n "$mpre" ] && [ "$mpre" = "$mpost" ] && echo 0 || echo 1)" \
        "$sid OPS-26 import leaves the runtime config untouched"
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
        assert "$([ "$(cat "$out/bridge-$step.rc")" -eq 0 ] && echo 0 || echo 1)" \
            "$sid R2 bridge $step exits 0 (rc=$(cat "$out/bridge-$step.rc"))"
    done

    snap "$c" "$out/post"
    local same_sorted same_ports
    same_sorted=$(cmp -s "$out/pre/config.sorted.json" "$out/post/config.sorted.json" && echo 0 || echo 1)
    same_ports=$(cmp -s "$out/pre/ports.txt" "$out/post/ports.txt" && echo 0 || echo 1)
    assert "$same_sorted" "$sid R2 runtime config is semantically unchanged"
    assert "$same_ports"  "$sid R2 listening ports are unchanged"
    assert "$([ "$(sed -n 1p "$out/post/active.txt")" = "active" ] && echo 0 || echo 1)" \
        "$sid R2 xray stays active"
    assert "$(jq -e '.state == "COMMITTED"' "$out/bridge-status.json" >/dev/null 2>&1 && echo 0 || echo 1)" \
        "$sid R2 bridge status reports a committed migration"
    run_l4 "$sid" "$c" "$out" "$net" "$l4p" "$l4t" post
    assert "$([ "$(cat "$out/L4-post.rc")" -eq 0 ] && echo 0 || echo 1)" \
        "$sid R2 traffic works after activation (rc=$(cat "$out/L4-post.rc"))"

    [[ "${E2E_KEEP:-0}" == "1" ]] || { docker rm -f "$c" >/dev/null 2>&1; docker network rm "$net" >/dev/null 2>&1; }
}

# --- I1/I2/I4: fault injection on the Bash tree before takeover -------------
# matrix.json upgrade.injections: a takeover must refuse the candidate, name
# the broken input, and leave the running installation alone.
run_injections() { # run_injections <sid> <profile> <bash-arg> <go-args...>
    local sid=$1 profile=$2 barg=$3
    shift 3
    local -a goargs=("$@")
    local net="e2e-$RUN_ID-$sid-inj-net" c="e2e-$RUN_ID-$sid-inj"
    local out="$EVID/$sid/INJ" cfg=/etc/idleleo/conf/xray/config.json
    local -a envs=(-e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY ${NGINX_ENVS[@]+"${NGINX_ENVS[@]}"})
    docker network create "$net" >/dev/null 2>&1 || true
    log "[$sid/INJ] start"
    if ! start_server "$c" "$out/bash" "$net"; then
        log "[$sid/INJ] container failed"; assert 1 "$sid INJ container started"; return
    fi
    docker exec "${NGINX_ENVS[@]}" \
        -e E2E_OUT=/out -e E2E_ROUND=1 -e E2E_SCENARIO="$sid" \
        -e E2E_PROFILE="$profile" -e E2E_ARG="$barg" -e E2E_MENU="" \
        -e E2E_INSTALL_SRC="${E2E_INSTALL_SRC:-}" \
        -e E2E_TRANSPORT=1 -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET" \
        -e E2E_PORT=443 -e E2E_LOCAL_IP=127.0.0.1 \
        "$c" bash /src/tests/e2e-diff/drivers/bash_install.sh
    local brc=$?
    echo "$brc" >"$out/bash.rc"
    assert "$([ "$brc" -eq 0 ] && echo 0 || echo 1)" "$sid INJ bash install exits 0 (rc=$brc)"
    [ "$brc" -eq 0 ] || { docker rm -f "$c" >/dev/null 2>&1; return; }

    docker exec "$c" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    snap "$c" "$out/pre"

    # attempt <injection>: run the takeover and keep rc/stdout/stderr.
    attempt() { # attempt <injection>
        docker exec "${envs[@]}" "$c" /usr/local/bin/idleleo xray install --keep-config \
            --binary /usr/local/bin/xray --container --json "${goargs[@]}" \
            >"$out/$1.json" 2>"$out/$1.err"
        echo $? >"$out/$1.rc"
    }
    # fingerprint of everything a refused takeover must not touch, minus the
    # input the injection itself changed.
    untouched() { # untouched <injection> [extra-exclude-regex]
        local inj=$1 pat=${2:-}
        grep -v "/etc/idleleo/conf/xray/config.json" "$out/pre/sha.txt" | sort \
            >"$out/pre/others.txt"
        grep -v "/etc/idleleo/conf/xray/config.json" "$out/$inj/sha.txt" | sort \
            >"$out/$inj/others.txt"
        if [ -n "$pat" ]; then
            for f in "$out/pre/others.txt" "$out/$inj/others.txt"; do
                grep -Ev "$pat" "$f" >"$f.tmp" && mv "$f.tmp" "$f"
            done
        fi
        cmp -s "$out/pre/others.txt" "$out/$inj/others.txt" && echo 0 || echo 1
    }
    restore_service() { # restore_service <injection>
        docker exec "$c" systemctl restart xray >/dev/null 2>&1
        local rc=$?
        sleep 2
        local st; st=$(docker exec "$c" systemctl is-active xray 2>/dev/null | head -1)
        echo "restart_rc=$rc state=$st" >"$out/$1.restart.txt"
        assert "$([ "$rc" -eq 0 ] && [ "$st" = "active" ] && echo 0 || echo 1)" \
            "$sid $1 service recovers once the input is repaired (rc=$rc state=$st)"
    }

    # I1 corrupt-config: invalid JSON must be rejected by xray -test, the
    # runtime file must stay exactly as the operator left it, and the service
    # must come back once the file is repaired.
    docker exec "$c" sh -c "cp $cfg /tmp/config.good && printf '{\"inbounds\": [' > $cfg"
    local corrupt1; corrupt1=$(docker exec "$c" sha256sum "$cfg" | awk '{print $1}')
    attempt I1
    local i1; i1=$(cat "$out/I1.rc")
    assert "$([ "$i1" -ne 0 ] && echo 0 || echo 1)" "$sid I1 corrupt config is refused (rc=$i1)"
    assert "$(grep -q 'rejected the candidate' "$out/I1.err" && echo 0 || echo 1)" \
        "$sid I1 error reports the rejected candidate"
    assert "$(grep -q 'config.json' "$out/I1.err" && echo 0 || echo 1)" \
        "$sid I1 error names the config file"
    snap "$c" "$out/I1"
    assert "$(untouched I1)" "$sid I1 leaves units, certs and cron untouched"
    assert "$([ "$corrupt1" = "$(docker exec "$c" sha256sum "$cfg" | awk '{print $1}')" ] && echo 0 || echo 1)" \
        "$sid I1 the refused install does not overwrite the corrupt input"
    docker exec "$c" sh -c "cp /tmp/config.good $cfg" &&
        assert "$(docker exec "$c" /usr/local/bin/xray -test -config "$cfg" >/dev/null 2>&1 && echo 0 || echo 1)" \
            "$sid I1 restored config validates"
    restore_service I1

    # I2 missing-cert (TLS trees only): absent certificate must be refused and
    # named. The files are moved out and put back, so the tree is unchanged.
    if [ "$profile" = "tls" ]; then
        docker exec "$c" sh -c 'mkdir -p /tmp/cert.bak && mv /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key /tmp/cert.bak/'
        attempt I2
        local i2; i2=$(cat "$out/I2.rc")
        assert "$([ "$i2" -ne 0 ] && echo 0 || echo 1)" "$sid I2 missing certificate is refused (rc=$i2)"
        assert "$(grep -q 'xray.crt' "$out/I2.err" && echo 0 || echo 1)" \
            "$sid I2 error names the missing certificate"
        snap "$c" "$out/I2"
        assert "$(untouched I2 '/cert/xray\.(crt|key)')" "$sid I2 leaves units and cron untouched"
        docker exec "$c" sh -c 'mv /tmp/cert.bak/xray.crt /tmp/cert.bak/xray.key /etc/idleleo/cert/' &&
            assert "$(docker exec "$c" /usr/local/bin/xray -test -config "$cfg" >/dev/null 2>&1 && echo 0 || echo 1)" \
                "$sid I2 restored certificate validates"
        restore_service I2
    fi

    # I4 read-only-target: a write-refusing config dir must fail loudly, keep
    # the runtime config byte-identical, and leave a recovery journal that the
    # documented `xray recover` path clears.
    local before4 after4
    before4=$(docker exec "$c" sha256sum "$cfg" | awk '{print $1}')
    docker exec "$c" sh -c 'mkdir -p /tmp/roconf && cp -a /etc/idleleo/conf/xray/. /tmp/roconf/ &&
        mount --bind /tmp/roconf /etc/idleleo/conf/xray &&
        mount -o remount,ro,bind /etc/idleleo/conf/xray'
    attempt I4
    local i4; i4=$(cat "$out/I4.rc")
    assert "$([ "$i4" -ne 0 ] && echo 0 || echo 1)" "$sid I4 read-only target is refused (rc=$i4)"
    assert "$(grep -Eq 'read-only|conf/xray' "$out/I4.err" && echo 0 || echo 1)" \
        "$sid I4 error names the write-refused path"
    docker exec "$c" sh -c 'umount /etc/idleleo/conf/xray' >/dev/null 2>&1 || true
    after4=$(docker exec "$c" sha256sum "$cfg" | awk '{print $1}')
    assert "$([ -n "$before4" ] && [ "$before4" = "$after4" ] && echo 0 || echo 1)" \
        "$sid I4 runtime config is byte-identical after the refusal"
    assert "$(docker exec "$c" test -e /var/lib/idleleo/deploy/journal.json && echo 0 || echo 1)" \
        "$sid I4 the un-restorable rollback keeps a recovery journal"
    docker exec "${envs[@]}" "$c" /usr/local/bin/idleleo xray recover --container --json \
        >"$out/I4.recover.json" 2>"$out/I4.recover.err"
    local r4=$?
    echo "$r4" >"$out/I4.recover.rc"
    assert "$([ "$r4" -eq 0 ] && echo 0 || echo 1)" "$sid I4 xray recover clears the journal (rc=$r4)"
    assert "$(docker exec "$c" test ! -e /var/lib/idleleo/deploy/journal.json && echo 0 || echo 1)" \
        "$sid I4 recovery journal is removed"
    assert "$([ "$(docker exec "$c" systemctl is-active xray 2>/dev/null | head -1)" = "active" ] && echo 0 || echo 1)" \
        "$sid I4 service stays active"
    assert "$([ "$before4" = "$(docker exec "$c" sha256sum "$cfg" | awk '{print $1}')" ] && echo 0 || echo 1)" \
        "$sid I4 recovery leaves the runtime config unchanged"

    [[ "${E2E_KEEP:-0}" == "1" ]] || { docker rm -f "$c" >/dev/null 2>&1; docker network rm "$net" >/dev/null 2>&1; }
}

# --- I3 port-in-use: fresh install must refuse an occupied public port --------
run_port_injection() {
    local sid=I3 net="e2e-$RUN_ID-i3-net" c="e2e-$RUN_ID-i3"
    local out="$EVID/I3"
    docker network create "$net" >/dev/null 2>&1 || true
    log "[I3] start"
    if ! start_server "$c" "$out" "$net"; then
        log "[I3] container failed"; assert 1 "I3 container started"; return
    fi
    docker exec "$c" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    docker exec "$c" install -m 0755 /seed/xray /usr/local/bin/xray
    # Hold 443 from a detached exec: a foreground `&` dies with the exec PTY.
    docker exec -d "$c" python3 -c 'import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 443))
s.listen(1)
time.sleep(120)'
    local holding=1
    for _ in $(seq 1 20); do
        if docker exec "$c" sh -c 'ss -ltn | grep -q ":443 "'; then holding=0; break; fi
        sleep 1
    done
    docker exec "$c" ss -ltn >"$out/held-ports.txt" 2>&1 || true
    assert "$holding" "I3 harness holds port 443 before the install"
    docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$c" \
        /usr/local/bin/idleleo xray install --binary /usr/local/bin/xray --mode reality \
        --domain "$DOMAIN" --target "$TARGET" --port 443 --container --json \
        >"$out/install.json" 2>"$out/install.err"
    local rc=$?
    echo "$rc" >"$out/install.rc"
    assert "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" "I3 occupied port is refused (rc=$rc)"
    assert "$(grep -q 'already in use' "$out/install.err" && echo 0 || echo 1)" \
        "I3 error reports the port conflict"
    assert "$(docker exec "$c" sh -c '[ ! -e /etc/idleleo/conf/xray/config.json ] && echo 0 || echo 1')" \
        "I3 refusal writes no runtime config"
    assert "$(docker exec "$c" sh -c '[ ! -e /etc/systemd/system/xray.service ] && echo 0 || echo 1')" \
        "I3 refusal writes no unit file"
    [[ "${E2E_KEEP:-0}" == "1" ]] || { docker rm -f "$c" >/dev/null 2>&1; docker network rm "$net" >/dev/null 2>&1; }
}

run_paths() { # run_paths <sid> <args...> -- respects E2E_PATHS
    local sid=$1; shift
    case ",$PATHS," in
        *,both,*) run_r1 "$sid" "$@"; run_r2 "$sid" "$@"; run_injections "$sid" "$@" ;;
        *,r1,*)   run_r1 "$sid" "$@" ;;
        *,r2,*)   run_r2 "$sid" "$@" ;;
        *,inj,*)  run_injections "$sid" "$@" ;;
    esac
}

log "run_start=$(date -u +%Y-%m-%dT%H:%M:%SZ) only=$ONLY paths=$PATHS"
case ",$ONLY," in *,M1,*) run_paths M1 reality -2 reality reality \
    --mode reality --domain "$DOMAIN" --target "$TARGET" --port 443 ;; esac
case ",$ONLY," in *,M4,*) run_paths M4 tls -1 tls ws \
    --mode tls --transport ws --domain "$DOMAIN" --port 443 ;; esac
case ",$PATHS," in
    *,both,*|*,inj,*) run_port_injection ;;
esac
log "run_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s PASS\n%s FAIL\n' \
    "$(grep -c '^PASS' "$EVID/assertions.txt")" "$(grep -c '^FAIL' "$EVID/assertions.txt")" | tee -a "$EVID/run.log"
