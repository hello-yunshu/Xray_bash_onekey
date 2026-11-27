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
IMAGE_DOCKERFILE="${E2E_IMAGE_DOCKERFILE:-$SUITE/image/Dockerfile}"
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
# E2E_BLOCK_HOSTS pins the named hosts to loopback so a scenario can prove it
# never needs them (offline-cache evidence). Names still resolve, so a code
# path that ignores the cache fails fast instead of hanging.
BLOCK_HOSTS=()
if [[ -n "${E2E_BLOCK_HOSTS:-}" ]]; then
    IFS=',' read -r -a BLOCK_HOSTS <<<"$E2E_BLOCK_HOSTS"
fi
host_blocked() {
    local want="$1" h
    for h in ${BLOCK_HOSTS[@]+"${BLOCK_HOSTS[@]}"}; do
        [[ "${h// /}" == "$want" ]] && return 0
    done
    return 1
}
pin_host() {
    local h=$1 ip
    if host_blocked "$h"; then
        PIN_ARGS+=(--add-host "$h:127.0.0.1")
        return
    fi
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
elif host_blocked github.com; then
    PIN_ARGS+=(--add-host "github.com:127.0.0.1")
else
    pin_host github.com
fi

matrix_get() {
    python3 - "$SUITE/matrix.json" "$1" "$2" <<'PY'
import json, sys
matrix = json.load(open(sys.argv[1]))
sid, path = sys.argv[2], sys.argv[3]
scenario = next((x for x in matrix['install'] if x['id'] == sid), {})
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
# Evidence is bind-mounted as /out and some probes append to their transcripts.
# Reusing a RUN_ID would silently mix the previous attempt into this one, so
# require a fresh directory instead of producing ambiguous evidence.
if [[ -d "$EVID" && -n "$(ls -A "$EVID" 2>/dev/null)" ]]; then
    log "FATAL: $EVID already holds evidence; choose a new E2E_RUN_ID"
    exit 2
fi
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "run_id=$RUN_ID"
if [[ -n "${E2E_BLOCK_HOSTS:-}" ]]; then
    log "blocked_hosts=${E2E_BLOCK_HOSTS} (pinned to 127.0.0.1 for offline proof)"
fi
docker build -q -t "$IMAGE_TAG" -f "$IMAGE_DOCKERFILE" "$SUITE/image" >/dev/null || {
    log "FATAL: image build failed"; exit 2
}
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE_TAG")
IMAGE_PLATFORM=$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$IMAGE_TAG")
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

# --- offline Nginx artifact cache ------------------------------------------
# OPS-19/31/32 install a managed Nginx front from a GitHub release. A flaky
# download must not decide those verdicts, so seed one verified cache that both
# sides read locally (Bash: IDLELEO_NGINX_CACHE, Go: Options.CacheDir). Missing
# cache files are fetched once on the host and verified against the manifest; a
# failed seed is non-fatal and falls back to the historical online path.
NGINX_BUILD="${E2E_NGINX_BUILD:-2026.10.15.7679}"
case "$ARCH" in
    amd64) NGINX_ARCH=x86 ;;
    arm64) NGINX_ARCH=arm ;;
    *) NGINX_ARCH="" ;;
esac
NGINX_ASSET="xray-nginx-custom-${NGINX_ARCH}.tar.gz"
NGINX_CACHE="${E2E_NGINX_CACHE:-$HOME/.cache/xray-audit/nginx/$NGINX_BUILD}"
# OPS-17b starts from a real older binary so the update really replaces it.
NGINX_OLD_IMAGE="${E2E_NGINX_OLD_IMAGE:-nginx:1.27}"
NGINX_CACHE_ENVS=()
# MENU_NGINX_ENVS injects the offline cache into menu-driven installs; only the
# OPS-17b update sets it, every other menu row keeps its previous environment.
MENU_NGINX_ENVS=()

# nginx_cache_asset_info prints build/filename/sha256/size for one arch.
nginx_cache_asset_info() {
    python3 - "$1" "$2" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    print("\t\t\t")
    raise SystemExit(0)
build = ((data.get("versions") or {}).get("nginx_build") or "")
entry = next((a for a in data.get("assets") or [] if a.get("arch") == sys.argv[2]), None)
if entry is None:
    print("%s\t\t\t" % build)
else:
    print("%s\t%s\t%s\t%s" % (build, entry.get("filename") or "",
                              entry.get("sha256") or "", entry.get("size_bytes") or ""))
PY
}

seed_nginx_cache() {
    local dest="$WORK/seed/nginx"
    local manifest="$NGINX_CACHE/release-manifest.json"
    local tarball="$NGINX_CACHE/$NGINX_ASSET"
    local cache_source="host-cache"
    if [[ -z "$NGINX_ARCH" ]]; then
        log "nginx_cache=miss reason=unsupported-arch arch=$ARCH"
        return 1
    fi
    mkdir -p "$dest" "$NGINX_CACHE"
    if [[ ! -f "$manifest" || ! -f "$tarball" ]]; then
        cache_source="download"
        local base="https://github.com/hello-yunshu/Xray_bash_onekey_Nginx/releases/download/v$NGINX_BUILD"
        if ! curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
                -o "$manifest.tmp" "$base/release-manifest.json" ||
           ! mv "$manifest.tmp" "$manifest"; then
            rm -f "$manifest.tmp"
            log "nginx_cache=miss reason=manifest-download-failed build=$NGINX_BUILD"
            return 1
        fi
        if ! curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 \
                -o "$tarball.tmp" "$base/$NGINX_ASSET" ||
           ! mv "$tarball.tmp" "$tarball"; then
            rm -f "$tarball.tmp"
            log "nginx_cache=miss reason=asset-download-failed asset=$NGINX_ASSET"
            return 1
        fi
    fi
    local build want_name want_sha want_size got_sha
    IFS=$'\t' read -r build want_name want_sha want_size < <(nginx_cache_asset_info "$manifest" "$NGINX_ARCH" || true)
    got_sha=$(host_sha256 "$tarball" 2>/dev/null || true)
    if [[ "$build" != "$NGINX_BUILD" || "$want_name" != "$NGINX_ASSET" ||
          -z "$want_sha" || ! "$want_size" =~ ^[0-9]+$ || "$got_sha" != "$want_sha" ]]; then
        # A stale, half-written or tampered cache must never reach a container.
        rm -f "$manifest" "$tarball" "$manifest.tmp" "$tarball.tmp"
        log "nginx_cache=miss reason=verify-failed build=${build:-none} asset=$NGINX_ASSET"
        return 1
    fi
    cp "$manifest" "$dest/release-manifest.json"
    cp "$tarball" "$dest/$NGINX_ASSET"
    printf '{"nginx_build_online_version":"%s"}\n' "$NGINX_BUILD" >"$dest/versions.json"
    NGINX_CACHE_ENVS=(-e IDLELEO_NGINX_CACHE=/seed/nginx -e E2E_NGINX_BUILD="$NGINX_BUILD")
    cat >"$EVID/nginx-cache.json" <<JSON
{
  "build": "$NGINX_BUILD",
  "arch": "$NGINX_ARCH",
  "asset": "$NGINX_ASSET",
  "source": "$cache_source",
  "tarballSha256": "$want_sha",
  "tarballSizeBytes": $want_size,
  "manifestSha256": "$(host_sha256 "$dest/release-manifest.json")",
  "versionsSha256": "$(host_sha256 "$dest/versions.json")"
}
JSON
    log "nginx_cache=$cache_source build=$NGINX_BUILD arch=$NGINX_ARCH tarball_sha256=$want_sha"
}

if seed_nginx_cache; then
    log "nginx_cache=hit (OPS-19/31/32 offline Nginx)"
else
    NGINX_CACHE_ENVS=()
    log "nginx_cache=miss (falling back to online downloads)"
fi

# write_go_nginx_manifest renders the component/version/url/sha256 contract the
# Go updater reads. The Bash release manifest uses a different schema, so it
# cannot be handed to `idleleo update nginx` directly.
write_go_nginx_manifest() {
    local dest="$WORK/seed/nginx"
    [[ -f "$dest/release-manifest.json" && -f "$dest/$NGINX_ASSET" ]] || return 1
    python3 - "$dest/release-manifest.json" "$dest/$NGINX_ASSET" \
        "$NGINX_ARCH" "$NGINX_ASSET" "$dest/go-nginx-manifest.json" <<'PY'
import hashlib, json, os, sys

manifest, tarball, arch, name, out = sys.argv[1:6]
data = json.load(open(manifest))
version = (data.get("versions") or {}).get("nginx") or ""
entry = next((a for a in data.get("assets") or [] if a.get("arch") == arch), None)
if not version or entry is None:
    raise SystemExit("manifest lacks versions.nginx or the %s asset" % arch)
payload = open(tarball, "rb").read()
if hashlib.sha256(payload).hexdigest() != (entry.get("sha256") or ""):
    raise SystemExit("seeded tarball does not match the manifest sha256")
json.dump({
    "schemaVersion": 1,
    "component": "nginx",
    "version": version,
    "sha256": entry["sha256"],
    "sizeBytes": len(payload),
    "url": "/seed/nginx/" + name,
}, open(out, "w"), indent=2)
open(out, "a").write("\n")
print(version)
PY
}

# seed_old_nginx_binary puts a real 1.27 binary into the managed tree so the
# update path has something to replace. If the release binary cannot run in
# this image, fall back to a version-only stub and record which one was used.
seed_old_nginx_binary() { # <server> <outdir>
    local server=$1 out=$2 cid
    mkdir -p "$out"
    if cid=$(docker create "$NGINX_OLD_IMAGE" 2>/dev/null) &&
       docker cp "$cid:/usr/sbin/nginx" "$out/nginx-1.27" >/dev/null 2>&1; then
        docker rm "$cid" >/dev/null 2>&1
        if docker cp "$out/nginx-1.27" "$server:/usr/local/nginx/sbin/nginx" >/dev/null 2>&1 &&
           docker exec "$server" chmod 0755 /usr/local/nginx/sbin/nginx >/dev/null 2>&1 &&
           docker exec "$server" /usr/local/nginx/sbin/nginx -v 2>&1 | grep -q 'nginx/1\.27\.'; then
            echo real >"$out/previous-binary.txt"
            return 0
        fi
    else
        docker rm "$cid" >/dev/null 2>&1 || true
    fi
    docker exec "$server" sh -c 'printf "#!/bin/sh\n[ \"\$1\" = \"-t\" ] && exit 0\necho \"nginx version: nginx/1.27.0\" >&2\nexit 0\n" > /usr/local/nginx/sbin/nginx && chmod 0755 /usr/local/nginx/sbin/nginx' \
        >/dev/null 2>&1
    echo stub >"$out/previous-binary.txt"
}

# --- offline release template cache ----------------------------------------
# OPS-19/31/32 fresh installs also fetch the Xray config template from the
# release raw tree. Seed the tracked templates so a raw.githubusercontent.com
# hiccup cannot fail the install; download_json_file still jq-validates them.
RELEASE_CACHE_ENVS=()
seed_release_cache() {
    local dest="$WORK/seed/release/config" f
    mkdir -p "$dest"
    for f in vless_reality.json vless_tls.json; do
        if [[ ! -f "$ROOT/config/$f" ]]; then
            log "release_cache=miss reason=missing-template file=$f"
            return 1
        fi
        cp "$ROOT/config/$f" "$dest/$f"
    done
    RELEASE_CACHE_ENVS=(-e IDLELEO_RELEASE_CACHE=/seed/release)
    log "release_cache=seeded templates=vless_reality.json,vless_tls.json"
}

if seed_release_cache; then
    log "release_cache=hit"
else
    RELEASE_CACHE_ENVS=()
    log "release_cache=miss (falling back to online downloads)"
fi

# --- offline apt cache ------------------------------------------------------
# OPS-19 (and the OPS M2/M3 installs) refresh the Ubuntu archive before any
# package work. Seed the exact .deb closure for the installer's dependency set
# so `apt update` is skipped and any install stays local; the installer fails
# closed when the closure is incomplete.
APT_CACHE_ENVS=()
APT_PACKAGES="bc curl dbus git jq lsof python3 qrencode cron fail2ban"
APT_BASE_IMAGE=$(awk '/^FROM /{print $2; exit}' "$SUITE/image/Dockerfile")
APT_CACHE="${E2E_APT_CACHE:-$HOME/.cache/xray-audit/apt/noble-$ARCH}"

apt_cache_needed() {
    [[ -z "$ONLY" || "$ONLY" == *OPS-* ]]
}

seed_apt_cache() {
    local dest="$WORK/seed/apt"
    local apt_source="host-cache"
    mkdir -p "$dest" "$APT_CACHE"
    if ! compgen -G "$APT_CACHE/*.deb" >/dev/null; then
        apt_source="download"
        if ! docker run --rm "$APT_BASE_IMAGE" bash -c "
                set -e
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq
                apt-get install -y --download-only --no-install-recommends $APT_PACKAGES >/dev/null
                tar -C /var/cache/apt/archives -cf - .
            " | tar -C "$APT_CACHE" -xf -; then
            log "apt_cache=miss reason=download-failed base=$APT_BASE_IMAGE"
            return 1
        fi
    fi
    if ! compgen -G "$APT_CACHE/*.deb" >/dev/null; then
        log "apt_cache=miss reason=empty dir=$APT_CACHE"
        return 1
    fi
    cp "$APT_CACHE"/*.deb "$dest/"
    APT_CACHE_ENVS=(-e IDLELEO_APT_CACHE=/seed/apt)
    python3 - "$dest" "$EVID/apt-cache.json" "$APT_PACKAGES" "$apt_source" <<'PY'
import hashlib, json, os, sys
dest, out, packages, source = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
debs = []
for name in sorted(os.listdir(dest)):
    if name.endswith('.deb'):
        with open(os.path.join(dest, name), 'rb') as fh:
            debs.append({"file": name, "sha256": hashlib.sha256(fh.read()).hexdigest()})
with open(out, 'w') as fh:
    json.dump({"packages": packages.split(), "source": source,
               "debCount": len(debs), "debs": debs}, fh, indent=2)
    fh.write('\n')
PY
    log "apt_cache=$apt_source debs=$(ls "$dest"/*.deb | wc -l | tr -d ' ') packages=$APT_PACKAGES"
}

if ! apt_cache_needed; then
    log "apt_cache=skipped (no OPS scenario selected)"
elif seed_apt_cache; then
    log "apt_cache=hit (OPS offline apt)"
else
    APT_CACHE_ENVS=()
    log "apt_cache=miss (falling back to apt update)"
fi

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

# A relay has no Xray inbound and no user credential, so the Go client probe
# proves its strongest honest layer: a real HTTP request through the managed
# Nginx stream listener. The evidence level must be REAL_CLIENT_PASS.
relay_doctor_probe() {
    local sid=$1 server=$2 out=$3
    docker exec "$server" idleleo doctor --client-probe \
        --probe-url "http://$RELAY_HOST:$RELAY_PORT/" --probe-expect relay-ok --json \
        >"$out/doctor-relay.json" 2>"$out/doctor-relay.err"
    local rc=$?
    echo "{\"rc\":$rc,\"probeUrl\":\"http://$RELAY_HOST:$RELAY_PORT/\"}" \
        >"$out/doctor-relay.rc.json"
    return "$rc"
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
                -e E2E_TIMEOUT="${E2E_TIMEOUT:-900}"
                "${NGINX_CACHE_ENVS[@]+"${NGINX_CACHE_ENVS[@]}"}"
                "${RELEASE_CACHE_ENVS[@]+"${RELEASE_CACHE_ENVS[@]}"}"
                "${APT_CACHE_ENVS[@]+"${APT_CACHE_ENVS[@]}"}")
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
    local -a run_cmd=(docker exec -e E2E_OUT="$target_out" -e E2E_ROUND="$round" -e E2E_SCENARIO="$sid"
        -e E2E_PROFILE="$profile" -e E2E_PREV_OUT=/out
        "${acme_envs[@]+"${acme_envs[@]}"}"
        "${NGINX_CACHE_ENVS[@]+"${NGINX_CACHE_ENVS[@]}"}"
        "${RELEASE_CACHE_ENVS[@]+"${RELEASE_CACHE_ENVS[@]}"}"
        "${APT_CACHE_ENVS[@]+"${APT_CACHE_ENVS[@]}"}"
        "$server" bash "/src/tests/e2e-diff/drivers/$driver" "${argv[@]}")
    "${run_cmd[@]}"; local rc=$?
    # The managed Nginx artifact comes from the network. A reset/EOF there is an
    # environment fault, not a parity result, so retry once and keep both tries
    # in install.log instead of spending a whole RUN_ID on it.
    if [[ $rc -ne 0 ]] && grep -Eqi 'EOF|TLS handshake timeout|connection reset by peer|i/o timeout|temporary failure in name resolution' "$out/install.log" 2>/dev/null; then
        echo "install_retry=transient-network" >>"$out/install.log"
        "${run_cmd[@]}"; rc=$?
    fi
    echo "$rc" >"$out/install.rc"
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
        if [[ "$profile" == "relay" ]]; then
            relay_l4 "$sid" go "$gserver" "$gout" "$net" 2
            relay_doctor_probe "$sid" "$gserver" "$gout" || true
        else
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
    mkdir -p "$out"
    docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY \
        "$server" idleleo "$@" >"$out/$name.out" 2>"$out/$name.err"
    echo $? >"$out/$name.rc"
}

# --- generic OPS rows -------------------------------------------------------
# OPS-04/05/06/07/10/17c/30 now have a Bash execution path (bash_ops.exp) and a
# Go counter-command. A row is PASS only when both sides were observed in the
# same job; a missing side is HARNESS-ERROR.
OPS_PORT_ALT="${E2E_OPS_PORT_ALT:-8443}"
OPS_UUID="${E2E_OPS_UUID:-99999999-8888-7777-6666-555555555555}"
OPS_UUID_LABEL="${E2E_OPS_UUID_LABEL:-e2e-uuid}"
# OPS-10 creates a serverNames fragment under a domain that is not the install
# target, so the snapshot can prove the nested menu write instead of
# re-observing the fragment install.sh already generated.
OPS10_DOMAIN="${E2E_OPS10_DOMAIN:-ops10.example.com}"
# OPS-01/02/03 drive the real user-management menu (main menu 13/14/15).
OPS_USER_EMAIL="${E2E_OPS_USER_EMAIL:-user2@example.com}"
OPS_USER_UUID="${E2E_OPS_USER_UUID:-22222222-3333-4444-5555-666666666666}"
OPS_USER_SHORT_ID="${E2E_OPS_USER_SHORT_ID:-e2e0a1b2}"

ops_bash_base() { # <server> <dir> <sid>
    local server=$1 dir=$2 sid=$3
    if [[ "$sid" == "M2" ]]; then
        run_bash_round M2 "$OPS_NET" "$server" "$dir" 1 "" reality "" "1>1>1" "1"
    else
        run_bash_round M1 "$OPS_NET" "$server" "$dir" 1 "" reality "-2" "" "1"
    fi
}

ops_go_base() { # <server> <dir> <mode>
    local server=$1 dir=$2 mode=$3
    docker exec "$server" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    docker exec "$server" install -m 0755 /seed/xray /usr/local/bin/xray
    docker exec "${NGINX_CACHE_ENVS[@]+"${NGINX_CACHE_ENVS[@]}"}" \
        "${RELEASE_CACHE_ENVS[@]+"${RELEASE_CACHE_ENVS[@]}"}" \
        -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY \
        "$server" idleleo xray install --binary /usr/local/bin/xray --mode "$mode" \
        --domain "$DOMAIN" --target "$TARGET" --port 443 --container --json \
        >"$dir/go-install.json" 2>"$dir/go-install.err"
    echo $? >"$dir/go-install.rc"
}

ops_bash_menu() { # <server> <dir> <ops-id>
    local server=$1 dir=$2 oid=$3
    docker exec -e E2E_OPS_ID="$oid" -e E2E_LOG=/out/ops.log \
        -e E2E_TIMEOUT="${E2E_TIMEOUT:-900}" -e E2E_TARGET="$TARGET" \
        -e E2E_PORT_ALT="$OPS_PORT_ALT" -e E2E_UUID_LABEL="$OPS_UUID_LABEL" \
        -e E2E_OPS10_DOMAIN="$OPS10_DOMAIN" \
        -e XRAY_VERSIONS_FILE=/etc/idleleo/versions.json \
        "$server" expect -f /src/tests/e2e-diff/drivers/bash_ops.exp \
        >"$dir/ops.out" 2>&1
    echo $? >"$dir/ops.rc"
}

ops_bash_user_menu() { # <server> <dir> <add|show|remove>
    local server=$1 dir=$2 action=$3
    docker exec -e E2E_USER_ACTION="$action" -e E2E_USER_EMAIL="$OPS_USER_EMAIL" \
        -e E2E_LOG="/out/users-$action.log" -e E2E_TIMEOUT="${E2E_TIMEOUT:-900}" \
        "$server" expect -f /src/tests/e2e-diff/drivers/bash_users.exp \
        >"$dir/$action.out" 2>&1
    echo $? >"$dir/$action.rc"
}

ops_health() { # <server> <dir> <tag>
    local server=$1 dir=$2 tag=$3
    docker exec "$server" sh -c \
        'bin=$(command -v xray || echo /usr/local/bin/xray); "$bin" -test -config /etc/idleleo/conf/xray/config.json' \
        >"$dir/$tag.xray-test.log" 2>&1
    echo $? >"$dir/$tag.xray-test.rc"
    docker exec "$server" sh -c 'systemctl is-active xray' \
        >"$dir/$tag.xray-active.txt" 2>&1
    echo $? >"$dir/$tag.xray-active.rc"
}

ops_snapshot() { # <server> <dir> <tag>
    local server=$1 dir=$2 tag=$3
    docker exec "$server" sh -c \
        'jq -S "(.inbounds[]?.streamSettings.realitySettings.privateKey?) = \"REDACTED\"" \
         /etc/idleleo/conf/xray/config.json 2>/dev/null' >"$dir/$tag.config.sorted.json"
    docker exec "$server" sh -c \
        'jq -r ".inbounds[]?.port // empty" /etc/idleleo/conf/xray/config.json 2>/dev/null' \
        >"$dir/$tag.inbound-ports.txt"
    docker exec "$server" sh -c \
        'jq -r ".inbounds[]?.settings.clients[]?.id // empty" /etc/idleleo/conf/xray/config.json 2>/dev/null' \
        >"$dir/$tag.client-ids.txt"
    docker exec "$server" sh -c \
        'jq -r ".inbounds[]?.settings.clients[]?.email // empty" /etc/idleleo/conf/xray/config.json 2>/dev/null' \
        >"$dir/$tag.emails.txt"
    docker exec "$server" sh -c \
        'jq -r ".inbounds[]?.streamSettings.realitySettings.shortIds[]? // empty" \
         /etc/idleleo/conf/xray/config.json 2>/dev/null' >"$dir/$tag.short-ids.txt"
    docker exec "$server" sh -c \
        'jq -r ".inbounds[]?.streamSettings.realitySettings.target // empty" \
         /etc/idleleo/conf/xray/config.json 2>/dev/null' >"$dir/$tag.reality-target.txt"
    docker exec "$server" sh -c \
        'jq -r ".inbounds[]?.streamSettings.realitySettings.serverNames // [] | join(\",\")" \
         /etc/idleleo/conf/xray/config.json 2>/dev/null' >"$dir/$tag.reality-server-names.txt"
    # Effective Nginx config: the managed tree can sit several levels deep and
    # a stock /etc/nginx/nginx.conf must never be mistaken for it.
    docker exec "$server" sh -c '
        bin=""
        for p in nginx /usr/local/nginx/sbin/nginx /etc/idleleo/nginx/sbin/nginx \
                 $(find / -maxdepth 6 -type f -name nginx -perm -u+x 2>/dev/null | head -3); do
            if command -v "$p" >/dev/null 2>&1 || [ -x "$p" ]; then bin="$p"; break; fi
        done
        [ -n "$bin" ] && "$bin" -T 2>/dev/null
    ' >"$dir/$tag.nginx-dump.txt"
    docker exec "$server" sh -c 'crontab -l 2>/dev/null' >"$dir/$tag.cron.txt"
    docker exec "$server" sh -c \
        'systemctl list-timers --all --no-pager 2>/dev/null | grep -i idleleo || true' \
        >"$dir/$tag.timers.txt"
    docker exec "$server" sh -c \
        'sha256sum /etc/idleleo/language.conf 2>/dev/null || echo absent' \
        >"$dir/$tag.language.sha256"
    docker exec "$server" systemctl is-active xray >"$dir/$tag.active.txt" 2>&1
    docker exec "$server" sh -c \
        'command -v ss >/dev/null 2>&1 && ss -ltn || netstat -ltn 2>/dev/null' \
        >"$dir/$tag.listens.txt"
    docker exec "$server" sh -c '
        bin=""
        for p in nginx /usr/local/nginx/sbin/nginx /etc/idleleo/nginx/sbin/nginx \
                 $(find / -maxdepth 6 -type f -name nginx -perm -u+x 2>/dev/null | head -3); do
            if command -v "$p" >/dev/null 2>&1 || [ -x "$p" ]; then bin="$p"; break; fi
        done
        [ -n "$bin" ] || { echo "no nginx binary"; exit 1; }
        "$bin" -t
    ' >"$dir/$tag.nginx-test.txt" 2>&1
    echo $? >"$dir/$tag.nginx-test.rc"
    docker exec "$server" sh -c \
        'find /etc/idleleo/conf/nginx -maxdepth 1 -type f -name "*.conf" -exec sha256sum {} + 2>/dev/null | sort' \
        >"$dir/$tag.fragments.sha256"
}

ops_generic_verdict() { # <ops-id>
    local oid=$1 base="$EVID/$1"
    python3 - "$base" "$oid" "$TARGET" "$OPS10_DOMAIN" <<'PY'
import json
import os
import re
import sys

base, oid, target_domain, ops10_domain = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def read_rc(path):
    raw = read(path)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def lines(path):
    return [x.strip() for x in (read(path) or "").splitlines() if x.strip()]


UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

bash_rc = read_rc(os.path.join(base, "bash", "ops.rc"))
go_rc = read_rc(os.path.join(base, "go", "10-op.rc"))
bash_install_rc = read_rc(os.path.join(base, "bash", "install.rc"))
go_install_rc = read_rc(os.path.join(base, "go", "go-install.rc"))

harness = []
for name, value in (("bash install rc", bash_install_rc), ("go install rc", go_install_rc),
                    ("bash ops rc", bash_rc), ("go ops rc", go_rc)):
    if value is None:
        harness.append("missing %s" % name)
if bash_rc == 124 or go_rc == 124:
    harness.append("driver rc=124")

report = {"id": oid, "bothInstallRc": {"bash": bash_install_rc, "go": go_install_rc},
          "opsRc": {"bash": bash_rc, "go": go_rc}}
reasons = []


def snap(side, tag, name):
    return os.path.join(base, side, "%s.%s" % (tag, name))


def targets(side, tag):
    return lines(snap(side, tag, "reality-target.txt"))


def server_names(side, tag):
    return lines(snap(side, tag, "reality-server-names.txt"))


def nginx_config(side, tag):
    """Uncommented directives from `nginx -T`, one stripped line each."""
    out = []
    for line in lines(snap(side, tag, "nginx-dump.txt")):
        if line.startswith("#"):
            continue
        out.append(line.strip())
    return out


def nginx_raw(side, tag):
    """Every non-empty `nginx -T` line, comments included."""
    return [x.strip() for x in lines(snap(side, tag, "nginx-dump.txt")) if x.strip()]


if harness:
    verdict = "HARNESS-ERROR"
    reasons = harness
elif oid == "OPS-04":
    # Reality+Nginx keeps the loopback inbound on 9443 and moves the public
    # Nginx listen port; the user-facing "port" is the Nginx one.
    b_listen = [x for x in nginx_config("bash", "after") if x.startswith("listen")]
    g_listen = [x for x in nginx_config("go", "after") if x.startswith("listen")]
    b_active = (read(snap("bash", "after", "active.txt")) or "").strip()
    g_active = (read(snap("go", "after", "active.txt")) or "").strip()

    def listening(side, tag, port):
        for line in lines(snap(side, tag, "listens.txt")):
            if re.search(r":%d\b" % port, line):
                return True
        return False

    def share_port(side):
        try:
            data = json.loads(read(os.path.join(base, side, "share-8443.json")) or "{}")
        except ValueError:
            return None
        match = re.search(r"@[^\s:]+:(\d+)", data.get("shareUri") or "")
        return int(match.group(1)) if match else None

    if bash_rc != 0:
        reasons.append("bash port change rc=%s" % bash_rc)
    if go_rc != 0:
        reasons.append("go port change rc=%s" % go_rc)
    if not any("8443" in x for x in b_listen):
        reasons.append("bash nginx does not listen on 8443: %s" % b_listen)
    if not any("8443" in x for x in g_listen):
        reasons.append("go nginx does not listen on 8443: %s" % g_listen)
    if b_active != "active" or g_active != "active":
        reasons.append("xray not active (bash=%s go=%s)" % (b_active, g_active))
    # The old public port must be released, and the share link must carry the
    # new public port; otherwise a "successful" edit still strands clients.
    for side in ("bash", "go"):
        if listening(side, "after", 443):
            reasons.append("%s still listens on 443" % side)
        if listening(side, "after", 8443) is False:
            reasons.append("%s listener table lacks 8443" % side)
    # The Go install can render a share link; the Bash install only writes the
    # same port into Nginx, so a missing Bash share is recorded, not invented.
    b_share = share_port("bash")
    g_share = share_port("go")
    if g_share != 8443:
        reasons.append("go share port is %s, expected 8443" % g_share)
    if b_share is not None and b_share != 8443:
        reasons.append("bash share port is %s, expected 8443" % b_share)
    # Bash only moves the public port, so its loopback inbound must not change.
    b_in_before = lines(snap("bash", "before", "inbound-ports.txt"))
    b_in_after = lines(snap("bash", "after", "inbound-ports.txt"))
    if b_in_before != b_in_after:
        reasons.append("bash loopback inbound changed: %s -> %s" % (b_in_before, b_in_after))
    # A real client must complete a business request through the new port.
    b_l4 = read_rc(os.path.join(base, "bash", "L4-8443.rc"))
    g_l4 = read_rc(os.path.join(base, "go", "L4-8443.rc"))
    if b_l4 != 0:
        reasons.append("bash L4 through 8443 rc=%s" % b_l4)
    if g_l4 != 0:
        reasons.append("go L4 through 8443 rc=%s" % g_l4)
    # Re-applying the same port is a no-op; an invalid port is refused and
    # writes nothing. Both are compared against the first successful edit.
    b_first = read_rc(os.path.join(base, "bash", "ops-first.rc"))
    if b_first != 0 or bash_rc != 0:
        reasons.append("bash repeat rc first=%s second=%s" % (b_first, bash_rc))
    if (read(snap("bash", "after2", "config.sorted.json")) or "") != \
            (read(snap("bash", "after", "config.sorted.json")) or ""):
        reasons.append("bash repeat rewrote the runtime config")
    g_repeat = read_rc(os.path.join(base, "go", "11-repeat.rc"))
    g_negative = read_rc(os.path.join(base, "go", "12-negative.rc"))
    if g_repeat != 0:
        reasons.append("go repeat rc=%s" % g_repeat)
    if g_negative == 0:
        reasons.append("go accepted an out-of-range port")
    if (read(snap("go", "after2", "config.sorted.json")) or "") != \
            (read(snap("go", "after", "config.sorted.json")) or ""):
        reasons.append("go repeat/negative rewrote the runtime config")
    def connectivity_ok(side):
        try:
            data = json.loads(read(os.path.join(
                base, side, "L4-8443", "connectivity.json")) or "{}")
        except ValueError:
            return False
        return data.get("ok") is True

    def bash_share():
        return (read(os.path.join(base, "bash", "share-bash.uri")) or "").strip()

    def go_share():
        try:
            data = json.loads(read(os.path.join(
                base, "go", "share-8443.json")) or "{}")
        except ValueError:
            return ""
        return str(data.get("shareUri") or "").strip()

    report.update({"nginxListen": {"bash": b_listen, "go": g_listen},
                   "active": {"bash": b_active, "go": g_active},
                   "listening443": {"bash": listening("bash", "after", 443),
                                    "go": listening("go", "after", 443)},
                   "sharePort": {"bash": share_port("bash"), "go": share_port("go")},
                   "l4": {"bash": b_l4, "go": g_l4},
                   "repeat": {"bashFirst": b_first, "bashSecond": bash_rc,
                              "goRepeat": g_repeat, "goNegative": g_negative}})
    # Business facts: the new public port is really listening, a real VLESS
    # client completed a request through it, and the install rendered a share
    # link carrying that port. Missing observations stay missing (no invention).
    report["details"] = {
        side: {
            "portListening": listening(side, "after", 8443),
            "clientConnected": (
                read_rc(os.path.join(base, side, "L4-8443.rc")) == 0
                and connectivity_ok(side)),
            "shareInfo": bash_share() if side == "bash" else go_share(),
        }
        for side in ("bash", "go")
    }
    verdict = "BLOCKER" if reasons else "PASS"
elif oid == "OPS-05":
    b_before = lines(snap("bash", "before", "client-ids.txt"))
    b_after = lines(snap("bash", "after", "client-ids.txt"))
    g_before = lines(snap("go", "before", "client-ids.txt"))
    g_after = lines(snap("go", "after", "client-ids.txt"))
    if bash_rc != 0:
        reasons.append("bash uuid change rc=%s" % bash_rc)
    if go_rc != 0:
        reasons.append("go uuid change rc=%s" % go_rc)
    if not b_after or b_after == b_before:
        reasons.append("bash client id unchanged")
    if not g_after or g_after == g_before:
        reasons.append("go client id unchanged")
    if any(not UUID_RE.match(x) for x in b_after + g_after):
        reasons.append("non-UUID client id observed")
    report.update({"clientIds": {"bash": {"before": b_before, "after": b_after},
                                 "go": {"before": g_before, "after": g_after}},
                   "bashUuidLabel": "e2e-uuid",
                   "allowedDiff": "bash derives UUIDv5 from the mapping string; go applies the literal UUID"})
    verdict = "BLOCKER" if reasons else "PASS"
elif oid == "OPS-06":
    b_after = targets("bash", "after")
    g_after = targets("go", "after")
    b_names = server_names("bash", "after")
    g_names = server_names("go", "after")
    if bash_rc != 0:
        reasons.append("bash target change rc=%s" % bash_rc)
    if go_rc == 2:
        report["verdict"] = "BLOCKED"
        report["reasons"] = ["go refused the target change: origin probe failed (rc=2, no write)"]
        report["targets"] = {"bash": b_after, "go": g_after}
        with open(os.path.join(base, "ops.json"), "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print("BLOCKED")
        raise SystemExit(0)
    if go_rc != 0:
        reasons.append("go target change rc=%s" % go_rc)
    if not b_after or b_after[0].split(":")[0] != target_domain:
        reasons.append("bash target not applied: %s" % b_after)
    if not g_after or g_after[0].split(":")[0] != target_domain:
        reasons.append("go target not applied: %s" % g_after)
    if b_names != g_names:
        reasons.append("serverNames differ (bash=%s go=%s)" % (b_names, g_names))
    report["targets"] = {"bash": b_after, "go": g_after}
    report["serverNames"] = {"bash": b_names, "go": g_names}
    verdict = "BLOCKER" if reasons else "PASS"
elif oid == "OPS-07":
    # Reality + Nginx gates TLS versions in the stream map, so the observable
    # change is the uncommented "TLSv1.2 1;" line, not an ssl_protocols directive.
    b_tls = [x for x in nginx_config("bash", "after") if re.match(r"TLSv1\.2\s+1;", x)]
    g_tls = [x for x in nginx_config("go", "after") if re.match(r"TLSv1\.2\s+1;", x)]
    b_before = [x for x in nginx_raw("bash", "before") if re.match(r"#TLSv1\.2\s+1;", x)]
    g_before = [x for x in nginx_raw("go", "before") if re.match(r"#TLSv1\.2\s+1;", x)]
    if bash_rc != 0:
        reasons.append("bash tls version change rc=%s" % bash_rc)
    if go_rc != 0:
        reasons.append("go tls version change rc=%s" % go_rc)
    if not any("TLSv1.2" in x for x in b_tls):
        reasons.append("bash 00-xray.conf keeps TLSv1.2 disabled: %s" % b_tls)
    if not any("TLSv1.2" in x for x in g_tls):
        reasons.append("go 00-xray.conf keeps TLSv1.2 disabled: %s" % g_tls)
    if not b_before or not g_before:
        reasons.append("baseline did not have TLSv1.2 commented out")
    report["nginxTls"] = {"bash": b_tls, "go": g_tls,
                          "bashBefore": b_before, "goBefore": g_before}
    verdict = "BLOCKER" if reasons else "PASS"
elif oid == "OPS-10":
    if bash_rc == 3:
        report["verdict"] = "BLOCKED"
        report["reasons"] = ["bash nested menu prerequisite missing"]
        report["blockedFile"] = read(os.path.join(base, "bash", "nested.json")) \
            or read(os.path.join(base, "bash", "blocked.json"))
        with open(os.path.join(base, "ops.json"), "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print("BLOCKED")
        raise SystemExit(0)
    # The observable is the map fragment that install.sh includes for every
    # accepted SNI, not an nginx "server_name" directive.
    fragment = ops10_domain + " reality;"
    b_before = [x for x in nginx_config("bash", "before") if x == fragment]
    g_before = [x for x in nginx_config("go", "before") if x == fragment]
    b_after = [x for x in nginx_config("bash", "after") if x == fragment]
    g_after = [x for x in nginx_config("go", "after") if x == fragment]
    if bash_rc != 0:
        reasons.append("bash serverNames change rc=%s" % bash_rc)
    if go_rc != 0:
        reasons.append("go serverNames change rc=%s" % go_rc)
    if b_before or g_before:
        reasons.append("baseline already carried %s" % fragment)
    if not b_after:
        reasons.append("bash nested menu did not create %s" % fragment)
    if not g_after:
        reasons.append("go nginx fragment lacks %s" % fragment)
    # Reload health and real traffic: the write must leave a valid, loaded
    # Nginx and keep existing clients working.
    for side in ("bash", "go"):
        nrc = read_rc(os.path.join(base, side, "after.nginx-test.rc"))
        if nrc != 0:
            reasons.append("%s nginx -t rc=%s" % (side, nrc))
        l4 = read_rc(os.path.join(base, side, "L4-443.rc"))
        if l4 != 0:
            reasons.append("%s L4 after serverNames rc=%s" % (side, l4))

    def frags(side, tag):
        out = {}
        for line in lines(snap(side, tag, "fragments.sha256")):
            digest, _, path = line.partition("  ")
            if path:
                out[path.strip()] = digest.strip()
        return out

    for side in ("bash", "go"):
        before_f = frags(side, "before")
        after_f = frags(side, "after")
        changed = sorted(p for p in before_f if p in after_f and before_f[p] != after_f[p])
        removed = sorted(p for p in before_f if p not in after_f)
        # The target's own serverNames list is the intended write; every other
        # fragment must keep its bytes.
        legal = [p for p in changed if "serverNames" in p]
        unexpected = [p for p in changed if "serverNames" not in p]
        if unexpected:
            reasons.append("%s rewrote unrelated fragments: %s" % (side, unexpected))
        if removed:
            reasons.append("%s removed fragments: %s" % (side, removed))
        report.setdefault("fragments", {})[side] = {
            "changed": changed, "legalServerNames": legal,
            "removed": removed, "added": sorted(set(after_f) - set(before_f))}
    report["nginxServerNames"] = {"bashBefore": b_before, "goBefore": g_before,
                                  "bash": b_after, "go": g_after,
                                  "fragment": fragment}
    # Business fact: the accepted SNI really reached the rendered fragment on
    # each side. Empty means the write never landed, so the row stays blocked.
    report["details"] = {
        "bash": {"serverNames": b_after},
        "go": {"serverNames": g_after},
    }
    verdict = "BLOCKER" if reasons else "PASS"
elif oid == "OPS-17c":
    b_cron = read(snap("bash", "after", "cron.txt")) or ""
    g_timers = read(snap("go", "after", "timers.txt")) or ""
    if bash_rc != 0:
        reasons.append("bash auto-update setup rc=%s" % bash_rc)
    if go_rc != 0:
        reasons.append("go schedule install rc=%s" % go_rc)
    if "auto_update.sh" not in b_cron:
        reasons.append("bash crontab lacks auto_update.sh")
    if "idleleo" not in g_timers:
        reasons.append("go has no idleleo timer: %s" % g_timers.strip())
    report["autoUpdate"] = {"bashCron": b_cron, "goTimers": g_timers}
    report["allowedDiff"] = "bash writes a crontab entry; go writes a systemd timer"
    verdict = "BLOCKER" if reasons else "PASS"
elif oid == "OPS-30":
    b_before = (read(snap("bash", "before", "language.sha256")) or "").strip()
    b_after = (read(snap("bash", "after", "language.sha256")) or "").strip()
    if bash_rc != 0:
        reasons.append("bash language change rc=%s" % bash_rc)
    if b_before == b_after:
        reasons.append("language.conf unchanged (before=%s after=%s)" % (b_before, b_after))
    report["language"] = {"before": b_before, "after": b_after}
    report["allowedDiff"] = "go has no language capability; row is bash-only"
    verdict = "BLOCKER" if reasons else "BASH-ONLY"
else:
    verdict = "NOT-RUN"
    reasons = ["no verdict rule"]

report["verdict"] = verdict
report["reasons"] = reasons
with open(os.path.join(base, "ops.json"), "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(verdict)
PY
}

ops_l4() { # <server> <dir> <net> <port>
    local server=$1 dir=$2 net=$3 port=$4
    E2E_L4_URL="http://example.com/" E2E_L4_MARKER="Example Domain" E2E_L4_PORT="$port" \
        bash "$SUITE/collect/l4.sh" "$server" "e2e-$RUN_ID-$server-l4-$port" \
            "$IMAGE_TAG" "$net" reality "$DOMAIN" "$WORK/seed/xray" \
            "$WORK/secret/$server-l4-$port" "$dir/L4-$port" >"$dir/L4-$port.log" 2>&1
    echo $? >"$dir/L4-$port.rc"
}

# ops_l4_user proves the user the job just added is the one that connects. The
# client builder is pinned to that email, so a stale clients[0] cannot pass.
ops_l4_user() { # <server> <dir> <net>
    local server=$1 dir=$2 net=$3
    E2E_L4_URL="http://example.com/" E2E_L4_MARKER="Example Domain" \
        E2E_L4_EMAIL="$OPS_USER_EMAIL" \
        bash "$SUITE/collect/l4.sh" "$server" "e2e-$RUN_ID-$server-l4-user" \
            "$IMAGE_TAG" "$net" reality "$DOMAIN" "$WORK/seed/xray" \
            "$WORK/secret/$server-l4-user" "$dir/L4-user" \
            >"$dir/L4-user.log" 2>&1
    echo $? >"$dir/L4-user.rc"
}

ops_simple_job() { # <ops-id> <base-scenario> <go-mode>
    local oid=$1 sid=$2 gmode=$3
    OPS_NET="e2e-$RUN_ID-$oid"
    local base="$EVID/$oid" bdir="$EVID/$oid/bash" gdir="$EVID/$oid/go"
    mkdir -p "$bdir" "$gdir"
    docker network create "$OPS_NET" >/dev/null 2>&1 || true
    log "[$oid] start"

    local bserver="e2e-$RUN_ID-$oid-bash"
    if start_server "$bserver" "$oid" bash "$bdir" "$OPS_NET"; then
        ops_bash_base "$bserver" "$bdir" "$sid"
        ops_snapshot "$bserver" "$bdir" before
        ops_bash_menu "$bserver" "$bdir" "$oid"
        ops_snapshot "$bserver" "$bdir" after
        if [[ "$oid" == "OPS-04" ]]; then
            ops_l4 "$bserver" "$bdir" "$OPS_NET" "$OPS_PORT_ALT"
            # The Bash menu has no share command, but install.sh -s really
            # renders one. Capture it while the container still exists; an
            # unparsable output stays empty instead of being invented.
            docker exec "$bserver" bash /etc/idleleo/install.sh -s \
                >"$bdir/share-bash.txt" 2>&1
            echo $? >"$bdir/share-bash.rc"
            grep -oE 'vless://[^[:space:]]+' "$bdir/share-bash.txt" |
                head -n 1 >"$bdir/share-bash.uri" || true
            # Re-applying the same port must stay green and rewrite nothing.
            mv "$bdir/ops.rc" "$bdir/ops-first.rc"
            mv "$bdir/ops.out" "$bdir/ops-first.out"
            cp "$bdir/ops.log" "$bdir/ops-first.log" 2>/dev/null || true
            # The repeat is a no-op check; fail fast instead of hanging 900s.
            local saved_timeout="${E2E_TIMEOUT:-900}"
            E2E_TIMEOUT=180 ops_bash_menu "$bserver" "$bdir" "$oid"
            E2E_TIMEOUT="$saved_timeout"
            ops_snapshot "$bserver" "$bdir" after2
        elif [[ "$oid" == "OPS-10" ]]; then
            ops_l4 "$bserver" "$bdir" "$OPS_NET" 443
        fi
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    local gserver="e2e-$RUN_ID-$oid-go"
    if start_server "$gserver" "$oid" go "$gdir" "$OPS_NET"; then
        ops_go_base "$gserver" "$gdir" "$gmode"
        ops_snapshot "$gserver" "$gdir" before
        case "$oid" in
            OPS-04) ops_go_cli "$gserver" "$gdir" 10-op xray config edit --port 8444 --public-port "$OPS_PORT_ALT" --yes --no-probe --container --json ;;
            OPS-05) ops_go_cli "$gserver" "$gdir" 10-op xray config edit --uuid "$OPS_UUID" --yes --no-probe --container --json ;;
            OPS-06) ops_go_cli "$gserver" "$gdir" 10-op xray config edit --target "$TARGET:443" --server-names "$TARGET" --yes --no-probe --container --json ;;
            OPS-07) ops_go_cli "$gserver" "$gdir" 10-op xray tls --version 1.2+ --container ;;
            OPS-10) ops_go_cli "$gserver" "$gdir" 10-op xray config edit --server-names "$OPS10_DOMAIN" --yes --no-probe --container --json ;;
            OPS-17c)
                ops_go_cli "$gserver" "$gdir" 10-op schedule install --interval 3600 --container
                ops_go_cli "$gserver" "$gdir" 11-status schedule status
                ;;
            OPS-30) echo 0 >"$gdir/10-op.rc" ;;
        esac
        ops_snapshot "$gserver" "$gdir" after
        if [[ "$oid" == "OPS-04" ]]; then
            ops_l4 "$gserver" "$gdir" "$OPS_NET" "$OPS_PORT_ALT"
            # The managed CLI must render the new public port in the link.
            docker exec "$gserver" /usr/local/bin/idleleo xray share \
                --path /etc/idleleo/conf/xray/config.json \
                --host "$DOMAIN" --public-port "$OPS_PORT_ALT" --json \
                >"$gdir/share-8443.json" 2>"$gdir/share-8443.err" || true
            ops_go_cli "$gserver" "$gdir" 11-repeat xray config edit --port 8444 \
                --public-port "$OPS_PORT_ALT" --yes --no-probe --container --json
            # An out-of-range port must be refused without touching the tree.
            ops_go_cli "$gserver" "$gdir" 12-negative xray config edit --port 70000 \
                --yes --no-probe --container --json
            ops_snapshot "$gserver" "$gdir" after2
        elif [[ "$oid" == "OPS-10" ]]; then
            ops_l4 "$gserver" "$gdir" "$OPS_NET" 443
        fi
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$gdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker network rm "$OPS_NET" >/dev/null 2>&1 || true

    log "[$oid] verdict=$(ops_generic_verdict "$oid")"
}

# --- state/query OPS rows (round 3 D07 remainder) --------------------------
# OPS-08/11/15/20/22/28 are driven through the real install.sh menu on the Bash
# side and the real idleleo CLI on the Go side. A row is PASS only when both
# sides were observed in this job and their post-state agrees with the
# contract; a missing side or rc=124 is HARNESS-ERROR.
ops_state_probe() { # <server> <dir> <tag>
    local server=$1 dir=$2 tag=$3
    docker exec "$server" sh -c \
        'if [ -e /var/log/xray/e2e.log ]; then stat -c %s /var/log/xray/e2e.log; else echo missing; fi' \
        >"$dir/$tag.e2e-log-size.txt" 2>/dev/null || true
    docker exec "$server" sh -c \
        'grep -o "\"unknown_sni_policy\"[^,}]*" /etc/idleleo/conf/install_config.json 2>/dev/null | tail -1' \
        >"$dir/$tag.sni-policy.txt" 2>/dev/null || true
    docker exec "$server" sh -c \
        'cat /etc/idleleo/conf/nginx/03-isolate.conf 2>/dev/null; echo "---"; grep -h "default" /etc/idleleo/conf/nginx/00-xray.conf 2>/dev/null' \
        >"$dir/$tag.sni-files.txt" 2>/dev/null || true
    docker exec "$server" sh -c 'systemctl is-active nginx 2>/dev/null || true' \
        >"$dir/$tag.nginx-active.txt" 2>/dev/null || true
    docker exec "$server" sh -c \
        'if [ -e /etc/idleleo/conf/xray/config.json ]; then echo present; else echo absent; fi' \
        >"$dir/$tag.config-exists.txt" 2>/dev/null || true
    docker exec "$server" sh -c \
        'ls -1 /etc/idleleo/cert 2>/dev/null | sort' \
        >"$dir/$tag.cert-list.txt" 2>/dev/null || true
    if [[ "$tag" == "after" ]]; then
        # Real TLS probes on the public listener: the accepted SNI of this side
        # must still reach the runtime, an unknown SNI must be rejected by the
        # isolate policy. The accepted SNI is the reality server name the driver
        # actually rendered, not an assumption.
        local known_sni
        known_sni=$(head -n 1 "$dir/$tag.reality-server-names.txt" 2>/dev/null | tr -d '\r')
        [[ -n "$known_sni" ]] || known_sni="$DOMAIN"
        docker exec "$server" timeout 20 openssl s_client \
            -connect 127.0.0.1:443 -servername "$known_sni" -brief </dev/null \
            >"$dir/$tag.sni-known.txt" 2>&1
        echo $? >"$dir/$tag.sni-known.rc"
        docker exec "$server" timeout 20 openssl s_client \
            -connect 127.0.0.1:443 -servername e2e-unknown.invalid -brief </dev/null \
            >"$dir/$tag.sni-unknown.txt" 2>&1
        echo $? >"$dir/$tag.sni-unknown.rc"
    fi
}

ops20_capture_stats() { # <bash|go> <server> <dir> <tag>
    local side=$1 server=$2 dir=$3 tag=$4 rc attempt
    for attempt in 1 2 3 4 5; do
        if [[ "$side" == "bash" ]]; then
            docker exec "$server" bash /etc/idleleo/scripts/xray_stats.sh --json \
                >"$dir/$tag.stats.json" 2>"$dir/$tag.stats.err"
        else
            docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$server" \
                /usr/local/bin/idleleo stats --json >"$dir/$tag.stats.json" 2>"$dir/$tag.stats.err"
        fi
        rc=$?
        [[ $rc -eq 0 ]] && break
        # The Bash menu restarts Xray while enabling API stats. Give its API
        # listener a short settling window before taking the traffic baseline.
        sleep 1
    done
    echo "$rc" >"$dir/$tag.stats.rc"
    return 0
}

ops20_l4() { # <server> <dir> <net> <side>
    local server=$1 dir=$2 net=$3 side=$4
    E2E_L4_URL="http://${OPS20_ORIGIN_IP}/payload.bin" \
    E2E_L4_MARKER="Example Domain" E2E_L4_EXPECTED_SHA256="$OPS20_ORIGIN_SHA" \
    E2E_L4_EXPECTED_BYTES="$OPS20_ORIGIN_BYTES" \
        bash "$SUITE/collect/l4.sh" "$server" "e2e-$RUN_ID-OPS-20-$side-client" \
            "$IMAGE_TAG" "$net" reality "$DOMAIN" "$WORK/seed/xray" \
            "$WORK/secret/ops20-$side" "$dir/L4-traffic" >"$dir/L4-traffic.log" 2>&1
    echo $? >"$dir/L4-traffic.rc"
}

ops20_summarize_traffic() { # <side> <side-dir>
    python3 - "$1" "$2" <<'PY'
import hashlib, json, os, sys
side, base = sys.argv[1:3]
def read(name):
    try:
        with open(os.path.join(base, name), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None
def rc(name):
    try:
        return int(open(os.path.join(base, name), encoding="ascii").read().strip())
    except (OSError, ValueError):
        return None
def counters(doc):
    if not isinstance(doc, dict):
        return {}
    rows = {}
    for item in doc.get("inbounds", []):
        if isinstance(item, dict):
            tag = str(item.get("tag") or "")
            rows[tag] = {"uplinkBytes": int(item.get("uplinkBytes", 0)),
                         "downlinkBytes": int(item.get("downlinkBytes", 0))}
    for item in (doc.get("stat") or []):
        if not isinstance(item, dict):
            continue
        parts = str(item.get("name") or "").split(">>>")
        if len(parts) == 4 and parts[0] == "inbound" and parts[2:4] == ["traffic", "uplink"]:
            rows.setdefault(parts[1], {})["uplinkBytes"] = int(item.get("value") or 0)
        elif len(parts) == 4 and parts[0] == "inbound" and parts[2:4] == ["traffic", "downlink"]:
            rows.setdefault(parts[1], {})["downlinkBytes"] = int(item.get("value") or 0)
    return rows
before, after = read("traffic-before.stats.json"), read("traffic-after.stats.json")
conn = read("L4-traffic/connectivity.json")
left, right = counters(before), counters(after)
details = {}
for tag in sorted(set(left) | set(right)):
    b, a = left.get(tag, {}), right.get(tag, {})
    up = a.get("uplinkBytes", 0) - b.get("uplinkBytes", 0)
    down = a.get("downlinkBytes", 0) - b.get("downlinkBytes", 0)
    details[tag] = {"before": b, "after": a, "uplinkDeltaBytes": up,
                    "downlinkDeltaBytes": down, "totalDeltaBytes": up + down}
summary = {
    "apiPreRc": rc("traffic-pre.stats.rc"), "apiPreExpectedRc": 2 if side == "bash" else 3,
    "statsBeforeRc": rc("traffic-before.stats.rc"),
    "statsAfterRc": rc("traffic-after.stats.rc"),
    "httpRc": (conn or {}).get("curlExit"), "httpOk": (conn or {}).get("ok") is True,
    "httpBodyBytes": (conn or {}).get("bodyBytes"),
    "httpBodySha256": (conn or {}).get("bodySha256"),
    "expectedBodyBytes": (conn or {}).get("expectedBodyBytes"),
    "expectedBodySha256": (conn or {}).get("expectedBodySha256"),
    "inboundCounters": details,
    "trafficBytes": sum(max(0, x["totalDeltaBytes"]) for x in details.values()),
}
with open(os.path.join(base, "traffic-summary.json"), "w", encoding="utf-8") as fh:
    json.dump(summary, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

ops_state_job() { # <ops-id>
    local oid=$1 sid=M1 gmode=reality
    local ops20_subnet="" ops20_gateway=""
    case "$oid" in
        OPS-08) sid=M2; gmode=reality-nginx ;;
    esac
    OPS_NET="e2e-$RUN_ID-$oid"
    local base="$EVID/$oid" bdir="$EVID/$oid/bash" gdir="$EVID/$oid/go"
    mkdir -p "$bdir" "$gdir"
    if [[ "$oid" == "OPS-20" ]]; then
        # Use a controlled, non-RFC1918 test subnet. The managed freedom
        # outbound intentionally blackholes private destinations, so a Docker
        # origin on its default RFC1918 bridge would not exercise business
        # traffic through Xray.
        ops20_subnet="$(printf '%s.%s.%s.%s/24' 11 0 0 0)"
        ops20_gateway="$(printf '%s.%s.%s.%s' 11 0 0 1)"
        docker network create --subnet "$ops20_subnet" --gateway "$ops20_gateway" "$OPS_NET" >/dev/null 2>&1 || true
    else
        docker network create "$OPS_NET" >/dev/null 2>&1 || true
    fi
    log "[$oid] start"

    if [[ "$oid" == "OPS-20" ]]; then
        local origin_dir="$WORK/ops20-origin"
        mkdir -p "$origin_dir"
        OPS20_ORIGIN_BYTES=1048576
        python3 - "$origin_dir/payload.bin" "$OPS20_ORIGIN_BYTES" <<'PY'
import sys
body = (b"Example Domain | Xray OPS-20 local origin payload\n" * 30000)[:int(sys.argv[2])]
if len(body) != int(sys.argv[2]):
    raise SystemExit("payload length mismatch")
# collect/l4.sh captures curl output in a shell variable, which strips trailing
# newlines. Keep the known payload byte-for-byte comparable through that path.
body = body[:-1] + b"X"
open(sys.argv[1], "wb").write(body)
PY
        OPS20_ORIGIN_SHA=$(host_sha256 "$origin_dir/payload.bin")
        OPS20_ORIGIN_IP="$(printf '%s.%s.%s.%s' 11 0 0 3)"
        docker run -d --name "e2e-$RUN_ID-OPS-20-origin" --network "$OPS_NET" --ip "$OPS20_ORIGIN_IP" \
            --network-alias e2e-origin -v "$origin_dir:/usr/share/nginx/html:ro" \
            nginx:1.27 >/dev/null || { log "FATAL: OPS-20 local origin failed to start"; return 2; }
        OPS20_ORIGIN_IP=$(docker inspect -f "{{with index .NetworkSettings.Networks \"$OPS_NET\"}}{{.IPAddress}}{{end}}" \
            "e2e-$RUN_ID-OPS-20-origin")
        [[ -n "$OPS20_ORIGIN_IP" ]] || { log "FATAL: OPS-20 local origin has no network address"; return 2; }
    fi

    local bserver="e2e-$RUN_ID-$oid-bash"
    if start_server "$bserver" "$oid" bash "$bdir" "$OPS_NET"; then
        ops_bash_base "$bserver" "$bdir" "$sid"
        if [[ "$oid" == "OPS-22" ]]; then
            docker exec "$bserver" sh -c \
                'mkdir -p /var/log/xray && printf "round3-seed\n" > /var/log/xray/e2e.log' \
                >/dev/null 2>&1 || true
        fi
        if [[ "$oid" == "OPS-20" ]]; then
            ops20_capture_stats bash "$bserver" "$bdir" traffic-pre
        fi
        ops_snapshot "$bserver" "$bdir" before
        ops_state_probe "$bserver" "$bdir" before
        ops_bash_menu "$bserver" "$bdir" "$oid"
        if [[ "$oid" == "OPS-20" ]]; then
            ops20_capture_stats bash "$bserver" "$bdir" traffic-before
            ops20_l4 "$bserver" "$bdir" "$OPS_NET" bash
            ops20_capture_stats bash "$bserver" "$bdir" traffic-after
            ops20_summarize_traffic bash "$bdir"
        fi
        ops_snapshot "$bserver" "$bdir" after
        ops_state_probe "$bserver" "$bdir" after
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    local gserver="e2e-$RUN_ID-$oid-go"
    if start_server "$gserver" "$oid" go "$gdir" "$OPS_NET"; then
        ops_go_base "$gserver" "$gdir" "$gmode"
        if [[ "$oid" == "OPS-22" ]]; then
            docker exec "$gserver" sh -c \
                'mkdir -p /var/log/xray && printf "round3-seed\n" > /var/log/xray/e2e.log' \
                >/dev/null 2>&1 || true
        fi
        if [[ "$oid" == "OPS-20" ]]; then
            ops20_capture_stats go "$gserver" "$gdir" traffic-pre
        fi
        if [[ "$oid" == "OPS-20" ]]; then
            docker exec "$gserver" sh -c \
                'printf "#!/bin/sh\nexec systemctl restart xray\n" > /usr/local/bin/e2e-service-apply && chmod 0755 /usr/local/bin/e2e-service-apply' \
                >/dev/null 2>&1 || true
        fi
        ops_snapshot "$gserver" "$gdir" before
        ops_state_probe "$gserver" "$gdir" before
        case "$oid" in
            OPS-08)
                ops_go_cli "$gserver" "$gdir" 10-op xray guard set --policy isolate --container --json
                ops_go_cli "$gserver" "$gdir" 11-show xray guard show --json
                # Change a valid directive in the active isolate fragment,
                # preserve an older mtime, and prove the live old Nginx worker
                # still rejects unknown SNI while Guard reports the changed
                # content as not verified in runtime.
                docker exec "$gserver" cp /etc/idleleo/conf/nginx/03-isolate.conf /tmp/03-isolate.saved
                docker exec "$gserver" python3 -c 'from pathlib import Path; p=Path("/etc/idleleo/conf/nginx/03-isolate.conf"); s=p.read_text(); assert "access_log off;" in s; p.write_text(s.replace("access_log off;", "access_log /tmp/e2e-guard-stale.log;", 1))'
                docker exec "$gserver" touch -t 202001010000 /etc/idleleo/conf/nginx/03-isolate.conf
                docker exec "$gserver" /usr/local/nginx/sbin/nginx -t \
                    >"$gdir/12-unreloaded.nginx-test.out" 2>&1
                echo $? >"$gdir/12-unreloaded.nginx-test.rc"
                ops_go_cli "$gserver" "$gdir" 12-unreloaded xray guard show --json
                docker exec "$gserver" timeout 20 openssl s_client -connect 127.0.0.1:443 \
                    -servername e2e-unknown.invalid -brief </dev/null \
                    >"$gdir/12-unreloaded.unknown-sni.out" 2>&1
                echo $? >"$gdir/12-unreloaded.unknown-sni.rc"
                # A managed apply rewrites the authoritative isolate content,
                # performs a real Nginx reload, and records that process/hash.
                ops_go_cli "$gserver" "$gdir" 13-reloaded xray guard set --policy isolate --container --json
                ops_go_cli "$gserver" "$gdir" 14-after-reload xray guard show --json
                ;;
            OPS-11) ops_go_cli "$gserver" "$gdir" 10-op show --json ;;
            OPS-15) ops_go_cli "$gserver" "$gdir" 10-op service restart --container ;;
            OPS-20)
                ops_go_cli "$gserver" "$gdir" 10-enable xray api enable --sandbox / \
                    --validator /usr/local/bin/xray --service /usr/local/bin/e2e-service-apply \
                    --container --json
                ops_go_cli "$gserver" "$gdir" 10-op stats --json
                ;;
            OPS-22) ops_go_cli "$gserver" "$gdir" 10-op xray logs clean --yes --container --json ;;
            OPS-28) ops_go_cli "$gserver" "$gdir" 10-op xray uninstall --purge --container --json ;;
        esac
        if [[ "$oid" == "OPS-20" ]]; then
            ops20_capture_stats go "$gserver" "$gdir" traffic-before
            ops20_l4 "$gserver" "$gdir" "$OPS_NET" go
            ops20_capture_stats go "$gserver" "$gdir" traffic-after
            ops20_summarize_traffic go "$gdir"
        fi
        ops_snapshot "$gserver" "$gdir" after
        ops_state_probe "$gserver" "$gdir" after
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$gdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker rm -f "e2e-$RUN_ID-OPS-20-origin" >/dev/null 2>&1 || true
    docker network rm "$OPS_NET" >/dev/null 2>&1 || true

    log "[$oid] verdict=$(ops_state_verdict "$oid")"
}

ops_state_verdict() { # <ops-id>
    local oid=$1 base="$EVID/$1"
    python3 - "$base" "$oid" <<'PY'
import json
import os
import sys

base, oid = sys.argv[1], sys.argv[2]


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def rc(path):
    raw = read(path)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def jload(path):
    try:
        return json.loads(read(path) or "")
    except ValueError:
        return None


def text(path):
    return (read(path) or "").strip()


def probe(side, tag, name):
    return text(os.path.join(base, side, "%s.%s.txt" % (tag, name)))


bash_install = rc(os.path.join(base, "bash", "install.rc"))
go_install = rc(os.path.join(base, "go", "go-install.rc"))
bash_rc = rc(os.path.join(base, "bash", "ops.rc"))
go_rc = rc(os.path.join(base, "go", "10-op.rc"))

harness = []
biz_details = {}
for name, value in (("bash install rc", bash_install), ("go install rc", go_install),
                    ("bash ops rc", bash_rc), ("go ops rc", go_rc)):
    if value is None:
        harness.append("missing %s" % name)
if bash_rc == 124 or go_rc == 124:
    harness.append("driver rc=124")

reasons = []
if not harness:
    if bash_rc != 0:
        reasons.append("bash menu rc=%s" % bash_rc)
    if go_rc != 0:
        reasons.append("go command rc=%s" % go_rc)

    if oid == "OPS-08":
        b_policy = probe("bash", "after", "sni-policy")
        g_show = jload(os.path.join(base, "go", "11-show.out")) or {}
        if "isolate" not in b_policy:
            reasons.append("bash install_config sni policy is not isolate: %r" % b_policy)
        if g_show.get("policy") != "isolate":
            reasons.append("go guard show policy=%r (want isolate)" % g_show.get("policy"))
        if g_show.get("status") not in ("configured", "active"):
            reasons.append("go guard status=%r (want configured/active)" % g_show.get("status"))
        for side in ("bash", "go"):
            files = probe(side, "after", "sni-files")
            if "ssl_reject_handshake on" not in files:
                reasons.append("%s has no isolate TLS-reject fragment" % side)
            if probe(side, "after", "nginx-active") != "active":
                reasons.append("%s nginx is not active after the policy change" % side)
        # Real TLS probes, recorded per side. A known SNI has to complete a
        # handshake through the front; an unknown SNI has to be refused. The
        # policy label is derived from the probe output, not assumed.
        details = {}
        for side in ("bash", "go"):
            known_out = read(os.path.join(base, side, "after.sni-known.txt"))
            unknown_out = read(os.path.join(base, side, "after.sni-unknown.txt"))
            known_rc = rc(os.path.join(base, side, "after.sni-known.rc"))
            unknown_rc = rc(os.path.join(base, side, "after.sni-unknown.rc"))
            if known_rc is None or unknown_rc is None:
                continue
            known_ok = known_rc == 0 and "CONNECTION ESTABLISHED" in (known_out or "")
            unknown_open = ("CONNECTION ESTABLISHED" in (unknown_out or "")
                            or "Verify return code" in (unknown_out or ""))
            unknown_rejected = not unknown_open and unknown_rc != 0
            if unknown_rejected:
                policy = ("ssl_reject_handshake"
                          if "ssl_reject_handshake on" in probe(side, "after", "sni-files")
                          else "handshake-failed")
            else:
                policy = "accepted"
            details[side] = {
                "sniProbe": {
                    "knownSniOk": known_ok,
                    "unknownSniPolicy": policy,
                    "knownRc": known_rc,
                    "unknownRc": unknown_rc,
                }
            }
        if details:
            biz_details = details
        stale = jload(os.path.join(base, "go", "12-unreloaded.out")) or {}
        reloaded = jload(os.path.join(base, "go", "14-after-reload.out")) or {}
        stale_rc = rc(os.path.join(base, "go", "12-unreloaded.rc"))
        reload_rc = rc(os.path.join(base, "go", "13-reloaded.rc"))
        nginx_test_rc = rc(os.path.join(base, "go", "12-unreloaded.nginx-test.rc"))
        stale_unknown_rc = rc(os.path.join(base, "go", "12-unreloaded.unknown-sni.rc"))
        runtime_probe = {
            "diskEditWithoutReload": True,
            "preservedOldMtime": True,
            "nginxTestRc": nginx_test_rc,
            "showRc": stale_rc,
            "reportedStatusBeforeReload": stale.get("status"),
            "unknownSniRcBeforeReload": stale_unknown_rc,
            "managedReloadRc": reload_rc,
            "reportedStatusAfterReload": reloaded.get("status"),
        }
        if nginx_test_rc != 0:
            reasons.append("nginx -t did not accept the on-disk policy edit")
        if stale_rc != 0 or stale.get("status") != "runtime-unverified":
            reasons.append("Guard did not report the edited, unreloaded policy as runtime-unverified")
        if stale_unknown_rc is None or stale_unknown_rc == 0:
            reasons.append("the running old Nginx worker did not reject unknown SNI before reload")
        if reload_rc != 0 or reloaded.get("status") != "active":
            reasons.append("managed Guard reload did not restore verified active status")
        for side in ("bash", "go"):
            biz_details.setdefault(side, {})["guardRuntime"] = runtime_probe

    elif oid == "OPS-11":
        b_out = text(os.path.join(base, "bash", "ops.out"))
        g_show = jload(os.path.join(base, "go", "10-op.out"))
        if not b_out:
            reasons.append("bash show produced no output")
        elif not any(k in b_out for k in ("协议", "port", "域名", "UUID", "mode")):
            reasons.append("bash show output lacks the expected fields")
        if not isinstance(g_show, (dict, list)) or not g_show:
            reasons.append("go show --json is empty or not JSON")

    elif oid == "OPS-15":
        for side in ("bash", "go"):
            if probe(side, "after", "active") != "active":
                reasons.append("%s xray is not active after restart" % side)

    elif oid == "OPS-20":
        if rc(os.path.join(base, "go", "10-enable.rc")) != 0:
            reasons.append("go xray api enable rc=%s" % rc(os.path.join(base, "go", "10-enable.rc")))
        g_stats = jload(os.path.join(base, "go", "10-op.out"))
        if g_stats is None:
            reasons.append("go stats --json is not parseable")
        traffic = {}
        for side in ("bash", "go"):
            cfg = text(os.path.join(base, side, "after.config.sorted.json"))
            if '"api"' not in cfg or '"listen"' not in cfg:
                reasons.append("%s config lacks the stats/api listener" % side)
            facts = jload(os.path.join(base, side, "traffic-summary.json")) or {}
            traffic[side] = facts
            for field, expected in (("apiPreRc", 2 if side == "bash" else 3),
                                    ("statsBeforeRc", 0), ("statsAfterRc", 0), ("httpRc", 0),
                                    ("httpBodyBytes", 1048576)):
                if facts.get(field) != expected:
                    reasons.append("%s %s=%r (expected %r)" % (side, field, facts.get(field), expected))
            if facts.get("expectedBodyBytes") != 1048576 or facts.get("httpOk") is not True:
                reasons.append("%s did not verify the known local-origin HTTP payload" % side)
            if (not facts.get("expectedBodySha256")
                    or facts.get("httpBodySha256") != facts.get("expectedBodySha256")):
                reasons.append("%s local-origin body hash does not match" % side)
            if facts.get("trafficBytes", 0) <= 0:
                reasons.append("%s inbound traffic counters did not increase" % side)
        biz_details = {
            side: {
                "trafficBytes": traffic[side].get("trafficBytes", 0),
                "apiPreRc": traffic[side].get("apiPreRc"),
                "apiPreExpectedRc": traffic[side].get("apiPreExpectedRc"),
                "statsBeforeRc": traffic[side].get("statsBeforeRc"),
                "statsAfterRc": traffic[side].get("statsAfterRc"),
                "httpRc": traffic[side].get("httpRc"),
                "httpOk": traffic[side].get("httpOk"),
                "httpBodyBytes": traffic[side].get("httpBodyBytes"),
                "httpBodySha256": traffic[side].get("httpBodySha256"),
                "expectedBodySha256": traffic[side].get("expectedBodySha256"),
                "inboundCounters": traffic[side].get("inboundCounters", {}),
                "counterDimension": "per-inbound uplink/downlink bytes",
            }
            for side in ("bash", "go")
        }

    elif oid == "OPS-22":
        for side in ("bash", "go"):
            size = probe(side, "after", "e2e-log-size")
            if size not in ("0", "missing"):
                reasons.append("%s e2e log not truncated (size=%s)" % (side, size))

    elif oid == "OPS-28":
        for side in ("bash", "go"):
            if probe(side, "after", "active") == "active":
                reasons.append("%s xray still active after uninstall" % side)
            if probe(side, "after", "config-exists") != "absent":
                reasons.append("%s runtime config still present after purge" % side)

if harness:
    verdict, reasons = "HARNESS-ERROR", harness
elif reasons:
    verdict = "FAIL"
else:
    verdict = "PASS"

out = os.path.join(base, "ops.json")
report = {
    "id": oid,
    "verdict": verdict,
    "reasons": reasons,
    "bothInstallRc": {"bash": bash_install, "go": go_install},
    "opsRc": {"bash": bash_rc, "go": go_rc},
    "observed": {
        "bash": {
            "active": probe("bash", "after", "active"),
            "config": probe("bash", "after", "config-exists"),
            "sniPolicy": probe("bash", "after", "sni-policy"),
            "e2eLogSize": probe("bash", "after", "e2e-log-size"),
        },
        "go": {
            "active": probe("go", "after", "active"),
            "config": probe("go", "after", "config-exists"),
            "e2eLogSize": probe("go", "after", "e2e-log-size"),
        },
    },
}
if biz_details:
    report["details"] = biz_details
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(verdict)
PY
}

# --- observe-only OPS rows (round 3 D07 remainder) -------------------------
# These rows are not equivalence candidates in this round. They are still
# executed on both sides so the recorded DIFF/BLOCKED verdict cites real
# output instead of the absence of a Bash entry point.
ops_bash_capture() { # <server> <dir> <label> <timeout> <shell-command>
    local server=$1 dir=$2 label=$3 limit=$4 script=$5
    mkdir -p "$dir"
    docker exec -i "$server" timeout "$limit" bash -c "$script" \
        >"$dir/$label.out" 2>"$dir/$label.err"
    echo $? >"$dir/$label.rc"
}

ops_bash_pipe() { # <server> <dir> <label> <timeout> <input> [install.sh args...]
    local server=$1 dir=$2 label=$3 limit=$4 input=$5; shift 5
    mkdir -p "$dir"
    printf '%b' "$input" | docker exec -i "${MENU_NGINX_ENVS[@]+"${MENU_NGINX_ENVS[@]}"}" \
        "$server" timeout "$limit" \
        bash /etc/idleleo/install.sh "$@" >"$dir/$label.out" 2>"$dir/$label.err"
    echo $? >"$dir/$label.rc"
}

ops_backup_snapshot() { # <server> <dir> <tag>
    local server=$1 dir=$2 tag=$3
    docker exec "$server" bash -c '
        set +e
        root=/etc/idleleo
        for f in conf/xray/config.json conf/install_config.json cert/xray.crt cert/xray.key conf/nginx/00-xray.conf conf/ops25-canary.txt v1/metadata.json; do
            if [ -f "$root/$f" ]; then printf "%s %s\n" "$f" "$(sha256sum "$root/$f" | cut -d " " -f1)"; fi
        done
        stat -c "config-mode %a:%G" "$root/conf/xray/config.json" 2>/dev/null
        printf "xray-active %s\n" "$(systemctl is-active xray 2>/dev/null)"
        printf "nginx-active %s\n" "$(systemctl is-active nginx 2>/dev/null)"
        /usr/local/bin/xray run -test -config "$root/conf/xray/config.json" >/tmp/ops-xray-test.log 2>&1
        printf "xray-test-rc %s\n" "$?"
        /usr/local/nginx/sbin/nginx -t >/tmp/ops-nginx-test.log 2>&1
        printf "nginx-test-rc %s\n" "$?"
    ' >"$dir/$tag.snapshot.txt" 2>"$dir/$tag.snapshot.err"
}

ops_backup_mutate() { # <server>
    docker exec "$1" bash -c '
        printf "\n" >> /etc/idleleo/conf/xray/config.json
        printf "mutated-after-backup\n" > /etc/idleleo/conf/ops25-canary.txt
        chmod 0600 /etc/idleleo/conf/xray/config.json
    '
}

ops_observe_job() {
    OPS_NET="e2e-$RUN_ID-observe"
    local base="$EVID/observe" bdir="$EVID/observe/bash" gdir="$EVID/observe/go"
    mkdir -p "$bdir" "$gdir"
    docker network create "$OPS_NET" >/dev/null 2>&1 || true
    log "[observe] start"

    local bserver="e2e-$RUN_ID-observe-bash" gserver="e2e-$RUN_ID-observe-go"
    start_server "$bserver" observe bash "$bdir" "$OPS_NET" || {
        echo '{"status":"harness-error"}' >"$bdir/harness.json"
    }
    start_server "$gserver" observe go "$gdir" "$OPS_NET" || {
        echo '{"status":"harness-error"}' >"$gdir/harness.json"
    }
    ops_bash_base "$bserver" "$bdir" M2
    ops_go_base "$gserver" "$gdir" reality-nginx
    for side in "$bserver" "$gserver"; do
        docker exec "$side" sh -c 'mkdir -p /var/log/xray
            printf "e2e-access-marker\n" >> /var/log/xray/access.log
            printf "e2e-error-marker\n" >> /var/log/xray/error.log' >/dev/null 2>&1 || true
    done

    local d
    if [[ "${E2E_OBSERVE_BACKUP_ONLY:-0}" != "1" ]]; then
    # OPS-12/13: real live-tail vs finite journal snapshot.
    ops_bash_capture "$bserver" "$EVID/OPS-12/bash" run 6 'exec bash /etc/idleleo/install.sh -xa 20'
    ops_go_cli "$gserver" "$EVID/OPS-12/go" 10-op service logs --unit xray --lines 20
    ops_bash_capture "$bserver" "$EVID/OPS-13/bash" run 6 'exec bash /etc/idleleo/install.sh -xe 20'
    ops_go_cli "$gserver" "$EVID/OPS-13/go" 10-op service logs --unit xray --lines 20

    # OPS-14: iftop live UI vs stats query. The Go stats API is not enabled by a
    # default install, so enable it first; otherwise the row would compare a
    # working Bash UI against a command that was never given its API.
    ops_bash_pipe "$bserver" "$EVID/OPS-14/bash" run 8 '3\n4\n'
    docker exec "$gserver" sh -c \
        'printf "#!/bin/sh\nexec systemctl restart xray\n" > /usr/local/bin/e2e-service-apply && chmod 0755 /usr/local/bin/e2e-service-apply' \
        >/dev/null 2>&1 || true
    ops_go_cli "$gserver" "$EVID/OPS-14/go" 09-enable xray api enable --sandbox / \
        --validator /usr/local/bin/xray --service /usr/local/bin/e2e-service-apply \
        --container --json
    ops_go_cli "$gserver" "$EVID/OPS-14/go" 10-op stats --json

    # OPS-16 runs in its own job on a real TLS install (a Reality-only node has
    # no certificate), see ops_cert_job.

    # OPS-18: interactive host BBR switch vs tcp status.
    ops_bash_pipe "$bserver" "$EVID/OPS-18/bash" run 20 '6\n1\n'
    ops_go_cli "$gserver" "$EVID/OPS-18/go" 10-op tcp status --json

    # OPS-23: Bash menu 6>6 delegates to the idleleo binary.
    ops_bash_pipe "$bserver" "$EVID/OPS-23/bash" run 30 '6\n6\n'
    ops_go_cli "$gserver" "$EVID/OPS-23/go" 10-op speedtest --json \
        --server https://www.cloudflare.com --bytes 1024 --samples 1 --timeout 10s

    # OPS-24: interactive GeoData menu vs schedule status.
    ops_bash_pipe "$bserver" "$EVID/OPS-24/bash" run 40 '6\n7\n'
    ops_go_cli "$gserver" "$EVID/OPS-24/go" 10-op schedule status --json

    # OPS-29: Rill status from both sides.
    ops_bash_capture "$bserver" "$EVID/OPS-29/bash" run 30 'exec bash /etc/idleleo/install.sh --rill-agent-status'
    ops_go_cli "$gserver" "$EVID/OPS-29/go" 10-op rill status --json

    # OPS-17a/17b: update checks need the public distribution / a trusted
    # local package; still execute to prove the offline/fail-closed path.
    ops_bash_pipe "$bserver" "$EVID/OPS-17a/bash" run 30 '5\n1\n'
    ops_go_cli "$gserver" "$EVID/OPS-17a/go" 10-op update status --json

    # OPS-17b: both sides must replace a real 1.27 binary with the seeded
    # 1.30.6 build. Bash reads its current build from install_config, Go reads
    # the binary itself, so each side gets the matching fixture.
    local b17="$EVID/OPS-17b/bash" g17="$EVID/OPS-17b/go" go_manifest="/seed/nginx/go-nginx-manifest.json"
    mkdir -p "$b17" "$g17"
    if write_go_nginx_manifest >"$EVID/OPS-17b/expected-version.txt"; then
        seed_old_nginx_binary "$bserver" "$b17"
        seed_old_nginx_binary "$gserver" "$g17"
        docker exec "$bserver" sh -c '
            f=/etc/idleleo/conf/install_config.json
            jq --arg v "1.27.0" ".nginx_build_version=\$v" "$f" >"$f.tmp" && mv "$f.tmp" "$f"'
        docker exec "$bserver" cat /etc/idleleo/conf/install_config.json \
            >"$b17/install-config-before.json" 2>/dev/null || true
        docker exec "$bserver" /usr/local/nginx/sbin/nginx -v >"$b17/nginx-before.txt" 2>&1 || true
        docker exec "$gserver" /usr/local/nginx/sbin/nginx -v >"$g17/nginx-before.txt" 2>&1 || true
        MENU_NGINX_ENVS=("${NGINX_CACHE_ENVS[@]+"${NGINX_CACHE_ENVS[@]}"}")
        # 5=update menu, 3=nginx update, empty=IP prompt default, empty=keep
        # existing nginx conf, 0=exit the menu the update re-execs into.
        ops_bash_pipe "$bserver" "$b17" run 180 '5\n3\n\n\n0\n'
        MENU_NGINX_ENVS=()
        ops_go_cli "$gserver" "$g17" 10-op update nginx \
            --manifest "$go_manifest" --container --json
        docker exec "$bserver" /usr/local/nginx/sbin/nginx -v >"$b17/nginx-after.txt" 2>&1 || true
        docker exec "$gserver" /usr/local/nginx/sbin/nginx -v >"$g17/nginx-after.txt" 2>&1 || true
        docker exec "$bserver" sh -c 'ls -d /usr/local/nginx_backup_*' >"$b17/backup.txt" 2>&1 || true
        docker exec "$bserver" cat /etc/idleleo/conf/install_config.json \
            >"$b17/install-config-after.json" 2>/dev/null || true
        docker exec "$gserver" sh -c 'ls -d /etc/idleleo/backup/nginx-* 2>/dev/null' >"$g17/backup.txt" 2>&1 || true
        ops_health "$bserver" "$b17" updated
        ops_health "$gserver" "$g17" updated
    else
        echo "seed-nginx-cache-missing" >"$EVID/OPS-17b/harness-blocked.txt"
    fi

    fi

    # OPS-25/26: real native archives on both managers. Capture the managed
    # state, permissions, validators, services and L4 before/after; corrupt the
    # live copy after backup so a successful restore must recover archived data.
    local b25="$EVID/OPS-25/bash" g25="$EVID/OPS-25/go"
    local b26="$EVID/OPS-26/bash" g26="$EVID/OPS-26/go"
    mkdir -p "$b25" "$g25" "$b26" "$g26"
    for side in bash go; do
        local server dir
        if [[ "$side" == bash ]]; then server=$bserver; dir=$b25; else server=$gserver; dir=$g25; fi
        docker exec "$server" sh -c 'printf "ops25-canary\n" > /etc/idleleo/conf/ops25-canary.txt' >/dev/null 2>&1 || true
        ops_backup_snapshot "$server" "$dir" before
    done
    ops_bash_pipe "$bserver" "$b25" create 90 'e2e-ops25\n' --backup
    docker exec "$bserver" sh -c 'find /etc/idleleo -maxdepth 1 -name "xray_bash_e2e-ops25_*.tar.gz" -print -quit' \
        >"$b25/archive-path.txt" 2>"$b25/archive-path.err"
    docker exec "$bserver" bash -c 'a=$(find /etc/idleleo -maxdepth 1 -name "xray_bash_e2e-ops25_*.tar.gz" -print -quit); [ -n "$a" ] && stat -c "%a" "$a" && sha256sum "$a"' \
        >"$b25/archive-integrity.txt" 2>&1
    echo $? >"$b25/archive-integrity.rc"
    docker exec "$bserver" bash -c '
        set -e
        a=$(find /etc/idleleo -maxdepth 1 -name "xray_bash_e2e-ops25_*.tar.gz" -print -quit)
        d=$(mktemp -d)
        trap "rm -rf \"$d\"" EXIT
        tar -xzf "$a" -C "$d"
        (cd "$d" && sha256sum --strict -c etc/idleleo/.backup_sha256sums.txt)
    ' >"$b25/archive-verify.out" 2>"$b25/archive-verify.err"
    echo $? >"$b25/archive-verify.rc"
    ops_go_cli "$gserver" "$g25" create backup create --out /tmp/ops25-go.tar.gz --include-geodata --container --json
    docker exec "$gserver" bash -c 'stat -c "%a" /tmp/ops25-go.tar.gz; sha256sum /tmp/ops25-go.tar.gz' \
        >"$g25/archive-integrity.txt" 2>&1
    echo $? >"$g25/archive-integrity.rc"
    ops_go_cli "$gserver" "$g25" verify backup verify --archive /tmp/ops25-go.tar.gz --json

    ops_backup_mutate "$bserver"; ops_backup_mutate "$gserver"
    ops_bash_pipe "$bserver" "$b26" restore 180 '' --restore
    ops_go_cli "$gserver" "$g26" restore backup restore --archive /tmp/ops25-go.tar.gz --container --json
    # Bash restore intentionally leaves service startup to the caller; restart
    # both units after restoring, while Go performs restart inside its restore
    # transaction. Record these semantics and verify actual runtime afterward.
    docker exec "$bserver" systemctl restart xray nginx >"$b26/service-restart.out" 2>&1
    echo $? >"$b26/service-restart.rc"
    ops_backup_snapshot "$bserver" "$b26" after
    ops_backup_snapshot "$gserver" "$g26" after
    docker exec "$bserver" cat /etc/idleleo/conf/ops25-canary.txt >"$b26/canary.txt" 2>&1
    echo $? >"$b26/canary.rc"
    docker exec "$gserver" cat /etc/idleleo/conf/ops25-canary.txt >"$g26/canary.txt" 2>&1
    echo $? >"$g26/canary.rc"
    run_l4 M2 bash "$bserver" "$b26" "$OPS_NET" reality 3
    run_l4 M2 go "$gserver" "$g26" "$OPS_NET" reality 3

    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" "$gserver" >/dev/null 2>&1 || true
    docker network rm "$OPS_NET" >/dev/null 2>&1 || true

    ops_observe_verdict
    log "[observe] verdicts written"
}

ops_observe_verdict() {
    python3 - "$EVID" <<'PY'
import json
import os
import re
import sys

evid = sys.argv[1]


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def rc(path):
    try:
        return int(read(path).strip())
    except ValueError:
        return None


def write(oid, verdict, reasons, extra=None):
    entry = {
        "id": oid,
        "verdict": verdict,
        "reasons": reasons,
        "opsRc": {
            "bash": rc(os.path.join(evid, oid, "bash", "run.rc")) if os.path.isdir(os.path.join(evid, oid, "bash")) else None,
            "go": rc(os.path.join(evid, oid, "go", "10-op.rc")),
        },
    }
    if extra:
        entry.update(extra)
    path = os.path.join(evid, oid)
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "ops.json"), "w", encoding="utf-8") as fh:
        json.dump(entry, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return entry


def write_doc(oid, name, payload):
    path = os.path.join(evid, oid)
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, name), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def out(oid, side, name):
    return read(os.path.join(evid, oid, side, name + ".out"))


def bash_exists(oid):
    return os.path.isdir(os.path.join(evid, oid, "bash"))


# Live-tail Bash vs finite journal Go: the content is real on both sides, but
# one is an unbounded stream and the other a bounded query.
for oid, marker, logfile in (
    ("OPS-12", "e2e-access-marker", "/var/log/xray/access.log"),
    ("OPS-13", "e2e-error-marker", "/var/log/xray/error.log"),
):
    b = out(oid, "bash", "run")
    g = out(oid, "go", "10-op")
    reasons = ["Bash menu entry is an unbounded 'tail -f' stream; Go emits a finite journald snapshot"]
    if marker not in b:
        reasons.append("Bash live stream did not surface the seeded %s line" % marker)
    if not g.strip():
        reasons.append("Go journal snapshot is empty")
    entry = write(oid, "DIFF", reasons)
    write_doc(oid, "log-source-difference.json", {
        "id": oid,
        "result": "DIFF",
        "approved": False,
        "source": logfile,
        "bash": {
            "entry": "install.sh menu live tail",
            "rc": entry["opsRc"]["bash"],
            "seededMarkerVisible": marker in b,
        },
        "go": {
            "entry": "idleleo service logs (journald snapshot)",
            "rc": entry["opsRc"]["go"],
            "outputBytes": len(g.encode()),
        },
        "reasons": reasons,
        "note": "Live tail is unbounded; the finite Go snapshot is not an equivalent command. External approval is required before treating this as equal.",
    })

# iftop vs stats query.
b14 = out("OPS-14", "bash", "run")
g14 = out("OPS-14", "go", "10-op")
write("OPS-14", "DIFF", [
    "Bash entry is the interactive iftop UI; Go is a bounded stats query",
    "bash output bytes=%d" % len(b14.encode()),
    "go api enable rc=%s" % rc(os.path.join(evid, "OPS-14", "go", "09-enable.rc")),
    "go stats rc=%s" % rc(os.path.join(evid, "OPS-14", "go", "10-op.rc")),
])

# OPS-16 is verified in ops_cert_job on a real TLS install.

# Host BBR cannot be proven from inside a container.
write("OPS-18", "BLOCKED", [
    "Bash entry is an interactive host BBR switch; a container cannot change or prove the host kernel",
    "Go tcp status rc=%s" % rc(os.path.join(evid, "OPS-18", "go", "10-op.rc")),
])

# Bash no longer has an independent speedtest: menu 6>6 delegates to idleleo.
b23 = out("OPS-23", "bash", "run")
write("OPS-23", "BLOCKED", [
    "Bash menu 6>6 delegates to the idleleo Go binary, so this is not an independent Bash implementation",
    "delegation observed=%s" % ("idleleo" in b23 or "命令未找到" in b23 or "command not found" in b23),
])

# GeoData: the Bash menu downloads from the hard-coded public GitHub release and
# needs live internet; the isolated container only reaches its local peers. The
# Go geodata job is verified separately by run_ops_sweep.sh against a pinned
# local origin, so this row stays BLOCKED here rather than claiming parity.
b24 = out("OPS-24", "bash", "run")
write("OPS-24", "BLOCKED", [
    "Bash GeoData menu refreshes from the hard-coded public GitHub release; this isolated job has no public origin",
    "bash output shows the GeoData menu, bytes=%d" % len(b24.encode()),
    "go schedule status rc=%s; real Go geodata refresh is covered by the ops sweep with a local origin"
    % rc(os.path.join(evid, "OPS-24", "go", "10-op.rc")),
])

def read_snapshot(path):
    data = {}
    for line in read(path).splitlines():
        key, _, value = line.partition(" ")
        if key:
            data[key] = value
    return data

def backup_side_checks(side):
    base = os.path.join(evid, "OPS-25", side)
    after_dir = os.path.join(evid, "OPS-26", side)
    before = read_snapshot(os.path.join(base, "before.snapshot.txt"))
    after = read_snapshot(os.path.join(after_dir, "after.snapshot.txt"))
    expected_files = ("conf/xray/config.json", "cert/xray.crt", "cert/xray.key",
                      "conf/nginx/00-xray.conf", "conf/ops25-canary.txt")
    present = [name for name in expected_files if before.get(name)]
    same = bool(present) and all(before[name] == after.get(name) for name in present)
    wanted_mode = "600:root" if side == "bash" else "640:xray"
    permissions = before.get("config-mode") == after.get("config-mode") == wanted_mode
    services = all(after.get(k) == v for k, v in (("xray-active", "active"),
                                                   ("nginx-active", "active"),
                                                   ("xray-test-rc", "0"),
                                                   ("nginx-test-rc", "0")))
    canary = read(os.path.join(after_dir, "canary.txt")).strip() == "ops25-canary"
    l4_rows = []
    try:
        l4_rows = [json.loads(line) for line in read(os.path.join(after_dir, "L4", "round3.jsonl")).splitlines()
                   if line.strip()]
    except ValueError:
        pass
    l4 = bool(l4_rows) and all(row.get("rc") == 0 for row in l4_rows)
    if side == "bash":
        create_rc = rc(os.path.join(base, "create.rc"))
        verify_rc = rc(os.path.join(base, "archive-verify.rc"))
        archive_lines = read(os.path.join(base, "archive-integrity.txt")).splitlines()
        archive_ok = bool(archive_lines and archive_lines[0].strip() == "600" and len(archive_lines) > 1)
        restore_rc = rc(os.path.join(after_dir, "restore.rc"))
    else:
        create_rc = rc(os.path.join(base, "create.rc"))
        verify_rc = rc(os.path.join(base, "verify.rc"))
        archive_lines = read(os.path.join(base, "archive-integrity.txt")).splitlines()
        archive_ok = bool(archive_lines and archive_lines[0].strip() == "600" and len(archive_lines) > 1)
        restore_rc = rc(os.path.join(after_dir, "restore.rc"))
    return {"createRc": create_rc, "verifyRc": verify_rc, "restoreRc": restore_rc,
            "archiveModeAndDigest": archive_ok, "managedFilesRestored": same,
            "permissionsRestored": permissions, "servicesAndValidators": services,
            "canaryRestored": canary, "realClient": l4,
            "before": before, "after": after}

b26, g26 = backup_side_checks("bash"), backup_side_checks("go")
for oid in ("OPS-25", "OPS-26"):
    complete = all(s["createRc"] == 0 and s["archiveModeAndDigest"] and
                   s["managedFilesRestored"] and s["permissionsRestored"] and
                   s["servicesAndValidators"] and s["canaryRestored"] and s["realClient"] and
                   s["verifyRc"] == 0 and (oid != "OPS-26" or s["restoreRc"] == 0)
                   for s in (b26, g26))
    reasons = ["Both sides exercised their native backup/restore path with real Docker services and clients",
               "Bash result=%s" % json.dumps({k:v for k,v in b26.items() if k not in ("before","after")}, sort_keys=True),
               "Go result=%s" % json.dumps({k:v for k,v in g26.items() if k not in ("before","after")}, sort_keys=True)]
    write(oid, "DUAL" if complete else "DIFF", reasons, {"bash": b26, "go": g26})
write_doc("OPS-26", "native-backup-restore-comparison.json", {
    "id": "OPS-25/26", "result": "DUAL" if all(
        s["createRc"] == 0 and s["verifyRc"] == 0 and s["restoreRc"] == 0 and
        s["archiveModeAndDigest"] and s["managedFilesRestored"] and
        s["permissionsRestored"] and s["servicesAndValidators"] and
        s["canaryRestored"] and s["realClient"] for s in (b26, g26)) else "DIFF",
    "bash": b26, "go": g26,
    "note": "Native archive formats and scope are not treated as identical. Bash includes broader runtime files and preserves its 0600:root config policy; Go archives only managed state and preserves its 0640:xray policy. The probe compares common managed data, each manager's established permission policy, validation, service state and real-client connectivity. The harness restarts Bash services after restore because Bash restore does not start them; Go restarts services inside its restore transaction."
})

# Rill status is a genuine read-only query on both sides.
b29, g29 = out("OPS-29", "bash", "run"), out("OPS-29", "go", "10-op")
r29 = {"bash": rc(os.path.join(evid, "OPS-29", "bash", "run.rc")),
       "go": rc(os.path.join(evid, "OPS-29", "go", "10-op.rc"))}
if r29["bash"] == 0 and r29["go"] == 0 and b29.strip() and g29.strip():
    write("OPS-29", "PASS", ["both sides returned Rill status"])
else:
    write("OPS-29", "DIFF", ["Rill status could not be proven on both sides: rc=%r" % r29])

# Update checks need public distribution / a trusted local package.
write("OPS-17a", "BLOCKED", [
    "update check requires the public distribution; this job has no pinned manifest",
    "bash rc=%s go rc=%s" % (rc(os.path.join(evid, "OPS-17a", "bash", "run.rc")),
                             rc(os.path.join(evid, "OPS-17a", "go", "10-op.rc"))),
])
# OPS-17b: both sides must really replace the 1.27 binary with the seeded build.
def nginx_version(path):
    match = re.search(r"nginx/([0-9][0-9.]*)", read(path))
    return match.group(1) if match else ""


b17 = os.path.join(evid, "OPS-17b", "bash")
g17 = os.path.join(evid, "OPS-17b", "go")
expected = read(os.path.join(evid, "OPS-17b", "expected-version.txt")).strip()
try:
    expected_build = json.loads(read(os.path.join(evid, "nginx-cache.json")) or "{}").get("build") or ""
except ValueError:
    expected_build = ""


def bash_build_after():
    try:
        config = json.loads(read(os.path.join(b17, "install-config-after.json")) or "{}")
    except ValueError:
        return ""
    return str(config.get("nginx_build_version") or "")


bash_backup = [line for line in read(os.path.join(b17, "backup.txt")).splitlines()
               if line.startswith("/usr/local/nginx_backup_")]
bash17 = {
    "rc": rc(os.path.join(b17, "run.rc")),
    "before": nginx_version(os.path.join(b17, "nginx-before.txt")),
    "after": nginx_version(os.path.join(b17, "nginx-after.txt")),
    "buildAfter": bash_build_after(),
    # Bash deletes its backup after a successful update, so the log line is the
    # durable proof that the old tree was copied before replacement. A failed
    # `ls` (the expected post-delete state) must not count as a backup.
    "backup": bash_backup[0] if bash_backup
              else ("backup-created" if "备份旧版" in read(os.path.join(b17, "run.out")) else ""),
    "health": rc(os.path.join(b17, "updated.xray-active.rc")),
    "previousBinary": read(os.path.join(b17, "previous-binary.txt")).strip(),
}
go17 = {
    "rc": rc(os.path.join(g17, "10-op.rc")),
    "before": nginx_version(os.path.join(g17, "nginx-before.txt")),
    "after": nginx_version(os.path.join(g17, "nginx-after.txt")),
    "backup": read(os.path.join(g17, "backup.txt")).strip(),
    "health": rc(os.path.join(g17, "updated.xray-active.rc")),
    "previousBinary": read(os.path.join(g17, "previous-binary.txt")).strip(),
}
try:
    go17_report = json.loads(read(os.path.join(g17, "10-op.out")) or "{}")
except ValueError:
    go17_report = {}
biz17 = {"bash": bash17, "go": go17, "expected": expected,
         "goReport": {k: go17_report.get(k) for k in
                      ("previousVersion", "newVersion", "verified", "health", "backupPath", "restarted")}}
if not expected:
    write("OPS-17b", "BLOCKED", [
        "the seeded Nginx package is unavailable, so the update cannot be exercised",
        "see OPS-17b/harness-blocked.txt",
    ], extra={"details": biz17})
else:
    reasons = []
    for name, obs17 in (("bash", bash17), ("go", go17)):
        if obs17["rc"] != 0:
            reasons.append("%s update rc=%s" % (name, obs17["rc"]))
        if not obs17["before"].startswith("1.27"):
            reasons.append("%s previous nginx is %r, want 1.27.x" % (name, obs17["before"]))
        if obs17["after"] != expected:
            reasons.append("%s installed nginx is %r, want %r" % (name, obs17["after"], expected))
        if not obs17["backup"]:
            reasons.append("%s left no nginx backup" % name)
        if obs17["health"] != 0:
            reasons.append("%s nginx/xray unhealthy after update" % name)
    if go17_report.get("newVersion") not in (None, "", expected):
        reasons.append("go reports newVersion=%r" % go17_report.get("newVersion"))
    if go17_report.get("previousVersion") and not str(go17_report["previousVersion"]).startswith("1.27"):
        reasons.append("go reports previousVersion=%r" % go17_report.get("previousVersion"))
    if expected_build and bash17["buildAfter"] != expected_build:
        reasons.append("bash recorded nginx build %r, want %r" % (bash17["buildAfter"], expected_build))
    if reasons:
        write("OPS-17b", "FAIL", reasons, extra={"details": biz17})
    else:
        write("OPS-17b", "PASS", [], extra={"details": biz17})
PY
}


# OPS-16: certificate status. Both sides run on a real TLS install, because a
# Reality-only node has no certificate and the Bash menu refuses the operation.
# A self-signed pair is seeded for both sides; the Bash menu and the Go renewal
# preflight are different operations, so the row stays an unapproved DIFF with
# recorded certificate facts, never a PASS.
ops_cert_job() {
    local oid=OPS-16
    OPS_NET="e2e-$RUN_ID-$oid"
    local bdir="$EVID/$oid/bash" gdir="$EVID/$oid/go"
    mkdir -p "$bdir" "$gdir"
    docker network create "$OPS_NET" >/dev/null 2>&1 || true
    log "[$oid] start"

    local bserver="e2e-$RUN_ID-$oid-bash"
    if start_server "$bserver" "$oid" bash "$bdir" "$OPS_NET"; then
        run_bash_round M4 "$OPS_NET" "$bserver" "$bdir" 1 "" tls "-1" "" 1
        ops_cert_facts "$bserver" "$bdir/cert-facts.txt"
        # 4>2>1 status, 4>2>2 validity, then unwind the three menus.
        ops_bash_pipe "$bserver" "$bdir" run 60 '4\n2\n1\n0\n2\n2\n0\n0\n0\n'
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    local gserver="e2e-$RUN_ID-$oid-go" go_argv_json
    go_argv_json=$(matrix_get M4 go.argv)
    if [[ -n "$go_argv_json" ]] && start_server "$gserver" "$oid" go "$gdir" "$OPS_NET"; then
        local -a GO_ARGV=()
        while IFS= read -r line; do GO_ARGV+=("$line"); done < <(json_list "$go_argv_json")
        run_go_round M4 "$gserver" "$gdir" 1 "" tls "${GO_ARGV[@]}"
        ops_cert_facts "$gserver" "$gdir/cert-facts.txt"
        ops_go_cli "$gserver" "$gdir" 10-op xray cert renew --dry-run --json \
            --domain "$DOMAIN" --webroot /var/lib/idleleo/acme \
            --cert-out /etc/idleleo/cert/xray.crt --key-out /etc/idleleo/cert/xray.key
    else
        echo '{"status":"harness-error","reason":"container or M4 argv unavailable"}' >"$gdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker network rm "$OPS_NET" >/dev/null 2>&1 || true

    log "[$oid] verdict=$(ops_cert_verdict)"
}

ops_cert_facts() { # <server> <out-file>
    docker exec "$1" sh -c '
        f=/etc/idleleo/cert/xray.crt
        if [ ! -f "$f" ]; then echo "present=false"; exit 0; fi
        echo "present=true"
        openssl x509 -in "$f" -noout -subject -enddate 2>&1
        if openssl x509 -in "$f" -noout -checkend 0 >/dev/null 2>&1; then
            echo "notExpired=true"
        else
            echo "notExpired=false"
        fi
        sha256sum "$f" | awk "{print \"sha256=\" \$1}"
    ' >"$2" 2>&1 || true
}

ops_cert_verdict() {
    python3 - "$EVID/OPS-16" <<'PY'
import json
import os
import sys

base = sys.argv[1]


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def rc(path):
    try:
        return int(read(path).strip())
    except ValueError:
        return None


bash_facts = read(os.path.join(base, "bash", "cert-facts.txt"))
go_facts = read(os.path.join(base, "go", "cert-facts.txt"))
go_out = read(os.path.join(base, "go", "10-op.out"))
state = ""
if '"certificateFile"' in go_out:
    try:
        data = json.loads(go_out)
        if data.get("missing"):
            state = "missing"
        elif data.get("userManaged"):
            state = "user-managed"
        elif data.get("due"):
            state = "due"
        else:
            state = "not-due"
    except ValueError:
        state = ""

reasons = [
    "Bash menu 4>2>1/4>2>2 shows certificate status/validity; Go 'cert renew --dry-run' is a renewal preflight",
    "bash rc=%s" % rc(os.path.join(base, "bash", "run.rc")),
    "go rc=%s" % rc(os.path.join(base, "go", "10-op.rc")),
    "bash certificate present=%s" % ("present=true" in bash_facts),
    "go certificate present=%s notExpired=%s state=%s"
    % ("present=true" in go_facts, "notExpired=true" in go_facts, state or "unknown"),
]
entry = {
    "id": "OPS-16",
    "verdict": "DIFF",
    "reasons": reasons,
    "opsRc": {
        "bash": rc(os.path.join(base, "bash", "run.rc")),
        "go": rc(os.path.join(base, "go", "10-op.rc")),
    },
    "certificate": {
        "bashPresent": "present=true" in bash_facts,
        "goPresent": "present=true" in go_facts,
        "goNotExpired": "notExpired=true" in go_facts,
        "goState": state,
    },
}
with open(os.path.join(base, "ops.json"), "w", encoding="utf-8") as fh:
    json.dump(entry, fh, indent=2, sort_keys=True)
    fh.write("\n")
print("DIFF")
PY
}

# Bash backup menu 7>3 authorizes rm -rf of the whole certificate directory
# after one interactive confirm. Go only removes entries whose
# .managed-by-idleleo sha256 ownership proves they belong to this project.
# Both sides are executed on the same fixture; the third-party canary proves
# the difference and the row stays an UNAPPROVED difference (never a PASS).
ops_certclear_job() {
    local oid=OPS-27
    OPS_NET="e2e-$RUN_ID-$oid"
    local base="$EVID/$oid" bdir="$EVID/$oid/bash" gdir="$EVID/$oid/go"
    mkdir -p "$bdir" "$gdir"
    docker network create "$OPS_NET" >/dev/null 2>&1 || true
    log "[$oid] start"

    local bserver="e2e-$RUN_ID-$oid-bash"
    if start_server "$bserver" "$oid" bash "$bdir" "$OPS_NET"; then
        ops_bash_base "$bserver" "$bdir" M2
        ops_cert_canary "$bserver"
        ops_state_probe "$bserver" "$bdir" before
        ops_bash_menu "$bserver" "$bdir" "$oid"
        ops_state_probe "$bserver" "$bdir" after
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    local gserver="e2e-$RUN_ID-$oid-go"
    if start_server "$gserver" "$oid" go "$gdir" "$OPS_NET"; then
        ops_go_base "$gserver" "$gdir" reality-nginx
        ops_cert_canary "$gserver"
        ops_state_probe "$gserver" "$gdir" before
        ops_go_cli "$gserver" "$gdir" 10-op xray cert clear --yes --container --json
        ops_state_probe "$gserver" "$gdir" after
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$gdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker network rm "$OPS_NET" >/dev/null 2>&1 || true

    log "[$oid] difference=$(ops_certclear_verdict)"
}

# A certificate and key that no management metadata references.
ops_cert_canary() { # <server>
    docker exec "$1" sh -c '
        mkdir -p /etc/idleleo/cert
        openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -subj "/CN=thirdparty.example.com" \
            -keyout /etc/idleleo/cert/thirdparty.key \
            -out /etc/idleleo/cert/thirdparty.crt >/dev/null 2>&1
    ' >/dev/null 2>&1 || true
}

ops_certclear_verdict() {
    local base="$EVID/OPS-27"
    python3 - "$base" <<'PY'
import json
import os
import sys

base = sys.argv[1]


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def rc(path):
    try:
        return int(read(path).strip())
    except ValueError:
        return None


def entries(side, tag):
    return sorted(x for x in read(os.path.join(base, side, "%s.cert-list.txt" % tag)).splitlines() if x)


bash_rc = rc(os.path.join(base, "bash", "ops.rc"))
go_rc = rc(os.path.join(base, "go", "10-op.rc"))
b_before, b_after = entries("bash", "before"), entries("bash", "after")
g_before, g_after = entries("go", "before"), entries("go", "after")

harness = []
if bash_rc is None or go_rc is None:
    harness.append("missing execution rc")
if bash_rc == 124 or go_rc == 124:
    harness.append("driver rc=124")

canary = "thirdparty.crt"
bash_kept = canary in b_after
go_kept = canary in g_after
reasons = [
    "Bash backup menu 7>3 deletes the whole certificate directory after one confirm; Go requires managed ownership proof",
]
if not bash_kept:
    reasons.append("Bash removed the third-party canary (rm -rf entire cert dir)")
if go_kept:
    reasons.append("Go kept the third-party canary (no managed ownership)")
elif canary not in g_before:
    reasons.append("Go fixture lost the canary before the command ran")

report = {
    "id": "OPS-27",
    "result": "HARNESS-ERROR" if harness else "DIFF",
    "reasons": harness + reasons,
    "opsRc": {"bash": bash_rc, "go": go_rc},
    "bashCertList": {"before": b_before, "after": b_after},
    "goCertList": {"before": g_before, "after": g_after},
    "canaryKeptByGo": go_kept,
    "canaryRemovedByBash": not bash_kept,
    "approved": False,
    "note": "unapproved behavioural difference; the row is NOT dual-side verified",
}
out = os.path.join(base, "cert-clear-difference.json")
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(report["result"])
PY
}

ops_users_verdict() { # <base>
    local base=$1
    python3 - "$base" "$OPS_USER_EMAIL" "$OPS_USER_UUID" "$OPS_USER_SHORT_ID" <<'PY'
import json
import os
import sys

base, email, go_uuid, go_short_id = sys.argv[1:5]
p2 = os.path.dirname(base)
bdir, gdir = os.path.join(base, "bash"), os.path.join(base, "go")


def lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [line.strip() for line in fh if line.strip()]
    except OSError:
        return []


def text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def rc(path):
    raw = text(path).strip()
    try:
        return int(raw)
    except ValueError:
        return None


def active(tag, side):
    return text(os.path.join(base, side, "%s.xray-active.txt" % tag)).strip().startswith("active")


def healthy(tag):
    return all(
        rc(os.path.join(base, side, "%s.xray-test.rc" % tag)) == 0
        and rc(os.path.join(base, side, "%s.xray-active.rc" % tag)) == 0
        and active(tag, side)
        for side in ("bash", "go")
    )


def snap(side, tag, kind):
    return set(lines(os.path.join(base, side, "%s.%s.txt" % (tag, kind))))


def l4_ok(side):
    """True only when the probe bound to the added email completed a request."""
    if rc(os.path.join(base, side, "L4-user.rc")) != 0:
        return False
    try:
        data = json.loads(text(os.path.join(
            base, side, "L4-user", "connectivity.json")) or "{}")
    except ValueError:
        return False
    return data.get("ok") is True


obs = {}
for side in ("bash", "go"):
    obs[side] = {
        "before": snap(side, "before", "client-ids"),
        "added": snap(side, "added", "client-ids"),
        "removed": snap(side, "removed", "client-ids"),
        "addedEmails": snap(side, "added", "emails"),
        "removedEmails": snap(side, "removed", "emails"),
        "beforeSids": snap(side, "before", "short-ids"),
        "addedSids": snap(side, "added", "short-ids"),
        "removedSids": snap(side, "removed", "short-ids"),
        "cleanedSids": snap(side, "cleaned", "short-ids"),
        "addRc": rc(os.path.join(base, side, "add.rc")),
        "showRc": rc(os.path.join(base, side, "11-show.rc" if side == "go" else "show.rc")),
        "removeRc": rc(os.path.join(base, side, "remove.rc")),
        "cleanupRc": rc(os.path.join(
            base, side, "12-short-id-clean.rc" if side == "go" else "remove.rc")),
    }
    obs[side]["newIds"] = obs[side]["added"] - obs[side]["before"]

go_show = []
try:
    go_show = json.loads(text(os.path.join(gdir, "11-show.out")) or "[]")
except json.JSONDecodeError:
    go_show = []
bash_show_text = text(os.path.join(bdir, "show.out")) + text(os.path.join(bdir, "users-show.log"))

details = {
    side: {
        "beforeClients": len(obs[side]["before"]),
        "addedClients": len(obs[side]["added"]),
        "removedClients": len(obs[side]["removed"]),
        "newIds": sorted(obs[side]["newIds"]),
        "beforeShortIds": len(obs[side]["beforeSids"]),
        "addedShortIds": len(obs[side]["addedSids"]),
        "removedShortIds": len(obs[side]["removedSids"]),
        "addRc": obs[side]["addRc"],
        "showRc": obs[side]["showRc"],
        "removeRc": obs[side]["removeRc"],
        "cleanupRc": obs[side]["cleanupRc"],
        # Residue before the documented cleanup step stays visible: Bash is
        # one-step, Go needs `xray config edit --short-id-remove`.
        "shortIdResidueAfterRemove": len(obs[side]["removedSids"]) - len(obs[side]["beforeSids"]),
        "cleanupCommand": ("xray config edit --short-id-remove" if side == "go"
                           else "none (user remove clears the sid on Bash)"),
        "cleanedShortIds": len(obs[side]["cleanedSids"]),
        "clientConnected": l4_ok(side),
    }
    for side in ("bash", "go")
}


def write(oid, verdict, reasons, bash_rc, go_rc, extra=None):
    out = os.path.join(p2, oid)
    os.makedirs(out, exist_ok=True)
    report = {
        "id": oid,
        "verdict": verdict,
        "reasons": reasons,
        "opsRc": {"bash": bash_rc, "go": go_rc},
        "details": details,
    }
    if extra:
        report.update(extra)
    with open(os.path.join(out, "ops.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")


# OPS-01: both sides must list the newly added user (email + its UUID).
reasons = []
if obs["bash"]["showRc"] != 0:
    reasons.append("bash show rc=%s" % obs["bash"]["showRc"])
if obs["go"]["showRc"] != 0:
    reasons.append("go list rc=%s" % obs["go"]["showRc"])
bash_new = sorted(obs["bash"]["newIds"])
go_new = sorted(obs["go"]["newIds"])
if len(bash_new) != 1:
    reasons.append("bash added %d new clients (want 1)" % len(bash_new))
elif email not in bash_show_text or bash_new[0] not in bash_show_text:
    reasons.append("bash show output lacks the added email/UUID")
if len(go_new) != 1:
    reasons.append("go added %d new clients (want 1)" % len(go_new))
elif not isinstance(go_show, list) or not any(
        isinstance(item, dict) and item.get("email") == email and item.get("uuid") == go_new[0]
        for item in go_show):
    reasons.append("go user list lacks the added email/UUID")
if not healthy("added"):
    reasons.append("xray -test/service not healthy after add")
for side in ("bash", "go"):
    if not l4_ok(side):
        reasons.append("%s added user did not complete a VLESS request" % side)
write("OPS-01", "PASS" if not reasons else "FAIL", reasons,
      obs["bash"]["showRc"], obs["go"]["showRc"])

# OPS-02: one new client + one new Reality shortId on both sides.
reasons = []
for side in ("bash", "go"):
    if obs[side]["addRc"] != 0:
        reasons.append("%s add rc=%s" % (side, obs[side]["addRc"]))
    if len(obs[side]["newIds"]) != 1:
        reasons.append("%s added %d clients (want 1)" % (side, len(obs[side]["newIds"])))
    if email not in obs[side]["addedEmails"]:
        reasons.append("%s config lacks the added email" % side)
    if len(obs[side]["addedSids"]) != len(obs[side]["beforeSids"]) + 1:
        reasons.append("%s shortId count %d -> %d (want +1)"
                       % (side, len(obs[side]["beforeSids"]), len(obs[side]["addedSids"])))
if not healthy("added"):
    reasons.append("xray -test/service not healthy after add")
for side in ("bash", "go"):
    if not l4_ok(side):
        reasons.append("%s added user did not complete a VLESS request" % side)
write("OPS-02", "PASS" if not reasons else "FAIL", reasons,
      obs["bash"]["addRc"], obs["go"]["addRc"])

# OPS-03: removal must restore the client set. Bash also removes the Reality
# shortId it generated; Go currently keeps it. Only when both sides fully
# converge do we claim a dual verdict; otherwise the row stays GO_ONLY and the
# observed difference is recorded instead of being papered over.
reasons = []
for side in ("bash", "go"):
    if obs[side]["removeRc"] != 0:
        reasons.append("%s remove rc=%s" % (side, obs[side]["removeRc"]))
    if obs[side]["removed"] != obs[side]["before"]:
        reasons.append("%s client set not restored after remove" % side)
    if email in obs[side]["removedEmails"]:
        reasons.append("%s removed config still lists the email" % side)
if not healthy("removed"):
    reasons.append("xray -test/service not healthy after remove")
if not healthy("cleaned"):
    reasons.append("xray -test/service not healthy after the shortId cleanup step")
shortid_clean = all(
    obs[side]["cleanupRc"] == 0
    and obs[side]["cleanedSids"] == obs[side]["beforeSids"]
    for side in ("bash", "go")
)
if not shortid_clean:
    reasons.append("shortId residue after cleanup: bash=%d go=%d (baseline %d/%d)"
                   % (len(obs["bash"]["cleanedSids"]), len(obs["go"]["cleanedSids"]),
                      len(obs["bash"]["beforeSids"]), len(obs["go"]["beforeSids"])))
if not reasons:
    write("OPS-03", "PASS", [], obs["bash"]["removeRc"], obs["go"]["removeRc"],
          extra={"shortIdDivergence": {
              "bash": "one step: user remove clears the sid",
              "go": "two steps: user remove keeps inbound-level sids, then xray config edit --short-id-remove",
              "goResidueAfterRemove": details["go"]["shortIdResidueAfterRemove"],
          }})
else:
    out = os.path.join(p2, "OPS-03")
    os.makedirs(out, exist_ok=True)
    record = {
        "id": "OPS-03",
        "result": "DIFF" if len(reasons) == 1 and "shortId residue" in reasons[0] else "FAIL",
        "reasons": reasons,
        "details": details,
        "remediation": "xray config edit --short-id-remove %s" % go_short_id,
        "note": "no ops.json: the row is not claimed as dual-side verified",
    }
    with open(os.path.join(out, "shortid-difference.json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
        fh.write("\n")

summary = {"shortIdClean": shortid_clean, "reasons": reasons}
with open(os.path.join(base, "users-summary.json"), "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2, sort_keys=True)
    fh.write("\n")
print("OPS-01/02 written; shortIdClean=%s" % shortid_clean)
PY
}

ops_users_job() {
    OPS_NET="e2e-$RUN_ID-users"
    local base="$EVID/OPS-USERS" bdir="$EVID/OPS-USERS/bash" gdir="$EVID/OPS-USERS/go"
    mkdir -p "$bdir" "$gdir"
    docker network create "$OPS_NET" >/dev/null 2>&1 || true
    log "[OPS-USERS] start"

    local bserver="e2e-$RUN_ID-users-bash"
    if start_server "$bserver" OPS-USERS bash "$bdir" "$OPS_NET"; then
        ops_bash_base "$bserver" "$bdir" M2
        ops_snapshot "$bserver" "$bdir" before
        ops_health "$bserver" "$bdir" before
        ops_bash_user_menu "$bserver" "$bdir" add
        ops_snapshot "$bserver" "$bdir" added
        ops_health "$bserver" "$bdir" added
        ops_l4_user "$bserver" "$bdir" "$OPS_NET"
        ops_bash_user_menu "$bserver" "$bdir" show
        ops_bash_user_menu "$bserver" "$bdir" remove
        ops_snapshot "$bserver" "$bdir" removed
        ops_health "$bserver" "$bdir" removed
        # Bash clears the sid as part of remove; snapshot again so both sides
        # are compared after their documented cleanup step, not before it.
        ops_snapshot "$bserver" "$bdir" cleaned
        ops_health "$bserver" "$bdir" cleaned
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$bdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$bserver" >/dev/null 2>&1 || true

    local gserver="e2e-$RUN_ID-users-go"
    if start_server "$gserver" OPS-USERS go "$gdir" "$OPS_NET"; then
        ops_go_base "$gserver" "$gdir" reality-nginx
        docker exec "$gserver" sh -c \
            'printf "#!/bin/sh\nexec systemctl restart xray\n" >/usr/local/bin/e2e-service-apply && chmod 0755 /usr/local/bin/e2e-service-apply'
        ops_snapshot "$gserver" "$gdir" before
        ops_health "$gserver" "$gdir" before
        ops_go_cli "$gserver" "$gdir" add xray user add --sandbox / \
            --email "$OPS_USER_EMAIL" --uuid "$OPS_USER_UUID" --short-id "$OPS_USER_SHORT_ID" \
            --validator /usr/local/bin/xray --service /usr/local/bin/e2e-service-apply \
            --container --json
        ops_snapshot "$gserver" "$gdir" added
        ops_health "$gserver" "$gdir" added
        ops_l4_user "$gserver" "$gdir" "$OPS_NET"
        ops_go_cli "$gserver" "$gdir" 11-show xray user list \
            --path /etc/idleleo/conf/xray/config.json --json
        ops_go_cli "$gserver" "$gdir" remove xray user remove --sandbox / \
            --email "$OPS_USER_EMAIL" --validator /usr/local/bin/xray \
            --service /usr/local/bin/e2e-service-apply --container --json
        ops_snapshot "$gserver" "$gdir" removed
        ops_health "$gserver" "$gdir" removed
        # Go keeps inbound-level shortIds on remove by design (it has no
        # email->sid map), so the documented second step removes the sid the
        # driver assigned to this user.
        ops_go_cli "$gserver" "$gdir" 12-short-id-clean --root / xray config edit \
            --short-id-remove "$OPS_USER_SHORT_ID" \
            --path /etc/idleleo/conf/xray/config.json \
            --container --yes --json
        ops_snapshot "$gserver" "$gdir" cleaned
        ops_health "$gserver" "$gdir" cleaned
    else
        echo '{"status":"harness-error","reason":"container start failed"}' >"$gdir/harness.json"
    fi
    [[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$gserver" >/dev/null 2>&1 || true
    docker network rm "$OPS_NET" >/dev/null 2>&1 || true

    log "[OPS-USERS] $(ops_users_verdict "$base")"
}


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
go_unban_rc = read_rc(os.path.join(go_dir, "05-unban.rc"))
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
if bash_unban_rc is None or go_unban_rc is None or go_unban is None:
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
    "opsRc": {"bash": bash_unban_rc, "go": go_unban_rc},
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
OPS21_BASH_CHECKS="baselineControl applyRcZero rulesAdded fallbackDirect noCatchAllBlocked serviceAliveAfterApply controlAfterApply adsBlocked privateBlocked countryBlocked offRcZero offRestored controlAfterOff"
OPS21_GO_CHECKS="$OPS21_BASH_CHECKS customListConfigured customRuleApplied customListKept customRuleRemoved editRcZero editUuidApplied editRoutingIdentical editOwnedRulesKept editUserRuleKept editBlockReported controlAfterEdit adsBlockedAfterEdit"

ops21_verdict() {
    local base=$1
    python3 - "$base" "$OPS21_BASH_CHECKS" "$OPS21_GO_CHECKS" <<'PY'
import json, os, sys

base, bash_required, go_required = sys.argv[1], sys.argv[2].split(), sys.argv[3].split()
sides = {"bash": os.path.join(base, "bash", "block-bash", "result.json"),
         "go": os.path.join(base, "go", "block-go", "result.json")}
required = {"bash": bash_required, "go": go_required}


def read_rc(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


steps = {}
results, harness, reasons = {}, [], []
for side, path in sides.items():
    block_dir = os.path.dirname(path)
    side_steps = {"apply": read_rc(os.path.join(block_dir, "apply.rc")),
                  "off": read_rc(os.path.join(block_dir, "off.rc"))}
    if side == "go":
        side_steps["edit"] = read_rc(os.path.join(block_dir, "edit.rc"))
    steps[side] = side_steps
    if side_steps["apply"] is None or side_steps["off"] is None:
        harness.append("%s: missing apply/off exit code; the action is unproven" % side)
    elif side_steps["apply"] != 0 or side_steps["off"] != 0:
        reasons.append("%s: action rc apply=%s off=%s" % (side, side_steps["apply"], side_steps["off"]))
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
    # Only checks this side is required to satisfy may fail the scenario; the
    # other side's diagnostics (e.g. Go-only customRuleApplied) are recorded but
    # must not be reported as a failure of the side that cannot implement them.
    failed = [name for name in required[side] if checks.get(name) is False]
    if failed:
        reasons.append("%s failed: %s" % (side, ", ".join(sorted(failed))))

if harness:
    verdict = "HARNESS-ERROR"
else:
    verdict = "BLOCKER" if reasons else "PASS"

def brief(side):
    checks = {c["name"]: c["ok"] for c in (results.get(side) or {}).get("checks", [])}
    side_harness = [r for r in harness if r.startswith(side + ":")]
    failed = [name for name in required[side] if checks.get(name) is False]
    if side_harness:
        status = "HARNESS-ERROR"
    else:
        status = "fail" if failed else "pass"
    return {"status": status,
            "reasons": side_harness,
            "failed": failed,
            "checks": checks}

report = {
    "id": "OPS-21",
    "verdict": verdict,
    "reasons": harness + reasons,
    "opsRc": {side: (steps.get(side) or {}).get("apply") for side in sides},
    "stepRc": steps,
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
    "opsRc": {"bash": b_add_rc, "go": g_add_rc},
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
# max_fails counters are per nginx worker, and the front runs worker_processes
# auto. A 60-request burst can hand each worker only one connect() failure, so
# no worker reaches max_fails=2 and passive removal is unobservable (seen in
# round3-final-20261122-99997da0). 480 requests keep the same one-second burst
# while giving every worker enough samples to trip the counter.
OPS32_BURST="${E2E_OPS32_BURST:-480}"
# The steady phase must outlive fail_timeout (10s) several times: a worker that
# marked the dead peer down re-admits it after the window, so a short 12s
# steady phase can end before any worker logs its second connect() failure.
# Six windows (120 x 0.5s = 60s) make the per-worker max_fails evidence
# observable without touching the product configuration.
OPS32_STEADY="${E2E_OPS32_STEADY:-120}"
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
# A side is verified only when every upstream recorded a zero action exit code;
# a missing code stays None so the ledger refuses to call the row complete.
summary_rc = {}
for side in ("bash", "go"):
    values = [((rep or {}).get("opsRc") or {}).get(side) for rep in upstreams.values()]
    summary_rc[side] = (0 if values and all(value == 0 for value in values)
                        else next((value for value in values if value not in (None, 0)), None))
report["opsRc"] = summary_rc


def side_detail(side):
    """Fold the measured removal/recovery facts of both upstreams per side."""
    removed, recovered = {}, {}
    for name in sorted(upstreams):
        rep = upstreams.get(name) or {}
        removed[name] = (rep.get("removedAt") or {}).get(side)
        stable = (rep.get("stableRecovery") or {}).get(side) or {}
        recovered[name] = stable.get("reached")
    return {
        "faultRemoved": all(value not in (None, "") for value in removed.values()),
        "recovered": all(value is True for value in recovered.values()),
        "removedAt": removed,
        "recoveredAt": {name: (((upstreams.get(name) or {}).get(
            "stableRecovery") or {}).get(side) or {}).get("at")
                        for name in sorted(upstreams)},
    }


report["details"] = {side: side_detail(side) for side in ("bash", "go")}
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
        OPS-01|OPS-02|OPS-03)
            if [[ ! -f "$EVID/.ops-users-done" ]]; then
                ops_users_job
                : >"$EVID/.ops-users-done"
            fi
            ;;
        OPS-09) ops_balance_job OPS-09 ws wsServers tls ;;
        OPS-31) ops_balance_job OPS-31 reality realityServers reality ;;
        OPS-32) ops32_job ;;
        OPS-04) ops_simple_job OPS-04 M2 reality-nginx ;;
        OPS-05) ops_simple_job OPS-05 M2 reality-nginx ;;
        OPS-06) ops_simple_job OPS-06 M2 reality-nginx ;;
        OPS-07) ops_simple_job OPS-07 M2 reality-nginx ;;
        OPS-10) ops_simple_job OPS-10 M2 reality-nginx ;;
        OPS-17c) ops_simple_job OPS-17c M1 reality ;;
        OPS-30) ops_simple_job OPS-30 M1 reality ;;
        OPS-08|OPS-11|OPS-15|OPS-20|OPS-22|OPS-28) ops_state_job "$1" ;;
        OPS-16) ops_cert_job ;;
        OPS-27) ops_certclear_job ;;
        OPS-OBSERVE) ops_observe_job ;;
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
for oid in OPS-19 OPS-21 OPS-09 OPS-31 OPS-32 \
           OPS-01 OPS-02 OPS-03 \
           OPS-04 OPS-05 OPS-06 OPS-07 OPS-10 OPS-17c OPS-30 \
           OPS-08 OPS-11 OPS-15 OPS-16 OPS-20 OPS-22 OPS-27 OPS-28 OPS-OBSERVE; do
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

# Remove capture-host addresses and home paths before the build manifest binds
# archived artifacts. Hashing before this rewrite made the manifest disagree
# with the exact evidence retained for audit.
python3 "$SUITE/collect/sanitize_evidence.py" "$EVID" || {
    log "FATAL: evidence sanitize failed"
    exit 2
}

# Stamp every recorded verdict with the provenance the acceptance ledger
# requires: frozen product commit, both shipped artefacts, the driver and the
# container image. Evidence without this block is reported as BLOCKED by
# build_ledger.py instead of being counted as a pass.
python3 - "$EVID" "$RUN_ID" "$ROOT" "$WORK/seed/idleleo" "$IMAGE_ID" "$IMAGE_PLATFORM" "$STARTED_AT" <<'PY'
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

evid, run_id, root, binary, image_id, platform, started = sys.argv[1:8]

def digest(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None

artifact_dir = os.path.join(evid, "build")
os.makedirs(artifact_dir, exist_ok=True)
artifact_paths = {
    "binary": os.path.join(artifact_dir, "idleleo"),
    "bashScript": os.path.join(artifact_dir, "install.sh"),
    "driver": os.path.join(artifact_dir, "run_p2_matrix.sh"),
}
for source, target in ((binary, artifact_paths["binary"]),
                       (os.path.join(root, "install.sh"), artifact_paths["bashScript"]),
                       (os.path.join(root, "tests/e2e-diff/run_p2_matrix.sh"), artifact_paths["driver"])):
    shutil.copyfile(source, target)
artifact_rels = {name: os.path.relpath(path, evid) for name, path in artifact_paths.items()}
dependency_sources = (
    "tests/e2e-diff/collect/l4.sh",
    "tests/e2e-diff/collect/client_config.py",
    "tests/e2e-diff/collect/build_ledger.py",
    "tests/e2e-diff/drivers/bash_ops.exp",
    "tests/go-parity/lib/docker_common.sh",
)
dependencies = []
for rel in dependency_sources:
    source = os.path.join(root, rel)
    target = os.path.join(artifact_dir, "dependencies", rel)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copyfile(source, target)
    dependencies.append({"source": rel, "path": os.path.relpath(target, evid), "sha256": digest(target)})
manifest = {
    "productCodeSha": subprocess.check_output(
        ["git", "-C", root, "rev-parse", "HEAD"], text=True).strip(),
    "binarySha256": digest(artifact_paths["binary"]),
    "bashScriptSha256": digest(artifact_paths["bashScript"]),
    "driverSha": digest(artifact_paths["driver"]),
    "image": image_id,
    "platform": platform,
    "artifacts": artifact_rels,
    "dependencies": dependencies,
}
manifest_path = os.path.join(evid, "build-manifest.json")
with open(manifest_path, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
run = {
    **{key: value for key, value in manifest.items() if key != "artifacts"},
    "runId": run_id,
    "layer": "L0-L4 docker matrix",
    # A red run stays red unless a later run names it here and states the fix
    # commit; build_ledger.py only promotes FAIL when both fields are present.
    "supersedes": os.environ.get("E2E_SUPERSEDES") or None,
    "fixedBy": os.environ.get("E2E_FIXED_BY") or None,
    "startedAt": started,
    "finishedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "manifestPath": "build-manifest.json",
    "manifestSha256": digest(manifest_path),
}
with open(os.path.join(evid, "run.json"), "w", encoding="utf-8") as fh:
    json.dump(run, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")

stamped = 0
for path in glob.glob(os.path.join(evid, "OPS-*", "*.json")):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        continue
    if not isinstance(data, dict) or isinstance(data.get("run"), dict):
        continue
    data["run"] = run
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    stamped += 1
print("stamped %d verdict file(s) with run provenance" % stamped)
PY

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

log "P2 finished: ${EVID#"$ROOT/"}"
