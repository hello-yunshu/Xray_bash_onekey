#!/usr/bin/env bash
# Real-root OPS rows that need a managed nginx tree and therefore cannot run in
# the systemd-only ops sweep:
#
#   OPS-17b  update nginx      nginx 1.27 -> the project's 1.30.6 build
#   OPS-08   SNI guard         real nginx main config + fragment inspection
#   OPS-27   cert clear        real root certificate ownership scan
#
# This is single-sided (Go) evidence: the Bash menu side is recorded by the
# differential matrix. Every assertion comes from a fresh container run.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-ops-realroot-$(date +%Y%m%d-%H%M)-$(git -C "$ROOT" rev-parse --short HEAD)}"
EVID="$SUITE/evidence/$RUN_ID/realroot"
WORK="/tmp/e2e-$RUN_ID"
IMAGE_TAG="${E2E_NGINX_IMAGE:-nginx:1.27}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
PASS=0
FAIL=0

mkdir -p "$EVID" "$WORK/seed"
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$EVID/run.log"; }
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
    "$GO_IMAGE" go build -buildvcs=false -trimpath -o /out/idleleo ./cmd/idleleo || {
    log "FATAL: build failed"; exit 2
}

# The managed nginx artifact is the real release build the Bash installer pins.
ART=""
EXPECTED_NGINX=""
case "$(uname -m)" in
    arm64|aarch64) ART="$HOME/.cache/xray-audit/nginx/2026.10.15.7679/xray-nginx-custom-arm.tar.gz" ;;
    *)             ART="$HOME/.cache/xray-audit/nginx/2026.10.15.7679/xray-nginx-custom-x86.tar.gz" ;;
esac
[[ -f "$ART" ]] || { log "FATAL: nginx artifact missing: $ART"; exit 2; }
cp "$ART" "$WORK/seed/nginx.tar.gz"
EXPECTED_NGINX=$(python3 - "$HOME/.cache/xray-audit/nginx/2026.10.15.7679/release-manifest.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
print(data["versions"]["nginx"])
PY
)
python3 - "$WORK/seed/nginx.tar.gz" "$EXPECTED_NGINX" "$WORK/seed/nginx-manifest.json" <<'PY'
import hashlib, json, os, sys
path, version, out = sys.argv[1:]
data = open(path, "rb").read()
json.dump({
    "schemaVersion": 1,
    "component": "nginx",
    "version": version,
    "sha256": hashlib.sha256(data).hexdigest(),
    "sizeBytes": len(data),
    "url": "/seed/nginx.tar.gz",
}, open(out, "w"), indent=2)
open(out, "a").write("\n")
PY
chmod 0755 "$WORK/seed/idleleo"
log "nginx_artifact=$(basename "$ART") version=$EXPECTED_NGINX sha256=$(shasum -a 256 "$ART" | awk '{print $1}')"

C="e2e-$RUN_ID-realroot"
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" -v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$EVID:/out" \
    "$IMAGE_TAG" sleep infinity >/dev/null || { log "FATAL: container start failed"; exit 2; }
docker exec "$C" install -m 0755 /seed/idleleo /usr/local/bin/idleleo
ENVS=(-e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY)

# --- OPS-17b: update nginx from the image's real 1.27 to the release 1.30.6 ---
docker exec "$C" sh -c 'rm -rf /usr/local/nginx /etc/idleleo && \
    mkdir -p /usr/local/nginx/sbin /usr/local/nginx/conf /usr/local/nginx/logs && \
    ln -s /usr/sbin/nginx /usr/local/nginx/sbin/nginx && \
    printf "worker_processes 1;\nevents { worker_connections 64; }\n" \
        >/usr/local/nginx/conf/nginx.conf'
PREV=$(docker exec "$C" /usr/local/nginx/sbin/nginx -v 2>&1 |
    sed -n 's/.*nginx\/\([0-9][0-9.]*\).*/\1/p' | head -1)
mkdir -p "$EVID/ops/OPS-17b"
docker exec "${ENVS[@]}" "$C" /usr/local/bin/idleleo update nginx \
    --manifest /seed/nginx-manifest.json --container --json \
    >"$EVID/ops/OPS-17b/out.txt" 2>"$EVID/ops/OPS-17b/err.txt"
rc=$?
echo "$rc" >"$EVID/ops/OPS-17b/rc"
echo "previous=$PREV expected=$EXPECTED_NGINX" >"$EVID/ops/OPS-17b/versions.txt"
assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "OPS-17b update nginx exits 0 (rc=$rc)"
assert "$(grep -q '"action": "update"' "$EVID/ops/OPS-17b/out.txt" && echo 0 || echo 1)" \
    "OPS-17b reports an update action"
assert "$(grep -q "\"previousVersion\": \"$PREV\"" "$EVID/ops/OPS-17b/out.txt" && echo 0 || echo 1)" \
    "OPS-17b reads the installed $PREV"
assert "$(grep -q "\"newVersion\": \"$EXPECTED_NGINX\"" "$EVID/ops/OPS-17b/out.txt" && echo 0 || echo 1)" \
    "OPS-17b installs the manifest $EXPECTED_NGINX"
assert "$(grep -q '"verified": true' "$EVID/ops/OPS-17b/out.txt" && echo 0 || echo 1)" \
    "OPS-17b verifies the artifact digest"
assert "$(grep -q '"health": true' "$EVID/ops/OPS-17b/out.txt" && echo 0 || echo 1)" \
    "OPS-17b passes the nginx -t health check"
now=$(docker exec "$C" /usr/local/nginx/sbin/nginx -v 2>&1 | sed -n 's/.*nginx\/\([0-9][0-9.]*\).*/\1/p' | head -1)
docker exec "$C" /usr/local/nginx/sbin/nginx -v >"$EVID/ops/OPS-17b/installed-version.txt" 2>&1
assert "$([ "$now" = "$EXPECTED_NGINX" ] && echo 0 || echo 1)" \
    "OPS-17b activated binary reports $now"
assert "$(docker exec "$C" sh -c 'ls -d /etc/idleleo/backup/nginx-* >/dev/null 2>&1 && echo 0 || echo 1')" \
    "OPS-17b kept a backup of the previous tree"

# --- OPS-08 / OPS-27: real-root drivers --------------------------------------
emit_cases() { # emit_cases <log> <ops-id> <label>
    local file=$1 oid=$2 label=$3 name status
    while IFS= read -r line; do
        case "$line" in
            "CASE "*" PASS ("*) name=$(printf '%s' "$line" | awk '{print $2}')
                assert 0 "$oid $label $name" ;;
            "CASE "*" FAIL ("*) name=$(printf '%s' "$line" | awk '{print $2}')
                assert 1 "$oid $label $name: $line" ;;
        esac
    done <"$file"
}

log "OPS-08 guard cases"
docker exec "$C" sh /src/tests/e2e-diff/drivers/guard_cases.sh >"$EVID/ops/OPS-08.log" 2>&1
guard_rc=$?
echo "$guard_rc" >"$EVID/ops/OPS-08.rc"
emit_cases "$EVID/ops/OPS-08.log" OPS-08 guard
assert "$([ "$guard_rc" -eq 0 ] && echo 0 || echo 1)" "OPS-08 guard driver exits 0 (rc=$guard_rc)"

log "OPS-27 cert clear cases"
docker exec "$C" sh /src/tests/e2e-diff/drivers/cert_clear_cases.sh >"$EVID/ops/OPS-27.log" 2>&1
clear_rc=$?
echo "$clear_rc" >"$EVID/ops/OPS-27.rc"
emit_cases "$EVID/ops/OPS-27.log" OPS-27 cert-clear
assert "$([ "$clear_rc" -eq 0 ] && echo 0 || echo 1)" "OPS-27 cert-clear driver exits 0 (rc=$clear_rc)"

log "run_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "$PASS PASS / $FAIL FAIL"
[[ "${E2E_KEEP:-0}" == "1" ]] || docker rm -f "$C" >/dev/null 2>&1
[ "$FAIL" -eq 0 ]
