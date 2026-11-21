#!/usr/bin/env bash
# P0-A evidence: relay listen binding survives to real Nginx, and a loopback
# bind is not reachable from another container. Builds the current tree, runs
# the product install path (managed Nginx + nginx -t), then probes the data
# plane from a peer container on the same bridge.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-$ROOT/artifacts/audit-remediation/p0a}
WORK=$(mktemp -d /tmp/p0a.XXXXXX)
NET="p0a-$RANDOM-$$"
NODE="p0a-node-$$"
ORIGIN="p0a-origin-$$"
IMAGE=${IMAGE:-idleleo-e2e:24.04}
GOIMAGE=${GOIMAGE:-golang:1.27.4}
ORIGIN_IMAGE=${ORIGIN_IMAGE:-nginx:1.27-alpine}
mkdir -p "$OUT"

cleanup() {
  docker rm -f "$NODE" "$ORIGIN" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

log "building idleleo from $ROOT"
docker run --rm -v "$ROOT:/src:ro" -v "$WORK:/out" -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache \
  "$GOIMAGE" bash -c 'export PATH=$PATH:/usr/local/go/bin; go build -trimpath -o /out/idleleo ./cmd/idleleo'
BIN_SHA=$(shasum -a 256 "$WORK/idleleo" | awk '{print $1}')

docker network create "$NET" >/dev/null
docker run -d --name "$ORIGIN" --network "$NET" --network-alias origin.example.com "$ORIGIN_IMAGE" >/dev/null
docker run -d --name "$NODE" --network "$NET" --hostname p0a-node \
  -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY "$IMAGE" sleep infinity >/dev/null
docker cp "$WORK/idleleo" "$NODE:/usr/local/bin/idleleo" >/dev/null

NODE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NODE")
RESULT="$OUT/results.jsonl"
: >"$RESULT"

run_node() { docker exec "$NODE" "$@"; }

install_relay() {
  local addr=$1 port=$2 logf=$3
  set +e
  run_node idleleo xray install --role relay --target origin.example.com:80 \
    --listen-port "$port" --listen "$addr" --container --no-service --json >"$logf" 2>&1
  local rc=$?
  set -e
  return $rc
}

nginx_test() {
  set +e
  run_node /usr/local/nginx/sbin/nginx -t -c /usr/local/nginx/conf/nginx.conf >"$OUT/nginx-$1.log" 2>&1
  local rc=$?
  set -e
  return $rc
}

start_or_reload() {
  if run_node pgrep -x nginx >/dev/null 2>&1; then
    run_node /usr/local/nginx/sbin/nginx -s reload >/dev/null 2>&1 || \
      run_node /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
  else
    run_node /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
  fi
  sleep 0.4
}

local_probe() { # addr:port
  set +e
  run_node curl -fsS -m 3 "http://$1/" 2>/dev/null | grep -q "Welcome to nginx"
  local rc=$?
  set -e
  return $rc
}

remote_probe() { # node-ip port
  set +e
  docker run --rm --network "$NET" "$IMAGE" curl -fsS -m 3 "http://$1:$2/" 2>/dev/null | grep -q "Welcome to nginx"
  local rc=$?
  set -e
  return $rc
}

record() { # addr port install_rc test_rc local_rc remote_rc verdict
  printf '{"address":"%s","port":%s,"install_rc":%s,"nginx_test_rc":%s,"local_rc":%s,"remote_rc":%s,"verdict":"%s"}\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" >>"$RESULT"
}

# --- loopback: product install must bind 127.0.0.1 and stay unreachable ----
log "case 127.0.0.1"
INSTALL_RC=0; install_relay 127.0.0.1 18443 "$OUT/install-127.log" || INSTALL_RC=$?
TEST_RC=0; nginx_test 127 || TEST_RC=$?
start_or_reload || true
LOCAL_RC=0; local_probe "127.0.0.1:18443" || LOCAL_RC=$?
REMOTE_RC=0; remote_probe "$NODE_IP" 18443 || REMOTE_RC=$?
VERDICT=FAIL
if [[ $INSTALL_RC -eq 0 && $TEST_RC -eq 0 && $LOCAL_RC -eq 0 && $REMOTE_RC -ne 0 ]]; then VERDICT=PASS; fi
record 127.0.0.1 18443 "$INSTALL_RC" "$TEST_RC" "$LOCAL_RC" "$REMOTE_RC" "$VERDICT"

# --- wildcard: reachable from a peer container ----------------------------
log "case 0.0.0.0"
INSTALL_RC=1; install_relay 0.0.0.0 18444 "$OUT/install-any.log" && INSTALL_RC=0
TEST_RC=1; nginx_test any && TEST_RC=0
start_or_reload || true
LOCAL_RC=0; local_probe "127.0.0.1:18444" || LOCAL_RC=$?
REMOTE_RC=0; remote_probe "$NODE_IP" 18444 || REMOTE_RC=$?
VERDICT=FAIL
if [[ $INSTALL_RC -eq 0 && $TEST_RC -eq 0 && $LOCAL_RC -eq 0 && $REMOTE_RC -eq 0 ]]; then VERDICT=PASS; fi
record 0.0.0.0 18444 "$INSTALL_RC" "$TEST_RC" "$LOCAL_RC" "$REMOTE_RC" "$VERDICT"

# --- IPv6 loopback: local only, no wildcard leak --------------------------
log "case ::1"
INSTALL_RC=1; install_relay ::1 18445 "$OUT/install-v6loop.log" && INSTALL_RC=0
TEST_RC=1; nginx_test v6loop && TEST_RC=0
start_or_reload || true
LOCAL_RC=0; local_probe "[::1]:18445" || LOCAL_RC=$?
REMOTE_RC=0; remote_probe "$NODE_IP" 18445 || REMOTE_RC=$?
LEAK=0
run_node ss -ltn 2>/dev/null | grep -q '0.0.0.0:18445' && LEAK=1 || true
VERDICT=FAIL
if [[ $INSTALL_RC -eq 0 && $TEST_RC -eq 0 && $LOCAL_RC -eq 0 && $REMOTE_RC -ne 0 && $LEAK -eq 0 ]]; then VERDICT=PASS; fi
record ::1 18445 "$INSTALL_RC" "$TEST_RC" "$LOCAL_RC" "$REMOTE_RC" "$VERDICT"

# --- IPv6 wildcard --------------------------------------------------------
log "case ::"
INSTALL_RC=1; install_relay :: 18446 "$OUT/install-v6any.log" && INSTALL_RC=0
TEST_RC=1; nginx_test v6any && TEST_RC=0
start_or_reload || true
LOCAL_RC=0; local_probe "[::1]:18446" || LOCAL_RC=$?
REMOTE_RC=0; remote_probe "$NODE_IP" 18446 || REMOTE_RC=$?
V6_WILDCARD=0
run_node ss -ltn 2>/dev/null | grep -Eq '\[::\]:18446|:::18446' && V6_WILDCARD=1 || true
# Docker's default bridge has no IPv6, so only the IPv6 wildcard itself and
# the local data plane are provable here; external IPv6 stays NOT_RUN.
VERDICT=FAIL
if [[ $INSTALL_RC -eq 0 && $TEST_RC -eq 0 && $LOCAL_RC -eq 0 && $V6_WILDCARD -eq 1 ]]; then VERDICT=PASS; fi
printf '{"check":"ipv6_wildcard_listener","listen_ss_hit":%s,"external_ipv6":"NOT_RUN"}\n' "$V6_WILDCARD" >>"$RESULT"
record :: 18446 "$INSTALL_RC" "$TEST_RC" "$LOCAL_RC" "$REMOTE_RC" "$VERDICT"

# --- invalid values: non-zero and no relay fragment written --------------
log "invalid addresses"
BEFORE=$(run_node sh -c 'cat /etc/idleleo/conf/nginx/relay-stream.conf 2>/dev/null | sha256sum' || true)
for bad in node.example "127.0.0.1]" "0.0.0.0:443"; do
  set +e
  run_node idleleo xray install --role relay --target origin.example.com:80 \
    --listen-port 18447 --listen "$bad" --container --no-service --json >"$OUT/invalid-$(echo "$bad" | tr -c 'a-z0-9' '_').log" 2>&1
  rc=$?
  set -e
  printf '{"address":"%s","install_rc":%s,"verdict":"%s"}\n' "$bad" "$rc" "$([[ $rc -ne 0 ]] && echo PASS || echo FAIL)" >>"$RESULT"
done
AFTER=$(run_node sh -c 'cat /etc/idleleo/conf/nginx/relay-stream.conf 2>/dev/null | sha256sum' || true)
if [[ "$BEFORE" == "$AFTER" ]]; then
  printf '{"check":"invalid_leaves_config_untouched","verdict":"PASS"}\n' >>"$RESULT"
else
  printf '{"check":"invalid_leaves_config_untouched","verdict":"FAIL"}\n' >>"$RESULT"
fi

python3 - "$RESULT" "$OUT/summary.json" "$BIN_SHA" "$IMAGE" "$NODE_IP" <<'PY'
import json, sys
src, dst, sha, image, ip = sys.argv[1:6]
rows = [json.loads(l) for l in open(src) if l.strip()]
ok = all(r.get("verdict") != "FAIL" for r in rows)
json.dump({"phase": "P0-A", "binarySha256": sha, "image": image, "nodeIp": ip,
           "allPass": ok, "results": rows}, open(dst, "w"), indent=2)
print("P0-A allPass=%s -> %s" % (ok, dst))
sys.exit(0 if ok else 1)
PY
