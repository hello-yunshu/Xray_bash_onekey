#!/usr/bin/env bash
# P0-C evidence: a real Bash layout copy is scanned without writes, prepare
# leaves the runtime config/entry/cron untouched, and recover discards a
# PREPARED transaction. Drift/third-party-entry/SIGKILL coverage is executed by
# the targeted Go tests invoked at the end.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-$ROOT/artifacts/audit-remediation/p0c}
WORK=$(mktemp -d /tmp/p0c.XXXXXX)
NODE="p0c-node-$$"
IMAGE=${IMAGE:-idleleo-e2e:24.04}
GOIMAGE=${GOIMAGE:-golang:1.27.4}
mkdir -p "$OUT" "$WORK/roots" "$WORK/bin"

cleanup() {
  docker rm -f "$NODE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

log "building idleleo + idleleo-recover"
docker run --rm -v "$ROOT:/src:ro" -v "$WORK/bin:/out" -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache \
  "$GOIMAGE" bash -c 'export PATH=$PATH:/usr/local/go/bin; go build -trimpath -o /out/idleleo ./cmd/idleleo && go build -trimpath -o /out/idleleo-recover ./cmd/idleleo-recover'
BIN_SHA=$(shasum -a 256 "$WORK/bin/idleleo" | awk '{print $1}')

setup_root() { # fixture
  local fx=$1 root="$WORK/roots/$1"
  mkdir -p "$root/etc/idleleo/conf/xray" "$root/etc/idleleo/conf/nginx" "$root/usr/bin"
  cp "$ROOT/tests/fixtures/legacy/$fx/install_config.json" "$root/etc/idleleo/conf/install_config.json"
  if [[ -f "$ROOT/tests/fixtures/legacy/$fx/relay-stream.conf" ]]; then
    cp "$ROOT/tests/fixtures/legacy/$fx/relay-stream.conf" "$root/etc/idleleo/conf/nginx/relay-stream.conf"
  elif [[ -f "$ROOT/tests/fixtures/legacy/$fx/xray-config.json" ]]; then
    cp "$ROOT/tests/fixtures/legacy/$fx/xray-config.json" "$root/etc/idleleo/conf/xray/config.json"
  fi
  printf '#!/bin/sh\necho legacy-bash-entry\n' >"$root/etc/idleleo/install.sh"
  chmod 0755 "$root/etc/idleleo/install.sh"
  ln -sfn ../../etc/idleleo/install.sh "$root/usr/bin/idleleo"
  # Explicit sandbox marker: prepare refuses writes anywhere else.
  printf 'I_ACCEPT_DISPOSABLE_SANDBOX\n' >"$root/.idleleo-phase01-sandbox"
}

tree_hash() { # root
  python3 - "$1" <<'PY'
import hashlib, os, sys
root = sys.argv[1]
h = hashlib.sha256()
for dirpath, dirnames, filenames in os.walk(root):
    dirnames.sort()
    for name in sorted(filenames):
        p = os.path.join(dirpath, name)
        rel = os.path.relpath(p, root)
        st = os.lstat(p)
        h.update(rel.encode() + b'\0' + oct(st.st_mode).encode() + b'\0')
        if os.path.islink(p):
            h.update(os.readlink(p).encode())
        else:
            with open(p, 'rb') as f:
                h.update(hashlib.sha256(f.read()).digest())
print(h.hexdigest())
PY
}


runtime_hash() { # root: only the resources migration must never rewrite
  python3 - "$1" <<'PY2'
import hashlib, os, sys
root = sys.argv[1]
rels = ["etc/idleleo/conf/xray/config.json", "etc/idleleo/conf/install_config.json",
        "etc/idleleo/conf/nginx/relay-stream.conf", "etc/idleleo/install.sh", "usr/bin/idleleo"]
h = hashlib.sha256()
for rel in rels:
    p = os.path.join(root, rel)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        continue
    h.update(rel.encode() + b'\0' + oct(st.st_mode).encode() + b'\0')
    if os.path.islink(p):
        h.update(os.readlink(p).encode())
    else:
        h.update(hashlib.sha256(open(p, 'rb').read()).digest())
print(h.hexdigest())
PY2
}

for fx in reality-direct reality-nginx tls-multi custom-dns-routing relay xtls-only; do
  setup_root "$fx"
done

docker run -d --name "$NODE" -v "$WORK:/work" "$IMAGE" sleep infinity >/dev/null
docker cp "$WORK/bin/idleleo" "$NODE:/usr/local/bin/idleleo" >/dev/null
docker cp "$WORK/bin/idleleo-recover" "$NODE:/usr/local/bin/idleleo-recover" >/dev/null
run_node() { docker exec "$NODE" "$@"; }

RESULT="$OUT/results.jsonl"
: >"$RESULT"
record() { printf '%s\n' "$1" >>"$RESULT"; }

# --- audit must be strictly read-only ------------------------------------
log "audit zero-write"
for fx in reality-direct reality-nginx tls-multi custom-dns-routing relay xtls-only; do
  before=$(tree_hash "$WORK/roots/$fx")
  set +e
  run_node idleleo --root "/work/roots/$fx" bridge audit --json >"$OUT/audit-$fx.json" 2>"$OUT/audit-$fx.err"
  rc=$?
  set -e
  after=$(tree_hash "$WORK/roots/$fx")
  verdict=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("verdict","?"))' "$OUT/audit-$fx.json" 2>/dev/null || echo parse-error)
  same=false; [[ "$before" == "$after" ]] && same=true
  record "{\"check\":\"audit_zero_write\",\"fixture\":\"$fx\",\"rc\":$rc,\"verdict\":\"$verdict\",\"tree_unchanged\":$same}"
done

# --- prepare must not touch runtime config / entry ------------------------
log "prepare leaves runtime untouched"
for fx in tls-multi reality-direct; do
  root="/work/roots/$fx"
  before=$(runtime_hash "$WORK/roots/$fx")
  set +e
  run_node idleleo --root "$root" bridge prepare --candidate /work/bin/idleleo \
    --recovery /work/bin/idleleo-recover --acknowledge-custom --json \
    >"$OUT/prepare-$fx.json" 2>"$OUT/prepare-$fx.err"
  rc=$?
  set -e
  after=$(runtime_hash "$WORK/roots/$fx")
  runtime_same=$( [[ "$before" == "$after" ]] && echo true || echo false )
  state=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("state","?"))' "$OUT/prepare-$fx.json" 2>/dev/null || echo parse-error)
  record "{\"check\":\"prepare_keeps_runtime\",\"fixture\":\"$fx\",\"rc\":$rc,\"state\":\"$state\",\"runtime_unchanged\":$runtime_same}"

  set +e
  run_node idleleo --root "$root" bridge recover --json >"$OUT/recover-$fx.json" 2>"$OUT/recover-$fx.err"
  rrc=$?
  set -e
  after2=$(runtime_hash "$WORK/roots/$fx")
  runtime2=$( [[ "$after2" == "$after" ]] && echo true || echo false )
  rstate=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("state","?"))' "$OUT/recover-$fx.json" 2>/dev/null || echo parse-error)
  record "{\"check\":\"recover_discards_prepared\",\"fixture\":\"$fx\",\"rc\":$rrc,\"state\":\"$rstate\",\"runtime_unchanged\":$runtime2}"
done

# --- drift / third-party entry / SIGKILL: authoritative Go tests ----------
log "targeted Go safety tests"
set +e
docker run --rm -v "$ROOT:/src:ro" -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache \
  "$GOIMAGE" bash -c 'export PATH=$PATH:/usr/local/go/bin; go test -count=1 -v ./internal/legacybridge ./internal/backup ./internal/repair' \
  >"$OUT/go-safety-tests.log" 2>&1
GO_RC=$?
set -e
record "{\"check\":\"go_safety_tests\",\"rc\":$GO_RC,\"log\":\"p0c/go-safety-tests.log\"}"

python3 - "$RESULT" "$OUT/summary.json" "$BIN_SHA" "$IMAGE" <<'PY'
import json, sys
src, dst, sha, image = sys.argv[1:5]
rows = [json.loads(l) for l in open(src) if l.strip()]
ok = all(r.get("rc") == 0 and r.get("tree_unchanged", True) and r.get("runtime_unchanged", True)
         and r.get("runtime_same", True) for r in rows)
json.dump({"phase": "P0-C", "binarySha256": sha, "image": image,
           "allPass": ok, "results": rows}, open(dst, "w"), indent=2)
print("P0-C allPass=%s -> %s" % (ok, dst))
sys.exit(0 if ok else 1)
PY
