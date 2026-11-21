#!/usr/bin/env bash
# Cold-restore driver: one mode per container.
#
#   source  archives the managed state and proves a real client works
#   target  restores that archive on a freshly installed machine and proves the
#           service account, the Xray validator and a real client all work
#
# The archive lives in /handoff (a host temp directory), never in the evidence
# tree: it carries private keys. Evidence keeps only digests.
set -uo pipefail

MODE="${1:?source|target required}"
OUT="${E2E_OUT:?E2E_OUT required}"
GO=/usr/local/bin/idleleo
XRAY=/usr/local/bin/xray
CFG=/etc/idleleo/conf/xray/config.json
HANDOFF="${E2E_HANDOFF:-/handoff}"
ARCHIVE="$HANDOFF/state.tar.gz"
HTTP_PORT=18080
ORIGIN_IP=1.2.3.4
ORIGIN="http://$ORIGIN_IP:$HTTP_PORT"
DOMAIN="${E2E_DOMAIN:-www.cloudflare.com}"
ART="$OUT/artifacts"
mkdir -p "$OUT" "$ART"
: >"$OUT/assertions.txt"
: >"$OUT/driver.log"

export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY

log() { printf '%s\n' "$*" | tee -a "$OUT/driver.log"; }
run() {
    local id=$1; shift
    mkdir -p "$OUT/$id"
    "$@" >"$OUT/$id/stdout.txt" 2>"$OUT/$id/stderr.txt"
    local rc=$?
    printf '%s\n' "$rc" >"$OUT/$id/rc.txt"
    return $rc
}
assert() { # assert <ok:0|1> <label>
    if [ "$1" -eq 0 ]; then
        printf 'PASS\t%s\n' "$2" >>"$OUT/assertions.txt"
    else
        printf 'FAIL\t%s\n' "$2" >>"$OUT/assertions.txt"
    fi
}
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

# The freedom outbound blackholes private/loopback destinations, so the origin
# is bound to a public-looking alias on lo and the route stays local.
cat >/tmp/cold-http.py <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"cold-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
PY
python3 /tmp/cold-http.py "$HTTP_PORT" >/dev/null 2>&1 &
HTTP_PID=$!
if ! ip addr add "$ORIGIN_IP/32" dev lo 2>/dev/null && ! ip addr show dev lo | grep -q " $ORIGIN_IP/32"; then
    log "FATAL: cannot add the origin loopback alias"
    exit 2
fi

cleanup() {
    kill "$HTTP_PID" >/dev/null 2>&1
    [ -n "${CLIENT_PID:-}" ] && kill "$CLIENT_PID" >/dev/null 2>&1
    rm -f /tmp/cold-http.py /tmp/cold-client.json /tmp/cold-client.log
}
trap cleanup EXIT

client_probe() { # client_probe <step-id>
    local id=$1 rc
    mkdir -p "$OUT/$id"
    python3 /src/tests/e2e-diff/collect/client_config.py \
        --config "$CFG" --mode reality --transport reality \
        --server-address 127.0.0.1 --server-port 443 \
        --domain "$DOMAIN" --output /tmp/cold-client.json \
        >"$OUT/$id/client-config.log" 2>&1 || return 1
    "$XRAY" run -c /tmp/cold-client.json >/tmp/cold-client.log 2>&1 &
    CLIENT_PID=$!
    for _ in $(seq 1 120); do
        if (exec 3<>/dev/tcp/127.0.0.1/1080) 2>/dev/null; then break; fi
        sleep 0.1
    done
    local body=""
    for _ in $(seq 1 20); do
        body=$(curl -sS --max-time 10 --socks5-hostname 127.0.0.1:1080 "$ORIGIN/fast" 2>"$OUT/$id/curl.err")
        rc=$?
        [ "$rc" -eq 0 ] && [ "$body" = "cold-ok" ] && break
        sleep 1
    done
    printf '%s\n' "$body" >"$OUT/$id/body.txt"
    kill "$CLIENT_PID" >/dev/null 2>&1
    wait "$CLIENT_PID" 2>/dev/null
    CLIENT_PID=""
    [ "$rc" -eq 0 ] && [ "$body" = "cold-ok" ]
}

log "driver_start=$(date -u +%Y-%m-%dT%H:%M:%SZ) mode=$MODE root=/"

case "$MODE" in
source)
    run S1-doctor "$GO" doctor --json
    rc1=$?
    assert $([ "$rc1" -eq 0 ] && echo 0 || echo 1) "source install is healthy before the backup (rc=$rc1)"

    run S2-backup "$GO" backup create --out "$ARCHIVE" --include-geodata --container --json
    rc2=$?
    assert $([ "$rc2" -eq 0 ] && echo 0 || echo 1) "source backup create exits 0 (rc=$rc2)"
    assert $([ -f "$ARCHIVE" ] && echo 0 || echo 1) "source archive exists"
    assert $([ "$(stat -c '%a' "$ARCHIVE")" = "600" ] && echo 0 || echo 1) \
        "source archive is mode 0600 (mode=$(stat -c '%a' "$ARCHIVE" 2>/dev/null || echo missing))"

    run S3-verify "$GO" backup verify --archive "$ARCHIVE" --json
    rc3=$?
    assert $([ "$rc3" -eq 0 ] && echo 0 || echo 1) "source archive verifies (rc=$rc3)"

    sha "$CFG" >"$HANDOFF/config.sha256"
    sha "$ARCHIVE" >"$HANDOFF/archive.sha256"
    sha "$CFG" >"$OUT/config.sha256"
    sha "$ARCHIVE" >"$OUT/archive.sha256"

    if client_probe S4-real-client; then rc4=0; else rc4=1; fi
    assert $rc4 "a real client reaches the origin on the source machine"

    run S5-probe "$GO" doctor --deep --client-probe --probe-url "$ORIGIN/fast" \
        --probe-expect cold-ok --json
    rc5=$?
    assert $([ "$rc5" -eq 0 ] && echo 0 || echo 1) "source doctor --client-probe exits 0 (rc=$rc5)"
    assert $(jq -e '.evidenceLevel=="REAL_CLIENT_PASS"' "$OUT/S5-probe/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
        "source probe reports REAL_CLIENT_PASS"
    ;;

target)
    run T1-doctor-before "$GO" doctor --json
    rc1=$?
    assert $([ "$rc1" -eq 0 ] && echo 0 || echo 1) "target install is healthy before the restore (rc=$rc1)"
    before=$(sha "$CFG")
    want=$(cat "$HANDOFF/config.sha256" 2>/dev/null || true)
    assert $([ -n "$want" ] && [ "$before" != "$want" ] && echo 0 || echo 1) \
        "the fresh target starts with different managed state"

    run T2-verify "$GO" backup verify --archive "$ARCHIVE" --json
    rc2=$?
    assert $([ "$rc2" -eq 0 ] && echo 0 || echo 1) "target verifies the source archive (rc=$rc2)"
    assert $([ "$(sha "$ARCHIVE")" = "$(cat "$HANDOFF/archive.sha256")" ] && echo 0 || echo 1) \
        "the handoff archive digest matches the source"

    run T3-restore "$GO" backup restore --archive "$ARCHIVE" --container --json
    rc3=$?
    assert $([ "$rc3" -eq 0 ] && echo 0 || echo 1) "cold restore exits 0 (rc=$rc3)"
    after=$(sha "$CFG")
    assert $([ "$after" = "$want" ] && echo 0 || echo 1) \
        "restored config is byte-identical to the source"
    assert $(jq -e . "$CFG" >/dev/null 2>&1 && echo 0 || echo 1) "restored config is valid JSON"
    assert $([ -n "$(jq -r '.preBackup // ""' "$OUT/T3-restore/stdout.txt")" ] && echo 0 || echo 1) \
        "the restore wrote a pre-restore backup"

    mode=$(stat -c '%a' "$CFG")
    group=$(stat -c '%G' "$CFG")
    assert $([ "$mode" = "640" ] && echo 0 || echo 1) "restored config is mode 0640 (mode=$mode)"
    assert $([ "$group" = "xray" ] && echo 0 || echo 1) "restored config group is xray (group=$group)"
    if runuser -u xray -- test -r "$CFG" 2>/dev/null; then readable=0; else readable=1; fi
    assert $readable "the target xray service account can read the restored config"

    run T4-xray-test "$XRAY" run -test -config "$CFG"
    rc4=$?
    assert $([ "$rc4" -eq 0 ] && echo 0 || echo 1) "the restored config passes xray -test (rc=$rc4)"

    active=$(systemctl is-active xray 2>/dev/null || true)
    assert $([ "$active" = "active" ] && echo 0 || echo 1) "xray is active after the restore (state=$active)"

    run T5-doctor "$GO" doctor --json
    rc5=$?
    assert $([ "$rc5" -eq 0 ] && echo 0 || echo 1) "doctor is healthy after the cold restore (rc=$rc5)"

    if client_probe T6-real-client; then rc6=0; else rc6=1; fi
    assert $rc6 "a real client reaches the origin after the cold restore"

    run T7-probe "$GO" doctor --deep --client-probe --probe-url "$ORIGIN/fast" \
        --probe-expect cold-ok --json
    rc7=$?
    assert $([ "$rc7" -eq 0 ] && echo 0 || echo 1) "target doctor --client-probe exits 0 (rc=$rc7)"
    assert $(jq -e '.evidenceLevel=="REAL_CLIENT_PASS"' "$OUT/T7-probe/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
        "target probe reports REAL_CLIENT_PASS"

    # A second process restart proves the restored state does not depend on the
    # installer process that ran before the restore.
    systemctl restart xray
    sleep 1
    active2=$(systemctl is-active xray 2>/dev/null || true)
    assert $([ "$active2" = "active" ] && echo 0 || echo 1) "xray survives a restart after the restore (state=$active2)"
    if client_probe T8-real-client-after-restart; then rc8=0; else rc8=1; fi
    assert $rc8 "a real client still reaches the origin after the post-restore restart"
    ;;
*)
    log "FATAL: unknown mode $MODE"
    exit 2
    ;;
esac

# UUIDs and credentials never belong in committed evidence.
find "$OUT" -type f \( -name '*.txt' -o -name '*.log' -o -name '*.json' \) -print0 \
    | xargs -0 -r sed -i -E 's/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/<uuid>/g'

log "driver_done assertions=$(grep -c '^PASS' "$OUT/assertions.txt") pass / $(grep -c '^FAIL' "$OUT/assertions.txt") fail"
grep -q '^FAIL' "$OUT/assertions.txt" && exit 1
exit 0
