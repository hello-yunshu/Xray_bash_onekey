#!/usr/bin/env bash
# P3 real-machine driver: loopback API, experimental hot add/remove, real
# clients, crash-free restart, concurrency, the repair permission regression
# and the operator summary.
#
# Every step records rc/stdout/stderr under $E2E_OUT/<step>/ plus one line in
# assertions.txt. A failed assertion is evidence, not a reason to abort the
# remaining independent steps.
set -uo pipefail

OUT="${E2E_OUT:?E2E_OUT required}"
GO=/usr/local/bin/idleleo
XRAY=/usr/local/bin/xray
CFG=/etc/idleleo/conf/xray/config.json
API=127.0.0.1:10085
HOOK=/usr/local/bin/p3-service-apply
HTTP_PORT=18080
# Freedom blackholes loopback and private destinations, so the origin lives on
# a public-looking alias bound to lo: the route stays local, the address does
# not look private.
ORIGIN_IP=1.2.3.4
ORIGIN="http://$ORIGIN_IP:$HTTP_PORT"
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
new_uuid() { python3 -c 'import uuid;print(uuid.uuid4())'; }
config_has_email() { jq -e --arg e "$1" '[.inbounds[].settings.clients[]? | select(.email==$e)] | length > 0' "$CFG" >/dev/null 2>&1; }
runtime_id() { # runtime_id <email>
    $XRAY api inbounduser --server="$API" --tag="$TAG" --email="$1" 2>/dev/null \
        | jq -r '[.users[]? | (.account.id // .id // empty)] | first // ""'
}
runtime_has() { [ "$(runtime_id "$1")" = "$2" ]; }
share_uri() { # share_uri <email>  (never written to evidence)
    $GO xray share --path "$CFG" --user "$1" --json 2>/dev/null | jq -r '.shareUri // ""'
}
client_readiness() { # client_readiness <socks-port>
    for _ in $(seq 1 120); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    return 1
}
client_up() { # client_up <tag> <email> <socks-port>
    local uri
    uri=$(share_uri "$2")
    if [ -z "$uri" ]; then return 1; fi
    python3 /tmp/p3-client.py "$uri" 127.0.0.1 "$MAIN_PORT" "$3" "/tmp/p3-client-$1.json" || return 1
    $XRAY run -c "/tmp/p3-client-$1.json" >"/tmp/p3-client-$1.log" 2>&1 &
    CLIENT_PID=$!
    client_readiness "$3"
}
client_up_file() { # client_up_file <name> <config-file> <socks-port>
    $XRAY run -c "$2" >"/tmp/p3-client-$1.log" 2>&1 &
    CLIENT_PID=$!
    client_readiness "$3"
}
client_down() {
    if [ -n "${CLIENT_PID:-}" ]; then
        kill "$CLIENT_PID" >/dev/null 2>&1
        wait "$CLIENT_PID" 2>/dev/null
        CLIENT_PID=""
    fi
}
tunnel_get() { # tunnel_get <socks-port> <path>
    curl -sS --max-time 12 --socks5-hostname "127.0.0.1:$1" "$ORIGIN/$2"
}

log "driver_start=$(date -u +%Y-%m-%dT%H:%M:%SZ) root=/"

# --- local origin and a restart hook --------------------------------------
cat >/tmp/p3-http.py <<'PY'
import sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = "/tmp/p3-http.log"
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/slow"):
            with open(LOG, "a") as f:
                f.write("slow-start\n")
            time.sleep(6)
            body = b"hot-ok-slow\n"
        else:
            body = b"hot-ok-fast\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
PY
python3 /tmp/p3-http.py "$HTTP_PORT" >/dev/null 2>&1 &
HTTP_PID=$!
if ! ip addr add "$ORIGIN_IP/32" dev lo 2>/dev/null && ! ip addr show dev lo | grep -q " $ORIGIN_IP/32"; then
    log "FATAL: cannot add the origin loopback alias"
    exit 2
fi

cat >/tmp/p3-client.py <<'PY'
import json, sys, urllib.parse

uri, host, port, socks, out = sys.argv[1:6]
u = urllib.parse.urlsplit(uri)
q = dict(urllib.parse.parse_qsl(u.query))
net = q.get("type") or "tcp"
if net == "tcp":
    net = "raw"
reality = {"serverName": q["sni"], "fingerprint": q.get("fp") or "chrome",
           "publicKey": q["pbk"], "shortId": q.get("sid", "")}
if q.get("spx"):
    reality["spiderX"] = q["spx"]
stream = {"network": net, "security": "reality", "realitySettings": reality}
if net == "ws":
    stream["wsSettings"] = {"path": q.get("path") or "/"}
if net == "grpc":
    stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
user = {"id": u.username, "encryption": "none"}
if q.get("flow"):
    user["flow"] = q["flow"]
cfg = {"log": {"loglevel": "warning"},
       "inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": int(socks),
                     "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
       "outbounds": [{"tag": "proxy", "protocol": "vless",
                      "settings": {"vnext": [{"address": host, "port": int(port), "users": [user]}]},
                      "streamSettings": stream}]}
open(out, "w").write(json.dumps(cfg, indent=2))
PY

cat >"$HOOK" <<'SH'
#!/bin/sh
exec systemctl restart xray
SH
chmod 0755 "$HOOK"

MAIN_PORT=$(jq -r '[.inbounds[] | select(.protocol=="vless")][0].port' "$CFG")
TAG=$(jq -r '[.inbounds[] | select(.protocol=="vless")][0].tag' "$CFG")
A_EMAIL=hot-a@test.local
A_UUID=$(new_uuid)
B_EMAIL=hot-b@test.local
B_UUID=$(new_uuid)
C_EMAIL=hot-c@test.local
C_UUID=$(new_uuid)
D_EMAIL=hot-d@test.local
D_UUID=$(new_uuid)
log "main_port=$MAIN_PORT tag=$TAG"

# --- E1 the API is off on a fresh install ---------------------------------
run E1-api-status "$GO" xray api status --json
rc1=$?
assert $([ "$rc1" -eq 0 ] && echo 0 || echo 1) "api status exits 0 before enablement (rc=$rc1)"
assert $(jq -e '.configured == false' "$OUT/E1-api-status/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "api status reports configured=false"

# --- E2 hot add without an API persists, does not apply, exits 8 -----------
run E2-hot-noapi "$GO" xray user add --sandbox / --email "$B_EMAIL" --uuid "$B_UUID" \
    --validator "$XRAY" --experimental-hot --container --json
rc2=$?
assert $([ "$rc2" -eq 8 ] && echo 0 || echo 1) "hot add without an API exits 8 (rc=$rc2)"
assert $(jq -e '.hot.persisted == true and .hot.applied == false' "$OUT/E2-hot-noapi/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "report says persisted but not applied"
assert $(config_has_email "$B_EMAIL" && echo 0 || echo 1) "the committed config already carries the new user"

# --- E2b crash recovery: SIGKILL between persist and apply -----------------
# E2 left exactly the state a crash would leave: the user is on disk but not in
# the running process. The credential must fail now and work after a restart.
if client_up b_crash "$B_EMAIL" 21083; then upb_crash=0; else upb_crash=1; fi
assert $upb_crash "a client for the persisted-but-unapplied user starts"
crash_before=$(tunnel_get 21083 fast 2>/dev/null)
assert $([ "$crash_before" != "hot-ok-fast" ] && echo 0 || echo 1) \
    "the unapplied user is rejected by the running process"
client_down
pkill -9 -x xray >/dev/null 2>&1
for _ in $(seq 1 100); do systemctl is-active --quiet xray || break; sleep 0.1; done
systemctl reset-failed xray >/dev/null 2>&1 || true
systemctl start xray >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(systemctl is-active xray)" = "active" ] && break; sleep 0.1; done
assert $([ "$(systemctl is-active xray)" = "active" ] && echo 0 || echo 1) "xray restarts after the crash"
if client_up b_after_crash "$B_EMAIL" 21084; then upb_after=0; else upb_after=1; fi
assert $upb_after "a client for the recovered user starts"
assert $([ "$(tunnel_get 21084 fast)" = "hot-ok-fast" ] && echo 0 || echo 1) \
    "the user persisted before the crash works after the restart"
client_down

# --- E3 enable the loopback API through the normal transaction ------------
run E3-api-enable "$GO" xray api enable --sandbox / --validator "$XRAY" --service "$HOOK" --container --json
rc3=$?
assert $([ "$rc3" -eq 0 ] && echo 0 || echo 1) "api enable exits 0 (rc=$rc3)"
assert $(jq -e '.changed == true and .reachable == true' "$OUT/E3-api-enable/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "api enable reports changed and reachable"
assert $(jq -e '[.inbounds[] | select(.tag=="api")] | length == 1' "$CFG" >/dev/null 2>&1 && echo 0 || echo 1) \
    "config has exactly one api inbound"
assert $([ "$(systemctl is-active xray)" = "active" ] && echo 0 || echo 1) "xray is active after the api change"
run E3-api-lsi "$XRAY" api lsi --server="$API"
assert $([ "$(cat "$OUT/E3-api-lsi/rc.txt")" -eq 0 ] && echo 0 || echo 1) "xray api lsi answers on the loopback API"

# --- E4 retry converges without rewriting the config ----------------------
before4=$(sha "$CFG")
run E4-hot-retry "$GO" xray user add --sandbox / --email "$B_EMAIL" --uuid "$B_UUID" \
    --validator "$XRAY" --experimental-hot --container --json
rc4=$?
assert $([ "$rc4" -eq 0 ] && echo 0 || echo 1) "hot retry exits 0 (rc=$rc4)"
assert $(jq -e '.hot.persisted == false and .hot.applied == true' "$OUT/E4-hot-retry/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "retry skipped the write and applied to the running inbound"
assert $([ "$(sha "$CFG")" = "$before4" ] && echo 0 || echo 1) "retry did not rewrite the config"
assert $(runtime_has "$B_EMAIL" "$B_UUID" && echo 0 || echo 1) "the running inbound now has user B"

# --- E5 a real client for B reaches the local origin ----------------------
if client_up b "$B_EMAIL" 21080; then upb=0; else upb=1; fi
assert $upb "real client for B starts"
body5=$(tunnel_get 21080 fast)
assert $([ "$body5" = "hot-ok-fast" ] && echo 0 || echo 1) "client B reaches the origin through VLESS+Reality"
client_down

# --- E6 hot add A ---------------------------------------------------------
run E6-hot-add-a "$GO" xray user add --sandbox / --email "$A_EMAIL" --uuid "$A_UUID" \
    --validator "$XRAY" --experimental-hot --container --json
rc6=$?
assert $([ "$rc6" -eq 0 ] && echo 0 || echo 1) "hot add A exits 0 (rc=$rc6)"
assert $(jq -e '.hot.persisted == true and .hot.applied == true' "$OUT/E6-hot-add-a/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "A was persisted and applied"
assert $(runtime_has "$A_EMAIL" "$A_UUID" && echo 0 || echo 1) "the running inbound has A"

# --- E7 A works; hold one connection open across the removal --------------
if client_up a "$A_EMAIL" 21081; then upa=0; else upa=1; fi
assert $upa "real client for A starts"
# Keep A's client config: once the user is gone the config no longer yields a
# share link, and the stale credential is exactly what has to be rejected. Give
# the copy its own loopback SOCKS port so it can run alongside the live clients.
jq '.inbounds[0].port = 21082' /tmp/p3-client-a.json >/tmp/p3-a2-removed.json
assert $([ "$(tunnel_get 21081 fast)" = "hot-ok-fast" ] && echo 0 || echo 1) "client A reaches the origin"
: >/tmp/p3-http.log
tunnel_get 21081 slow >/tmp/p3-slow.body 2>/tmp/p3-slow.err &
SLOW_PID=$!
for _ in $(seq 1 100); do grep -q slow-start /tmp/p3-http.log 2>/dev/null && break; sleep 0.05; done
assert $(grep -q slow-start /tmp/p3-http.log && echo 0 || echo 1) "a slow request from A is in flight"

# --- E8 hot remove A: new connections fail, the open one survives ---------
run E8-hot-remove-a "$GO" xray user remove --sandbox / --email "$A_EMAIL" \
    --validator "$XRAY" --experimental-hot --container --json
rc8=$?
assert $([ "$rc8" -eq 0 ] && echo 0 || echo 1) "hot remove A exits 0 (rc=$rc8)"
assert $(jq -e '.hot.persisted == true and .hot.applied == true' "$OUT/E8-hot-remove-a/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "A was removed from config and runtime"
assert $(config_has_email "$A_EMAIL" && echo 1 || echo 0) "the committed config no longer has A"
assert $([ -z "$(runtime_id "$A_EMAIL")" ] && echo 0 || echo 1) \
    "the running inbound no longer has A"
wait "$SLOW_PID"
slow_rc=$?
assert $([ "$slow_rc" -eq 0 ] && [ "$(cat /tmp/p3-slow.body)" = "hot-ok-slow" ] && echo 0 || echo 1) \
    "the connection opened before removal still completed"
client_down
if client_up b_keep "$B_EMAIL" 21085; then upbk=0; else upbk=1; fi
assert $upbk "a real client for B starts after A was removed"
assert $([ "$(tunnel_get 21085 fast)" = "hot-ok-fast" ] && echo 0 || echo 1) "B still works after A was removed"
client_down
if client_up_file a2 /tmp/p3-a2-removed.json 21082; then upa2=0; else upa2=1; fi
assert $upa2 "a client with the removed credential still starts locally"
tunnel_get 21082 fast >/tmp/p3-a2.body 2>/tmp/p3-a2.err
a2_rc=$?
assert $([ "$a2_rc" -ne 0 ] && echo 0 || echo 1) "a new connection with A's credential is rejected (rc=$a2_rc)"
client_down

# --- E9 restart keeps B and keeps A removed ------------------------------
before9=$(sha "$CFG")
systemctl restart xray
sleep 1
assert $([ "$(systemctl is-active xray)" = "active" ] && echo 0 || echo 1) "xray restarts with the committed config"
assert $([ "$(sha "$CFG")" = "$before9" ] && echo 0 || echo 1) "restart did not rewrite the config"
assert $(runtime_has "$B_EMAIL" "$B_UUID" && echo 0 || echo 1) "B survives the restart"
assert $([ -z "$(runtime_id "$A_EMAIL")" ] && echo 0 || echo 1) "A stays removed after the restart"
if client_up b2 "$B_EMAIL" 21083; then upb2=0; else upb2=1; fi
assert $upb2 "a real client for B starts after the restart"
assert $([ "$(tunnel_get 21083 fast)" = "hot-ok-fast" ] && echo 0 || echo 1) "B still reaches the origin after the restart"
client_down

# --- E10 concurrent hot adds serialize instead of interleaving -----------
mkdir -p "$OUT/E10-concurrent-c" "$OUT/E10-concurrent-d"
( $GO xray user add --sandbox / --email "$C_EMAIL" --uuid "$C_UUID" --validator "$XRAY" \
      --experimental-hot --container --json >"$OUT/E10-concurrent-c/stdout.txt" 2>"$OUT/E10-concurrent-c/stderr.txt";
  echo $? >"$OUT/E10-concurrent-c/rc.txt" ) &
P1=$!
( $GO xray user add --sandbox / --email "$D_EMAIL" --uuid "$D_UUID" --validator "$XRAY" \
      --experimental-hot --container --json >"$OUT/E10-concurrent-d/stdout.txt" 2>"$OUT/E10-concurrent-d/stderr.txt";
  echo $? >"$OUT/E10-concurrent-d/rc.txt" ) &
P2=$!
wait "$P1"; wait "$P2"
assert $([ "$(cat "$OUT/E10-concurrent-c/rc.txt")" -eq 0 ] && [ "$(cat "$OUT/E10-concurrent-d/rc.txt")" -eq 0 ] && echo 0 || echo 1) \
    "both concurrent hot adds exit 0"
assert $(config_has_email "$C_EMAIL" && config_has_email "$D_EMAIL" && echo 0 || echo 1) "both users are in the committed config"
assert $(runtime_has "$C_EMAIL" "$C_UUID" && runtime_has "$D_EMAIL" "$D_UUID" && echo 0 || echo 1) \
    "both users are in the running inbound"

# --- E11 the repair permission regression is caught and fixed ------------
chown root:root "$CFG" /etc/idleleo/conf
chmod 0600 "$CFG"
chmod 0750 /etc/idleleo/conf
run E11-doctor-perm "$GO" doctor --json
rc11=$?
assert $([ "$rc11" -ne 0 ] && echo 0 || echo 1) "doctor fails when the service account cannot read the config (rc=$rc11)"
assert $(jq -e '.checks[] | select(.id=="service-access") | .status=="fail"' "$OUT/E11-doctor-perm/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "the service-access check names the unreadable config"
run E11-repair "$GO" repair --container --json
rc11b=$?
assert $([ "$rc11b" -eq 0 ] && echo 0 || echo 1) "repair exits healthy (rc=$rc11b)"
assert $([ "$(stat -c '%a' "$CFG")" = "640" ] && echo 0 || echo 1) "repair restores the config to 0640"
assert $([ "$(stat -c '%G' "$CFG")" = "xray" ] && echo 0 || echo 1) "repair aligns the config group with xray"
assert $([ "$(stat -c '%G' /etc/idleleo/conf)" = "xray" ] && echo 0 || echo 1) "repair aligns the conf directory group with xray"
systemctl restart xray
sleep 1
assert $([ "$(systemctl is-active xray)" = "active" ] && echo 0 || echo 1) "xray restarts after the repair"
if client_up b3 "$B_EMAIL" 21084; then upb3=0; else upb3=1; fi
assert $upb3 "a real client for B starts after the repaired restart"
assert $([ "$(tunnel_get 21084 fast)" = "hot-ok-fast" ] && echo 0 || echo 1) "B reaches the origin after the repaired restart"
client_down

# --- E12 read-only operator summary --------------------------------------
run E12-ops "$GO" ops summary --json
rc12=$?
assert $([ "$rc12" -eq 0 ] && echo 0 || echo 1) "ops summary exits 0 (rc=$rc12)"
assert $(jq -e --argjson p "$MAIN_PORT" '[.ports[] | select(.port==$p)] | length == 1' "$OUT/E12-ops/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "the summary lists the main inbound port"
assert $(jq -e '[.ports[] | select(.port==10085)] | length == 1' "$OUT/E12-ops/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "the summary lists the loopback API port"
assert $(jq -e '.lastChange != null and .restartCount >= 0' "$OUT/E12-ops/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "the summary carries the last change and a restart count"
run E12-ops-text "$GO" ops summary
assert $([ "$(cat "$OUT/E12-ops-text/rc.txt")" -eq 0 ] && echo 0 || echo 1) "ops summary renders as text"

# --- E13b doctor --client-probe proves a real user session ----------------
# This is the strongest evidence the manager can produce without a remote
# client: the installed xray binary is started as a client, the managed
# Reality listener is dialled and the origin body is checked.
run E13b-doctor-probe "$GO" doctor --deep --client-probe --probe-url "$ORIGIN/fast" \
    --probe-expect hot-ok-fast --json
rc13b=$?
assert $([ "$rc13b" -eq 0 ] && echo 0 || echo 1) "doctor --client-probe exits 0 (rc=$rc13b)"
assert $(jq -e '.evidenceLevel=="REAL_CLIENT_PASS" and
    (.checks[] | select(.id=="client-probe") | .status=="ok" and .evidence=="REAL_CLIENT_PASS")' \
    "$OUT/E13b-doctor-probe/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "the real-client probe reports REAL_CLIENT_PASS"

# --- E13 final health ----------------------------------------------------
run E13-doctor-final "$GO" doctor --json
rc13=$?
assert $([ "$rc13" -eq 0 ] && echo 0 || echo 1) "doctor is healthy after the hot and repair scenarios (rc=$rc13)"

kill "$HTTP_PID" >/dev/null 2>&1
rm -f /tmp/p3-http.py /tmp/p3-client.py /tmp/p3-client-*.json /tmp/p3-client-*.log \
    /tmp/p3-http.log /tmp/p3-slow.body /tmp/p3-slow.err /tmp/p3-a2.body /tmp/p3-a2.err \
    /tmp/p3-a2-removed.json

# UUIDs and credentials never belong in committed evidence.
find "$OUT" -type f \( -name '*.txt' -o -name '*.log' -o -name '*.json' \) -print0 \
    | xargs -0 -r sed -i -E 's/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/<uuid>/g'

log "driver_done assertions=$(grep -c '^PASS' "$OUT/assertions.txt") pass / $(grep -c '^FAIL' "$OUT/assertions.txt") fail"
grep -q '^FAIL' "$OUT/assertions.txt" && exit 1
exit 0
