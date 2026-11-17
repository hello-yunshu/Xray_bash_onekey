#!/usr/bin/env bash
# E7/E8: Reality credential edits, proved with a real Xray client.
#
# Usage:
#   bash go_edit_reality.sh E7 idleleo xray config edit --short-id-auto --container --json
#   bash go_edit_reality.sh E8 idleleo xray config edit --rotate-reality-private-key \
#        --confirm-reality-rotation rotate-reality-key --container --json
#
# E7 walks the documented zero-downtime path: append a new shortId, switch the
# client, then remove the old one, checking the old link keeps working while it
# is still accepted.
# E8 rotates the private key twice: the first rotation must succeed; the second
# runs with a systemd drop-in that keeps the pre-rotation config live, so the
# restart succeeds but the new credential never takes effect. That forces the
# real handshake to fail, which must roll back and re-probe the old link.
set -uo pipefail

SCENARIO="${E2E_SCENARIO:?E2E_SCENARIO required}"
OUT="${E2E_OUT:?E2E_OUT required}"
DIR="$OUT/edit"
CFG=/etc/idleleo/conf/xray/config.json
PROBE=/tmp/e2e-reality-probe.py
LOG="$DIR/edit.log"
IDLELEO="${IDLELEO_BIN:-idleleo}"
mkdir -p "$DIR"
: >"$DIR/checks.jsonl"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >>"$LOG"; }
export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY

sha_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

json_get() {
    python3 - "$1" "$2" <<'PY'
import json, sys
cur = json.load(open(sys.argv[1]))
for part in sys.argv[2].split('.'):
    cur = cur.get(part) if isinstance(cur, dict) else None
print("" if cur is None else (cur if isinstance(cur, str) else json.dumps(cur)))
PY
}

uri_field() {
    python3 - "$1" "$2" <<'PY'
import sys
from urllib.parse import urlparse, parse_qs
q = parse_qs(urlparse(sys.argv[1]).query)
print((q.get(sys.argv[2]) or [""])[0])
PY
}

check() { # name ok detail
    python3 - "$DIR/checks.jsonl" "$1" "$2" "${3:-}" <<'PY'
import json, sys
with open(sys.argv[1], "a") as fh:
    fh.write(json.dumps({"name": sys.argv[2], "ok": sys.argv[3] == "true", "detail": sys.argv[4]}) + "\n")
PY
}

finalize() {
    python3 - "$DIR/checks.jsonl" "$DIR/checks.json" "$SCENARIO" <<'PY'
import json, os, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
checks = {c["name"]: c["ok"] for c in rows}
meta_path = os.path.join(os.path.dirname(sys.argv[2]), "meta.json")
meta = json.load(open(meta_path)) if os.path.exists(meta_path) else {}
out = {"scenario": sys.argv[3], "checks": checks, "wanted": list(checks),
       "allPassed": all(checks.values()) if checks else False,
       "count": len(checks), "details": rows,
       "editRc": meta.get("editRc", 0), "beforeSha": meta.get("beforeSha", ""),
       "afterSha": meta.get("afterSha", "")}
json.dump(out, open(sys.argv[2], "w"), indent=2, sort_keys=True)
print("allPassed=%s checks=%d" % (out["allPassed"], out["count"]))
PY
}

share_uri() {
    "$IDLELEO" xray share --path "$CFG" --public-port 443 --json 2>/dev/null |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["shareUri"])'
}

# The probe mirrors the Go edit probe: a TLS handshake inside the tunnel plus
# an authenticated HTTP request to a destination the fallback never dials.
cat >"$PROBE" <<'PY'
import json, os, socket, ssl, subprocess, sys, tempfile, time
from urllib.parse import urlparse, parse_qs

uri, server_addr, server_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
u = urlparse(uri)
q = parse_qs(u.query)
get = lambda k, d="": (q.get(k) or [d])[0]
reality = {
    "serverName": get("sni"),
    "fingerprint": get("fp") or "chrome",
    "publicKey": get("pbk"),
    "shortId": get("sid"),
}
if get("spx"):
    reality["spiderX"] = get("spx")
network = get("type") or "raw"
stream = {"network": network, "security": "reality", "realitySettings": reality}
if network == "ws":
    stream["wsSettings"] = {"path": get("path", "/")}
elif network == "grpc":
    stream["grpcSettings"] = {"serviceName": get("serviceName")}
elif network == "xhttp":
    stream["xhttpSettings"] = {"path": get("path", "/")}
user = {"id": u.username, "encryption": "none"}
if get("flow"):
    user["flow"] = get("flow")

s = socket.socket()
s.bind(("127.0.0.1", 0))
socks_port = s.getsockname()[1]
s.close()
cfg = {
    "log": {"loglevel": "warning"},
    "inbounds": [{"tag": "probe", "listen": "127.0.0.1", "port": socks_port,
                  "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
    "outbounds": [{"tag": "proxy", "protocol": "vless",
                   "settings": {"vnext": [{"address": server_addr, "port": server_port,
                                           "users": [user]}]},
                   "streamSettings": stream}],
}
cfg_file = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump(cfg, cfg_file)
cfg_file.close()
proc = subprocess.Popen(["/usr/local/bin/xray", "run", "-c", cfg_file.name],
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def connect(target):
    c = socket.create_connection(("127.0.0.1", socks_port), timeout=10)
    c.settimeout(15)
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        raise RuntimeError("socks auth rejected")
    host, port = target
    c.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + port.to_bytes(2, "big"))
    head = c.recv(4)
    if len(head) < 2 or head[1] != 0:
        raise RuntimeError("socks connect rejected: %r" % head)
    if head[3] == 1:
        c.recv(6)
    elif head[3] == 4:
        c.recv(18)
    elif head[3] == 3:
        n = c.recv(1)[0]
        c.recv(n + 2)
    return c

try:
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", socks_port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("client socks never opened")

    tls_conn = ssl.create_default_context().wrap_socket(
        connect(("example.com", 443)), server_hostname="example.com")
    tls_conn.do_handshake()
    tls_conn.close()

    http = connect(("example.com", 80))
    http.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: e2e-probe\r\n"
                 b"Accept: */*\r\nConnection: close\r\n\r\n")
    body = b""
    while True:
        chunk = http.recv(4096)
        if not chunk:
            break
        body += chunk
    text = body.decode("utf-8", "replace")
    if not (text.startswith("HTTP/1.1 200") or text.startswith("HTTP/1.0 200")):
        raise RuntimeError("unexpected response %r" % text[:120])
    if "Example Domain" not in text:
        raise RuntimeError("marker missing")
    print("ok")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    os.unlink(cfg_file.name)
PY

handshake() { # uri tag => 0 when the link authenticates end to end
    local uri=$1 tag=$2
    python3 "$PROBE" "$uri" 127.0.0.1 443 >"$DIR/handshake-$tag.log" 2>&1
    local rc=$?
    printf 'rc=%d\n' "$rc" >>"$DIR/handshake-$tag.log"
    return $rc
}

service_stamp() { systemctl show -p ActiveEnterTimestampMonotonic --value xray 2>/dev/null; }

run_edit() { # outfile + full argv (idleleo ...)
    local outfile=$1
    shift
    local -a argv=("$@")
    [[ "${argv[0]}" == "idleleo" ]] && argv[0]="$IDLELEO"
    "${argv[@]}" >"$outfile" 2>"$outfile.err"
    local rc=$?
    echo "$rc" >"$outfile.rc"
    return $rc
}

fail_and_exit() {
    log "FATAL: $*"
    check "driverCompleted" false "$*"
    finalize >&2
    exit 1
}

# --- baseline --------------------------------------------------------------
cp "$CFG" "$DIR/before-config.json"
sha_before=$(sha_of "$CFG")
old_uri=$(share_uri)
sid_old=$(uri_field "$old_uri" sid)
[[ -n "$old_uri" && -n "$sid_old" ]] || fail_and_exit "cannot read the installed share link"
log "baseline sid=$sid_old"
handshake "$old_uri" old-before || fail_and_exit "the installed link does not authenticate before the edit"
check "baselineLinkWorks" true "$sid_old"

E7_ARGS=("${@:2}")   # drop the scenario word; keep idleleo ...
run_after_edit() { run_edit "$@"; }

case "$SCENARIO" in
E7)
    stamp_before=$(service_stamp)
    run_edit "$DIR/append.json" "${E7_ARGS[@]}" || fail_and_exit "shortId append failed"
    new_uri=$(json_get "$DIR/append.json" shareUri)
    sid_new=$(uri_field "$new_uri" sid)
    short_ids=$(json_get "$DIR/append.json" shortIds)
    stamp_after=$(service_stamp)
    check "appendRcZero" true "rc=0"
    check "appendKeepsOldSid" "$([[ "$short_ids" == *"$sid_old"* ]] && echo true || echo false)" "$short_ids"
    check "newLinkUsesNewSid" "$([[ -n "$sid_new" && "$sid_new" != "$sid_old" ]] && echo true || echo false)" "$sid_new"
    check "appendRestartedService" "$([[ "$stamp_before" != "$stamp_after" ]] && echo true || echo false)" "$stamp_before -> $stamp_after"
    handshake "$old_uri" old-after-append
    check "oldLinkWorksAfterAppend" "$([[ $? -eq 0 ]] && echo true || echo false)" "sid=$sid_old"
    handshake "$new_uri" new-after-append
    check "newLinkWorksAfterAppend" "$([[ $? -eq 0 ]] && echo true || echo false)" "sid=$sid_new"

    stamp_before=$(service_stamp)
    run_edit "$DIR/remove.json" "$IDLELEO" xray config edit \
        --short-id-remove "$sid_old" --yes --container --json \
        || fail_and_exit "shortId remove failed"
    stamp_after=$(service_stamp)
    short_ids=$(json_get "$DIR/remove.json" shortIds)
    check "removeRcZero" true "rc=0"
    check "oldSidGone" "$([[ "$short_ids" != *"$sid_old"* ]] && echo true || echo false)" "$short_ids"
    check "removeRestartedService" "$([[ "$stamp_before" != "$stamp_after" ]] && echo true || echo false)" "$stamp_before -> $stamp_after"
    handshake "$old_uri" old-after-remove
    check "oldLinkFailsAfterRemove" "$([[ $? -ne 0 ]] && echo true || echo false)" "sid=$sid_old"
    handshake "$new_uri" new-after-remove
    check "newLinkStillWorks" "$([[ $? -eq 0 ]] && echo true || echo false)" "sid=$sid_new"
    ;;
E8)
    run_edit "$DIR/rotate.json" "${E7_ARGS[@]}" || fail_and_exit "private-key rotation failed"
    rotated_uri=$(json_get "$DIR/rotate.json" shareUri)
    rotated_old=$(json_get "$DIR/rotate.json" oldShareUri)
    backup_dir=$(json_get "$DIR/rotate.json" backupDir)
    check "rotateRcZero" true "rc=0"
    check "rotationReported" "$([[ "$(json_get "$DIR/rotate.json" privateKeyRotated)" == "true" ]] && echo true || echo false)" ""
    check "oldLinkCaptured" "$([[ "$rotated_old" == "$old_uri" ]] && echo true || echo false)" "$rotated_old"
    check "backupHasOldShareUri" \
        "$([[ -f "$backup_dir/old-share-uri.txt" && "$(cat "$backup_dir/old-share-uri.txt")" == "$old_uri" ]] && echo true || echo false)" \
        "$backup_dir/old-share-uri.txt"
    handshake "$rotated_uri" new-after-rotate
    check "newLinkWorksAfterRotate" "$([[ $? -eq 0 ]] && echo true || echo false)" ""
    handshake "$old_uri" old-after-rotate
    check "oldLinkFailsAfterRotate" "$([[ $? -ne 0 ]] && echo true || echo false)" ""

    # Fault injection: keep the pre-rotation config live while the edit writes
    # and restarts. The restart succeeds, so only the real handshake can catch
    # that the new credential is not serving.
    sha_before_fault=$(sha_of "$CFG")
    cp "$CFG" /tmp/e8-frozen.json
    chmod 0644 /tmp/e8-frozen.json
    mkdir -p /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service.d/e8-frozen.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/bin/xray run -config /tmp/e8-frozen.json
EOF
    systemctl daemon-reload
    systemctl restart xray
    for _ in $(seq 1 30); do
        systemctl is-active --quiet xray && break
        sleep 0.5
    done
    log "injected frozen runtime config"

    run_edit "$DIR/rollback.json" "${E7_ARGS[@]}"
    rc=$?
    check "faultEditFails" "$([[ $rc -ne 0 ]] && echo true || echo false)" "rc=$rc"
    check "failurePointRecorded" \
        "$([[ "$(json_get "$DIR/rollback.json" failurePoint)" == "reality-handshake" ]] && echo true || echo false)" \
        "$(json_get "$DIR/rollback.json" failurePoint)"
    check "rollbackProbeOk" \
        "$([[ "$(json_get "$DIR/rollback.json" realityRollbackProbe)" == ok* ]] && echo true || echo false)" \
        "$(json_get "$DIR/rollback.json" realityRollbackProbe)"
    check "configRestored" "$([[ "$(sha_of "$CFG")" == "$sha_before_fault" ]] && echo true || echo false)" ""
    handshake "$rotated_uri" old-after-rollback
    check "oldLinkWorksAfterRollback" "$([[ $? -eq 0 ]] && echo true || echo false)" ""

    rm -f /etc/systemd/system/xray.service.d/e8-frozen.conf
    systemctl daemon-reload
    systemctl restart xray
    for _ in $(seq 1 30); do
        systemctl is-active --quiet xray && break
        sleep 0.5
    done
    check "serviceActiveAfterCleanup" "$(systemctl is-active --quiet xray && echo true || echo false)" ""
    ;;
*)
    check "scenarioKnown" false "$SCENARIO"
    ;;
esac

check "serviceActive" "$(systemctl is-active --quiet xray && echo true || echo false)" ""
python3 - "$DIR/meta.json" "$sha_before" "$(sha_of "$CFG")" <<'PY'
import json, sys
json.dump({"editRc": 0, "beforeSha": sys.argv[2], "afterSha": sys.argv[3]},
          open(sys.argv[1], "w"))
PY
finalize | tee -a "$LOG"
