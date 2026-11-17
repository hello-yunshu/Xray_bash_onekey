#!/usr/bin/env bash
# OPS-23: single-user UUID rotation on a live Go install.
#
# Proves, against one running Xray instance:
#   1. every user's link works before the change;
#   2. rotating user B leaves A and C valid (the links they already hold);
#   3. B's old link is refused quickly (never a timeout) and B's new link works;
#   4. the restart only invalidates B's credential: A/C client objects, emails,
#      ports and routing rules stay byte-identical;
#   5. a failing rotation rolls back completely: all three users keep the old
#      UUID and the config hash does not move;
#   6. rotating B back restores the old link, which is the documented rollback.
#
# Usage: bash ops23_user_uuid.sh go
# Env: E2E_OUT (required), E2E_CONTROL_HOST/PORT (default 11.0.0.2:80)
set -uo pipefail

SIDE="${1:?side required (go)}"
OUT="${E2E_OUT:?E2E_OUT required}"
DIR="$OUT/c5-uuid-$SIDE"
CFG=/etc/idleleo/conf/xray/config.json
IDLELEO=/usr/local/bin/idleleo
XRAY=/usr/local/bin/xray
PROBE=/src/tests/e2e-diff/drivers/ops21_probe.py
CONTROL_HOST="${E2E_CONTROL_HOST:-11.0.0.2}"
CONTROL_PORT="${E2E_CONTROL_PORT:-80}"
SANDBOX=/sbx
mkdir -p "$DIR"
: >"$DIR/c5.log"
export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$DIR/c5.log"; }

checks="$DIR/checks.jsonl"
: >"$checks"
check() { # name ok detail
    local ok=$2
    [[ "$ok" == "true" || "$ok" == "1" ]] && ok=true || ok=false
    printf '{"name":"%s","ok":%s,"detail":%s}\n' "$1" "$ok" \
        "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${3:-}")" >>"$checks"
    log "check $1=$ok ${3:-}"
}

json_get() { python3 - "$1" "$2" <<'PY'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    print("")
    sys.exit(0)
cur = doc
for part in sys.argv[2].split('.'):
    cur = cur.get(part) if isinstance(cur, dict) else None
print("" if cur is None else (cur if isinstance(cur, str) else json.dumps(cur)))
PY
}

wait_service() {
    local state=""
    for _ in $(seq 1 40); do
        state=$(systemctl is-active xray 2>/dev/null)
        [[ "$state" == "active" ]] && return 0
        sleep 1
    done
    return 1
}

# The control page must not depend on the container network. Bind a public-range
# address to lo and serve it locally; 11.0.0.2 is outside geoip:private.
ensure_control() {
    if curl -fsS --max-time 2 "http://$CONTROL_HOST:$CONTROL_PORT/" >/dev/null 2>&1; then
        return 0
    fi
    if ! ip addr show dev lo | grep -q " $CONTROL_HOST/"; then
        ip addr add "$CONTROL_HOST/32" dev lo 2>/dev/null || true
    fi
    mkdir -p /tmp/c5-origin
    printf '<!doctype html><title>Example Domain</title><h1>Example Domain</h1>\n' \
        >/tmp/c5-origin/index.html
    (cd /tmp/c5-origin && exec python3 -m http.server "$CONTROL_PORT" --bind "$CONTROL_HOST" \
        >/tmp/c5-origin.log 2>&1) &
    for _ in $(seq 1 20); do
        curl -fsS --max-time 1 "http://$CONTROL_HOST:$CONTROL_PORT/" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    return 1
}

# Reality borrows its target's certificate during the handshake. With no egress a
# public target is unreachable and every tunnel resets, so stand up a loopback
# TLS origin signed by a local CA and point Reality at it.
setup_reality_origin() {
    local dir=/tmp/c5-tls
    rm -rf "$dir"; mkdir -p "$dir"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=c5 e2e CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$dir/ca.key" -out "$dir/ca.crt" >/dev/null 2>&1 || return 1
    openssl req -newkey rsa:2048 -nodes -subj "/CN=local.test" \
        -keyout "$dir/key.pem" -out "$dir/server.csr" >/dev/null 2>&1 || return 1
    cat >"$dir/server.ext" <<'EOF'
subjectAltName=DNS:local.test
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
    openssl x509 -req -in "$dir/server.csr" -days 1 -CA "$dir/ca.crt" \
        -CAkey "$dir/ca.key" -CAcreateserial -extfile "$dir/server.ext" \
        -out "$dir/leaf.pem" >/dev/null 2>&1 || return 1
    cat "$dir/leaf.pem" "$dir/ca.crt" >"$dir/fullchain.pem"
    cat "$dir/ca.crt" >>/etc/ssl/certs/ca-certificates.crt
    cat >"$dir/serve.py" <<'PY'
import socket, ssl, sys, threading, time
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
ctx.set_alpn_protocols(["h2", "http/1.1"])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8443))
srv.listen(16)


def handle(conn):
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        time.sleep(8)
        tls.close()
    except Exception:
        conn.close()


while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
    python3 "$dir/serve.py" "$dir/fullchain.pem" "$dir/key.pem" >/tmp/c5-tls.log 2>&1 &
    sleep 0.5
    return 0
}

share_uri() { # email
    "$IDLELEO" xray share --path "$CFG" --public-port 443 --user "$1" --json 2>/dev/null |
        python3 -c 'import json,sys; print(json.load(sys.stdin).get("shareUri",""))'
}

probe() { # name uri host port
    python3 "$PROBE" "$2" 127.0.0.1 443 "$3" "$4" 6000 \
        >"$DIR/$1.json" 2>"$DIR/$1.err"
    json_get "$DIR/$1.json" outcome
}
marker() { json_get "$DIR/$1.json" marker; }

uuid_of() { # email
    python3 - "$CFG" "$1" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
for inb in cfg["inbounds"]:
    for c in inb.get("settings", {}).get("clients", []):
        if c.get("email") == sys.argv[2]:
            print(c.get("id", ""))
            sys.exit(0)
print("")
PY
}

routing_sha() {
    python3 - "$CFG" <<'PY'
import hashlib, json, sys
cfg = json.load(open(sys.argv[1]))
print(hashlib.sha256(json.dumps(cfg.get("routing") or {}, sort_keys=True).encode()).hexdigest())
PY
}

offline_yet() { [[ "$SIDE" != "go" ]]; }

if offline_yet; then
    check harness false "OPS-23 only runs the Go side"
    exit 2
fi

wait_service || check serviceActive false "xray is not active before rotation"
ensure_control || log "WARN: control origin did not come up"
setup_reality_origin || log "WARN: local reality origin failed"

if ! "$IDLELEO" xray config edit --target 127.0.0.1:8443 --server-names local.test \
    --yes --container --json >"$DIR/reality-origin.json" 2>"$DIR/reality-origin.err"; then
    check realityOriginLocal false "$(tail -1 "$DIR/reality-origin.err" 2>/dev/null)"
    exit 3
fi
check realityOriginLocal true "target=127.0.0.1:8443 sni=local.test"
wait_service >/dev/null || true

# ── sandbox for the user transaction (same contract as xray user add/remove) ──
cat >/usr/local/bin/idleleo-service-apply <<'SH'
#!/bin/sh
if [ "${1:-}" = apply ]; then exec systemctl restart xray; fi
exit 2
SH
chmod +x /usr/local/bin/idleleo-service-apply
rm -rf "$SANDBOX"
mkdir -p "$SANDBOX/etc/idleleo/v1" "$SANDBOX/var/lib/idleleo/transactions"
printf 'I_ACCEPT_DISPOSABLE_SANDBOX\n' >"$SANDBOX/.idleleo-phase01-sandbox"
cp /etc/idleleo/v1/metadata.json "$SANDBOX/etc/idleleo/v1/metadata.json"

add_user() { # email uuid
    "$IDLELEO" xray user add --sandbox "$SANDBOX" --path "$CFG" --email "$1" --uuid "$2" \
        --flow xtls-rprx-vision --validator "$XRAY" --service /usr/local/bin/idleleo-service-apply \
        --json >"$DIR/add-$1.json" 2>&1
}

add_user user-b@idleleo 99999999-2222-3333-4444-555555555555 ||
    check addUserB false "$(tail -2 "$DIR/add-user-b@idleleo.json" 2>/dev/null)"
add_user user-c@idleleo 77777777-2222-3333-4444-555555555555 ||
    check addUserC false "$(tail -2 "$DIR/add-user-c@idleleo.json" 2>/dev/null)"
wait_service >/dev/null || true

A_EMAIL=me@hey.run
B_EMAIL=user-b@idleleo
C_EMAIL=user-c@idleleo
A_OLD=$(uuid_of "$A_EMAIL")
B_OLD=$(uuid_of "$B_EMAIL")
C_OLD=$(uuid_of "$C_EMAIL")
[[ -n "$A_OLD" && -n "$B_OLD" && -n "$C_OLD" ]] ||
    check allUsersPresent false "a=$A_OLD b=$B_OLD c=$C_OLD"

URI_A=$(share_uri "$A_EMAIL")
URI_B=$(share_uri "$B_EMAIL")
URI_C=$(share_uri "$C_EMAIL")
[[ -n "$URI_A" && -n "$URI_B" && -n "$URI_C" ]] ||
    check shareUris false "one of the three links is empty"

# ── 1. baseline: all three credentials work ──────────────────────────────────
check baselineA "$([[ "$(probe baseline-a "$URI_A" "$CONTROL_HOST" "$CONTROL_PORT")" == ok && "$(marker baseline-a)" == true ]] && echo true || echo false)" ""
check baselineB "$([[ "$(probe baseline-b "$URI_B" "$CONTROL_HOST" "$CONTROL_PORT")" == ok && "$(marker baseline-b)" == true ]] && echo true || echo false)" ""
check baselineC "$([[ "$(probe baseline-c "$URI_C" "$CONTROL_HOST" "$CONTROL_PORT")" == ok && "$(marker baseline-c)" == true ]] && echo true || echo false)" ""

ROUTING_BEFORE=$(routing_sha)
CFG_BEFORE=$(sha256sum "$CFG" | awk '{print $1}')
A_CLIENT_BEFORE=$(python3 - "$CFG" "$A_EMAIL" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
for inb in cfg["inbounds"]:
    for c in inb.get("settings", {}).get("clients", []):
        if c.get("email") == sys.argv[2]:
            print(json.dumps(c, sort_keys=True)); sys.exit(0)
PY
)
C_CLIENT_BEFORE=$(python3 - "$CFG" "$C_EMAIL" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
for inb in cfg["inbounds"]:
    for c in inb.get("settings", {}).get("clients", []):
        if c.get("email") == sys.argv[2]:
            print(json.dumps(c, sort_keys=True)); sys.exit(0)
PY
)

B_NEW=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

# ── 2. a failing rotation must leave all three users on their old UUID ──────
UUID_FAIL=cccccccc-dddd-eeee-ffff-000000000000
CFG_PRE_FAIL=$(sha256sum "$CFG" | awk '{print $1}')
set +e
"$IDLELEO" xray user uuid --sandbox "$SANDBOX" --path "$CFG" --email "$C_EMAIL" \
    --new-uuid "$UUID_FAIL" --validator "$XRAY" --service /usr/local/bin/idleleo-service-apply \
    --fault service-fail >"$DIR/fail-rotate.out" 2>&1
fail_rc=$?
set +e
printf '%s\n' "$fail_rc" >"$DIR/fail-rotate.rc"
check failRollbackExit "$([[ $fail_rc -eq 9 ]] && echo true || echo false)" "rc=$fail_rc"
check failConfigHash "$([[ "$(sha256sum "$CFG" | awk '{print $1}')" == "$CFG_PRE_FAIL" ]] && echo true || echo false)" ""
check failAllOld "$([[ "$(uuid_of "$A_EMAIL")" == "$A_OLD" && "$(uuid_of "$B_EMAIL")" == "$B_OLD" && "$(uuid_of "$C_EMAIL")" == "$C_OLD" ]] && echo true || echo false)" "a=$(uuid_of "$A_EMAIL") b=$(uuid_of "$B_EMAIL") c=$(uuid_of "$C_EMAIL")"
wait_service >/dev/null || true
check failNoHalfState "$([[ "$(probe fail-a "$URI_A" "$CONTROL_HOST" "$CONTROL_PORT")" == ok && "$(probe fail-c "$URI_C" "$CONTROL_HOST" "$CONTROL_PORT")" == ok ]] && echo true || echo false)" ""

# ── 3. rotate B ─────────────────────────────────────────────────────────────
DRY_B=$("$IDLELEO" xray user uuid --sandbox "$SANDBOX" --path "$CFG" --email "$B_EMAIL" --new-uuid "$B_NEW" \
    --validator "$XRAY" --dry-run 2>&1)
printf '%s\n' "$DRY_B" >"$DIR/dryrun-b.txt"
check dryRunListsInbound "$(grep -q "inbound 0 client" <<<"$DRY_B" && echo true || echo false)" "$(grep -m1 'inbound 0 client' <<<"$DRY_B")"
check dryRunShowsOldUUID "$(grep -q "$B_OLD" <<<"$DRY_B" && echo true || echo false)" ""
check dryRunWarnsRestart "$(grep -q 'warning: this restarts the Xray service' <<<"$DRY_B" && echo true || echo false)" "$(grep -m1 'warning: this restarts' <<<"$DRY_B")"

set +e
"$IDLELEO" xray user uuid --sandbox "$SANDBOX" --path "$CFG" --email "$B_EMAIL" \
    --new-uuid "$B_NEW" --validator "$XRAY" --service /usr/local/bin/idleleo-service-apply \
    >"$DIR/rotate-b.out" 2>"$DIR/rotate-b.err"
rot_rc=$?
set +e
printf '%s\n' "$rot_rc" >"$DIR/rotate-b.rc"
check rotateExit "$([[ $rot_rc -eq 0 ]] && echo true || echo false)" "rc=$rot_rc $(tail -1 "$DIR/rotate-b.err" 2>/dev/null)"
check rotateOutputWarnsRestart "$(grep -q 'warning: this restarts the Xray service' "$DIR/rotate-b.out" && echo true || echo false)" "$(grep -m1 'inbound 0 client' "$DIR/rotate-b.out")"

wait_service >/dev/null || true
check serviceAfterRotate "$(systemctl is-active xray 2>/dev/null | grep -qx active && echo true || echo false)" ""
check uuidApplied "$([[ "$(uuid_of "$B_EMAIL")" == "$B_NEW" ]] && echo true || echo false)" "b=$(uuid_of "$B_EMAIL")"

# ── 4. the credential that must break ───────────────────────────────────────
old_outcome=$(probe b-old "$URI_B" "$CONTROL_HOST" "$CONTROL_PORT")
check bOldLinkRefused "$([[ "$old_outcome" == blocked ]] && echo true || echo false)" "outcome=$old_outcome (timeout means the probe is inconclusive)"

# ── 3. the credentials that must not break ──────────────────────────────────
URI_B_NEW=$(share_uri "$B_EMAIL")
check bNewLinkWorks "$([[ "$(probe b-new "$URI_B_NEW" "$CONTROL_HOST" "$CONTROL_PORT")" == ok && "$(marker b-new)" == true ]] && echo true || echo false)" ""
check aStillWorks "$([[ "$(probe after-a "$URI_A" "$CONTROL_HOST" "$CONTROL_PORT")" == ok && "$(marker after-a)" == true ]] && echo true || echo false)" ""
check cStillWorks "$([[ "$(probe after-c "$URI_C" "$CONTROL_HOST" "$CONTROL_PORT")" == ok && "$(marker after-c)" == true ]] && echo true || echo false)" ""

# ── 4. nothing else moved ───────────────────────────────────────────────────
A_CLIENT_AFTER=$(python3 - "$CFG" "$A_EMAIL" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
for inb in cfg["inbounds"]:
    for c in inb.get("settings", {}).get("clients", []):
        if c.get("email") == sys.argv[2]:
            print(json.dumps(c, sort_keys=True)); sys.exit(0)
PY
)
C_CLIENT_AFTER=$(python3 - "$CFG" "$C_EMAIL" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
for inb in cfg["inbounds"]:
    for c in inb.get("settings", {}).get("clients", []):
        if c.get("email") == sys.argv[2]:
            print(json.dumps(c, sort_keys=True)); sys.exit(0)
PY
)
check aClientUnchanged "$([[ "$A_CLIENT_AFTER" == "$A_CLIENT_BEFORE" ]] && echo true || echo false)" ""
check cClientUnchanged "$([[ "$C_CLIENT_AFTER" == "$C_CLIENT_BEFORE" ]] && echo true || echo false)" ""
check routingUnchanged "$([[ "$(routing_sha)" == "$ROUTING_BEFORE" ]] && echo true || echo false)" ""

# ── 5. rollback: put B back on the old credential ───────────────────────────
set +e
"$IDLELEO" xray user uuid --sandbox "$SANDBOX" --path "$CFG" --email "$B_EMAIL" \
    --new-uuid "$B_OLD" --validator "$XRAY" --service /usr/local/bin/idleleo-service-apply \
    --json >"$DIR/revert-b.json" 2>"$DIR/revert-b.err"
rev_rc=$?
set +e
printf '%s\n' "$rev_rc" >"$DIR/revert-b.rc"
wait_service >/dev/null || true
check revertExit "$([[ $rev_rc -eq 0 ]] && echo true || echo false)" "rc=$rev_rc"
check revertOldLinkWorks "$([[ "$(probe reverted-b "$URI_B" "$CONTROL_HOST" "$CONTROL_PORT")" == ok && "$(marker reverted-b)" == true ]] && echo true || echo false)" ""
check revertOthersStillWork "$([[ "$(probe revert-a "$URI_A" "$CONTROL_HOST" "$CONTROL_PORT")" == ok && "$(probe revert-c "$URI_C" "$CONTROL_HOST" "$CONTROL_PORT")" == ok ]] && echo true || echo false)" ""
check revertUuid "$([[ "$(uuid_of "$B_EMAIL")" == "$B_OLD" ]] && echo true || echo false)" ""

log "done checks=$(wc -l <"$checks")"
