#!/usr/bin/env bash
# Runs `idleleo xray config edit` after a real install and captures before/after
# evidence plus a machine-readable checks file.
#
# Usage:
#   bash go_edit.sh idleleo xray config edit --uuid <uuid> --yes --container --json
#
# Environment:
#   E2E_OUT       evidence directory for the scenario (required)
#   E2E_SCENARIO  E1 (before/after) | E2 (restart failure rollback)
#
# E2 injects a one-shot systemd failure: the first ExecStartPre creates the
# marker and exits non-zero, so the edit's restart fails but the rollback
# restart succeeds. That distinguishes a real rollback from a permanently
# broken service.
set -uo pipefail

OUT="${E2E_OUT:?E2E_OUT required}"
SCENARIO="${E2E_SCENARIO:?E2E_SCENARIO required}"
DIR="$OUT/edit"
CFG=/etc/idleleo/conf/xray/config.json
mkdir -p "$DIR"

log() { printf '%s\n' "$*" >>"$DIR/edit.log"; }
export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY

sha_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

cp "$CFG" "$DIR/before-config.json" 2>/dev/null || log "missing $CFG"
sha_before=$(sha_of "$CFG")
idleleo show --json >"$DIR/before-show.json" 2>&1 || true
idleleo xray share --path "$CFG" --public-port 443 --json \
    >"$DIR/before-share.json" 2>&1 || true

if [[ "$SCENARIO" == "E2" ]]; then
    mkdir -p /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service.d/e2e-fail-once.conf <<'EOF'
[Service]
ExecStartPre=/bin/sh -c "if [ ! -f /tmp/e2e-xray-failed-once ]; then touch /tmp/e2e-xray-failed-once; exit 1; fi"
EOF
    rm -f /tmp/e2e-xray-failed-once
    systemctl daemon-reload
    log "injected one-shot restart failure"
fi

# E4 needs a live TLS origin on loopback so the edit-time probe can succeed
# without external network access. The origin certificate is signed by a local
# CA that is trusted inside this container (probe + Reality handshake) and
# exported for the L4 client container (l4.sh E2E_EXTRA_CA), so the chain is
# verified exactly like a public origin's.
ORIGIN_PID=""
if [[ "$SCENARIO" == "E4" ]]; then
    ORIGIN_DIR=/tmp/e2e-origin-tls
    rm -rf "$ORIGIN_DIR"; mkdir -p "$ORIGIN_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=e2e local CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$ORIGIN_DIR/ca.key" -out "$ORIGIN_DIR/ca.crt" >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes -subj "/CN=local.test" \
        -keyout "$ORIGIN_DIR/key.pem" -out "$ORIGIN_DIR/server.csr" >/dev/null 2>&1
    cat >"$ORIGIN_DIR/server.ext" <<'EOF'
subjectAltName=DNS:local.test
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
    openssl x509 -req -in "$ORIGIN_DIR/server.csr" -days 1 \
        -CA "$ORIGIN_DIR/ca.crt" -CAkey "$ORIGIN_DIR/ca.key" -CAcreateserial \
        -extfile "$ORIGIN_DIR/server.ext" -out "$ORIGIN_DIR/leaf.pem" >/dev/null 2>&1
    cat "$ORIGIN_DIR/leaf.pem" "$ORIGIN_DIR/ca.crt" >"$ORIGIN_DIR/fullchain.pem"

    # Trust the CA here. Go reads the Debian/Ubuntu bundle, so appending works
    # with or without the ca-certificates helper; run the helper first so its
    # regeneration cannot drop the entry.
    if command -v update-ca-certificates >/dev/null 2>&1; then
        mkdir -p /usr/local/share/ca-certificates
        cp "$ORIGIN_DIR/ca.crt" /usr/local/share/ca-certificates/e2e-local-ca.crt
        update-ca-certificates >/dev/null 2>&1 || true
    fi
    cat "$ORIGIN_DIR/ca.crt" >>/etc/ssl/certs/ca-certificates.crt
    # Exported next to the other edit evidence; l4.sh picks it up for the
    # post-edit client container.
    cp "$ORIGIN_DIR/ca.crt" "$DIR/local-ca.crt"

    cat >"$ORIGIN_DIR/serve.py" <<'PY'
import socket, ssl, sys, threading, time
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
# Reality dials the target with the client's fingerprint, which offers
# h2/http1.1; a real origin negotiates ALPN, so the fixture must too or the
# server treats the connection as invalid and falls back.
ctx.set_alpn_protocols(["h2", "http/1.1"])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8443))
srv.listen(16)


def handle(conn):
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        # Reality dials the target to borrow its certificate; keep the session
        # open long enough for that exchange to finish. One thread per
        # connection keeps the dry-run preview probe and the real edit probe
        # from serialising behind this sleep, like a real origin would.
        time.sleep(5)
        tls.close()
    except Exception:
        conn.close()


while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY
    python3 "$ORIGIN_DIR/serve.py" "$ORIGIN_DIR/fullchain.pem" "$ORIGIN_DIR/key.pem" \
        >"$DIR/origin.log" 2>&1 &
    ORIGIN_PID=$!
    for _ in $(seq 1 20); do
        (exec 3<>/dev/tcp/127.0.0.1/8443) 2>/dev/null && { exec 3<&- 3>&-; break; }
        sleep 0.2
    done
    log "started local TLS origin pid=$ORIGIN_PID (local CA trusted)"
fi

expected_target=""
prev=""
for a in "$@"; do
    [[ "$prev" == "--target" ]] && expected_target="$a"
    prev="$a"
done

log "edit_argv=$*"
set +e
/usr/local/bin/idleleo xray config edit "${@:2}" >"$DIR/edit.json" 2>"$DIR/edit.err"
edit_rc=$?
set -e
log "edit_exit=$edit_rc"

# The rollback restart is asynchronous; give the unit a moment to settle.
for _ in $(seq 1 10); do
    [[ "$(systemctl is-active xray 2>/dev/null)" == "active" ]] && break
    sleep 1
done

sha_after=$(sha_of "$CFG")
state=$(systemctl is-active xray 2>/dev/null || true)
backups=$(find /etc/idleleo/backup -maxdepth 1 -type d -name 'edit-*' 2>/dev/null | wc -l | tr -d ' ') || true
backups=${backups:-0}
cp "$CFG" "$DIR/after-config.json" 2>/dev/null || true
idleleo show --json >"$DIR/after-show.json" 2>&1 || true
idleleo xray share --path "$CFG" --public-port 443 --json \
    >"$DIR/after-share.json" 2>&1 || true

python3 - "$DIR" "$SCENARIO" "$edit_rc" "$sha_before" "$sha_after" "$state" "$backups" "$expected_target" <<'PY'
import json
import os
import sys

(directory, scenario, edit_rc, sha_before, sha_after, state, backups, expected_target) = sys.argv[1:9]
edit_rc = int(edit_rc)
backups = int(backups)


def read_json(name, default):
    try:
        with open(os.path.join(directory, name)) as fh:
            return json.load(fh)
    except Exception:
        return default


err = ""
try:
    with open(os.path.join(directory, "edit.err")) as fh:
        err = fh.read()
except Exception:
    pass

after_cfg = read_json("after-config.json", {})
clients = []
try:
    for inbound in after_cfg.get("inbounds", []):
        clients += inbound.get("settings", {}).get("clients", [])
except Exception:
    pass
uuids = {c.get("id") for c in clients if isinstance(c, dict)}
after_share = read_json("after-share.json", {})
targets = []
try:
    for inbound in after_cfg.get("inbounds", []):
        target = inbound.get("streamSettings", {}).get("realitySettings", {}).get("target")
        if target:
            targets.append(target)
except Exception:
    pass
edit_out = ""
try:
    with open(os.path.join(directory, "edit.json")) as fh:
        edit_out = fh.read()
except Exception:
    pass

checks = {
    "editRcZero": edit_rc == 0,
    "editRcNonZero": edit_rc != 0,
    "configChanged": bool(sha_before) and sha_before != sha_after,
    "configRestored": bool(sha_before) and sha_before == sha_after,
    "rollbackReported": "restored" in err,
    "serviceActive": state == "active",
    "backupExists": backups > 0,
    "noBackup": backups == 0,
    "uuidApplied": "99999999-8888-7777-6666-555555555555" in uuids,
    "shareUriUpdated": "99999999-8888-7777-6666-555555555555" in json.dumps(after_share),
    "targetApplied": bool(expected_target) and expected_target in targets,
    "probeReported": ('"originProbe"' in edit_out and "originProbe\": \"\"" not in edit_out)
                     or ("origin:" in edit_out and "ok" in edit_out),
    "probeRefused": edit_rc == 2 and "origin unreachable" in err
                     and bool(sha_before) and sha_before == sha_after and backups == 0,
}

wanted = {
    "E1": ["editRcZero", "configChanged", "uuidApplied", "shareUriUpdated", "serviceActive", "backupExists"],
    "E2": ["editRcNonZero", "rollbackReported", "configRestored", "serviceActive"],
    "E3": ["probeRefused", "configRestored", "serviceActive", "noBackup"],
    "E4": ["editRcZero", "configChanged", "targetApplied", "probeReported", "serviceActive"],
}.get(scenario, [])

result = {
    "scenario": scenario,
    "editRc": edit_rc,
    "service": state,
    "backups": backups,
    "beforeSha": sha_before,
    "afterSha": sha_after,
    "checks": checks,
    "wanted": wanted,
    "allPassed": all(checks.get(name) for name in wanted) if wanted else False,
}
with open(os.path.join(directory, "checks.json"), "w") as fh:
    json.dump(result, fh, indent=2, sort_keys=True)
print(json.dumps(result, sort_keys=True))
PY

# The local TLS origin must outlive the edit: Reality's fallback keeps using
# the new target during the post-edit L4 check, so it is only removed with the
# container.
if [[ -n "$ORIGIN_PID" ]]; then
    log "local TLS origin left running (pid $ORIGIN_PID)"
fi
exit 0
