#!/usr/bin/env bash
# Real Bash archive cold-restore probe. Secrets and the private archive remain
# inside the disposable Docker network / host mode-0700 handoff directory.
set -uo pipefail

MODE="${1:?source|target required}"
OUT="${E2E_OUT:?E2E_OUT required}"
SCENARIO="${E2E_SCENARIO:?reality|relay|multi required}"
HANDOFF="${E2E_HANDOFF:-/handoff}"
INSTALL=/etc/idleleo/install.sh
XRAY=/usr/local/bin/xray
CFG=/etc/idleleo/conf/xray/config.json
DOMAIN="${E2E_DOMAIN:-example.com}"
ORIGIN_IP=1.2.3.4
ORIGIN_PORT=18080
mkdir -p "$OUT"
: >"$OUT/assertions.txt"
log() { printf '%s\n' "$*" | tee -a "$OUT/driver.log"; }
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
record() { printf '%s\n' "$*" >>"$OUT/assertions.txt"; }
active() { systemctl is-active "$1" 2>/dev/null || true; }

if [[ "$SCENARIO" == relay ]]; then
    STATE_FILE=/etc/idleleo/conf/nginx/relay-stream.conf
else
    STATE_FILE=$CFG
fi

mkdir -p /etc/idleleo/conf /etc/idleleo/cert
if [[ "$MODE" == source ]]; then
    printf 'source-bash-coldrestore-canary\n' >/etc/idleleo/conf/thirdparty-note.txt
else
    printf 'target-placeholder-canary\n' >/etc/idleleo/conf/thirdparty-note.txt
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=thirdparty.example.com' \
    -keyout /etc/idleleo/cert/thirdparty.key -out /etc/idleleo/cert/thirdparty.crt \
    >/dev/null 2>&1
chmod 0600 /etc/idleleo/cert/thirdparty.key
chmod 0644 /etc/idleleo/cert/thirdparty.crt
sha /etc/idleleo/conf/thirdparty-note.txt >"$HANDOFF/canary-note.sha256"

start_origin() {
    {
        echo '--- before origin ---'
        ip -brief addr show dev lo
        ip addr add "$ORIGIN_IP/32" dev lo
        ip_rc=$?
        echo "ip_addr_add_rc=$ip_rc"
        ip -brief addr show dev lo
    } >>"$OUT/origin-diagnostic.txt" 2>&1
    if [[ $ip_rc -ne 0 ]] && ! ip addr show dev lo | grep -q " $ORIGIN_IP/32"; then
        return 1
    fi
    cat >/tmp/bash-cold-origin.py <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"GET {self.path}", flush=True)
        body=b"bash-cold-ok\n"
        self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass
ThreadingHTTPServer(("0.0.0.0",18080),H).serve_forever()
PY
    python3 /tmp/bash-cold-origin.py >>"$OUT/origin-diagnostic.txt" 2>&1 & ORIGIN_PID=$!
    for _ in $(seq 1 40); do
        (exec 3<>"/dev/tcp/$ORIGIN_IP/$ORIGIN_PORT") 2>/dev/null && return 0
        kill -0 "$ORIGIN_PID" 2>/dev/null || break
        sleep .1
    done
    {
        echo "origin_pid=$ORIGIN_PID"
        ps -o pid,stat,args -p "$ORIGIN_PID" || true
        ip addr show dev lo
        ss -lntp || true
        cat "$OUT/origin-diagnostic.txt"
    } >>"$OUT/origin-diagnostic.txt" 2>&1
    return 1
}

client_probe() {
    local out="$1" body rc config_rc=0 mode=reality transport=reality
    mkdir -p "$out"
    if [[ "$SCENARIO" == relay ]]; then
        body=$(curl -sS --max-time 10 http://127.0.0.1:443/fast 2>"$out/curl.err")
        rc=$?
    else
        if [[ "$SCENARIO" != reality ]]; then mode=tls; transport=ws; fi
        local -a args=(--config "$CFG" --mode "$mode" --transport "$transport"
            --server-address 127.0.0.1 --server-port 443 --domain "$DOMAIN"
            --output /tmp/bash-cold-client.json)
        [[ "$mode" != tls ]] || args+=(--cert /etc/idleleo/cert/xray.crt)
        python3 /src/tests/e2e-diff/collect/client_config.py "${args[@]}" \
            >"$out/client-config.log" 2>&1
        config_rc=$?
        if [[ $config_rc -ne 0 ]]; then echo "$config_rc" >"$out/config.rc"; return 1; fi
        "$XRAY" run -c /tmp/bash-cold-client.json >"$out/client.log" 2>&1 & CLIENT_PID=$!
        for _ in $(seq 1 120); do (exec 3<>/dev/tcp/127.0.0.1/1080) 2>/dev/null && break; sleep .1; done
        for _ in $(seq 1 20); do
            body=$(curl -sS --max-time 10 --socks5-hostname 127.0.0.1:1080 \
                "http://$ORIGIN_IP:$ORIGIN_PORT/fast" 2>"$out/curl.err")
            rc=$?
            [[ $rc == 0 && "$body" == bash-cold-ok ]] && break
            sleep 1
        done
        kill "$CLIENT_PID" >/dev/null 2>&1 || true; wait "$CLIENT_PID" 2>/dev/null || true
        if [[ $rc != 0 || "$body" != bash-cold-ok ]] && [[ "$SCENARIO" != reality ]]; then
            openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" -showcerts \
                </dev/null >"$out/tls-server.txt" 2>&1 || true
            sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
                "$out/tls-server.txt" >"$out/tls-server.pem"
            if [[ -s "$out/tls-server.pem" ]]; then
                openssl x509 -in "$out/tls-server.pem" -noout -text >"$out/tls-server-cert.txt" 2>&1 || true
            fi
        fi
    fi
    printf '%s\n' "$body" >"$out/body.txt"
    printf '%s\n' "$rc" >"$out/curl.rc"
    [[ "$rc" == 0 && "$body" == bash-cold-ok ]]
}

snapshot() {
    local dest="$1"
    mkdir -p "$dest"
    for path in "$STATE_FILE" /etc/idleleo/install.sh /etc/idleleo/cert/xray.crt \
        /etc/idleleo/cert/xray.key /etc/idleleo/cert/thirdparty.key \
        /etc/idleleo/cert/thirdparty.crt /usr/local/bin/xray /usr/local/nginx/sbin/nginx \
        /etc/systemd/system/xray.service /etc/systemd/system/nginx.service \
        /etc/idleleo/conf/thirdparty-note.txt; do
        [[ -f "$path" ]] || continue
        local key=${path#/}; key=${key//\//_}
        sha "$path" >"$dest/$key.sha256"
        stat -c '%a %u:%g' "$path" >"$dest/$key.mode-owner"
    done
}

if [[ "$SCENARIO" != relay ]]; then
    [[ -x "$XRAY" ]] || { log 'FAIL missing Xray binary'; exit 2; }
fi
start_origin || { log 'FAIL local origin did not start'; exit 2; }
trap 'kill "${ORIGIN_PID:-}" "${CLIENT_PID:-}" >/dev/null 2>&1 || true; rm -f /tmp/bash-cold-origin.py /tmp/bash-cold-client.json' EXIT

if [[ "$MODE" == source ]]; then
    if [[ "$SCENARIO" == relay ]]; then
        systemctl is-active --quiet nginx || { log 'FAIL source Nginx is not active'; exit 1; }
    else
        systemctl is-active --quiet xray || { log 'FAIL source Xray is not active'; exit 1; }
    fi
    if [[ "$SCENARIO" != relay ]]; then
        "$XRAY" run -test -config "$CFG" >"$OUT/xray-test.log" 2>&1 || { log 'FAIL source xray -test'; exit 1; }
    fi
    client_probe "$OUT/source-client" || { log 'FAIL source real client'; exit 1; }
    snapshot "$OUT/source-state"
    cp -R "$OUT/source-state" "$HANDOFF/source-state"
    printf 'cold-%s-%s\n' "$SCENARIO" "$(date +%s)" | bash "$INSTALL" --backup >"$OUT/backup.log" 2>&1
    rc=$?
    printf '%s\n' "$rc" >"$OUT/backup.rc"
    archive=$(find /etc/idleleo -maxdepth 1 -type f -name 'xray_bash_*.tar.gz' -print | sort | tail -n1)
    [[ $rc == 0 && -n "$archive" ]] || { log "FAIL Bash backup rc=$rc"; exit 1; }
    tar -tzf "$archive" >"$OUT/archive-list.txt" || { log 'FAIL archive integrity'; exit 1; }
    [[ $(stat -c %a "$archive") == 600 ]] || { log 'FAIL archive mode is not 0600'; exit 1; }
    cp "$archive" "$HANDOFF/archive.tar.gz" && chmod 0600 "$HANDOFF/archive.tar.gz" || exit 1
    sha "$HANDOFF/archive.tar.gz" >"$HANDOFF/archive.sha256"
    printf 'PASS\t%s\n' 'source client connected through Bash-managed services' >>"$OUT/assertions.txt"
    printf 'PASS\t%s\n' 'Bash archive created, tar listing valid, archive mode 0600' >>"$OUT/assertions.txt"
    log "source_archive_sha256=$(cat "$HANDOFF/archive.sha256") mode=600"
    exit 0
fi

[[ "$MODE" == target ]] || { echo 'mode must be source or target' >&2; exit 2; }
[[ -s "$HANDOFF/archive.tar.gz" ]] || { log 'FAIL handoff archive missing'; exit 2; }
if [[ "$SCENARIO" == tls || "$SCENARIO" == multi ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -pkeyopt ec_param_enc:named_curve -nodes -days 2 \
        -subj '/CN=target-placeholder.example.com' \
        -keyout /etc/idleleo/cert/xray.key -out /etc/idleleo/cert/xray.crt >/dev/null 2>&1
    chmod 0600 /etc/idleleo/cert/xray.key; chmod 0644 /etc/idleleo/cert/xray.crt
fi
target_cert_sha=$(sha /etc/idleleo/cert/xray.crt 2>/dev/null || true)
install -m 0600 "$HANDOFF/archive.tar.gz" "/etc/idleleo/xray_bash_handoff_$(date +%Y%m%d%H%M%S).tar.gz"
if [[ "$(sha "$HANDOFF/archive.tar.gz")" != "$(cat "$HANDOFF/archive.sha256")" ]]; then
    log 'FAIL archive changed in transfer'
    exit 1
fi
printf 'transfer_sha256=%s\n' "$(sha "$HANDOFF/archive.tar.gz")" >"$OUT/archive-handoff-check.log"

bash "$INSTALL" --restore >"$OUT/restore.log" 2>&1
restore_rc=$?
printf '%s\n' "$restore_rc" >"$OUT/restore.rc"
if [[ $restore_rc != 0 ]]; then log "FAIL Bash restore rc=$restore_rc"; exit 1; fi
systemctl daemon-reload >>"$OUT/restore.log" 2>&1 || true
if [[ "$SCENARIO" == relay ]]; then
    systemctl restart nginx >>"$OUT/restore.log" 2>&1 || { log 'FAIL restart Nginx after restore'; exit 1; }
else
    systemctl restart xray >>"$OUT/restore.log" 2>&1 || { log 'FAIL restart Xray after restore'; exit 1; }
    if [[ "$SCENARIO" != reality ]]; then systemctl restart nginx >>"$OUT/restore.log" 2>&1 || { log 'FAIL restart Nginx after restore'; exit 1; }; fi
fi
sleep 2
if [[ "$SCENARIO" == relay ]]; then
    systemctl is-active --quiet nginx || { log 'FAIL restored Nginx inactive'; exit 1; }
else
    systemctl is-active --quiet xray || { log 'FAIL restored Xray inactive'; exit 1; }
    if [[ "$SCENARIO" != reality ]]; then systemctl is-active --quiet nginx || { log 'FAIL restored Nginx inactive'; exit 1; }; fi
fi
if [[ "$SCENARIO" != relay ]]; then
    "$XRAY" run -test -config "$CFG" >"$OUT/xray-test.log" 2>&1 || { log 'FAIL restored xray -test'; exit 1; }
else
    /usr/local/nginx/sbin/nginx -t >"$OUT/nginx-test.log" 2>&1 || { log 'FAIL restored nginx -t'; exit 1; }
fi

snapshot "$OUT/target-state"
for f in "$HANDOFF/source-state"/*.sha256; do
    name=${f##*/}
    [[ -f "$OUT/target-state/$name" ]] || { log "FAIL missing restored state $name"; exit 1; }
    cmp -s "$f" "$OUT/target-state/$name" || { log "FAIL restored state digest differs $name"; exit 1; }
done
printf 'PASS\t%s\n' 'fresh target Bash restore preserved managed state bytes' >>"$OUT/assertions.txt"
mode_owner_match=true
for f in "$HANDOFF/source-state"/*.mode-owner; do
    name=${f##*/}
    if [[ ! -f "$OUT/target-state/$name" ]]; then
        log "FAIL missing restored permission evidence $name"
        printf 'FAIL\t%s\n' "restored mode/owner evidence exists ($name)" >>"$OUT/assertions.txt"
        mode_owner_match=false
        continue
    fi
    if cmp -s "$f" "$OUT/target-state/$name"; then
        printf 'PASS\t%s\n' "restored mode/owner matches ($name)" >>"$OUT/assertions.txt"
    else
        log "FAIL restored mode/owner differs $name: source=$(cat "$f") target=$(cat "$OUT/target-state/$name")"
        printf 'FAIL\t%s\n' "restored mode/owner matches ($name)" >>"$OUT/assertions.txt"
        mode_owner_match=false
    fi
done
if [[ -n "$target_cert_sha" ]]; then
    restored_cert_sha=$(sha /etc/idleleo/cert/xray.crt)
    [[ "$target_cert_sha" != "$restored_cert_sha" ]] || { log 'FAIL target certificate was not replaced by archive'; exit 1; }
fi
client_probe "$OUT/restored-client" || { log 'FAIL restored real client'; exit 1; }
xray_active=$(systemctl is-active xray 2>/dev/null || true)
nginx_active=not-applicable
if [[ "$SCENARIO" != reality ]]; then
    nginx_active=$(systemctl is-active nginx 2>/dev/null || echo inactive)
fi
printf '{"manager":"bash","scenario":"%s","restoreRc":%s,"archiveSha256":"%s","targetPlaceholderCertSha256":"%s","restoredCertSha256":"%s","xrayActive":"%s","nginxActive":"%s","stateBytesMatch":true,"stateModeOwnerMatch":%s,"realClient":true}\n' \
    "$SCENARIO" "$restore_rc" "$(cat "$HANDOFF/archive.sha256")" "$target_cert_sha" \
    "$(sha /etc/idleleo/cert/xray.crt 2>/dev/null || true)" \
    "$xray_active" "$nginx_active" "$mode_owner_match" \
    >"$OUT/verification.json"
printf 'PASS\t%s\n' 'restored validators, services, and real client connection succeeded' >>"$OUT/assertions.txt"
if [[ "$mode_owner_match" != true ]]; then
    log "DIFF Bash cold restore changed one or more managed state mode/owner values"
    exit 1
fi
printf 'PASS\t%s\n' 'fresh target Bash restore preserved managed state mode and owner' >>"$OUT/assertions.txt"
log "PASS Bash cold restore scenario=$SCENARIO archive_sha256=$(cat "$HANDOFF/archive.sha256")"
