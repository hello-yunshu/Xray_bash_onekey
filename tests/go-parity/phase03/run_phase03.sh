#!/usr/bin/env bash
# Phase 03 Bridge E2E. Runs inside the pinned ubuntu:24.04 systemd probe with a
# real systemd, a real Xray binary, a real nginx and a real crontab file.
# Every check prints the command result; exit 0 only when all checks passed.
set -uo pipefail

export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY
XRAY=/opt/xray/xray
BIN=/work/bin/idleleo
REC=/work/bin/idleleo-recover
FIX=/work/fixtures
ENTRY=/usr/bin/idleleo
GOENTRY=/opt/idleleo/bin/idleleo
CRON=/var/spool/cron/crontabs/root
JOURNAL=/var/lib/idleleo/bridge/journal.json
PASS=0
FAIL=0

ok() { echo "PASS $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $1"; FAIL=$((FAIL + 1)); }
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

cfgval() {
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); v=d.get(sys.argv[2]); print("" if v is None else v)' "$1" "$2"
}

journal_state() {
    [[ -f "$JOURNAL" ]] || { echo none; return; }
    python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("state",""))' "$JOURNAL" 2>/dev/null || echo corrupt
}

count_users() {
    python3 - "$1" <<'PY'
import json,sys
d = json.load(open(sys.argv[1]))
n = 0
for i in d.get('inbounds', []):
    n += len(i.get('settings', {}).get('clients', []) or [])
print(n)
PY
}

cron_has() { grep -qF "$1" "$CRON" 2>/dev/null; }
cron_count() { grep -cF "$1" "$CRON" 2>/dev/null || true; }

project_cron_count() {
    grep -cE '^[^#].*/(etc/idleleo).*(auto_update|ssl_update|geo_update|xray_stats)\.sh' "$CRON" 2>/dev/null || true
}

active() { systemctl is-active "$1" 2>/dev/null || true; }
enabled() { systemctl is-enabled "$1" 2>/dev/null || true; }

write_xray_unit() {
    cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
After=network.target
[Service]
Type=simple
User=xray
Group=xray
ExecStart=/opt/xray/xray run -config /etc/idleleo/conf/xray/config.json
Restart=on-failure
LimitNOFILE=100000
[Install]
WantedBy=multi-user.target
EOF
}

write_nginx_unit() {
    cat >/etc/systemd/system/nginx.service <<'EOF'
[Unit]
Description=nginx - high performance web server
After=network.target
[Service]
Type=forking
ExecStartPre=/usr/sbin/nginx -t -q -c /etc/nginx/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s quit
[Install]
WantedBy=multi-user.target
EOF
}

make_cert() {
    mkdir -p /etc/idleleo/cert
    if [[ ! -f /etc/idleleo/cert/cert.pem ]]; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=legacy.example \
            -addext "subjectAltName=DNS:legacy.example" \
            -keyout /etc/idleleo/cert/privkey.pem -out /etc/idleleo/cert/cert.pem >/dev/null 2>&1
    fi
}

setup_nginx() {
    local kind="$1"
    make_cert
    # A user-owned fragment that must survive migration byte-for-byte.
    cat >/etc/idleleo/conf/nginx/http-custom.conf <<'EOF'
add_header X-Legacy-Project "preserved" always;
EOF
    case "$kind" in
    relay)
        cat >/etc/nginx/nginx.conf <<'EOF'
load_module modules/ngx_stream_module.so;
worker_processes 1;
events { worker_connections 512; }
include /etc/idleleo/conf/nginx/relay-stream.conf;
EOF
        ;;
    TLS)
        cat >/etc/nginx/nginx.conf <<'EOF'
worker_processes 1;
events { worker_connections 512; }
http {
    include /etc/idleleo/conf/nginx/http-custom.conf;
    server {
        listen 443 ssl;
        server_name legacy.example;
        ssl_certificate /etc/idleleo/cert/cert.pem;
        ssl_certificate_key /etc/idleleo/cert/privkey.pem;
        location /fixture-ws { proxy_pass http://127.0.0.1:10086; }
        location /fixture-grpc { grpc_pass grpc://127.0.0.1:10087; }
        location /fixture-xhttp { proxy_pass http://127.0.0.1:10088; }
        location / { return 200 "legacy\n"; }
    }
}
EOF
        ;;
    Reality)
        cat >/etc/nginx/nginx.conf <<'EOF'
worker_processes 1;
events { worker_connections 512; }
http {
    include /etc/idleleo/conf/nginx/http-custom.conf;
    server {
        listen 443 ssl default_server;
        server_name _;
        ssl_certificate /etc/idleleo/cert/cert.pem;
        ssl_certificate_key /etc/idleleo/cert/privkey.pem;
        location / { return 200 "decoy\n"; }
    }
}
EOF
        ;;
    esac
    write_nginx_unit
    /usr/sbin/nginx -t -c /etc/nginx/nginx.conf >/tmp/nginx-t.out 2>&1 || { cat /tmp/nginx-t.out; return 1; }
}

setup_legacy() {
    local fx="$1" tls role addng runtime
    systemctl stop nginx 2>/dev/null || true
    systemctl stop xray 2>/dev/null || true
    rm -f /etc/systemd/system/xray.service /etc/systemd/system/nginx.service
    systemctl daemon-reload 2>/dev/null || true
    rm -rf /etc/idleleo /opt/idleleo /var/lib/idleleo /var/log/xray
    rm -f "$ENTRY" /usr/local/bin/xray /run/lock/idleleo-update.lock
    mkdir -p /etc/idleleo/conf/xray /etc/idleleo/conf/nginx /etc/idleleo/cert /etc/idleleo/tmp \
        /var/log/xray /var/spool/cron/crontabs /etc/systemd/system
    cp "$FIX/$fx/install_config.json" /etc/idleleo/conf/install_config.json
    [[ -f "$FIX/$fx/xray-config.json" ]] && cp "$FIX/$fx/xray-config.json" /etc/idleleo/conf/xray/config.json
    [[ -f "$FIX/$fx/relay-stream.conf" ]] && cp "$FIX/$fx/relay-stream.conf" /etc/idleleo/conf/nginx/relay-stream.conf
    cp /work/install.sh /etc/idleleo/install.sh
    chmod 0755 /etc/idleleo/install.sh
    ln -sfn /etc/idleleo/install.sh "$ENTRY"
    printf '3.3.4\n' >/etc/idleleo/release-managed.version
    cat >"$CRON" <<'CRON'
# user jobs must survive migration
0 4 * * * /usr/bin/certbot renew --quiet
0 7 * * * /usr/local/bin/my-geo-refresh.sh >> /var/log/my-geo.log 2>&1
0 3 * * * /etc/idleleo/scripts/auto_update.sh >> /var/log/idleleo/auto_update.log 2>&1
0 5 * * * /etc/idleleo/scripts/ssl_update.sh >> /var/log/idleleo/ssl_update.log 2>&1
0 6 * * * /etc/idleleo/scripts/geo_update.sh >> /var/log/idleleo/geo_update.log 2>&1
*/5 * * * * /etc/idleleo/scripts/xray_stats.sh collect >/dev/null 2>&1
CRON
    chmod 0600 "$CRON"
    id xray >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin xray
    chown -R xray:xray /var/log/xray
    ln -sf /opt/xray/xray /usr/local/bin/xray

    tls=$(cfgval "$FIX/$fx/install_config.json" tls)
    role=$(cfgval "$FIX/$fx/install_config.json" role)
    addng=$(cfgval "$FIX/$fx/install_config.json" reality_add_nginx)
    runtime=/etc/idleleo/conf/xray/config.json
    if [[ "$role" == "relay" ]]; then
        setup_nginx relay || return 1
    else
        if [[ -f "$runtime" ]]; then
            write_xray_unit
            systemctl daemon-reload
            systemctl enable xray >/dev/null 2>&1 || true
            systemctl start xray >/dev/null 2>&1 || true
        fi
        if [[ "$tls" == "TLS" ]]; then
            setup_nginx TLS || return 1
        elif [[ "$addng" == "on" ]]; then
            setup_nginx Reality || return 1
        fi
    fi
    systemctl daemon-reload
    if [[ -f /etc/systemd/system/nginx.service ]]; then
        systemctl enable nginx >/dev/null 2>&1 || true
        systemctl start nginx >/dev/null 2>&1 || true
    fi
    sleep 1
    echo "setup[$fx] tls=$tls role=${role:-node} xray=$(active xray) nginx=$(active nginx)"
}

bridge() { "$BIN" bridge "$@" --container; }

# ---------------------------------------------------------------- asset server
write_asset_server() {
    mkdir -p /work/assets
    cp "$BIN" /work/assets/idleleo
    cp "$REC" /work/assets/idleleo-recover
    chmod 0755 /work/assets/idleleo /work/assets/idleleo-recover
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 \
        -addext "subjectAltName=IP:127.0.0.1" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -keyout /work/assets/key.pem -out /work/assets/cert.pem >/dev/null 2>&1
    cp /work/assets/cert.pem /usr/local/share/ca-certificates/bridge-test.crt
    update-ca-certificates >/tmp/ca.log 2>&1
    cat >/tmp/https_assets.py <<'PY'
import http.server, ssl, sys
port = int(sys.argv[1]); root = sys.argv[2]; log = sys.argv[3]
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=root, **k)
    def log_message(self, fmt, *args):
        with open(log, 'a') as f:
            f.write(self.path + "\n")
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(root + '/cert.pem', root + '/key.pem')
httpd = http.server.ThreadingHTTPServer(('127.0.0.1', port), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
    : >/tmp/requests.log
    python3 /tmp/https_assets.py 18443 /work/assets /tmp/requests.log >/tmp/https.out 2>&1 &
    ASSET_PID=$!
    sleep 1
    write_manifest
    echo "asset server: pid=$ASSET_PID assets idleleo=$(sha /work/assets/idleleo) recovery=$(sha /work/assets/idleleo-recover)"
}

write_manifest() {
    local s1 s2
    s1=$(sha /work/assets/idleleo)
    s2=$(sha /work/assets/idleleo-recover)
    mkdir -p /etc/idleleo/bridge
    cat >/etc/idleleo/bridge/asset.json <<EOF
{"schemaVersion":1,"version":"0.1.0-phase03-test","url":"https://127.0.0.1:18443/idleleo","sha256":"$s1","recoveryUrl":"https://127.0.0.1:18443/idleleo-recover","recoverySha256":"$s2"}
EOF
}

requests() { [[ -f /tmp/requests.log ]] && wc -l </tmp/requests.log | tr -d ' ' || echo 0; }

# Run a command with a real controlling TTY (the offer uses [[ -t 0 ]]) and
# deliver operator answers to the pty. Piping into `script` is unreliable: the
# child's read can observe EOF before the piped line reaches the pty.
tty_run() {
    local answers="$1" command="$2"
    python3 - "$answers" "$command" <<'PY'
import os, pty, select, sys, time
answers = sys.argv[1].encode().decode('unicode_escape').encode()
command = sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.execvp('bash', ['bash', '-c', command])
out = []
status = 0
slept = 0.0
sent = False
start = time.time()
while True:
    if time.time() - start > 150:
        os.kill(pid, 9)
        status = 9
        break
    if not sent and slept >= 1.0:
        if answers:
            os.write(fd, answers)
        sent = True
    try:
        r, _, _ = select.select([fd], [], [], 0.1)
    except OSError:
        break
    if r:
        try:
            data = os.read(fd, 8192)
        except OSError:
            data = b''
        if not data:
            break
        out.append(data)
    done, st = os.waitpid(pid, os.WNOHANG)
    if done == pid:
        status = st
        break
    slept += 0.1
try:
    while True:
        data = os.read(fd, 8192)
        if not data:
            break
        out.append(data)
except OSError:
    pass
sys.stdout.write(''.join(x.decode('utf-8', 'replace') for x in out))
sys.exit(os.waitstatus_to_exitcode(status))
PY
}

# ---------------------------------------------------------------- main scenarios
echo "== Phase 03 Bridge E2E =="
echo "kernel: $(uname -r)"
echo "systemd: $(systemctl is-system-running 2>&1)"
echo "xray: $($XRAY version 2>&1 | head -1)"
echo "nginx: $(/usr/sbin/nginx -v 2>&1)"
echo "idleleo candidate: $($BIN version 2>&1 | head -1)"

write_asset_server

for bin in "$BIN" "$REC"; do
    [[ -x "$bin" ]] || { echo "missing $bin" >&2; exit 2; }
done

# ---------------------------------------------------------- M05/M06 reality direct
echo "--- M05/M06 reality direct: audit, prepare, validate, activate ---"
setup_legacy reality-direct
RT=/etc/idleleo/conf/xray/config.json
rt_before=$(sha "$RT")
cron_before=$(sha "$CRON")
entry_before=$(readlink "$ENTRY")
unit_before=$(sha /etc/systemd/system/xray.service)
users_before=$(count_users "$RT")
bridge audit --json >/tmp/audit.json 2>/tmp/audit.err
[[ $? -eq 0 ]] && ok "reality: audit runs" || { bad "reality: audit"; cat /tmp/audit.err; }
python3 - <<'PY'
import json
a = json.load(open('/tmp/audit.json'))
assert a['verdict'] == 'convertible', a
assert a['role'] == 'node' and a['tls'] == 'Reality', a
assert a['userCount'] == 1, a
assert a['nginxRequired'] is False, a
PY
[[ $? -eq 0 ]] && ok "reality: audit convertible, 1 user, no nginx" || bad "reality: audit fields"

bridge prepare --candidate "$BIN" --recovery "$REC" --json >/tmp/prep.json 2>/tmp/prep.err
prec=$?
[[ $prec -eq 0 ]] && ok "reality: prepare exit 0" || { bad "reality: prepare exit $prec"; cat /tmp/prep.err; }
python3 - <<'PY'
import json
p = json.load(open('/tmp/prep.json'))
assert p['state'] == 'PREPARED', p
assert p['candidateSha256'], p
assert p['recoverySha256'], p
PY
[[ $? -eq 0 ]] && ok "reality: prepare report state/hashes" || bad "reality: prepare report"
[[ "$(journal_state)" == "PREPARED" ]] && ok "reality: journal PREPARED" || bad "reality: journal $(journal_state)"
[[ "$(sha "$RT")" == "$rt_before" ]] && ok "reality: prepare left runtime byte-identical" || bad "reality: prepare changed runtime"
[[ "$(readlink "$ENTRY")" == "$entry_before" ]] && ok "reality: prepare left entry unchanged" || bad "reality: prepare changed entry"
[[ "$(sha "$CRON")" == "$cron_before" ]] && ok "reality: prepare left cron unchanged" || bad "reality: prepare changed cron"
[[ "$(active xray)" == "active" && "$(enabled xray)" == "enabled" ]] && ok "reality: xray active/enabled after prepare" || bad "reality: xray state after prepare"

bridge validate --xray /usr/local/bin/xray --json >/tmp/val.json 2>/tmp/val.err
vrc=$?
[[ $vrc -eq 0 ]] && ok "reality: validate exit 0" || { bad "reality: validate exit $vrc"; cat /tmp/val.err; }
python3 - <<'PY'
import json
v = json.load(open('/tmp/val.json'))
assert v['state'] == 'VALIDATED', v
assert v['xrayExit'] == 0 and v['candidateExit'] == 0, v
assert v['runtimeSha256']
PY
[[ $? -eq 0 ]] && ok "reality: real xray -test accepted runtime (exit 0)" || bad "reality: validate report"

bridge activate --json >/tmp/act.json 2>/tmp/act.err
arc=$?
[[ $arc -eq 0 ]] && ok "reality: activate exit 0" || { bad "reality: activate exit $arc"; cat /tmp/act.err; }
python3 - <<'PY'
import json
r = json.load(open('/tmp/act.json'))
assert r['state'] == 'COMMITTED', r
assert r['removedCronLines'] == 4, r
assert r['serviceXray'] == 'active', r
assert r['serviceEnabled'] == 'enabled', r
PY
[[ $? -eq 0 ]] && ok "reality: activate committed, removed 4 project cron lines" || bad "reality: activate report"
[[ "$(readlink "$ENTRY")" == "$GOENTRY" ]] && ok "reality: entry points at Go manager" || bad "reality: entry $(readlink "$ENTRY")"
[[ -x "$ENTRY" && "$("$ENTRY" version 2>/dev/null | head -1 | grep -c phase)" -ge 0 ]] && ok "reality: /usr/bin/idleleo runs Go version" || bad "reality: entry not runnable"
[[ "$(sha "$RT")" == "$rt_before" ]] && ok "reality: runtime config byte-identical after commit" || bad "reality: runtime changed"
[[ "$(count_users "$RT")" == "$users_before" ]] && ok "reality: user set unchanged ($users_before users)" || bad "reality: user count changed"
[[ "$(sha /etc/systemd/system/xray.service)" == "$unit_before" ]] && ok "reality: xray unit byte-identical" || bad "reality: unit changed"
[[ "$(active xray)" == "active" && "$(enabled xray)" == "enabled" ]] && ok "reality: xray active/enabled after commit" || bad "reality: xray not active/enabled"
[[ "$(project_cron_count)" == "0" ]] && ok "reality: no project cron lines remain" || bad "reality: project cron remains"
cron_has /usr/bin/certbot && ok "reality: user certbot cron kept" || bad "reality: user cron lost"
cron_has /usr/local/bin/my-geo-refresh.sh && ok "reality: custom geo refresh cron kept" || bad "reality: custom cron lost"
[[ -x /opt/idleleo/recovery/legacy-install.sh ]] && ok "reality: legacy Bash kept as recovery backup" || bad "reality: legacy backup missing"
[[ "$(readlink -f "$ENTRY")" == "$GOENTRY" ]] && [[ "$(type -a idleleo 2>/dev/null | wc -l | tr -d ' ')" -ge 1 ]] \
    && ok "reality: PATH resolves only to the Go manager" || bad "reality: PATH manager ambiguous"
python3 - <<'PY'
import json
m = json.load(open('/etc/idleleo/v1/metadata.json'))
assert m['role'] == 'node' and m['tls'] == 'Reality', m
assert m['ownedResources'], m
raw = open('/etc/idleleo/v1/metadata.json').read()
for secret in ('oD7nlMJVY4oXH5eom_ijOe741Y4WDjpCm6_bzYRCvmk', '11111111-2222-4333-8444-555555555555', '0123456789abcdef'):
    assert secret not in raw, secret
PY
[[ $? -eq 0 ]] && ok "reality: metadata correct and secret-free" || bad "reality: metadata leak"
raw=$(cat "$JOURNAL")
for secret in 'oD7nlMJVY4oXH5eom_ijOe741Y4WDjpCm6_bzYRCvmk' '11111111-2222-4333-8444-555555555555' '0123456789abcdef'; do
    [[ "$raw" != *"$secret"* ]] || bad "reality: journal leaked secret"
done
ok "reality: journal contains no runtime secrets"

systemctl restart xray
sleep 1
[[ "$(active xray)" == "active" ]] && ok "reality: real systemctl restart xray succeeds after migration" || bad "reality: xray restart failed"

bridge audit --json >/tmp/audit2.json 2>/dev/null
python3 - <<'PY'
import json
a = json.load(open('/tmp/audit2.json'))
assert a['verdict'] == 'blocked', a
assert any(f['code'] == 'already-migrated' for f in a['findings']), a
PY
[[ $? -eq 0 ]] && ok "M13 reality: repeat audit reports already-migrated" || bad "M13 reality: repeat audit"
set +e
bridge prepare --candidate "$BIN" --recovery "$REC" >/tmp/prep2.out 2>&1
rc=$?
set -e
[[ $rc -eq 3 ]] && ok "M13 reality: repeat prepare refused (exit 3)" || bad "M13 reality: repeat prepare exit $rc"
set +e
"$BIN" recover --container >/tmp/rec.out 2>&1
rc=$?
set -e
[[ $rc -eq 3 ]] && ok "M13 reality: recover after COMMITTED refused (exit 3)" || bad "M13 reality: committed recover exit $rc"
[[ "$(readlink "$ENTRY")" == "$GOENTRY" ]] && ok "M13 reality: committed entry untouched" || bad "M13 reality: entry moved"

# ---------------------------------------------------------------- M07 TLS multi
echo "--- M07 TLS multi: certificates, custom fragment, nginx -t ---"
setup_legacy tls-multi
RT=/etc/idleleo/conf/xray/config.json
rt_before=$(sha "$RT")
cron_before=$(sha "$CRON")
cert_before=$(sha /etc/idleleo/cert/cert.pem)
key_before=$(sha /etc/idleleo/cert/privkey.pem)
fragment_before=$(sha /etc/idleleo/conf/nginx/http-custom.conf)
users_before=$(count_users "$RT")
bridge audit --json >/tmp/audit.json 2>/dev/null
python3 - <<'PY'
import json
a = json.load(open('/tmp/audit.json'))
assert a['verdict'] == 'convertible', a
assert a['role'] == 'node' and a['tls'] == 'TLS', a
assert a['nginxRequired'] is True, a
assert a['userCount'] == 4, a
assert len(a['certFiles']) >= 2, a
PY
[[ $? -eq 0 ]] && ok "tls: audit convertible, 4 users, nginx+certs required" || bad "tls: audit fields"

bridge prepare --candidate "$BIN" --recovery "$REC" --json >/tmp/prep.json 2>/tmp/prep.err
prec=$?
[[ $prec -eq 0 ]] && ok "tls: prepare exit 0" || { bad "tls: prepare exit $prec"; cat /tmp/prep.err; }
bridge validate --xray /usr/local/bin/xray --nginx /usr/sbin/nginx --json >/tmp/val.json 2>/tmp/val.err
vrc=$?
[[ $vrc -eq 0 ]] && ok "tls: validate exit 0 (xray -test + nginx -t)" || { bad "tls: validate exit $vrc"; cat /tmp/val.err; }
python3 - <<'PY'
import json
v = json.load(open('/tmp/val.json'))
assert v['xrayExit'] == 0 and v['nginxExit'] == 0, v
PY
[[ $? -eq 0 ]] && ok "tls: real xray -test and nginx -t both exit 0" || bad "tls: validator outputs"
bridge activate --json >/tmp/act.json 2>/tmp/act.err
arc=$?
[[ $arc -eq 0 ]] && ok "tls: activate exit 0" || { bad "tls: activate exit $arc"; cat /tmp/act.err; }
[[ "$(readlink "$ENTRY")" == "$GOENTRY" ]] && ok "tls: entry switched" || bad "tls: entry"
[[ "$(sha "$RT")" == "$rt_before" ]] && ok "tls: runtime config byte-identical" || bad "tls: runtime changed"
[[ "$(count_users "$RT")" == "$users_before" ]] && ok "tls: 4 users unchanged" || bad "tls: users changed"
[[ "$(sha /etc/idleleo/cert/cert.pem)" == "$cert_before" && "$(sha /etc/idleleo/cert/privkey.pem)" == "$key_before" ]] \
    && ok "tls: certificate and key byte-identical (not re-issued)" || bad "tls: certificate changed"
[[ "$(sha /etc/idleleo/conf/nginx/http-custom.conf)" == "$fragment_before" ]] \
    && ok "tls: custom nginx fragment byte-identical" || bad "tls: nginx fragment changed"
[[ "$(active nginx)" == "active" && "$(enabled nginx)" == "enabled" ]] && ok "tls: nginx active/enabled after migration" || bad "tls: nginx state"
systemctl reload nginx
sleep 1
[[ "$(active nginx)" == "active" ]] && ok "tls: real systemctl reload nginx succeeds after migration" || bad "tls: nginx reload"
cron_has /usr/bin/certbot && ok "tls: user certbot cron kept" || bad "tls: user cron lost"

# ---------------------------------------------------------------- M08 relay
echo "--- M08 relay: no Xray, nginx stream only ---"
setup_legacy relay
frag_before=$(sha /etc/idleleo/conf/nginx/relay-stream.conf)
cron_before=$(sha "$CRON")
bridge audit --json >/tmp/audit.json 2>/dev/null
python3 - <<'PY'
import json
a = json.load(open('/tmp/audit.json'))
assert a['verdict'] == 'convertible', a
assert a['role'] == 'relay' and a['tls'] == 'None', a
assert a['nginxRequired'] is True, a
assert a['units']['xray']['present'] is False, a
PY
[[ $? -eq 0 ]] && ok "relay: audit convertible role=relay, no xray unit" || bad "relay: audit fields"
bridge prepare --candidate "$BIN" --recovery "$REC" --json >/tmp/prep.json 2>/tmp/prep.err
[[ $? -eq 0 ]] && ok "relay: prepare exit 0 without xray" || { bad "relay: prepare"; cat /tmp/prep.err; }
bridge validate --nginx /usr/sbin/nginx --json >/tmp/val.json 2>/tmp/val.err
vrc=$?
[[ $vrc -eq 0 ]] && ok "relay: validate exit 0 without --xray" || { bad "relay: validate exit $vrc"; cat /tmp/val.err; }
python3 - <<'PY'
import json
v = json.load(open('/tmp/val.json'))
assert v['nginxExit'] == 0 and v['xrayExit'] == 0, v
PY
[[ $? -eq 0 ]] && ok "relay: nginx -t accepted the stream layout" || bad "relay: nginx output"
bridge activate --json >/tmp/act.json 2>/tmp/act.err
arc=$?
[[ $arc -eq 0 ]] && ok "relay: activate exit 0" || { bad "relay: activate exit $arc"; cat /tmp/act.err; }
[[ "$(readlink "$ENTRY")" == "$GOENTRY" ]] && ok "relay: entry switched" || bad "relay: entry"
[[ "$(sha /etc/idleleo/conf/nginx/relay-stream.conf)" == "$frag_before" ]] && ok "relay: stream fragment byte-identical" || bad "relay: stream fragment changed"
[[ "$(active nginx)" == "active" ]] && ok "relay: nginx still active" || bad "relay: nginx inactive"
[[ ! -e /etc/systemd/system/xray.service ]] && ok "relay: migration did not invent an xray unit" || bad "relay: xray unit appeared"
python3 - <<'PY'
import json
m = json.load(open('/etc/idleleo/v1/metadata.json'))
assert m['role'] == 'relay', m
assert 'etc/idleleo/conf/nginx/relay-stream.conf' in m['ownedResources'], m
assert m['runtimeSha256'] == '', m
PY
[[ $? -eq 0 ]] && ok "relay: metadata role/resources correct" || bad "relay: metadata"

# ---------------------------------------------------------------- M04 XTLS
echo "--- M04 XTLS only: blocked, no changes ---"
setup_legacy xtls-only
entry_before=$(readlink "$ENTRY")
cron_before=$(sha "$CRON")
set +e
bridge prepare --candidate "$BIN" --recovery "$REC" >/tmp/prep.out 2>&1
rc=$?
set -e
[[ $rc -eq 3 ]] && ok "xtls: prepare refused (exit 3)" || bad "xtls: prepare exit $rc"
bridge audit --json >/tmp/audit.json 2>/dev/null
python3 - <<'PY'
import json
a = json.load(open('/tmp/audit.json'))
assert a['verdict'] == 'blocked', a
assert any(f['code'] == 'legacy-xtls-removed' for f in a['findings']), a
PY
[[ $? -eq 0 ]] && ok "xtls: audit reports legacy-xtls-removed" || bad "xtls: audit finding"
[[ "$(readlink "$ENTRY")" == "$entry_before" ]] && ok "xtls: entry unchanged" || bad "xtls: entry changed"
[[ "$(sha "$CRON")" == "$cron_before" ]] && ok "xtls: cron unchanged" || bad "xtls: cron changed"
[[ "$(journal_state)" == "none" ]] && ok "xtls: no journal written" || bad "xtls: journal $(journal_state)"

# ---------------------------------------------------------------- M15 no recovery
echo "--- M15 recovery entry missing: activation refused ---"
setup_legacy reality-direct
entry_before=$(readlink "$ENTRY")
cron_before=$(sha "$CRON")
bridge prepare --candidate "$BIN" --json >/tmp/prep.json 2>/tmp/prep.err
[[ $? -eq 0 ]] && ok "m15: prepare without recovery exit 0" || { bad "m15: prepare"; cat /tmp/prep.err; }
bridge validate --xray /usr/local/bin/xray >/dev/null 2>&1
[[ $? -eq 0 ]] && ok "m15: validate exit 0" || bad "m15: validate"
set +e
bridge activate >/tmp/act.out 2>&1
rc=$?
set -e
[[ $rc -eq 3 ]] && ok "M15: activate refused because recovery entry is missing (exit 3)" || bad "M15: activate exit $rc"
[[ "$(journal_state)" == "VALIDATED" ]] && ok "M15: journal stays VALIDATED" || bad "M15: journal $(journal_state)"
[[ "$(readlink "$ENTRY")" == "$entry_before" ]] && ok "M15: entry still Bash" || bad "M15: entry changed"
[[ "$(sha "$CRON")" == "$cron_before" ]] && ok "M15: cron unchanged" || bad "M15: cron changed"
"$BIN" recover --container >/tmp/rec.out 2>&1
[[ $? -eq 0 && "$(journal_state)" == "ROLLED_BACK" ]] && ok "M15: recover discards candidate, ROLLED_BACK" || bad "M15: recover state"

# ---------------------------------------------------------------- M12 drift
echo "--- M12 runtime drift: validate refuses, files preserved ---"
setup_legacy tls-multi
RT=/etc/idleleo/conf/xray/config.json
bridge prepare --candidate "$BIN" --recovery "$REC" >/dev/null 2>&1
printf '\n' >>"$RT"
drift_sha=$(sha "$RT")
entry_before=$(readlink "$ENTRY")
cron_before=$(sha "$CRON")
set +e
bridge validate --xray /usr/local/bin/xray --nginx /usr/sbin/nginx >/tmp/val.out 2>&1
rc=$?
set -e
[[ $rc -eq 6 ]] && ok "M12: validate detects drift (exit 6)" || { bad "M12: validate exit $rc"; cat /tmp/val.out; }
[[ "$(sha "$RT")" == "$drift_sha" ]] && ok "M12: runtime file not overwritten" || bad "M12: runtime overwritten"
[[ "$(readlink "$ENTRY")" == "$entry_before" ]] && ok "M12: entry unchanged" || bad "M12: entry changed"
[[ "$(sha "$CRON")" == "$cron_before" ]] && ok "M12: cron unchanged" || bad "M12: cron changed"
set +e
bridge activate >/tmp/act.out 2>&1
rc=$?
set -e
[[ $rc -eq 3 ]] && ok "M12: activation refused without VALIDATED (exit 3)" || bad "M12: activate exit $rc"
[[ "$(sha "$RT")" == "$drift_sha" ]] && ok "M12: activation did not overwrite drifted runtime" || bad "M12: runtime changed on activate"
"$BIN" recover --container >/dev/null 2>&1
[[ "$(journal_state)" == "ROLLED_BACK" ]] && ok "M12: recover marks ROLLED_BACK" || bad "M12: recover state"

# ---------------------------------------------------------------- M10/M11 faults
fault_case() {
    local point="$1" expect_entry="$2" expect_cron="$3"
    echo "--- fault $point: abrupt exit 70, then independent recovery ---"
    setup_legacy reality-direct
    local RT=/etc/idleleo/conf/xray/config.json
    local rt_before cron_before entry_before
    rt_before=$(sha "$RT")
    cron_before=$(sha "$CRON")
    entry_before=$(readlink "$ENTRY")
    bridge prepare --candidate "$BIN" --recovery "$REC" >/dev/null 2>&1 || { bad "$point: prepare"; return; }
    bridge validate --xray /usr/local/bin/xray >/dev/null 2>&1 || { bad "$point: validate"; return; }
    set +e
    bridge activate --fault "$point" >/tmp/fault.out 2>&1
    local frc=$?
    set -e
    [[ $frc -eq 70 ]] && ok "$point: process killed abruptly (exit 70)" || { bad "$point: fault exit $frc"; cat /tmp/fault.out; }
    [[ "$(journal_state)" == "ACTIVATING" ]] && ok "$point: journal survives as ACTIVATING" || bad "$point: journal $(journal_state)"
    if [[ "$expect_entry" == "go" ]]; then
        [[ "$(readlink "$ENTRY")" == "$GOENTRY" ]] && ok "$point: entry had switched before the kill" || bad "$point: entry $(readlink "$ENTRY")"
    else
        [[ "$(readlink "$ENTRY")" == "$entry_before" ]] && ok "$point: entry had not switched" || bad "$point: entry moved"
    fi
    if [[ "$expect_cron" == "removed" ]]; then
        [[ "$(project_cron_count)" == "0" ]] && ok "$point: project cron had been removed before the kill" || bad "$point: project cron still present"
    else
        [[ "$(sha "$CRON")" == "$cron_before" ]] && ok "$point: cron untouched before the kill" || bad "$point: cron changed"
    fi

    # Independent recovery process: not the manager entry, standard library only.
    set +e
    "$REC" --root / --container --json >/tmp/rec.json 2>/tmp/rec.err
    local rrc=$?
    set -e
    [[ $rrc -eq 0 ]] && ok "$point: independent idleleo-recover exits 0" || { bad "$point: recover exit $rrc"; cat /tmp/rec.err; }
    [[ "$(journal_state)" == "ROLLED_BACK" ]] && ok "$point: journal ROLLED_BACK after recovery" || bad "$point: journal $(journal_state)"
    [[ "$(readlink "$ENTRY")" == "$entry_before" ]] && ok "$point: Bash entry restored" || bad "$point: entry $(readlink "$ENTRY")"
    [[ "$(sha "$RT")" == "$rt_before" ]] && ok "$point: runtime byte-identical after recovery" || bad "$point: runtime changed"
    [[ "$(sha "$CRON")" == "$cron_before" ]] && ok "$point: exact cron set restored" || bad "$point: cron mismatch"
    local dup=0
    for marker in auto_update.sh ssl_update.sh geo_update.sh xray_stats.sh; do
        [[ "$(cron_count "/etc/idleleo/scripts/$marker")" == "1" ]] || dup=1
    done
    [[ $dup -eq 0 ]] && ok "$point: each project cron line appears exactly once" || bad "$point: project cron line duplicated/missing"
    cron_has /usr/bin/certbot && ok "$point: user cron kept" || bad "$point: user cron lost"
    [[ "$(active xray)" == "active" && "$(enabled xray)" == "enabled" ]] && ok "$point: xray still active/enabled" || bad "$point: xray state"
}

fault_case after-activating before untouched
fault_case after-entry-switch go untouched
fault_case after-cron go removed

# ---------------------------------------------------------------- bad journal
echo "--- corrupt journal: honest exit, no silent success ---"
setup_legacy reality-direct
entry_before=$(readlink "$ENTRY")
mkdir -p /var/lib/idleleo/bridge
printf 'not json\n' >"$JOURNAL"
set +e
"$REC" --root / --container >/tmp/rec.out 2>&1
rc=$?
set -e
[[ $rc -eq 2 ]] && ok "journal: independent recover refuses corrupt journal (exit 2)" || bad "journal: recover exit $rc"
[[ "$(readlink "$ENTRY")" == "$entry_before" ]] && ok "journal: corrupt journal left entry unchanged" || bad "journal: entry changed"
set +e
"$BIN" --root / bridge status --json >/tmp/status.json 2>/tmp/status.err
rc=$?
set -e
[[ $rc -eq 5 ]] && ok "journal: status reports unusable journal (exit 5)" || { bad "journal: status exit $rc"; cat /tmp/status.err; }

# ---------------------------------------------------------------- update lock
echo "--- shared update lock: a concurrent Bash updater blocks the bridge ---"
setup_legacy reality-direct
mkdir -p /run/lock
flock /run/lock/idleleo-update.lock -c 'sleep 5' &
locker=$!
sleep 0.5
set +e
bridge prepare --candidate "$BIN" --recovery "$REC" >/tmp/lock.out 2>&1
rc=$?
set -e
wait "$locker" 2>/dev/null || true
[[ $rc -eq 13 ]] && ok "lock: prepare refused while the Bash update lock is held (exit 13)" || { bad "lock: prepare exit $rc"; cat /tmp/lock.out; }
[[ "$(journal_state)" == "none" ]] && ok "lock: no journal written under contention" || bad "lock: journal $(journal_state)"
bridge prepare --candidate "$BIN" --recovery "$REC" >/tmp/lock2.out 2>&1
[[ $? -eq 0 ]] && ok "lock: prepare succeeds after the lock is released" || { bad "lock: prepare after release"; cat /tmp/lock2.out; }
"$BIN" recover --container >/dev/null 2>&1 || true

# ---------------------------------------------------------------- Bash gate matrix
echo "--- M01/M02/M03/M16 Bash migration discovery gates ---"
setup_legacy reality-direct
write_manifest
entry_before=$(readlink "$ENTRY")
cron_before=$(sha "$CRON")
rt_before=$(sha /etc/idleleo/conf/xray/config.json)

reset_requests() { : >/tmp/requests.log; }
reset_requests

# M16/M01: no TTY -> zero network and zero changes.
bash /etc/idleleo/install.sh --internal-bridge-offer </dev/null >/tmp/offer.out 2>&1
rc=$?
[[ $rc -eq 0 && "$(requests)" == "0" ]] && ok "M16/M01: non-TTY offer makes 0 asset requests" || bad "M16/M01: requests=$(requests) exit=$rc"
[[ "$(readlink "$ENTRY")" == "$entry_before" && "$(sha "$CRON")" == "$cron_before" ]] && ok "M16/M01: non-TTY offer changed nothing" || bad "M16/M01: state changed"

# M01: auto_update with a real TTY still makes zero requests.
reset_requests
tty_run '' "env auto_update=YES bash /etc/idleleo/install.sh --internal-bridge-offer" >/tmp/offer.out 2>&1
rc=$?
[[ "$(requests)" == "0" ]] && ok "M01: auto_update=YES with TTY makes 0 asset requests" || bad "M01: requests=$(requests)"
[[ "$(readlink "$ENTRY")" == "$entry_before" ]] && ok "M01: auto_update did not switch the entry" || bad "M01: entry changed"

# M02: the real `-u --yes` path. setup supplies XRAY_VERSIONS_FILE (the only
# version source) so the run is offline except for the Bash release probe.
cat >/work/versions.json <<'EOF'
{"shell_online_version":"3.3.4","shell_release_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","xray_online_version":"26.10.31","xray_installer_ref":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","xray_installer_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","nginx_build_online_version":"2026.10.15.7679"}
EOF
setup_legacy reality-direct
write_manifest
reset_requests
tty_run '' "env XRAY_VERSIONS_FILE=/work/versions.json bash /etc/idleleo/install.sh -u --yes" >/tmp/update.out 2>&1
rc=$?
[[ "$(requests)" == "0" ]] && ok "M02: real Bash -u --yes makes 0 asset requests" || bad "M02: requests=$(requests) exit=$rc"
[[ "$(readlink "$ENTRY")" == "/etc/idleleo/install.sh" ]] && ok "M02: -u --yes did not switch the entry" || bad "M02: entry $(readlink "$ENTRY")"

# M03: explicit manual TTY, operator answers no -> zero requests.
reset_requests
tty_run 'n\n' "bash /etc/idleleo/install.sh --internal-bridge-offer" >/tmp/offer.out 2>&1
rc=$?
[[ "$(requests)" == "0" ]] && ok "M03: TTY refusal makes 0 asset requests" || bad "M03: requests=$(requests)"
grep -q '已取消' /tmp/offer.out && ok "M03: refusal is reported to the operator" || bad "M03: refusal message missing"
[[ "$(readlink "$ENTRY")" == "$entry_before" && "$(sha "$CRON")" == "$cron_before" && "$(sha /etc/idleleo/conf/xray/config.json)" == "$rt_before" ]] \
    && ok "M03: refusal left entry, cron and runtime unchanged" || bad "M03: refusal changed state"

# Without the explicit write acknowledgement the offer must refuse before download.
reset_requests
tty_run 'y\n' "env -u IDLELEO_ALLOW_SYSTEM_WRITES bash /etc/idleleo/install.sh --internal-bridge-offer" >/tmp/offer.out 2>&1
rc=$?
[[ "$(requests)" == "0" ]] && ok "gate: missing container write ack makes 0 asset requests" || bad "gate: requests=$(requests)"
grep -q '未设置 IDLELEO_ALLOW_SYSTEM_WRITES' /tmp/offer.out && ok "gate: missing write ack is reported" || bad "gate: write ack message missing"

# Missing manifest: the offer reports skip and downloads nothing.
reset_requests
mv /etc/idleleo/bridge/asset.json /tmp/asset.json.bak
tty_run 'y\n' "bash /etc/idleleo/install.sh --internal-bridge-offer" >/tmp/offer.out 2>&1
rc=$?
[[ "$(requests)" == "0" ]] && ok "gate: missing manifest makes 0 asset requests" || bad "gate: requests=$(requests)"
grep -q '尚未发布' /tmp/offer.out && ok "gate: missing manifest is reported" || bad "gate: manifest message missing"
mv /tmp/asset.json.bak /etc/idleleo/bridge/asset.json

# Real manual TTY consent: exactly two asset downloads and a committed switch.
reset_requests
tty_run 'y\ny\n' "bash /etc/idleleo/install.sh --internal-bridge-offer" >/tmp/offer.out 2>&1
rc=$?
[[ $rc -eq 0 && "$(requests)" == "2" ]] && ok "M03/M05: TTY consent downloads exactly 2 pinned assets" || { bad "offer: exit=$rc requests=$(requests)"; tail -20 /tmp/offer.out; }
[[ "$(readlink "$ENTRY")" == "$GOENTRY" ]] && ok "M03/M05: consented TTY offer switched the entry" || bad "offer: entry $(readlink "$ENTRY")"
[[ "$(journal_state)" == "COMMITTED" ]] && ok "offer: journal COMMITTED" || bad "offer: journal $(journal_state)"
[[ "$(sha /etc/idleleo/conf/xray/config.json)" == "$rt_before" ]] && ok "offer: runtime config unchanged through Bash consent path" || bad "offer: runtime changed"

# M14: the real Bash -u path uses XRAY_VERSIONS_FILE metadata only. The local
# versions file has no Go asset field, so an automatic update cannot discover
# the Go channel; auto_update=YES must make zero Go requests.
cat >/work/versions.json <<'EOF'
{"shell_online_version":"3.3.4","shell_release_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","xray_online_version":"26.10.31","xray_installer_ref":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","xray_installer_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","nginx_build_online_version":"2026.10.15.7679"}
EOF
setup_legacy reality-direct
write_manifest
reset_requests
tty_run '' "env XRAY_VERSIONS_FILE=/work/versions.json auto_update=YES bash /etc/idleleo/install.sh -u" >/tmp/update.out 2>&1
rc=$?
[[ "$(requests)" == "0" ]] && ok "M14: Bash -u auto update makes 0 Go asset requests" || bad "M14: requests=$(requests)"
grep -q 'Go 迁移资产' /tmp/update.out && bad "M14: auto update reached the Go offer" || ok "M14: auto update never reached the Go offer"
[[ "$(readlink "$ENTRY")" == "/etc/idleleo/install.sh" ]] && ok "M14: auto update left the Bash entry in place" || bad "M14: entry $(readlink "$ENTRY")"

# M14 positive: the same real -u path with a manual TTY reaches the offer.
reset_requests
tty_run 'y\ny\n' "env XRAY_VERSIONS_FILE=/work/versions.json bash /etc/idleleo/install.sh -u" >/tmp/update.out 2>&1
rc=$?
if [[ "$(requests)" == "2" && "$(readlink "$ENTRY")" == "$GOENTRY" ]]; then
    ok "M14/M03: real Bash -u manual TTY reached the offer and committed"
else
    bad "M14: real -u manual path requests=$(requests) entry=$(readlink "$ENTRY") exit=$rc"
    tail -30 /tmp/update.out
fi

# ---------------------------------------------------------------- exit status
echo "== Result: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
