#!/usr/bin/env bash
# Phase 02 container E2E. Runs inside the pinned ubuntu:24.04 systemd probe.
# Records each command/result; exit code 0 only when every check passed.
set -uo pipefail

XRAY="${XRAY:-/opt/xray/xray}"
BIN="${IDLELEO_BIN:-/bin/idleleo}"
export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY
CONF=/etc/idleleo/conf/xray/config.json
UNIT=/etc/systemd/system/xray.service
PASS=0
FAIL=0

ok()  { echo "PASS $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $1"; FAIL=$((FAIL + 1)); }

run_ok() {
    local name="$1"; shift
    if "$@" >/tmp/step.out 2>&1; then ok "$name"; else bad "$name"; cat /tmp/step.out; fi
}

sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

echo "== Phase 02 container E2E =="
echo "kernel: $(uname -r)"
echo "systemd: $(systemctl is-system-running 2>&1)"
echo "xray: $($XRAY version 2>&1 | head -1)"
echo "image: $(. /etc/os-release && echo "$PRETTY_NAME")"

# The install step must create its own log directory and service account.
mkdir -p /var/log

# ---------------------------------------------------------------- 1. fail-closed
echo "--- 1. install fails closed before writing ---"
rm -rf /etc/idleleo/conf/xray "$UNIT" /usr/local/bin/xray /etc/idleleo/v1/metadata.json
systemctl daemon-reload || true
set +e
"$BIN" xray install --binary "$XRAY" --mode reality --server-names 'bad name!' --port 8443 --container --json >/tmp/pre.json 2>/tmp/pre.err
rc=$?
if [[ $rc -eq 2 && ! -e "$CONF" && ! -e "$UNIT" && ! -e /usr/local/bin/xray ]]; then
    ok "pre-write rejection leaves no config/unit/binary (exit 2)"
else
    bad "pre-write rejection (exit $rc, files: $(ls "$CONF" "$UNIT" /usr/local/bin/xray 2>/dev/null | tr '\n' ' '))"
    cat /tmp/pre.err
fi

# ------------------------------------------------------- 2. fresh install (reality)
echo "--- 2. fresh install reality ---"
run_ok "fresh install writes report" "$BIN" xray install --binary "$XRAY" --mode reality --domain example.com --port 8443 --container --json
cp /tmp/step.out /tmp/install.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/install.json'))
assert d['mode'] == 'reality', d
assert d['transport'] == 'raw', d
assert d['validatorExit'] == 0, d
assert d['serviceActive'] == 'active', d
assert d['serviceEnabled'] == 'enabled', d
assert d['configSha256'], d
PY
[[ $? -eq 0 ]] && ok "install report fields" || bad "install report fields"
[[ "$(systemctl is-active xray 2>&1)" == "active" ]] && ok "systemctl is-active xray" || bad "systemctl is-active xray"
[[ "$(systemctl is-enabled xray 2>&1)" == "enabled" ]] && ok "systemctl is-enabled xray" || bad "systemctl is-enabled xray"
grep -q 'User=xray' "$UNIT" && ok "unit keeps User=xray" || bad "unit User=xray missing"
[[ "$(ps -o user= -C xray | tr -d ' ' | head -1)" == "xray" ]] && ok "xray runs as service account xray" || bad "xray not running as xray"
run_ok "installed config passes real xray -test" "$XRAY" -test -config "$CONF"

# ------------------------------------------------ 3. reality end-to-end data path
echo "--- 3. reality data path (server + client + socks + http) ---"
"$BIN" xray share --path "$CONF" --host 127.0.0.1 --public-port 8443 --json >/tmp/share.json
python3 - <<'PY'
import json
s = json.load(open('/tmp/share.json'))
p = s['shareUri']
from urllib.parse import urlparse, parse_qs, unquote
u = urlparse(p)
q = parse_qs(u.query)
cfg = {
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False}}],
  "outbounds": [{
    "protocol": "vless",
    "settings": {"vnext": [{"address": "127.0.0.1", "port": 8443,
      "users": [{"id": u.username, "encryption": "none", "flow": q['flow'][0]}]}]},
    "streamSettings": {"network": "raw", "security": "reality",
      "realitySettings": {"serverName": q['sni'][0], "fingerprint": q['fp'][0],
        "publicKey": q['pbk'][0], "shortId": q['sid'][0], "spiderX": "/"}}
  }]
}
json.dump(cfg, open('/tmp/client.json', 'w'))
assert q['security'] == ['reality']
assert q['pbk'][0], q
PY
[[ $? -eq 0 ]] && ok "share URI contains usable reality fields" || bad "share URI fields"
# Xray 26 freedom blackholes loopback/private targets, so the data path is
# proven against a public HTTP origin (real bytes through the tunnel).
"$XRAY" run -config /tmp/client.json >/tmp/client.log 2>&1 &
CLIENT_PID=$!
sleep 2
if curl -s --max-time 20 --socks5-hostname 127.0.0.1:1080 http://example.com/ >/tmp/curl.out 2>&1 \
    && grep -q 'Example Domain' /tmp/curl.out; then
    ok "client fetched HTTP through reality tunnel (bytes=$(wc -c </tmp/curl.out))"
else
    bad "reality tunnel data path"
    tail -20 /tmp/client.log
    tail -20 /var/log/xray/error.log 2>/dev/null
fi
kill "$CLIENT_PID" 2>/dev/null || true

# ----------------------------------------------------- 4. user transaction + fault
echo "--- 4. user add/remove transaction against live service ---"
cat >/usr/local/bin/idleleo-service-apply <<'SH'
#!/bin/sh
if [ "${1:-}" = apply ]; then exec systemctl restart xray; fi
exit 2
SH
chmod +x /usr/local/bin/idleleo-service-apply
# /sbx is the disposable transaction sandbox (marker + metadata copy); --path
# still points at the live config so the real service restart is exercised.
rm -rf /sbx
mkdir -p /sbx/etc/idleleo/v1 /sbx/var/lib/idleleo/transactions
printf 'I_ACCEPT_DISPOSABLE_SANDBOX\n' > /sbx/.idleleo-phase01-sandbox
cp /etc/idleleo/v1/metadata.json /sbx/etc/idleleo/v1/metadata.json
before=$(sha "$CONF")
run_ok "add user via transaction + real service restart" "$BIN" xray user add --sandbox /sbx --path "$CONF" \
    --email e2e@idleleo --flow xtls-rprx-vision --validator "$XRAY" \
    --service /usr/local/bin/idleleo-service-apply --json
sleep 1
[[ "$(systemctl is-active xray 2>&1)" == "active" ]] && ok "service active after user change" || bad "service not active after user change"
run_ok "config with new user passes xray -test" "$XRAY" -test -config "$CONF"
before_fault=$(sha "$CONF")
set +e
"$BIN" xray user add --sandbox /sbx --path "$CONF" --email fault@idleleo --validator "$XRAY" \
    --service /usr/local/bin/idleleo-service-apply --fault write-fail >/tmp/fault.out 2>&1
frc=$?
if [[ $frc -eq 13 && "$(sha "$CONF")" == "$before_fault" ]]; then
    ok "write-fail fault leaves config byte-identical (exit 13)"
else
    bad "fault injection (exit $frc)"
    cat /tmp/fault.out
fi
before_svc=$(sha "$CONF")
set +e
"$BIN" xray user add --sandbox /sbx --path "$CONF" --email svcfail@idleleo --validator "$XRAY" \
    --service /usr/local/bin/idleleo-service-apply --fault service-fail >/tmp/svcfail.out 2>&1
src=$?
if [[ $src -eq 9 && "$(sha "$CONF")" == "$before_svc" ]]; then
    ok "service-fail rolls config back byte-identically (exit 9)"
    grep -q 'ROLLED_BACK' /sbx/var/lib/idleleo/transactions/phase01.json \
        && ok "journal records rolled_back state" || bad "journal missing rolled_back"
else
    bad "service-fail rollback (exit $src)"
    cat /tmp/svcfail.out
fi
run_ok "remove non-primary user" "$BIN" xray user remove --sandbox /sbx --path "$CONF" \
    --email e2e@idleleo --validator "$XRAY" --service /usr/local/bin/idleleo-service-apply --json

# --------------------------------------------- 5. uninstall keeps config, reinstall
echo "--- 5. uninstall/reinstall preserves custom DNS ---"
run_ok "uninstall keeps config" "$BIN" xray uninstall --container --json
[[ ! -e /usr/local/bin/xray && ! -e "$UNIT" && -e "$CONF" ]] && ok "uninstall removed runtime, kept config" || bad "uninstall layout"
run_ok "service inactive after uninstall" bash -c '! systemctl is-active --quiet xray'
python3 - <<'PY'
import json
p = '/etc/idleleo/conf/xray/config.json'
d = json.load(open(p))
d['dns']['servers'].append('https://custom.example/dns-query')
json.dump(d, open(p, 'w'), indent=2)
PY
custom_sha=$(sha "$CONF")
run_ok "reinstall with --keep-config" "$BIN" xray install --binary "$XRAY" --mode reality --domain example.com \
    --port 8443 --keep-config --container --json
cp /tmp/step.out /tmp/reinstall.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/reinstall.json'))
assert d['preservedConfig'] is True, d
assert d['serviceActive'] == 'active', d
PY
[[ $? -eq 0 ]] && ok "reinstall report preserved=true" || bad "reinstall report"
[[ "$(sha "$CONF")" == "$custom_sha" ]] && ok "custom DNS preserved byte-for-byte" || bad "custom DNS changed"
python3 - <<'PY'
import json
d = json.load(open('/etc/idleleo/conf/xray/config.json'))
assert 'https://custom.example/dns-query' in d['dns']['servers']
PY
[[ $? -eq 0 ]] && ok "custom DNS still present after reinstall" || bad "custom DNS missing"
run_ok "reinstalled config passes xray -test" "$XRAY" -test -config "$CONF"

# ------------------------------------------------------------- 6. generation matrix
echo "--- 6. config generation matrix (real xray -test) ---"
gen_test() {
    local name="$1"; shift
    "$BIN" xray generate "$@" --out "/var/tmp/$name.json" --json >/tmp/gen.json 2>/tmp/gen.err || { bad "generate $name"; cat /tmp/gen.err; return; }
    "$XRAY" -test -config "/var/tmp/$name.json" >/tmp/gen-test.out 2>&1 || { bad "xray -test $name"; cat /tmp/gen-test.out; return; }
    ok "generate+test $name"
}
gen_test reality --mode reality --domain example.com
gen_test tls-ws --mode tls --transport ws --domain example.com
gen_test tls-grpc --mode tls --transport grpc --domain example.com
gen_test tls-xhttp --mode tls --transport xhttp --domain example.com
gen_test none-ws --mode none --transport ws --domain example.com
gen_test reality-nginx --mode reality-nginx --domain example.com
set +e
"$BIN" xray generate --mode none --listen 0.0.0.0 --out /var/tmp/none-public.json --json >/tmp/genpub.json 2>/tmp/genpub.err
grc=$?
if [[ $grc -eq 2 && ! -e /var/tmp/none-public.json ]]; then
    ok "none mode non-loopback refused without confirmation"
else
    bad "none non-loopback guard (exit $grc)"
    cat /tmp/genpub.err
fi
"$BIN" xray relay --target backend.internal:443 --listen-port 9443 --out /var/tmp/relay-stream.conf >/tmp/relay.out 2>&1
[[ $? -eq 0 ]] && ok "relay nginx fragment generated" || bad "relay fragment"

# ------------------------------------------------------------------ 7. purge
echo "--- 7. purge removes config ---"
run_ok "uninstall --purge" "$BIN" xray uninstall --container --purge --json
[[ ! -e "$CONF" ]] && ok "purge removed config" || bad "purge left config"

# ------------------------------------------------------- 8. native GeoData cycles
echo "--- 8. Xray native GeoData: two refresh cycles ---"
mkdir -p /geo/assets
GEO_URL="https://geo-origin/geoip.dat"
GEO_SIZE="${GEO_ORIGIN_BYTES:-0}"
# The downloader prepends the 3-byte Lua guard header to every fetched asset.
GEO_WRITTEN=$((GEO_SIZE + 3))
update-ca-certificates >/tmp/ca.log 2>&1
if [[ $GEO_SIZE -gt 1000000 ]] \
    && curl -s --max-time 20 -o /geo/assets/geoip.dat "$GEO_URL" \
    && [[ "$(stat -c %s /geo/assets/geoip.dat)" -eq $GEO_SIZE ]]; then
    "$BIN" xray generate --mode reality --domain example.com --port 18443 --out /geo/geo.json >/dev/null 2>&1
    # Only geoip.dat is listed; the local HTTPS/2 origin serves the same real
    # asset, so the post-download reload succeeds without GitHub throughput.
    python3 - <<PY
import json
p = '/geo/geo.json'
d = json.load(open(p))
d['geodata'] = {'cron': '* * * * *', 'assets': [
    {'url': '$GEO_URL', 'file': 'geoip.dat'}]}
json.dump(d, open(p, 'w'), indent=2)
PY
    export XRAY_LOCATION_ASSET=/geo/assets
    mkdir -p /var/log/xray
    "$XRAY" run -config /geo/geo.json >/geo/xray.log 2>&1 &
    GEO_PID=$!
    sleep 3
    repaired=0
    details=""
    for cycle in 1 2; do
        echo "CORRUPTED_CYCLE_$cycle" > /geo/assets/geoip.dat
        bytes=0
        for _ in $(seq 1 22); do
            sleep 5
            bytes=$(stat -c %s /geo/assets/geoip.dat)
            [[ "$bytes" -eq $GEO_WRITTEN ]] && break
        done
        details="$details cycle$cycle=${bytes}B"
        [[ "$bytes" -eq $GEO_WRITTEN ]] && repaired=$((repaired + 1))
    done
    kill "$GEO_PID" 2>/dev/null || true
    echo "geodata refresh:$details (origin=${GEO_SIZE}B expected=${GEO_WRITTEN}B)"
    if [[ $repaired -eq 2 ]]; then
        ok "two native GeoData refresh cycles restored both corruptions"
    else
        bad "native GeoData refresh cycles ($repaired/2)"
        grep -E 'geodata|reload|downloading|error' /geo/xray.log | tail -20
    fi
else
    bad "local GeoData HTTPS origin unavailable"
fi

echo "== Result: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
