#!/usr/bin/env bash
# Real nginx -t verification for `xray guard set` / `xray cert clear`.
# Run as root in a disposable nginx image with a Linux idleleo binary:
#   docker run --rm -v ...:/usr/local/bin/idleleo:ro -v ...:/smoke.sh:ro \
#     nginx:1.27-alpine sh /smoke.sh
set -euo pipefail

bin="${1:-/usr/local/bin/idleleo}"
test -x "${bin}"
# This script only ever runs inside a disposable container root.
export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY
# The image has no init system. A stub keeps the reload step from rolling back;
# the real assertion here is `nginx -t`, which still runs the shipped binary.
if ! command -v systemctl >/dev/null 2>&1; then
  printf '#!/bin/sh\nexit 0\n' >/usr/bin/systemctl
  chmod +x /usr/bin/systemctl
fi

rm -rf /etc/idleleo /usr/local/nginx
mkdir -p /etc/idleleo/v1 /etc/idleleo/conf/xray /etc/idleleo/conf/nginx \
  /etc/idleleo/cert /usr/local/nginx/conf /usr/local/nginx/sbin

cat >/etc/idleleo/v1/metadata.json <<'JSON'
{
  "schemaVersion": 1,
  "activeEngine": "xray",
  "role": "node",
  "tls": "Reality",
  "transport": "raw",
  "runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
  "runtimeSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "ownedResources": [],
  "updatedAt": "2026-01-01T00:00:00Z",
  "install": {"port": 443, "serverNames": ["node.example.com"]}
}
JSON

printf '%s\n' '{"inbounds":[{"port":443,"protocol":"vless"}]}' \
  >/etc/idleleo/conf/xray/config.json

cat >/etc/idleleo/conf/nginx/00-xray.conf <<'CONF'
stream {
    map $ssl_preread_server_name $sni_upstream {
        include /etc/idleleo/conf/nginx/*.serverNames;
        default deny;
    }
    upstream deny {
        server 127.0.0.1:9403;
    }
    server {
        listen 443;
        ssl_preread on;
        proxy_pass $sni_upstream;
    }
}
CONF

cat >/etc/idleleo/conf/nginx/03-isolate.conf <<'CONF'
server {
    listen 127.0.0.1:9403 ssl;
    ssl_reject_handshake on;
    access_log off;
    error_log /dev/null;
}
CONF

cat >/usr/local/nginx/conf/nginx.conf <<'CONF'
worker_processes 1;
error_log /tmp/nginx-error.log;
pid /tmp/nginx.pid;
events { worker_connections 64; }
http {
    server {
        listen 9080;
        location / { return 200 "ok\n"; }
    }
    include /etc/idleleo/conf/nginx/03-isolate.conf;
}
include /etc/idleleo/conf/nginx/00-xray.conf;
CONF

ln -sf /usr/sbin/nginx /usr/local/nginx/sbin/nginx
/usr/local/nginx/sbin/nginx -t -p /usr/local/nginx/ -c /usr/local/nginx/conf/nginx.conf 2>&1 | tee /tmp/nginx-before.log

if ! grep -q 'decoy.local' /etc/hosts; then
  printf '127.0.0.1 decoy.local\n' >>/etc/hosts
fi

# isolate -> reject: real nginx -t must accept the dead deny port and no site.
"${bin}" xray guard set --policy reject --container --json | tee /tmp/guard-reject.json
grep -q '"denyPort": *9404' /tmp/guard-reject.json
test ! -e /etc/idleleo/conf/nginx/03-isolate.conf
grep -q '127.0.0.1:9404' /etc/idleleo/conf/nginx/00-xray.conf
/usr/local/nginx/sbin/nginx -t -p /usr/local/nginx/ -c /usr/local/nginx/conf/nginx.conf 2>&1 | tee /tmp/nginx-reject.log
! grep -q '03-isolate.conf' /usr/local/nginx/conf/nginx.conf

# reject -> decoy: self-signed site, real nginx -t, key not world-readable.
"${bin}" xray guard set --policy decoy --decoy-domain decoy.local --container --json | tee /tmp/guard-decoy.json
grep -q '"selfSigned": *true' /tmp/guard-decoy.json
test -s /etc/idleleo/cert/decoy.crt
test -s /etc/idleleo/cert/decoy.key
test "$(stat -c %a /etc/idleleo/cert/decoy.key)" = "600"
grep -q 'server_name decoy.local;' /etc/idleleo/conf/nginx/03-decoy.conf
grep -q 'listen 127.0.0.1:9444 ssl;' /etc/idleleo/conf/nginx/03-decoy.conf
grep -q '03-decoy.conf' /usr/local/nginx/conf/nginx.conf
/usr/local/nginx/sbin/nginx -t -p /usr/local/nginx/ -c /usr/local/nginx/conf/nginx.conf 2>&1 | tee /tmp/nginx-decoy.log

# decoy -> isolate: site switches back, include count stays one.
"${bin}" xray guard set --policy isolate --container --json | tee /tmp/guard-isolate.json
grep -q 'ssl_reject_handshake on;' /etc/idleleo/conf/nginx/03-isolate.conf
grep -q '127.0.0.1:9403' /etc/idleleo/conf/nginx/00-xray.conf
test ! -e /etc/idleleo/conf/nginx/03-decoy.conf
test "$(grep -c '03-isolate.conf' /usr/local/nginx/conf/nginx.conf)" = "1"
/usr/local/nginx/sbin/nginx -t -p /usr/local/nginx/ -c /usr/local/nginx/conf/nginx.conf 2>&1 | tee /tmp/nginx-isolate.log

# Certificate clear on the real root removes only provably project-owned,
# unreferenced material; an unknown file survives.
printf 'cert\n' >/etc/idleleo/cert/xray.crt
printf 'key\n' >/etc/idleleo/cert/xray.key
printf 'third-party\n' >/etc/idleleo/cert/third-party.pem
"${bin}" xray cert clear --yes --container --json | tee /tmp/cert-clear.json
test ! -e /etc/idleleo/cert/xray.crt
test ! -e /etc/idleleo/cert/xray.key
test ! -e /etc/idleleo/cert/decoy.key
test -e /etc/idleleo/cert/third-party.pem
grep -q '"owner": *"unknown"' /tmp/cert-clear.json

echo "OPS-08/OPS-27 real nginx: PASS"
