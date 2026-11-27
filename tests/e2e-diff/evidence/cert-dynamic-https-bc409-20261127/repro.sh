#!/bin/sh
set -eu
export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY
E=/evidence
trap 'rc=$?; if test -f /usr/local/nginx/logs/error.log; then cp /usr/local/nginx/logs/error.log "$E/nginx-error-final.log"; fi; exit "$rc"' EXIT

mkdir -p /etc/idleleo/cert /etc/idleleo/conf/nginx /etc/idleleo/conf/xray /etc/idleleo/v1 \
  /usr/local/nginx/conf /usr/local/nginx/sbin /root/.acme.sh/owned.local_ecc
ln -sf "$(command -v nginx)" /usr/local/nginx/sbin/nginx

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout /etc/idleleo/cert/owned.key -out /etc/idleleo/cert/owned.crt \
  -subj /CN=owned.local -addext subjectAltName=DNS:owned.local
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout /etc/idleleo/cert/xray.key -out /etc/idleleo/cert/xray.crt \
  -subj /CN=unused.local -addext subjectAltName=DNS:unused.local
chmod 600 /etc/idleleo/cert/*.key

cert_sha=$(sha256sum /etc/idleleo/cert/owned.crt | awk '{print $1}')
key_sha=$(sha256sum /etc/idleleo/cert/owned.key | awk '{print $1}')
xray_cert_sha=$(sha256sum /etc/idleleo/cert/xray.crt | awk '{print $1}')
xray_key_sha=$(sha256sum /etc/idleleo/cert/xray.key | awk '{print $1}')
printf 'managed-by=idleleo\nformat=2\nfile=owned.crt\ttype=regular\tsha256=%s\nfile=owned.key\ttype=regular\tsha256=%s\nfile=xray.crt\ttype=regular\tsha256=%s\nfile=xray.key\ttype=regular\tsha256=%s\n' \
  "$cert_sha" "$key_sha" "$xray_cert_sha" "$xray_key_sha" \
  >/etc/idleleo/cert/.managed-by-idleleo

cp /etc/idleleo/cert/owned.crt /root/.acme.sh/owned.local_ecc/owned.local.cer
cp /etc/idleleo/cert/owned.key /root/.acme.sh/owned.local_ecc/owned.local.key
printf 'third-party account sentinel\n' >/root/.acme.sh/owned.local_ecc/account.conf
printf 'renewal hook sentinel\n' >/root/.acme.sh/owned.local_ecc/renew-hook.sh
find /root/.acme.sh/owned.local_ecc -type f -print0 | sort -z | xargs -0 sha256sum >"$E/acme-before.sha256"

cat >/usr/local/nginx/conf/nginx.conf <<'CONF'
user root;
worker_processes 1;
pid /usr/local/nginx/logs/nginx.pid;
error_log /usr/local/nginx/logs/error.log notice;
events { worker_connections 64; }
http {
    map $ssl_server_name $cert_name { default owned; }
    server {
        listen 127.0.0.1:8443 ssl;
        server_name _;
        ssl_certificate /etc/idleleo/cert/${cert_name}.crt;
        ssl_certificate_key /etc/idleleo/cert/${cert_name}.key;
        location / { return 200 "dynamic-cert-ok\n"; }
    }
}
CONF
mkdir -p /usr/local/nginx/logs

/usr/local/nginx/sbin/nginx -t -p /usr/local/nginx/ -c /usr/local/nginx/conf/nginx.conf \
  >"$E/nginx-before-test.log" 2>&1
/usr/local/nginx/sbin/nginx -p /usr/local/nginx/ -c /usr/local/nginx/conf/nginx.conf
for i in $(seq 1 50); do
  if printf 'GET / HTTP/1.0\r\nHost: owned.local\r\n\r\n' | timeout 5 openssl s_client \
      -connect 127.0.0.1:8443 -servername owned.local -quiet \
      >"$E/https-before.body" 2>"$E/https-before.err"; then break; fi
  sleep 0.1
done
grep -q 'HTTP/1.1 200 OK' "$E/https-before.body"
grep -q 'dynamic-cert-ok' "$E/https-before.body"
openssl s_client -connect 127.0.0.1:8443 -servername owned.local -showcerts </dev/null \
  >"$E/https-before.handshake.log" 2>&1 || true
grep -q 'BEGIN CERTIFICATE' "$E/https-before.handshake.log"
sha256sum /etc/idleleo/cert/owned.crt /etc/idleleo/cert/owned.key \
  /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key >"$E/certs-before.sha256"
stat -c '%a:%U:%G %n' /etc/idleleo/cert/owned.crt /etc/idleleo/cert/owned.key \
  /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key >"$E/certs-before.mode"

idleleo xray cert clear --yes --container --json >"$E/cert-clear.json" 2>"$E/cert-clear.err"
printf '%s\n' "$?" >"$E/cert-clear.rc"

test -s /etc/idleleo/cert/owned.crt
test -s /etc/idleleo/cert/owned.key
test -s /etc/idleleo/cert/xray.crt
test -s /etc/idleleo/cert/xray.key
/usr/local/nginx/sbin/nginx -t -p /usr/local/nginx/ -c /usr/local/nginx/conf/nginx.conf \
  >"$E/nginx-after-test.log" 2>&1
printf 'GET / HTTP/1.0\r\nHost: owned.local\r\n\r\n' | timeout 5 openssl s_client \
  -connect 127.0.0.1:8443 -servername owned.local -quiet \
  >"$E/https-after.body" 2>"$E/https-after.err"
grep -q 'HTTP/1.1 200 OK' "$E/https-after.body"
grep -q 'dynamic-cert-ok' "$E/https-after.body"
openssl s_client -connect 127.0.0.1:8443 -servername owned.local -showcerts </dev/null \
  >"$E/https-after.handshake.log" 2>&1 || true
grep -q 'BEGIN CERTIFICATE' "$E/https-after.handshake.log"
sha256sum /etc/idleleo/cert/owned.crt /etc/idleleo/cert/owned.key >"$E/certs-after.sha256"
stat -c '%a:%U:%G %n' /etc/idleleo/cert/owned.crt /etc/idleleo/cert/owned.key >"$E/certs-after.mode"
find /root/.acme.sh/owned.local_ecc -type f -print0 | sort -z | xargs -0 sha256sum >"$E/acme-after.sha256"
diff -u "$E/acme-before.sha256" "$E/acme-after.sha256" >"$E/acme-diff.txt"

# Once the variable path is replaced by an explicit static reference, the
# owned but unreferenced xray pair is independently eligible for removal.
cat >/usr/local/nginx/conf/nginx.conf <<'CONF'
user root;
worker_processes 1;
pid /usr/local/nginx/logs/nginx.pid;
error_log /usr/local/nginx/logs/error.log notice;
events { worker_connections 64; }
http {
    server {
        listen 127.0.0.1:8443 ssl;
        server_name _;
        ssl_certificate /etc/idleleo/cert/owned.crt;
        ssl_certificate_key /etc/idleleo/cert/owned.key;
        location / { return 200 "static-cert-ok\n"; }
    }
}
CONF
/usr/local/nginx/sbin/nginx -t -p /usr/local/nginx/ -c /usr/local/nginx/conf/nginx.conf \
  >"$E/nginx-static-test.log" 2>&1
idleleo xray cert clear --yes --container --json \
  >"$E/cert-clear-static.json" 2>"$E/cert-clear-static.err"
printf '%s\n' "$?" >"$E/cert-clear-static.rc"
test -s /etc/idleleo/cert/owned.crt
test -s /etc/idleleo/cert/owned.key
test ! -e /etc/idleleo/cert/xray.crt
test ! -e /etc/idleleo/cert/xray.key

nginx -p /usr/local/nginx/ -c /usr/local/nginx/conf/nginx.conf -s quit || true
echo "dynamic TLS HTTPS retained; static reference kept; unused owned pair removed; external ACME tree unchanged"
