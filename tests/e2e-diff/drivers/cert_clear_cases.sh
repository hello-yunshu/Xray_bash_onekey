#!/bin/sh
# Real-root certificate-clear cases. Run inside a disposable nginx image as
# root with the idleleo binary mounted at /usr/local/bin/idleleo.
#
# Every case builds a real Nginx configuration, runs `nginx -t` before and after
# `idleleo xray cert clear`, and prints one machine-readable line per case.
# The same script is used against the audit HEAD (red) and the fixed binary.
set -u

BIN=/usr/local/bin/idleleo
export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY
MAIN=/usr/local/nginx/conf/nginx.conf
NGINX=/usr/local/nginx/sbin/nginx
FAILED=0

reset() {
    rm -rf /etc/idleleo /usr/local/nginx /opt/third /etc/nginx /var/lib/idleleo /root/.acme.sh
    rm -f /tmp/nginx-error.log /tmp/nginx.pid /tmp/cert-clear.json
    mkdir -p /etc/idleleo/cert /etc/idleleo/conf/nginx /etc/idleleo/conf/xray \
        /etc/idleleo/v1 /usr/local/nginx/conf /usr/local/nginx/sbin \
        /usr/local/nginx/logs /opt/third
    ln -sf /usr/sbin/nginx "$NGINX"
}

base_main() {
    {
        printf 'worker_processes 1;\n'
        printf 'error_log /tmp/nginx-error.log;\n'
        printf 'pid /tmp/nginx.pid;\n'
        printf 'events { worker_connections 64; }\n'
    } >"$MAIN"
}

genpair() { # cert key
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$2" -out "$1" \
        -subj /CN=node.example.com -addext subjectAltName=DNS:node.example.com >/dev/null 2>&1
}

nginx_t() { "$NGINX" -t -p /usr/local/nginx/ -c "$MAIN" >/tmp/nginx-t.log 2>&1; }

clear_certs() {
    "$BIN" xray cert clear --yes --container --json >/tmp/cert-clear.json 2>/tmp/cert-clear.err
    echo $?
}

removed_count() {
    awk '/^[[:space:]]*"removed": \[$/{f=1;next} f&&/^[[:space:]]*\][[:space:]]*,?$/{f=0} f&&/"/{n++} END{print n+0}' \
        /tmp/cert-clear.json 2>/dev/null || echo -1
}

has_warning() {
    ! grep -q '"warnings": \[\]' /tmp/cert-clear.json 2>/dev/null
}

report() { # name expected actual -> pass/fail
    if [ "$2" = "$3" ]; then
        echo "CASE $1 PASS ($3)"
    else
        echo "CASE $1 FAIL (expected $2, got $3)"
        FAILED=$((FAILED + 1))
    fi
}

# --- 1. two certificate directives on one physical line --------------------
reset
base_main
genpair /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
cat >>"$MAIN" <<'CONF'
http {
    server {
        listen 9443 ssl;
        ssl_certificate /etc/idleleo/cert/xray.crt; ssl_certificate_key /etc/idleleo/cert/xray.key;
    }
}
CONF
nginx_t; before=$?
rc=$(clear_certs)
nginx_t; after=$?
exists=0
[ -e /etc/idleleo/cert/xray.crt ] && [ -e /etc/idleleo/cert/xray.key ] && exists=1
report inline-multi "rc=0 before=0 after=0 kept=1 removed=0" "rc=$rc before=$before after=$after kept=$exists removed=$(removed_count)"

# --- 2. certificate directives through an include outside the managed dir ---
reset
base_main
genpair /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
cat >>"$MAIN" <<'CONF'
http {
    include /opt/third/site.conf;
}
CONF
cat >/opt/third/site.conf <<'CONF'
server {
    listen 9443 ssl;
    ssl_certificate /etc/idleleo/cert/xray.crt;
    ssl_certificate_key /etc/idleleo/cert/xray.key;
}
CONF
nginx_t; before=$?
rc=$(clear_certs)
nginx_t; after=$?
exists=0
[ -e /etc/idleleo/cert/xray.crt ] && [ -e /etc/idleleo/cert/xray.key ] && exists=1
report external-include "rc=0 before=0 after=0 kept=1 removed=0" "rc=$rc before=$before after=$after kept=$exists removed=$(removed_count)"

# --- 3. reference through a symlink alias ----------------------------------
reset
base_main
genpair /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
mkdir -p /etc/nginx
ln -sf /etc/idleleo/cert/xray.crt /etc/nginx/alias.crt
ln -sf /etc/idleleo/cert/xray.key /etc/nginx/alias.key
cat >>"$MAIN" <<'CONF'
http {
    include /etc/nginx/site.conf;
}
CONF
cat >/etc/nginx/site.conf <<'CONF'
server {
    listen 9443 ssl;
    ssl_certificate /etc/nginx/alias.crt;
    ssl_certificate_key /etc/nginx/alias.key;
}
CONF
nginx_t; before=$?
rc=$(clear_certs)
nginx_t; after=$?
exists=0
[ -e /etc/idleleo/cert/xray.crt ] && [ -e /etc/idleleo/cert/xray.key ] && exists=1
report symlink-alias "rc=0 before=0 after=0 kept=1 removed=0" "rc=$rc before=$before after=$after kept=$exists removed=$(removed_count)"

# --- 4. variable certificate path: fail closed -----------------------------
reset
base_main
genpair /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
cat >>"$MAIN" <<'CONF'
http {
    server {
        listen 9443 ssl;
        ssl_certificate $ssl_server_name.crt;
        ssl_certificate_key $ssl_server_name.key;
    }
}
CONF
nginx_t; before=$?
rc=$(clear_certs)
nginx_t; after=$?
exists=0
[ -e /etc/idleleo/cert/xray.crt ] && [ -e /etc/idleleo/cert/xray.key ] && exists=1
report variable-path "rc=0 before=0 after=0 kept=1 removed=0" "rc=$rc before=$before after=$after kept=$exists removed=$(removed_count)"

# --- 5. a second Xray config references the pair ---------------------------
reset
base_main
genpair /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
cat >>"$MAIN" <<'CONF'
http {
    server { listen 9080; location / { return 200 "ok\n"; } }
}
CONF
printf '{"inbounds":[]}\n' >/etc/idleleo/conf/xray/config.json
cat >/etc/idleleo/conf/xray/second.json <<'JSON'
{"inbounds":[{"streamSettings":{"tlsSettings":{"certificates":[{"certificateFile":"/etc/idleleo/cert/xray.crt","keyFile":"/etc/idleleo/cert/xray.key"}]}}}]}
JSON
nginx_t; before=$?
rc=$(clear_certs)
nginx_t; after=$?
exists=0
[ -e /etc/idleleo/cert/xray.crt ] && [ -e /etc/idleleo/cert/xray.key ] && exists=1
report xray-second-config "rc=0 before=0 after=0 kept=1 removed=0" "rc=$rc before=$before after=$after kept=$exists removed=$(removed_count)"

# --- 6. unused project pair is removable, third-party canary survives ------
reset
base_main
genpair /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
printf 'third-party\n' >/etc/idleleo/cert/third-party.pem
cat >>"$MAIN" <<'CONF'
http {
    server { listen 9080; location / { return 200 "ok\n"; } }
}
CONF
rc=$(clear_certs)
removed=0
[ -e /etc/idleleo/cert/xray.crt ] || removed=$((removed + 1))
[ -e /etc/idleleo/cert/xray.key ] || removed=$((removed + 1))
canary=0
[ -e /etc/idleleo/cert/third-party.pem ] && canary=1
nginx_t; after=$?
report unused-pair "rc=0 removed=2 canary=1 after=0" "rc=$rc removed=$removed canary=$canary after=$after"

# --- 7. broken include chain: keep everything (fail closed) ---------------
reset
base_main
genpair /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
cat >>"$MAIN" <<'CONF'
http {
    include /opt/third/missing.conf;
}
CONF
nginx_t; before=$?
rc=$(clear_certs)
exists=0
[ -e /etc/idleleo/cert/xray.crt ] && [ -e /etc/idleleo/cert/xray.key ] && exists=1
warn=0
has_warning && warn=1
before_state=ok
[ "$before" -ne 0 ] && before_state=broken
report broken-config "rc=0 before=broken kept=1 removed=0 warn=1" "rc=$rc before=$before_state kept=$exists removed=$(removed_count) warn=$warn"

# --- 8. quoted directives with extra spaces on one line --------------------
reset
base_main
genpair /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
cat >>"$MAIN" <<'CONF'
http {
    server {
        listen 9443 ssl;
        ssl_certificate     "/etc/idleleo/cert/xray.crt";    ssl_certificate_key   "/etc/idleleo/cert/xray.key";
    }
}
CONF
nginx_t; before=$?
rc=$(clear_certs)
nginx_t; after=$?
exists=0
[ -e /etc/idleleo/cert/xray.crt ] && [ -e /etc/idleleo/cert/xray.key ] && exists=1
report quoted-inline "rc=0 before=0 after=0 kept=1 removed=0" "rc=$rc before=$before after=$after kept=$exists removed=$(removed_count)"

# --- 9. invalid Nginx config with a complete scan: refuse before deleting --
reset
base_main
genpair /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
cat >>"$MAIN" <<'CONF'
this_is_not_a_directive;
http {
    server { listen 9080; location / { return 200 "ok\n"; } }
}
CONF
nginx_t; before=$?
rc=$(clear_certs)
exists=0
[ -e /etc/idleleo/cert/xray.crt ] && [ -e /etc/idleleo/cert/xray.key ] && exists=1
rc_state=ok
[ "$rc" -ne 0 ] && rc_state=refused
before_state=ok
[ "$before" -ne 0 ] && before_state=broken
report invalid-nginx-refuse "rc=refused before=broken kept=1" "rc=$rc_state before=$before_state kept=$exists"

# --- 10. fault injection: post-move nginx -t failure rolls back ------------
reset
base_main
genpair /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
cat >>"$MAIN" <<'CONF'
http {
    server { listen 9080; location / { return 200 "ok\n"; } }
}
CONF
rm -f /tmp/nginx-calls
rm -f "$NGINX"
cat >"$NGINX" <<'FAKE'
#!/bin/sh
n=$(cat /tmp/nginx-calls 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" >/tmp/nginx-calls
if [ "$n" -ge 2 ]; then
    echo "injected post-change failure" >&2
    exit 1
fi
exec /usr/sbin/nginx "$@"
FAKE
chmod +x "$NGINX"
rc=$(clear_certs)
exists=0
[ -e /etc/idleleo/cert/xray.crt ] && [ -e /etc/idleleo/cert/xray.key ] && exists=1
rm -f "$NGINX"
ln -sf /usr/sbin/nginx "$NGINX"
nginx_t; after=$?
rc_state=ok
[ "$rc" -ne 0 ] && rc_state=refused
report rollback-fault "rc=refused kept=1 after=0" "rc=$rc_state kept=$exists after=$after"

echo "CERT_CLEAR_SUMMARY failed=$FAILED"
[ "$FAILED" -eq 0 ]
