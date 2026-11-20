#!/bin/sh
# Real-root SNI guard inspection cases. Run inside a disposable nginx image as
# root with the idleleo binary mounted at /usr/local/bin/idleleo.
set -u

BIN=/usr/local/bin/idleleo
MAIN=/usr/local/nginx/conf/nginx.conf
NGINX=/usr/local/nginx/sbin/nginx
FAILED=0

reset() {
    [ -f /usr/local/nginx/logs/nginx.pid ] && "$NGINX" -s stop -p /usr/local/nginx/ -c "$MAIN" >/dev/null 2>&1
    rm -rf /etc/idleleo /usr/local/nginx
    mkdir -p /etc/idleleo/cert /etc/idleleo/conf/nginx /etc/idleleo/conf/xray \
        /etc/idleleo/v1 /usr/local/nginx/conf /usr/local/nginx/sbin /usr/local/nginx/logs
    ln -sf /usr/sbin/nginx "$NGINX"
    printf 'worker_processes 1;\nerror_log /tmp/nginx-error.log;\npid /usr/local/nginx/logs/nginx.pid;\nevents { worker_connections 64; }\n' >"$MAIN"
}

write_front() { # deny-port
    cat >/etc/idleleo/conf/nginx/00-xray.conf <<CONF
stream {
    map \$ssl_preread_server_name \$sni_upstream {
        include /etc/idleleo/conf/nginx/*.serverNames;
        default deny;
    }
    upstream deny {
        server 127.0.0.1:$1;
    }
}
CONF
}

write_isolate() {
    cat >/etc/idleleo/conf/nginx/03-isolate.conf <<'CONF'
server {
    listen 127.0.0.1:9403 ssl;
    ssl_reject_handshake on;
}
CONF
}

includes_isolate() { # deny-port
    cat >>"$MAIN" <<CONF
stream {
    map \$ssl_preread_server_name \$sni_upstream {
        include /etc/idleleo/conf/nginx/*.serverNames;
        default deny;
    }
    upstream deny {
        server 127.0.0.1:$1;
    }
    include /etc/idleleo/conf/nginx/03-isolate.conf;
}
CONF
}

show() {
    "$BIN" xray guard show --json >/tmp/guard.json 2>/tmp/guard.err
    echo $?
}

field() { # name (string value)
    sed -n "s/.*\"$1\": \"\\([^\"]*\\)\".*/\\1/p" /tmp/guard.json | head -1
}

num() { # name (numeric value)
    sed -n "s/.*\"$1\": \\([0-9][0-9]*\\).*/\\1/p" /tmp/guard.json | head -1
}

report() {
    if [ "$2" = "$3" ]; then
        echo "CASE $1 PASS ($3)"
    else
        echo "CASE $1 FAIL (expected $2, got $3)"
        FAILED=$((FAILED + 1))
    fi
}

# --- 1. consistent isolate files, nginx not running -> configured ----------
reset
write_front 9403
write_isolate
includes_isolate 9403
rc=$(show)
report configured-isolate "rc=0 status=configured policy=isolate deny=9403" \
    "rc=$rc status=$(field status) policy=$(field policy) deny=$(num denyPort)"

# --- 2. deny points at isolate port but the fragment is missing ------------
reset
write_front 9403
includes_isolate 9403
rc=$(show)
report missing-fragment "rc=0 status=inconsistent policy=" \
    "rc=$rc status=$(field status) policy=$(field policy)"

# --- 3. main config cannot be read (deleted) -------------------------------
reset
write_front 9403
write_isolate
rm -f "$MAIN"
rc=$(show)
report missing-main "rc=0 status=inconsistent" "rc=$rc status=$(field status)"

# --- 4. main config cannot be read (a directory) ---------------------------
reset
write_front 9403
write_isolate
rm -f "$MAIN"
mkdir -p "$MAIN"
rc=$(show)
report unreadable-main "rc=0 status=inconsistent" "rc=$rc status=$(field status)"

# --- 5. nginx really running -> active -------------------------------------
reset
write_front 9403
write_isolate
includes_isolate 9403
"$NGINX" -p /usr/local/nginx/ -c "$MAIN" >/dev/null 2>&1
started=0
[ -s /usr/local/nginx/logs/nginx.pid ] && started=1
rc=$(show)
report active-running "rc=0 started=1 status=active policy=isolate" \
    "rc=$rc started=$started status=$(field status) policy=$(field policy)"
"$NGINX" -s stop -p /usr/local/nginx/ -c "$MAIN" >/dev/null 2>&1

# --- 6. reject policy is the documented baseline ---------------------------
reset
write_front 9404
includes_isolate 9404
rc=$(show)
report reject-configured "rc=0 status=configured policy=reject deny=9404" \
    "rc=$rc status=$(field status) policy=$(field policy) deny=$(num denyPort)"

echo "GUARD_SUMMARY failed=$FAILED"
[ "$FAILED" -eq 0 ]
