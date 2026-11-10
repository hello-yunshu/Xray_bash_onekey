#!/usr/bin/env bash
# Relay + Nginx verification:
#   1) project-owned TLS server snippet and stream fragment pass `nginx -t`;
#   2) the stream relay forwards real TCP bytes to a backend.
set -euo pipefail

NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27}"
NGINX_DIGEST="sha256:6784fb0834aa7dbbe12e3d7471e69c290df3e6ba810dc38b34ae33d3c1c05f7d"
BIN_IMAGE="${BIN_IMAGE:-idleleo-phase01-test:1.24}"
WORK="$(mktemp -d)"
NET="idleleo-p02-relay-$$"

cleanup() {
    docker rm -f p02-backend p02-relay >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "== generating relay and TLS snippets =="
docker run --rm -v "$WORK:/work" -v /tmp/idleleo-linux:/bin/idleleo:ro "$BIN_IMAGE" bash -c '
set -e
/bin/idleleo xray generate --mode tls --transport ws --domain example.com \
    --out /work/tls.json --nginx-out /work/tls-server.conf
# Syntax probe uses a resolvable literal target so nginx -t does not depend
# on Docker DNS; the runtime fragment below keeps the service name.
/bin/idleleo xray relay --target 127.0.0.1:9000 --listen-port 9443 --out /work/relay-syntax.conf
/bin/idleleo xray relay --target backend:9000 --listen-port 9443 --out /work/relay.conf
'
cat >"$WORK/nginx-tls-main.conf" <<'EOF'
events {}
http {
    include /work/tls-server.conf;
}
EOF
cat >"$WORK/nginx-stream-main.conf" <<'EOF'
events {}
include /work/relay.conf;
EOF
cat >"$WORK/nginx-stream-syntax.conf" <<'EOF'
events {}
include /work/relay-syntax.conf;
EOF

echo "== nginx -t (TLS server snippet) =="
docker run --rm -v "$WORK:/work" "$NGINX_IMAGE" sh -c '
set -e
mkdir -p /etc/idleleo/cert
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=example.com -days 2 \
    -keyout /etc/idleleo/cert/example.com.key \
    -out /etc/idleleo/cert/example.com.crt >/dev/null 2>&1
nginx -t -c /work/nginx-tls-main.conf
'

echo "== nginx -t (stream relay syntax) =="
docker run --rm -v "$WORK:/work" "$NGINX_IMAGE" nginx -t -c /work/nginx-stream-syntax.conf

echo "== real TCP forwarding through nginx stream relay =="
docker network create "$NET" >/dev/null
docker run -d --name p02-backend --network "$NET" --network-alias backend busybox:1.36 sh -c \
    'while true; do nc -l -p 9000 -e /bin/cat; done' >/dev/null
docker run --rm --network "$NET" -v "$WORK:/work" "$NGINX_IMAGE" nginx -t -c /work/nginx-stream-main.conf
docker run -d --name p02-relay --network "$NET" \
    -v "$WORK/relay.conf:/etc/nginx/stream.d/relay.conf:ro" "$NGINX_IMAGE" \
    sh -c 'printf "events {}\ninclude /etc/nginx/stream.d/*.conf;\n" > /etc/nginx/nginx.conf; exec nginx -g "daemon off;"' >/dev/null
sleep 2
got=$(docker run --rm --network "$NET" busybox:1.36 sh -c '(printf PING; sleep 2) | nc -w 5 p02-relay 9443')
if [[ "$got" == "PING" ]]; then
    echo "PASS relay TCP bytes forwarded (PING echoed)"
else
    echo "FAIL relay TCP forwarding (got: ${got:-empty})"
    docker logs p02-relay | tail -20
    exit 1
fi
echo "nginx-image: $NGINX_IMAGE $NGINX_DIGEST"
