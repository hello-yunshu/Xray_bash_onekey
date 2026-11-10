#!/usr/bin/env bash
# Runs inside the disposable container. Loads the Go-generated stream conf into
# a real Nginx (stream module), puts two TCP backends behind it, and proves:
#   1. a matching SNI + TLSv1.3 is round-robined across both backends
#   2. an unknown SNI never reaches a backend (isolate deny path)
#   3. a non-TLS connection never reaches a backend
# Labelled DOCKER_BALANCE_SIMULATED: this validates the routing layer only.
set -euo pipefail

OUT="${BAL_OUT:?BAL_OUT required}"
GO_BIN="${BAL_GO_BIN:?BAL_GO_BIN required}"
PORT="${BAL_PORT:-8443}"
SERVERNAME="${BAL_SERVERNAME:-www.cloudflare.com}"
UUID_VALUE="${BAL_UUID:?BAL_UUID required}"
PRIVATE_KEY="${BAL_PRIVATE_KEY:?BAL_PRIVATE_KEY required}"
SHORT_ID="${BAL_SHORT_ID:?BAL_SHORT_ID required}"
FRAGS="/etc/idleleo/conf/nginx"
LOGS="/usr/local/nginx/logs"
BASH_DIR="$OUT/primary/bash"
SIM="$OUT/primary/sim"
mkdir -p "$FRAGS" "$LOGS" "$SIM"
: >"$SIM/result.txt"

mkdir -p /usr/local/nginx/conf

# ---- 1. Bash-generated conf must also pass nginx -t -----------------------
cp "$BASH_DIR/fragments/"*.realityServers "$BASH_DIR/fragments/"*.serverNames "$FRAGS/"
cp "$BASH_DIR/fragments/03-isolate.conf" "$FRAGS/"
cp "$BASH_DIR/nginx/00-xray.conf" "$FRAGS/00-xray.conf"
cat >/usr/local/nginx/conf/nginx.conf <<EOF
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
worker_processes 1;
error_log /tmp/nginx-bash-error.log notice;
pid /tmp/nginx-bash.pid;
events { worker_connections 256; }
http { include $FRAGS/03-isolate.conf; }
include $FRAGS/00-xray.conf;
EOF
set +e
nginx -t -c /usr/local/nginx/conf/nginx.conf >"$SIM/nginx-test-bash.log" 2>&1
bash_test=$?
set -e
printf 'bash_nginx_test_exit=%s\n' "$bash_test" >>"$SIM/result.txt"

# ---- 2. Go-generated conf with two backends -------------------------------
rm -rf "$SIM/go-fragments"
"$GO_BIN" xray generate \
    --mode reality-balance --role primary --port "$PORT" \
    --server-names "$SERVERNAME" --target "$SERVERNAME:443" \
    --uuid "$UUID_VALUE" --private-key "$PRIVATE_KEY" --short-id "$SHORT_ID" \
    --backend 127.0.0.1:9443 --backend 127.0.0.1:9444 \
    --out "$SIM/go-runtime.json" --nginx-out "$FRAGS/00-xray.conf" \
    --fragments-out "$SIM/go-fragments" --force --json >"$SIM/go-generate.json"

rm -f "$FRAGS"/*.realityServers "$FRAGS"/*.serverNames "$FRAGS/03-isolate.conf"
cp "$SIM/go-fragments/"*.realityServers "$SIM/go-fragments/"*.serverNames "$FRAGS/"
cp "$SIM/go-fragments/03-isolate.conf" "$FRAGS/"
cat >/usr/local/nginx/conf/nginx.conf <<EOF
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
worker_processes 1;
error_log /tmp/nginx-go-error.log notice;
pid /tmp/nginx-go.pid;
events { worker_connections 256; }
http { include $FRAGS/03-isolate.conf; }
include $FRAGS/00-xray.conf;
EOF
set +e
nginx -t -c /usr/local/nginx/conf/nginx.conf >"$SIM/nginx-test-go.log" 2>&1
go_test=$?
set -e
printf 'go_nginx_test_exit=%s\n' "$go_test" >>"$SIM/result.txt"
[[ "$bash_test" -eq 0 && "$go_test" -eq 0 ]] || {
    echo "nginx -t failed (bash=$bash_test go=$go_test)" >&2
    cat "$SIM/nginx-test-bash.log" "$SIM/nginx-test-go.log" >&2
    exit 1
}

# ---- 3. backends + nginx --------------------------------------------------
python3 /src/tests/go-parity/balance/backends.py 9443 9444 "$SIM" &
backends_pid=$!
nginx -c /usr/local/nginx/conf/nginx.conf
for _ in $(seq 1 20); do
    ss -lnt 2>/dev/null | grep -q ":$PORT" && break
    sleep 0.2
done
ss -lntp >"$SIM/listeners.txt" 2>&1 || true

hits() { cat "$SIM/hits-9443.txt"; }
hits4() { cat "$SIM/hits-9444.txt"; }

# matching SNI, TLS1.3
for _ in $(seq 1 6); do
    timeout 3 openssl s_client -connect "127.0.0.1:$PORT" \
        -servername "$SERVERNAME" -tls1_3 </dev/null >/dev/null 2>&1 || true
done
sleep 0.3
before3=$(hits)
before4=$(hits4)
printf 'after_valid_sni hits_9443=%s hits_9444=%s\n' "$before3" "$before4" >>"$SIM/result.txt"

# unknown SNI must be denied and must not touch a backend
for _ in $(seq 1 3); do
    timeout 3 openssl s_client -connect "127.0.0.1:$PORT" \
        -servername unknown.example -tls1_3 </dev/null >/dev/null 2>&1 || true
done
sleep 0.3
after_unknown_3=$(hits)
after_unknown_4=$(hits4)
printf 'after_unknown_sni hits_9443=%s hits_9444=%s\n' "$after_unknown_3" "$after_unknown_4" >>"$SIM/result.txt"

# non-TLS must be denied and must not touch a backend
python3 - "$PORT" <<'PY' || true
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
try:
    s.recv(64)
except Exception:
    pass
s.close()
PY
sleep 0.3
after_plain_3=$(hits)
after_plain_4=$(hits4)
printf 'after_plain_tcp hits_9443=%s hits_9444=%s\n' "$after_plain_3" "$after_plain_4" >>"$SIM/result.txt"

# ---- assertions ----------------------------------------------------------
total=$(( before3 + before4 ))
fail=0
[[ "$total" -ge 6 ]] || { echo "expected 6 backend hits, got $total" >>"$SIM/result.txt"; fail=1; }
[[ "$before3" -gt 0 && "$before4" -gt 0 ]] || { echo "round-robin did not reach both backends" >>"$SIM/result.txt"; fail=1; }
[[ "$after_unknown_3" == "$before3" && "$after_unknown_4" == "$before4" ]] || {
    echo "unknown SNI reached a backend" >>"$SIM/result.txt"; fail=1; }
[[ "$after_plain_3" == "$before3" && "$after_plain_4" == "$before4" ]] || {
    echo "non-TLS traffic reached a backend" >>"$SIM/result.txt"; fail=1; }

nginx -s stop -c /usr/local/nginx/conf/nginx.conf 2>/dev/null || true
kill "$backends_pid" 2>/dev/null || true
cat "$SIM/result.txt"
if [[ "$fail" -ne 0 ]]; then
    exit 1
fi
printf 'sim=PASS\n' >>"$SIM/result.txt"
