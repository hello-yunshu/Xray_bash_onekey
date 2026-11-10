#!/usr/bin/env bash
# Real end-to-end Reality primary/secondary verification inside one disposable
# container: real Xray primary + secondary, real Nginx stream SNI guard, real
# Reality client traffic over Socks, real backend failure and recovery.
set -uo pipefail
OUT=/e2e/out
mkdir -p "$OUT" /etc/idleleo/conf/nginx /usr/local/nginx/logs /var/log/xray
: >"$OUT/assertions.log"
FAIL=0
record() {
    echo "$1" | tee -a "$OUT/assertions.log"
    case "$1" in FAIL*) FAIL=1 ;; esac
}

# Per-process access logs so backend routing is observable without sharing a file.
python3 - <<'PY'
import json
for name in ("primary", "secondary", "client"):
    path = f"/e2e/conf/{name}.json"
    cfg = json.load(open(path))
    cfg.setdefault("log", {})["access"] = f"/e2e/out/{name}-access.log"
    cfg["log"]["error"] = f"/e2e/out/{name}-error.log"
    cfg["log"]["loglevel"] = "warning"
    json.dump(cfg, open(path, "w"), indent=2)
PY

wait_port() {
    python3 - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(80):
    try:
        s = socket.create_connection(("127.0.0.1", port), 0.2)
        s.close()
        raise SystemExit(0)
    except Exception:
        time.sleep(0.1)
raise SystemExit(1)
PY
}

/usr/local/bin/xray -config /e2e/conf/secondary.json >"$OUT/secondary.out" 2>&1 &
SEC_PID=$!
/usr/local/bin/xray -config /e2e/conf/primary.json >"$OUT/primary.out" 2>&1 &
PRI_PID=$!
/usr/local/bin/xray -config /e2e/conf/client.json >"$OUT/client.out" 2>&1 &
CLI_PID=$!
cp -a /e2e/nginx/. /etc/idleleo/conf/nginx/
nginx -t -c /nginx-wrapper.conf >"$OUT/nginx-test.log" 2>&1
if [ $? -ne 0 ]; then
    record "FAIL nginx -t rejected the generated stream artifacts"
    cat "$OUT/nginx-test.log" >>"$OUT/assertions.log"
    exit 1
fi
record "PASS nginx -t accepted the generated stream artifacts"
nginx -c /nginx-wrapper.conf
NGX_PID=$(cat "$OUT/nginx.pid" 2>/dev/null || true)
for port in 9443 10444 1081 8443; do
    if ! wait_port "$port"; then record "FAIL port $port did not open"; exit 1; fi
done
( for i in $(seq 1 80); do
    alive=$(kill -0 "$SEC_PID" 2>/dev/null && echo 1 || echo 0)
    printf '%s sec sec_alive=%s sec_port=%s\n' "$i" "$alive" "$(ss -ltn 2>/dev/null | grep -c ':10444')"
    sleep 1
  done ) >"$OUT/sec-monitor.log" 2>&1 &
MON_PID=$!

hit() {
    curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
        -x socks5h://127.0.0.1:1081 "$REQ_URL"
}
ok_code() {
    case "$1" in 2*|3*) return 0 ;; *) return 1 ;; esac
}
lines() { wc -l <"$1" 2>/dev/null | tr -d ' '; }

REQ_URL=${E2E_REQ_URL:-http://example.com/}
curl -v -o /dev/null --max-time 8 -x socks5h://127.0.0.1:1081 \
    "$REQ_URL" >"$OUT/probe.log" 2>&1 || true

round=1
ok=0
for _ in 1 2 3 4 5 6; do
    code=$(hit || true)
    if ! ok_code "$code"; then
        # Reality may need one warm-up handshake on a cold target.
        sleep 1
        code=$(hit || true)
    fi
    ok_code "$code" && ok=$((ok + 1))
    round=$((round + 1))
done
b_pri=$(lines "$OUT/primary-access.log")
b_sec=$(lines "$OUT/secondary-access.log")
record "INFO round-robin http200=$ok/6 primary=$b_pri secondary=$b_sec"
if [ "$ok" -eq 6 ] && [ "$b_pri" -gt 0 ] && [ "$b_sec" -gt 0 ]; then
    record "PASS both backends served real Reality traffic"
else
    record "FAIL round-robin did not hit both backends"
fi

# Backend failure: stop the secondary and prove the primary still serves.
kill "$SEC_PID" 2>/dev/null
sleep 1
ok=0
for _ in 1 2 3 4 5 6 7 8; do
    code=$(hit || true)
    ok_code "$code" && ok=$((ok + 1))
done
a_pri=$(lines "$OUT/primary-access.log")
a_sec=$(lines "$OUT/secondary-access.log")
record "INFO secondary-down http200=$ok/8 primary=$a_pri secondary=$a_sec"
if [ "$ok" -eq 8 ] && [ "$a_sec" = "$b_sec" ]; then
    record "PASS traffic continued on the primary after secondary failure"
else
    record "FAIL primary did not absorb secondary failure"
fi

# Recovery: restart the secondary and require traffic to reach it again. The
# upstream marks a failed peer down for fail_timeout=10s, so poll for up to 30s
# instead of assuming an exact instant.
/usr/local/bin/xray -config /e2e/conf/secondary.json >"$OUT/secondary-restart.out" 2>&1 &
SEC_PID=$!
if ! wait_port 10444; then record "FAIL secondary did not restart"; fi
ok=0
tries=0
rejoined=0
for _ in $(seq 1 30); do
    code=$(hit || true)
    ok_code "$code" && ok=$((ok + 1))
    tries=$((tries + 1))
    r_sec=$(lines "$OUT/secondary-access.log")
    if [ "$r_sec" -gt "$a_sec" ]; then rejoined=1; break; fi
    sleep 1
done
r_pri=$(lines "$OUT/primary-access.log")
record "INFO recovered http_ok=$ok/$tries primary=$r_pri secondary=$r_sec rejoined=$rejoined"
if [ "$rejoined" -eq 1 ] && [ "$ok" -ge 6 ]; then
    record "PASS secondary rejoined and served traffic after recovery"
else
    record "FAIL secondary did not rejoin after recovery"
fi

# Unknown SNI must be refused by the isolate ssl_reject_handshake server.
timeout 8 openssl s_client -connect 127.0.0.1:8443 -servername wrong.example -quiet </dev/null >"$OUT/unknown-sni.log" 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
    record "PASS unknown SNI refused (openssl exit $rc)"
else
    record "FAIL unknown SNI was accepted"
fi

python3 - "$OUT/summary.json" "$FAIL" <<'PY'
import json, sys
lines = [line.strip() for line in open("/e2e/out/assertions.log") if line.strip()]
summary = {
    "evidence": "REAL_NGINX_REAL_XRAY_E2E",
    "containerOnly": True,
    "failures": int(sys.argv[2]),
    "assertions": lines,
    "roundRobin": {"primary": sum("primary=" in x for x in lines), "secondary": sum("secondary=" in x for x in lines)},
}
json.dump(summary, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY

kill "$NGX_PID" "$SEC_PID" "$PRI_PID" "$CLI_PID" 2>/dev/null
wait 2>/dev/null
cat "$OUT/assertions.log"
exit "$FAIL"
