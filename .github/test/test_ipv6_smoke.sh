#!/usr/bin/env bash
# Optional real IPv6 socket smoke test (spec 6).
#
# When the runner has IPv6 socket capability this genuinely exercises:
#   - AF_INET6 socket creation
#   - ::1 loopback bind
#   - IPv6 loopback connect + echo round-trip
#   - IPv6 loopback HTTP request via `curl -6` (when curl has IPv6 support)
# When the runner has no IPv6 capability the whole test is SKIP (never PASS).
# A SKIP is reported explicitly and does not count as a success qualification.
#
# Run: bash .github/test/test_ipv6_smoke.sh

set -uo pipefail

PASS=0
FAIL=0
SKIP=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok()   { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP: %s\n' "$1"; }

# --- capability gate: can this runner even open an IPv6 socket? -------------
capability=$(python3 -c '
import socket, sys
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.close()
    sys.stdout.write("OK")
except OSError:
    sys.stdout.write("NO")
' 2>/dev/null)

if [[ "${capability}" != "OK" ]]; then
    skip "runner has no IPv6 socket capability"
    echo
    printf 'IPv6 smoke: 0 pass, %d fail, %d skip\n' "${FAIL}" "${SKIP}"
    exit 0
fi

printf '%s\n' '--- IPv6 loopback socket smoke ---'

# 1. AF_INET6 socket + ::1 bind + connect + echo round-trip
if python3 -c '
import socket, sys
srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("::1", 0))
srv.listen(1)
port = srv.getsockname()[1]
cli = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
cli.connect(("::1", port))
conn, _ = srv.accept()
cli.sendall(b"ping6")
data = conn.recv(16)
conn.close(); cli.close(); srv.close()
sys.exit(0 if data == b"ping6" else 1)
' 2>/dev/null; then
    ok "IPv6 loopback bind + echo round-trip"
else
    bad "IPv6 loopback bind + echo round-trip"
fi

# 2. HTTP request over ::1 via curl -6 (only when curl has IPv6 support)
curl6_ok=0
if command -v curl >/dev/null 2>&1 && curl -V 2>/dev/null | grep -qi ipv6; then
    curl6_ok=1
fi

if [[ ${curl6_ok} -eq 1 ]]; then
    PORT_FILE="${TMP_ROOT}/port"
    python3 -c '
import http.server, socket, sys
class V6Server(http.server.HTTPServer):
    address_family = socket.AF_INET6
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b"v6ok")
    def log_message(self, *a):
        pass
srv = V6Server(("::1", 0), H)
with open(sys.argv[1], "w") as f:
    f.write(str(srv.server_address[1]))
srv.handle_request()
srv.server_close()
' "${PORT_FILE}" &
    srv_pid=$!
    port=""
    for _ in 1 2 3 4 5; do
        [[ -s "${PORT_FILE}" ]] && { port=$(cat "${PORT_FILE}" 2>/dev/null || true); break; }
        sleep 0.2
    done
    if [[ -n "${port}" ]] && out=$(curl -6 -s --max-time 5 "http://[::1]:${port}/" 2>/dev/null) && [[ "${out}" == "v6ok" ]]; then
        ok "curl -6 IPv6 loopback HTTP request"
    else
        bad "curl -6 IPv6 loopback HTTP request"
    fi
    wait "${srv_pid}" 2>/dev/null || true
else
    skip "curl lacks IPv6 support; IPv6 HTTP path not tested"
fi

echo
if [[ ${FAIL} -eq 0 ]]; then
    printf 'IPv6 smoke PASSED: %d pass, %d fail, %d skip\n' "${PASS}" "${FAIL}" "${SKIP}"
else
    printf 'IPv6 smoke FAILED: %d pass, %d fail, %d skip\n' "${PASS}" "${FAIL}" "${SKIP}"
    exit 1
fi
