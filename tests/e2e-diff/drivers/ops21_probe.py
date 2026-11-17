#!/usr/bin/env python3
"""OPS-21 control/blocked probe.

Connects through the installed Reality inbound with a real Xray client and asks
the proxy for one target. The outcome distinguishes a refusal (the server
routed the request to the blocked outbound) from a slow network failure:

  ok        response received; "marker" says whether the expected body text was seen
  blocked   SOCKS rejected or the tunnel closed before any HTTP response
  timeout   nothing happened within the timeout; a block must never look like this
  error     the probe client itself failed

Usage: ops21_probe.py URI ADDR PORT TARGET_HOST TARGET_PORT [TIMEOUT_MS]
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse, parse_qs

uri, server_addr, server_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
target_host, target_port = sys.argv[4], int(sys.argv[5])
timeout_ms = int(sys.argv[6]) if len(sys.argv) > 6 else 6000
timeout = timeout_ms / 1000.0

u = urlparse(uri)
q = parse_qs(u.query)
get = lambda k, d="": (q.get(k) or [d])[0]
reality = {
    "serverName": get("sni"),
    "fingerprint": get("fp") or "chrome",
    "publicKey": get("pbk"),
    "shortId": get("sid"),
}
if get("spx"):
    reality["spiderX"] = get("spx")
network = get("type") or "raw"
stream = {"network": network, "security": "reality", "realitySettings": reality}
if network == "ws":
    stream["wsSettings"] = {"path": get("path", "/")}
elif network == "grpc":
    stream["grpcSettings"] = {"serviceName": get("serviceName")}
elif network == "xhttp":
    stream["xhttpSettings"] = {"path": get("path", "/")}
user = {"id": u.username, "encryption": "none"}
if get("flow"):
    user["flow"] = get("flow")

s = socket.socket()
s.bind(("127.0.0.1", 0))
socks_port = s.getsockname()[1]
s.close()
cfg = {
    "log": {"loglevel": "warning"},
    "inbounds": [{"tag": "probe", "listen": "127.0.0.1", "port": socks_port,
                  "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
    "outbounds": [{"tag": "proxy", "protocol": "vless",
                   "settings": {"vnext": [{"address": server_addr, "port": server_port,
                                           "users": [user]}]},
                   "streamSettings": stream}],
}
cfg_file = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump(cfg, cfg_file)
cfg_file.close()
proc = subprocess.Popen(["/usr/local/bin/xray", "run", "-c", cfg_file.name],
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def finish(outcome, detail, started, marker=False):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    os.unlink(cfg_file.name)
    print(json.dumps({
        "outcome": outcome,
        "detail": detail[:200],
        "marker": marker,
        "elapsed_ms": int((time.time() - started) * 1000),
    }))
    sys.exit(0)


def socks_connect():
    c = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    c.settimeout(timeout)
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        raise RuntimeError("socks auth rejected")
    # An IP literal must use ATYP 1/4; sending it as a domain makes some
    # resolvers fail before routing even runs.
    try:
        packed = socket.inet_pton(socket.AF_INET, target_host)
        addr = b"\x01" + packed
    except OSError:
        try:
            packed = socket.inet_pton(socket.AF_INET6, target_host)
            addr = b"\x04" + packed
        except OSError:
            addr = b"\x03" + bytes([len(target_host)]) + target_host.encode()
    c.sendall(b"\x05\x01\x00" + addr + target_port.to_bytes(2, "big"))
    head = c.recv(4)
    if len(head) < 2 or head[1] != 0:
        raise ConnectionRefusedError("socks connect rejected: %r" % head)
    if head[3] == 1:
        c.recv(6)
    elif head[3] == 4:
        c.recv(18)
    elif head[3] == 3:
        n = c.recv(1)[0]
        c.recv(n + 2)
    return c


started = time.time()
try:
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", socks_port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        finish("error", "client socks never opened", started)

    try:
        conn = socks_connect()
    except ConnectionRefusedError as exc:
        finish("blocked", str(exc), started)
    except OSError as exc:
        if isinstance(exc, socket.timeout):
            finish("timeout", "socks connect timed out", started)
        finish("blocked", str(exc), started)

    try:
        conn.sendall(b"GET / HTTP/1.1\r\nHost: " + target_host.encode()
                     + b"\r\nUser-Agent: e2e-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        body = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk
    except socket.timeout:
        finish("timeout", "no response within the timeout", started)
    except OSError as exc:
        finish("blocked", "tunnel closed: %s" % exc, started)
    finally:
        conn.close()

    text = body.decode("utf-8", "replace")
    if not text.strip():
        finish("blocked", "tunnel closed without an HTTP response", started)
    marker = "Example Domain" in text
    if text.startswith("HTTP/1.1 200") or text.startswith("HTTP/1.0 200"):
        finish("ok", text.splitlines()[0], started, marker)
    finish("error", text[:120], started, marker)
except Exception as exc:  # noqa: BLE001 - probe must always report JSON
    finish("error", repr(exc), started)
