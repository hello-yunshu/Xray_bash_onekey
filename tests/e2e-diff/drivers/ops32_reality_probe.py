#!/usr/bin/env python3
"""OPS-32 probe for the nginx stream (Reality balance) upstream.

One raw connection per request. The client sends a genuine TLS 1.3 ClientHello
with the configured SNI so nginx's `ssl_preread` + `*.serverNames` map route
the connection to the `reality` upstream, then reads the clear-text marker the
marker backend answers with.

Because the peer is not a Reality server there is no HTTP status and no
Reality handshake here; the transcript records `-` for the status column and
the marker in the body column:

    <epoch>\t<phase>\t<seq>\t<rc>\t-\t<body>

Usage:
    ops32_reality_probe.py <sni> <port> <out> <phase> <count> <interval> [stop_body]
"""

import socket
import ssl
import sys
import time

sni = sys.argv[1]
port = int(sys.argv[2])
out = sys.argv[3]
phase = sys.argv[4]
count = int(sys.argv[5])
interval = float(sys.argv[6])
stop_body = sys.argv[7] if len(sys.argv) > 7 else ""


def client_hello():
    """Bytes of a TLS 1.3 ClientHello carrying the SNI nginx must see."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


hello = client_hello()
with open(out, "w", encoding="utf-8") as fh:
    for seq in range(1, count + 1):
        ts = time.time()
        body = ""
        rc = 0
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.settimeout(5)
                sock.sendall(hello)
                body = sock.recv(64).decode("utf-8", "replace").strip()
                if not body:
                    rc = 1
        except OSError:
            rc = 1
        fh.write("%.3f\t%s\t%d\t%d\t-\t%s\n" % (ts, phase, seq, rc, body))
        fh.flush()
        if stop_body and body == stop_body:
            break
        if interval:
            time.sleep(interval)
