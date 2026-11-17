#!/usr/bin/env python3
"""OPS-32 marker backend for the nginx stream (Reality balance) upstream.

It is a plain TCP peer, not a Reality server: it consumes the bytes nginx
forwards and answers with the marker. The client still sends a real TLS 1.3
ClientHello because nginx runs `ssl_preread` and the `*.serverNames` map needs
an SNI to pick the `reality` upstream. Nothing after that is TLS.

That limitation is deliberate: this scenario measures nginx's stream peer
selection and `max_fails`/`fail_timeout` removal, which happen at connect time
and are independent of the Reality handshake. It does not prove an end-to-end
Reality/VLESS session.

One line is appended per served connection:

    <epoch>  <marker>

Usage:
    python3 ops32_reality_backend.py <marker> <port> <request-log>
"""

import socket
import sys
import threading
import time

marker = sys.argv[1]
port = int(sys.argv[2])
request_log = sys.argv[3]

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(256)


def handle(conn):
    try:
        conn.settimeout(10)
        conn.recv(4096)
        with open(request_log, "a", encoding="utf-8") as fh:
            fh.write("%.3f\t%s\n" % (time.time(), marker))
        conn.sendall(marker.encode())
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
