#!/usr/bin/env python3
"""Two plain TCP backends used to prove the Nginx stream layer routes by SNI.

Each accepted connection is recorded in a counter file; the socket is closed
immediately so `openssl s_client` returns after sending its ClientHello. This is
a DOCKER_BALANCE_SIMULATED test of the routing layer, not a Reality handshake.
"""
import socket
import sys
import threading
from pathlib import Path


def serve(port: int, counter: Path):
    counter.write_text("0\n")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        n = int(counter.read_text().strip() or "0") + 1
        counter.write_text(f"{n}\n")
        conn.close()


def main():
    ports = [int(p) for p in sys.argv[1:3]]
    root = Path(sys.argv[3])
    root.mkdir(parents=True, exist_ok=True)
    threads = [threading.Thread(target=serve, args=(p, root / f"hits-{p}.txt"), daemon=True)
               for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
