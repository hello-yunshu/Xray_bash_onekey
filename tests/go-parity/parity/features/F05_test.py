#!/usr/bin/env python3
"""F05 — standalone relay fragment and real byte forwarding.

Preview evidence level: CONTAINER_VERIFIED.

The fixture renders the project-owned Nginx stream fragment, proves it passes
`nginx -t`, then starts a dedicated Nginx (own prefix/pid/logs, never the system
one) and forwards real TCP bytes through it to a local echo server. Ports are
allocated at runtime, so repeated runs do not collide with F01's 8443.
"""
import json
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402


class EchoServer:
    """Local TCP echo backend; the port stays bound for the whole fixture."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_port(port, deadline):
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def roundtrip(port, payload, timeout=10):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        received = b""
        while len(received) < len(payload):
            chunk = sock.recv(4096)
            if not chunk:
                break
            received += chunk
        return received


def stream_module_line(f):
    r = f.run(["nginx", "-V"], timeout=15)
    version = (r.out or "") + (r.err or "")
    if "with-stream=dynamic" not in version:
        return ""
    for candidate in ("/usr/lib/nginx/modules/ngx_stream_module.so",
                      "/usr/lib64/nginx/modules/ngx_stream_module.so"):
        if Path(candidate).is_file():
            return f"load_module {candidate};"
    f.need(False, "nginx has a dynamic stream module but the module file is missing")
    return ""


def nginx_config(prefix, relay_conf, module_line):
    return f"""{module_line}
worker_processes 1;
pid {prefix}/nginx.pid;
error_log {prefix}/nginx-error.log warn;

events {{ worker_connections 64; }}

include {relay_conf};
"""


def stop_nginx(f, conf, prefix):
    pid_file = prefix / "nginx.pid"
    f.run(["nginx", "-s", "quit", "-c", str(conf), "-p", str(prefix)], timeout=15)
    for _ in range(50):
        if not pid_file.exists():
            return
        time.sleep(0.1)
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text().strip()), signal.SIGKILL)
        except (ValueError, OSError):
            pass


def main(f):
    f.need_root()
    f.need_tool("nginx")
    before = f.tree_digest("/etc/idleleo")

    prefix = f.evidence / "nginx"
    prefix.mkdir(parents=True, exist_ok=True)
    relay_conf = prefix / "relay.conf"
    echo = EchoServer()
    conf = prefix / "nginx.conf"
    nginx_started = False
    try:
        listen_port = free_port()
        relay = f.run([
            f.go, "xray", "relay", "--target", f"127.0.0.1:{echo.port}",
            "--listen-address", "127.0.0.1", "--listen-port", str(listen_port),
            "--out", str(relay_conf), "--json",
        ], timeout=30)
        f.check(relay.rc == 0, "relay exit 0", f"rc={relay.rc} {relay.err[:300]}")
        if relay.rc != 0:
            return
        report = f.json_of(relay, "relay report")
        if report is None:
            return
        f.write_json("relay-report.json", report)
        f.check(report.get("listenAddress") == "127.0.0.1", "listenAddress echoed",
                str(report.get("listenAddress")))
        f.check(report.get("listenPort") == listen_port, "listenPort echoed",
                str(report.get("listenPort")))
        f.check(report.get("target") == f"127.0.0.1:{echo.port}", "target echoed",
                str(report.get("target")))

        fragment = relay_conf.read_text() if relay_conf.is_file() else ""
        f.check(relay_conf.is_file() and "stream {" in fragment, "stream fragment written")
        f.check(f"listen 127.0.0.1:{listen_port};" in fragment, "fragment binds the requested port")
        f.check(f"proxy_pass 127.0.0.1:{echo.port};" in fragment, "fragment forwards to the backend")
        f.check("proxy_connect_timeout 10s;" in fragment, "fragment keeps 10s connect timeout")
        f.check("proxy_timeout 720m;" in fragment, "fragment keeps 720m proxy timeout")
        f.check("proxy_socket_keepalive on;" in fragment, "fragment keeps socket keepalive")

        module_line = stream_module_line(f)
        conf.write_text(nginx_config(prefix, relay_conf, module_line))
        tested = f.run(["nginx", "-t", "-c", str(conf), "-p", str(prefix)], timeout=30)
        f.check(tested.rc == 0, "nginx -t accepts the rendered fragment",
                f"rc={tested.rc} {(tested.err or tested.out)[:300]}")

        started = f.run(["nginx", "-c", str(conf), "-p", str(prefix)], timeout=20)
        f.check(started.rc == 0, "dedicated nginx started",
                f"rc={started.rc} {(started.err or started.out)[:300]}")
        if started.rc != 0:
            return
        nginx_started = True
        f.check(wait_port(listen_port, time.monotonic() + 10), "relay port is listening",
                f"127.0.0.1:{listen_port}")

        first = b"preview-f05-payload-1\n"
        echoed = roundtrip(listen_port, first)
        f.check(echoed == first, "first TCP connection echoed byte-for-byte",
                f"sent={len(first)} got={len(echoed)}")
        second = b"preview-f05-payload-2-longer\n" * 3
        echoed2 = roundtrip(listen_port, second)
        f.check(echoed2 == second, "second TCP connection echoed byte-for-byte",
                f"sent={len(second)} got={len(echoed2)}")
    finally:
        if nginx_started:
            stop_nginx(f, conf, prefix)
        echo.close()

    after = f.tree_digest("/etc/idleleo")
    f.check(before == after, "relay created no Xray/UUID/certificate state", f"{before[:16]} -> {after[:16]}")
    f.run([f.go, "xray", "relay", "--target", "not-a-host", "--out", str(f.evidence / "bad.conf")],
          timeout=20)
    f.check(not (f.evidence / "bad.conf").exists(), "invalid target wrote no fragment")


if __name__ == "__main__":
    sys.exit(run_fixture("F05", main))
