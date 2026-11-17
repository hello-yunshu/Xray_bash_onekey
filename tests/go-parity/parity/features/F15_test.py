#!/usr/bin/env python3
"""F15 — inbound traffic statistics: read-only stats, JSON, and exit codes.

Preview evidence level: CONTAINER_VERIFIED (real Xray StatsService).

The fixture starts a real Xray process with an HTTP proxy inbound, a
dokodemo-door API inbound and StatsService enabled, pushes a known HTTP body
through the proxy, and then compares:

  * Go `idleleo stats --json` (raw `xray api statsquery` passthrough) with the
    fixed Bash baseline `scripts/xray_stats.sh --json` (normalized schema),
  * the human output counters with a direct statsquery,
  * the documented exit codes (5 non-root, 8 API down, 3 missing/unusable
    config, 2 invalid arguments), and
  * the scheduled `stats-collect` job writing `schedule/stats.json`.

`watch` and `reset` are not implemented in Go on purpose. The fixture asserts
they are refused explicitly (unknown flag, exit 2) instead of being silently
accepted, and records the Bash baseline exit-code differences in evidence.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

SANDBOX_MARKER = ".idleleo-phase01-sandbox"
SANDBOX_VALUE = "I_ACCEPT_DISPOSABLE_SANDBOX"
TAG = "http-in"
PAYLOAD = b"x" * 65536


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_port(port, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


class Origin:
    """Loopback HTTP origin whose body is used to generate inbound traffic."""

    def __init__(self):
        self.port = free_port()
        origin = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(PAYLOAD)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(PAYLOAD)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def proxy_get(proxy_port, target_url, timeout=10.0):
    """Send an absolute-form GET to the Xray HTTP proxy inbound."""
    request = (
        f"GET {target_url} HTTP/1.1\r\n"
        f"Host: 127.0.0.1\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def config_doc(api_port, http_port, include_api=True, stats=True):
    doc = {
        "log": {"loglevel": "warning"},
        "policy": {"system": {"statsInboundUplink": True, "statsInboundDownlink": True}},
        "inbounds": [{
            "tag": TAG,
            "listen": "127.0.0.1",
            "port": http_port,
            "protocol": "http",
            "settings": {},
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    if stats:
        doc["stats"] = {}
    if include_api:
        doc["api"] = {
            "tag": "api",
            "listen": f"127.0.0.1:{api_port}",
            "services": ["StatsService"],
        }
        doc["inbounds"].append({
            "tag": "api-in",
            "listen": "127.0.0.1",
            "port": api_port,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
        })
    return doc


def write_config(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def start_xray(f, xray, cfg_path, log_path):
    log = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(xray), "run", "-c", str(cfg_path)],
        stdout=log, stderr=subprocess.STDOUT,
    )
    log.close()
    return proc


def stop_xray(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def statsquery(f, xray, server, pattern="inbound>>>"):
    r = f.run([xray, "api", "statsquery", "--server=" + server,
               "-pattern", pattern, "-reset=false"], timeout=30)
    if r.rc != 0:
        return None
    try:
        doc = json.loads(r.out)
    except ValueError:
        return None
    out = {}
    for item in doc.get("stat", []):
        try:
            out[item["name"]] = int(item.get("value", "0"))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def wait_counters(f, xray, server, timeout=15.0):
    up = f"inbound>>>{TAG}>>>traffic>>>uplink"
    down = f"inbound>>>{TAG}>>>traffic>>>downlink"
    deadline = time.monotonic() + timeout
    values = {}
    while time.monotonic() < deadline:
        values = statsquery(f, xray, server) or {}
        if values.get(up, 0) > 0 and values.get(down, 0) > 0:
            return values
        time.sleep(0.25)
    return values


def wait_uptime(f, xray, server, timeout=15.0):
    """Wait until statssys reports Uptime.

    Xray omits the protobuf default value, so a server younger than one second
    answers without an `Uptime` field. The fixed Bash baseline requires it, so
    wait for real uptime instead of racing the first second of the process.
    """
    deadline = time.monotonic() + timeout
    result = None
    while time.monotonic() < deadline:
        result = f.run([xray, "api", "statssys", "--server=" + server], timeout=30)
        if result.rc == 0 and '"Uptime"' in result.out:
            return result
        time.sleep(0.25)
    return result


def baseline(f, script, cfg_path, xray, *extra, env=None):
    base_env = dict(f.env, XRAY_STATS_BIN=str(xray), XRAY_STATS_ASCII="1",
                    LC_ALL="C.UTF-8", LANG="C.UTF-8")
    if env:
        base_env.update(env)
    cmd = ["bash", str(script), "--config", str(cfg_path)] + list(extra)
    return f.run(cmd, timeout=60, env=base_env)


def main(f):
    f.need_root()
    script = (f.bash_repo / "scripts/xray_stats.sh") if f.bash_repo else None
    f.check(script is not None and script.is_file(),
            "Bash xray_stats.sh baseline is present", str(script))
    if script is None or not script.is_file():
        return
    f.need_tool("bash")
    f.need_tool("jq")
    f.need_tool("setpriv")
    xray = f.xray_bin()

    # The Go manager resolves `xray` from PATH exactly like a real install.
    installed = Path("/usr/local/bin/xray")
    if not installed.exists():
        installed.parent.mkdir(parents=True, exist_ok=True)
        try:
            installed.symlink_to(xray)
        except OSError:
            shutil.copy2(xray, installed)
            os.chmod(installed, 0o755)

    work = f.evidence / "stats-work"
    if work.exists():
        shutil.rmtree(work)
    root = work / "sandbox"
    config_path = root / "etc/idleleo/conf/xray/config.json"
    root.mkdir(parents=True)
    (root / SANDBOX_MARKER).write_text(SANDBOX_VALUE + "\n")
    os.chmod(root / SANDBOX_MARKER, 0o600)

    api_port = free_port()
    http_port = free_port()
    server = f"127.0.0.1:{api_port}"
    write_config(config_path, config_doc(api_port, http_port))
    before_config = f.tree_digest(root)

    origin = Origin()
    origin.start()
    proc = start_xray(f, xray, config_path, work / "xray.log")
    try:
        f.check(wait_port(api_port), "real Xray Stats API is listening", server)
        f.check(wait_port(http_port), "real Xray HTTP inbound is listening", str(http_port))

        response = proxy_get(http_port, f"http://127.0.0.1:{origin.port}/payload")
        f.check(response.startswith(b"HTTP/1.1 200") or response.startswith(b"HTTP/1.0 200"),
                "HTTP proxy request reached the origin", response[:80].decode("latin-1"))
        f.check(PAYLOAD[:32] in response, "origin body came back through Xray")

        values = wait_counters(f, xray, server)
        up_name = f"inbound>>>{TAG}>>>traffic>>>uplink"
        down_name = f"inbound>>>{TAG}>>>traffic>>>downlink"
        f.write_json("direct-statsquery.json", values)
        f.check(values.get(up_name, 0) > 0, "StatsService recorded inbound uplink",
                str(values.get(up_name)))
        f.check(values.get(down_name, 0) >= len(PAYLOAD),
                "StatsService recorded inbound downlink >= body size",
                str(values.get(down_name)))
        if values.get(up_name, 0) <= 0 or values.get(down_name, 0) < len(PAYLOAD):
            return

        # 1) JSON passthrough: Go prints the raw statsquery object.
        go_json = f.run([f.go, "--root", str(root), "stats", "--json"], timeout=60)
        f.check(go_json.rc == 0, "stats --json exit 0", f"rc={go_json.rc} {go_json.err[:200]}")
        raw = f.json_of(go_json, "go stats json")
        if raw is None:
            return
        f.write_json("go-stats-raw.json", raw)
        f.check(isinstance(raw.get("stat"), list), "Go --json passes the raw stat array through",
                str(type(raw.get("stat"))))
        raw_map = {s.get("name"): int(s.get("value", "0")) for s in raw.get("stat", [])
                   if isinstance(s, dict) and s.get("name")}
        f.check(raw_map.get(up_name) == values.get(up_name),
                "Go JSON uplink equals direct statsquery",
                f"{raw_map.get(up_name)} vs {values.get(up_name)}")
        f.check(raw_map.get(down_name) == values.get(down_name),
                "Go JSON downlink equals direct statsquery",
                f"{raw_map.get(down_name)} vs {values.get(down_name)}")
        f.check("schemaVersion" not in raw, "Go JSON is passthrough, not the Bash schema")

        # 2) Fixed Bash baseline on the same live API.
        sys_probe = wait_uptime(f, xray, server)
        (f.evidence / "statssys.json").write_text(sys_probe.out or sys_probe.err, encoding="utf-8")
        f.check(sys_probe.rc == 0 and '"Uptime"' in sys_probe.out,
                "direct statssys returns Uptime", (sys_probe.out or sys_probe.err).strip()[:160])
        bash_json = baseline(f, script, config_path, xray, "--json")
        f.check(bash_json.rc == 0, "Bash stats baseline exit 0", f"rc={bash_json.rc} {bash_json.err[:200]}")
        bash_doc = f.json_of(bash_json, "bash stats json")
        if bash_doc is None:
            return
        f.write_json("bash-stats-normalized.json", bash_doc)
        inbound = next((i for i in bash_doc.get("inbounds", []) if i.get("tag") == TAG), {})
        f.check(inbound.get("uplinkBytes") == values.get(up_name),
                "Bash uplink equals direct statsquery",
                f"{inbound.get('uplinkBytes')} vs {values.get(up_name)}")
        f.check(inbound.get("downlinkBytes") == values.get(down_name),
                "Bash downlink equals direct statsquery",
                f"{inbound.get('downlinkBytes')} vs {values.get(down_name)}")
        f.check(inbound.get("totalBytes") == values.get(up_name, 0) + values.get(down_name, 0),
                "Bash total is uplink+downlink", str(inbound.get("totalBytes")))
        f.check(bash_doc.get("server") == server, "Bash reports the same API server",
                str(bash_doc.get("server")))
        bash_tags = {i.get("tag") for i in bash_doc.get("inbounds", [])}
        go_tags = {name.split(">>>")[1] for name in raw_map
                   if name.startswith("inbound>>>") and name.split(">>>")[2:3] == ["traffic"]}
        f.check(TAG in bash_tags, "Bash reports the traffic inbound tag", str(sorted(bash_tags)))
        f.check(bash_tags == go_tags, "Bash and Go observe the same inbound tag set",
                f"bash={sorted(bash_tags)} go={sorted(go_tags)}")

        # 3) Human output prints name=value counters.
        text = f.run([f.go, "--root", str(root), "stats"], timeout=60)
        f.check(text.rc == 0, "stats text exit 0", f"rc={text.rc}")
        lines = dict(line.split("=", 1) for line in text.out.splitlines() if "=" in line)
        f.check(str(lines.get(up_name)) == str(values.get(up_name)),
                "text uplink matches statsquery", f"{lines.get(up_name)}")
        f.check(str(lines.get(down_name)) == str(values.get(down_name)),
                "text downlink matches statsquery", f"{lines.get(down_name)}")

        # 4) --pattern is forwarded to statsquery.
        pattern = f.run([f.go, "--root", str(root), "stats", "--json",
                         "--pattern", down_name], timeout=60)
        f.check(pattern.rc == 0, "stats --pattern exit 0", f"rc={pattern.rc}")
        pattern_doc = f.json_of(pattern, "pattern json") or {}
        names = [s.get("name") for s in pattern_doc.get("stat", [])]
        f.check(names == [down_name], "pattern returns exactly the requested counter",
                str(names))

        # 5) Read-only: the manager must not touch the root.
        after_config = f.tree_digest(root)
        f.check(before_config == after_config,
                "stats queries leave the root tree byte-identical",
                f"{before_config[:12]} -> {after_config[:12]}")

        # 6) Explicit unsupported watch/reset instead of silent acceptance.
        for flag in ("--watch", "--reset", "--yes"):
            refused = f.run([f.go, "--root", str(root), "stats", flag], timeout=30)
            f.check(refused.rc == 2, f"stats {flag} is refused with exit 2",
                    f"rc={refused.rc}")
            f.check("unknown flag" in refused.err,
                    f"stats {flag} refusal names the unknown flag",
                    refused.err.strip()[:160])

        # 7) Argument and config failures.
        bad_timeout = f.run([f.go, "--root", str(root), "stats", "--timeout", "nope"], timeout=30)
        f.check(bad_timeout.rc == 2, "invalid --timeout exits 2", f"rc={bad_timeout.rc}")

        escape = f.run([f.go, "--root", str(root), "stats", "--path", "../escape.json"], timeout=30)
        f.check(escape.rc == 2, "path traversal exits 2", f"rc={escape.rc}")
        f.check("relative path" in escape.err, "path traversal error is explicit",
                escape.err.strip()[:160])

        no_api_path = root / "etc/idleleo/conf/xray/noapi.json"
        write_config(no_api_path, config_doc(api_port, http_port, include_api=False))
        no_api = f.run([f.go, "--root", str(root), "stats", "--json",
                        "--path", "etc/idleleo/conf/xray/noapi.json"], timeout=30)
        f.check(no_api.rc == 3, "missing api.listen exits 3", f"rc={no_api.rc}")
        f.check("api.listen" in no_api.err, "missing api.listen is explained",
                no_api.err.strip()[:160])

        bad_json_path = root / "etc/idleleo/conf/xray/bad.json"
        bad_json_path.write_text("{", encoding="utf-8")
        bad_json = f.run([f.go, "--root", str(root), "stats", "--path",
                          "etc/idleleo/conf/xray/bad.json"], timeout=30)
        f.check(bad_json.rc == 3, "invalid config JSON exits 3", f"rc={bad_json.rc}")
        f.check("not valid JSON" in bad_json.err, "invalid JSON is explained",
                bad_json.err.strip()[:160])

        missing_root = work / "empty-root"
        missing_root.mkdir()
        missing = f.run([f.go, "--root", str(missing_root), "stats"], timeout=30)
        f.check(missing.rc == 3, "missing runtime config exits 3", f"rc={missing.rc}")

        # 8) Non-root exit 5, same as the Bash baseline.
        non_root = f.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
                          str(f.go), "stats", "--json"], timeout=30)
        f.check(non_root.rc == 5, "non-root stats exits 5", f"rc={non_root.rc}")
        f.check("requires root" in non_root.err, "non-root refusal is explicit",
                non_root.err.strip()[:160])
        bash_non_root = f.run(["setpriv", "--reuid=65534", "--regid=65534",
                               "--clear-groups", "bash", str(script),
                               "--config", str(config_path), "--json"], timeout=30,
                              env=dict(f.env, XRAY_STATS_BIN=str(xray)))
        f.check(bash_non_root.rc == 5, "Bash non-root baseline also exits 5",
                f"rc={bash_non_root.rc}")

        # 9) Scheduled stats-collect writes the raw query to stats.json.
        sched_root = work / "schedule-root"
        sched_cfg = sched_root / "etc/idleleo/conf/xray/config.json"
        sched_root.mkdir()
        (sched_root / SANDBOX_MARKER).write_text(SANDBOX_VALUE + "\n")
        os.chmod(sched_root / SANDBOX_MARKER, 0o600)
        write_config(sched_cfg, config_doc(api_port, http_port))
        sched_cfg_before = sched_cfg.read_bytes()

        sched = f.run([f.go, "--root", str(sched_root), "schedule", "run",
                       "--job", "stats-collect", "--json"], timeout=90)
        f.check(sched.rc == 0, "schedule stats-collect exits 0", f"rc={sched.rc} {sched.err[:200]}")
        sched_doc = f.json_of(sched, "schedule report") or {}
        f.write_json("schedule-stats-collect.json", sched_doc)
        result = (sched_doc.get("results") or [{}])[0]
        f.check(result.get("job") == "stats-collect", "schedule ran stats-collect",
                str(result.get("job")))
        f.check(result.get("result") == "ok", "schedule stats-collect result ok",
                str(result.get("result")))
        stats_path = sched_root / "var/lib/idleleo/schedule/stats.json"
        f.check(stats_path.is_file(), "schedule wrote stats.json", str(stats_path))
        if stats_path.is_file():
            saved = json.loads(stats_path.read_text())
            f.write_json("schedule-stats.json", saved)
            saved_map = {s.get("name"): int(s.get("value", "0"))
                         for s in saved.get("stat", []) if isinstance(s, dict) and s.get("name")}
            f.check(saved_map.get(up_name, 0) >= values.get(up_name, 0),
                    "saved stats.json retains the inbound uplink", str(saved_map.get(up_name)))
            f.check((stats_path.stat().st_mode & 0o777) == 0o640,
                    "stats.json is 0640", oct(stats_path.stat().st_mode & 0o777))
        f.check(sched_cfg.read_bytes() == sched_cfg_before,
                "schedule stats-collect leaves the runtime config untouched")

        # 10) API down: Go exits 8; the Bash baseline reports 2.
        stop_xray(proc)
        proc = None
        f.check(not wait_port(api_port, timeout=1.0), "Xray API is down")
        down = f.run([f.go, "--root", str(root), "stats", "--json"], timeout=60)
        f.check(down.rc == 8, "stats with the API down exits 8", f"rc={down.rc}")
        f.check("stats query failed" in down.err, "API-down error is explicit",
                down.err.strip()[:200])
        bash_down = baseline(f, script, config_path, xray, "--json")
        f.check(bash_down.rc == 2, "Bash API-down baseline exits 2 (documented divergence)",
                f"rc={bash_down.rc}")
        f.write_json("exit-code-divergence.json", {
            "case": "api-down",
            "go": {"exit": down.rc, "stderr": down.err.strip()},
            "bash": {"exit": bash_down.rc, "stderr": bash_down.err.strip()},
            "note": "F15 migration note documents Go exit 8 vs Bash exit 2 for an unreachable Stats API",
        })

        sched_down = f.run([f.go, "--root", str(sched_root), "schedule", "run",
                            "--job", "stats-collect", "--json"], timeout=90)
        f.check(sched_down.rc == 1, "schedule stats-collect fails when the API is down",
                f"rc={sched_down.rc}")
        sched_down_doc = f.json_of(sched_down, "schedule down report") or {}
        f.write_json("schedule-api-down.json", sched_down_doc)
        down_result = (sched_down_doc.get("results") or [{}])[0]
        f.check(down_result.get("result") == "failed",
                "schedule reports the Stats failure explicitly", str(down_result.get("result")))
    finally:
        stop_xray(proc)
        origin.stop()


if __name__ == "__main__":
    sys.exit(run_fixture("F15", main))
