#!/usr/bin/env python3
"""F01 — Reality install and a real client handshake.

Preview evidence level: CONTAINER_VERIFIED (root + systemd + xray + network).

The fixture is deliberately self-contained: it removes any previous xray
install, proves an invalid request writes nothing, installs Reality, checks the
systemd unit and the validator, then builds a real Xray client from the printed
share URI and fetches HTTP bytes through the tunnel. A failure at any stage is
a RED fixture, never a skip.
"""
import json
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture, sha256  # noqa: E402

CONFIG = Path("/etc/idleleo/conf/xray/config.json")
UNIT = Path("/etc/systemd/system/xray.service")
INSTALLED_BIN = Path("/usr/local/bin/xray")
METADATA = Path("/etc/idleleo/v1/metadata.json")
ORIGIN = "http://example.com/"


def cleanup(f, keep_config=False):
    f.run(["systemctl", "stop", "xray"], timeout=20)
    f.run(["systemctl", "disable", "xray"], timeout=20)
    for path in (UNIT, INSTALLED_BIN, METADATA):
        path.unlink(missing_ok=True)
    if not keep_config:
        CONFIG.unlink(missing_ok=True)
    f.run(["systemctl", "daemon-reload"], timeout=20)
    f.run(["systemctl", "reset-failed", "xray"], timeout=20)


def process_users(f):
    r = f.run(["ps", "-eo", "user=,comm="], timeout=15)
    users = {}
    for line in r.out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == "xray":
            users.setdefault(parts[0], 0)
            users[parts[0]] += 1
    return users


def wait_port(port, deadline):
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def client_config(uri, socks_port):
    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qs(parsed.query)
    one = lambda key, default="": query.get(key, [default])[0]
    network = one("type", "tcp")
    if network in ("tcp", "raw"):
        network = "raw"
    security = one("security", "none")
    reality = {
        "serverName": one("sni"),
        "fingerprint": one("fp", "chrome"),
        "publicKey": one("pbk"),
        "shortId": one("sid"),
        "spiderX": urllib.parse.unquote(one("spx", "/")),
    }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": False},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "users": [{
                    "id": urllib.parse.unquote(parsed.username or ""),
                    "encryption": "none",
                    "flow": one("flow"),
                }],
            }]},
            "streamSettings": {
                "network": network,
                "security": security,
                "realitySettings": reality,
            },
        }],
    }


def main(f):
    f.need_root()
    f.need_systemd()
    xray = f.xray_bin()
    f.need_tool("curl")
    write_env = dict(f.env, IDLELEO_ALLOW_SYSTEM_WRITES="I_ACCEPT_CONTAINER_ONLY")

    cleanup(f)

    # 1) Fail closed before any write: an invalid serverName must not leave a
    #    config, unit or binary behind.
    bad = f.run([
        f.go, "xray", "install", "--binary", xray, "--mode", "reality",
        "--server-names", "bad name!", "--port", "8443", "--container", "--json",
    ], timeout=60)
    f.check(bad.rc == 2, "invalid serverName refused with exit 2", f"rc={bad.rc}")
    f.check(not CONFIG.exists() and not UNIT.exists() and not INSTALLED_BIN.exists(),
            "invalid request wrote nothing", f"config={CONFIG.exists()} unit={UNIT.exists()} bin={INSTALLED_BIN.exists()}")
    if f.failed:
        return

    # 2) Real install.
    install = f.run([
        f.go, "xray", "install", "--binary", xray, "--mode", "reality",
        "--domain", "example.com", "--port", "8443", "--container", "--json",
    ], timeout=120, env=write_env)
    f.check(install.rc == 0, "reality install exit 0", f"rc={install.rc} {install.err[:300]}")
    if install.rc != 0:
        return
    report = f.json_of(install, "install report")
    if report is None:
        return
    f.write_json("install-report.json", report)

    f.check(report.get("mode") == "reality", "report mode=reality", str(report.get("mode")))
    f.check(report.get("tls") == "Reality", "report tls=Reality", str(report.get("tls")))
    f.check(report.get("validatorExit") == 0, "report validatorExit=0", str(report.get("validatorExit")))
    f.check(report.get("serviceActive") == "active", "report serviceActive=active", str(report.get("serviceActive")))
    f.check(report.get("serviceEnabled") == "enabled", "report serviceEnabled=enabled", str(report.get("serviceEnabled")))
    f.check(CONFIG.is_file(), "runtime config exists", str(CONFIG))
    if CONFIG.is_file():
        f.check(report.get("configSha256") == sha256(CONFIG), "report configSha256 matches file",
                f"{report.get('configSha256')} vs {sha256(CONFIG)}")

    # 3) systemd and runtime ownership.
    active = f.run(["systemctl", "is-active", "xray"], timeout=20)
    f.check(active.out.strip() == "active", "systemctl is-active active", active.out.strip())
    enabled = f.run(["systemctl", "is-enabled", "xray"], timeout=20)
    f.check(enabled.out.strip() == "enabled", "systemctl is-enabled enabled", enabled.out.strip())
    unit_text = UNIT.read_text() if UNIT.is_file() else ""
    f.check("User=xray" in unit_text, "unit runs as User=xray")
    users = process_users(f)
    f.write_json("process-users.json", users)
    f.check("xray" in users, "xray process is owned by user xray", json.dumps(users))
    validate = f.run([INSTALLED_BIN, "-test", "-config", str(CONFIG)], timeout=30)
    f.check(validate.rc == 0, "installed xray -test accepts the config", f"rc={validate.rc} {validate.err[:300]}")

    # 4) Real handshake: share URI -> client -> SOCKS -> HTTP bytes.
    share = f.run([f.go, "xray", "share", "--path", str(CONFIG), "--host", "127.0.0.1",
                   "--public-port", "8443", "--json"], timeout=30)
    f.check(share.rc == 0, "share exit 0", f"rc={share.rc}")
    info = f.json_of(share, "share report")
    if info is None:
        return
    f.write_json("share.json", info)
    uri = info.get("shareUri") or ""
    f.check(uri.startswith("vless://"), "shareUri is a vless URI", uri[:80])

    socks_port = 10808
    client_path = f.evidence / "client.json"
    client_path.write_text(json.dumps(client_config(uri, socks_port), indent=2))
    client_log = open(f.evidence / "client.log", "w", encoding="utf-8")
    client = subprocess.Popen([str(xray), "run", "-c", str(client_path)],
                              stdout=client_log, stderr=subprocess.STDOUT)
    body = f.evidence / "origin-body.txt"
    ok = False
    try:
        if wait_port(socks_port, time.monotonic() + 15):
            f.ok("client SOCKS listener ready", f"127.0.0.1:{socks_port}")
            for attempt in range(1, 4):
                curl = f.run([
                    "curl", "-sS", "--max-time", "15", "--socks5-hostname",
                    f"127.0.0.1:{socks_port}", "-o", str(body), "-w", "%{http_code}", ORIGIN,
                ], timeout=25)
                code = (curl.out or "").strip()
                size = body.stat().st_size if body.exists() else 0
                if curl.rc == 0 and code == "200" and size > 0:
                    f.ok("real handshake fetched HTTP bytes", f"attempt={attempt} status={code} bytes={size}")
                    ok = True
                    break
                f.bad(f"handshake attempt {attempt} failed", f"rc={curl.rc} status={code} bytes={size} {curl.err[:200]}")
        else:
            f.bad("client SOCKS listener did not start", "15s")
    finally:
        client.terminate()
        try:
            client.wait(timeout=10)
        except subprocess.TimeoutExpired:
            client.kill()
        client_log.close()
    f.check(ok, "Reality data path works end to end", ORIGIN)

    # 5) Remove the fixture installation; purge keeps a clean hand-off for the
    #    next fixture and leaves no systemd unit behind.
    cleanup(f)


if __name__ == "__main__":
    sys.exit(run_fixture("F01", main))
