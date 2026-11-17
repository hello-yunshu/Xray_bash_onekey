#!/usr/bin/env python3
"""Generate the three real configs for the Reality primary/secondary e2e run.

The identity (UUID, Reality key pair, shortId, SNI, target) is generated once
and reused by both backends and the client, so a successful proxy request
proves that the client, the front and either backend share one Reality identity.
"""
import json
import subprocess
import sys
from pathlib import Path

GO_BIN = "/out/idleleo"
NODE_UUID = "7a4ab30c-b199-4840-a31e-316f4f73a72b"
DOMAIN = "www.cloudflare.com"
# Reality must mimic a real, publicly trusted TLS target; the e2e container
# therefore needs egress (no host network or kernel changes are made).
TARGET = "www.cloudflare.com:443"


def generate(out, *args):
    proc = subprocess.run([GO_BIN, "xray", "generate", "--out", str(out), "--force",
                           "--json", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"generate failed: {proc.stderr}")
    return json.loads(proc.stdout)


def main():
    root = Path(sys.argv[1])
    conf = root / "conf"
    nginx = root / "nginx"
    conf.mkdir(parents=True, exist_ok=True)
    nginx.mkdir(parents=True, exist_ok=True)

    common = ["--domain", DOMAIN, "--target", TARGET,
              "--server-names", DOMAIN, "--uuid", NODE_UUID]
    primary = generate(conf / "primary.json", "--mode", "reality-balance",
                       "--role", "primary", "--port", "8443",
                       "--backend", "127.0.0.1:10444", *common,
                       "--nginx-out", str(nginx / "00-xray.conf"),
                       "--fragments-out", str(nginx))
    identity = ["--private-key", primary["privateKey"], "--short-id", primary["shortId"]]
    generate(conf / "secondary.json", "--mode", "reality-balance",
             "--role", "secondary", "--port", "10444", *common, *identity)

    client = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": 1081,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "tag": "reality-out", "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1", "port": 8443,
                "users": [{"id": NODE_UUID, "encryption": "none",
                           "flow": "xtls-rprx-vision"}],
            }]},
            "streamSettings": {
                "network": "raw", "security": "reality",
                "realitySettings": {
                    "serverName": DOMAIN, "fingerprint": "chrome",
                    "publicKey": primary["publicKey"], "shortId": primary["shortId"],
                    "spiderX": "/",
                },
            },
        }],
    }
    (conf / "client.json").write_text(json.dumps(client, indent=2))
    # Only non-secret facts are written outside the container.
    (root / "identity.json").write_text(json.dumps({
        "uuid": NODE_UUID, "serverName": DOMAIN, "publicKey": primary["publicKey"],
        "shortId": primary["shortId"], "primaryPort": 8443, "secondaryPort": 10444,
    }, indent=2))


if __name__ == "__main__":
    main()
