#!/usr/bin/env python3
"""C6 — edit a direct TLS config without regenerating it.

Preview evidence level: CONTAINER_VERIFIED (real idleleo binary, real xray
process under systemd, real handshake; no host writes outside the container).

What the fixture proves:

* a mismatch between --domain and the live pair is refused before any write;
* --dry-run plans the change and touches nothing (config sha and xray pid stay);
* a valid pair rotation rewrites only certificateFile/keyFile, keeps routing and
  the ws path, restarts xray, and the new leaf is served on the wire;
* the report says tls-probe ok with mode=tls-direct and warns that renewal is
  not managed by this tool;
* the install-time TLS label is not replaced by the edit classification.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

ROOT = Path("/")
CONF = ROOT / "etc/idleleo/conf/xray/config.json"
CERT_DIR = ROOT / "etc/idleleo/cert"
META = ROOT / "etc/idleleo/v1/metadata.json"
UNIT = ROOT / "etc/systemd/system/xray.service"
BIN = ROOT / "usr/local/bin/xray"
PORT = 18443


def write_text(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def sha256(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


def make_pair(work, stem, domain):
    cert = work / f"{stem}.crt"
    key = work / f"{stem}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
         "-subj", f"/CN={domain}", "-addext", f"subjectAltName=DNS:{domain}",
         "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True)
    cert.chmod(0o640)
    key.chmod(0o640)
    return cert, key


def config_body(cert, key):
    return json.dumps({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "vless-ws-tls",
            "listen": "0.0.0.0",
            "port": PORT,
            "protocol": "vless",
            "settings": {"clients": [{"id": "7a4ab30c-b199-4840-a31e-316f4f73a72b"}],
                         "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "example.com",
                    "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}],
                },
                "wsSettings": {"path": "/c6"},
            },
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": [{"type": "field", "domain": ["keep.example"],
                               "outboundTag": "direct"}]},
    }, indent=2) + "\n"


def metadata():
    return json.dumps({
        "schemaVersion": 1,
        "activeEngine": "xray",
        "role": "node",
        "tls": "TLS",
        "transport": "ws",
        "provenance": "native",
        "runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
        "runtimeSha256": "",
        "ownedResources": [],
        "updatedAt": "2026-01-01T00:00:00Z",
    }, indent=2) + "\n"


def unit():
    return f"""[Unit]
Description=Xray Service
After=network.target

[Service]
User=root
NoNewPrivileges=true
ExecStart={BIN} run -config {CONF}
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""


def served_fp(domain):
    pem = subprocess.run(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", "-servername", domain,
         "-showcerts"], input="", capture_output=True, text=True, timeout=15).stdout
    match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    if not match:
        return ""
    proc = subprocess.run(
        ["openssl", "x509", "-noout", "-fingerprint", "-sha256"],
        input=match.group(0), capture_output=True, text=True, timeout=10)
    return proc.stdout.strip().split("=", 1)[-1].upper()


def ping(work):
    return subprocess.run(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", "-servername", "example.com"],
        input="", capture_output=True, text=True, timeout=15)


def main(f):
    f.need(os.geteuid() == 0, "C6 rewrites /etc/idleleo and restarts xray")
    f.need_systemd()
    xray = f.xray_bin()
    f.need(shutil.which("openssl") is not None, "openssl is required")
    work = f.evidence / "c6-work"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)

    subprocess.run(["install", "-m", "0755", str(xray), str(BIN)], check=True)
    old_cert, old_key = make_pair(work, "old", "example.com")
    cert, key = CERT_DIR / "c6-old.crt", CERT_DIR / "c6-old.key"
    cert.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(old_cert, cert)
    shutil.copy2(old_key, key)
    write_text(CONF, config_body(cert, key))
    write_text(META, metadata())
    write_text(UNIT, unit())
    f.run(["systemctl", "daemon-reload"])
    f.run(["systemctl", "enable", "--now", "xray"], timeout=60)
    f.check(f.run(["systemctl", "is-active", "xray"]).out.strip() == "active",
            "direct TLS xray service starts")
    old_fp = served_fp("example.com")
    f.check(bool(old_fp), "old certificate is served on the wire", old_fp)

    base_sha = sha256(CONF)
    pid_before = f.run(["systemctl", "show", "xray", "-p", "MainPID"]).out.strip()
    env = dict(f.env, IDLELEO_ALLOW_SYSTEM_WRITES="I_ACCEPT_CONTAINER_ONLY")
    edit_cmd = [f.go, "xray", "config", "edit", "--container", "--json"]

    # ---- 1. negative: a domain the live pair does not cover ----------------
    guard = f.run(edit_cmd + ["--domain", "other.test", "--yes"], env=env)
    f.check(guard.rc != 0, "mismatched --domain is refused", guard.text[-300:])
    f.check("does not cover" in guard.text, "refusal names the SAN mismatch")
    f.check(sha256(CONF) == base_sha, "refused edit keeps the config byte-identical")
    f.check(f.run(["systemctl", "show", "xray", "-p", "MainPID"]).out.strip() == pid_before,
            "refused edit does not restart xray")

    # ---- 2. dry-run: plan only ---------------------------------------------
    new_cert, new_key = make_pair(work, "new", "example.com")
    target_cert, target_key = CERT_DIR / "c6-new.crt", CERT_DIR / "c6-new.key"
    shutil.copy2(new_cert, target_cert)
    shutil.copy2(new_key, target_key)
    dry = f.run(edit_cmd + ["--cert", str(target_cert), "--cert-key", str(target_key),
                            "--dry-run"], env=env)
    dry_json = f.json_of(dry, "config edit --dry-run --json") if dry.rc == 0 else None
    f.check(dry.rc == 0, "dry-run rc=0", dry.text[-300:])
    f.check(sha256(CONF) == base_sha, "dry-run writes nothing")
    f.check(f.run(["systemctl", "show", "xray", "-p", "MainPID"]).out.strip() == pid_before,
            "dry-run does not restart xray")
    if dry_json:
        f.check(dry_json.get("mode") == "tls-direct", "dry-run reports mode=tls-direct")
        f.check("cert-file" in dry_json.get("changed", []), "dry-run plans the pair rotation")

    # ---- 3. positive: rotate the pair for real ------------------------------
    edit = f.run(edit_cmd + ["--cert", str(target_cert), "--cert-key", str(target_key),
                             "--yes"], env=env, timeout=90)
    report = f.json_of(edit, "config edit --json") if edit.rc == 0 else None
    f.check(edit.rc == 0, "pair rotation rc=0", edit.text[-400:])
    if report:
        f.check(report.get("mode") == "tls-direct", "report mode=tls-direct")
        f.check(report.get("tlsProbe") == "ok", "local TLS probe verified")
        f.check(report.get("tlsServerName") == "example.com", "probe used the configured SNI")
        f.check(any("renewal is not managed" in w for w in report.get("warnings", [])),
                "report warns that renewal is not managed", str(report.get("warnings")))
        f.check(report.get("scheduleUpdated") in (False, None), "no schedule is rewritten")
        f.write_json("c6-report.json", report)

    new_fp = served_fp("example.com")
    f.check(new_fp == _fp_of(target_cert), "the new leaf is served on the wire", new_fp)
    f.check(new_fp != old_fp, "the served leaf changed")
    f.check(ping(work).stdout != "" and ping(work).returncode == 0,
            "a TLS handshake still succeeds after the edit")

    after = json.loads(CONF.read_text(encoding="utf-8"))
    inbound = after["inbounds"][0]
    certs = inbound["streamSettings"]["tlsSettings"]["certificates"][0]
    f.check(certs["certificateFile"] == str(target_cert), "config points at the new certificate")
    f.check(certs["keyFile"] == str(target_key), "config points at the new key")
    f.check(inbound["streamSettings"]["wsSettings"]["path"] == "/c6", "ws path is untouched")
    f.check(after["routing"]["rules"][0]["domain"] == ["keep.example"], "routing is untouched")
    f.check(after["outbounds"][0]["tag"] == "direct", "outbounds are untouched")
    f.check(
        f.run(["systemctl", "show", "xray", "-p", "MainPID"]).out.strip() != pid_before,
        "xray restarted to load the pair")

    meta = json.loads(META.read_text(encoding="utf-8"))
    f.check(meta.get("tls") == "TLS", "install-time TLS label is preserved", str(meta.get("tls")))
    f.check(meta.get("runtimeSha256") == sha256(CONF), "metadata records the new runtime sha")

    shutil.copy2(CONF, work / "config.after.json")
    f.write_json("c6-observed.json", {
        "chain": "direct-tls->config-edit",
        "oldFingerprint": old_fp,
        "newFingerprint": new_fp,
        "beforeSha": base_sha,
        "afterSha": sha256(CONF),
        "mode": "tls-direct",
    })
    f.run(["systemctl", "stop", "xray"], timeout=30)


def _fp_of(path):
    proc = subprocess.run(["openssl", "x509", "-in", str(path), "-noout", "-fingerprint",
                           "-sha256"], capture_output=True, text=True, timeout=10)
    return proc.stdout.strip().split("=", 1)[-1].upper()


if __name__ == "__main__":
    sys.exit(run_fixture("C6", main))
