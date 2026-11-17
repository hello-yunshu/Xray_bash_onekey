#!/usr/bin/env python3
"""F12 — certificate issuance, renewal, permissions and cleanup.

Preview evidence level: CONTAINER_VERIFIED + ACME_LOCAL_CA.

The fixture runs an in-process ACME v2 server over HTTPS (a throwaway CA made
with openssl) and points the native client at it. That exercises the real
order/authorization/HTTP-01/finalize/download path, the atomic pair install,
the layered 0750/0640 root:idleleo-nginx permissions and the rollback of a
failed reload. No public CA is contacted, ever.

Covered contract (D-024):
  * `cert renew --dry-run` is read-only for missing / valid / due / user-managed;
  * the default account state lives outside the certificate tree and a legacy
    `<certdir>/acme` directory is migrated fail-closed;
  * `.user-managed` refuses overwrite until `--takeover`;
  * `--production` preflights via staging unless --no-staging-check or an
    explicit --directory is given;
  * installed pairs are 0644/0600 without a worker group and 0640 root:<group>
    inside the managed 0750 directory;
  * a failed reload restores the previous pair (content, mode, owner);
  * the schedule skips a user-managed pair but reloads services when the
    operator replaces it.
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import secrets
import grp
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture, sha256  # noqa: E402

MANAGED_CERT_DIR = Path("/etc/idleleo/cert")
MANAGED_GROUP = "idleleo-nginx"
SCHEDULE_CONFIG = Path("/etc/idleleo/schedule/jobs.json")
SCHEDULE_STATE = Path("/var/lib/idleleo/schedule")
PROBE_XRAY = Path("/etc/systemd/system/xray.service")
PROBE_NGINX = Path("/etc/systemd/system/nginx.service")


def b64url_decode(value):
    if not value:
        return b""
    return __import__("base64").urlsafe_b64decode(value + "=" * (-len(value) % 4))


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def utc_after(hours):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def mode_of(path):
    return oct(path.stat().st_mode & 0o7777)


def owner_of(path):
    st = path.stat()
    return st.st_uid, st.st_gid


class LocalCA:
    """Minimal RFC 8555 server: newNonce/newAccount/newOrder/authz/chall/finalize/cert."""

    def __init__(self, f, base, webroot):
        self.f = f
        self.base = base
        self.webroot = webroot
        self.ca_dir = base / "ca"
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_key = self.ca_dir / "ca.key"
        self.ca_cert = self.ca_dir / "ca.crt"
        self.tls_key = self.ca_dir / "tls.key"
        self.tls_cert = self.ca_dir / "tls.crt"
        self.port = free_port()
        self.url = f"https://127.0.0.1:{self.port}/directory"
        self.base_url = f"https://127.0.0.1:{self.port}"
        self.seq = 0
        self.orders = {}
        self.lock = threading.Lock()
        self._make_ca()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), self._handler())
        self.httpd.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.tls_cert, self.tls_key)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    # -- pki ------------------------------------------------------------------
    def _make_ca(self):
        f = self.f
        ext = self.ca_dir / "tls.ext"
        ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
        steps = [
            (["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
              "-keyout", self.ca_key, "-out", self.ca_cert, "-subj", "/CN=idleleo-f12-local-ca"],
             "local CA created"),
            (["openssl", "req", "-newkey", "rsa:2048", "-nodes",
              "-keyout", self.tls_key, "-out", self.ca_dir / "tls.csr",
              "-subj", "/CN=localhost"], "local CA TLS key created"),
            (["openssl", "x509", "-req", "-in", self.ca_dir / "tls.csr",
              "-CA", self.ca_cert, "-CAkey", self.ca_key, "-CAcreateserial",
              "-days", "2", "-out", self.tls_cert, "-extfile", ext],
             "local CA TLS certificate signed"),
        ]
        for args, name in steps:
            r = f.run(args, timeout=60)
            f.check(r.rc == 0, name, (r.err or r.out)[:300])
            if r.rc != 0:
                raise RuntimeError(name)

    def sign(self, domains, csr_der):
        work = self.base / "sign"
        work.mkdir(exist_ok=True)
        with self.lock:
            self.seq += 1
            n = self.seq
        csr = work / f"{n}.csr"
        pem = work / f"{n}.pem"
        out = work / f"{n}.crt"
        ext = work / f"{n}.ext"
        csr.write_bytes(csr_der)
        ext.write_text("subjectAltName=" + ",".join("DNS:" + d for d in domains) + "\n")
        serial = "0x" + secrets.token_hex(8)
        first = subprocess.run(["openssl", "req", "-inform", "DER", "-in", str(csr),
                                "-out", str(pem)], capture_output=True, text=True)
        if first.returncode != 0:
            return None, first.stderr
        second = subprocess.run(["openssl", "x509", "-req", "-in", str(pem),
                                 "-CA", str(self.ca_cert), "-CAkey", str(self.ca_key),
                                 "-set_serial", serial, "-days", self.days_for(domains),
                                 "-out", str(out), "-extfile", str(ext)],
                                capture_output=True, text=True)
        if second.returncode != 0:
            return None, second.stderr
        return out.read_bytes() + self.ca_cert.read_bytes(), ""

    def days_for(self, domains):
        # A short-lived certificate lets the fixture drive the 30-day renewal
        # window without waiting or touching the system clock.
        return "1" if any(d.startswith("short.") for d in domains) else "90"

    def start(self):
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    # -- http ----------------------------------------------------------------
    def _handler(self):
        ca = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, fmt, *args):
                pass

            def _send(self, code, payload=None, headers=None, raw=None, ctype="application/json"):
                if raw is not None:
                    body = raw
                elif payload is None:
                    body = b""
                else:
                    body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Replay-Nonce", secrets.token_urlsafe(16))
                self.send_header("Content-Length", str(len(body)))
                if body:
                    self.send_header("Content-Type", ctype)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def _payload(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                if not raw:
                    return {}
                try:
                    jws = json.loads(raw)
                    decoded = b64url_decode(jws.get("payload", ""))
                    return json.loads(decoded) if decoded else {}
                except (ValueError, TypeError):
                    return {}

            def do_HEAD(self):
                self._route()

            def do_GET(self):
                self._route()

            def do_POST(self):
                self._route()

            def _route(self):
                path = urlparse(self.path).path
                try:
                    if path in ("/directory", "/"):
                        return self._send(200, {
                            "newNonce": ca.base_url + "/new-nonce",
                            "newAccount": ca.base_url + "/new-account",
                            "newOrder": ca.base_url + "/new-order",
                            "revokeCert": ca.base_url + "/revoke",
                            "keyChange": ca.base_url + "/key-change",
                        })
                    if path == "/new-nonce":
                        return self._send(200)
                    if path == "/new-account":
                        return self._send(201, {"status": "valid"},
                                          {"Location": ca.base_url + "/acct/1"})
                    if path == "/new-order":
                        return self._new_order()
                    if path.startswith("/authz/"):
                        return self._authz(path.rsplit("/", 1)[-1])
                    if path.startswith("/challenge/"):
                        return self._challenge(path.rsplit("/", 1)[-1])
                    if path.startswith("/order/"):
                        return self._order(path.rsplit("/", 1)[-1])
                    if path.startswith("/finalize/"):
                        return self._finalize(path.rsplit("/", 1)[-1])
                    if path.startswith("/cert/"):
                        return self._cert(path.rsplit("/", 1)[-1])
                    return self._send(404, {"type": "about:blank", "detail": "not found", "status": 404})
                except Exception as exc:  # keep the protocol error visible
                    return self._send(500, {"type": "urn:ietf:params:acme:error:serverInternal",
                                            "detail": str(exc), "status": 500})

            def _new_order(self):
                payload = self._payload()
                identifiers = payload.get("identifiers") or []
                if not identifiers:
                    return self._send(400, {"type": "urn:ietf:params:acme:error:malformed",
                                            "detail": "identifiers required", "status": 400})
                order_id = str(secrets.token_hex(6))
                ca.orders[order_id] = {
                    "identifiers": identifiers,
                    "status": "pending",
                    "token": secrets.token_urlsafe(16),
                    "valid": False,
                    "cert": None,
                }
                url = ca.base_url + "/order/" + order_id
                return self._send(201, self._order_body(order_id),
                                  {"Location": url})

            def _order_body(self, order_id):
                order = ca.orders[order_id]
                body = {
                    "status": order["status"],
                    "expires": utc_after(1),
                    "identifiers": order["identifiers"],
                    "authorizations": [ca.base_url + "/authz/" + order_id],
                    "finalize": ca.base_url + "/finalize/" + order_id,
                }
                if order["cert"]:
                    body["certificate"] = ca.base_url + "/cert/" + order_id
                return body

            def _authz(self, order_id):
                order = ca.orders.get(order_id)
                if order is None:
                    return self._send(404, {"type": "about:blank", "detail": "unknown authz", "status": 404})
                status = "valid" if order["valid"] else "pending"
                challenge = {
                    "type": "http-01",
                    "url": ca.base_url + "/challenge/" + order_id,
                    "status": status,
                    "token": order["token"],
                }
                if order["valid"]:
                    challenge["validated"] = utc_after(0)
                body = {
                    "status": status,
                    "expires": utc_after(1),
                    "identifier": order["identifiers"][0],
                    "challenges": [challenge],
                }
                return self._send(200, body)

            def _challenge(self, order_id):
                order = ca.orders.get(order_id)
                if order is None:
                    return self._send(404, {"type": "about:blank", "detail": "unknown challenge", "status": 404})
                token_path = ca.webroot / ".well-known" / "acme-challenge" / order["token"]
                presented = token_path.is_file() and token_path.stat().st_size > 0
                order["valid"] = presented
                status = "valid" if presented else "invalid"
                body = {
                    "type": "http-01",
                    "url": ca.base_url + "/challenge/" + order_id,
                    "status": status,
                    "token": order["token"],
                }
                if presented:
                    body["validated"] = utc_after(0)
                else:
                    body["error"] = {"type": "urn:ietf:params:acme:error:unauthorized",
                                     "detail": "http-01 token was not published", "status": 403}
                return self._send(200, body, {"Link": "<" + ca.base_url + "/authz/" + order_id + ">; rel=\"up\""})

            def _order(self, order_id):
                if order_id not in ca.orders:
                    return self._send(404, {"type": "about:blank", "detail": "unknown order", "status": 404})
                return self._send(200, self._order_body(order_id))

            def _finalize(self, order_id):
                order = ca.orders.get(order_id)
                if order is None:
                    return self._send(404, {"type": "about:blank", "detail": "unknown order", "status": 404})
                if not order["valid"]:
                    return self._send(403, {"type": "urn:ietf:params:acme:error:unauthorized",
                                            "detail": "authorization is still pending", "status": 403})
                payload = self._payload()
                try:
                    csr = b64url_decode(payload.get("csr", ""))
                except ValueError:
                    csr = b""
                if not csr:
                    return self._send(400, {"type": "urn:ietf:params:acme:error:malformed",
                                            "detail": "csr required", "status": 400})
                domains = [item.get("value", "") for item in order["identifiers"]]
                chain, err = ca.sign(domains, csr)
                if chain is None:
                    return self._send(500, {"type": "urn:ietf:params:acme:error:serverInternal",
                                            "detail": "signing failed: " + err, "status": 500})
                (ca.base / "issued").mkdir(exist_ok=True)
                (ca.base / "issued" / (order_id + ".pem")).write_bytes(chain)
                order["cert"] = chain
                order["status"] = "valid"
                return self._send(200, self._order_body(order_id))

            def _cert(self, order_id):
                order = ca.orders.get(order_id)
                if order is None or not order["cert"]:
                    return self._send(404, {"type": "about:blank", "detail": "certificate not ready", "status": 404})
                return self._send(200, raw=order["cert"], ctype="application/pem-certificate-chain")

        return Handler


class Backups:
    """Move fixture-owned system state aside and put it back on exit."""

    def __init__(self, f, base):
        self.f = f
        self.base = base
        self.moved = []
        self.created_units = []

    def take_dir(self, path):
        if path.exists():
            dest = self.base / ("backup-" + path.name)
            shutil.move(str(path), str(dest))
            self.moved.append((dest, path))

    def take_file(self, path):
        if path.exists():
            dest = self.base / ("backup-" + path.name)
            shutil.copy2(path, dest)
            path.unlink()
            self.moved.append((dest, path))

    def restore(self):
        # Tear the probe units down first, otherwise restoring an original
        # unit file would immediately be deleted by the probe cleanup.
        for unit in self.created_units:
            self.f.run(["systemctl", "stop", unit], timeout=20)
            self.f.run(["systemctl", "disable", unit], timeout=20)
            Path("/etc/systemd/system/" + unit).unlink(missing_ok=True)
        if self.created_units:
            self.f.run(["systemctl", "daemon-reload"], timeout=20)
        for dest, path in reversed(self.moved):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.exists():
                path.unlink()
            path.parent.mkdir(parents=True, exist_ok=True)
            if dest.is_dir():
                shutil.move(str(dest), str(path))
            else:
                shutil.copy2(dest, path)
        if self.created_units:
            self.f.run(["systemctl", "daemon-reload"], timeout=20)
        self.moved = []
        self.created_units = []


def openssl_ok(f, args, name):
    r = f.run(["openssl"] + args, timeout=30)
    f.check(r.rc == 0, name, (r.err or r.out)[:300])
    return r.rc == 0


def cert_digest(path):
    return sha256(path) if path.is_file() else ""


def pair_bytes(path):
    return path.read_bytes() if path.is_file() else b""


def group_gid(name):
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def write_probe_units(f, base, backups):
    marker = base / "reloads"
    marker.mkdir(exist_ok=True)
    units = {
        "xray.service": f"""[Unit]
Description=idleleo F12 probe xray
After=network.target

[Service]
Type=simple
ExecStart=/bin/sh -c 'echo start >> {marker}/xray-starts; exec sleep 600'
ExecReload=/bin/sh -c 'echo reload >> {marker}/xray-reloads'

[Install]
WantedBy=multi-user.target
""",
        "nginx.service": f"""[Unit]
Description=idleleo F12 probe nginx
After=network.target

[Service]
Type=simple
ExecStart=/bin/sh -c 'exec sleep 600'
ExecReload=/bin/sh -c 'echo reload >> {marker}/nginx-reloads'

[Install]
WantedBy=multi-user.target
""",
    }
    for name, body in units.items():
        path = Path("/etc/systemd/system/" + name)
        backups.take_file(path)
        path.write_text(body)
        backups.created_units.append(name)
    f.run(["systemctl", "daemon-reload"], timeout=20)
    r = f.run(["systemctl", "enable", "--now", "xray", "nginx"], timeout=60)
    f.check(r.rc == 0, "probe xray/nginx units active", f"rc={r.rc} {r.err[:300]}")
    return marker


def run_cert(f, action, domain, webroot, cert, key, extra=None, env=None, timeout=90):
    cmd = [f.go, "xray", "cert", action, "--domain", domain, "--webroot", str(webroot),
           "--cert-out", str(cert), "--key-out", str(key), "--json"]
    cmd += list(extra or [])
    return f.run(cmd, timeout=timeout, env=env)


def main(f):
    f.need_root()
    f.need_systemd()
    f.need_tool("openssl")
    f.need_tool("groupadd")

    base = f.evidence / "acme-work"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    webroot = base / "webroot"
    webroot.mkdir()
    standalone = base / "standalone"
    standalone.mkdir()
    issuing = base / "issuing"
    issuing.mkdir()

    backups = Backups(f, base)
    created_group = False
    if group_gid(MANAGED_GROUP) is None:
        r = f.run(["groupadd", "--system", MANAGED_GROUP], timeout=30)
        f.check(r.rc == 0, "worker group created for the layered model", f"rc={r.rc}")
        created_group = r.rc == 0
    absent_dirs = [d for d in (MANAGED_CERT_DIR, Path("/etc/idleleo/acme"),
                               Path("/etc/idleleo/schedule"), SCHEDULE_STATE)
                   if not d.exists()]
    try:
        backups.take_dir(MANAGED_CERT_DIR)
        backups.take_dir(Path("/etc/idleleo/acme"))
        backups.take_dir(Path("/etc/idleleo/schedule"))
        backups.take_dir(SCHEDULE_STATE)

        ca = LocalCA(f, base, webroot)
        ca.start()
        f.write_json("local-ca.json", {"directory": ca.url, "caCert": str(ca.ca_cert),
                                       "port": ca.port, "level": "ACME_LOCAL_CA"})
        cert = standalone / "xray.crt"
        key = standalone / "xray.key"
        account = base / "account"
        common = ["--directory", ca.url, "--ca-cert", str(ca.ca_cert),
                  "--account-dir", str(account)]

        # 1) dry-run is read-only and reports a missing pair.
        before = f.tree_digest(standalone)
        dry = run_cert(f, "renew", "example.com", webroot, cert, key,
                       ["--dry-run", "--renew-before", "720h"])
        f.check(dry.rc == 0, "dry-run on a missing pair exit 0", f"rc={dry.rc}")
        pre = f.json_of(dry, "missing dry-run")
        if pre is not None:
            f.write_json("dry-run-missing.json", pre)
            f.check(pre.get("missing") is True, "dry-run reports missing=true", str(pre.get("missing")))
            f.check(pre.get("due") is True, "dry-run marks a missing pair as due", str(pre.get("due")))
            f.check(pre.get("certificateFile") == str(cert), "dry-run echoes the certificate path")
            f.check(pre.get("renewBefore") == "720h0m0s", "dry-run echoes the renew window")
        f.check(f.tree_digest(standalone) == before, "dry-run wrote nothing")

        # 2) real issuance against the local CA.
        issue = run_cert(f, "issue", "example.com", webroot, cert, key, common)
        f.check(issue.rc == 0, "local CA issuance exit 0", f"rc={issue.rc} {issue.err[:400]}")
        if issue.rc != 0:
            return
        issued = f.json_of(issue, "issuance report") or {}
        f.write_json("issue.json", issued)
        f.check(issued.get("issued") is True, "report issued=true", str(issued.get("issued")))
        f.check(issued.get("domain") == "example.com", "report domain", str(issued.get("domain")))
        f.check((issued.get("accountUrl") or "").startswith(ca.base_url + "/acct/"),
                "report carries the local account URL", str(issued.get("accountUrl")))
        f.check(bool(issued.get("notAfter")), "report carries notAfter", str(issued.get("notAfter")))
        f.check(cert.is_file() and key.is_file(), "certificate pair written")
        f.check(mode_of(cert) == "0o644", "standalone certificate is 0644", mode_of(cert))
        f.check(mode_of(key) == "0o600", "standalone key is 0600", mode_of(key))
        openssl_ok(f, ["verify", "-CAfile", str(ca.ca_cert), str(cert)], "issued chain verifies against the local CA")
        san = f.run(["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"], timeout=20)
        f.check("DNS:example.com" in (san.out + san.err), "issued SAN contains example.com",
                (san.out + san.err).strip()[:200])
        cert_pub = f.run(["openssl", "x509", "-in", str(cert), "-noout", "-pubkey"], timeout=20)
        key_pub = f.run(["openssl", "pkey", "-in", str(key), "-pubout"], timeout=20)
        f.check(cert_pub.out == key_pub.out and cert_pub.out != "", "certificate and key are a pair")
        account_key = account / "account.key"
        account_state = account / "account.json"
        f.check(account_key.is_file() and mode_of(account_key) == "0o600",
                "account key lives outside the certificate tree at 0600",
                f"{account_key} {mode_of(account_key) if account_key.exists() else 'missing'}")
        state = json.loads(account_state.read_text()) if account_state.is_file() else {}
        f.write_json("account-state.json", state)
        f.check((state.get("accounts") or {}).get(ca.url, "").startswith(ca.base_url + "/acct/"),
                "account state keeps one URL per CA directory", json.dumps(state)[:300])

        # 3) dry-run states: valid and due.
        ok = run_cert(f, "renew", "example.com", webroot, cert, key, ["--dry-run"])
        okj = f.json_of(ok, "valid dry-run") or {}
        f.write_json("dry-run-valid.json", okj)
        f.check(ok.rc == 0 and okj.get("due") is False and not okj.get("missing"),
                "dry-run reports a valid pair as not due", json.dumps(okj)[:200])
        f.check(bool(okj.get("renewAt")), "dry-run prints the next renewal point", str(okj.get("renewAt")))
        due = run_cert(f, "renew", "example.com", webroot, cert, key,
                       ["--dry-run", "--renew-before", "2161h"])
        duej = f.json_of(due, "due dry-run") or {}
        f.write_json("dry-run-due.json", duej)
        f.check(due.rc == 0 and duej.get("due") is True, "dry-run reports a due pair", json.dumps(duej)[:200])

        # 4) renew inside the window is skipped, and leaves the pair untouched.
        digest_before = cert_digest(cert)
        skip = run_cert(f, "renew", "example.com", webroot, cert, key, common)
        skipj = f.json_of(skip, "renew skip") or {}
        f.write_json("renew-skip.json", skipj)
        f.check(skip.rc == 0 and skipj.get("skipped") is True,
                "renew skips a certificate outside the window", json.dumps(skipj)[:200])
        f.check(cert_digest(cert) == digest_before, "a skipped renewal leaves the pair unchanged")

        # 5) user-managed marker: refuse overwrite, skip renewal, adopt with --takeover.
        marker = standalone / ".user-managed"
        marker.write_text("managed-by=user\n")
        os.chmod(marker, 0o640)
        digest_before = cert_digest(cert)
        refuse = run_cert(f, "issue", "example.com", webroot, cert, key, common)
        f.check(refuse.rc == 1, "issue refuses a user-managed pair with exit 1", f"rc={refuse.rc}")
        f.check("user-managed" in (refuse.out + refuse.err), "refusal names the user-managed marker",
                (refuse.out + refuse.err).strip()[:200])
        f.check(cert_digest(cert) == digest_before, "refused issuance leaves the user pair untouched")
        username = run_cert(f, "renew", "example.com", webroot, cert, key, common)
        usernamej = f.json_of(username, "user-managed renew") or {}
        f.write_json("renew-user-managed.json", usernamej)
        f.check(username.rc == 0 and usernamej.get("skipped") is True,
                "renew skips a user-managed pair", json.dumps(usernamej)[:200])
        dry = run_cert(f, "renew", "example.com", webroot, cert, key,
                       ["--dry-run", "--renew-before", "2161h"])
        dryj = f.json_of(dry, "user-managed dry-run") or {}
        f.write_json("dry-run-user-managed.json", dryj)
        f.check(dryj.get("userManaged") is True, "dry-run flags userManaged", json.dumps(dryj)[:200])
        adopt = run_cert(f, "issue", "example.com", webroot, cert, key, common + ["--takeover"])
        f.check(adopt.rc == 0, "--takeover adopts the pair", f"rc={adopt.rc} {adopt.err[:300]}")
        f.check(not marker.exists(), "takeover removes the user-managed marker")
        f.check((standalone / ".managed-by-idleleo").is_file(), "takeover records native ownership")

        # 6) legacy account state migrates, and refuses unexpected entries.
        legacy = standalone / "acme"
        legacy.mkdir()
        (legacy / "account.key").write_text("not a key\n")
        (legacy / "stray.txt").write_text("x\n")
        digest_before = cert_digest(cert)
        blocked = run_cert(f, "issue", "example.com", webroot, cert, key, common)
        f.check(blocked.rc == 1, "legacy state with unexpected entries fails closed", f"rc={blocked.rc}")
        f.check("refusing to migrate" in (blocked.out + blocked.err),
                "legacy failure explains the refusal", (blocked.out + blocked.err).strip()[:200])
        f.check(cert_digest(cert) == digest_before, "legacy refusal leaves the pair untouched")
        (legacy / "stray.txt").unlink()
        good_key = f.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                          "ec_paramgen_curve:P-256", "-out", str(legacy / "account.key")], timeout=30)
        f.check(good_key.rc == 0, "valid legacy account key generated", (good_key.err or "")[:200])
        account2 = base / "account2"
        migrated = run_cert(f, "issue", "example.com", webroot, cert, key,
                            ["--directory", ca.url, "--ca-cert", str(ca.ca_cert),
                             "--account-dir", str(account2)])
        f.check(migrated.rc == 0, "legacy account state migrates into the new directory",
                f"rc={migrated.rc} {migrated.err[:300]}")
        f.check((account2 / "account.key").is_file(),
                "migrated account key exists at 0600",
                mode_of(account2 / "account.key") if (account2 / "account.key").exists() else "missing")
        f.check(mode_of(account2 / "account.key") == "0o600", "migrated account key is 0600",
                mode_of(account2 / "account.key") if (account2 / "account.key").exists() else "missing")
        f.check(not legacy.exists(), "legacy account directory is removed after migration")

        # 7) a failed reload restores the previous pair, including owner/mode.
        old_cert, old_key = pair_bytes(cert), pair_bytes(key)
        old_modes = (mode_of(cert), mode_of(key))
        old_owners = (owner_of(cert), owner_of(key))
        broken = run_cert(f, "issue", "example.com", webroot, cert, key,
                          common + ["--reload-command", "false"])
        f.check(broken.rc == 1, "failed reload exits 1", f"rc={broken.rc}")
        f.check("reload failed" in (broken.out + broken.err), "failed reload is reported",
                (broken.out + broken.err).strip()[:300])
        f.check(pair_bytes(cert) == old_cert and pair_bytes(key) == old_key,
                "failed reload restores the previous pair byte for byte")
        f.check((mode_of(cert), mode_of(key)) == old_modes, "failed reload restores file modes",
                f"{mode_of(cert)}/{mode_of(key)} vs {old_modes[0]}/{old_modes[1]}")
        f.check((owner_of(cert), owner_of(key)) == old_owners, "failed reload restores file owners",
                f"{owner_of(cert)} vs {old_owners[0]}")

        # 8) layered permissions in the managed directory.
        gid = group_gid(MANAGED_GROUP)
        managed_cert = MANAGED_CERT_DIR / "xray.crt"
        managed_key = MANAGED_CERT_DIR / "xray.key"
        managed = run_cert(f, "issue", "perm.example.com", webroot, managed_cert, managed_key, common)
        f.check(managed.rc == 0, "managed-directory issuance exit 0", f"rc={managed.rc} {managed.err[:300]}")
        if managed.rc == 0:
            f.check(mode_of(MANAGED_CERT_DIR) == "0o750", "managed certificate directory is 0750",
                    mode_of(MANAGED_CERT_DIR))
            f.check(managed_cert.is_file() and mode_of(managed_cert) == "0o640",
                    "managed certificate is 0640", mode_of(managed_cert) if managed_cert.exists() else "missing")
            f.check(managed_key.is_file() and mode_of(managed_key) == "0o640",
                    "managed key is 0640", mode_of(managed_key) if managed_key.exists() else "missing")
            f.check(owner_of(managed_cert)[1] == gid and owner_of(managed_key)[1] == gid,
                    "managed pair is owned by root:<group>", f"{owner_of(managed_cert)} gid={gid}")
            marker_path = MANAGED_CERT_DIR / ".managed-by-idleleo"
            f.check(marker_path.is_file() and mode_of(marker_path) == "0o640",
                    "ownership marker is 0640 in the managed directory",
                    mode_of(marker_path) if marker_path.exists() else "missing")

        # 9) --production preflights via staging by default, without public traffic.
        staging_cert = issuing / "staging.crt"
        staging_key = issuing / "staging.key"
        preflight = run_cert(f, "issue", "invalid", webroot, staging_cert, staging_key, ["--production"])
        f.check(preflight.rc != 0, "--production without an explicit directory does not issue", f"rc={preflight.rc}")
        f.check("staging preflight" in (preflight.out + preflight.err),
                "default --production path names the staging preflight", (preflight.out + preflight.err).strip()[:300])
        bypass = run_cert(f, "issue", "invalid", webroot, staging_cert, staging_key,
                          ["--production", "--no-staging-check"])
        f.check(bypass.rc != 0, "--no-staging-check still rejects an invalid domain", f"rc={bypass.rc}")
        f.check("staging preflight" not in (bypass.out + bypass.err),
                "--no-staging-check bypasses the staging preflight", (bypass.out + bypass.err).strip()[:300])
        f.check(not staging_cert.exists() and not staging_key.exists(),
                "rejected production/preflight attempts write no pair")

        # 10) schedule skips a user-managed pair and reloads when it is replaced.
        SCHEDULE_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        relative = lambda p: str(p).lstrip("/")
        SCHEDULE_CONFIG.write_text(json.dumps({
            "schemaVersion": 1,
            "intervalSeconds": 3600,
            "jobs": ["cert-renew"],
            "certDomain": "example.com",
            "certWebroot": relative(webroot),
            "certFile": relative(managed_cert),
            "certKeyFile": relative(managed_key),
            "acmeDirectory": ca.url,
        }, indent=2) + "\n")
        os.chmod(SCHEDULE_CONFIG, 0o640)
        # Put a user-managed pair in the managed directory (operator-supplied).
        managed_cert.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cert, managed_cert)
        shutil.copy2(key, managed_key)
        (MANAGED_CERT_DIR / ".managed-by-idleleo").unlink(missing_ok=True)
        (MANAGED_CERT_DIR / ".user-managed").write_text("managed-by=user\n")
        os.chmod(MANAGED_CERT_DIR / ".user-managed", 0o640)
        reloads = write_probe_units(f, base, backups)
        first = f.run([f.go, "schedule", "run", "--job", "cert-renew", "--json"], timeout=90)
        firstj = f.json_of(first, "schedule baseline") or {}
        f.write_json("schedule-baseline.json", firstj)
        f.check(first.rc == 0, "schedule baseline run exit 0", f"rc={first.rc} {first.err[:300]}")
        detail = json.dumps(firstj)
        f.check("user-managed" in detail, "schedule skips a user-managed pair", detail[:300])
        f.check(_count(reloads / "xray-starts") == 1,
                "baseline does not restart services",
                _count(reloads / "xray-starts"))
        managed_digest = cert_digest(managed_cert)
        shutil.copy2(managed_cert, base / "operator-old.crt")
        # The operator replaces the pair; the schedule must reload, not reissue.
        replacement = issuing / "replacement"
        replacement.mkdir()
        rep = run_cert(f, "issue", "replacement.example.com", webroot,
                       replacement / "xray.crt", replacement / "xray.key", common)
        f.check(rep.rc == 0, "replacement pair issued", f"rc={rep.rc} {rep.err[:300]}")
        if rep.rc == 0:
            shutil.copy2(replacement / "xray.crt", managed_cert)
            shutil.copy2(replacement / "xray.key", managed_key)
            os.chmod(managed_cert, 0o640)
            os.chmod(managed_key, 0o640)
            starts_before = _count(reloads / "xray-starts")
            reload_before = _count(reloads / "nginx-reloads")
            second = f.run([f.go, "schedule", "run", "--job", "cert-renew", "--json"], timeout=90)
            secondj = f.json_of(second, "schedule reload") or {}
            f.write_json("schedule-reload.json", secondj)
            f.check(second.rc == 0, "schedule reload run exit 0", f"rc={second.rc} {second.err[:300]}")
            detail = json.dumps(secondj)
            f.check("user-managed" in detail, "replacement stays user-managed", detail[:300])
            f.check(cert_digest(managed_cert) == cert_digest(replacement / "xray.crt"),
                    "schedule never reissues a user-managed pair")
            f.check(_count(reloads / "xray-starts") == starts_before + 1,
                    "replacement restarts xray", f"{starts_before} -> {_count(reloads / 'xray-starts')}")
            f.check(_count(reloads / "nginx-reloads") == reload_before + 1,
                    "replacement reloads nginx", f"{reload_before} -> {_count(reloads / 'nginx-reloads')}")
        f.check(managed_digest == cert_digest(base / "operator-old.crt"),
                "baseline recorded the operator pair before replacement")
    finally:
        if 'ca' in locals():
            ca.stop()
        backups.restore()
        for path in absent_dirs:
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
        if created_group:
            f.run(["groupdel", MANAGED_GROUP], timeout=30)


def _count(path):
    if not path.is_file():
        return 0
    return len([line for line in path.read_text().splitlines() if line.strip()])


if __name__ == "__main__":
    sys.exit(run_fixture("F12", main))
