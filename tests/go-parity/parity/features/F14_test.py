#!/usr/bin/env python3
"""F14 — native self-update channel and the scheduled auto-update job.

Preview evidence level: CONTAINER_VERIFIED + LOCAL_RELEASE_ORIGIN.

The fixture builds a signed Go release manifest on a loopback HTTP origin and
drives the real `update` command against a disposable sandbox root. It proves
the fail-closed signature check, digest/ELF/health gates, a successful install,
an explicit rollback when the new binary fails its health check, and the
downgrade refusal. It then installs the native schedule in the same sandbox:
the timer cadence, the explicit auto-update degradation without a channel, and
a real scheduled apply once the channel is configured.

The fixed Bash baseline is read from the checkout (install.sh installs
`0 1 * * * bash auto_update.sh`; that script updates script/Xray/Nginx), so the
Go result is always compared with the legacy cadence rather than in isolation.
"""
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

SANDBOX_MARKER = ".idleleo-phase01-sandbox"
SANDBOX_VALUE = "I_ACCEPT_DISPOSABLE_SANDBOX"
BASH_CRON = '0 1 * * * bash'


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def platform_key():
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "linux-arm64"
    if machine in ("x86_64", "amd64"):
        return "linux-amd64"
    return ""


def bump_patch(version):
    base = version.split("-", 1)[0].split("+", 1)[0]
    parts = base.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return "0.0.1"
    return f"{parts[0]}.{parts[1]}.{int(parts[2]) + 1}"


class Origin:
    """Loopback HTTP origin serving signed manifests and release assets."""

    def __init__(self, routes):
        self.routes = routes
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        origin = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                body = origin.routes.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def canonical(obj):
    """Byte-for-byte match for release.CanonicalManifest."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_manifest(f, obj, key, work):
    raw = canonical(obj)
    payload = work / "canonical.bin"
    signature = work / "signature.bin"
    payload.write_bytes(raw)
    r = f.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key),
               "-in", str(payload), "-out", str(signature)], timeout=30)
    f.check(r.rc == 0, "manifest signed with ed25519", (r.err or "")[:200])
    signed = dict(obj)
    signed["signature"] = "ed25519:" + base64.b64encode(signature.read_bytes()).decode()
    return json.dumps(signed, separators=(",", ":")).encode()


def manifest(version, asset_name, data, url, platform_name):
    return {
        "schemaVersion": 1,
        "channel": "go",
        "version": version,
        "assets": {platform_name: {
            "name": asset_name,
            "sha256": sha256_bytes(data),
            "size": len(data),
            "url": url,
        }},
    }


def update(f, root, sub, extra, env, timeout=90):
    cmd = [f.go, "--root", str(root), "update", sub] + list(extra)
    return f.run(cmd, timeout=timeout, env=env)


def schedule(f, root, sub, extra, env, timeout=90):
    cmd = [f.go, "--root", str(root), "schedule", sub] + list(extra)
    return f.run(cmd, timeout=timeout, env=env)


def read_json(path):
    return json.loads(path.read_text()) if path.is_file() else {}


def main(f):
    f.need_root()
    f.need_tool("openssl")
    f.need_tool("systemctl")
    f.check(f.bash_repo is not None and (f.bash_repo / "scripts/auto_update.sh").is_file(),
            "Bash auto_update.sh baseline is present",
            str(f.bash_repo))

    work = f.evidence / "release-work"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    root = work / "root"
    root.mkdir()
    (root / SANDBOX_MARKER).write_text(SANDBOX_VALUE + "\n")
    os.chmod(root / SANDBOX_MARKER, 0o600)

    key = work / "release.key"
    pub = work / "release.pub"
    r = f.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], timeout=30)
    f.check(r.rc == 0, "ed25519 release key generated", (r.err or "")[:200])
    r = f.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], timeout=30)
    f.check(r.rc == 0, "ed25519 public key exported", (r.err or "")[:200])
    env = dict(f.env, IDLELEO_RELEASE_PUBKEY_FILE=str(pub))

    version_run = f.run([f.go, "--version"], timeout=20)
    output = (version_run.out or "").strip()
    match = re.search(r"\d+\.\d+\.\d+(?:[-+]\S+)?", output)
    current = match.group(0) if match else ""
    f.check(version_run.rc == 0 and "idleleo" in output and bool(current),
            "manager reports its release version", output)
    if not current:
        return
    plat = platform_key()
    f.check(bool(plat), "fixture runs on a supported release platform", platform.machine())
    if not plat:
        return

    binary = f.go.read_bytes()
    bad = Path("/bin/true").read_bytes()
    rollback_version = bump_patch(current)
    manifests = {
        "/manifest-unsigned.json": json.dumps(
            manifest(current, "idleleo", binary, "/idleleo", plat), separators=(",", ":")).encode(),
        "/manifest.json": sign_manifest(
            f, manifest(current, "idleleo", binary, "/idleleo", plat), key, work),
        "/manifest-rollback.json": sign_manifest(
            f, manifest(rollback_version, "idleleo", bad, "/bad", plat), key, work),
        "/manifest-badsha.json": sign_manifest(
            f, manifest(bump_patch(current), "idleleo", binary, "/idleleo", plat), key, work),
        "/manifest-downgrade.json": sign_manifest(
            f, manifest("0.1.0", "idleleo", binary, "/idleleo", plat), key, work),
    }
    # Corrupt the digest of the badsha manifest after signing: the signature is
    # over the manifest, so this must fail before any download/install.
    badsha = json.loads(manifests["/manifest-badsha.json"])
    badsha["assets"][plat]["sha256"] = "0" * 64
    manifests["/manifest-badsha.json"] = sign_manifest(
        f, {k: v for k, v in badsha.items() if k != "signature"}, key, work)

    origin = Origin({"/idleleo": binary, "/bad": bad, **manifests})
    origin.start()
    try:
        manifest_url = origin.base + "/manifest.json"

        # 1) Read-only defaults: no channel, stable exit codes.
        status = update(f, root, "status", ["--json"], env)
        statusj = f.json_of(status, "initial status") or {}
        f.write_json("status-initial.json", statusj)
        f.check(status.rc == 0 and statusj.get("configured") is False,
                "status reports no channel before configuration", json.dumps(statusj)[:200])
        missing = update(f, root, "check", ["--json"], env)
        f.check(missing.rc == 3, "check without a channel exits 3", f"rc={missing.rc}")
        f.check("no Go release channel" in (missing.out + missing.err),
                "check explains the missing channel", (missing.out + missing.err).strip()[:200])

        # 2) Fail closed on an unsigned manifest and on a bad digest.
        unsigned = update(f, root, "check", ["--manifest-url", origin.base + "/manifest-unsigned.json", "--json"], env)
        f.check(unsigned.rc == 1, "unsigned manifest is refused", f"rc={unsigned.rc}")
        f.check("signature" in (unsigned.out + unsigned.err).lower(),
                "unsigned refusal names the signature", (unsigned.out + unsigned.err).strip()[:240])
        badsha = update(f, root, "check", ["--manifest-url", origin.base + "/manifest-badsha.json", "--json"], env)
        badshaj = f.json_of(badsha, "badsha check") or {}
        f.write_json("check-badsha.json", badshaj)
        f.check(badsha.rc == 1, "digest mismatch fails the check", f"rc={badsha.rc}")
        f.check("sha256 mismatch" in (badsha.out + badsha.err),
                "digest refusal names sha256", (badsha.out + badsha.err).strip()[:240])
        f.check(not (root / "var/lib/idleleo/release/state.json").exists(),
                "refused checks write no release state")

        # 3) Configure and verify the channel read-only.
        configure = update(f, root, "configure",
                           ["--manifest-url", manifest_url, "--install-path", "tmp/release/idleleo"], env)
        f.check(configure.rc == 0, "configure exit 0", f"rc={configure.rc} {configure.err[:300]}")
        channel_path = root / "etc/idleleo/release/channel.json"
        channel = read_json(channel_path)
        f.write_json("channel.json", channel)
        f.check(channel.get("channel") == "go" and channel.get("manifestUrl") == manifest_url,
                "channel is pinned to the Go manifest", json.dumps(channel)[:240])
        f.check(channel.get("installPath") == "tmp/release/idleleo", "channel records the install path",
                str(channel.get("installPath")))
        f.check(channel_path.is_file() and (channel_path.stat().st_mode & 0o777) == 0o640,
                "channel file is 0640", oct(channel_path.stat().st_mode & 0o777) if channel_path.exists() else "missing")
        status = update(f, root, "status", ["--json"], env)
        statusj = f.json_of(status, "configured status") or {}
        f.write_json("status-configured.json", statusj)
        f.check(statusj.get("configured") is True and statusj.get("channel") == "go",
                "status reports the configured channel", json.dumps(statusj)[:240])

        check = update(f, root, "check", ["--json"], env)
        checkj = f.json_of(check, "check") or {}
        f.write_json("check-available.json", checkj)
        f.check(check.rc == 0, "check exit 0", f"rc={check.rc} {check.err[:300]}")
        f.check(checkj.get("verified") is True and checkj.get("state") == "available",
                "check verifies a first install as available", json.dumps(checkj)[:240])
        f.check(checkj.get("latestVersion") == current and checkj.get("platform") == plat,
                "check reports version and platform", f"{checkj.get('latestVersion')} {checkj.get('platform')}")
        asset = checkj.get("asset") or {}
        f.check(asset.get("sha256") == sha256_bytes(binary) and asset.get("size") == len(binary),
                "check reports the exact asset digest and size", json.dumps(asset)[:240])

        # 4) Real install, health check and idempotent second apply.
        apply = update(f, root, "apply", ["--json"], env, timeout=120)
        applyj = f.json_of(apply, "apply") or {}
        f.write_json("apply.json", applyj)
        f.check(apply.rc == 0, "apply exit 0", f"rc={apply.rc} {apply.err[:400]}")
        f.check(applyj.get("action") == "applied" and applyj.get("newVersion") == current,
                "apply installed the manifest version", json.dumps(applyj)[:300])
        f.check(current in str(applyj.get("healthOutput", "")),
                "health output identifies the new version", str(applyj.get("healthOutput")))
        install_path = Path(applyj.get("installPath", ""))
        f.check(install_path.is_file() and sha256_bytes(install_path.read_bytes()) == sha256_bytes(binary),
                "installed binary matches the verified asset", str(install_path))
        f.check(install_path.is_file() and (install_path.stat().st_mode & 0o777) == 0o755,
                "installed binary is 0755", oct(install_path.stat().st_mode & 0o777) if install_path.exists() else "missing")
        state = read_json(root / "var/lib/idleleo/release/state.json")
        f.write_json("state.json", state)
        f.check(state.get("version") == current and state.get("sha256") == sha256_bytes(binary),
                "state records the applied release", json.dumps(state)[:240])
        again = update(f, root, "apply", ["--json"], env, timeout=120)
        againj = f.json_of(again, "second apply") or {}
        f.write_json("apply-again.json", againj)
        f.check(again.rc == 0 and againj.get("action") == "up-to-date",
                "second apply is a no-op", json.dumps(againj)[:240])

        # 5) Health failure rolls the previous binary back, byte for byte.
        before = install_path.read_bytes()
        broken = update(f, root, "apply", ["--manifest-url", origin.base + "/manifest-rollback.json", "--json"],
                        env, timeout=120)
        brokenj = f.json_of(broken, "rollback apply") or {}
        f.write_json("apply-rollback.json", brokenj)
        f.check(broken.rc == 1, "failed health check exits 1", f"rc={broken.rc}")
        f.check(brokenj.get("action") == "rolled-back", "report marks the rollback", json.dumps(brokenj)[:300])
        f.check("restored" in (broken.out + broken.err).lower(),
                "rollback is reported to the operator", (broken.out + broken.err).strip()[:300])
        f.check(install_path.read_bytes() == before, "rollback restores the previous binary")
        state = read_json(root / "var/lib/idleleo/release/state.json")
        f.check(state.get("version") == current and state.get("sha256") == sha256_bytes(binary),
                "rollback leaves the recorded release untouched", json.dumps(state)[:240])

        # 6) A valid-but-older manifest is refused before any write.
        downgrade = update(f, root, "check", ["--manifest-url", origin.base + "/manifest-downgrade.json", "--json"], env)
        downgradej = f.json_of(downgrade, "downgrade check") or {}
        f.write_json("check-downgrade.json", downgradej)
        f.check(downgrade.rc == 4, "downgrade check exits 4", f"rc={downgrade.rc}")
        f.check(downgradej.get("state") == "refused-downgrade", "downgrade state is explicit",
                json.dumps(downgradej)[:240])
        apply_down = update(f, root, "apply", ["--manifest-url", origin.base + "/manifest-downgrade.json", "--json"],
                            env, timeout=60)
        f.check(apply_down.rc == 4, "downgrade apply exits 4", f"rc={apply_down.rc}")
        f.check(install_path.read_bytes() == before, "downgrade never touches the installed binary")

        # 7) Native schedule: same sandbox, no cron, explicit degradation.
        install = schedule(f, root, "install", ["--json"], env)
        installj = f.json_of(install, "schedule install") or {}
        f.write_json("schedule-install.json", installj)
        f.check(install.rc == 0, "schedule install exit 0", f"rc={install.rc} {install.err[:300]}")
        f.check(installj.get("intervalSeconds") == 3600, "default interval is 3600s",
                str(installj.get("intervalSeconds")))
        f.check(sorted(installj.get("jobs") or []) == ["auto-update", "cert-renew", "geodata-refresh", "stats-collect"],
                "native schedule owns all four legacy responsibilities", json.dumps(installj.get("jobs")))
        degraded = " ".join(installj.get("degradedJobs") or [])
        f.check("auto-update" in degraded and "retained" in degraded,
                "auto-update degradation is explicit", degraded[:300])
        f.check(installj.get("systemd") == "sandbox-not-queried",
                "sandbox install does not touch the host systemd", str(installj.get("systemd")))
        config_path = root / "etc/idleleo/schedule/jobs.json"
        config = read_json(config_path)
        f.write_json("schedule-config.json", config)
        f.check(config.get("intervalSeconds") == 3600 and sorted(config.get("jobs") or []) ==
                ["auto-update", "cert-renew", "geodata-refresh", "stats-collect"],
                "persisted schedule config matches the report", json.dumps(config)[:300])
        timer_path = root / "etc/systemd/system/idleleo-schedule.timer"
        timer = timer_path.read_text() if timer_path.is_file() else ""
        f.check("OnUnitActiveSec=3600s" in timer and "Persistent=true" in timer,
                "timer runs every 3600s persistently", timer[:300])
        f.check(not (root / "var/spool/cron").exists(),
                "native schedule writes no crontab")

        # 8) The fixed Bash cadence is the comparison baseline.
        install_sh = (f.bash_repo / "install.sh").read_text()
        f.check(BASH_CRON in install_sh and "auto_update.sh" in install_sh,
                "Bash baseline installs the daily 01:00 auto_update.sh cron")
        bash_update = (f.bash_repo / "scripts/auto_update.sh").read_text()
        f.check("xray" in bash_update and "nginx" in bash_update,
                "Bash auto_update.sh covers Xray and Nginx")
        f.check("3600" in timer and BASH_CRON in install_sh,
                "Go timer and Bash cron are both recorded for the comparison")

        # 9) Scheduled auto-update: explicit degraded without a channel, then a
        #    real apply once the channel exists.
        channel_backup = channel_path.read_bytes()
        channel_path.unlink()
        degraded_run = schedule(f, root, "run", ["--job", "auto-update", "--json"], env)
        degradedj = f.json_of(degraded_run, "degraded auto-update") or {}
        f.write_json("schedule-auto-update-degraded.json", degradedj)
        f.check(degraded_run.rc == 0, "degraded scheduled run exits 0", f"rc={degraded_run.rc}")
        results = degradedj.get("results") or []
        f.check(results and results[0].get("result") == "degraded",
                "scheduled auto-update reports degraded", json.dumps(results)[:300])
        f.check("no Go release channel" in str(results[0].get("detail", "")),
                "degraded detail names the missing channel", str(results[0].get("detail"))[:240])
        channel_path.parent.mkdir(parents=True, exist_ok=True)
        channel_path.write_bytes(channel_backup)
        install_path.unlink()
        (root / "var/lib/idleleo/release/state.json").unlink(missing_ok=True)
        scheduled = schedule(f, root, "run", ["--job", "auto-update", "--json"], env, timeout=120)
        scheduledj = f.json_of(scheduled, "scheduled apply") or {}
        f.write_json("schedule-auto-update-applied.json", scheduledj)
        f.check(scheduled.rc == 0, "scheduled apply exit 0", f"rc={scheduled.rc} {scheduled.err[:400]}")
        results = scheduledj.get("results") or []
        f.check(results and results[0].get("result") == "ok",
                "scheduled auto-update applies the channel", json.dumps(results)[:300])
        f.check("updated" in str(results[0].get("detail", "")),
                "scheduled detail records the version change", str(results[0].get("detail"))[:300])
        f.check(install_path.is_file() and sha256_bytes(install_path.read_bytes()) == sha256_bytes(binary),
                "scheduled apply installed the verified binary", str(install_path))
        log_path = root / "var/log/idleleo/schedule/schedule.log"
        log = log_path.read_text() if log_path.is_file() else ""
        f.check("auto-update" in log and "degraded" in log and "ok" in log,
                "schedule log keeps both outcomes", log[:300])
    finally:
        origin.stop()


if __name__ == "__main__":
    sys.exit(run_fixture("F14", main))
