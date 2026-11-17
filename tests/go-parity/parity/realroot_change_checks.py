#!/usr/bin/env python3
"""Real-root change acceptance inside a privileged systemd container.

Everything runs against the container's own /etc, /var and systemd: the
environment is installed with `idleleo xray install` (no hand-written metadata),
and every mutation goes through the real host.RequireSystemWrite gate and the
real change transaction.

For every success it asserts the bytes on disk, the metadata sha256 and a real
service restart (MainPID plus /proc starttime), not just the exit code. Failure
paths assert the config is exactly the old version afterwards and that
`change recover` converges.

Exit 0 only when every check passes. Results are written to
<evidence>/realroot-result.json.
"""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

GO = "/work/bin/idleleo"
XRAY_SRC = "/opt/xray/xray"
INSTALLED_BIN = Path("/usr/local/bin/xray")
UNIT = Path("/etc/systemd/system/xray.service")
CONFIG = Path("/etc/idleleo/conf/xray/config.json")
META = Path("/etc/idleleo/v1/metadata.json")
JOURNAL = Path("/var/lib/idleleo/transactions/phase01.json")
AUDIT = Path("/var/log/idleleo/system-writes.log")
ROLLBACK = CONFIG.parent / ".idleleo-phase01-rollback"
CANDIDATE_GLOB = ".idleleo-phase01-candidate-*"
HOOK_APPLY = Path("/usr/local/bin/idleleo-xray-apply")
HOOK_FAIL = Path("/usr/local/bin/idleleo-xray-fail")
HOOK_KILL = Path("/usr/local/bin/idleleo-xray-kill-once")
KILL_ARMED = Path("/run/idleleo-kill-armed")
BASE_PORT = 18443
ACK = {"IDLELEO_ALLOW_SYSTEM_WRITES": "I_ACCEPT_CONTAINER_ONLY"}
EVIDENCE = Path("/work/evidence")

RESULT = {"schemaVersion": 1, "ok": True, "checks": [], "installReport": None}


class CheckFailed(Exception):
    pass


def sha256(path):
    import hashlib

    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sh(cmd, timeout=180, ack=True):
    env = dict(os.environ)
    if ack:
        env.update(ACK)
    else:
        env.pop("IDLELEO_ALLOW_SYSTEM_WRITES", None)
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True,
                          timeout=timeout, env=env)


def run_ok(cmd, timeout=180, ack=True):
    return sh(cmd, timeout=timeout, ack=ack)


def require(cond, msg):
    if not cond:
        raise CheckFailed(msg)


def check(name, fn):
    try:
        detail = fn()
    except CheckFailed as exc:
        RESULT["ok"] = False
        RESULT["checks"].append({"name": name, "status": "FAIL", "detail": str(exc)})
        print(f"FAIL {name}: {exc}")
        raise
    except Exception as exc:  # noqa: BLE001 - report every failure shape
        RESULT["ok"] = False
        RESULT["checks"].append({"name": name, "status": "FAIL", "detail": repr(exc)})
        print(f"FAIL {name}: {exc!r}")
        raise
    RESULT["checks"].append({"name": name, "status": "PASS", "detail": detail})
    print(f"PASS {name}: {detail}")
    return detail


def metadata():
    require(META.is_file(), f"metadata missing at {META}")
    return json.loads(META.read_text())


def config():
    require(CONFIG.is_file(), f"runtime config missing at {CONFIG}")
    return json.loads(CONFIG.read_text())


def service_identity():
    out = sh(["systemctl", "show", "-p", "MainPID", "--value", "xray"], timeout=20).stdout.strip()
    pid = int(out or "0")
    starttime = ""
    if pid > 0 and Path(f"/proc/{pid}/stat").is_file():
        starttime = Path(f"/proc/{pid}/stat").read_text().split()[21]
    active = sh(["systemctl", "is-active", "xray"], timeout=20).stdout.strip()
    return {"pid": pid, "starttime": starttime, "active": active}


def require_active(ident, where):
    require(ident["active"] == "active", f"{where}: xray is {ident['active']!r}, want active")
    require(ident["pid"] > 0, f"{where}: xray has no MainPID")


def require_restarted(before, after, where):
    require_active(after, where)
    require((before["pid"], before["starttime"]) != (after["pid"], after["starttime"]),
            f"{where}: service did not restart (pid={after['pid']} starttime={after['starttime']})")


def journal_last():
    if not JOURNAL.is_file():
        return None
    entries = json.loads(JOURNAL.read_text())
    return entries[-1] if entries else None


def no_leftovers(where):
    require(not ROLLBACK.exists(), f"{where}: rollback snapshot left behind")
    leftovers = list(CONFIG.parent.glob(CANDIDATE_GLOB))
    require(not leftovers, f"{where}: candidate files left behind: {leftovers}")


def xray_test(path=CONFIG):
    p = sh([INSTALLED_BIN, "-test", "-config", str(path)], timeout=60, ack=False)
    require(p.returncode == 0, f"xray -test rejected {path}: {p.stderr[:300]}")
    return True


def write_hooks():
    HOOK_APPLY.write_text("#!/bin/sh\nset -eu\nsystemctl restart xray\n")
    HOOK_FAIL.write_text("#!/bin/sh\nset -eu\nexit 1\n")
    HOOK_KILL.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "if [ ! -f /run/idleleo-kill-armed ]; then\n"
        "    : > /run/idleleo-kill-armed\n"
        "    kill -9 \"$PPID\"\n"
        "    exit 1\n"
        "fi\n"
        "systemctl restart xray\n"
    )
    for hook in (HOOK_APPLY, HOOK_FAIL, HOOK_KILL):
        hook.chmod(0o755)


def cleanup_install():
    sh(["systemctl", "stop", "xray"], timeout=30, ack=False)
    sh(["systemctl", "disable", "xray"], timeout=30, ack=False)
    UNIT.unlink(missing_ok=True)
    INSTALLED_BIN.unlink(missing_ok=True)
    for path in (Path("/etc/idleleo"), Path("/var/lib/idleleo"), Path("/var/log/idleleo")):
        shutil.rmtree(path, ignore_errors=True)
    for hook in (HOOK_APPLY, HOOK_FAIL, HOOK_KILL):
        hook.unlink(missing_ok=True)
    KILL_ARMED.unlink(missing_ok=True)
    sh(["systemctl", "daemon-reload"], timeout=30, ack=False)


def change_port(port, service, fault=None, ack=True, container=True, validator=None):
    cmd = [GO, "--root", "/", "change", "set-inbound-port",
           "--sandbox", "/", "--port", str(port),
           "--validator", validator or str(INSTALLED_BIN),
           "--service", str(service), "--json"]
    if fault:
        cmd += ["--fault", fault]
    if container:
        cmd.append("--container")
    return sh(cmd, timeout=120, ack=ack)


def recover():
    return sh([GO, "--root", "/", "change", "recover", "--container", "--json"], timeout=60)


def check_recover_none(where):
    p = recover()
    require(p.returncode == 0, f"{where}: recover rc={p.returncode}: {p.stderr[:300]}")
    rep = json.loads(p.stdout)
    require(rep["converged"] is True, f"{where}: recover not converged: {rep}")
    return rep


def phase_install():
    def do():
        cleanup_install()
        p = sh([GO, "xray", "install", "--binary", XRAY_SRC, "--mode", "reality",
                "--domain", "example.com", "--port", str(BASE_PORT), "--container", "--json"],
               timeout=180)
        require(p.returncode == 0, f"install rc={p.returncode}: {p.stderr[:400]}")
        rep = json.loads(p.stdout)
        RESULT["installReport"] = rep
        require(rep.get("validatorExit") == 0, f"install validatorExit={rep.get('validatorExit')}")
        require(rep.get("serviceActive") == "active", f"install serviceActive={rep.get('serviceActive')}")
        require(rep.get("serviceEnabled") == "enabled", f"install serviceEnabled={rep.get('serviceEnabled')}")
        require(CONFIG.is_file() and UNIT.is_file() and INSTALLED_BIN.is_file(),
                "install did not produce config/unit/binary")
        require(rep.get("configSha256") == sha256(CONFIG), "install configSha256 mismatch")
        meta = metadata()
        require(meta.get("runtimeConfigPath") == "etc/idleleo/conf/xray/config.json",
                f"metadata runtimeConfigPath={meta.get('runtimeConfigPath')}")
        require(meta.get("runtimeSha256") == sha256(CONFIG),
                f"metadata runtimeSha256={meta.get('runtimeSha256')} != {sha256(CONFIG)}")
        ident = service_identity()
        require_active(ident, "install")
        write_hooks()
        audit = AUDIT.read_text() if AUDIT.is_file() else ""
        require("mode=container" in audit, "install did not record a container write in the audit log")
        return {"configSha256": sha256(CONFIG), "pid": ident["pid"]}

    return check("install writes real metadata and a running unit", do)


def phase_gate():
    def no_container():
        before = sha256(CONFIG)
        pid = service_identity()["pid"]
        p = change_port(BASE_PORT + 1, HOOK_APPLY, container=False)
        require(p.returncode == 2, f"without --container rc={p.returncode}: {p.stderr[:300]}")
        require("--container" in p.stderr, f"refusal does not name --container: {p.stderr[:300]}")
        require(sha256(CONFIG) == before, "refused write changed the config")
        require(service_identity()["pid"] == pid, "refused write restarted the service")
        return "rc=2, config and PID unchanged"

    def no_env():
        before = sha256(CONFIG)
        pid = service_identity()["pid"]
        p = change_port(BASE_PORT + 1, HOOK_APPLY, ack=False)
        require(p.returncode == 2, f"without env rc={p.returncode}: {p.stderr[:300]}")
        require("IDLELEO_ALLOW_SYSTEM_WRITES" in p.stderr,
                f"refusal does not name the env acknowledgement: {p.stderr[:300]}")
        require(sha256(CONFIG) == before, "refused write changed the config")
        require(service_identity()["pid"] == pid, "refused write restarted the service")
        return "rc=2, config and PID unchanged"

    check("gate refuses real-root write without --container", no_container)
    return check("gate refuses real-root write without the env acknowledgement", no_env)


def phase_port():
    def do():
        before_sha = sha256(CONFIG)
        before_pid = service_identity()
        new_port = BASE_PORT + 1
        p = change_port(new_port, HOOK_APPLY)
        require(p.returncode == 0, f"change rc={p.returncode}: {p.stderr[:400]}")
        entry = json.loads(p.stdout)
        require(entry["state"] == "COMMITTED", f"state={entry['state']}")
        cfg = config()
        require(cfg["inbounds"][0]["port"] == new_port, f"port={cfg['inbounds'][0]['port']}")
        after_sha = sha256(CONFIG)
        require(after_sha != before_sha, "config bytes did not change")
        require(entry["newSha256"] == after_sha, "journal newSha256 does not match the config")
        meta = metadata()
        require(meta["runtimeSha256"] == after_sha,
                f"metadata runtimeSha256={meta['runtimeSha256']} != {after_sha}")
        after_pid = service_identity()
        require_restarted(before_pid, after_pid, "port change")
        xray_test()
        last = journal_last()
        require(last and last["state"] == "COMMITTED", f"journal last={last}")
        no_leftovers("port change")
        return {"port": new_port, "sha": after_sha, "pid": after_pid["pid"]}

    return check("port change commits, refreshes metadata and restarts the service", do)


def phase_user_add():
    def do():
        before_sha = sha256(CONFIG)
        before_pid = service_identity()
        email = "realroot@example.com"
        p = sh([GO, "xray", "user", "add", "--sandbox", "/",
                "--validator", str(INSTALLED_BIN), "--service", str(HOOK_APPLY),
                "--email", email, "--container", "--json"], timeout=120)
        require(p.returncode == 0, f"user add rc={p.returncode}: {p.stderr[:400]}")
        body = json.loads(p.stdout)
        require(body["entry"]["state"] == "COMMITTED", f"state={body['entry']['state']}")
        uuid = body["user"]["uuid"]
        clients = config()["inbounds"][0]["settings"]["clients"]
        require(any(c.get("email") == email for c in clients), f"client {email} not in config")
        after_sha = sha256(CONFIG)
        require(after_sha != before_sha, "config bytes did not change")
        require(metadata()["runtimeSha256"] == after_sha, "metadata sha was not refreshed")
        require_restarted(before_pid, service_identity(), "user add")
        xray_test()
        no_leftovers("user add")
        return {"email": email, "uuid": uuid}

    return check("user add commits, updates metadata and restarts the service", do)


def phase_user_remove():
    def do():
        before_sha = sha256(CONFIG)
        before_pid = service_identity()
        email = "realroot@example.com"
        p = sh([GO, "xray", "user", "remove", "--sandbox", "/",
                "--validator", str(INSTALLED_BIN), "--service", str(HOOK_APPLY),
                "--email", email, "--container", "--json"], timeout=120)
        require(p.returncode == 0, f"user remove rc={p.returncode}: {p.stderr[:400]}")
        body = json.loads(p.stdout)
        require(body["entry"]["state"] == "COMMITTED", f"state={body['entry']['state']}")
        clients = config()["inbounds"][0]["settings"]["clients"]
        require(not any(c.get("email") == email for c in clients), f"client {email} still present")
        after_sha = sha256(CONFIG)
        require(after_sha != before_sha, "config bytes did not change")
        require(metadata()["runtimeSha256"] == after_sha, "metadata sha was not refreshed")
        require_restarted(before_pid, service_identity(), "user remove")
        xray_test()
        no_leftovers("user remove")
        return {"email": email}

    return check("user remove commits, updates metadata and restarts the service", do)


def phase_fault_refusal():
    def do():
        before = sha256(CONFIG)
        pid = service_identity()["pid"]
        last_before = journal_last()
        p = change_port(BASE_PORT + 2, HOOK_APPLY, fault="write-fail")
        require(p.returncode == 2, f"--fault on real root rc={p.returncode}: {p.stderr[:300]}")
        require("marked sandbox" in p.stderr, f"refusal does not explain sandbox-only: {p.stderr[:300]}")
        require(sha256(CONFIG) == before, "--fault refusal changed the config")
        require(service_identity()["pid"] == pid, "--fault refusal restarted the service")
        require(journal_last() == last_before, "--fault refusal wrote a journal entry")
        check_recover_none("--fault refusal")
        return "rc=2, sandbox-only, no writes, recover converged"

    return check("--fault is refused on the real root without any write", do)


def phase_validator_failure():
    def do():
        before = sha256(CONFIG)
        pid = service_identity()["pid"]
        p = change_port(BASE_PORT + 2, HOOK_APPLY, validator="/bin/false")
        require(p.returncode == 8, f"validator failure rc={p.returncode}: {p.stderr[:300]}")
        require(sha256(CONFIG) == before, "validator failure changed the config")
        require(service_identity()["pid"] == pid, "validator failure restarted the service")
        xray_test()
        last = journal_last()
        require(last and last["state"] == "REJECTED", f"journal last={last}")
        no_leftovers("validator failure")
        rep = check_recover_none("validator failure")
        return {"journal": last["state"], "recover": rep["action"]}

    return check("xray -test failure leaves the old config and converges", do)


def phase_service_failure():
    def do():
        before = sha256(CONFIG)
        pid = service_identity()["pid"]
        p = change_port(BASE_PORT + 2, HOOK_FAIL)
        require(p.returncode == 9, f"service failure rc={p.returncode}: {p.stderr[:300]}")
        require(sha256(CONFIG) == before, "service failure did not roll the config back")
        require(service_identity()["pid"] == pid, "failed apply unexpectedly changed the unit")
        xray_test()
        last = journal_last()
        require(last and last["state"] == "ROLLED_BACK", f"journal last={last}")
        no_leftovers("service failure")
        rep = check_recover_none("service failure")
        return {"journal": last["state"], "recover": rep["action"]}

    return check("service restart failure rolls back and converges", do)


def phase_kill():
    def do():
        before = sha256(CONFIG)
        KILL_ARMED.unlink(missing_ok=True)
        p = change_port(BASE_PORT + 2, HOOK_KILL)
        require(p.returncode in (-9, 137), f"SIGKILL expected, rc={p.returncode}: {p.stderr[:300]}")
        last = journal_last()
        require(last and last["state"] == "PREPARED", f"journal last={last}")
        require(ROLLBACK.is_file(), "rollback snapshot missing after SIGKILL")
        # PREPARED is journaled before the candidate hash is known, so compare
        # against the rollback snapshot: it must hold the old bytes exactly,
        # while the target has already been renamed to the new config.
        require(sha256(ROLLBACK) == before, "rollback snapshot does not hold the old config")
        require(sha256(CONFIG) != before, "config was not renamed before the kill")
        xray_test()
        killed = service_identity()
        rep = recover()
        require(rep.returncode == 0, f"recover rc={rep.returncode}: {rep.stderr[:300]}")
        report = json.loads(rep.stdout)
        require(report["converged"] is True, f"recover not converged: {report}")
        require(report["action"] == "rolled-back", f"recover action={report['action']}")
        require(sha256(CONFIG) == before, "recover did not restore the old config")
        xray_test()
        last = journal_last()
        require(last and last["state"] == "ROLLED_BACK", f"journal last={last}")
        no_leftovers("SIGKILL recover")
        require_restarted(killed, service_identity(), "SIGKILL recover")
        return {"killedPid": killed["pid"], "recover": report["action"]}

    return check("SIGKILL mid-transaction rolls back through change recover", do)


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    fn = EVIDENCE / "realroot-result.json"
    try:
        phase_install()
        phase_gate()
        phase_port()
        phase_user_add()
        phase_user_remove()
        phase_fault_refusal()
        phase_validator_failure()
        phase_service_failure()
        phase_kill()
    except Exception:  # noqa: BLE001 - evidence is written for every failure
        RESULT["ok"] = False
    finally:
        (EVIDENCE / "realroot-result.json").write_text(
            json.dumps(RESULT, indent=2, sort_keys=True) + "\n")
    passed = sum(1 for c in RESULT["checks"] if c["status"] == "PASS")
    failed = sum(1 for c in RESULT["checks"] if c["status"] == "FAIL")
    print(f"REALROOT RESULT: {'PASS' if RESULT['ok'] else 'FAIL'} "
          f"({passed} passed, {failed} failed) evidence={fn}")
    return 0 if RESULT["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
