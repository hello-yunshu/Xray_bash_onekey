#!/usr/bin/env python3
"""F11 — systemd lifecycle for the owned unit.

Preview evidence level: CONTAINER_VERIFIED (root + systemd + journald).

A real xray.service probe is installed so the fixture does not depend on F01's
installation. Every lifecycle verb goes through idleleo service, and the journal
start counter proves restart/start actually happened. Cleanup is idempotent so
this fixture can be rerun without leftovers.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

UNIT = Path("/etc/systemd/system/xray.service")
PROBE = Path("/usr/local/bin/idleleo-f11-probe")
MARKER = "idleleo-f11-start"

PROBE_SCRIPT = """#!/bin/sh
echo "{marker} $(date +%s%N)"
exec sleep 600
"""

UNIT_FILE = """[Unit]
Description=idleleo preview F11 probe
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/idleleo-f11-probe
Restart=no

[Install]
WantedBy=multi-user.target
"""


def cleanup(f):
    f.run(["systemctl", "stop", "xray"], timeout=20)
    f.run(["systemctl", "disable", "xray"], timeout=20)
    UNIT.unlink(missing_ok=True)
    PROBE.unlink(missing_ok=True)
    f.run(["systemctl", "daemon-reload"], timeout=20)
    f.run(["systemctl", "reset-failed", "xray"], timeout=20)


def journal_starts(f, lines=500):
    r = f.run(["journalctl", "-u", "xray.service", "-n", str(lines), "--no-pager"], timeout=30)
    return sum(1 for line in r.out.splitlines() if MARKER in line)


def unit_state(report, name="xray.service"):
    for unit in report.get("units", []):
        if unit.get("unit") == name:
            return unit
    return {}


def main(f):
    f.need_root()
    f.need_systemd()
    cleanup(f)
    write_env = dict(f.env, IDLELEO_ALLOW_SYSTEM_WRITES="I_ACCEPT_CONTAINER_ONLY")

    PROBE.write_text(PROBE_SCRIPT.format(marker=MARKER))
    PROBE.chmod(0o755)
    UNIT.write_text(UNIT_FILE)
    f.run(["systemctl", "daemon-reload"], timeout=20)
    enabled = f.run(["systemctl", "enable", "--now", "xray"], timeout=40)
    f.check(enabled.rc == 0, "probe unit enabled and started", f"rc={enabled.rc}")
    if enabled.rc != 0:
        return

    status = f.run([f.go, "service", "status", "--json"], timeout=30)
    f.check(status.rc == 0, "service status exit 0", f"rc={status.rc}")
    status_json = f.json_of(status, "status report")
    if status_json is None:
        return
    f.write_json("status-initial.json", status_json)
    xray = unit_state(status_json)
    f.check(xray.get("active") == "active", "status reports xray active", str(xray.get("active")))
    f.check(xray.get("enabled") == "enabled", "status reports xray enabled", str(xray.get("enabled")))

    before = journal_starts(f)
    f.check(before >= 1, "journal contains the probe start marker", f"count={before}")

    restart = f.run([f.go, "service", "restart", "--container", "--json"], timeout=60, env=write_env)
    f.check(restart.rc == 0, "service restart exit 0", f"rc={restart.rc} {restart.err[:200]}")
    restart_json = f.json_of(restart, "restart report") or {}
    f.write_json("restart.json", restart_json)
    f.check(restart_json.get("action") == "restart", "restart report action", str(restart_json.get("action")))
    f.check(restart_json.get("unit") == "xray.service", "restart targets xray.service",
            str(restart_json.get("unit")))
    after_restart = journal_starts(f)
    f.check(after_restart == before + 1, "restart added exactly one start",
            f"{before} -> {after_restart}")

    stop = f.run([f.go, "service", "stop", "--container", "--json"], timeout=60, env=write_env)
    f.check(stop.rc == 0, "service stop exit 0", f"rc={stop.rc}")
    stopped = f.run([f.go, "service", "status", "--json"], timeout=30)
    stopped_json = f.json_of(stopped, "stopped status") or {}
    f.write_json("status-stopped.json", stopped_json)
    f.check(unit_state(stopped_json).get("active") == "inactive", "status reports xray inactive",
            str(unit_state(stopped_json).get("active")))

    start = f.run([f.go, "service", "start", "--container", "--json"], timeout=60, env=write_env)
    f.check(start.rc == 0, "service start exit 0", f"rc={start.rc}")
    after_start = journal_starts(f)
    f.check(after_start == after_restart + 1, "start added exactly one start",
            f"{after_restart} -> {after_start}")

    logs = f.run([f.go, "service", "logs", "--lines", "100", "--json"], timeout=30)
    f.check(logs.rc == 0, "service logs exit 0", f"rc={logs.rc}")
    logs_json = f.json_of(logs, "logs report") or {}
    f.write_json("logs.json", logs_json)
    f.check(logs_json.get("unit") == "xray.service", "logs target xray.service",
            str(logs_json.get("unit")))
    f.check(MARKER in (logs_json.get("output") or ""), "logs include the probe marker")

    unmanaged = f.run([f.go, "service", "restart", "--unit", "sshd", "--container", "--json"],
                      timeout=30, env=write_env)
    f.check(unmanaged.rc == 2, "unmanaged unit refused with exit 2", f"rc={unmanaged.rc}")
    f.check("not managed" in unmanaged.err, "unmanaged unit error is explicit",
            unmanaged.err.strip()[:200])

    sandbox = f.evidence / "sandbox-root"
    sandbox.mkdir(exist_ok=True)
    sandbox_status = f.run([f.go, "--root", str(sandbox), "service", "status", "--json"],
                           timeout=30)
    f.check(sandbox_status.rc == 2, "sandbox root refused with exit 2", f"rc={sandbox_status.rc}")
    f.check("real system only" in sandbox_status.err, "sandbox refusal is explicit",
            sandbox_status.err.strip()[:200])

    cleanup(f)


if __name__ == "__main__":
    sys.exit(run_fixture("F11", main))
