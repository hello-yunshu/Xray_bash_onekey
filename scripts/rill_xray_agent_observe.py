#!/usr/bin/env python3
"""Rill Xray Agent - root observer (host-owned, safe metadata only).

Produces the safe observation document and appends *meaningful* state-change
events to the bounded timeline. This script NEVER mutates the host: it only
reads the installed Xray/Nginx state and writes safe metadata.

Canonical implementation contract:
- event derivation: rill_xray_agent.events.derive_events (ONE implementation)
- event journal:    rill_xray_agent.event_journal.EventJournal (ONE impl)

The installed canonical package lives at /opt/rill-xray-agent/python;
tests and sandboxes may point RILL_XRAY_AGENT_PYTHON elsewhere. If the
canonical modules cannot be imported the observer FAILS CLOSED rather than
falling back to a second, drifting implementation.

Never recorded: raw config bodies, UUID/credentials, private keys,
certificate private material, addresses, command stdout/stderr, free text.
"""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

_CANONICAL_PY = os.environ.get("RILL_XRAY_AGENT_PYTHON", "/opt/rill-xray-agent/python")
if _CANONICAL_PY and _CANONICAL_PY not in sys.path:
    sys.path.insert(0, _CANONICAL_PY)
try:
    from rill_xray_agent.event_journal import EventJournal
    from rill_xray_agent.observer_transition import (CHECKPOINT_NAME,
                                                     commit_transition)
except ImportError as exc:  # pragma: no cover - fail closed, never drift
    raise SystemExit(f"rill_xray_agent canonical modules unavailable: {exc}")

ROOT = Path(os.environ.get("RILL_XRAY_HOST_ROOT", "/etc/idleleo"))
OUT = Path(os.environ.get("RILL_XRAY_AGENT_OUTPUT", "/var/lib/rill-xray-agent-xray/status/xray-observation.json"))
HISTORY = Path(os.environ.get("RILL_XRAY_AGENT_HISTORY", "/var/lib/rill-xray-agent-xray/history"))
SEGMENT_BYTES = 512 * 1024
TOTAL_BYTES = 4 * 1024 * 1024


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def summary(path: Path) -> dict:
    if not path.exists():
        return {"present": False}
    if path.is_symlink():
        return {"present": True, "safe": False}
    if path.is_file():
        return {"present": True, "safe": True, "sha256": sha(path), "size": path.stat().st_size}
    digest = hashlib.sha256()
    count = 0
    for item in sorted(path.rglob("*")):
        if item.is_file() and not item.is_symlink():
            digest.update(item.relative_to(path).as_posix().encode() + b"\0" + bytes.fromhex(sha(item)))
            count += 1
    return {"present": True, "safe": True, "treeSha256": digest.hexdigest(), "files": count}


def run(command: list[str]) -> dict:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "returnCode": 124 if isinstance(exc, subprocess.TimeoutExpired) else 127,
            "outputSha256": hashlib.sha256(str(exc).encode()).hexdigest(),
        }
    return {
        "ok": result.returncode == 0,
        "returnCode": result.returncode,
        "outputSha256": hashlib.sha256(result.stdout[:1_048_576]).hexdigest(),
    }


xray_config = ROOT / "conf/xray/config.json"
nginx_config = ROOT / "conf/nginx"
install_config = ROOT / "conf/install_config.json"
xray_bin = Path("/usr/local/bin/xray")
nginx_bin = Path("/usr/local/nginx/sbin/nginx")
missing = {"ok": False, "returnCode": 66, "outputSha256": hashlib.sha256(b"missing").hexdigest()}
data = {
    "schemaVersion": 1,
    "capturedAtEpochSeconds": int(time.time()),
    "xrayConfig": summary(xray_config),
    "nginxConfig": summary(nginx_config),
    "installConfig": summary(install_config),
    "xrayValidation": run([str(xray_bin), "run", "-test", "-config", str(xray_config)]) if xray_bin.exists() and xray_config.exists() else missing,
    "nginxValidation": run([str(nginx_bin), "-t"]) if nginx_bin.exists() else missing,
    "services": {
        "xray": run(["/bin/systemctl", "is-active", "--quiet", "xray"]),
        "nginx": run(["/bin/systemctl", "is-active", "--quiet", "nginx"]),
    },
}

# Canonical journal: one implementation, crash-safe, single-writer, bounded.
journal = EventJournal(HISTORY, segment_bytes=SEGMENT_BYTES, total_bytes=TOTAL_BYTES)
journal.recover()
previous = None
if OUT.is_file() and not OUT.is_symlink():
    try:
        previous = json.loads(OUT.read_text())
    except Exception:
        previous = None
# Crash-safe exactly-once transition commit (canonical module): appends the
# derived events, then atomically replaces the observation. A crash between
# the two is recovered idempotently on restart (no lost, no duplicate event).
commit_transition(journal, OUT, OUT.parent / CHECKPOINT_NAME, previous, data)
print(json.dumps(data, sort_keys=True))