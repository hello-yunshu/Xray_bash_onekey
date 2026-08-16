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
    from rill_xray_agent.locking import ObserverLock
    from rill_xray_agent.observer_transition import (CHECKPOINT_NAME,
                                                     commit_transition,
                                                     recover_pending_transition)
    from rill_xray_agent.canonical import atomic_write_json
    from rill_xray_agent.route_topology import RouteTopologyProjection
except ImportError as exc:  # pragma: no cover - fail closed, never drift
    raise SystemExit(f"rill_xray_agent canonical modules unavailable: {exc}")

ROOT = Path(os.environ.get("RILL_XRAY_HOST_ROOT", "/etc/idleleo"))
# §P0-2: the root-authoritative Rill config (mode/routeStage/managed-route
# intent). Root-owned 0640; only the ROOT observer reads it and embeds a
# SANITIZED managed-route intent into the safe topology projection so the
# unprivileged Runtime never touches this file directly.
RILL_CONFIG = Path(os.environ.get(
    "RILL_XRAY_AGENT_RUNTIME_CONFIG", "/etc/rill-xray-agent/config.json"))
OUT = Path(os.environ.get("RILL_XRAY_AGENT_OUTPUT", "/var/lib/rill-xray-agent-xray/status/xray-observation.json"))
# §P0-4: the safe, secret-free route-topology projection. The ROOT observer
# produces it from the root-owned config + the root-owned generation file; the
# unprivileged Runtime consumes it READ-ONLY and never reads the raw config.
ROUTE_TOPOLOGY = Path(os.environ.get(
    "RILL_XRAY_AGENT_TOPOLOGY",
    "/var/lib/rill-xray-agent-xray/status/route-topology.json"))
# Root-owned generation authority (§P0-7): the generation file lives in the
# root-only state tree. Only the root oneshot executor writes it; the root
# observer reads it so the projection carries the CURRENT generation.
GENERATION_FILE = Path(os.environ.get(
    "RILL_XRAY_AGENT_GENERATION", "/var/lib/rill-xray-agent-root/generation"))
HISTORY = Path(os.environ.get("RILL_XRAY_AGENT_HISTORY", "/var/lib/rill-xray-agent-xray/history"))
SEGMENT_BYTES = 512 * 1024
TOTAL_BYTES = 4 * 1024 * 1024
# Cross-process mutex over the WHOLE observer transaction (see ObserverLock).
# The systemd timer/path observer and a direct manager/install call share this
# lock so their (recover -> derive -> journal append -> observation replace ->
# checkpoint clear) critical sections can never interleave. root-owned, never
# follows a symlink, blocking with a bounded timeout.
OBSERVER_LOCK = Path(os.environ.get(
    "RILL_XRAY_AGENT_LOCK", "/var/lib/rill-xray-agent-xray/.observer.lock"))


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def summary(path: Path) -> dict:
    """Safe summary of a config path, FAIL-CLOSED on any unsafe member.

    A single walk of the tree (minimising the TOCTOU window) treats any nested
    file symlink, nested directory symlink, dangling symlink, symlink escaping
    the tree, or non-regular special file as unsafe and reports
    `{"present": true, "safe": false}`. Symlink targets are NEVER followed,
    saved or read. An unreadable member also fails closed.
    """
    if path.is_symlink():
        return {"present": True, "safe": False}
    if not path.exists():
        return {"present": False}
    if path.is_file():
        return {"present": True, "safe": True, "sha256": sha(path), "size": path.stat().st_size}
    if not path.is_dir():
        # A non-regular top-level member (fifo/socket/device/...) fails closed.
        return {"present": True, "safe": False}
    digest = hashlib.sha256()
    count = 0
    try:
        for item in sorted(path.rglob("*")):
            if item.is_symlink():
                return {"present": True, "safe": False}
            if item.is_file():
                digest.update(item.relative_to(path).as_posix().encode() + b"\0" + bytes.fromhex(sha(item)))
                count += 1
            elif not item.is_dir():
                return {"present": True, "safe": False}  # special file
    except (OSError, PermissionError):
        return {"present": True, "safe": False}
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


def read_generation() -> int:
    """Root-owned configuration generation (§P0-7). Missing/unreadable file
    fails closed to 0 (a fresh install has no committed generation yet)."""
    try:
        return int(GENERATION_FILE.read_text().strip())
    except Exception:
        return 0


def read_managed_route_intent() -> dict:
    """§P0-2: read the root-authoritative managed-route intent.

    The Rill config is root-owned (0640); only the ROOT observer reads it.
    The intent is extracted from the 'managedRouteIntent' block and then
    re-sanitized inside RouteTopologyProjection (allowlisted selector types,
    safe scalar/list values, secret-bearing selectors dropped). Any missing /
    unparseable / malformed intent fails closed to an empty intent so the
    projection never leaks or invents state.
    """
    if not RILL_CONFIG.is_file() or RILL_CONFIG.is_symlink():
        return {}
    try:
        raw = json.loads(RILL_CONFIG.read_text())
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    intent = raw.get("managedRouteIntent")
    return intent if isinstance(intent, dict) else {}


def route_topology_projection() -> dict:
    """Safe, secret-free route-topology projection (§P0-4/§P0-2).

    Reads the ROOT-owned Xray config (never visible to the Runtime), the
    root-owned generation file and the root-owned managed-route intent, then
    emits RouteTopologyProjection.project(). Selector values are persisted only
    as digests; UUID / privateKey / Reality material / proxy URLs / credentials
    never appear. A missing or unparseable config produces an EMPTY projection
    (fail closed), never a partial leak.
    """
    routing = None
    whole_digest = ""
    if xray_config.is_file() and not xray_config.is_symlink():
        try:
            raw = json.loads(xray_config.read_text())
        except Exception:
            raw = None
        if isinstance(raw, dict) and isinstance(raw.get("routing"), dict):
            routing = raw["routing"]
        whole_digest = sha(xray_config)
    return RouteTopologyProjection(
        routing if isinstance(routing, dict) else {},
        config_generation=read_generation(),
        whole_config_safe_digest=whole_digest,
        captured_at_epoch_seconds=int(time.time()),
        intent=read_managed_route_intent(),
    ).project()


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
# The whole transaction runs under the cross-process observer mutex so a
# concurrent timer/path observer or direct manager call can never interleave
# the exactly-once commit (recover -> derive -> append -> observation replace
# -> checkpoint clear). The lock is acquired BEFORE journal recovery and
# released only after commit_transition returns.
with ObserverLock(OBSERVER_LOCK):
    journal = EventJournal(HISTORY, segment_bytes=SEGMENT_BYTES, total_bytes=TOTAL_BYTES)
    journal.recover()
    # CRITICAL recovery ordering: FIRST complete any pending transition from its
    # durable checkpoint (using the safe projection saved there, never the live
    # state), THEN use the live state for a new transition. This keeps the chain
    # correct when the host changed while the observer was down (pending O0->O1
    # with live moved to O2 -> recover O0->O1, then record O1->O2).
    recovered = recover_pending_transition(journal, OUT, OUT.parent / CHECKPOINT_NAME)
    if recovered is not None:
        previous = recovered
    else:
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
    # §P0-4: the safe route-topology projection is written atomically (0640
    # root:rill-xray-agent, parent status dir is setgid 2750) under the SAME
    # observer mutex so topology and observation are captured consistently.
    # atomic_write_json rejects symlink targets and replaces atomically.
    atomic_write_json(ROUTE_TOPOLOGY, route_topology_projection(), 0o640)
print(json.dumps(data, sort_keys=True))