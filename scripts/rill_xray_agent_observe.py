#!/usr/bin/env python3
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

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


# ---------------------------------------------------------------------------
# Bounded safe event journal (self-contained so the observer needs no package
# dependency). Mirrors the runtime design philosophy: segment + total size
# bounds, atomic fsync'd appends, symlink rejection, safe ring-buffer rollover.
# ---------------------------------------------------------------------------
def _segments():
    return sorted(p for p in HISTORY.glob("events-*.jsonl") if not p.is_symlink())


def _total_size():
    return sum(p.stat().st_size for p in _segments() if p.exists())


def _meta():
    path = HISTORY / "meta.json"
    if not path.is_file() or path.is_symlink():
        return {"nextSequence": 1, "nextSegment": 1}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {"nextSequence": 1, "nextSegment": 1}
    return {"nextSequence": int(data.get("nextSequence", 1)),
            "nextSegment": int(data.get("nextSegment", 1))}


def _write_meta(meta):
    path = HISTORY / "meta.json"
    if path.is_symlink():
        raise ValueError("symlink journal meta")
    fd, tmp = tempfile.mkstemp(prefix=".meta.", dir=HISTORY)
    with os.fdopen(fd, "w") as stream:
        json.dump({"schemaVersion": 1, "nextSequence": meta["nextSequence"],
                   "nextSegment": meta["nextSegment"]}, stream, sort_keys=True,
                  separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def _make_room(line_len: int):
    if line_len > SEGMENT_BYTES:
        raise ValueError("event larger than segment bound")
    while _total_size() + line_len > TOTAL_BYTES:
        segs = _segments()
        if not segs:
            return
        segs[0].unlink()


def append_event(event: dict):
    HISTORY.mkdir(parents=True, exist_ok=True)
    meta = _meta()
    meta["nextSequence"] += 1
    event = dict(event)
    event["sequence"] = meta["nextSequence"]
    event.setdefault("capturedAtEpochSeconds", int(time.time()))
    ident = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    event["eventId"] = event.get("eventId") or ident
    line = json.dumps(event, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    _make_room(len(line))
    seg_num = meta["nextSegment"]
    seg = HISTORY / ("events-%06d.jsonl" % seg_num)
    if seg.exists() and seg.stat().st_size + len(line) > SEGMENT_BYTES:
        seg_num += 1
        seg = HISTORY / ("events-%06d.jsonl" % seg_num)
    if seg.is_symlink():
        raise ValueError("symlink journal segment")
    with seg.open("ab") as stream:
        stream.write(line)
        stream.flush()
        os.fsync(stream.fileno())
    meta["nextSegment"] = seg_num
    _write_meta(meta)


def config_digest(obs, component):
    key = {"xray": "xrayConfig", "nginx": "nginxConfig", "install": "installConfig"}[component]
    entry = (obs or {}).get(key) or {}
    if not entry.get("present"):
        return ""
    if entry.get("safe") is False:
        return "unsafe"
    return entry.get("sha256") or entry.get("treeSha256") or ""


def validation_ok(obs, component):
    value = (obs or {}).get("xrayValidation" if component == "xray" else "nginxValidation")
    return bool((value or {}).get("ok")) if isinstance(value, dict) else None


def service_ok(obs, component):
    services = (obs or {}).get("services") or {}
    value = services.get(component)
    return bool(value.get("ok")) if isinstance(value, dict) else None


def unsafe_path(obs):
    for component in ("xray", "nginx", "install"):
        key = {"xray": "xrayConfig", "nginx": "nginxConfig", "install": "installConfig"}[component]
        entry = (obs or {}).get(key) or {}
        if entry.get("present") and entry.get("safe") is False:
            return True
    return False


def derive_events(previous, current):
    if previous is None:
        return [{"schemaVersion": 1, "eventType": "baseline_observed",
                 "component": "agent", "facts": {"firstObservation": True}}]
    events = []
    for component in ("xray", "nginx", "install"):
        if config_digest(previous, component) != config_digest(current, component):
            events.append({"schemaVersion": 1,
                           "eventType": "%s_config_changed" % component,
                           "component": component, "facts": {}})
    for component in ("xray", "nginx"):
        prev_ok = validation_ok(previous, component)
        curr_ok = validation_ok(current, component)
        if prev_ok is not None and curr_ok is not None and prev_ok != curr_ok:
            events.append({"schemaVersion": 1,
                           "eventType": "%s_validation_%s" % (component, "recovered" if curr_ok else "failed"),
                           "component": component, "facts": {}})
        prev_ok = service_ok(previous, component)
        curr_ok = service_ok(current, component)
        if prev_ok is not None and curr_ok is not None and prev_ok != curr_ok:
            events.append({"schemaVersion": 1,
                           "eventType": "%s_service_%s" % (component, "up" if curr_ok else "down"),
                           "component": component, "facts": {}})
    if unsafe_path(current):
        events.append({"schemaVersion": 1, "eventType": "unsafe_path_detected",
                       "component": "agent", "facts": {"unsafe": True}})
    return events


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

# persist meaningful state-change events to the bounded timeline
previous = None
if OUT.is_file() and not OUT.is_symlink():
    try:
        previous = json.loads(OUT.read_text())
    except Exception:
        previous = None
for event in derive_events(previous, data):
    append_event(event)

OUT.parent.mkdir(parents=True, exist_ok=True)
fd, temp = tempfile.mkstemp(prefix=".observation.", dir=OUT.parent)
with os.fdopen(fd, "w") as stream:
    json.dump(data, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.chmod(temp, 0o640)
os.replace(temp, OUT)
print(json.dumps(data, sort_keys=True))