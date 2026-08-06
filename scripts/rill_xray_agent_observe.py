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
