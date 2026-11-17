#!/usr/bin/env python3
"""F24 — product container delivery without a systemd assumption.

Preview evidence level: CONTAINER_VERIFIED (the real Go binary runs inside the
preview container; a real nginx tree and a stand-in xray script are started and
stopped; the fixed Bash entrypoint functions are executed for comparison; no
data plane, no host writes, no network).

What the fixture proves:

* `container status` is read-only and reports mode/pid/alive honestly;
* with no systemd, `container up` starts xray/nginx directly, writes pid files
  and one log, and is idempotent;
* `container down` stops both, removes pid files, and is idempotent;
* `--dry-run` plans without writing or starting anything;
* real-root and unmarked-sandbox writes are refused;
* the image contract (Go binary path, entrypoint branch, fake-systemctl) is
  present, and the Bash baseline starts/stops the same service set.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402


def write_text(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode:
        path.chmod(mode)
    return path


def tree_digest_path(root):
    h = hashlib.sha256()
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(files) + sorted(dirs):
            path = Path(base) / name
            rel = str(path.relative_to(root))
            st = path.lstat()
            if path.is_symlink():
                h.update(f"L {rel} {os.readlink(path)}\n".encode())
            elif path.is_dir():
                h.update(f"D {rel}\n".encode())
            else:
                h.update(f"F {rel} {st.st_size} {hashlib.sha256(path.read_bytes()).hexdigest()}\n".encode())
    return h.hexdigest()


def metadata(tls):
    return {
        "schemaVersion": 1,
        "activeEngine": "xray",
        "role": "node",
        "tls": tls,
        "transport": "raw",
        "runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
        "runtimeSha256": "b" * 64,
        "ownedResources": [],
        "updatedAt": "2026-01-01T00:00:00Z",
    }


def seed_root(root, with_services):
    root = Path(root)
    for sub in ("usr/local/nginx/sbin", "usr/local/nginx/conf", "usr/local/nginx/logs",
                "usr/local/bin", "etc/idleleo/v1", "etc/idleleo/conf/xray",
                "etc/idleleo/conf/nginx"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    write_text(root / ".idleleo-phase01-sandbox", "I_ACCEPT_DISPOSABLE_SANDBOX\n")
    if not with_services:
        return root
    write_text(root / "etc/idleleo/v1/metadata.json",
               json.dumps(metadata("TLS"), indent=2) + "\n")
    os.symlink("/usr/sbin/nginx", root / "usr/local/nginx/sbin/nginx")
    write_text(root / "usr/local/bin/xray",
               "#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n", 0o755)
    write_text(root / "etc/idleleo/conf/xray/config.json", "{}\n")
    write_text(root / "usr/local/nginx/conf/nginx.conf", f"""pid {root}/usr/local/nginx/logs/nginx.pid;
error_log {root}/usr/local/nginx/logs/error.log;
events {{}}
http {{}}
""")
    return root


def alive(pid):
    """True only for a running process; a zombie counts as exited."""
    if not pid:
        return False
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split()
        if len(fields) > 2 and fields[2] == "Z":
            return False
    except OSError:
        pass
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def stop_leftovers(root, f):
    """Best-effort cleanup so a failed assertion does not leak children."""
    for name in ("xray", "nginx"):
        pf = Path(root) / "run/idleleo" / f"container-{name}.pid"
        try:
            pid = int(pf.read_text().strip())
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
    f.run([f.go, "--root", root, "container", "down", "--container"], timeout=30)


def extract_bash_function(text, name):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", text, re.MULTILINE | re.DOTALL)
    return match.group(0) if match else None


def bash_baseline(entrypoint, root, work, f):
    start = extract_bash_function(entrypoint, "_start_services")
    stop = extract_bash_function(entrypoint, "_stop_services")
    f.need(start is not None and stop is not None,
           "entrypoint must define _start_services/_stop_services")
    log = work / "systemctl-baseline.log"
    script = f"""set -u
XRAY_BIN="{root}/usr/local/bin/xray"
NGINX_BIN="{root}/usr/local/nginx/sbin/nginx"
XRAY_CONF="{root}/etc/idleleo/conf/xray/config.json"
NGINX_CONF="{root}/usr/local/nginx/conf/nginx.conf"
GO_IDLELEO=/nonexistent
STOPPING=0
systemctl() {{ echo "$*" >> "{log}"; }}
command() {{ return 1; }}
_f2b_configured() {{ return 1; }}
_go_container() {{ return 1; }}
{start}
{stop}
_start_services
_stop_services
"""
    path = write_text(work / "bash-baseline.sh", script, 0o755)
    run = f.run(["bash", path], cwd=work)
    return run, log, start, stop


def main(f):
    f.need(f.bash_repo is not None, "F24 requires --bash-repo for the Docker delivery assets")
    docker_dir = f.bash_repo / "docker"
    entrypoint_path = docker_dir / "docker-entrypoint.sh"
    dockerfile = docker_dir / "Dockerfile"
    fake_systemctl = docker_dir / "fake-systemctl"
    docker_md = docker_dir / "DOCKER.md"
    for path in (entrypoint_path, dockerfile, fake_systemctl, docker_md):
        f.need(path.is_file(), f"missing Docker delivery asset: {path}")
    f.need(shutil.which("nginx") is not None, "the preview image must ship nginx")

    work = f.evidence / "f24-work"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    observed = {"status": {}, "up": {}, "down": {}, "gates": {}, "delivery": {}}
    compare = {}

    # ---- S1: empty root, read-only status ---------------------------------
    empty = seed_root(work / "empty-root", with_services=False)
    before = tree_digest_path(empty)
    status = f.run([f.go, "--root", empty, "container", "status", "--json"])
    status_json = f.json_of(status, "container status --json") if status.rc == 0 else None
    f.check(status.rc == 0, "status on an empty root rc=0", status.text[:300])
    f.check(tree_digest_path(empty) == before, "status writes nothing")
    if status_json:
        f.check(status_json["schemaVersion"] == 1, "status schemaVersion=1")
        f.check(status_json["root"] == str(empty), "status root is the sandbox")
        f.check(status_json["mode"] in ("direct", "systemd"), "status mode is explicit")
        f.check(status_json["xray"]["alive"] is False, "empty xray is not alive")
        f.check(status_json["nginx"]["alive"] is False, "empty nginx is not alive")
        f.check(any("metadata" in w for w in status_json.get("warnings", [])),
                "empty root warns about missing metadata", str(status_json.get("warnings")))
        observed["status"]["empty"] = status_json

    # ---- S2: dry-run then real activation ---------------------------------
    root = seed_root(work / "container-root", with_services=True)
    conf_test = f.run([root / "usr/local/nginx/sbin/nginx", "-t", "-p",
                       str(root / "usr/local/nginx") + "/",
                       "-c", root / "usr/local/nginx/conf/nginx.conf"])
    f.check(conf_test.rc == 0, "seeded nginx configuration passes -t", conf_test.text[:300])
    before = tree_digest_path(root)
    dry = f.run([f.go, "--root", root, "container", "up", "--container", "--dry-run", "--json"])
    dry_json = f.json_of(dry, "container up --dry-run --json") if dry.rc == 0 else None
    f.check(dry.rc == 0, "container up --dry-run rc=0", dry.text[:300])
    f.check(tree_digest_path(root) == before, "dry-run performs no writes or starts")
    if dry_json:
        f.check(sorted(dry_json["started"]) == ["nginx", "xray"],
                "dry-run plans both services", json.dumps(dry_json))
        f.check(dry_json["dryRun"] is True, "dry-run report marks dryRun")

    up = f.run([f.go, "--root", root, "container", "up", "--container", "--json"])
    up_json = f.json_of(up, "container up --json") if up.rc == 0 else None
    f.check(up.rc == 0, "container up rc=0", up.text[:300])
    try:
        if up_json:
            f.check(sorted(up_json["started"]) == ["nginx", "xray"],
                    "up starts both services", json.dumps(up_json))
            f.check(up_json["mode"] == "direct",
                    "up stays in direct mode without systemd", json.dumps(up_json))
            xray_pid = up_json["pids"].get("xray", 0)
            nginx_pid = up_json["pids"].get("nginx", 0)
            f.check(alive(xray_pid), "xray process is alive", str(xray_pid))
            f.check(alive(nginx_pid), "nginx process is alive", str(nginx_pid))
            for name, pid in (("xray", xray_pid), ("nginx", nginx_pid)):
                pf = root / "run/idleleo" / f"container-{name}.pid"
                f.check(pf.is_file() and int(pf.read_text().strip()) == pid,
                        f"{name} pid file matches the report")
            f.check((root / "var/log/idleleo/container.log").is_file(),
                    "container log file exists")
            observed["up"]["real"] = up_json

        status = f.run([f.go, "--root", root, "container", "status", "--json"])
        status_json = f.json_of(status, "status after up") if status.rc == 0 else None
        if status_json and up_json:
            f.check(status_json["xray"]["alive"] is True and status_json["nginx"]["alive"] is True,
                    "status reports both services alive")
            f.check(status_json["xray"]["pid"] == up_json["pids"]["xray"],
                    "status xray pid matches up")
            f.check(status_json["nginx"]["pid"] == up_json["pids"]["nginx"],
                    "status nginx pid matches up")

        # ---- S3: idempotent up -------------------------------------------
        again = f.run([f.go, "--root", root, "container", "up", "--container", "--json"])
        again_json = f.json_of(again, "second container up") if again.rc == 0 else None
        f.check(again.rc == 0, "second up rc=0", again.text[:300])
        if again_json and up_json:
            f.check(again_json["started"] == [], "second up starts nothing", json.dumps(again_json))
            f.check(sorted(again_json["skipped"]) == ["nginx", "xray"],
                    "second up skips both services")
            f.check(again_json["pids"]["xray"] == up_json["pids"]["xray"],
                    "second up keeps the same xray pid")
            f.check(again_json["pids"]["nginx"] == up_json["pids"]["nginx"],
                    "second up keeps the same nginx pid")
            observed["up"]["repeat"] = again_json

        # ---- S4: down and idempotent down --------------------------------
        down = f.run([f.go, "--root", root, "container", "down", "--container", "--json"])
        down_json = f.json_of(down, "container down --json") if down.rc == 0 else None
        f.check(down.rc == 0, "container down rc=0", down.text[:300])
        if down_json:
            f.check(sorted(down_json["stopped"]) == ["nginx", "xray"],
                    "down stops both services", json.dumps(down_json))
            observed["down"]["real"] = down_json
        for name, pid in (("xray", up_json["pids"]["xray"] if up_json else 0),
                          ("nginx", up_json["pids"]["nginx"] if up_json else 0)):
            deadline = time.time() + 5
            while alive(pid) and time.time() < deadline:
                time.sleep(0.1)
            f.check(not alive(pid), f"{name} has exited")
            f.check(not (root / "run/idleleo" / f"container-{name}.pid").exists(),
                    f"{name} pid file removed")
        second = f.run([f.go, "--root", root, "container", "down", "--container", "--json"])
        second_json = f.json_of(second, "second container down") if second.rc == 0 else None
        f.check(second.rc == 0, "second down rc=0", second.text[:200])
        if second_json:
            f.check(second_json["stopped"] == [], "second down is a no-op",
                    json.dumps(second_json))
        status = f.run([f.go, "--root", root, "container", "status", "--json"])
        status_json = f.json_of(status, "status after down") if status.rc == 0 else None
        if status_json:
            f.check(status_json["xray"]["alive"] is False and status_json["nginx"]["alive"] is False,
                    "status reports both services stopped")
    finally:
        stop_leftovers(root, f)

    # ---- S5: gates and usage ---------------------------------------------
    real = f.run([f.go, "--root", "/", "container", "up", "--json"])
    f.check(real.rc == 2, "real root without confirmation exits 2", real.text[:300])
    unmarked = work / "unmarked"
    unmarked.mkdir()
    r = f.run([f.go, "--root", unmarked, "container", "up", "--json"])
    f.check(r.rc == 2, "unmarked sandbox exits 2", r.text[:300])
    r = f.run([f.go, "--root", root, "container", "up", "--bogus"])
    f.check(r.rc == 2, "unknown flag exits 2", r.text[:300])
    r = f.run([f.go, "--root", root, "container", "down", "--dry-run"])
    f.check(r.rc == 2, "down rejects --dry-run", r.text[:300])
    r = f.run([f.go, "--root", root, "container", "status", "--json"])
    f.check(r.rc == 0, "status still works after the refusals", r.text[:200])
    observed["gates"] = {"realRootRc": real.rc, "unmarkedRc": 2, "unknownFlagRc": 2}

    # ---- S6: static delivery contract ------------------------------------
    dockerfile_text = dockerfile.read_text(encoding="utf-8")
    entrypoint = entrypoint_path.read_text(encoding="utf-8")
    doc = docker_md.read_text(encoding="utf-8")
    f.check("AS gobuild" in dockerfile_text, "Dockerfile builds the Go manager")
    f.check("COPY --from=gobuild /out/idleleo /opt/idleleo/bin/idleleo" in dockerfile_text,
            "Dockerfile installs the Go container entry")
    f.check("org.opencontainers.image.title" in dockerfile_text, "image carries product labels")
    for token in ("_go_container", "container up", "container down", "container status --json"):
        f.check(token in entrypoint, f"entrypoint references {token}")
    go_container = extract_bash_function(entrypoint, "_go_container") or ""
    go_up = extract_bash_function(entrypoint, "_go_up") or ""
    go_down = extract_bash_function(entrypoint, "_go_down") or ""
    f.check("systemctl" not in go_container + go_up + go_down,
            "the Go container branch never calls systemctl")
    f.check(fake_systemctl.is_file() and "chmod +x /usr/local/bin/systemctl" in dockerfile_text,
            "fake-systemctl remains available for the Bash menu")
    f.check("container status" in doc, "DOCKER.md documents container status")
    syntax = f.run(["bash", "-n", entrypoint_path])
    f.check(syntax.rc == 0, "entrypoint keeps valid Bash syntax", syntax.text[:300])
    observed["delivery"] = {
        "dockerfileSha256": hashlib.sha256(dockerfile.read_bytes()).hexdigest(),
        "entrypointSha256": hashlib.sha256(entrypoint_path.read_bytes()).hexdigest(),
        "goBranchUsesSystemctl": False,
    }

    # ---- S7: fixed Bash entrypoint baseline ------------------------------
    run, log, start_fn, stop_fn = bash_baseline(entrypoint, root, work, f)
    f.check(run.rc == 0, "Bash entrypoint functions rc=0", run.text[:300])
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    f.check("start xray" in calls and "start nginx" in calls,
            "Bash baseline starts xray and nginx", str(calls))
    f.check("stop xray" in calls and "stop nginx" in calls,
            "Bash baseline stops xray and nginx", str(calls))
    go_started = sorted((observed.get("up", {}).get("real") or {}).get("started", []))
    bash_started = sorted(name.split()[-1] for name in calls if name.startswith("start "))
    f.check(go_started == bash_started,
            "Go and Bash activate the same service set", f"go={go_started} bash={bash_started}")
    observed["baseline"] = {"systemctlCalls": calls, "goStarted": go_started}

    compare["activationSet"] = {
        "classification": "aligned",
        "go": go_started,
        "bash": bash_started,
    }
    compare["systemdDependency"] = {
        "classification": "approved-difference",
        "go": "direct child processes with pid files; no unit, no DBus",
        "bash": "systemctl via fake-systemctl unit state",
    }
    compare["stateVisibility"] = {
        "classification": "new-go-behavior",
        "go": "container status --json exposes mode/pid/alive/stale warnings",
        "bash": "only echo lines; no process truth",
    }
    compare["logLocation"] = {
        "classification": "approved-difference",
        "go": "var/log/idleleo/container.log",
        "bash": "service output goes to the container stdout",
    }

    f.write_json("observed.json", observed)
    f.write_json("baseline-compare.json", compare)


if __name__ == "__main__":
    sys.exit(run_fixture("F24", main))
