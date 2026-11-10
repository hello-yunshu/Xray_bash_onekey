"""Shared harness for the real Fxx feature fixtures.

Contract with the gates (check_release_gate.py / check_preview_gate.py):

    python3 -I features/Fxx_test.py --go-bin <manager> --bash-repo <checkout>

* the gate runs the fixture with a 240 second wall-clock timeout,
* the fixture must execute real system behaviour; skipping is a failure,
* exit 0 means every assertion passed, any other code means RED.

This module only uses the standard library. It records every command it runs
under IDLELEO_PREVIEW_EVIDENCE (set by the preview gate) or the current
directory, so a RED run keeps enough evidence to explain itself.
"""
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

TOTAL_BUDGET = 200  # seconds; the gate kills the fixture at 240


class Result:
    def __init__(self, cmd, rc, out, err, timed_out, seconds):
        self.cmd = cmd
        self.rc = rc
        self.out = out
        self.err = err
        self.timed_out = timed_out
        self.seconds = seconds

    @property
    def text(self):
        return (self.out or "") + (self.err or "")


class Fixture:
    def __init__(self, fid):
        import argparse

        self.fid = fid
        self.started = time.monotonic()
        self.passed = 0
        self.failed = 0
        self.notes = []
        evidence = os.environ.get("IDLELEO_PREVIEW_EVIDENCE") or "."
        self.evidence = Path(evidence).resolve()
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.log_path = self.evidence / "commands.log"
        parser = argparse.ArgumentParser(prog=f"{fid}_test.py")
        parser.add_argument("--go-bin", type=Path, required=True)
        parser.add_argument("--bash-repo", type=Path)
        parser.add_argument("--xray-bin", type=Path)
        self.args = parser.parse_args()
        self.go = Path(self.args.go_bin).resolve()
        self.bash_repo = Path(self.args.bash_repo).resolve() if self.args.bash_repo else None
        self.env = os.environ.copy()
        self.env.setdefault("LANG", "C.UTF-8")
        self.env.setdefault("LC_ALL", "C.UTF-8")
        self._log(f"== {fid} go={self.go} bash={self.bash_repo} host={platform.machine()}")
        self.need(self.go.is_file(), f"go binary not found: {self.go}")
        if self.bash_repo is not None:
            self.need((self.bash_repo / "install.sh").is_file(),
                      f"bash baseline install.sh not found under {self.bash_repo}")

    # -- logging / assertions -------------------------------------------------
    def _log(self, line):
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def ok(self, name, detail=""):
        self.passed += 1
        print(f"PASS {name}" + (f": {detail}" if detail else ""), flush=True)
        self._log(f"PASS {name} {detail}")

    def bad(self, name, detail=""):
        self.failed += 1
        print(f"FAIL {name}" + (f": {detail}" if detail else ""), file=sys.stderr, flush=True)
        self._log(f"FAIL {name} {detail}")

    def check(self, condition, name, detail=""):
        if condition:
            self.ok(name, detail)
        else:
            self.bad(name, detail)
        return bool(condition)

    def need(self, condition, message):
        if condition:
            return
        print(f"UNSUPPORTED_ENVIRONMENT: {message}", file=sys.stderr, flush=True)
        self._log(f"UNSUPPORTED_ENVIRONMENT {message}")
        self.finish()
        # A missing precondition is never a pass: write the evidence result,
        # then exit with the fixture-contract code for an unusable environment.
        raise SystemExit(2)

    def elapsed(self):
        return time.monotonic() - self.started

    def write_json(self, name, payload):
        path = self.evidence / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    # -- process execution ----------------------------------------------------
    def run(self, cmd, timeout=60, env=None, cwd=None):
        cmd = [str(x) for x in cmd]
        started = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                env=env or self.env, cwd=cwd,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            rc = 124
            out = _decode(exc.stdout)
            err = _decode(exc.stderr)
        seconds = round(time.monotonic() - started, 2)
        self._log(f"$ {' '.join(cmd)} (rc={rc} {seconds}s)")
        if out:
            self._log("  stdout: " + out.strip()[:8000].replace("\n", "\n          "))
        if err:
            self._log("  stderr: " + err.strip()[:8000].replace("\n", "\n          "))
        if timed_out:
            self.bad(f"timeout after {timeout}s", " ".join(cmd))
        if self.elapsed() > TOTAL_BUDGET:
            self.bad("internal budget exceeded", f"{self.elapsed():.1f}s > {TOTAL_BUDGET}s")
            raise SystemExit(self.finish())
        return Result(cmd, rc, out, err, timed_out, seconds)

    def json_of(self, result, name):
        try:
            return json.loads(result.out)
        except (ValueError, TypeError):
            self.bad(f"{name}: invalid JSON", (result.out or result.err or "")[:500])
            return None

    # -- preconditions --------------------------------------------------------
    def need_root(self):
        self.need(os.geteuid() == 0, "fixture must run as root")

    def need_systemd(self, budget=30.0, interval=1.5):
        """Wait a bounded time for systemd to leave the boot "starting" state.

        Hosted runners can report "starting" for a while after boot. Only
        "running"/"degraded" are accepted; waiting never widens that set, and a
        timeout is still UNSUPPORTED_ENVIRONMENT (exit 2).
        """
        deadline = time.monotonic() + budget
        while True:
            r = self.run(["systemctl", "is-system-running"], timeout=15)
            state = (r.out or r.err).strip().splitlines()[-1] if (r.out or r.err).strip() else ""
            if state in ("running", "degraded"):
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.need(False, f"systemd is not usable after {budget:.0f}s: {state or r.rc}")
            time.sleep(min(interval, remaining))
        self.ok("systemd is usable", f"{state} after {self.elapsed():.1f}s")

    def need_tool(self, name):
        path = shutil.which(name)
        self.need(path is not None, f"required tool not found on PATH: {name}")
        return path

    def xray_bin(self):
        candidates = [
            self.args.xray_bin,
            os.environ.get("IDLELEO_XRAY_BIN"),
            shutil.which("xray"),
            "/usr/local/bin/xray",
            "/opt/xray/xray",
        ]
        for candidate in candidates:
            if not candidate:
                continue
            path = Path(candidate)
            if not path.is_file():
                continue
            r = self.run([path, "version"], timeout=20)
            if r.rc == 0:
                return path
        self.need(False, "xray binary not found; pass --xray-bin or set IDLELEO_XRAY_BIN")
        return None

    # -- evidence -------------------------------------------------------------
    def tree_digest(self, root):
        root = Path(root)
        h = hashlib.sha256()
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs.sort()
            for name in sorted(files) + sorted(dirs):
                path = Path(base) / name
                rel = str(path.relative_to(root))
                st = path.lstat()
                mode = oct(st.st_mode & 0o7777)
                if path.is_symlink():
                    h.update(f"L {rel} {os.readlink(path)}\n".encode())
                elif path.is_dir():
                    h.update(f"D {rel} {mode}\n".encode())
                else:
                    h.update(f"F {rel} {mode} {sha256(path)} {st.st_size}\n".encode())
        return h.hexdigest()

    def finish(self):
        elapsed = round(self.elapsed(), 2)
        if elapsed > TOTAL_BUDGET and self.failed == 0:
            self.bad("internal budget exceeded", f"{elapsed}s > {TOTAL_BUDGET}s")
        payload = {
            "fixture": self.fid,
            "goBin": str(self.go),
            "goBinSha256": sha256(self.go) if self.go.is_file() else "",
            "bashRepo": str(self.bash_repo or ""),
            "hostMachine": platform.machine(),
            "passed": self.passed,
            "failed": self.failed,
            "elapsedSeconds": elapsed,
        }
        self.write_json("fixture-result.json", payload)
        print(f"== {self.fid}: {self.passed} passed, {self.failed} failed, {elapsed}s ==", flush=True)
        return 0 if self.failed == 0 else 1


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _decode(raw):
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return raw


def run_fixture(fid, main):
    fixture = None
    try:
        fixture = Fixture(fid)
        main(fixture)
        return fixture.finish()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        if fixture is not None:
            fixture.bad("uncaught exception")
            return fixture.finish()
        return 1
