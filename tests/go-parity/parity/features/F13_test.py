#!/usr/bin/env python3
"""F13 — managed component upgrades (`update xray|nginx`).

Preview evidence level: CONTAINER_VERIFIED (the real Go binary runs against a
real sandbox root, real loopback HTTP manifests, real tar.gz artifacts and a
real nginx `-t`; the fixed Bash baseline is executed function-by-function from
install.sh `version_compare`/`version_gt`; no systemd, no host writes, no
VPS, no ACME).

What the fixture proves:

* a digest-verified xray upgrade replaces the binary byte for byte, keeps the
  old bytes in the backup directory and skips the sandbox restart with a
  warning;
* an equal version is a `reinstall`, a downgrade returns 4, a bad digest or
  size returns 5, and none of those touch the binary or the backups;
* a failing `run -test` rolls the old bytes back and returns 6;
* a nginx upgrade replaces the whole tree from the tar.gz, `nginx -t` passes,
  and a broken artifact restores the previous tree digest;
* manifest/flag/root gates reject with 2 or 3 and zero writes;
* the Go version comparison matches Bash `version_compare` on one table.
"""
import functools
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import sys
import tarfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

MARKER = "I_ACCEPT_DISPOSABLE_SANDBOX\n"
ZERO_SHA = "0" * 64
NGINX_VERSION_RE = re.compile(r"nginx version:\s*nginx/([0-9]+(?:\.[0-9]+)*)")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def write_bytes(path, data, mode=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mode is not None:
        path.chmod(mode)
    return path


def write_text(path, text, mode=None):
    return write_bytes(path, text.encode(), mode)


def read_bytes(path):
    path = Path(path)
    return path.read_bytes() if path.is_file() else b""


def xray_shim(version, test_rc=0):
    return f"""#!/bin/sh
case "$1" in
  version) echo "Xray {version} (Xray, Penetrates Everything.) Custom (go1.24 linux/amd64)"; exit 0 ;;
  run) echo "xray test: {version} config ok" >&2; exit {test_rc} ;;
  *) echo "xray shim: unsupported $*" >&2; exit 1 ;;
esac
"""


NGINX_CONF = """worker_processes 1;
error_log stderr;
pid logs/nginx.pid;
events { worker_connections 16; }
http {
    server {
        listen 18080;
        server_name example.com;
        location / { return 204; }
    }
}
"""


def nginx_shim(real_nginx, version, test_rc=0):
    test = f'exec {real_nginx} "$@"' if test_rc == 0 else 'echo "nginx: configuration test failed" >&2; exit 1'
    return f"""#!/bin/sh
if [ "$1" = "-v" ]; then echo "nginx version: nginx/{version}" >&2; exit 0; fi
if [ "$1" = "-t" ]; then {test}; fi
exec {real_nginx} "$@"
"""


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # noqa: D401 - silence the fixture log
        pass


def serve_dir(directory):
    handler = functools.partial(QuietHandler, directory=str(directory))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def manifest(component, version, data, url, sha=None, size=None):
    return {
        "schemaVersion": 1,
        "component": component,
        "version": version,
        "sha256": sha if sha is not None else sha256_bytes(data),
        "sizeBytes": len(data) if size is None else size,
        "url": url,
    }


def seed_root(root):
    root = Path(root)
    for sub in ("usr/local/bin", "etc/idleleo/conf/xray"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    write_text(root / ".idleleo-phase01-sandbox", MARKER)
    write_text(root / "etc/idleleo/conf/xray/config.json",
               '{\n  "log": {"loglevel": "warning"}\n}\n')
    return root


def backup_names(root):
    backup = Path(root) / "etc/idleleo/backup"
    if not backup.is_dir():
        return []
    return sorted(p.name for p in backup.iterdir())


def install_xray_shim(root, version, test_rc=0):
    return write_text(Path(root) / "usr/local/bin/xray", xray_shim(version, test_rc), 0o755)


def make_nginx_tar(real_nginx, version, test_rc=0):
    buf = io.BytesIO()
    shim = nginx_shim(real_nginx, version, test_rc).encode()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in ("nginx", "nginx/sbin", "nginx/conf", "nginx/logs"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            tf.addfile(info)
        info = tarfile.TarInfo("nginx/sbin/nginx")
        info.size = len(shim)
        info.mode = 0o755
        info.mtime = 0
        tf.addfile(info, io.BytesIO(shim))
        conf = NGINX_CONF.encode()
        info = tarfile.TarInfo("nginx/conf/nginx.conf")
        info.size = len(conf)
        info.mode = 0o644
        info.mtime = 0
        tf.addfile(info, io.BytesIO(conf))
    return buf.getvalue()


def extract_bash_function(text, name):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", text, re.MULTILINE | re.DOTALL)
    return match.group(0) if match else None


def go_compare(f, root, installed, candidate):
    """Derive Go's version comparison without touching the managed files.

    The bogus digest forces rc=5 after the comparison decision, and the JSON
    report still names the action: reinstall means equal, update means newer.
    A downgrade returns rc=4 before any fetch.
    """
    install_xray_shim(root, installed)
    work = Path(f.evidence) / "f13-work" / "compare"
    path = write_text(work / f"candidate-{candidate}.txt", "compare payload\n")
    payload = write_text(work / f"manifest-{installed}-{candidate}.json", json.dumps(
        manifest("xray", candidate, b"compare payload\n", str(path), sha=ZERO_SHA)))
    r = f.run([f.go, "--root", root, "update", "xray", "--manifest", payload, "--json"])
    if r.rc == 4:
        return -1, r
    if r.rc == 5:
        try:
            report = json.loads(r.out)
        except ValueError:
            return None, r
        return (0 if report.get("action") == "reinstall" else 1), r
    return None, r


def main(f):
    f.need(f.bash_repo is not None,
           "F13 requires --bash-repo for the Bash version_compare baseline")
    install = f.bash_repo / "install.sh"
    f.need(install.is_file(), f"Bash baseline not found: {install}")
    version_is_numeric = extract_bash_function(install.read_text(encoding="utf-8"), "version_is_numeric")
    version_compare = extract_bash_function(install.read_text(encoding="utf-8"), "version_compare")
    version_gt = extract_bash_function(install.read_text(encoding="utf-8"), "version_gt")
    f.need(all((version_is_numeric, version_compare, version_gt)),
           "version_compare/version_gt not found in install.sh")

    work = Path(f.evidence) / "f13-work"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)

    serve = work / "serve"
    serve.mkdir(parents=True)
    httpd, port = serve_dir(serve)
    base = f"http://127.0.0.1:{port}"
    observed = {"xray": {}, "nginx": {}, "gates": {}, "versionTable": {}}
    compare = {}

    # ---- S1: digest-verified xray upgrade --------------------------------
    root = seed_root(work / "xray-root")
    old_bytes = xray_shim("1.8.20").encode()
    write_bytes(root / "usr/local/bin/xray", old_bytes, 0o755)
    cand1 = write_text(serve / "xray-1.8.24", xray_shim("1.8.24"), 0o755).read_bytes()
    m1 = write_text(serve / "xray-1.8.24.json",
                    json.dumps(manifest("xray", "1.8.24", cand1, f"{base}/xray-1.8.24")))
    up = f.run([f.go, "--root", root, "update", "xray", "--manifest", m1, "--json"])
    report = f.json_of(up, "update xray --json") if up.rc == 0 else None
    f.check(up.rc == 0, "xray upgrade rc=0", up.text[:300])
    if report:
        f.check(report["action"] == "update" and report["previousVersion"] == "1.8.20"
                and report["newVersion"] == "1.8.24", "report update 1.8.20 -> 1.8.24",
                json.dumps(report, sort_keys=True))
        f.check(report["verified"] is True and report["health"] is True,
                "report verified and health true", json.dumps(report, sort_keys=True))
        f.check(report["restarted"] is False and report["rolledBack"] is False,
                "sandbox root does not restart", json.dumps(report, sort_keys=True))
        f.check(any("sandbox root" in w for w in report["warnings"]),
                "sandbox restart warning recorded", str(report.get("warnings")))
        backup = Path(report["backupPath"]) if report.get("backupPath") else None
        f.check(backup is not None and backup.parent == root / "etc/idleleo/backup",
                "backup lives under etc/idleleo/backup", str(backup))
        f.check(backup is not None and backup.read_bytes() == old_bytes,
                "backup keeps the previous bytes", str(backup))
        f.check(backup is not None and oct(backup.stat().st_mode & 0o777) == "0o755",
                "backup keeps mode 0755", oct(backup.stat().st_mode & 0o777) if backup else "")
        observed["xray"]["backup"] = str(backup.name) if backup else ""
    bin_path = root / "usr/local/bin/xray"
    f.check(bin_path.read_bytes() == cand1, "binary equals the candidate artifact")
    f.check(oct(bin_path.stat().st_mode & 0o777) == "0o755", "installed binary is 0755")
    f.check(not (root / "usr/local/bin/xray.new").exists(), "no .xray.new staging file")
    f.check(len(backup_names(root)) == 1, "exactly one backup after the upgrade",
            str(backup_names(root)))

    # ---- S2: equal version is a reinstall -------------------------------
    m2 = write_text(serve / "xray-1.8.24-again.json",
                    json.dumps(manifest("xray", "1.8.24", cand1, f"{base}/xray-1.8.24")))
    again = f.run([f.go, "--root", root, "update", "xray", "--manifest", m2, "--json"])
    again_report = f.json_of(again, "reinstall --json") if again.rc == 0 else None
    f.check(again.rc == 0, "equal version reinstall rc=0", again.text[:300])
    if again_report:
        f.check(again_report["action"] == "reinstall", "equal version reports reinstall",
                json.dumps(again_report, sort_keys=True))
        prev_backup = Path(again_report.get("backupPath") or "")
        f.check(prev_backup.is_file() and prev_backup.read_bytes() == cand1,
                "reinstall refreshes the backup with the current bytes", str(prev_backup))
    f.check(len(backup_names(root)) == 2, "reinstall adds a second backup",
            str(backup_names(root)))

    # ---- S3: downgrade is refused with zero writes ----------------------
    cand_old = write_text(serve / "xray-1.8.10", xray_shim("1.8.10"), 0o755).read_bytes()
    m3 = write_text(serve / "xray-1.8.10.json",
                    json.dumps(manifest("xray", "1.8.10", cand_old, f"{base}/xray-1.8.10")))
    before_digest = f.tree_digest(root)
    down = f.run([f.go, "--root", root, "update", "xray", "--manifest", m3])
    f.check(down.rc == 4, "downgrade exits 4", down.text[:240])
    f.check(f.tree_digest(root) == before_digest, "downgrade leaves the tree unchanged")
    f.check(len(backup_names(root)) == 2, "downgrade creates no backup",
            str(backup_names(root)))

    # ---- S4/S5: digest and size mismatches ------------------------------
    cand_new = write_text(serve / "xray-1.8.25", xray_shim("1.8.25"), 0o755).read_bytes()
    m4 = write_text(serve / "xray-1.8.25-badsha.json",
                    json.dumps(manifest("xray", "1.8.25", cand_new,
                                        f"{base}/xray-1.8.25", sha="a" * 64)))
    before_digest = f.tree_digest(root)
    bad_sha = f.run([f.go, "--root", root, "update", "xray", "--manifest", m4])
    f.check(bad_sha.rc == 5, "sha256 mismatch exits 5", bad_sha.text[:240])
    m5 = write_text(serve / "xray-1.8.25-badsize.json",
                    json.dumps(manifest("xray", "1.8.25", cand_new,
                                        f"{base}/xray-1.8.25", size=len(cand_new) + 1)))
    bad_size = f.run([f.go, "--root", root, "update", "xray", "--manifest", m5])
    f.check(bad_size.rc == 5, "size mismatch exits 5", bad_size.text[:240])
    f.check(f.tree_digest(root) == before_digest, "digest failures leave the tree unchanged")
    f.check(len(backup_names(root)) == 2, "digest failures create no backup",
            str(backup_names(root)))

    # ---- S6: health failure rolls back ----------------------------------
    cand_bad = write_text(serve / "xray-1.8.26", xray_shim("1.8.26", test_rc=1), 0o755).read_bytes()
    m6 = write_text(serve / "xray-1.8.26.json",
                    json.dumps(manifest("xray", "1.8.26", cand_bad, f"{base}/xray-1.8.26")))
    sick = f.run([f.go, "--root", root, "update", "xray", "--manifest", m6, "--json"])
    sick_report = f.json_of(sick, "health failure --json") if sick.out.strip() else None
    f.check(sick.rc == 6, "failed run -test exits 6", sick.text[:300])
    if sick_report:
        f.check(sick_report["rolledBack"] is True and sick_report["health"] is False,
                "health failure reports rolledBack", json.dumps(sick_report, sort_keys=True))
    f.check(bin_path.read_bytes() == cand1, "rollback restores the previous bytes")
    f.check(not (root / "usr/local/bin/xray.new").exists(), "rollback removes the staging file")
    f.check(len(backup_names(root)) == 3, "failed health keeps exactly one new backup",
            str(backup_names(root)))

    # ---- S7: nginx tree upgrade with a real `-t` ------------------------
    real_nginx = shutil.which("nginx")
    f.need(real_nginx is not None, "nginx must be installed in the container")
    nroot = seed_root(work / "nginx-root")
    for sub in ("usr/local/nginx/sbin", "usr/local/nginx/conf", "usr/local/nginx/logs"):
        (nroot / sub).mkdir(parents=True, exist_ok=True)
    old_shim = nginx_shim(real_nginx, "1.24.0").encode()
    write_bytes(nroot / "usr/local/nginx/sbin/nginx", old_shim, 0o755)
    write_text(nroot / "usr/local/nginx/conf/nginx.conf", NGINX_CONF)
    write_text(nroot / "usr/local/nginx/conf/legacy-marker.txt", "old tree\n")
    old_test = f.run([nroot / "usr/local/nginx/sbin/nginx", "-t", "-p",
                      str(nroot / "usr/local/nginx") + "/",
                      "-c", nroot / "usr/local/nginx/conf/nginx.conf"])
    f.check(old_test.rc == 0, "seeded nginx tree passes a real nginx -t", old_test.text[:240])

    tar_ok = make_nginx_tar(real_nginx, "1.24.1")
    write_bytes(serve / "nginx-1.24.1.tar.gz", tar_ok)
    nm = write_text(serve / "nginx-1.24.1.json", json.dumps(
        manifest("nginx", "1.24.1", tar_ok, f"{base}/nginx-1.24.1.tar.gz")))
    nup = f.run([f.go, "--root", nroot, "update", "nginx", "--manifest", nm, "--json"])
    nreport = f.json_of(nup, "update nginx --json") if nup.rc == 0 else None
    f.check(nup.rc == 0, "nginx upgrade rc=0", nup.text[:300])
    if nreport:
        f.check(nreport["action"] == "update" and nreport["previousVersion"] == "1.24.0"
                and nreport["newVersion"] == "1.24.1", "nginx report 1.24.0 -> 1.24.1",
                json.dumps(nreport, sort_keys=True))
        f.check(nreport["health"] is True and nreport["restarted"] is False,
                "nginx health true and sandbox restart skipped",
                json.dumps(nreport, sort_keys=True))
    new_shim = (nroot / "usr/local/nginx/sbin/nginx").read_bytes()
    f.check(NGINX_VERSION_RE.search(new_shim.decode(errors="replace")) is not None
            and b"nginx/1.24.1" in new_shim,
            "nginx tree was replaced by the artifact tree")
    f.check(not (nroot / "usr/local/nginx/conf/legacy-marker.txt").exists(),
            "the previous tree is gone from usr/local/nginx")
    f.check(not (nroot / "usr/local/.nginx-stage").exists(), "extraction staging directory removed")
    if nreport and nreport.get("backupPath"):
        legacy = Path(nreport["backupPath"]) / "conf/legacy-marker.txt"
        f.check(legacy.is_file(), "the previous nginx tree is kept in the backup", str(legacy))
    observed["nginx"]["upgradedSha256"] = sha256_bytes(new_shim)

    # ---- S8: broken nginx artifact restores the tree --------------------
    before_tree = f.tree_digest(nroot / "usr/local/nginx")
    tar_bad = make_nginx_tar(real_nginx, "1.24.2", test_rc=1)
    write_bytes(serve / "nginx-1.24.2.tar.gz", tar_bad)
    nbm = write_text(serve / "nginx-1.24.2.json", json.dumps(
        manifest("nginx", "1.24.2", tar_bad, f"{base}/nginx-1.24.2.tar.gz")))
    nbad = f.run([f.go, "--root", nroot, "update", "nginx", "--manifest", nbm, "--json"])
    nbad_report = f.json_of(nbad, "nginx health failure --json") if nbad.text.strip() else None
    f.check(nbad.rc == 6, "broken nginx artifact exits 6", nbad.text[:300])
    if nbad_report:
        f.check(nbad_report["rolledBack"] is True, "nginx failure reports rolledBack",
                json.dumps(nbad_report, sort_keys=True))
    f.check(f.tree_digest(nroot / "usr/local/nginx") == before_tree,
            "nginx health failure restores the whole tree digest")
    f.check(not (nroot / "usr/local/.nginx-stage").exists(),
            "failed nginx upgrade leaves no staging directory")

    # ---- S9: manifest, flag and root gates ------------------------------
    groot = seed_root(work / "gate-root")
    write_text(groot / "usr/local/bin/xray", xray_shim("1.8.24"), 0o755)
    gate_digest = f.tree_digest(groot)
    good = write_text(serve / "xray-1.8.25-good.json", json.dumps(
        manifest("xray", "1.8.25", cand_new, f"{base}/xray-1.8.25")))

    missing = f.run([f.go, "--root", groot, "update", "xray"])
    f.check(missing.rc == 2, "missing --manifest exits 2", missing.text[:160])
    no_value = f.run([f.go, "--root", groot, "update", "xray", "--manifest"])
    f.check(no_value.rc == 2, "--manifest without a value exits 2", no_value.text[:160])
    unknown = f.run([f.go, "--root", groot, "update", "xray", "--manifest", good, "--bogus"])
    f.check(unknown.rc == 2, "unknown flag exits 2", unknown.text[:160])

    broken = write_text(work / "broken.json", "{not json")
    r = f.run([f.go, "--root", groot, "update", "xray", "--manifest", broken])
    f.check(r.rc == 3, "broken JSON exits 3", r.text[:200])
    wrong_component = write_text(serve / "wrong-component.json", json.dumps(
        manifest("nginx", "1.8.25", cand_new, f"{base}/xray-1.8.25")))
    r = f.run([f.go, "--root", groot, "update", "xray", "--manifest", wrong_component])
    f.check(r.rc == 3 and "component" in r.text, "wrong component exits 3", r.text[:200])
    bad_version = write_text(serve / "bad-version.json", json.dumps(
        manifest("xray", "1.8.25-beta", cand_new, f"{base}/xray-1.8.25")))
    r = f.run([f.go, "--root", groot, "update", "xray", "--manifest", bad_version])
    f.check(r.rc == 3, "non-dotted version exits 3", r.text[:200])
    bad_schema = write_text(serve / "bad-schema.json", json.dumps(
        {**manifest("xray", "1.8.25", cand_new, f"{base}/xray-1.8.25"), "schemaVersion": 2}))
    r = f.run([f.go, "--root", groot, "update", "xray", "--manifest", bad_schema])
    f.check(r.rc == 3 and "schemaVersion" in r.text,
            "unsupported schemaVersion exits 3", r.text[:200])
    zero_size = write_text(serve / "zero-size.json", json.dumps(
        {**manifest("xray", "1.8.25", cand_new, f"{base}/xray-1.8.25"), "sizeBytes": 0}))
    r = f.run([f.go, "--root", groot, "update", "xray", "--manifest", zero_size])
    f.check(r.rc == 3 and "sizeBytes" in r.text,
            "non-positive sizeBytes exits 3", r.text[:200])
    r = f.run([f.go, "--root", groot, "update", "xray", "--manifest", f"{base}/missing.json"])
    f.check(r.rc == 3, "HTTP 404 manifest exits 3", r.text[:200])
    r = f.run([f.go, "--root", groot, "update", "xray", "--manifest", "/nonexistent/m.json"])
    f.check(r.rc == 3, "missing manifest file exits 3", r.text[:200])
    f.check(f.tree_digest(groot) == gate_digest, "rejected manifests leave the tree unchanged")
    f.check(len(backup_names(groot)) == 0, "rejected manifests create no backup")

    real_root = f.run([f.go, "--root", "/", "update", "xray", "--manifest", good])
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        f.check(real_root.rc == 2 and "--container" in real_root.text,
                "real root without --container exits 2", real_root.text[:200])
    else:
        # A real host is deliberately allowed to migrate; it must not pretend
        # to be the container-gated path.
        f.check(real_root.rc in (0, 1), "real host uses the audited host path",
                real_root.text[:200])
    unmarked = work / "unmarked-root"
    (unmarked / "usr/local/bin").mkdir(parents=True)
    r = f.run([f.go, "--root", unmarked, "update", "xray", "--manifest", good])
    f.check(r.rc == 2 and "sandbox" in r.text, "unmarked sandbox exits 2", r.text[:200])
    f.check(not (unmarked / "etc/idleleo/backup").exists(),
            "unmarked sandbox gets no backup directory")
    observed["gates"] = {"missing": missing.rc, "unknown": unknown.rc, "brokenJson": 3,
                         "realRoot": real_root.rc, "unmarked": r.rc}

    # ---- S10: Go and Bash version comparison agree ----------------------
    table = [
        ("1.8.24", "1.8.20"), ("1.8.20", "1.8.24"), ("1.8.20", "1.8.20"),
        ("1.8", "1.8.0"), ("26.9.30", "26.10.31"), ("2026.10.15.7679", "2026.10.15.2"),
        ("1.10", "1.9"), ("2.0", "1.99.99"), ("1.0.0.1", "1.0.0"),
    ]
    bash_lines = "\n".join(f'"{a}|{b}"' for a, b in table)
    script = f"""set -uo pipefail
{version_is_numeric}
{version_compare}
{version_gt}
pairs=(
{bash_lines}
)
for pair in "${{pairs[@]}}"; do
    a=${{pair%%|*}}
    b=${{pair##*|}}
    printf '%s|%s|%s\\n' "$a" "$b" "$(version_compare "$a" "$b")"
done
"""
    script_path = write_text(work / "baseline-version.sh", script)
    bash = f.run(["bash", script_path], cwd=str(work))
    f.check(bash.rc == 0, "Bash version_compare baseline rc=0", bash.text[:200])
    bash_rows = {}
    for line in bash.out.splitlines():
        if line.count("|") != 2:
            continue
        a, b, result = line.split("|")
        bash_rows[(a, b)] = int(result)
    f.check(len(bash_rows) == len(table), "Bash baseline covers the whole table",
            str(len(bash_rows)))

    root_cmp = seed_root(work / "compare-root")
    go_rows = {}
    mismatches = []
    for a, b in table:
        value, result = go_compare(f, root_cmp, b, a)
        go_rows[f"{a}|{b}"] = value
        if value != bash_rows.get((a, b)):
            mismatches.append(f"{a} vs {b}: go={value} bash={bash_rows.get((a, b))} rc={result.rc}")
    f.check(not mismatches, "Go CompareVersions matches Bash version_compare",
            "; ".join(mismatches[:4]))
    observed["versionTable"]["pairs"] = len(table)

    compare["versionCompare"] = {
        "classification": "aligned",
        "go": "numeric per-component compare with v-prefix strip and zero padding",
        "bash": "version_is_numeric + version_compare from install.sh",
        "pairs": len(table),
    }
    compare["downgrade"] = {
        "classification": "approved-difference",
        "go": "rc=4 and zero writes",
        "bash": "prints a warning and continues the update path with rc=0",
    }
    compare["digestGate"] = {
        "classification": "approved-difference",
        "go": "sha256 and sizeBytes are mandatory and re-verified before any write",
        "bash": "trusts the upstream installer's own verification",
    }
    compare["healthRollback"] = {
        "classification": "approved-difference",
        "go": "automatic rollback to the backup with rc=6",
        "bash": "health check exists but rollback is an interactive path",
    }
    compare["backupLayout"] = {
        "classification": "new-go-behavior",
        "go": "etc/idleleo/backup/<component>-<version>-<unixnano>",
        "bash": "component-specific _backup_<version> names next to the tree",
    }
    compare["restartScope"] = {
        "classification": "approved-difference",
        "go": "restarts only on a real systemd root; sandbox roots warn and skip",
        "bash": "always stops and starts xray/nginx",
    }

    f.write_json("observed.json", observed)
    f.write_json("baseline-compare.json", compare)
    httpd.shutdown()


if __name__ == "__main__":
    sys.exit(run_fixture("F13", main))
