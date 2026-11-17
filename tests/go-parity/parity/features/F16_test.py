#!/usr/bin/env python3
"""F16 — scheduled GeoData refresh (`schedule run --job geodata-refresh`).

Preview evidence level: CONTAINER_VERIFIED + LOCAL_GEODATA_ORIGIN.

The fixture serves deterministic GeoIP/GeoSite bytes and their `.sha256sum`
files from a loopback HTTP origin and drives the real Go manager against
disposable sandbox roots. It proves:

  * `schedule install --geodata-url` persists the origin and the native jobs,
  * a successful refresh replaces both assets atomically, with 0644 files in a
    0755 directory, records state/log, leaves a foreign old-layout tree alone
    and never writes the Bash `geo_version.json` metadata,
  * every verification failure (bad digest, truncation, empty body, HTML body,
    missing checksum, mixed assets) keeps the previous generation untouched and
    fails the job,
  * a fetch that never verified creates no geodata directory at all,
  * the sandbox marker, real-root euid, unsafe `geodataDir` and unknown job
    boundaries fail closed,
  * the fixed Bash baseline's contracts (`scripts/geo_update.sh`) are listed
    with a Go status so the divergences are explicit instead of implied.
"""
import hashlib
import json
import os
import shutil
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

SANDBOX_MARKER = ".idleleo-phase01-sandbox"
SANDBOX_VALUE = "I_ACCEPT_DISPOSABLE_SANDBOX"
GEODATA_REL = "etc/idleleo/share/xray"
FOREIGN_GEO_REL = "usr/local/share/xray"
CONFIG_REL = "etc/idleleo/schedule/jobs.json"
STATE_REL = "var/lib/idleleo/schedule/state.json"
LOG_REL = "var/log/idleleo/schedule/schedule.log"
ASSETS = ("geoip.dat", "geosite.dat")
FAILURE_CASES = ("badsha", "truncated", "empty", "html", "missing", "mixed")

# First byte must not be "<" or "{" so only the intended gate can reject them.
GEOIP_GOOD = b"F16 geoip payload\n" + b"geoip-body-" * 33
GEOSITE_GOOD = b"F16 geosite payload\n" + b"geosite-body-" * 47
OLD_GEOIP = b"F16 old geoip generation 1\n"
OLD_GEOSITE = b"F16 old geosite generation 1\n"
FOREIGN_GEOIP = b"F16 foreign legacy geoip\n"
FOREIGN_GEOSITE = b"F16 foreign legacy geosite\n"
HTML_BODY = b"<html>not geodata</html>"


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def checksum_file(asset, data):
    return f"{hashlib.sha256(data).hexdigest()}  {asset}\n".encode()


def build_routes():
    routes = {}
    for asset, good in zip(ASSETS, (GEOIP_GOOD, GEOSITE_GOOD)):
        routes[f"/good/{asset}"] = good
        routes[f"/good/{asset}.sha256sum"] = checksum_file(asset, good)

        # Checksum computed first, asset bytes changed afterwards.
        routes[f"/badsha/{asset}"] = b"F16 tampered body " + good
        routes[f"/badsha/{asset}.sha256sum"] = checksum_file(asset, good)

        # Checksum of the full payload, body cut down to a few bytes.
        routes[f"/truncated/{asset}"] = good[:5]
        routes[f"/truncated/{asset}.sha256sum"] = checksum_file(asset, good)

        routes[f"/empty/{asset}"] = b""
        routes[f"/empty/{asset}.sha256sum"] = checksum_file(asset, b"")

        routes[f"/html/{asset}"] = HTML_BODY
        routes[f"/html/{asset}.sha256sum"] = checksum_file(asset, HTML_BODY)

    routes["/mixed/geoip.dat"] = GEOIP_GOOD
    routes["/mixed/geoip.dat.sha256sum"] = checksum_file("geoip.dat", GEOIP_GOOD)
    routes["/mixed/geosite.dat"] = b"F16 mixed geosite that differs\n"
    routes["/mixed/geosite.dat.sha256sum"] = checksum_file("geosite.dat", GEOSITE_GOOD)
    return routes


class Origin:
    """Loopback origin that also records every requested path."""

    def __init__(self, routes):
        self.routes = routes
        self.requests = []
        self.lock = threading.Lock()
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        origin = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                with origin.lock:
                    origin.requests.append(self.path)
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


def make_sandbox(work, name, old=None, foreign=None, marked=True):
    root = Path(work) / name
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    if marked:
        marker = root / SANDBOX_MARKER
        marker.write_text(SANDBOX_VALUE + "\n", encoding="utf-8")
        os.chmod(marker, 0o600)
    if old is not None:
        target = root / GEODATA_REL
        target.mkdir(parents=True, exist_ok=True)
        os.chmod(target, 0o755)
        for asset, data in zip(ASSETS, old):
            path = target / asset
            path.write_bytes(data)
            os.chmod(path, 0o644)
    if foreign is not None:
        legacy = root / FOREIGN_GEO_REL
        legacy.mkdir(parents=True, exist_ok=True)
        os.chmod(legacy, 0o755)
        for asset, data in zip(ASSETS, foreign):
            path = legacy / asset
            path.write_bytes(data)
            os.chmod(path, 0o644)
    return root


def install_geo(f, root, url):
    return f.run([f.go, "--root", str(root), "--json", "schedule", "install",
                  "--geodata-url", url, "--container"], timeout=90)


def run_geo(f, root, job="geodata-refresh"):
    return f.run([f.go, "--root", str(root), "--json", "schedule", "run",
                  "--job", job], timeout=90)


def first_result(doc):
    results = (doc or {}).get("results") or []
    return results[0] if results else {}


def entries(path):
    path = Path(path)
    return sorted(p.name for p in path.iterdir()) if path.is_dir() else []


def read_json(path):
    return json.loads(path.read_text()) if path.is_file() else {}


def write_config(root, body, mode=0o640):
    path = Path(root) / CONFIG_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, mode)
    return path


def mode_of(path):
    return oct(path.stat().st_mode & 0o777)


def success_path(f, origin, work):
    sb = make_sandbox(work, "success", old=(OLD_GEOIP, OLD_GEOSITE),
                      foreign=(FOREIGN_GEOIP, FOREIGN_GEOSITE))
    target = sb / GEODATA_REL
    config_path = sb / CONFIG_REL
    state_path = sb / STATE_REL
    legacy = sb / FOREIGN_GEO_REL
    legacy_digest = f.tree_digest(legacy)
    url = origin.base + "/good"
    expected = (f"geoip.dat={len(GEOIP_GOOD)} bytes geosite.dat={len(GEOSITE_GOOD)} bytes; "
                "sandbox root, no service reload")

    install = install_geo(f, sb, url)
    install_doc = f.json_of(install, "schedule install") or {}
    f.check(install.rc == 0, "install exits 0", f"rc={install.rc} {install.err[:200]}")
    f.check(Path(str(install_doc.get("configPath", ""))) == config_path,
            "install reports the config path", str(install_doc.get("configPath")))
    f.check("geodata-refresh" in (install_doc.get("jobs") or []),
            "install owns the geodata-refresh job", json.dumps(install_doc.get("jobs")))
    f.check(install_doc.get("systemd") == "sandbox-not-queried",
            "sandbox install does not query systemd", str(install_doc.get("systemd")))
    f.check(config_path.is_file(), "schedule config exists", str(config_path))
    f.check(config_path.is_file() and (config_path.stat().st_mode & 0o777) == 0o640,
            "schedule config is 0640",
            mode_of(config_path) if config_path.exists() else "missing")
    config = read_json(config_path)
    f.check(config.get("geodataUrl") == url, "config pins the GeoData origin",
            str(config.get("geodataUrl")))

    run1 = run_geo(f, sb)
    doc1 = f.json_of(run1, "first geodata run") or {}
    res1 = first_result(doc1)
    f.check(run1.rc == 0, "geodata run exits 0", f"rc={run1.rc} {run1.err[:200]}")
    f.check(res1.get("job") == "geodata-refresh", "run reports the geodata job",
            str(res1.get("job")))
    f.check(res1.get("result") == "ok", "geodata run result is ok", str(res1.get("result")))
    f.check(res1.get("detail") == expected, "detail reports both asset sizes",
            str(res1.get("detail")))

    for asset, data in zip(ASSETS, (GEOIP_GOOD, GEOSITE_GOOD)):
        path = target / asset
        f.check(path.is_file() and path.read_bytes() == data,
                f"{asset} matches the origin payload")
        f.check(path.is_file() and (path.stat().st_mode & 0o777) == 0o644,
                f"{asset} is 0644", mode_of(path) if path.exists() else "missing")
    f.check(target.is_dir() and (target.stat().st_mode & 0o777) == 0o755,
            "geodata dir is 0755", mode_of(target) if target.exists() else "missing")
    f.check(entries(target) == sorted(ASSETS),
            "geodata dir holds exactly the two assets", str(entries(target)))

    f.check(state_path.is_file(), "state.json exists", str(state_path))
    f.check(state_path.is_file() and (state_path.stat().st_mode & 0o777) == 0o640,
            "state.json is 0640", mode_of(state_path) if state_path.exists() else "missing")
    state = read_json(state_path)
    job_state = (state.get("jobs") or {}).get("geodata-refresh") or {}
    f.check(job_state.get("result") == "ok", "state records an ok geodata run",
            json.dumps(job_state)[:200])
    f.check(state.get("runs") == 1, "state records the first run", str(state.get("runs")))

    log_path = sb / LOG_REL
    log = log_path.read_text(encoding="utf-8") if log_path.is_file() else ""
    f.check(any("geodata-refresh" in line and "result=ok" in line for line in log.splitlines()),
            "schedule log records the geodata run", log[:200])

    f.check(f.tree_digest(legacy) == legacy_digest,
            "foreign /usr/local/share/xray tree is untouched")

    run2 = run_geo(f, sb)
    doc2 = f.json_of(run2, "second geodata run") or {}
    res2 = first_result(doc2)
    f.check(run2.rc == 0 and res2.get("result") == "ok", "second geodata run is ok",
            f"rc={run2.rc} {res2.get('result')}")
    for asset, data in zip(ASSETS, (GEOIP_GOOD, GEOSITE_GOOD)):
        path = target / asset
        f.check(path.is_file() and path.read_bytes() == data,
                f"{asset} is unchanged by the second run")
    state2 = read_json(state_path)
    f.check(state2.get("runs") == 2, "state records the second run", str(state2.get("runs")))
    f.check(entries(target) == sorted(ASSETS), "second run leaves no residue",
            str(entries(target)))

    f.check(not list((sb / "etc").rglob("geo_version.json")),
            "Go writes no geo_version.json metadata")

    f.write_json("success.json", {"install": install_doc, "run": doc1, "secondRun": doc2})


def failure_matrix(f, origin, work):
    matrix = []
    for tag in FAILURE_CASES:
        old = (f"F16 old {tag} geoip\n".encode(), f"F16 old {tag} geosite\n".encode())
        sb = make_sandbox(work, f"fail-{tag}", old=old)
        target = sb / GEODATA_REL
        before = f.tree_digest(target)

        install = install_geo(f, sb, origin.base + "/" + tag)
        f.check(install.rc == 0, f"{tag}: install exits 0",
                f"rc={install.rc} {install.err[:160]}")

        run = run_geo(f, sb)
        doc = f.json_of(run, f"{tag} run") or {}
        res = first_result(doc)
        detail = str(res.get("detail") or "")
        after = f.tree_digest(target)
        names = entries(target)
        residue = [name for name in names if name not in ASSETS]
        state = read_json(sb / STATE_REL)
        job_state = (state.get("jobs") or {}).get("geodata-refresh") or {}

        f.check(run.rc == 1, f"{tag}: failed refresh exits 1",
                f"rc={run.rc} {detail[:160]}")
        f.check(res.get("result") == "failed", f"{tag}: result is failed",
                str(res.get("result")))
        f.check(bool(detail), f"{tag}: failure detail is recorded", detail[:200])
        f.check(before == after, f"{tag}: previous assets stay byte-identical",
                f"{before[:12]} != {after[:12]}")
        f.check(names == sorted(ASSETS), f"{tag}: no temp or stage residue", str(names))
        f.check(job_state.get("result") == "failed",
                f"{tag}: state records the failure", json.dumps(job_state)[:200])

        if tag == "mixed":
            geoip = target / "geoip.dat"
            f.check(geoip.is_file() and geoip.read_bytes() == old[0],
                    "mixed: verified geoip.dat is not partially written")

        matrix.append({
            "origin": "/" + tag,
            "rc": run.rc,
            "result": res.get("result"),
            "detail": detail,
            "oldDigestUnchanged": before == after,
            "residueCount": len(residue),
            "targetDirExists": target.is_dir(),
        })

    # A fetch that fails verification must not even create the target dir.
    sb = make_sandbox(work, "fail-badsha-fresh")
    target = sb / GEODATA_REL
    f.check(not target.exists(), "fresh sandbox starts without a geodata dir")
    install = install_geo(f, sb, origin.base + "/badsha")
    f.check(install.rc == 0, "badsha without previous assets: install exits 0",
            f"rc={install.rc} {install.err[:160]}")
    run = run_geo(f, sb)
    doc = f.json_of(run, "badsha without previous assets") or {}
    res = first_result(doc)
    f.check(run.rc == 1 and res.get("result") == "failed",
            "badsha without previous assets fails the job",
            f"rc={run.rc} {res.get('result')}")
    f.check(not target.exists(), "failed fetch creates no geodata dir", str(target))
    matrix.append({
        "origin": "/badsha (no previous assets)",
        "rc": run.rc,
        "result": res.get("result"),
        "detail": str(res.get("detail") or ""),
        "oldDigestUnchanged": True,
        "residueCount": 0,
        "targetDirExists": target.is_dir(),
    })

    f.write_json("failure-matrix.json", {"cases": matrix})


def boundaries(f, origin, work):
    unmarked = make_sandbox(work, "unmarked", marked=False)
    run = run_geo(f, unmarked)
    text = (run.out + run.err).lower()
    f.check(run.rc == 1, "unmarked root run exits 1", f"rc={run.rc}")
    f.check("sandbox" in text, "unmarked refusal names the sandbox marker",
            run.text.strip()[:200])
    f.check(not (unmarked / "etc").exists(), "unmarked refusal creates no etc tree")

    setpriv = f.need_tool("setpriv")
    nonroot = f.run([setpriv, "--reuid=65534", "--regid=65534", "--clear-groups",
                     str(f.go), "--root", "/", "--json", "schedule", "run",
                     "--job", "geodata-refresh"], timeout=60)
    f.check(nonroot.rc == 1, "non-root real-root run exits 1", f"rc={nonroot.rc}")
    f.check("root required" in (nonroot.out + nonroot.err).lower(),
            "real root requires root", nonroot.text.strip()[:200])

    escape = make_sandbox(work, "escape-config")
    write_config(escape, {
        "schemaVersion": 1,
        "jobs": ["geodata-refresh"],
        "geodataUrl": origin.base + "/good",
        "geodataDir": "../escape",
    })
    run = run_geo(f, escape)
    text = (run.out + run.err).lower()
    f.check(run.rc == 1, "escaping geodataDir exits 1", f"rc={run.rc}")
    f.check("unsafe" in text and "path" in text and "geodatadir" in text,
            "escaping geodataDir is refused as an unsafe path", run.text.strip()[:200])
    f.check(not (Path(work) / "escape").exists(), "escape directory is never created")
    f.check(not (escape / "etc/idleleo/share").exists(),
            "refused config creates no geodata dir")

    unknown = make_sandbox(work, "unknown-job")
    run = run_geo(f, unknown, job="nope")
    f.check(run.rc == 1, "unknown job exits 1", f"rc={run.rc}")
    f.check("unknown scheduled job" in (run.out + run.err),
            "unknown job is named", run.text.strip()[:200])


def locate(text, file_label, needle):
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return {"file": file_label, "line": number, "snippet": line.strip()}
    return {"file": file_label, "line": 0, "snippet": ""}


def bash_baseline(f):
    if f.bash_repo is None:
        f.check(False, "Bash geo_update.sh baseline is present", "no --bash-repo")
        return
    script_rel = "scripts/geo_update.sh"
    script = f.bash_repo / script_rel
    install_sh = f.bash_repo / "install.sh"
    f.check(script.is_file(), "Bash geo_update.sh baseline is present", script_rel)
    if not script.is_file():
        return

    geo_text = script.read_text(encoding="utf-8")
    install_text = install_sh.read_text(encoding="utf-8") if install_sh.is_file() else ""

    contracts = [
        {
            "contract": "checksum verification",
            "text": geo_text,
            "file": script_rel,
            "needles": ["verify_checksum_file"],
            "goStatus": "aligned",
            "note": "internal/geodata reads <asset>.sha256sum and verifies the sha256 of "
                    "both assets before writing anything; a mismatch keeps the previous file.",
        },
        {
            "contract": "pinned release tag and geo_version.json metadata",
            "text": geo_text,
            "file": script_rel,
            "needles": [
                'release_latest="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest"',
                "geo_version_file=",
            ],
            "goStatus": "different",
            "note": "Go downloads from releases/latest/download (geodata.DefaultURL): no tag "
                    "resolution, no version metadata, and no geo_version.json is written.",
        },
        {
            "contract": "Xray run -test pre-validation",
            "text": geo_text,
            "file": script_rel,
            "needles": ["run -test -config"],
            "goStatus": "missing",
            "note": "Go never invokes Xray to validate staged assets before installing them.",
        },
        {
            "contract": "stage-and-restore rollback",
            "text": geo_text,
            "file": script_rel,
            "needles": ["stage_dir=$(mktemp -d", "restore_previous"],
            "goStatus": "missing",
            "note": "Go relies on verify-before-write: both assets are fetched and verified in "
                    "memory, then written with writeAtomic; there is no stage dir or restore step.",
        },
        {
            "contract": "restart when Xray is active",
            "text": geo_text,
            "file": script_rel,
            "needles": ["was_active=true", "systemctl restart xray"],
            "goStatus": "different",
            "note": "Go restarts xray only on the real root / when is-active reports active; a "
                    "sandbox root records 'sandbox root, no service reload'.",
        },
        {
            "contract": "old-layout migration",
            "text": install_text,
            "file": "install.sh",
            "needles": ["manages as a symlink into /etc/idleleo/share/xray"],
            "goStatus": "missing",
            "note": "Go writes only etc/idleleo/share/xray; a foreign /usr/local/share/xray tree "
                    "is neither migrated nor linked (asserted untouched in the success path).",
        },
    ]

    entries = []
    extracted = []
    for spec in contracts:
        found_all = True
        first = None
        for needle in spec["needles"]:
            evidence = locate(spec["text"], spec["file"], needle)
            present = evidence["line"] > 0
            found_all = found_all and present
            if present:
                extracted.append(f"{evidence['file']}:{evidence['line']}: {evidence['snippet']}")
                if first is None:
                    first = evidence
        f.check(found_all, f"Bash baseline keeps the {spec['contract']} contract",
                json.dumps(first or {})[:200])
        entries.append({
            "contract": spec["contract"],
            "bashEvidence": first or {"file": spec["file"], "line": 0, "snippet": ""},
            "goStatus": spec["goStatus"],
            "note": spec["note"],
        })

    seen = set()
    unique = [line for line in extracted if line not in seen and not seen.add(line)]
    f.write_json("baseline-compare.json",
                 {"baseline": script_rel, "entries": entries})
    (f.evidence / "bash-contracts.txt").write_text("\n".join(unique) + "\n",
                                                   encoding="utf-8")


def main(f):
    f.need_root()
    work = f.evidence / "geodata-work"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    origin = Origin(build_routes())
    origin.start()
    try:
        success_path(f, origin, work)
        failure_matrix(f, origin, work)
        boundaries(f, origin, work)
        bash_baseline(f)
    finally:
        origin.stop()
        f.write_json("origin-requests.json", origin.requests)


if __name__ == "__main__":
    sys.exit(run_fixture("F16", main))
