#!/usr/bin/env python3
"""F22 — read-only Rill handover status.

Preview evidence level: CONTAINER_VERIFIED (real legacy projection + Bash CLI).

The fixture builds disposable roots that mimic the Rill agent on disk and
checks `idleleo rill status` in every documented state: absent, active, stale,
installed but unobserved, and a corrupt config. It proves the projection uses
`capturedAtEpochSeconds` rather than the file mtime, never writes to the root,
and stays readable without root.

The fixed Bash baseline is `install.sh --rill-agent-status`, which sources the
legacy manager's `rxa_status_json`. The two surfaces are compared where they
overlap (installed, mode); their schema/freshness differences are recorded in
`baseline-compare.json` instead of being papered over. Install, diagnose,
authorize and uninstall are not migrated, so the fixture asserts they are
refused with the help/exit-2 path rather than silently accepted.
"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

CONFIG_REL = "etc/rill-xray-agent/config.json"
OBS_REL = "var/lib/rill-xray-agent-xray/status/xray-observation.json"
BIN_REL = "opt/rill-xray-agent/bin/rill-xray-agent"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def make_root(work, name, mode="normal", obs_age=None, config_body=None,
              binary=True, mtime_age=None, readable=False):
    root = work / name
    root.mkdir(parents=True)
    dir_mode = 0o755 if readable else 0o750
    file_mode = 0o644 if readable else 0o600
    config = root / CONFIG_REL
    config.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(config.parent, dir_mode)
    if config_body is None:
        config_body = json.dumps({
            "schemaVersion": 1,
            "mode": mode,
            "sentinelEnabled": True,
            "routeStage": "observe",
            "routeAssistEnabled": False,
            "boundedAutoAllowed": False,
        }, sort_keys=True) + "\n"
    config.write_text(config_body, encoding="utf-8")
    os.chmod(config, file_mode)
    if binary:
        binary_path = root / BIN_REL
        binary_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(binary_path.parent, dir_mode)
        binary_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        os.chmod(binary_path, 0o755)
    if obs_age is not None:
        obs = root / OBS_REL
        obs.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(obs.parent, dir_mode)
        obs.write_text(json.dumps({
            "schemaVersion": 1,
            "capturedAtEpochSeconds": int(time.time()) - obs_age,
            "xrayConfig": {},
            "services": [],
        }) + "\n", encoding="utf-8")
        os.chmod(obs, file_mode)
        if mtime_age is not None:
            stamp = time.time() - mtime_age
            os.utime(obs, (stamp, stamp))
    return root


def rill(f, root, *args):
    return f.run([f.go, "--root", str(root), "rill", *args], timeout=60)


def bash_status(f, root):
    env = dict(
        f.env,
        RILL_XRAY_AGENT_HOME=str(root / "etc/rill-xray-agent"),
        RILL_XRAY_AGENT_CONFIG=str(root / CONFIG_REL),
        RILL_XRAY_AGENT_STATUS=str(root / OBS_REL),
        RILL_XRAY_AGENT_CLI=str(root / BIN_REL),
        RILL_XRAY_AGENT_ROOT_POLICY_HELPER=str(root / "opt/rill-xray-agent/bin/root-policy"),
        RILL_XRAY_AGENT_ACCEPT_MODE_SWITCH="1",
        # install.sh only sources the real manager when this path exists; the
        # preview image has no installed copy, so point it at the checkout.
        RILL_XRAY_AGENT_MANAGER=str(f.bash_repo / "scripts/rill_xray_agent_manager.sh"),
    )
    return f.run(["bash", str(f.bash_repo / "install.sh"), "--rill-agent-status"],
                 timeout=120, env=env)


def main(f):
    f.need_root()
    f.check(f.bash_repo is not None and (f.bash_repo / "install.sh").is_file(),
            "Bash install.sh --rill-agent-status baseline is present",
            str(f.bash_repo / "install.sh"))
    if f.bash_repo is None:
        return
    f.need_tool("bash")
    f.need_tool("jq")
    f.need_tool("setpriv")

    work = f.evidence / "rill-work"
    if work.exists():
        import shutil
        shutil.rmtree(work)
    work.mkdir(parents=True)

    # 1) absent: no Rill paths at all, and the projection writes nothing.
    absent = make_root(work, "absent", binary=False)
    for rel in (CONFIG_REL, BIN_REL, OBS_REL):
        path = absent / rel
        if path.exists():
            path.unlink()
    before = f.tree_digest(absent)
    r = rill(f, absent, "status", "--json")
    f.check(r.rc == 0, "absent status exits 0", f"rc={r.rc} {r.err[:160]}")
    info = (f.json_of(r, "absent json") or {}).get("rill") or {}
    f.write_json("status-absent.json", info)
    f.check(info.get("installed") is False, "absent reports installed=false",
            json.dumps(info)[:160])
    f.check(info.get("status") == "absent", "absent reports status=absent",
            str(info.get("status")))
    f.check(info.get("enabled") is False, "absent reports enabled=false")
    text = rill(f, absent, "status")
    f.check(text.rc == 0 and "installed=false status=absent" in text.out,
            "absent text projection is stable", text.out.strip()[:160])
    f.check(f.tree_digest(absent) == before,
            "absent status does not create or modify files")

    # 2) active: capturedAtEpochSeconds is fresh while the file mtime is old.
    active = make_root(work, "active", mode="normal", obs_age=30, mtime_age=7200)
    before = f.tree_digest(active)
    r = rill(f, active, "status", "--json")
    f.check(r.rc == 0, "active status exits 0", f"rc={r.rc}")
    info = (f.json_of(r, "active json") or {}).get("rill") or {}
    active_info = info
    f.write_json("status-active.json", info)
    f.check(info.get("installed") is True, "active reports installed=true")
    f.check(info.get("status") == "active", "fresh capturedAt wins over an old mtime",
            str(info.get("status")))
    f.check(info.get("enabled") is True, "active reports enabled=true")
    f.check(info.get("mode") == "normal", "active reports the configured mode",
            str(info.get("mode")))
    f.check(0 <= int(info.get("observationAgeSeconds", -1)) <= 120,
            "active observation age is fresh", str(info.get("observationAgeSeconds")))
    f.check(info.get("configSha256") == sha256_file(active / CONFIG_REL),
            "config hash matches the file")
    f.check(info.get("observationSha256") == sha256_file(active / OBS_REL),
            "observation hash matches the file")
    f.check(info.get("binary") == BIN_REL and info.get("configPath") == CONFIG_REL,
            "projection exposes canonical relative paths",
            f"{info.get('binary')} {info.get('configPath')}")
    text = rill(f, active, "status")
    f.check(text.rc == 0 and "status=active" in text.out and "binary=" + BIN_REL in text.out,
            "active text projection includes paths", text.out.strip()[:200])
    f.check(f.tree_digest(active) == before, "active status is read-only")

    # 3) stale: capturedAt is old while the file mtime is fresh.
    stale = make_root(work, "stale", mode="observe-only", obs_age=1200, mtime_age=0)
    before = f.tree_digest(stale)
    r = rill(f, stale, "status", "--json")
    f.check(r.rc == 0, "stale status exits 0", f"rc={r.rc}")
    info = (f.json_of(r, "stale json") or {}).get("rill") or {}
    f.write_json("status-stale.json", info)
    f.check(info.get("status") == "stale", "old capturedAt wins over a fresh mtime",
            str(info.get("status")))
    f.check(int(info.get("observationAgeSeconds", 0)) >= 1200,
            "stale observation age is reported", str(info.get("observationAgeSeconds")))
    f.check("seconds old" in (info.get("warning") or ""), "stale warning is explicit",
            str(info.get("warning")))
    text = rill(f, stale, "status")
    f.check("warning=" in text.out, "stale text output carries the warning",
            text.out.strip()[:200])
    f.check(f.tree_digest(stale) == before, "stale status is read-only")

    # 4) installed but unobserved, then the observation appears live.
    unobserved = make_root(work, "unobserved", mode="normal", obs_age=None)
    r = rill(f, unobserved, "status", "--json")
    info = (f.json_of(r, "unobserved json") or {}).get("rill") or {}
    f.write_json("status-unobserved.json", info)
    f.check(info.get("installed") is True and info.get("status") == "installed-unobserved",
            "missing observation is reported explicitly", json.dumps(info)[:200])
    f.check("no xray-observation.json yet" in (info.get("warning") or ""),
            "missing-observation warning is exact", str(info.get("warning")))
    obs = unobserved / OBS_REL
    obs.parent.mkdir(parents=True, exist_ok=True)
    obs.write_text(json.dumps({"capturedAtEpochSeconds": int(time.time())}) + "\n")
    r = rill(f, unobserved, "status", "--json")
    info = (f.json_of(r, "observed later json") or {}).get("rill") or {}
    f.check(info.get("status") == "active", "status flips to active once observed",
            str(info.get("status")))
    obs.unlink()
    r = rill(f, unobserved, "status", "--json")
    info = (f.json_of(r, "observation removed json") or {}).get("rill") or {}
    f.check(info.get("status") == "installed-unobserved",
            "status returns to installed-unobserved when the observation is removed",
            str(info.get("status")))

    # 5) corrupt config: warn and keep projecting, never crash.
    bad = make_root(work, "badconfig", config_body="{", obs_age=10)
    before = f.tree_digest(bad)
    r = rill(f, bad, "status", "--json")
    f.check(r.rc == 0, "corrupt config exits 0", f"rc={r.rc}")
    info = (f.json_of(r, "badconfig json") or {}).get("rill") or {}
    f.write_json("status-badconfig.json", info)
    f.check(info.get("installed") is True and info.get("status") == "active",
            "corrupt config still projects installed state", json.dumps(info)[:200])
    f.check(info.get("warning") == "config.json is not valid JSON",
            "corrupt config warning is explicit", str(info.get("warning")))
    f.check(f.tree_digest(bad) == before, "corrupt-config status is read-only")

    # 6) rootless read-only status (same contract as the pure-readonly Bash path).
    rootless = make_root(work, "rootless", mode="normal", obs_age=20, readable=True)
    r = f.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
               str(f.go), "--root", str(rootless), "rill", "status", "--json"], timeout=60)
    f.check(r.rc == 0, "non-root rill status exits 0", f"rc={r.rc} {r.err[:160]}")
    rootless_info = (f.json_of(r, "rootless json") or {}).get("rill") or {}
    f.check(rootless_info.get("status") == "active",
            "non-root status reads the same state", str(rootless_info.get("status")))

    # 7) Unmigrated Rill surfaces are refused, never silently accepted.
    for sub in ("install", "diagnose", "authorize", "uninstall"):
        refused = rill(f, active, sub)
        f.check(refused.rc == 2, f"rill {sub} is refused with exit 2", f"rc={refused.rc}")
        f.check("rill status" in refused.out,
                f"rill {sub} refusal shows the supported surface", refused.out.strip()[:120])
    no_sub = f.run([f.go, "--root", str(active), "rill"], timeout=30)
    f.check(no_sub.rc == 2, "rill without a subcommand exits 2", f"rc={no_sub.rc}")
    bogus = rill(f, active, "status", "--bogus")
    f.check(bogus.rc == 2 and "unknown flag" in bogus.err,
            "unknown status flag exits 2", bogus.err.strip()[:160])

    # 8) Fixed Bash baseline where the surfaces overlap.
    bash_root = make_root(work, "bash-active", mode="normal", obs_age=20)
    before_bash = f.tree_digest(bash_root)
    b = bash_status(f, bash_root)
    f.check(b.rc == 0, "Bash rill status exits 0", f"rc={b.rc} {b.err[:200]}")
    doc = f.json_of(b, "bash rill status") or {}
    f.write_json("bash-status.json", doc)
    f.check(doc.get("schemaVersion") == 1, "Bash status keeps schemaVersion 1")
    f.check(doc.get("installed") is True, "Bash reports installed=true")
    f.check(doc.get("mode") == active_info.get("mode"),
            "Bash and Go agree on the configured mode",
            f"bash={doc.get('mode')} go={active_info.get('mode')}")
    f.check(doc.get("routeAssistEnabled") is False and doc.get("boundedAutoAllowed") is False,
            "Bash keeps route assist and bounded auto disabled",
            f"{doc.get('routeAssistEnabled')} {doc.get('boundedAutoAllowed')}")
    f.check("status" not in doc and "observationAgeSeconds" not in doc,
            "Bash status has no observation freshness surface")
    after_bash = f.tree_digest(bash_root)
    bash_wrote_config = before_bash != after_bash
    f.check(not bash_wrote_config, "Bash status leaves a pre-created root unchanged",
            "changed" if bash_wrote_config else "unchanged")

    # 9) Baseline divergence on an empty root: Bash fabricates a config and
    #    reports installed=true; Go projects the real absence.
    bash_absent = work / "bash-absent"
    bash_absent.mkdir()
    b_absent = bash_status(f, bash_absent)
    absent_doc = f.json_of(b_absent, "bash absent status") or {}
    f.write_json("bash-status-absent.json", absent_doc)
    f.check(b_absent.rc == 0, "Bash status on an empty root exits 0", f"rc={b_absent.rc}")
    f.check((bash_absent / CONFIG_REL).is_file(),
            "Bash status creates a default config when none exists")
    f.check(absent_doc.get("installed") is True,
            "Bash reports installed=true on an empty root (documented divergence)",
            str(absent_doc.get("installed")))
    (f.evidence / "baseline-compare.json").write_text(json.dumps({
        "go": {"installed": active_info.get("installed"), "mode": active_info.get("mode"),
               "observationStatus": "active/stale/installed-unobserved",
               "freshnessSeconds": 600,
               "absentRoot": {"installed": False, "status": "absent"}},
        "bash": {"installed": doc.get("installed"), "mode": doc.get("mode"),
                 "observationStatus": "not exposed", "freshnessSeconds": 3700,
                 "absentRoot": {"installed": absent_doc.get("installed"),
                                "createsConfig": True}},
        "notes": [
            "Bash rxa_status_json reports installed=true after creating a default config; Go projects actual files.",
            "Bash status JSON has no observation age/status; Go adds active/stale/installed-unobserved with a 600s freshness limit (Bash verify uses 3700s).",
            "Install/diagnose/authorize/uninstall stay on the Bash side; Go refuses them with usage/exit 2.",
        ],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(run_fixture("F22", main))
