#!/usr/bin/env python3
"""F08 — port/listen edits, target/serverNames and the SNI-guard policy.

Preview evidence level: CONTAINER_VERIFIED (config-level: the real Go binary
patches real Xray JSON configs inside a disposable sandbox root; the installed
`xray` binary is a fixture stub that records its argv, so `xray -test` is the
only engine surface being simulated. No Xray data plane, no systemd, no host
root, no network).

What the fixture proves about the Go manager:

* `xray config edit` refuses live-disconnect edits without `--yes` in a
  non-TTY invocation and writes nothing;
* a dry run reports the exact scope (`inbounds[0].port`) and leaves the file,
  its mode, the metadata and the backup tree untouched;
* a committed port edit preserves mode 0640, backs up the old bytes, updates
  `runtimeSha256`, marks the edit no-restart/no-probe and — because a direct
  Reality install has no front — advertises the new port in the link it prints
  and in a follow-up `xray share`;
* an `xray -test` rejection aborts before any write (candidate validation);
* `--listen` rewrites only the listen field; `--server-names` accepts a
  comma-separated list on direct Reality, keeps the target and makes the first
  name the SNI in the link; `--target` honours an explicit `host:port` and
  defaults a bare host to :443;
* reserved Reality ports (9403/9404/9443/9444) and malformed targets/names are
  refused with nothing written, and target/serverNames are refused on
  non-Reality installs;
* SNI Guard lives in the generator: reality-nginx renders the Bash stream
  block, isolate (default) adds the 03-isolate.conf handshake-reject site,
  reject switches the deny upstream to 9404, decoy is refused because its
  artifacts are not generated.

The Bash baseline is extracted from the fixed install.sh and compared in
`baseline-compare.json`: Bash edits target/serverNames with a hard-coded :443
and exactly one serverName, offers a three-way SNI-guard menu (including a
decoy site) at runtime, and refuses a guard port that collides with a
configured port. None of those runtime switches exist as Go subcommands.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

SANDBOX_MARKER = "I_ACCEPT_DISPOSABLE_SANDBOX"
BASH_FUNCTIONS = (
    "serverNames_set",
    "modify_target_serverNames",
    "nginx_reality_serverNames_add",
    "sni_guard_policy_choose",
    "sni_guard_port_conflicts",
    "ensure_reality_sni_guard_defaults",
    "reset_sni_guard_policy",
)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def mode_of(path):
    return stat.S_IMODE(Path(path).stat().st_mode)


def inbound(config, index=0):
    return config["inbounds"][index]


def uri_parts(uri):
    parts = urlsplit(uri)
    return parts, parse_qs(parts.query)


def extract_bash_function(text, name):
    match = re.search(rf"^{re.escape(name)}\s*\(\)\s*\{{\n(.*?)^\}}\s*$",
                      text, re.MULTILINE | re.DOTALL)
    return match.group(0) if match else None


def main(f):
    f.need(f.bash_repo is not None,
           "F08 requires --bash-repo for the fixed Bash port/target/SNI-guard baseline")

    work = f.evidence / "f08-work"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    install_sh = f.bash_repo / "install.sh"
    install_text = install_sh.read_text(encoding="utf-8")
    observed = {"base": {}, "edits": {}, "sniGuard": {}}

    # ---- S0: one real direct-Reality config to patch ---------------------
    base = work / "reality-base.json"
    r = f.run([f.go, "xray", "generate", "--out", base, "--json",
               "--mode", "reality", "--domain", "example.com", "--port", "18443"])
    payload = f.json_of(r, "generate reality base") if r.rc == 0 else None
    f.check(r.rc == 0 and base.is_file(), "generate reality base rc=0 and wrote config",
            r.text[:200])
    f.need(payload is not None and base.is_file(), "the Reality base config was generated")
    cfg = read_json(base)
    f.check(payload["mode"] == "reality" and payload["transport"] == "raw",
            "base mode/transport", f"{payload['mode']}/{payload['transport']}")
    f.check(payload["port"] == 18443, "base port", str(payload["port"]))
    f.check(inbound(cfg)["port"] == 18443, "base inbound port", str(inbound(cfg)["port"]))
    f.check(inbound(cfg)["listen"] == "0.0.0.0", "base listen", inbound(cfg)["listen"])
    reality = inbound(cfg)["streamSettings"]["realitySettings"]
    f.check(reality["serverNames"] == ["example.com"], "base serverNames",
            json.dumps(reality["serverNames"]))
    f.check(reality["target"] == "example.com:443", "base target", reality["target"])
    f.check(mode_of(base) == 0o600, "base config mode is 0600", oct(mode_of(base)))
    base_bytes = base.read_bytes()
    base_sha = sha256_bytes(base_bytes)
    observed["base"] = {
        "configSha256": base_sha,
        "port": inbound(cfg)["port"], "listen": inbound(cfg)["listen"],
        "serverNames": reality["serverNames"], "target": reality["target"],
    }

    def build_root(name, config_bytes, xray_rc=0):
        """A disposable sandbox root carrying metadata plus an argv-recording xray stub."""
        root = work / name
        (root / "etc/idleleo/v1").mkdir(parents=True)
        (root / "etc/idleleo/conf/xray").mkdir(parents=True)
        (root / "usr/local/bin").mkdir(parents=True)
        (root / "var").mkdir(parents=True)
        (root / ".idleleo-phase01-sandbox").write_text(SANDBOX_MARKER + "\n", encoding="utf-8")
        config_path = root / "etc/idleleo/conf/xray/config.json"
        config_path.write_bytes(config_bytes)
        os.chmod(config_path, 0o640)
        meta = {
            "schemaVersion": 1,
            "activeEngine": "xray",
            "provenance": "native",
            "role": "node",
            "tls": "Reality",
            "transport": "raw",
            "runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
            "runtimeSha256": sha256_bytes(config_bytes),
            "ownedResources": ["xray:runtime"],
            "updatedAt": "2026-11-17T00:00:00Z",
        }
        (root / "etc/idleleo/v1/metadata.json").write_text(
            json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        log = root / "var" / "xray-test.log"
        stub = root / "usr/local/bin/xray"
        stub.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$*\" >> '{log}'\n"
            + ("exit 0\n" if xray_rc == 0 else
               f"echo 'fixture: xray -test rejected the candidate' >&2\nexit {xray_rc}\n"),
            encoding="utf-8")
        os.chmod(stub, 0o755)
        return root, config_path, log

    def edit(root, config_path, *args):
        return f.run([f.go, "--root", str(root), "xray", "config", "edit",
                      "--path", str(config_path), "--json", "--no-probe", *args])

    def metadata_of(root):
        return read_json(root / "etc/idleleo/v1/metadata.json")

    def backups_of(root):
        return sorted((root / "etc/idleleo/backup").glob("edit-*")) \
            if (root / "etc/idleleo/backup").is_dir() else []

    root1, cfg1, log1 = build_root("root-reality", base_bytes)

    # ---- S1: setting the current value is a no-op ------------------------
    r = edit(root1, cfg1, "--port", "18443", "--dry-run")
    rep = f.json_of(r, "no-op dry run") if r.rc == 0 else None
    f.check(r.rc == 0, "identical port dry run rc=0", r.text[:200])
    if rep:
        f.check(rep["noChanges"] is True, "identical port reports noChanges", json.dumps(rep["changed"]))
        f.check("diff" not in rep or rep["diff"] == [], "identical port has an empty diff",
                json.dumps(rep.get("diff")))
    f.check(sha256_file(cfg1) == base_sha, "no-op dry run leaves the config untouched")

    # ---- S2: dry run names the exact scope -------------------------------
    r = edit(root1, cfg1, "--port", "19443", "--dry-run")
    rep = f.json_of(r, "port dry run") if r.rc == 0 else None
    f.check(r.rc == 0, "port dry run rc=0", r.text[:200])
    if rep:
        f.check(rep["dryRun"] is True, "port dry run is marked dryRun")
        f.check(rep["changed"] == ["port"], "port dry run changed=[port]", json.dumps(rep["changed"]))
        f.check(rep["diff"] == ["inbounds[0].port"], "port dry run diff scope",
                json.dumps(rep["diff"]))
        f.check(rep["noChanges"] is False, "port dry run reports a pending change")
        f.check(rep.get("backupDir", "") == "", "port dry run creates no backup")
        f.check(rep["newSha256"] != rep["oldSha256"], "port dry run predicts a new hash")
        parts, _ = uri_parts(rep["shareUri"])
        f.check(parts.port == 19443, "port dry run link uses the new port", str(parts.port))
    f.check(sha256_file(cfg1) == base_sha, "port dry run leaves the config untouched")
    f.check(mode_of(cfg1) == 0o640, "port dry run leaves the config mode alone", oct(mode_of(cfg1)))
    f.check(not log1.exists(), "port dry run never executes xray -test")

    # ---- S3: non-TTY disconnect refusal ---------------------------------
    r = edit(root1, cfg1, "--port", "19443")
    f.check(r.rc == 2, "port edit without --yes is refused (rc=2)", f"rc={r.rc}")
    f.check("--yes" in r.text, "refusal names --yes", r.text.strip()[:200])
    f.check(sha256_file(cfg1) == base_sha, "refused edit leaves the config untouched")
    f.check(backups_of(root1) == [], "refused edit creates no backup")
    f.check(not log1.exists(), "refused edit never executes xray -test")

    # ---- S4: committed port edit ----------------------------------------
    r = edit(root1, cfg1, "--port", "19443", "--yes", "--no-restart")
    rep = f.json_of(r, "port edit") if r.rc == 0 else None
    f.check(r.rc == 0, "port edit rc=0", r.text[:400])
    edited = read_json(cfg1)
    new_sha = sha256_file(cfg1)
    f.check(inbound(edited)["port"] == 19443, "port edit rewrites the inbound port",
            str(inbound(edited)["port"]))
    f.check(inbound(edited)["listen"] == "0.0.0.0", "port edit keeps the listen address",
            inbound(edited)["listen"])
    f.check(mode_of(cfg1) == 0o640, "port edit preserves config mode 0640", oct(mode_of(cfg1)))
    f.check(new_sha != base_sha, "port edit changes the config hash", new_sha[:16])
    f.check(metadata_of(root1)["runtimeSha256"] == new_sha,
            "port edit updates metadata runtimeSha256")
    backups = backups_of(root1)
    f.check(len(backups) == 1, "port edit leaves exactly one backup", str(len(backups)))
    if backups:
        old = backups[0] / "config.json"
        f.check(old.is_file() and old.read_bytes() == base_bytes,
                "backup holds the pre-edit bytes")
        f.check(mode_of(old) == 0o600, "backup config mode is 0600", oct(mode_of(old)))
    if rep:
        f.check(rep["backupDir"] != "", "report names the backup directory", rep["backupDir"])
        f.check(rep["noRestart"] is True, "report records --no-restart")
        f.check(rep["oldSha256"] == base_sha and rep["newSha256"] == new_sha,
                "report hashes match the file transition")
        parts, _ = uri_parts(rep["shareUri"])
        f.check(parts.port == 19443, "edit report advertises the new port", str(parts.port))
        f.check(rep["oldShareUri"] and uri_parts(rep["oldShareUri"])[0].port == 18443,
                "report keeps the pre-edit link for rollback")
    f.check(log1.is_file(), "committed edit executed the candidate validator")
    if log1.is_file():
        calls = log1.read_text(encoding="utf-8").strip().splitlines()
        f.check(len(calls) == 1 and calls[0].startswith("-test -config "),
                "validator was called once with -test -config", json.dumps(calls))
        f.check(".edit-candidate-" in calls[0],
                "validator ran against the candidate, not the live config", calls[0])
    r = f.run([f.go, "xray", "share", "--path", str(cfg1),
               "--host", "198.51.100.25", "--json"])
    info = f.json_of(r, "share after port edit") if r.rc == 0 else None
    f.check(r.rc == 0, "share after port edit rc=0", r.text[:200])
    if info:
        f.check(info["port"] == 19443, "share after port edit uses the new port",
                str(info["port"]))
    observed["edits"]["port"] = {
        "from": 18443, "to": 19443,
        "configSha256": new_sha, "shareUriPort": info["port"] if info else None,
    }

    # ---- S5: a rejected candidate never reaches the disk ----------------
    root2, cfg2, log2 = build_root("root-rejected", base_bytes, xray_rc=1)
    r = edit(root2, cfg2, "--port", "19443", "--yes", "--no-restart")
    f.check(r.rc == 1, "xray -test rejection fails the edit (rc=1)", f"rc={r.rc}")
    f.check("xray -test rejected the candidate" in r.text,
            "rejection surfaces the validator verdict", r.text.strip()[:300])
    f.check("configuration was not changed" in r.text,
            "rejection states the config was not changed", r.text.strip()[:300])
    f.check(sha256_file(cfg2) == base_sha, "rejected candidate leaves the config untouched")
    f.check(metadata_of(root2)["runtimeSha256"] == base_sha,
            "rejected candidate leaves metadata untouched")
    f.check(backups_of(root2) == [], "rejected candidate creates no backup")
    f.check(log2.is_file(), "the rejecting validator was executed")
    observed["edits"]["rejectedCandidate"] = {"rc": r.rc, "configSha256": base_sha}

    # ---- S6: --listen only touches the listen field ---------------------
    r = edit(root1, cfg1, "--listen", "127.0.0.1", "--yes", "--no-restart")
    rep = f.json_of(r, "listen edit") if r.rc == 0 else None
    f.check(r.rc == 0, "listen edit rc=0", r.text[:300])
    listened = read_json(cfg1)
    f.check(inbound(listened)["listen"] == "127.0.0.1", "listen edit rewrites the address",
            inbound(listened)["listen"])
    f.check(inbound(listened)["port"] == 19443, "listen edit keeps the port",
            str(inbound(listened)["port"]))
    if rep:
        f.check(rep["changed"] == ["listen"], "listen edit changed=[listen]",
                json.dumps(rep["changed"]))
        f.check(rep["diff"] == ["inbounds[0].listen"], "listen edit diff scope",
                json.dumps(rep["diff"]))
        parts, _ = uri_parts(rep["shareUri"])
        f.check(parts.hostname == "example.com" and parts.port == 19443,
                "listen edit keeps the public endpoint", f"{parts.hostname}:{parts.port}")

    # ---- S7: --server-names on direct Reality ---------------------------
    r = edit(root1, cfg1, "--server-names", "a.example.com, b.example.com", "--no-restart")
    rep = f.json_of(r, "server-names edit") if r.rc == 0 else None
    f.check(r.rc == 0, "server-names edit rc=0", r.text[:300])
    renamed = read_json(cfg1)
    settings = inbound(renamed)["streamSettings"]["realitySettings"]
    f.check(settings["serverNames"] == ["a.example.com", "b.example.com"],
            "server-names accepts a comma-separated list", json.dumps(settings["serverNames"]))
    f.check(settings["target"] == "example.com:443",
            "server-names keeps the target", settings["target"])
    if rep:
        f.check(rep["changed"] == ["server-names"], "server-names changed=[server-names]",
                json.dumps(rep["changed"]))
        f.check("inbounds[0].streamSettings.realitySettings.serverNames" in rep["diff"],
                "server-names diff stays inside realitySettings", json.dumps(rep["diff"]))
        _, query = uri_parts(rep["shareUri"])
        f.check(query.get("sni") == ["a.example.com"],
                "server-names makes the first name the link SNI", str(query.get("sni")))
        f.check(rep.get("originProbe") == "skipped: --no-probe",
                "--no-probe skips the origin handshake", rep.get("originProbe"))
    before_bad = sha256_file(cfg1)
    r = edit(root1, cfg1, "--server-names", "bad/name", "--no-restart")
    f.check(r.rc == 1, "invalid server name is refused (rc=1)", f"rc={r.rc}")
    f.check("invalid server name" in r.text, "invalid server name is named",
            r.text.strip()[:200])
    f.check(sha256_file(cfg1) == before_bad, "invalid server name writes nothing")

    # ---- S8: --target normalisation and validation ----------------------
    r = edit(root1, cfg1, "--target", "other.example.org", "--no-restart")
    rep = f.json_of(r, "target edit") if r.rc == 0 else None
    f.check(r.rc == 0, "bare target edit rc=0", r.text[:300])
    retargeted = read_json(cfg1)
    settings = inbound(retargeted)["streamSettings"]["realitySettings"]
    f.check(settings["target"] == "other.example.org:443",
            "bare target gains the default :443", settings["target"])
    f.check(settings["serverNames"] == ["a.example.com", "b.example.com"],
            "target edit keeps the serverNames list", json.dumps(settings["serverNames"]))
    if rep:
        _, query = uri_parts(rep["shareUri"])
        f.check(query.get("sni") == ["a.example.com"],
                "target edit keeps the link SNI on the serverName", str(query.get("sni")))
        f.check(rep.get("originProbe") == "skipped: --no-probe",
                "--no-probe skips the origin handshake for --target",
                rep.get("originProbe"))
    r = edit(root1, cfg1, "--target", "other.example.org:8443", "--no-restart")
    f.check(r.rc == 0, "explicit target port edit rc=0", r.text[:300])
    retargeted = read_json(cfg1)
    settings = inbound(retargeted)["streamSettings"]["realitySettings"]
    f.check(settings["target"] == "other.example.org:8443",
            "explicit target port is honoured", settings["target"])
    before_bad = sha256_file(cfg1)
    r = edit(root1, cfg1, "--target", "bad target!", "--no-restart")
    f.check(r.rc == 1, "malformed target is refused (rc=1)", f"rc={r.rc}")
    f.check("invalid reality target" in r.text, "malformed target is named",
            r.text.strip()[:200])
    f.check(sha256_file(cfg1) == before_bad, "malformed target writes nothing")
    observed["edits"]["targetServerNames"] = {
        "target": settings["target"],
        "serverNames": settings["serverNames"],
        "configSha256": sha256_file(cfg1),
    }

    # ---- S9: reserved port and runtime SNI-guard switches ---------------
    before_reserved = sha256_file(cfg1)
    r = edit(root1, cfg1, "--port", "9443", "--yes", "--no-restart")
    f.check(r.rc == 1, "reserved Reality port is refused (rc=1)", f"rc={r.rc}")
    f.check("reserved" in r.text, "reserved port refusal is explicit", r.text.strip()[:200])
    f.check(sha256_file(cfg1) == before_reserved, "reserved port writes nothing")
    r = edit(root1, cfg1, "--sni-guard", "isolate")
    f.check(r.rc == 2, "there is no --sni-guard runtime switch (rc=2)", f"rc={r.rc}")
    f.check("unknown flag" in r.text and "--sni-guard" in r.text,
            "--sni-guard is reported as an unknown flag", r.text.strip()[:200])
    r = edit(root1, cfg1, "--unknown-sni-policy", "reject")
    f.check(r.rc == 2, "config edit does not accept --unknown-sni-policy (rc=2)",
            f"rc={r.rc}")
    f.check(sha256_file(cfg1) == before_reserved, "unknown policy flags write nothing")

    # ---- S10: target/serverNames are Reality-only -----------------------
    none_cfg = work / "none-base.json"
    r = f.run([f.go, "xray", "generate", "--out", none_cfg, "--json",
               "--mode", "none", "--transport", "ws", "--port", "8080"])
    f.check(r.rc == 0 and none_cfg.is_file(), "generate none/ws base rc=0", r.text[:200])
    none_bytes = none_cfg.read_bytes()
    root3, cfg3, _ = build_root("root-none", none_bytes)
    r = edit(root3, cfg3, "--target", "example.org", "--no-restart")
    f.check(r.rc == 1, "target edit on none/ws is refused (rc=1)", f"rc={r.rc}")
    f.check("--target only applies to Reality modes" in r.text,
            "target refusal explains the mode restriction", r.text.strip()[:200])
    r = edit(root3, cfg3, "--server-names", "a.example.com", "--no-restart")
    f.check(r.rc == 1, "server-names edit on none/ws is refused (rc=1)", f"rc={r.rc}")
    f.check("--server-names only applies to Reality modes" in r.text,
            "server-names refusal explains the mode restriction", r.text.strip()[:200])
    f.check(sha256_file(cfg3) == sha256_bytes(none_bytes),
            "mode-restricted edits write nothing")

    # ---- S11: SNI Guard is a generator surface --------------------------
    def sni_generate(tag, policy, *extra):
        outdir = work / tag
        outdir.mkdir(parents=True, exist_ok=True)
        config_out = outdir / "config.json"
        nginx_out = outdir / "00-xray.conf"
        frags = outdir / "fragments"
        args = [f.go, "xray", "generate", "--json", "--mode", "reality-nginx",
                "--domain", "example.com", "--port", "443",
                "--out", str(config_out),
                "--nginx-out", str(nginx_out), "--fragments-out", str(frags), *extra]
        if policy is not None:
            args.extend(["--unknown-sni-policy", policy])
        return f.run(args), nginx_out, frags

    r, iso_conf, iso_frags = sni_generate("sni-isolate", "isolate")
    iso = f.json_of(r, "generate isolate") if r.rc == 0 else None
    iso_config = work / "sni-isolate" / "config.json"
    f.check(r.rc == 0 and iso_conf.is_file() and iso_config.is_file(),
            "isolate generation rc=0 and wrote config+nginx", r.text[:300])
    conf_text = iso_conf.read_text(encoding="utf-8") if iso_conf.is_file() else ""
    f.check("map $ssl_preread_server_name $sni_upstream" in conf_text,
            "nginx stream block maps the SNI")
    f.check("default deny;" in conf_text, "unknown SNI defaults to the deny upstream")
    f.check("server 127.0.0.1:9403;" in conf_text,
            "isolate deny upstream listens on 9403")
    f.check("listen 443 reuseport" in conf_text, "nginx listens on the operator port")
    f.check("ssl_preread on;" in conf_text, "stream server enables ssl_preread")
    if iso is not None:
        frag_map = iso.get("nginxFragments", {})
        f.check("example.com.serverNames" in frag_map,
                "SNI map fragment is named after the serverName", json.dumps(sorted(frag_map)))
        f.check(frag_map.get("example.com.serverNames") == "example.com reality;\n",
                "SNI map fragment routes the name to Reality",
                repr(frag_map.get("example.com.serverNames")))
        f.check("03-isolate.conf" in frag_map,
                "isolate adds the handshake-reject site", json.dumps(sorted(frag_map)))
        f.check("ssl_reject_handshake on;" in frag_map.get("03-isolate.conf", ""),
                "isolate site rejects unknown handshakes")
        f.check("listen 127.0.0.1:9403 ssl;" in frag_map.get("03-isolate.conf", ""),
                "isolate site owns 9403")
        observed["sniGuard"]["isolate"] = {
            "denyPort": 9403, "fragments": sorted(frag_map),
        }
    r, rej_conf, _ = sni_generate("sni-reject", "reject")
    f.check(r.rc == 0, "reject generation rc=0", r.text[:200])
    f.check((work / "sni-reject" / "config.json").is_file(),
            "reject generation wrote its config")
    rej_text = rej_conf.read_text(encoding="utf-8") if rej_conf.is_file() else ""
    f.check("server 127.0.0.1:9404;" in rej_text,
            "reject switches the deny upstream to 9404")
    f.check("server 127.0.0.1:9403;" not in rej_text,
            "reject does not also claim the isolate port")
    r = f.run([f.go, "xray", "generate", "--json", "--mode", "reality-nginx",
               "--domain", "example.com", "--port", "443",
               "--unknown-sni-policy", "decoy"])
    f.check(r.rc == 2, "decoy generation is refused (rc=2)", f"rc={r.rc}")
    f.check("decoy" in r.text, "decoy refusal explains the missing artifacts",
            r.text.strip()[:250])
    r = f.run([f.go, "xray", "generate", "--json", "--mode", "reality-nginx",
               "--domain", "example.com", "--port", "443",
               "--unknown-sni-policy", "bogus"])
    f.check(r.rc == 2, "unsupported SNI policy is refused (rc=2)", f"rc={r.rc}")
    observed["sniGuard"]["reject"] = {"denyPort": 9404}
    observed["sniGuard"]["decoy"] = "refused: needs pre-existing decoy artifacts"

    # ---- S12: fixed Bash baseline ---------------------------------------
    install_sha = sha256_file(install_sh)
    functions = {}
    missing = []
    for name in BASH_FUNCTIONS:
        body = extract_bash_function(install_text, name)
        functions[name] = body
        f.check(body is not None, f"Bash baseline function {name} exists")
        if body is None:
            missing.append(name)
    pin = functions.get("modify_target_serverNames") or ""
    f.check('"${target}:443"' in pin,
            "Bash pins the Reality target to :443 when editing serverNames")
    f.check(".inbounds[0].streamSettings.realitySettings.serverNames = [$serverName]" in pin,
            "Bash rewrites serverNames to exactly one element")
    picker = functions.get("serverNames_set") or ""
    f.check("请输入单个域名" in picker,
            "Bash serverNames_set documents a single domain")
    f.check("_validate_serverNames_hostname" in picker,
            "Bash validates the serverNames hostname")
    guard = functions.get("sni_guard_policy_choose") or ""
    f.check('unknown_sni_policy="decoy"' in guard,
            "Bash offers a decoy SNI fallback at runtime")
    f.check('unknown_sni_policy="reject"' in guard,
            "Bash offers a direct-reject SNI fallback at runtime")
    f.check("sni_guard_port_conflicts" in install_text,
            "Bash checks the SNI deny port against configured ports")
    conflicts = functions.get("sni_guard_port_conflicts") or ""
    f.check('"${port:-}"' in conflicts and 'return 0' in conflicts,
            "Bash flags a deny port that collides with a configured port")
    f.check(install_text.count("sni_guard_port_conflicts \"${_deny_port}\"") >= 3,
            "Bash consults the collision check before every guard port",
            str(install_text.count("sni_guard_port_conflicts \"${_deny_port}\"")))
    upgrade = functions.get("ensure_reality_sni_guard_defaults") or ""
    f.check("reality_nginx_sni_guard" in upgrade and "unknown_sni_policy" in upgrade,
            "Bash backfills SNI-guard defaults for upgraded installs")
    f.check(functions.get("reset_sni_guard_policy") is not None,
            "Bash has a runtime SNI-guard reset entry point")

    f.write_json("baseline-compare.json", {
        "fixture": "F08",
        "bashInstallSha256": install_sha,
        "functions": {name: body is not None for name, body in functions.items()},
        "comparisons": {
            "target.port": {
                "bash": "modify_target_serverNames always writes \"${target}:443\"",
                "go": "--target preserves an explicit host:port and defaults a bare host to :443",
                "status": "go-more-permissive",
            },
            "serverNames.cardinality": {
                "bash": "serverNames_set accepts exactly one domain and rewrites a one-element array",
                "go": "config edit --server-names accepts a comma-separated list on direct Reality",
                "status": "go-more-permissive",
            },
            "sni-guard.runtime-switch": {
                "bash": "reset_sni_guard_policy + sni_guard_policy_choose switch isolate/decoy/reject at runtime",
                "go": "no config-edit switch; --sni-guard and --unknown-sni-policy are unknown flags (rc=2)",
                "status": "go-gap",
                "mitigation": "regenerate with --mode reality-nginx --unknown-sni-policy isolate|reject",
            },
            "sni-guard.decoy": {
                "bash": "decoy_site_setup writes 03-decoy.conf and an HTTPS fallback site",
                "go": "generation refuses decoy because the artifacts are not produced",
                "status": "go-gap",
            },
            "sni-guard.deny-port-conflict": {
                "bash": "sni_guard_port_conflicts refuses 9403/9404/9444 when it collides with port/xport/gport/xhttpport",
                "go": "balanceDenyPort maps isolate->9403 / reject->9404 without a conflict probe",
                "status": "go-gap",
            },
            "sni-guard.upgrade-defaults": {
                "bash": "ensure_reality_sni_guard_defaults backfills upgraded installs",
                "go": "no in-place upgrade backfill; the generator always emits the policy explicitly",
                "status": "go-gap",
            },
            "edit.port.link": {
                "bash": "after a port change every link is regenerated from the new public port",
                "go": "the edit report and xray share both advertise the edited port (direct Reality)",
                "status": "parity",
            },
        },
        "missingFunctions": missing,
        "observed": observed,
    })

    (f.evidence / "observed.json").write_text(
        json.dumps(observed, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(run_fixture("F08", main))
