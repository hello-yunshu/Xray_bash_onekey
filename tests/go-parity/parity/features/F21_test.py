#!/usr/bin/env python3
"""F21 traffic blocking: real Go manager, real xray, real Bash baseline.

The fixture must run as root inside a systemd container: it installs a real
Xray service, lets `xray block apply` restart it, and validates the live
configuration with the real `xray -test`. A sandbox root cannot exercise the
restart/probe path, so a missing systemd is UNSUPPORTED_ENVIRONMENT exit 2.

External inputs (both are mounted read-only, never downloaded at runtime):
  * --xray-bin or IDLELEO_XRAY_BIN: real linux Xray binary
  * IDLELEO_GEO_DIR: directory holding real geoip.dat and geosite.dat
"""
import json
import os
import shlex
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture, sha256  # noqa: E402

CONFIG = Path("/etc/idleleo/conf/xray/config.json")
STATE = Path("/etc/idleleo/conf/xray/traffic_blocker.json")
BACKUP_ROOT = Path("/etc/idleleo/backup")
ASSET_DIR = Path("/etc/idleleo/share/xray")
DROPIN = Path("/etc/systemd/system/xray.service.d/50-xray-geodata.conf")
TOKEN = "IDLELEO_ALLOW_SYSTEM_WRITES"
TOKEN_VALUE = "I_ACCEPT_CONTAINER_ONLY"
INBOUND_TAG = "VLESS-ws-in"
SNIFFING = {"enabled": True, "routeOnly": True, "destOverride": ["http", "tls", "quic"]}

OWNED_RULES = [
    {"type": "field", "outboundTag": "blocked", "domain": ["geosite:cn"]},
    {"type": "field", "outboundTag": "blocked", "ip": ["geoip:cn"]},
    {"type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"]},
    {"type": "field", "outboundTag": "blocked", "domain": ["geosite:category-ads-all"]},
    {"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]},
    {"type": "field", "outboundTag": "blocked", "domain": ["domain:example.org"]},
    {"type": "field", "outboundTag": "blocked", "ip": ["192.0.2.0/24"]},
]
USER_RULE = {"type": "field", "domain": ["example.net"], "outboundTag": "direct"}
DIRECT_RULE = {"type": "field", "inboundTag": [INBOUND_TAG], "outboundTag": "direct"}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def file_sha(path):
    return sha256(Path(path))


def main(f):
    f.need_root()
    f.need_systemd()
    for tool in ("bash", "jq", "systemctl"):
        f.need_tool(tool)
    xray = f.xray_bin()
    bash_repo = f.bash_repo
    f.need(bash_repo is not None, "bash repo is required to run the baseline")
    script = bash_repo / "scripts" / "traffic_blocker.sh"
    f.need(script.is_file(), f"bash baseline not found: {script}")

    geo_dir = os.environ.get("IDLELEO_GEO_DIR") or ""
    geo = Path(geo_dir)
    f.need(bool(geo_dir), "IDLELEO_GEO_DIR is not set (needs geoip.dat and geosite.dat)")
    for name in ("geoip.dat", "geosite.dat"):
        f.need((geo / name).is_file(), f"missing {name} under {geo}")

    write_env = dict(f.env)
    write_env[TOKEN] = TOKEN_VALUE

    def go(*args, env=None, timeout=120):
        return f.run([f.go, "--root", "/", *args], env=env or f.env, timeout=timeout)

    def write_go(*args, timeout=180):
        return go(*args, env=write_env, timeout=timeout)

    def active():
        return f.run(["systemctl", "is-active", "xray"], timeout=20).out.strip()

    def reset_rate_limit():
        # systemd's default StartLimitBurst=5 in 10s is hit by a fixture that
        # restarts xray once per scenario (verified: the sixth restart reports
        # start-limit-hit). Each apply is an independent operator action, so
        # the counter is cleared before scenarios that must restart the unit.
        return f.run(["systemctl", "reset-failed", "xray"], timeout=20)

    # ---------------------------------------------------------------- S1 setup
    go("xray", "uninstall", "--purge", "--container", "--json", env=write_env)
    if STATE.exists():
        STATE.unlink()
    if BACKUP_ROOT.exists():
        shutil.rmtree(BACKUP_ROOT)
    if DROPIN.exists():
        DROPIN.unlink()
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("geoip.dat", "geosite.dat"):
        shutil.copyfile(geo / name, ASSET_DIR / name)

    install = write_go(
        "xray", "install", "--binary", str(xray), "--mode", "none",
        "--transport", "ws", "--path", "/f21", "--port", "443",
        "--allow-non-loopback", "--container", "--json",
    )
    ip = f.json_of(install, "install")
    f.check(install.rc == 0 and ip is not None, "S1 install exits 0",
            (install.err or install.out)[:300])
    f.check(ip and ip.get("mode") == "none" and ip.get("transport") == "ws",
            "S1 install reports mode none over ws")
    f.check(ip and ip.get("serviceActive") == "active" and ip.get("serviceEnabled") == "enabled",
            "S1 xray service is active and enabled")
    f.check(ip and ip.get("validatorExit") == 0 and ip.get("warnings") == [],
            "S1 install validator passed without warnings")
    cfg = read_json(CONFIG)
    inbound = cfg["inbounds"][0]
    f.check(inbound["tag"] == INBOUND_TAG and inbound["port"] == 443
            and inbound["protocol"] == "vless"
            and inbound.get("streamSettings", {}).get("network") == "ws",
            "S1 inbound is the VLESS-ws 443 listener")
    f.check([o["tag"] for o in cfg["outbounds"]] == ["direct", "blocked"],
            "S1 outbounds are direct then blocked")
    f.check(cfg["routing"]["domainStrategy"] == "AsIs"
            and cfg["routing"]["rules"] == [DIRECT_RULE],
            "S1 installed routing is the single direct rule")
    install_sha = file_sha(CONFIG)

    # ------------------------------------------------- S2 state and guard paths
    st0 = f.json_of(go("xray", "block", "status", "--json"), "status-initial")
    f.check(st0 and st0["configured"] is False and st0["applied"] is False
            and st0["drift"] is False and st0["ownedRuleCount"] == 0,
            "S2 no state yet: configured/applied/drift are false")

    noyes = go("xray", "block", "apply", "--container", "--json")
    f.check(noyes.rc == 2 and "re-run with --yes" in noyes.text,
            "S2 apply without --yes exits 2", noyes.text[:200])
    f.check(file_sha(CONFIG) == install_sha, "S2 rejected apply left config untouched")

    rootflag = f.run([f.go, "xray", "block", "status", "--root", "/tmp/f21", "--json"])
    f.check(rootflag.rc == 2 and "unknown flag: --root" in rootflag.text,
            "S2 block has no --root (unknown flag)", rootflag.text[:200])

    notoken = go("xray", "block", "ads", "disable", "--container", "--json")
    f.check(notoken.rc == 1
            and "container root writes require IDLELEO_ALLOW_SYSTEM_WRITES" in notoken.text,
            "S2 writing the real root needs the container token", notoken.text[:200])

    ops = [
        ("ads", "enable"),
        ("private-ip", "enable"),
        ("bittorrent", "enable"),
    ]
    for name, action in ops:
        r = write_go("xray", "block", name, action, "--container", "--json")
        f.check(r.rc == 0, f"S2 block {name} {action} exits 0", (r.err or r.out)[:200])
    for args in (
        ("country", "add", "cn"),
        ("custom", "add", "--kind", "domain", "--value", "example.org"),
        ("custom", "add", "--kind", "ip", "--value", "192.0.2.0/24"),
        ("custom", "enable", "--kind", "domain"),
        ("custom", "enable", "--kind", "ip"),
    ):
        r = write_go("xray", "block", *args, "--container", "--json")
        f.check(r.rc == 0, f"S2 block {' '.join(args)} exits 0", (r.err or r.out)[:200])

    st1 = f.json_of(go("xray", "block", "status", "--json"), "status-configured")
    f.check(st1 and st1["configured"] is True and st1["applied"] is False
            and st1["ads"] is True and st1["countries"] == ["cn"],
            "S2 status reflects the new switches")

    dry = write_go("xray", "block", "apply", "--yes", "--dry-run", "--container", "--json")
    dp = f.json_of(dry, "apply-dry-run")
    f.check(dry.rc == 0 and dp is not None and dp["applied"] is False
            and dp["ownedRuleCount"] == 7 and dp["serviceRestarted"] is False,
            "S2 dry-run reports seven rules without applying", str(dp)[:300])
    f.check(file_sha(CONFIG) == install_sha, "S2 dry-run left config untouched")

    for args, needle in (
        (("country", "add", "china"), 'country code "china" must be two letters'),
        (("custom", "add", "--kind", "ip", "--value", "999.1.1.1"),
         'custom IP "999.1.1.1" is not an address or CIDR'),
        (("custom", "add", "--kind", "url", "--value", "x"),
         '--kind must be domain or ip (got "url")'),
    ):
        r = write_go("xray", "block", *args, "--container", "--json")
        f.check(r.rc == 1 and needle in r.text,
                f"S2 rejects invalid input: {' '.join(args)}", r.text[:200])
    f.check(file_sha(CONFIG) == install_sha, "S2 invalid inputs wrote nothing")

    # ------------------------------------------------------------ S3 first apply
    reset_rate_limit()
    apply1 = write_go("xray", "block", "apply", "--yes", "--container", "--json")
    a1 = f.json_of(apply1, "apply-first")
    f.check(apply1.rc == 0 and a1 is not None and a1["applied"] is True,
            "S3 first apply exits 0", (apply1.err or "")[:300])
    f.check(a1 and a1["ownedRuleCount"] == 7
            and a1["domainStrategy"] == "IPIfNonMatch"
            and a1["sniffingEnabled"] is True,
            "S3 apply reports rules, strategy and sniffing")
    f.check(a1 and a1["serviceRestarted"] is True
            and str(a1.get("controlProbe", "")).startswith("ok: tcp control on 127.0.0.1:443"),
            "S3 apply restarted xray and the TCP probe passed", str(a1)[:300])
    f.check(a1 and a1.get("assetEnv") ==
            "created etc/systemd/system/xray.service.d/50-xray-geodata.conf",
            "S3 apply created the geodata drop-in", str(a1.get("assetEnv")))
    f.check(a1 and a1["oldSha256"] == install_sha
            and a1["newSha256"] == file_sha(CONFIG),
            "S3 apply reports the real before/after digests")

    cfg = read_json(CONFIG)
    f.check(cfg["routing"]["rules"] == OWNED_RULES + [DIRECT_RULE],
            "S3 routing rules match the ordered blocking set",
            json.dumps(cfg["routing"]["rules"])[:500])
    f.check(cfg["routing"]["domainStrategy"] == "IPIfNonMatch",
            "S3 domainStrategy is IPIfNonMatch")
    f.check(all(i.get("sniffing") == SNIFFING for i in cfg["inbounds"]),
            "S3 every inbound sniffs with routeOnly",
            json.dumps([i.get("sniffing") for i in cfg["inbounds"]])[:300])

    f.check(DROPIN.is_file(), "S3 geodata drop-in exists")
    if DROPIN.is_file():
        lines = [l.strip() for l in DROPIN.read_text().splitlines() if l.strip()]
        f.check(lines == ["[Service]", "Environment=XRAY_LOCATION_ASSET=/etc/idleleo/share/xray"],
                "S3 drop-in points Xray at the geo assets", str(lines))
    show = f.run(["systemctl", "show", "-p", "Environment", "xray"], timeout=20)
    f.check("XRAY_LOCATION_ASSET=/etc/idleleo/share/xray" in show.out,
            "S3 systemd exposes XRAY_LOCATION_ASSET to the service", show.out[:200])

    backup = Path(a1["backupDir"]) if a1 and a1.get("backupDir") else None
    f.check(backup is not None and backup.is_dir(), "S3 apply created a backup directory")
    if backup and backup.is_dir():
        names = sorted(p.name for p in backup.iterdir())
        f.check(names == ["config.json", "meta", "traffic_blocker.json"],
                "S3 backup holds config, state and meta", str(names))
        meta = (backup / "meta").read_text() if (backup / "meta").is_file() else ""
        f.check(meta.startswith("config="), "S3 backup meta records the config path", meta[:120])

    test_env = dict(f.env)
    test_env["XRAY_LOCATION_ASSET"] = str(ASSET_DIR)
    live_test = f.run([xray, "-test", "-config", str(CONFIG)], env=test_env, timeout=60)
    f.check(live_test.rc == 0 and "Configuration OK" in live_test.text,
            "S3 real xray -test accepts the applied config", live_test.text[:300])
    f.check(active() == "active", "S3 xray is still active after apply")

    # ------------------------------------------------------ S4 idempotency/status
    sha_before = file_sha(CONFIG)
    apply2 = write_go("xray", "block", "apply", "--yes", "--container", "--json")
    a2 = f.json_of(apply2, "apply-second")
    f.check(apply2.rc == 0 and a2 is not None and a2["applied"] is True,
            "S4 second apply exits 0")
    f.check(a2 and a2["oldSha256"] == a2["newSha256"] == sha_before,
            "S4 second apply is a no-op with equal digests", str(a2)[:300])
    f.check(file_sha(CONFIG) == sha_before, "S4 second apply did not rewrite the config")
    f.check(a2 and a2.get("assetEnv") == "reused existing XRAY_LOCATION_ASSET",
            "S4 second apply reuses the geodata drop-in", str(a2.get("assetEnv")))

    st2 = f.json_of(go("xray", "block", "status", "--json"), "status-applied")
    f.check(st2 and st2["configured"] is True and st2["applied"] is True
            and st2["drift"] is False,
            "S4 status reports applied without drift")
    f.check(st2 and st2["ads"] is True and st2["privateIp"] is True
            and st2["bittorrent"] is True and st2["countries"] == ["cn"],
            "S4 status lists the enabled switches")
    f.check(st2 and st2["customDomains"] == {"enabled": True, "items": ["example.org"]}
            and st2["customIps"] == {"enabled": True, "items": ["192.0.2.0/24"]},
            "S4 status lists the custom domain/IP lists")
    f.check(st2 and st2["ownedRuleCount"] == 7
            and st2["geosite"]["path"].endswith("/geosite.dat")
            and st2["geoip"]["path"].endswith("/geoip.dat")
            and st2["geosite"]["size"] > 0 and st2["geoip"]["size"] > 0,
            "S4 status reports rule count and geo assets", str(st2)[:400])

    # ---------------------------------------------------------------- S5 block off
    reset_rate_limit()
    off = write_go("xray", "block", "off", "--yes", "--container", "--json")
    o = f.json_of(off, "block-off")
    f.check(off.rc == 0 and o is not None and o["applied"] is False
            and o["ownedRuleCount"] == 0,
            "S5 off exits 0 and removes the owned rules", (off.err or "")[:300])
    f.check(o and o["newSha256"] == install_sha,
            "S5 off restores the exact install-time config digest", str(o.get("newSha256")))
    f.check(o and o["domainStrategy"] == "AsIs" and o["sniffingEnabled"] is False,
            "S5 off restores AsIs and clears sniffing")
    f.check(o and str(o.get("controlProbe", "")).startswith("not probed"),
            "S5 off does not probe the service", str(o.get("controlProbe")))
    cfg = read_json(CONFIG)
    f.check(cfg["routing"]["rules"] == [DIRECT_RULE]
            and cfg["routing"]["domainStrategy"] == "AsIs"
            and all(i.get("sniffing") is None for i in cfg["inbounds"]),
            "S5 config is back to the installed baseline")
    f.check(active() == "active", "S5 xray is active after off")
    st3 = f.json_of(go("xray", "block", "status", "--json"), "status-off")
    f.check(st3 and st3["applied"] is False and st3["ownedRuleCount"] == 0
            and st3["ads"] is True and st3["countries"] == ["cn"],
            "S5 switches survive off while applied turns false")
    sha_off = file_sha(CONFIG)
    off2 = write_go("xray", "block", "off", "--yes", "--container", "--json")
    f.check(off2.rc == 1 and "no traffic-block rules are installed" in off2.text,
            "S5 a second off reports there is nothing to remove", off2.text[:200])
    f.check(file_sha(CONFIG) == sha_off, "S5 rejected second off left the config untouched")
    st4 = f.json_of(go("xray", "block", "status", "--json"), "status-second-off")
    f.check(st4 and st4["configured"] is True and st4["ads"] is True
            and st4["countries"] == ["cn"],
            "S5 rejected second off kept the configured switches")

    # ------------------------------------------------------ S6 failures and rollback
    sha_fail = file_sha(CONFIG)
    write_go("xray", "block", "country", "add", "zz", "--container", "--json")
    reset_rate_limit()
    zz = write_go("xray", "block", "apply", "--yes", "--container", "--json")
    zp = f.json_of(zz, "apply-unknown-country")
    f.check(zz.rc == 1 and "xray -test rejected the candidate" in zz.text
            and "traffic blocking was not applied" in zz.text,
            "S6 xray -test rejects an unknown country", zz.text[:300])
    f.check(zp is not None and zp["applied"] is False and zp["ownedRuleCount"] == 9,
            "S6 failed apply reports the nine candidate rules", str(zp)[:300])
    f.check(file_sha(CONFIG) == sha_fail, "S6 failed apply left the config untouched")
    f.check(active() == "active", "S6 xray stays active after the rejected candidate")
    write_go("xray", "block", "country", "remove", "zz", "--container", "--json")

    saved = CONFIG.read_bytes()
    cfg = read_json(CONFIG)
    cfg["routing"]["rules"].append({"type": "field", "outboundTag": "blocked"})
    CONFIG.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    ub_sha = file_sha(CONFIG)
    ub = write_go("xray", "block", "apply", "--yes", "--container", "--json")
    f.check(ub.rc == 1 and "the last user routing rule blocks everything" in ub.text,
            "S6 apply refuses a user rule that swallows all traffic", ub.text[:300])
    f.check(file_sha(CONFIG) == ub_sha, "S6 refused apply left the user config untouched")
    CONFIG.write_bytes(saved)

    keep = Path(tempfile.mkdtemp(prefix="f21-geo-")) / "geosite.dat"
    shutil.move(str(ASSET_DIR / "geosite.dat"), str(keep))
    try:
        ng = write_go("xray", "block", "apply", "--yes",
                      "--geodata-url", "http://127.0.0.1:1", "--container", "--json")
    finally:
        shutil.move(str(keep), str(ASSET_DIR / "geosite.dat"))
    f.check(ng.rc == 1 and "GeoData files geosite.dat are missing" in ng.text
            and "traffic blocking was not applied" in ng.text,
            "S6 missing geosite fails closed", ng.text[:300])
    f.check(file_sha(CONFIG) == sha_fail, "S6 missing geosite left the config untouched")
    f.check(active() == "active", "S6 xray stays active after the geodata failure")

    # ------------------------------------------------------------ S7 Bash baseline
    tb = Path(tempfile.mkdtemp(prefix="f21-bash-"))
    bash_state = {"country_block": ["cn"], "ads": True, "bittorrent": True, "private_ip": True}
    (tb / "traffic_blocker.json").write_text(json.dumps(bash_state) + "\n", encoding="utf-8")
    command = (
        f"xray_conf_dir={shlex.quote(str(tb))}; idleleo_dir={shlex.quote(str(tb))}; "
        f"source {shlex.quote(str(script))}; tb_build_block_rules"
    )
    br = f.run(["bash", "-c", command], timeout=60)
    bash_rules = None
    try:
        bash_rules = json.loads(br.out)
    except (ValueError, TypeError):
        bash_rules = None
    f.check(br.rc == 0 and isinstance(bash_rules, list) and len(bash_rules) == 5,
            "S7 Bash baseline builds five built-in rules", br.text[:300])
    f.check(bash_rules is not None and bash_rules == OWNED_RULES[:5],
            "S7 Bash and Go built-in rules are semantically identical",
            json.dumps(bash_rules)[:400])

    reset_rate_limit()
    reapply = write_go("xray", "block", "apply", "--yes", "--container", "--json")
    f.check(reapply.rc == 0, "S7 re-apply for legacy comparison exits 0", (reapply.err or "")[:200])
    go_rules = read_json(CONFIG)["routing"]["rules"]
    f.check(go_rules[:5] == (bash_rules or []),
            "S7 applied Go rules start with the Bash baseline",
            json.dumps(go_rules[:5])[:400])

    state_doc = read_json(STATE)
    state_doc.pop("owned_rules", None)
    STATE.write_text(json.dumps(state_doc) + "\n", encoding="utf-8")
    cfg = read_json(CONFIG)
    cfg["routing"]["rules"] = (bash_rules or []) + [USER_RULE, DIRECT_RULE]
    CONFIG.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    reset_rate_limit()
    leg = write_go("xray", "block", "apply", "--yes", "--container", "--json")
    lp = f.json_of(leg, "apply-legacy")
    f.check(leg.rc == 0 and lp is not None and lp["applied"] is True,
            "S7 apply adopts rules left by the Bash baseline", (leg.err or "")[:300])
    leg_rules = read_json(CONFIG)["routing"]["rules"]
    f.check(leg_rules == OWNED_RULES + [USER_RULE, DIRECT_RULE],
            "S7 legacy adoption does not duplicate rules and keeps user rules",
            json.dumps(leg_rules)[:500])
    f.check(lp is not None and lp["ownedRuleCount"] == 7,
            "S7 legacy adoption owns exactly seven rules")
    f.check(sum(1 for r in leg_rules if r.get("domain") == ["geosite:cn"]) == 1,
            "S7 first Go apply over Bash rules keeps a single country rule")

    # ------------------------------------------------------------------ S8 evidence
    observed = {
        "install": {
            "mode": ip.get("mode") if ip else None,
            "transport": ip.get("transport") if ip else None,
            "serviceActive": ip.get("serviceActive") if ip else None,
            "serviceEnabled": ip.get("serviceEnabled") if ip else None,
            "validatorExit": ip.get("validatorExit") if ip else None,
            "configSha256": install_sha,
        },
        "statusInitial": st0,
        "apply": {
            "applied": a1.get("applied") if a1 else None,
            "ownedRuleCount": a1.get("ownedRuleCount") if a1 else None,
            "domainStrategy": a1.get("domainStrategy") if a1 else None,
            "sniffingEnabled": a1.get("sniffingEnabled") if a1 else None,
            "serviceRestarted": a1.get("serviceRestarted") if a1 else None,
            "controlProbe": a1.get("controlProbe") if a1 else None,
            "assetEnv": a1.get("assetEnv") if a1 else None,
            "oldSha256": a1.get("oldSha256") if a1 else None,
            "newSha256": a1.get("newSha256") if a1 else None,
            "rules": OWNED_RULES + [DIRECT_RULE],
            "sniffing": [i.get("sniffing") for i in cfg.get("inbounds", [])],
        },
        "applySecond": a2,
        "statusApplied": st2,
        "off": {
            "applied": o.get("applied") if o else None,
            "ownedRuleCount": o.get("ownedRuleCount") if o else None,
            "domainStrategy": o.get("domainStrategy") if o else None,
            "sniffingEnabled": o.get("sniffingEnabled") if o else None,
            "serviceRestarted": o.get("serviceRestarted") if o else None,
            "controlProbe": o.get("controlProbe") if o else None,
            "newSha256": o.get("newSha256") if o else None,
        },
        "failures": {
            "unknownCountry": {"rc": zz.rc, "ownedRuleCount": zp.get("ownedRuleCount") if zp else None},
            "userSwallowAll": {"rc": ub.rc},
            "missingGeosite": {"rc": ng.rc},
        },
        "bash": {"state": bash_state, "rules": bash_rules, "rc": br.rc},
        "legacyRules": leg_rules,
        "geo": {
            "geoip": {"sha256": file_sha(ASSET_DIR / "geoip.dat"),
                      "size": (ASSET_DIR / "geoip.dat").stat().st_size},
            "geosite": {"sha256": file_sha(ASSET_DIR / "geosite.dat"),
                        "size": (ASSET_DIR / "geosite.dat").stat().st_size},
        },
    }
    observed["apply"]["sniffing"] = [i.get("sniffing") for i in read_json(CONFIG)["inbounds"]]
    f.write_json("observed.json", observed)
    f.write_json("bash-result.json", {
        "state": bash_state,
        "rc": br.rc,
        "rules": bash_rules,
        "stderr": br.err.strip()[:2000],
    })

    entries = []
    for index, rule in enumerate(bash_rules or []):
        entries.append({
            "item": f"builtin-rule-{index + 1}",
            "status": "aligned" if index < len(OWNED_RULES) and OWNED_RULES[index] == rule
                      else "divergent",
            "detail": json.dumps(rule, sort_keys=True),
        })
    entries += [
        {"item": "custom-domain-rule", "status": "approved-difference",
         "detail": "Bash has no custom domain list; Go aggregates them into one rule"},
        {"item": "custom-ip-rule", "status": "approved-difference",
         "detail": "Bash has no custom IP list; Go aggregates them into one rule"},
        {"item": "domain-strategy-and-sniffing", "status": "approved-difference",
         "detail": "Go apply sets IPIfNonMatch and sniffing routeOnly; not part of tb_build_block_rules"},
        {"item": "state-owned-rules", "status": "approved-difference",
         "detail": "Go records owned_rules/previous_*; Bash keeps unknown keys"},
        {"item": "json-cli", "status": "approved-difference",
         "detail": "Go adds --json/--yes/--dry-run reports"},
        {"item": "mode-none-non443-probe", "status": "gap",
         "detail": "PublicPort=0 probes 127.0.0.1:443; a non-443 mode-none install fails apply"},
        {"item": "preset-countries", "status": "gap",
         "detail": "pinned geosite only carries cn; ru/ir/kp/gb/au/tr are rejected by xray -test"},
        {"item": "bash-interactive-apply", "status": "gap",
         "detail": "only the pure rule builder ran; menus, downloader and tb_apply_rules were not compared"},
        {"item": "uninstall-residue", "status": "gap",
         "detail": "xray uninstall --purge keeps traffic_blocker.json and block backups"},
        {"item": "client-data-plane", "status": "gap",
         "detail": "probe is a local TCP connect; blocked requests were not replayed"},
        {"item": "second-off", "status": "approved-difference",
         "detail": "with nothing applied Go exits 1 ('no traffic-block rules are installed') and keeps the config; Bash has no equivalent command"},
    ]
    f.write_json("baseline-compare.json", {"entries": entries, "notes": [
        "The fixture runs `systemctl reset-failed xray` before scenarios that restart the unit: "
        "in this disposable container the default StartLimitBurst=5/10s rejects the sixth restart "
        "with start-limit-hit, which is a systemd rate limit rather than a traffic-block behaviour.",
        "Each scenario is an independent operator action in production, so the rate-limit counter "
        "is cleared instead of stretching the fixture past the gate budget.",
    ]})

    work = f.evidence / "f21-work"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    if STATE.is_file():
        shutil.copyfile(STATE, work / "state-applied.json")
    (work / "rules-applied.json").write_text(
        json.dumps(read_json(CONFIG)["routing"]["rules"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    (work / "bash-state.json").write_text(
        json.dumps(bash_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (work / "dropin.txt").write_text(
        DROPIN.read_text() if DROPIN.is_file() else "<missing>", encoding="utf-8")
    (work / "backup-files.txt").write_text(
        "\n".join(sorted(p.name for p in backup.iterdir())) + "\n"
        if backup and backup.is_dir() else "<missing>\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(run_fixture("F21", main))
