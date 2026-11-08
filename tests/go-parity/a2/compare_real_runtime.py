#!/usr/bin/env python3
"""Compare REAL Bash-installed Xray runtime configs against Go `xray generate`.

The Bash side is the artifact actually written by the interactive main install
(captured in tests/go-parity/evidence/a2-*), not install_config_* metadata and
not a fixture rebuilt from templates. The Go side is invoked with the same
parameters extracted from that artifact.

Status vocabulary:
  MATCH              every compared field is equal
  MATCH_CORE_FIELDS  connectivity semantics equal, optional/extra fields differ
  GAP                at least one connectivity-relevant field differs
  UNSUPPORTED        Go refuses the captured topology outright
  REFUSED            expected Go refusal of invalid input (negative cases)
  UNCOVERED          no real Bash runtime was captured for this topology
"""
from __future__ import annotations
import argparse, json, os, subprocess, sys, tempfile
from pathlib import Path

CORE_KEYS = ("tag", "listen", "port", "protocol", "network", "security",
             "wsPath", "grpcServiceName", "xhttpPath", "clients")


def load(path: Path):
    with path.open() as fh:
        return json.load(fh)


def runtime_summary(cfg: dict):
    ib = (cfg.get("inbounds") or [{}])[0]
    ss = ib.get("streamSettings") or {}
    reality = None
    if ss.get("security") == "reality":
        rs = ss.get("realitySettings") or {}
        reality = {
            "target": rs.get("target"),
            "serverNames": rs.get("serverNames"),
            "shortIds": rs.get("shortIds"),
            "minClientVer": rs.get("minClientVer"),
            "flow": ((ib.get("settings") or {}).get("clients") or [{}])[0].get("flow"),
        }
    return {
        "inbound": ib,
        "tag": ib.get("tag"),
        "listen": ib.get("listen"),
        "port": ib.get("port"),
        "protocol": (ib.get("protocol") or "").lower(),
        "network": ss.get("network"),
        "security": ss.get("security"),
        "wsPath": (ss.get("wsSettings") or {}).get("path"),
        "grpcServiceName": (ss.get("grpcSettings") or {}).get("serviceName"),
        "xhttpPath": (ss.get("xhttpSettings") or {}).get("path"),
        "tcpSettings": ss.get("tcpSettings"),
        "reality": reality,
        "topLevelKeys": sorted(cfg.keys()),
        "outbounds": cfg.get("outbounds"),
        "dns": cfg.get("dns"),
        "routing": cfg.get("routing"),
        "log": cfg.get("log"),
        "extraStreamKeys": sorted(k for k in ss.keys()
                                 if k not in ("network", "security", "wsSettings",
                                              "grpcSettings", "xhttpSettings", "realitySettings",
                                              "tcpSettings")),
        "streamKeys": sorted(ss.keys()),
    }


def capture_facts(run_dir: Path):
    cfg = load(run_dir / "runtime/config.sanitized.json")
    facts = load(run_dir / "facts.json")
    rt = runtime_summary(cfg)
    ib = rt["inbound"]
    settings = ib.get("settings") or {}
    clients = settings.get("clients") or []
    first = clients[0] if clients else {}
    return {
        "run": facts.get("run"),
        "mode": facts.get("mode"),
        "transport": facts.get("transport"),
        "port": ib.get("port"),
        "listen": ib.get("listen"),
        "tag": ib.get("tag"),
        "protocol": ib.get("protocol"),
        "uuid": first.get("id"),
        "email": first.get("email"),
        "flow": first.get("flow"),
        "path": rt["wsPath"] or rt["xhttpPath"],
        "serviceName": rt["grpcServiceName"],
        "reality": rt["reality"],
        "network": rt["network"],
        "security": rt["security"],
        "raw": cfg,
    }


def go_generate(go_bin: Path, facts: dict, work: Path):
    mode = facts["mode"]
    transport = facts["transport"]
    if transport in ("ws+grpc+xhttp", "ws+xhttp"):
        return None, "Go supports only one transport (got %s)" % transport
    args = [str(go_bin), "xray", "generate",
            "--mode", mode,
            "--transport", transport,
            "--port", str(facts["port"]),
            "--out", str(work / "go.json"),
            "--force", "--json"]
    if facts["listen"]:
        args += ["--listen", facts["listen"]]
    if facts["uuid"]:
        args += ["--uuid", facts["uuid"]]
    if facts["email"]:
        args += ["--email", facts["email"]]
    if facts["flow"]:
        args += ["--flow", facts["flow"]]
    if transport == "grpc" and facts["serviceName"]:
        args += ["--service-name", facts["serviceName"]]
    elif facts["path"]:
        args += ["--path", facts["path"]]
    if mode in ("reality", "reality-nginx") and facts["reality"]:
        r = facts["reality"]
        if r.get("serverNames"):
            args += ["--server-names", ",".join(r["serverNames"])]
        if r.get("target"):
            args += ["--target", r["target"]]
        if r.get("shortIds"):
            args += ["--short-id", r["shortIds"][0]]
    p = subprocess.run(args, text=True, capture_output=True, timeout=60)
    if p.returncode != 0:
        return None, f"go generate exit {p.returncode}: {p.stderr.strip() or p.stdout.strip()}"
    return load(work / "go.json"), None


def mask_keys(cfg: dict):
    cfg = json.loads(json.dumps(cfg))
    for ib in cfg.get("inbounds") or []:
        ss = ib.get("streamSettings") or {}
        rs = ss.get("realitySettings")
        if isinstance(rs, dict):
            if "privateKey" in rs:
                rs["privateKey"] = "<set>"
            if isinstance(rs.get("settings"), dict) and "privateKey" in rs["settings"]:
                rs["settings"]["privateKey"] = "<set>"
    return cfg


def normalize_tags(cfg: dict):
    """Tag names are internal identifiers. Xray only requires self-consistency,
    so compare them case-insensitively and report the casing as a cosmetic diff."""
    cfg = json.loads(json.dumps(cfg))
    for ib in cfg.get("inbounds") or []:
        if isinstance(ib.get("tag"), str):
            ib["tag"] = ib["tag"].lower()
    for ob in cfg.get("outbounds") or []:
        if isinstance(ob.get("tag"), str):
            ob["tag"] = ob["tag"].lower()
    for rule in (cfg.get("routing") or {}).get("rules") or []:
        for key in ("inboundTag", "outboundTag"):
            if isinstance(rule.get(key), str):
                rule[key] = rule[key].lower()
            elif isinstance(rule.get(key), list):
                rule[key] = [x.lower() if isinstance(x, str) else x for x in rule[key]]
    return cfg


def compare(bash: dict, go_cfg: dict):
    bash = mask_keys(bash)
    go_cfg = mask_keys(go_cfg)
    bs = runtime_summary(bash)
    gs = runtime_summary(go_cfg)
    cosmetic = []
    if bs["tag"] != gs["tag"]:
        cosmetic.append({"field": "tagCasing", "bash": bs["tag"], "go": gs["tag"]})
    bash = normalize_tags(bash)
    go_cfg = normalize_tags(go_cfg)
    bs = runtime_summary(bash)
    gs = runtime_summary(go_cfg)
    diffs, core = list(cosmetic), []
    for key in CORE_KEYS:
        if key == "clients":
            continue
        b = bs[key]
        g = gs[key]
        if b != g:
            (core if key in ("listen", "port", "protocol", "network", "security",
                            "wsPath", "grpcServiceName", "xhttpPath") else diffs).append(
                {"field": key, "bash": b, "go": g})
    bc = [{"id": c.get("id"), "email": c.get("email"), "flow": c.get("flow"), "level": c.get("level")}
          for c in ((bs["inbound"].get("settings") or {}).get("clients") or [])]
    gc = [{"id": c.get("id"), "email": c.get("email"), "flow": c.get("flow"), "level": c.get("level")}
          for c in ((gs["inbound"].get("settings") or {}).get("clients") or [])]
    if bc != gc:
        core.append({"field": "clients", "bash": bc, "go": gc})
    for key in ("outbounds", "dns", "routing", "log"):
        if bs[key] != gs[key]:
            core.append({"field": key, "bash": bs[key], "go": gs[key]})
    if bs["reality"] != gs["reality"]:
        core.append({"field": "reality", "bash": bs["reality"], "go": gs["reality"]})
    if bs["tcpSettings"] != gs["tcpSettings"]:
        core.append({"field": "tcpSettings", "bash": bs["tcpSettings"], "go": gs["tcpSettings"]})
    if bs["extraStreamKeys"] != gs["extraStreamKeys"]:
        diffs.append({"field": "extraStreamKeys", "bash": bs["extraStreamKeys"], "go": gs["extraStreamKeys"]})
    if bs["streamKeys"] != gs["streamKeys"]:
        diffs.append({"field": "streamKeys", "bash": bs["streamKeys"], "go": gs["streamKeys"]})
    if bs["topLevelKeys"] != gs["topLevelKeys"]:
        diffs.append({"field": "topLevelKeys", "bash": bs["topLevelKeys"], "go": gs["topLevelKeys"]})
    if core:
        return "GAP", core + diffs
    if diffs:
        return "MATCH_CORE_FIELDS", diffs
    return "MATCH", []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--go-bin", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    evidence = Path(a.evidence)
    go_bin = Path(a.go_bin)
    rows, counts = [], {}
    for run_dir in sorted(p for p in evidence.iterdir() if p.is_dir() and (p / "facts.json").exists()):
        facts = capture_facts(run_dir)
        with tempfile.TemporaryDirectory() as td:
            go_cfg, err = go_generate(go_bin, facts, Path(td))
        if err:
            status = "UNSUPPORTED" if "only one transport" in err else "GAP"
            rows.append({"run": facts["run"], "mode": facts["mode"], "transport": facts["transport"],
                         "status": status, "error": err})
            counts[status] = counts.get(status, 0) + 1
            continue
        status, diffs = compare(facts["raw"], go_cfg)
        rows.append({"run": facts["run"], "mode": facts["mode"], "transport": facts["transport"],
                     "port": facts["port"], "status": status, "differences": diffs})
        counts[status] = counts.get(status, 0) + 1
    result = {"evidence": str(evidence), "goBin": str(go_bin), "counts": counts, "cases": rows}
    Path(a.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(counts, indent=2, sort_keys=True))
    for r in rows:
        print(f"{r['run']}: {r['status']}" + (f" ({r.get('error')})" if r.get("error") else ""))


if __name__ == "__main__":
    sys.exit(main())
