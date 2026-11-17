#!/usr/bin/env python3
"""Compare Bash-generated Reality balance artifacts with Go `xray generate`.

Inputs are artifacts captured inside a disposable container:
  --bash-dir      Bash output root (facts.json, runtime/, nginx/, fragments/)
  --go-conf       Xray config written by the Go CLI
  --go-nginx      Nginx stream conf written by the Go CLI (primary only)
  --go-fragments  directory with Go fragment files (primary only)
  --role          primary|secondary
  --out           JSON result path

Status vocabulary:
  MATCH               runtime, stream conf and fragments are equal
  MATCH_CORE_FIELDS   connectivity semantics equal; only non-wiring artifacts
                      (e.g. the Bash-managed main nginx.conf include) differ
  GAP                 at least one connectivity-relevant field differs
  REFUSED             Go refused input that Bash also refuses
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CORE_KEYS = ("tag", "listen", "port", "protocol", "network", "security", "wsPath",
             "grpcServiceName", "xhttpPath", "clients")


def load(path: Path):
    with path.open() as fh:
        return json.load(fh)


def mask_keys(cfg: dict):
    cfg = json.loads(json.dumps(cfg))
    for ib in cfg.get("inbounds") or []:
        rs = (ib.get("streamSettings") or {}).get("realitySettings")
        if isinstance(rs, dict):
            if "privateKey" in rs:
                rs["privateKey"] = "<set>"
            if isinstance(rs.get("settings"), dict) and "privateKey" in rs["settings"]:
                rs["settings"]["privateKey"] = "<set>"
    return cfg


def normalize_tags(cfg: dict):
    cfg = json.loads(json.dumps(cfg))
    for ib in cfg.get("inbounds") or []:
        if isinstance(ib.get("tag"), str):
            ib["tag"] = ib["tag"].lower()
    for ob in cfg.get("outbounds") or []:
        if isinstance(ob.get("tag"), str):
            ob["tag"] = ob["tag"].lower()
    for rule in (cfg.get("routing") or {}).get("rules") or []:
        for key in ("inboundTag", "outboundTag"):
            v = rule.get(key)
            if isinstance(v, str):
                rule[key] = v.lower()
            elif isinstance(v, list):
                rule[key] = [x.lower() if isinstance(x, str) else x for x in v]
    return cfg


def runtime_summary(cfg: dict):
    ib = (cfg.get("inbounds") or [{}])[0]
    ss = ib.get("streamSettings") or {}
    rs = ss.get("realitySettings") or {}
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
        "reality": {
            "target": rs.get("target"),
            "serverNames": rs.get("serverNames"),
            "shortIds": rs.get("shortIds"),
            "minClientVer": rs.get("minClientVer"),
            "flow": ((ib.get("settings") or {}).get("clients") or [{}])[0].get("flow"),
        },
        "topLevelKeys": sorted(cfg.keys()),
        "outbounds": cfg.get("outbounds"),
        "dns": cfg.get("dns"),
        "routing": cfg.get("routing"),
        "log": cfg.get("log"),
    }


def compare_runtime(bash: dict, go: dict):
    bash = normalize_tags(mask_keys(bash))
    go = normalize_tags(mask_keys(go))
    bs, gs = runtime_summary(bash), runtime_summary(go)
    core, cosmetic = [], []
    for key in CORE_KEYS:
        if key == "clients":
            continue
        if bs[key] != gs[key]:
            core.append({"field": f"runtime.{key}", "bash": bs[key], "go": gs[key]})
    bc = [{"id": c.get("id"), "email": c.get("email"), "flow": c.get("flow"), "level": c.get("level")}
          for c in ((bs["inbound"].get("settings") or {}).get("clients") or [])]
    gc = [{"id": c.get("id"), "email": c.get("email"), "flow": c.get("flow"), "level": c.get("level")}
          for c in ((gs["inbound"].get("settings") or {}).get("clients") or [])]
    if bc != gc:
        core.append({"field": "runtime.clients", "bash": bc, "go": gc})
    for key in ("outbounds", "dns", "routing", "log"):
        if bs[key] != gs[key]:
            core.append({"field": f"runtime.{key}", "bash": bs[key], "go": gs[key]})
    if bs["reality"] != gs["reality"]:
        core.append({"field": "runtime.reality", "bash": bs["reality"], "go": gs["reality"]})
    if len(bash.get("inbounds") or []) != len(go.get("inbounds") or []):
        core.append({"field": "runtime.inboundCount",
                     "bash": len(bash.get("inbounds") or []),
                     "go": len(go.get("inbounds") or [])})
    if bs["topLevelKeys"] != gs["topLevelKeys"]:
        cosmetic.append({"field": "runtime.topLevelKeys", "bash": bs["topLevelKeys"],
                         "go": gs["topLevelKeys"]})
    return core, cosmetic


def read_text(path: Path) -> str:
    return path.read_text() if path and path.is_file() else ""


def compare_nginx(bash_dir: Path, go_nginx: Path):
    diffs = []
    bash_conf = read_text(bash_dir / "nginx" / "00-xray.conf")
    go_conf = read_text(go_nginx)
    if bash_conf != go_conf:
        # Point at the first differing line so the report is actionable.
        bl = bash_conf.splitlines()
        gl = go_conf.splitlines()
        first = None
        for i in range(max(len(bl), len(gl))):
            b = bl[i] if i < len(bl) else "<missing>"
            g = gl[i] if i < len(gl) else "<missing>"
            if b != g:
                first = {"line": i + 1, "bash": b, "go": g}
                break
        diffs.append({"field": "nginx.streamConf", "firstDiff": first,
                      "bashSha": _sha(bash_conf), "goSha": _sha(go_conf)})
    return diffs


def _sha(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()


def compare_fragments(bash_dir: Path, go_fragments: Path):
    diffs = []
    bash_frag = bash_dir / "fragments"
    names = set()
    if bash_frag.is_dir():
        names |= {p.name for p in bash_frag.iterdir() if p.is_file()}
    if go_fragments and go_fragments.is_dir():
        names |= {p.name for p in go_fragments.iterdir() if p.is_file()}
    # 03-isolate.conf is an http-block site file; compare it too.
    for name in sorted(names):
        b = read_text(bash_frag / name) if bash_frag.is_dir() else ""
        g = read_text(go_fragments / name) if go_fragments and go_fragments.is_dir() else ""
        if b != g:
            diffs.append({"field": f"fragment.{name}", "bash": b, "go": g})
    return diffs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bash-dir", required=True)
    ap.add_argument("--go-conf", required=True)
    ap.add_argument("--go-nginx", default="")
    ap.add_argument("--go-fragments", default="")
    ap.add_argument("--role", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    bash_dir = Path(a.bash_dir)
    facts = load(bash_dir / "facts.json")
    bash_cfg = load(bash_dir / "runtime" / "config.json")
    go_cfg = load(Path(a.go_conf))
    core, cosmetic = compare_runtime(bash_cfg, go_cfg)

    if a.role == "primary":
        core += compare_nginx(bash_dir, Path(a.go_nginx))
        core += compare_fragments(bash_dir, Path(a.go_fragments) if a.go_fragments else None)
        # The Bash flow also rewrites the managed main nginx.conf (include +
        # server_tokens). Go generate emits artifacts only; wiring is a
        # deployment-step difference, not a stream-semantics difference.
        main_conf = read_text(bash_dir / "nginx" / "nginx.conf")
        if main_conf:
            cosmetic.append({"field": "nginx.mainConfigWiring",
                             "note": "Bash appends include 00-xray.conf and applies "
                                     "server_tokens/user directives; Go generate leaves "
                                     "nginx.conf untouched by design."})
    else:
        if (bash_dir / "nginx" / "00-xray.conf").exists():
            core.append({"field": "nginx.secondary", "bash": "has conf", "go": "none"})

    if facts.get("xrayTestExit") not in (0, None):
        core.append({"field": "bash.xrayTestExit", "bash": facts.get("xrayTestExit"), "go": "n/a"})

    if core:
        status = "GAP"
    elif cosmetic:
        status = "MATCH_CORE_FIELDS"
    else:
        status = "MATCH"

    result = {
        "role": a.role,
        "status": status,
        "bashFacts": facts,
        "coreDifferences": core,
        "cosmeticDifferences": cosmetic,
    }
    Path(a.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"{a.role}: {status}")
    for d in core:
        print(f"  GAP {d['field']}: {d.get('bash')!r} != {d.get('go')!r}")
    for d in cosmetic:
        print(f"  CORE {d['field']}: {d.get('note', '')}")
    # 0=MATCH, 2=MATCH_CORE_FIELDS (acceptable CORE conclusion), 1=GAP.
    if status == "MATCH":
        return 0
    if status == "MATCH_CORE_FIELDS":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
