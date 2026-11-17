#!/usr/bin/env python3
"""Field-by-field comparison of a real Bash A2 runtime against Go generation.

Two contracts are checked for every captured topology:

* ``fresh``    - Go generates a new installation from the same inputs. Ports,
                 paths and service names of *added* multi-entry inbounds may
                 differ by design, but every such difference is listed as an
                 approved new-install difference and is never reported as MATCH.
* ``preserve`` - Go ``xray generate --from-config`` must adopt the captured
                 Bash runtime without changing any value. This is the contract
                 that matters for migrating an existing installation.

The comparator matches inbounds by tag (not by position), compares every
connection parameter, clients, routing references and top-level sections, and
exits non-zero for any unapproved gap. Redacted identifiers/keys are reported
as ``UNCOVERED``; they are never silently replaced and never counted as MATCH.

``--self-test`` mutates a synthetic pair and asserts that each mutation is
detected, including the exit-code contract.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FIXED_UUID = "11111111-1111-4111-8111-111111111111"
FIXED_KEY = base64.urlsafe_b64encode(bytes([7] * 32)).rstrip(b"=").decode()
REDACTED_IDS = {"<redacted-uuid>", "REDACTED", "<set>", ""}
REDACTED_KEYS = {"REDACTED", "<set>", ""}

FAIL_STATUSES = {"GAP", "UNSUPPORTED", "FAIL"}
COUNTS = ["MATCH", "MATCH_CORE_FIELDS", "MATCH_STRUCTURE_UNCOVERED", "GAP", "UNSUPPORTED", "FAIL"]


def norm_tag(tag):
    return (tag or "").strip().lower()


def is_redacted_uuid(value):
    return value is None or value in REDACTED_IDS


def is_redacted_key(value):
    return value is None or value in REDACTED_KEYS


def inbound_view(ib):
    ss = ib.get("streamSettings") or {}
    settings = ib.get("settings") or {}
    rs = ss.get("realitySettings") or {}
    nested = (rs.get("settings") or {})
    ws = ss.get("wsSettings") or {}
    grpc = ss.get("grpcSettings") or {}
    xhttp = ss.get("xhttpSettings") or {}
    clients = []
    for client in settings.get("clients") or []:
        clients.append({
            "id": client.get("id"),
            "email": client.get("email"),
            "flow": client.get("flow"),
            "level": client.get("level"),
            "extra": sorted(k for k in client if k not in {"id", "email", "flow", "level"}),
        })
    clients.sort(key=lambda c: (str(c["email"]), str(c["id"]), str(c["flow"]), str(c["level"])))
    return {
        "tag": norm_tag(ib.get("tag")),
        "listen": ib.get("listen"),
        "port": ib.get("port"),
        "protocol": (ib.get("protocol") or "").lower(),
        "network": (ss.get("network") or "").lower(),
        "security": (ss.get("security") or "").lower(),
        "wsPath": ws.get("path"),
        "wsHost": ws.get("host"),
        "grpcServiceName": grpc.get("serviceName"),
        "grpcMultiMode": grpc.get("multiMode"),
        "grpcIdleTimeout": grpc.get("idle_timeout"),
        "xhttpPath": xhttp.get("path"),
        "xhttpMode": xhttp.get("mode"),
        "realityTarget": rs.get("target"),
        "realityServerNames": sorted(rs.get("serverNames") or []),
        "realityShortIds": sorted(rs.get("shortIds") or []),
        "realityMinClientVer": rs.get("minClientVer"),
        "realityMaxClientVer": rs.get("maxClientVer"),
        "realityPublicKey": rs.get("publicKey"),
        "realityFingerprint": rs.get("fingerprint"),
        "realitySpiderX": rs.get("spiderX"),
        "realityHasPrivateKey": bool(rs.get("privateKey") or nested.get("privateKey")),
        "realityPrivateKeyRaw": rs.get("privateKey") or nested.get("privateKey"),
        "clients": clients,
        "decryption": settings.get("decryption"),
        "clientExtraKeys": sorted(k for k in settings if k not in {"clients", "decryption"}),
        "streamExtraKeys": sorted(k for k in ss if k not in {
            "network", "security", "wsSettings", "grpcSettings", "xhttpSettings", "realitySettings"}),
    }


def index_inbounds(cfg):
    """Return (dict tag->view, duplicate tags, extra/duplicate info)."""
    views = {}
    duplicates = []
    for ib in cfg.get("inbounds") or []:
        tag = norm_tag(ib.get("tag"))
        if not tag:
            duplicates.append("<missing-tag>")
            continue
        if tag in views:
            duplicates.append(tag)
            continue
        views[tag] = inbound_view(ib)
    return views, duplicates


def field_diffs(bash, go, *, contract, bash_index, primary_tag):
    """Return (diffs, uncovered, approved). Each diff is a dict."""
    diffs, uncovered, approved = [], [], []
    fields = [
        "listen", "port", "protocol", "network", "security", "wsPath", "wsHost",
        "grpcServiceName", "grpcMultiMode", "grpcIdleTimeout", "xhttpPath", "xhttpMode",
        "realityTarget", "realityServerNames", "realityShortIds", "realityMinClientVer",
        "realityMaxClientVer", "realityFingerprint", "realitySpiderX", "decryption",
        "clientExtraKeys", "streamExtraKeys",
    ]
    for field in fields:
        b, g = bash.get(field), go.get(field)
        if b == g:
            continue
        # Fresh installs use deterministic ports/paths/service names for the
        # added multi-entry inbounds. Those are approved *only* outside the
        # primary inbound and never in the preserve contract.
        is_extra = bash_index > 0
        if contract == "fresh" and is_extra and field in {
                "port", "wsPath", "grpcServiceName", "xhttpPath"}:
            approved.append({"field": f"{bash['tag']}.{field}", "bash": b, "go": g,
                             "reason": "deterministic multi-entry value (new install)"})
            continue
        diffs.append({"field": f"{bash['tag']}.{field}", "bash": b, "go": g})

    # Reality private key is never printed. Compare presence only when this
    # inbound actually uses Reality; Bash templates carry an empty leftover
    # realitySettings block on none/TLS inbounds and that is cosmetic.
    if (bash.get("security") == "reality" or go.get("security") == "reality") and \
            bash.get("realityHasPrivateKey") != go.get("realityHasPrivateKey"):
        diffs.append({"field": f"{bash['tag']}.realityPrivateKeyPresence",
                      "bash": bash.get("realityHasPrivateKey"), "go": go.get("realityHasPrivateKey")})

    # Clients: compare as a multiset; a redacted id is UNCOVERED, not equal.
    b_clients, g_clients = bash.get("clients") or [], go.get("clients") or []
    if len(b_clients) != len(g_clients):
        diffs.append({"field": f"{bash['tag']}.clients.count", "bash": len(b_clients), "go": len(g_clients)})
    else:
        for i, (bc, gc) in enumerate(zip(b_clients, g_clients)):
            for key in ("email", "flow", "level"):
                if bc.get(key) != gc.get(key):
                    if contract == "fresh" and bash_index > 0 and key == "email":
                        approved.append({"field": f"{bash['tag']}.clients[{i}].email",
                                         "bash": bc.get(key), "go": gc.get(key),
                                         "reason": "added inbound label (new install)"})
                        continue
                    diffs.append({"field": f"{bash['tag']}.clients[{i}].{key}",
                                  "bash": bc.get(key), "go": gc.get(key)})
            bid = bc.get("id")
            if is_redacted_uuid(bid):
                uncovered.append({"field": f"{bash['tag']}.clients[{i}].id", "reason": "redacted in evidence"})
            elif bid != gc.get("id"):
                diffs.append({"field": f"{bash['tag']}.clients[{i}].id", "bash": "<uuid>", "go": "<uuid>"})
    # Private Reality material is redacted in committed evidence.
    if contract == "fresh" and bash.get("security") == "reality" and is_redacted_key(
            (bash.get("realityPrivateKeyRaw"))):
        uncovered.append({"field": f"{bash['tag']}.realityPrivateKey", "reason": "redacted in evidence"})
    return diffs, uncovered, approved


def compare_section(name, bash, go):
    return [] if bash == go else [{"field": name, "bash": bash, "go": go}]


def compare(bash_cfg, go_cfg, *, contract):
    """Return a result dict for one topology/contract."""
    diffs, uncovered, approved = [], [], []
    b_views, b_dups = index_inbounds(bash_cfg)
    g_views, g_dups = index_inbounds(go_cfg)
    for tag in b_dups:
        diffs.append({"field": f"bash.duplicateTag:{tag}", "bash": "duplicate", "go": None})
    for tag in g_dups:
        diffs.append({"field": f"go.duplicateTag:{tag}", "bash": None, "go": "duplicate"})
    b_tags, g_tags = set(b_views), set(g_views)
    for tag in sorted(b_tags - g_tags):
        diffs.append({"field": f"inbound.{tag}", "bash": "present", "go": "missing"})
    for tag in sorted(g_tags - b_tags):
        diffs.append({"field": f"inbound.{tag}", "bash": "missing", "go": "present"})
    bash_index = {tag: i for i, tag in enumerate(b_views)}
    for tag in sorted(b_tags & g_tags):
        d, u, a = field_diffs(b_views[tag], g_views[tag], contract=contract,
                              bash_index=bash_index[tag], primary_tag=tag)
        diffs.extend(d)
        uncovered.extend(u)
        approved.extend(a)
        raw_bash = next((ib for ib in bash_cfg.get("inbounds") or []
                         if norm_tag(ib.get("tag")) == tag), {})
        raw_ss = raw_bash.get("streamSettings") or {}
        if contract == "fresh" and raw_ss.get("security") == "reality" and is_redacted_key(
                (raw_ss.get("realitySettings") or {}).get("privateKey")):
            uncovered.append({"field": f"{tag}.realityPrivateKey", "reason": "redacted in evidence"})

    # Routing must reference the exact inbound tags that exist.
    known = {tag for tag in b_tags}
    for cfg, side in ((bash_cfg, "bash"), (go_cfg, "go")):
        routing = cfg.get("routing") or {}
        for rule in routing.get("rules") or []:
            for ref in rule.get("inboundTag") or []:
                if norm_tag(ref) not in known and norm_tag(ref) not in g_tags:
                    diffs.append({"field": f"{side}.routing.inboundTag", "bash": ref, "go": "unknown inbound"})

    for section in ("log", "outbounds", "dns", "routing", "policy", "stats"):
        diffs.extend(compare_section(section, bash_cfg.get(section), go_cfg.get(section)))
    bash_only = sorted(set(bash_cfg) - set(go_cfg))
    go_only = sorted(set(go_cfg) - set(bash_cfg))
    for key in bash_only:
        approved.append({"field": f"topLevel.{key}", "bash": "present", "go": "absent",
                         "reason": "Bash template leftover not read by Xray"})
    for key in go_only:
        diffs.append({"field": f"topLevel.{key}", "bash": "absent", "go": "present"})

    result = {
        "contract": contract,
        "status": "MATCH",
        "diffs": diffs,
        "uncovered": uncovered,
        "approvedNewInstallDiff": approved,
    }
    finalize_status(result)
    return result


def finalize_status(result):
    seen = set()
    deduped = []
    for item in result["uncovered"]:
        key = (item["field"], item["reason"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    result["uncovered"] = deduped
    if result["diffs"]:
        result["status"] = "GAP"
    elif result["approvedNewInstallDiff"]:
        result["status"] = "MATCH_CORE_FIELDS"
    elif result["uncovered"]:
        result["status"] = "MATCH_STRUCTURE_UNCOVERED"
    else:
        result["status"] = "MATCH"


def sha256_text(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def identity_check(run_dir, go_info, result, *, verify_uuid=True, verify_key=True, verify_short=True):
    """Compare only fingerprints, never secrets. A fingerprint is compared only
    when the Bash run captured that value in cleartext and the Go run was given
    the same input; a redacted input can never be confirmed and stays UNCOVERED.
    Covered identity removes the matching UNCOVERED marker; a mismatch between
    two known inputs is a hard GAP."""
    path = run_dir / "runtime/identity.json"
    if not path.exists():
        return
    identity = json.loads(path.read_text())
    covered_uuid = covered_key = covered_short = False
    for row in identity.get("inbounds") or []:
        tag = norm_tag(row.get("tag"))
        want_uuid = row.get("uuidSha256") or []
        if verify_uuid and want_uuid and go_info.get("uuid"):
            if sha256_text(go_info["uuid"]) not in want_uuid:
                result["diffs"].append({"field": f"identity.{tag}.uuid",
                                        "bash": "fingerprint", "go": "fingerprint mismatch"})
            else:
                covered_uuid = True
        want_key = row.get("realityPublicKeySha256")
        if verify_key and want_key and go_info.get("publicKey"):
            if sha256_text(go_info["publicKey"]) != want_key:
                result["diffs"].append({"field": f"identity.{tag}.realityPublicKey",
                                        "bash": "fingerprint", "go": "fingerprint mismatch"})
            else:
                covered_key = True
        want_short = row.get("shortIdsSha256") or []
        if verify_short and want_short and go_info.get("shortId"):
            if sha256_text(go_info["shortId"]) not in want_short:
                result["diffs"].append({"field": f"identity.{tag}.shortId",
                                        "bash": "fingerprint", "go": "fingerprint mismatch"})
            else:
                covered_short = True
    if covered_uuid:
        result["uncovered"] = [u for u in result["uncovered"] if not u["field"].endswith(".id")]
    if covered_key:
        result["uncovered"] = [u for u in result["uncovered"] if "realityPrivateKey" not in u["field"]]
    if covered_short:
        result["uncovered"] = [u for u in result["uncovered"] if "shortId" not in u["field"]]
    finalize_status(result)


def identity_inputs(cfg):
    """Which identity inputs a fresh Go generation was given explicitly."""
    ib = first_bash_inbound(cfg)
    ss = ib.get("streamSettings") or {}
    rs = ss.get("realitySettings") or {}
    client = ((ib.get("settings") or {}).get("clients") or [{}])[0]
    reality = ss.get("security") == "reality"
    return {
        "verify_uuid": not is_redacted_uuid(client.get("id")),
        "verify_key": reality and not is_redacted_key(rs.get("privateKey")),
        "verify_short": reality and bool([s for s in (rs.get("shortIds") or [])
                                          if s not in REDACTED_IDS]),
    }


def restore_placeholders(raw):
    """Return a Go-adoptable copy plus whether a redacted identity was restored.

    A redacted UUID or a redacted Reality private key means the adopted config
    carries a placeholder, so no identity value can be confirmed afterwards. A
    leftover empty realitySettings block on a none/TLS inbound is cosmetic and
    does not make the run UNCOVERED.
    """
    text = raw.decode("utf-8")
    redacted_identity = "<redacted-uuid>" in text
    try:
        cfg = json.loads(text)
    except ValueError:
        cfg = {}
    for ib in cfg.get("inbounds") or []:
        ss = ib.get("streamSettings") or {}
        if ss.get("security") == "reality":
            if ((ss.get("realitySettings") or {}).get("privateKey")) in REDACTED_KEYS:
                redacted_identity = True
    if "<redacted-uuid>" in text:
        text = text.replace("<redacted-uuid>", FIXED_UUID)
    if '"REDACTED"' in text:
        text = text.replace('"REDACTED"', json.dumps(FIXED_KEY))
    return text.encode("utf-8"), redacted_identity


def load_config(run_dir):
    for name in ("runtime/config.json", "runtime/config.sanitized.json"):
        path = run_dir / name
        if path.exists():
            return path, json.loads(path.read_text())
    raise FileNotFoundError(f"no runtime config in {run_dir}")


def go_generate(go_bin, args, out_path):
    cmd = [go_bin, "xray", "generate", "--out", str(out_path), "--force", "--json"] + args
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"go generate failed ({proc.returncode}): {proc.stderr.strip()}")
    return json.loads(out_path.read_text()), json.loads(proc.stdout or "{}")


def first_bash_inbound(cfg):
    return (cfg.get("inbounds") or [{}])[0]


def fresh_args(cfg, facts=None):
    facts = facts or {}
    ib = first_bash_inbound(cfg)
    ss = ib.get("streamSettings") or {}
    rs = ss.get("realitySettings") or {}
    settings = ib.get("settings") or {}
    client = (settings.get("clients") or [{}])[0]
    mode = "reality" if (ss.get("security") == "reality") else (
        "tls" if ss.get("security") == "tls" else "none")
    networks = [(i.get("streamSettings") or {}).get("network") for i in cfg.get("inbounds") or []]
    transport = "ws+grpc+xhttp" if len(networks) > 1 else (ss.get("network") or "raw")
    args = ["--mode", mode, "--transport", transport, "--port", str(ib.get("port")),
            "--listen", ib.get("listen") or "0.0.0.0"]
    if client.get("email"):
        args += ["--email", client.get("email")]
    if not is_redacted_uuid(client.get("id")):
        args += ["--uuid", client.get("id")]
    else:
        args += ["--uuid", FIXED_UUID]
    if mode == "reality":
        args += ["--target", rs.get("target") or ""]
        names = rs.get("serverNames") or []
        if names:
            args += ["--server-names", ",".join(names)]
        if not is_redacted_key(rs.get("privateKey")):
            args += ["--private-key", rs.get("privateKey")]
        ids = rs.get("shortIds") or []
        if ids:
            args += ["--short-id", ids[0]]
    ws = ss.get("wsSettings") or {}
    xhttp = ss.get("xhttpSettings") or {}
    path = ws.get("path") or xhttp.get("path")
    if path:
        args += ["--path", path]
    grpc = ss.get("grpcSettings") or {}
    if grpc.get("serviceName"):
        args += ["--service-name", grpc["serviceName"]]
    if mode == "tls":
        args += ["--domain", facts.get("domain") or "example.com"]
    return args


def compare_run(run_dir, go_bin, contracts):
    raw_path, bash_cfg = load_config(run_dir)
    facts = json.loads((run_dir / "facts.json").read_text()) if (run_dir / "facts.json").exists() else {}
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for contract in contracts:
            try:
                if contract == "fresh":
                    go_cfg, go_info = go_generate(go_bin, fresh_args(bash_cfg, facts), tmp / "fresh.json")
                    result = compare(bash_cfg, go_cfg, contract=contract)
                    identity_check(run_dir, go_info, result, **identity_inputs(bash_cfg))
                else:
                    raw, restore_changed = restore_placeholders(raw_path.read_bytes())
                    src = tmp / "bash-adopt.json"
                    src.write_bytes(raw)
                    go_cfg, _ = go_generate(go_bin, ["--from-config", str(src)], tmp / "preserve.json")
                    result = compare(bash_cfg, go_cfg, contract=contract)
                    if restore_changed and result["status"] not in FAIL_STATUSES:
                        if result["status"] == "MATCH":
                            result["status"] = "MATCH_STRUCTURE_UNCOVERED"
                        result["uncovered"].append({"field": "identity", "reason": "redacted in evidence"})
            except Exception as exc:  # noqa: BLE001 - reported as evidence, not hidden
                result = {"contract": contract, "status": "FAIL", "error": str(exc),
                          "diffs": [], "uncovered": [], "approvedNewInstallDiff": []}
            result["run"] = run_dir.name
            result["mode"] = facts.get("mode")
            result["transport"] = facts.get("transport")
            result["xrayVersion"] = facts.get("xrayVersion")
            result["serviceActive"] = facts.get("serviceActive")
            results.append(result)
    return results


def self_test():
    """Mutate a synthetic pair and require every mutation to be detected."""
    base = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "VLESS-ws-in", "listen": "127.0.0.1", "port": 10805, "protocol": "VLESS",
             "settings": {"clients": [{"id": FIXED_UUID, "level": 0, "email": "a@hey.run"}],
                          "decryption": "none"},
             "streamSettings": {"network": "ws", "security": "none",
                                "wsSettings": {"path": "/path-a"}}},
            {"tag": "VLESS-gRPC-in", "listen": "127.0.0.1", "port": 10198, "protocol": "VLESS",
             "settings": {"clients": [{"id": FIXED_UUID, "level": 0, "email": "a@hey.run"}],
                          "decryption": "none"},
             "streamSettings": {"network": "grpc", "security": "none",
                                "grpcSettings": {"serviceName": "svc", "multiMode": True,
                                                 "idle_timeout": 20}}},
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "dns": {"servers": ["1.1.1.1"]},
        "routing": {"rules": [{"type": "field", "inboundTag": ["VLESS-ws-in", "VLESS-gRPC-in"],
                               "outboundTag": "direct"}]},
    }
    good = compare(base, copy.deepcopy(base), contract="preserve")
    if good["status"] != "MATCH":
        print(f"SELFTEST_FAIL baseline status={good['status']} {good['diffs']}", file=sys.stderr)
        return 1

    def mutate(fn):
        other = copy.deepcopy(base)
        fn(other)
        return compare(base, other, contract="preserve")["status"]

    mutations = {
        "second-inbound-port": lambda c: c["inbounds"][1].update(port=10199),
        "ws-path": lambda c: c["inbounds"][0]["streamSettings"]["wsSettings"].update(path="/path-b"),
        "grpc-service-name": lambda c: c["inbounds"][1]["streamSettings"]["grpcSettings"].update(serviceName="other"),
        "grpc-multimode": lambda c: c["inbounds"][1]["streamSettings"]["grpcSettings"].update(multiMode=False),
        "client-uuid": lambda c: c["inbounds"][0]["settings"]["clients"][0].update(id="22222222-2222-4222-8222-222222222222"),
        "client-email": lambda c: c["inbounds"][0]["settings"]["clients"][0].update(email="b@hey.run"),
        "client-flow": lambda c: c["inbounds"][0]["settings"]["clients"][0].update(flow="xtls-rprx-vision"),
        "listen": lambda c: c["inbounds"][0].update(listen="0.0.0.0"),
        "security": lambda c: c["inbounds"][0]["streamSettings"].update(security="tls"),
        "routing-reference": lambda c: c["routing"]["rules"][0].update(inboundTag=["VLESS-ws-in", "VLESS-nonexistent"]),
        "drop-inbound": lambda c: c["inbounds"].pop(1),
        "duplicate-tag": lambda c: c["inbounds"][1].update(tag="VLESS-ws-in"),
        "dns": lambda c: c["dns"].update(servers=["8.8.8.8"]),
        "outbounds": lambda c: c["outbounds"][0].update(tag="proxy"),
    }
    failed = []
    for name, fn in mutations.items():
        status = mutate(fn)
        if status not in FAIL_STATUSES:
            failed.append((name, status))
    if failed:
        print(f"SELFTEST_FAIL undetected={failed}", file=sys.stderr)
        return 1
    # Exit-code contract: an unapproved gap must make the process non-zero.
    if exit_code([{"status": "GAP"}]) == 0 or exit_code([{"status": "MATCH"}]) != 0:
        print("SELFTEST_FAIL exit-code contract", file=sys.stderr)
        return 1
    print(f"SELFTEST_PASS mutations={len(mutations)} baseline=MATCH")
    return 0


def exit_code(results):
    return 1 if any(r.get("status") in FAIL_STATUSES for r in results) else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence")
    parser.add_argument("--go-bin")
    parser.add_argument("--out")
    parser.add_argument("--contract", choices=["fresh", "preserve", "both"], default="both")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.evidence or not args.go_bin or not args.out:
        parser.error("--evidence, --go-bin and --out are required unless --self-test is used")

    evidence = Path(args.evidence)
    runs = sorted(p for p in evidence.iterdir() if p.is_dir() and (p / "facts.json").exists())
    if not runs:
        print(f"ERROR: no captured runs under {evidence}", file=sys.stderr)
        return 1
    contracts = ["fresh", "preserve"] if args.contract == "both" else [args.contract]
    results = []
    for run_dir in runs:
        results.extend(compare_run(run_dir, args.go_bin, contracts))

    counts = {key: 0 for key in COUNTS}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    summary = {
        "contracts": contracts,
        "runs": len(runs),
        "rows": len(results),
        "counts": counts,
        "results": results,
    }
    Path(args.out).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(counts, sort_keys=True))
    for result in results:
        print(f"{result.get('run'):28} {result['contract']:8} {result['status']}")
        for diff in result.get("diffs", [])[:4]:
            print(f"    GAP {diff}")
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
