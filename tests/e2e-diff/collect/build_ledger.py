#!/usr/bin/env python3
"""Build the single OPS acceptance ledger from real run evidence.

The audit found three disagreeing summaries (matrix.json, acceptance.json and
report prose) that were edited by hand. This script makes one machine-readable
ledger the only source of truth and rewrites both summaries from it.

Inputs are evidence directories produced by the existing drivers:

  --matrix-evidence DIR   run_p2_matrix.sh output tree (dual-side ops)
  --ops-evidence DIR      run_ops_sweep.sh output tree (Go-side ops)

Rows are classified only from recorded verdicts/assertions. A row with no
evidence stays NOT_RUN; the denominator is never reduced.
"""

import argparse
import datetime
import json
import os
import re
import sys

OPS_IDS = (
    ["OPS-%02d" % i for i in range(1, 17)]
    + ["OPS-17a", "OPS-17b", "OPS-17c"]
    + ["OPS-%02d" % i for i in range(18, 33)]
)
assert len(OPS_IDS) == 34, len(OPS_IDS)

ASSERT_ID = re.compile(r"\b(PPS-[0-9]{2}[a-c]?|OPS-[0-9]{2}[a-c]?)\b")


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def matrix_results(root):
    """Read p2/OPS-*/ops.json verdicts from a matrix run."""
    out = {}
    if not root:
        return out
    p2 = os.path.join(root, "p2")
    if not os.path.isdir(p2):
        return out
    for name in sorted(os.listdir(p2)):
        if not name.startswith("OPS-"):
            continue
        data = read_json(os.path.join(p2, name, "ops.json"))
        if data is None:
            continue
        op_id = data.get("id") or name
        verdict = str(data.get("verdict") or "").upper().replace("-", "_")
        reasons = data.get("reasons") or []
        bash_rc = (data.get("opsRc") or {}).get("bash")
        go_rc = (data.get("opsRc") or {}).get("go")
        if "BASH_ONLY" in verdict or any("bash-only" in str(r).lower() for r in reasons):
            status = "BASH_ONLY"
        elif verdict in ("PASS", "MATCH", "GOOD", "ALLOWED_DIFF", "EXPECTED_DIFF"):
            status = "DUAL_SIDE_VERIFIED"
        elif verdict in ("FAIL", "MISMATCH", "GAP"):
            status = "FAIL"
        elif verdict in ("BLOCKED", "SKIP", "NOT_RUN", "ERROR"):
            status = "BLOCKED"
        else:
            continue
        out[op_id] = {
            "status": status,
            "verdict": verdict or None,
            "bashExit": bash_rc,
            "goExit": go_rc,
            "reasons": reasons,
            "evidence": os.path.join(root, "p2", name, "ops.json"),
            "runId": os.path.basename(os.path.normpath(root)),
            "layer": "L0-L4 driver evidence",
        }
    return out


def sweep_results(root):
    """Parse assertions.txt from an ops sweep: an ID passes with no FAIL."""
    out = {}
    if not root:
        return out
    path = os.path.join(root, "assertions.txt")
    try:
        lines = open(path, "r", encoding="utf-8").read().splitlines()
    except OSError:
        return out
    per_id = {}
    for line in lines:
        status, _, text = line.partition("\t")
        if status not in ("PASS", "FAIL"):
            continue
        for match in ASSERT_ID.findall(text):
            if match.startswith("PPS-"):
                continue
            op_id = match
            if op_id.endswith(("a", "b", "c")) and op_id not in OPS_IDS:
                op_id = op_id[:-1]
            if op_id not in OPS_IDS:
                continue
            entry = per_id.setdefault(op_id, {"pass": 0, "fail": 0, "failText": []})
            if status == "PASS":
                entry["pass"] += 1
            else:
                entry["fail"] += 1
                entry["failText"].append(text)
    for op_id, entry in per_id.items():
        if entry["pass"] == 0 and entry["fail"] == 0:
            continue
        out[op_id] = {
            "status": "GO_ONLY" if entry["fail"] == 0 else "FAIL",
            "verdict": "PASS" if entry["fail"] == 0 else "FAIL",
            "goExit": 0 if entry["fail"] == 0 else 1,
            "reasons": entry["failText"],
            "assertions": entry["pass"] + entry["fail"],
            "evidence": os.path.join(root, "assertions.txt"),
            "runId": os.path.basename(os.path.normpath(root)),
            "layer": "L0-L2 Go CLI evidence",
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix-evidence")
    ap.add_argument("--ops-evidence", action="append", default=[],
                    help="run_ops_sweep.sh / run_ops_realroot.sh output tree (repeatable)")
    ap.add_argument("--code-sha", default="")
    ap.add_argument("--out", default="tests/e2e-diff/ledger.json")
    ap.add_argument("--matrix-json", default="tests/e2e-diff/matrix.json")
    ap.add_argument("--acceptance-json", default="docs/go-evolution/hardening/acceptance.json")
    args = ap.parse_args()

    dual = matrix_results(args.matrix_evidence)
    sweep = {}
    for root in args.ops_evidence:
        for op_id, entry in sweep_results(root).items():
            # A failure from any sweep always wins; otherwise keep the first
            # passing record so the evidence path stays stable.
            if op_id not in sweep or entry["status"] == "FAIL":
                sweep[op_id] = entry

    results = []
    for op_id in OPS_IDS:
        if op_id in dual:
            entry = dict(dual[op_id])
        elif op_id in sweep:
            entry = dict(sweep[op_id])
        else:
            entry = {
                "status": "NOT_RUN",
                "verdict": None,
                "reasons": ["no evidence at the frozen commit"],
                "evidence": None,
                "layer": None,
            }
        entry["id"] = op_id
        results.append(entry)

    # A dual-side PASS proves more than a Go-only PASS, so it wins. A failure
    # always wins over a pass: nothing may be reported green while a red exists.
    by_id = {e["id"]: e for e in results}
    for op_id, e in dual.items():
        if e["status"] == "FAIL":
            by_id[op_id].update(e)
            by_id[op_id]["id"] = op_id
    for op_id, e in sweep.items():
        if e["status"] == "FAIL" and by_id[op_id]["status"] != "FAIL":
            merged = dict(by_id[op_id])
            merged.update(e)
            merged["id"] = op_id
            by_id[op_id] = merged

    # Every row records the real Bash menu entry, the Go command and the
    # expected contract so the ledger can be audited without cross-reading the
    # matrix. A missing Bash entry stays null instead of inventing a mapping.
    spec = read_json(args.matrix_json) or {}
    spec_ops = {o.get("id"): o for o in spec.get("ops") or [] if isinstance(o, dict)}
    for entry in results:
        o = spec_ops.get(entry["id"]) or {}
        go_cmd = o.get("go")
        entry["name"] = o.get("name")
        entry["bashEntry"] = o.get("bash")
        entry["goCommand"] = " ".join(go_cmd) if isinstance(go_cmd, list) else go_cmd
        entry["contract"] = o.get("verdict")
        entry["layers"] = o.get("layers")
        entry["notes"] = o.get("notes")

    counts = {}
    for e in results:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    dual_ids = [e["id"] for e in results if e["status"] == "DUAL_SIDE_VERIFIED"]
    go_ids = [e["id"] for e in results if e["status"] == "GO_ONLY"]
    fail_ids = [e["id"] for e in results if e["status"] == "FAIL"]
    bash_ids = [e["id"] for e in results if e["status"] == "BASH_ONLY"]
    blocked_ids = [e["id"] for e in results if e["status"] == "BLOCKED"]
    not_run_ids = [e["id"] for e in results if e["status"] == "NOT_RUN"]

    sha = args.code_sha or os.popen("git rev-parse HEAD").read().strip()
    generated = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    ledger = {
        "schemaVersion": 1,
        "generatedAt": generated,
        "codeSha": sha,
        "opsTotal": len(OPS_IDS),
        "counts": {
            "DUAL_SIDE_VERIFIED": len(dual_ids),
            "GO_ONLY": len(go_ids),
            "FAIL": len(fail_ids),
            "BASH_ONLY": len(bash_ids),
            "BLOCKED": len(blocked_ids),
            "NOT_RUN": len(not_run_ids),
        },
        "dualSideVerifiedIds": dual_ids,
        "goOnlyIds": go_ids,
        "failIds": fail_ids,
        "bashOnlyIds": bash_ids,
        "blockedIds": blocked_ids,
        "notRunIds": not_run_ids,
        "sources": {
            "matrixEvidence": os.path.abspath(args.matrix_evidence) if args.matrix_evidence else None,
            "opsEvidence": [os.path.abspath(p) for p in args.ops_evidence],
        },
        "results": results,
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(ledger, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    summary = {
        "total": len(OPS_IDS),
        "dualSideVerified": len(dual_ids),
        "dualSideVerifiedIds": dual_ids,
        "goOnly": len(go_ids),
        "fail": len(fail_ids),
        "failIds": fail_ids,
        "bashOnly": len(bash_ids),
        "bashOnlyIds": bash_ids,
        "blocked": len(blocked_ids),
        "blockedIds": blocked_ids,
        "notRun": len(not_run_ids),
        "notRunIds": not_run_ids,
        "generatedAt": generated,
        "codeSha": sha,
        "source": "tests/e2e-diff/ledger.json",
    }

    matrix = read_json(args.matrix_json)
    if matrix is not None:
        matrix["repoCommit"] = sha[:8]
        matrix["acceptance"] = {
            "opsTotal": summary["total"],
            "dualSideVerifiedOps": summary["dualSideVerified"],
            "goOnlyOps": summary["goOnly"],
            "failOps": summary["fail"],
            "bashOnlyOps": summary["bashOnly"],
            "blockedOps": summary["blocked"],
            "notRunOps": summary["notRun"],
            "dualSideVerifiedIds": dual_ids,
            "goOnlyIds": go_ids,
            "failIds": fail_ids,
            "bashOnlyIds": bash_ids,
            "notRunIds": not_run_ids,
            "generatedFrom": "tests/e2e-diff/ledger.json",
            "generatedAt": generated,
            "codeSha": sha,
        }
        with open(args.matrix_json, "w", encoding="utf-8") as fh:
            json.dump(matrix, fh, ensure_ascii=False, indent=2)
            fh.write("\n")

    acceptance = read_json(args.acceptance_json)
    if acceptance is not None:
        acceptance["ops"] = summary
        with open(args.acceptance_json, "w", encoding="utf-8") as fh:
            json.dump(acceptance, fh, ensure_ascii=False, indent=2)
            fh.write("\n")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
