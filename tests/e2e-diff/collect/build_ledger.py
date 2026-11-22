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

# Verdicts that assert the two sides are equivalent. Anything else that reports
# a difference is never silently accepted; DIFF/EXPECTED_DIFF only enter the
# ledger as APPROVED_DIFF when an out-of-band approval file names the row.
PASS_VERDICTS = {"PASS", "MATCH", "GOOD"}
FAIL_VERDICTS = {"FAIL", "MISMATCH", "GAP", "DIFF", "ERROR"}
DIFF_VERDICTS = {"EXPECTED_DIFF", "ALLOWED_DIFF"}
INCOMPLETE_VERDICTS = {"BLOCKED", "SKIP", "NOT_RUN"}

# A driver may record a known behavioural difference without writing ops.json.
# Those declarations are real evidence and must not disappear: they are treated
# exactly like an EXPECTED_DIFF verdict (approval required, otherwise FAIL).
DIFF_DECLARATION_FILES = (
    "shortid-difference.json",
    "cert-clear-difference.json",
    "log-source-difference.json",
    "metadata-difference.json",
    "difference.json",
    "diff.json",
)
DECLARED_DIFF_VERDICTS = DIFF_VERDICTS | {"DIFF"}


class EvidenceError(Exception):
    """Raised when a declared evidence directory is missing or unreadable."""


def load_approvals(path):
    """Return {op_id: approval} from an explicit approval file.

    Approvals are deliberately external input. The ledger never infers that a
    difference is acceptable, and an approved difference is still reported as
    APPROVED_DIFF, never as verified equivalence.
    """
    if not path:
        return {}
    data = read_json(path)
    if not isinstance(data, dict):
        raise EvidenceError("approval file %s is missing or not a JSON object" % path)
    out = {}
    for item in data.get("approved") or []:
        if not isinstance(item, dict) or not item.get("id"):
            raise EvidenceError("approval file %s has an entry without an id" % path)
        if not item.get("approvedBy") or not item.get("reason"):
            raise EvidenceError("approval for %s needs approvedBy and reason" % item["id"])
        out[item["id"]] = item
    return out


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def repo_path(path):
    """Record paths relative to the repo so the ledger carries no host path."""
    if not path:
        return path
    rel = os.path.relpath(os.path.abspath(path))
    return path if rel.startswith("..") or os.path.isabs(rel) else rel


def read_difference_declaration(dirpath):
    """Return (path, data) for a driver-recorded difference, else None."""
    for fname in DIFF_DECLARATION_FILES:
        path = os.path.join(dirpath, fname)
        data = read_json(path)
        if not isinstance(data, dict):
            continue
        verdict = str(data.get("result") or data.get("verdict") or "").upper().replace("-", "_")
        if verdict in DECLARED_DIFF_VERDICTS:
            return path, data
    return None


def matrix_results(root, approvals):
    """Read p2/OPS-*/ops.json verdicts from a matrix run.

    Every declared OPS directory produces a row. A missing/unreadable ops.json,
    an id that disagrees with the directory, or a verdict that cannot be
    classified becomes BLOCKED instead of disappearing. A failure or an
    unapproved difference always wins over a pass.
    """
    out = {}
    if not root:
        return out
    p2 = os.path.join(root, "p2")
    if not os.path.isdir(p2):
        raise EvidenceError("matrix evidence %s has no p2 directory" % root)
    for name in sorted(os.listdir(p2)):
        if not name.startswith("OPS-"):
            continue
        evidence_path = os.path.join(p2, name, "ops.json")
        data = read_json(evidence_path)
        if not isinstance(data, dict):
            declaration = read_difference_declaration(os.path.join(p2, name))
            if declaration is not None:
                path, data = declaration
                verdict = str(data.get("result") or data.get("verdict") or "").upper().replace("-", "_")
                reasons = [str(r) for r in (data.get("reasons") or [])]
                if name in approvals:
                    out[name] = {
                        "status": "APPROVED_DIFF", "verdict": verdict, "approval": approvals[name],
                        "reasons": reasons, "evidence": repo_path(path),
                        "runId": os.path.basename(os.path.normpath(root)),
                        "layer": "L0-L4 driver evidence",
                    }
                else:
                    out[name] = {
                        "status": "FAIL", "verdict": verdict,
                        "reasons": reasons + [
                            "%s declares a difference but no external approval names %s" % (os.path.basename(path), name)],
                        "evidence": repo_path(path),
                        "runId": os.path.basename(os.path.normpath(root)),
                        "layer": "L0-L4 driver evidence",
                    }
                continue
            out[name] = {
                "status": "BLOCKED",
                "verdict": None,
                "reasons": ["ops.json is missing or unreadable; this row has no acceptable evidence"],
                "evidence": repo_path(evidence_path),
                "runId": os.path.basename(os.path.normpath(root)),
                "layer": "L0-L4 driver evidence",
            }
            continue
        op_id = str(data.get("id") or name)
        verdict = str(data.get("verdict") or "").upper().replace("-", "_")
        reasons = [str(r) for r in (data.get("reasons") or [])]
        bash_rc = (data.get("opsRc") or {}).get("bash")
        go_rc = (data.get("opsRc") or {}).get("go")
        base = {
            "verdict": verdict or None,
            "bashExit": bash_rc,
            "goExit": go_rc,
            "reasons": reasons,
            "evidence": repo_path(evidence_path),
            "runId": os.path.basename(os.path.normpath(root)),
            "layer": "L0-L4 driver evidence",
        }
        if op_id != name:
            base.update(status="BLOCKED",
                        reasons=reasons + ["ops.json id %r does not match its directory %r" % (op_id, name)])
            out[name] = base
            continue
        if verdict in FAIL_VERDICTS:
            status = "FAIL"
        elif verdict in DIFF_VERDICTS:
            if op_id in approvals:
                status = "APPROVED_DIFF"
                base["approval"] = approvals[op_id]
            else:
                status = "FAIL"
                base["reasons"] = reasons + ["an expected/allowed difference was declared but no external approval names %s" % op_id]
        elif verdict in PASS_VERDICTS:
            # A PASS that carries a non-zero exit code is contradictory evidence,
            # not a pass. Both sides must have recorded a zero exit code.
            bad_rc = [label for label, rc in (("bash", bash_rc), ("go", go_rc)) if rc is not None and rc != 0]
            if bad_rc:
                status = "FAIL"
                base["reasons"] = reasons + ["verdict %s contradicts non-zero %s exit code" % (verdict, ",".join(bad_rc))]
            elif bash_rc is None or go_rc is None:
                status = "BLOCKED"
                base["reasons"] = reasons + ["dual-side PASS is missing an exit code; evidence is incomplete"]
            else:
                status = "DUAL_SIDE_VERIFIED"
        elif verdict == "BASH_ONLY":
            status = "BASH_ONLY"
        elif verdict in INCOMPLETE_VERDICTS:
            status = "BLOCKED"
        else:
            status = "BLOCKED"
            base["reasons"] = reasons + ["unrecognised or missing verdict %r; evidence is not acceptable" % verdict]
        base["status"] = status
        out[op_id] = base
    return out


def sweep_results(root):
    """Parse assertions.txt from an ops sweep: an ID passes with no FAIL.

    A declared sweep without a readable assertions.txt, with malformed lines, or
    with no OPS assertion at all is rejected instead of silently contributing an
    empty (and therefore green-looking) result.
    """
    out = {}
    if not root:
        return out
    path = os.path.join(root, "assertions.txt")
    if not os.path.isfile(path):
        raise EvidenceError("ops evidence %s has no assertions.txt" % root)
    try:
        lines = open(path, "r", encoding="utf-8").read().splitlines()
    except OSError as exc:
        raise EvidenceError("cannot read %s: %s" % (path, exc))
    per_id = {}
    for lineno, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        status, sep, text = line.partition("\t")
        if not sep or status not in ("PASS", "FAIL"):
            raise EvidenceError("%s:%d is not a PASS/FAIL assertion line" % (path, lineno))
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
    if not per_id:
        raise EvidenceError("%s contains no OPS assertion; this is not usable evidence" % path)
    for op_id, entry in per_id.items():
        if entry["pass"] == 0 and entry["fail"] == 0:
            continue
        out[op_id] = {
            "status": "GO_ONLY" if entry["fail"] == 0 else "FAIL",
            "verdict": "PASS" if entry["fail"] == 0 else "FAIL",
            "goExit": 0 if entry["fail"] == 0 else 1,
            "reasons": entry["failText"],
            "assertions": entry["pass"] + entry["fail"],
            "evidence": repo_path(path),
            "runId": os.path.basename(os.path.normpath(root)),
            "layer": "L0-L2 Go CLI evidence",
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix-evidence", action="append", default=[],
                    help="run_p2_matrix.sh output tree (repeatable; later runs fill gaps)")
    ap.add_argument("--ops-evidence", action="append", default=[],
                    help="run_ops_sweep.sh / run_ops_realroot.sh output tree (repeatable)")
    ap.add_argument("--code-sha", default="")
    ap.add_argument("--approved-diffs", default="",
                    help="explicit approval JSON for declared differences; without it a diff is a FAIL")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="exit 0 even when rows are not dual-side verified (never for final acceptance)")
    ap.add_argument("--out", default="tests/e2e-diff/ledger.json")
    ap.add_argument("--matrix-json", default="tests/e2e-diff/matrix.json")
    ap.add_argument("--acceptance-json", default="docs/go-evolution/hardening/acceptance.json")
    args = ap.parse_args()

    try:
        approvals = load_approvals(args.approved_diffs)
        matrix_runs = [matrix_results(root, approvals) for root in args.matrix_evidence]
        sweep_runs = [sweep_results(root) for root in args.ops_evidence]
    except EvidenceError as exc:
        print("ledger error: %s" % exc, file=sys.stderr)
        return 2

    # Strongest evidence per row wins: any failure, then a declared-and-approved
    # difference, then dual verification, then single-side evidence. Nothing is
    # discarded: a row with only weak evidence keeps that weak status.
    rank = {
        "NOT_RUN": 0,
        "BLOCKED": 1,
        "BASH_ONLY": 2,
        "GO_ONLY": 3,
        "DUAL_SIDE_VERIFIED": 4,
        "APPROVED_DIFF": 5,
        "FAIL": 6,
    }
    chosen = {}
    for record in matrix_runs + sweep_runs:
        for op_id, entry in record.items():
            if op_id not in chosen or rank[entry["status"]] > rank[chosen[op_id]["status"]]:
                chosen[op_id] = entry

    results = []
    for op_id in OPS_IDS:
        entry = dict(chosen.get(op_id) or {
            "status": "NOT_RUN",
            "verdict": None,
            "reasons": ["no evidence at the frozen commit"],
            "evidence": None,
            "layer": None,
        })
        entry["id"] = op_id
        results.append(entry)

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
    approved_diff_ids = [e["id"] for e in results if e["status"] == "APPROVED_DIFF"]
    unresolved = [e["id"] for e in results if e["status"] != "DUAL_SIDE_VERIFIED"]

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
            "APPROVED_DIFF": len(approved_diff_ids),
        },
        "dualSideVerifiedIds": dual_ids,
        "goOnlyIds": go_ids,
        "failIds": fail_ids,
        "bashOnlyIds": bash_ids,
        "blockedIds": blocked_ids,
        "notRunIds": not_run_ids,
        "approvedDiffIds": approved_diff_ids,
        "unresolvedIds": unresolved,
        "sources": {
            "matrixEvidence": [repo_path(p) for p in args.matrix_evidence],
            "opsEvidence": [repo_path(p) for p in args.ops_evidence],
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
        "approvedDiff": len(approved_diff_ids),
        "approvedDiffIds": approved_diff_ids,
        "unresolvedIds": unresolved,
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
            "approvedDiffOps": summary["approvedDiff"],
            "dualSideVerifiedIds": dual_ids,
            "goOnlyIds": go_ids,
            "failIds": fail_ids,
            "bashOnlyIds": bash_ids,
            "approvedDiffIds": approved_diff_ids,
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
    if fail_ids:
        print("ledger: FAIL rows present: %s" % ", ".join(fail_ids), file=sys.stderr)
        return 1
    if unresolved and not args.allow_incomplete:
        print("ledger: %d row(s) are not dual-side verified: %s"
              % (len(unresolved), ", ".join(unresolved)), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
