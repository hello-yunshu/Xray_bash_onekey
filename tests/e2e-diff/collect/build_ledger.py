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
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

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
FAIL_VERDICTS = {"FAIL", "MISMATCH", "GAP", "ERROR"}
DIFF_VERDICTS = {"EXPECTED_DIFF", "ALLOWED_DIFF", "DIFF"}
INCOMPLETE_VERDICTS = {"BLOCKED", "SKIP", "NOT_RUN"}

# A row counts as resolved for acceptance when the two sides were verified or
# when a human explicitly accepted the recorded difference/single-side evidence.
RESOLVED_STATUSES = {"DUAL_SIDE_VERIFIED", "APPROVED_DIFF", "APPROVED_SINGLE_SIDE"}

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
DECLARED_DIFF_VERDICTS = DIFF_VERDICTS


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
        if not str(item.get("scope") or "").strip():
            raise EvidenceError("approval for %s has no scope" % item["id"])
        out[item["id"]] = item
    return out


def file_sha256(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


PROVENANCE_FIELDS = (
    "productCodeSha", "binarySha256", "bashScriptSha256",
    "driverSha", "runId", "layer", "startedAt",
)


def provenance_problems_run(run, code_sha, dirname):
    """Return why a run block cannot bind evidence to the frozen candidate.

    Exit codes and verdicts are not provenance. Without the product commit, the
    two build artefacts, the driver commit and the run identity there is no way
    to tell current evidence from a stale run of an older candidate.
    """
    if not isinstance(run, dict):
        return ["no run provenance block; this evidence is not bound to a candidate build"]
    problems = []
    for key in PROVENANCE_FIELDS:
        if not str(run.get(key) or "").strip():
            problems.append("run provenance is missing %s" % key)
    product = str(run.get("productCodeSha") or "")
    if product and code_sha and product != code_sha:
        problems.append("evidence was produced for product %s, not the frozen %s"
                        % (product[:12], code_sha[:12]))
    run_id = str(run.get("runId") or "")
    if run_id and dirname and run_id != dirname:
        problems.append("run provenance runId %r does not match evidence directory %r"
                        % (run_id, dirname))
    return problems


def provenance_problems(data, code_sha, dirname):
    return provenance_problems_run(data.get("run"), code_sha, dirname)


def _positive(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _true(value):
    return value is True


def _nonempty(value):
    return bool(value)


def _sni_probe(value):
    return (isinstance(value, dict)
            and str(value.get("unknownSniPolicy") or "").strip() != ""
            and value.get("knownSniOk") is True)


# Facts the independent audit named explicitly. A PASS with both exit codes is
# only a necessary condition; the row must also carry the observable business
# result for each side. Rows without a contract still need provenance.
BUSINESS_FACTS = {
    "OPS-01": [("addedClients", _positive), ("removedClients", _positive), ("clientConnected", _true)],
    "OPS-02": [("addedClients", _positive), ("removedClients", _positive), ("clientConnected", _true)],
    "OPS-04": [("portListening", _true), ("clientConnected", _true), ("shareInfo", _nonempty)],
    "OPS-08": [("sniProbe", _sni_probe)],
    "OPS-10": [("serverNames", _nonempty)],
    "OPS-20": [("trafficBytes", _positive)],
    "OPS-25": [("restoreVerified", _true), ("checksumMatch", _true)],
    "OPS-26": [("restoreVerified", _true), ("checksumMatch", _true)],
    "OPS-32": [("faultRemoved", _true), ("recovered", _true)],
}


def business_problems(op_id, details):
    facts = BUSINESS_FACTS.get(op_id)
    if not facts:
        return []
    problems = []
    for side in ("bash", "go"):
        block = details.get(side) if isinstance(details, dict) else None
        if not isinstance(block, dict):
            problems.append("%s side has no business evidence block" % side)
            continue
        for key, predicate in facts:
            if not predicate(block.get(key)):
                problems.append("%s side lacks the required business fact %s" % (side, key))
    return problems


def approval_problems(approval, evidence_path, op_id):
    """Validate that an approval names this row, this difference and a deadline."""
    problems = []
    if not approval.get("approvedBy") or not approval.get("reason"):
        problems.append("approval for %s needs approvedBy and reason" % op_id)
    scope = str(approval.get("scope") or "").strip()
    if not scope:
        problems.append("approval for %s has no scope" % op_id)
    if str(approval.get("approvedBy") or "").lower() == "user" and not approval.get("provenance"):
        problems.append("a user approval must cite a traceable provenance record, not only approvedBy=user")
    if approval.get("opId") and approval["opId"] != op_id:
        problems.append("approval opId %r does not match %s" % (approval["opId"], op_id))
    expires = approval.get("expiresAt")
    if expires:
        try:
            expiry = datetime.date.fromisoformat(str(expires)[:10])
        except ValueError:
            problems.append("approval expiresAt %r is not an ISO date" % expires)
        else:
            today = datetime.datetime.now(datetime.timezone.utc).date()
            if expiry < today:
                problems.append("approval expired on %s" % expires)
    fingerprint = approval.get("fingerprint")
    if not fingerprint:
        problems.append("approval for %s has no evidence fingerprint; it cannot bind a specific difference" % op_id)
    else:
        actual = file_sha256(evidence_path)
        if actual != fingerprint:
            problems.append("approval fingerprint does not match the cited evidence for %s" % op_id)
    return problems


def single_side_approval(approvals, op_id, evidence_path):
    """Return the approval that makes one-sided evidence acceptable.

    The ledger never accepts single-side evidence on its own. Such an approval
    must also carry a scope, so the report can say which side was verified and
    what is still unverified instead of implying dual-side equivalence.
    """
    approval = approvals[op_id]
    if not str(approval.get("scope") or "").strip():
        raise EvidenceError(
            "approval for %s would accept single-side evidence but has no scope (%s)"
            % (op_id, evidence_path))
    return approval


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def git_toplevel():
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return out or None


def inside_repo(path, root):
    if not root:
        return False
    try:
        rel = os.path.relpath(os.path.abspath(path), root)
    except ValueError:
        return False
    return not (rel == ".." or rel.startswith(".." + os.sep) or os.path.isabs(rel))


def approval_applies(approval, evidence_path):
    """Return whether this approval was written for this exact evidence file.

    An approval names one difference in one file. The same op id can have both a
    dual-side ops.json and a Go-only sweep line, so a global per-id binding would
    let one file's approval be judged against the other file's fingerprint and
    poison an unrelated row. When the approval cites fingerprintOf we compare the
    resolved paths; legacy approvals without it keep the fingerprint-only check.
    """
    target = str(approval.get("fingerprintOf") or "").strip()
    if not target:
        return True
    root = git_toplevel() or os.getcwd()

    def resolve(path):
        if not os.path.isabs(path):
            path = os.path.join(root, path)
        return os.path.realpath(path)

    return resolve(target) == resolve(evidence_path)


def write_json_atomic(path, data):
    """Write JSON with a same-directory temp file and an atomic rename.

    A failed or interrupted run must never leave a partially written acceptance
    summary behind; either the previous file survives or the complete new one
    replaces it.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".ledger-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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


def matrix_results(root, approvals, code_sha=""):
    """Read p2/OPS-*/ops.json verdicts from a matrix run.

    Every declared OPS directory produces a row. A missing/unreadable ops.json,
    an id that disagrees with the directory, or a verdict that cannot be
    classified becomes BLOCKED instead of disappearing. A failure or an
    unapproved difference always wins over a pass.

    A verdict is never enough on its own: the row must also prove which commit
    and artefacts produced it, and (for audited rows) carry the observable
    business fact for both sides.
    """
    out = {}
    if not root:
        return out
    run_id = os.path.basename(os.path.normpath(root))
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
                prov = provenance_problems(data, code_sha, run_id)
                base = {
                    "verdict": verdict, "reasons": reasons,
                    "evidence": repo_path(path), "runId": run_id,
                    "layer": "L0-L4 driver evidence",
                }
                if prov:
                    base.update(status="BLOCKED", reasons=reasons + prov)
                elif name in approvals and approval_applies(approvals[name], path):
                    problems = approval_problems(approvals[name], path, name)
                    if problems:
                        base.update(status="FAIL", reasons=reasons + problems)
                    else:
                        base.update(status="APPROVED_DIFF", approval=approvals[name])
                else:
                    base.update(status="FAIL", reasons=reasons + [
                        "%s declares a difference but no external approval names %s" % (os.path.basename(path), name)])
                out[name] = base
                continue
            out[name] = {
                "status": "BLOCKED",
                "verdict": None,
                "reasons": ["ops.json is missing or unreadable; this row has no acceptable evidence"],
                "evidence": repo_path(evidence_path),
                "runId": run_id,
                "layer": "L0-L4 driver evidence",
            }
            continue
        op_id = str(data.get("id") or name)
        verdict = str(data.get("verdict") or "").upper().replace("-", "_")
        reasons = [str(r) for r in (data.get("reasons") or [])]
        bash_rc = (data.get("opsRc") or {}).get("bash")
        go_rc = (data.get("opsRc") or {}).get("go")
        run_block = data.get("run") if isinstance(data.get("run"), dict) else {}
        base = {
            "verdict": verdict or None,
            "bashExit": bash_rc,
            "goExit": go_rc,
            "reasons": reasons,
            "evidence": repo_path(evidence_path),
            "runId": run_id,
            "layer": "L0-L4 driver evidence",
            "productCodeSha": run_block.get("productCodeSha"),
            "binarySha256": run_block.get("binarySha256"),
            "bashScriptSha256": run_block.get("bashScriptSha256"),
            "driverSha": run_block.get("driverSha"),
            "supersedes": run_block.get("supersedes"),
            "fixedBy": run_block.get("fixedBy"),
        }
        if op_id != name:
            base.update(status="BLOCKED",
                        reasons=reasons + ["ops.json id %r does not match its directory %r" % (op_id, name)])
            out[name] = base
            continue
        prov = provenance_problems(data, code_sha, run_id)
        if prov:
            status = "BLOCKED"
            base["reasons"] = reasons + prov
        elif verdict in FAIL_VERDICTS:
            status = "FAIL"
        elif verdict in DIFF_VERDICTS:
            if op_id in approvals and approval_applies(approvals[op_id], evidence_path):
                problems = approval_problems(approvals[op_id], evidence_path, op_id)
                if problems:
                    status = "FAIL"
                    base["reasons"] = reasons + problems
                else:
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
                facts = business_problems(op_id, data.get("details"))
                if facts:
                    status = "BLOCKED"
                    base["reasons"] = reasons + facts
                else:
                    status = "DUAL_SIDE_VERIFIED"
        elif verdict == "BASH_ONLY":
            if op_id in approvals and approval_applies(approvals[op_id], evidence_path):
                problems = approval_problems(approvals[op_id], evidence_path, op_id)
                if problems:
                    status = "FAIL"
                    base["reasons"] = reasons + problems
                else:
                    status = "APPROVED_SINGLE_SIDE"
                    base["approval"] = approvals[op_id]
            else:
                status = "BASH_ONLY"
        elif verdict in INCOMPLETE_VERDICTS:
            status = "BLOCKED"
        else:
            status = "BLOCKED"
            base["reasons"] = reasons + ["unrecognised or missing verdict %r; evidence is not acceptable" % verdict]
        base["status"] = status
        out[op_id] = base
    return out


def sweep_results(root, approvals=None, code_sha=""):
    """Parse assertions.txt from an ops sweep: an ID passes with no FAIL.

    A declared sweep without a readable assertions.txt, with malformed lines, or
    with no OPS assertion at all is rejected instead of silently contributing an
    empty (and therefore green-looking) result. A clean Go-only row still needs
    an explicit scoped approval before it counts as resolved.

    The sweep script never records the product exit code. The ledger keeps that
    unknown (None) instead of inventing a zero; only the approval can resolve a
    one-sided row, and it must be bound to this file.
    """
    approvals = approvals or {}
    out = {}
    if not root:
        return out
    run_id = os.path.basename(os.path.normpath(root))
    prov = provenance_problems_run(read_json(os.path.join(root, "run.json")), code_sha, run_id)
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
        row = {
            "status": "GO_ONLY" if entry["fail"] == 0 else "FAIL",
            "verdict": "PASS" if entry["fail"] == 0 else "FAIL",
            "goExit": None,
            "expectedRc": None,
            "goExitRecorded": False,
            "reasons": entry["failText"],
            "assertions": entry["pass"] + entry["fail"],
            "evidence": repo_path(path),
            "runId": run_id,
            "layer": "L0-L2 Go CLI evidence",
        }
        if prov:
            row["status"] = "BLOCKED"
            row["reasons"] = entry["failText"] + prov
        elif row["status"] == "GO_ONLY" and op_id in approvals and approval_applies(approvals[op_id], path):
            problems = approval_problems(approvals[op_id], path, op_id)
            if problems:
                row["status"] = "FAIL"
                row["reasons"] = entry["failText"] + problems
            else:
                row["status"] = "APPROVED_SINGLE_SIDE"
                row["approval"] = approvals[op_id]
        out[op_id] = row
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix-evidence", action="append", default=[],
                    help="run_p2_matrix.sh output tree (repeatable; later runs fill gaps)")
    ap.add_argument("--ops-evidence", action="append", default=[],
                    help="run_ops_sweep.sh / run_ops_realroot.sh output tree (repeatable)")
    ap.add_argument("--code-sha", default="")
    ap.add_argument("--approved-diffs", default="",
                    help="explicit approval JSON for declared differences and single-side rows; "
                         "without it both remain FAIL/single-side")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="exit 0 even when rows are not dual-side verified (never for final acceptance)")
    ap.add_argument("--out", default="tests/e2e-diff/ledger.json")
    ap.add_argument("--matrix-json", default="tests/e2e-diff/matrix.json")
    ap.add_argument("--acceptance-json", default="docs/go-evolution/hardening/acceptance.json")
    ap.add_argument("--allow-repo-write", action="store_true",
                    help="allow writing the tracked ledger/matrix/acceptance artifacts; "
                         "tests and ad-hoc runs must keep every output in a temp directory")
    args = ap.parse_args()

    try:
        approvals = load_approvals(args.approved_diffs)
        matrix_runs = [matrix_results(root, approvals, args.code_sha) for root in args.matrix_evidence]
        sweep_runs = [sweep_results(root, approvals, args.code_sha) for root in args.ops_evidence]
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
        "APPROVED_SINGLE_SIDE": 4,
        "DUAL_SIDE_VERIFIED": 5,
        "APPROVED_DIFF": 6,
        "FAIL": 7,
    }
    chosen = {}
    history = {}
    for record in matrix_runs + sweep_runs:
        for op_id, entry in record.items():
            history.setdefault(op_id, []).append(entry)
            if op_id not in chosen or rank[entry["status"]] > rank[chosen[op_id]["status"]]:
                chosen[op_id] = entry

    # A failure stays a failure unless a later run of the same frozen candidate
    # explicitly names the failed run it supersedes, states the fix commit and
    # carries verified evidence. Silently dropping a red run is impossible.
    for op_id, entries in history.items():
        current = chosen.get(op_id)
        if not current or current["status"] != "FAIL":
            continue
        failed = [e for e in entries if e["status"] == "FAIL"]
        good = [e for e in entries if e["status"] in RESOLVED_STATUSES]
        for candidate in good:
            superseded = str(candidate.get("supersedes") or "").strip()
            fixed_by = str(candidate.get("fixedBy") or "").strip()
            if not superseded or not fixed_by:
                continue
            if not any(f.get("runId") == superseded for f in failed):
                continue
            merged = dict(candidate)
            merged["supersededRuns"] = sorted({f.get("runId") for f in failed if f.get("runId")})
            merged["fixedBy"] = fixed_by
            chosen[op_id] = merged
            break

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
        runs = history.get(op_id) or []
        if len(runs) > 1:
            entry["history"] = [
                {"runId": r.get("runId"), "status": r.get("status"),
                 "verdict": r.get("verdict"), "evidence": r.get("evidence")}
                for r in runs
            ]
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
    approved_single_side_ids = [e["id"] for e in results if e["status"] == "APPROVED_SINGLE_SIDE"]
    unresolved = [e["id"] for e in results if e["status"] not in RESOLVED_STATUSES]

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
            "APPROVED_SINGLE_SIDE": len(approved_single_side_ids),
        },
        "dualSideVerifiedIds": dual_ids,
        "goOnlyIds": go_ids,
        "failIds": fail_ids,
        "bashOnlyIds": bash_ids,
        "blockedIds": blocked_ids,
        "notRunIds": not_run_ids,
        "approvedDiffIds": approved_diff_ids,
        "approvedSingleSideIds": approved_single_side_ids,
        "unresolvedIds": unresolved,
        "sources": {
            "matrixEvidence": [repo_path(p) for p in args.matrix_evidence],
            "opsEvidence": [repo_path(p) for p in args.ops_evidence],
        },
        "results": results,
    }
    matrix = read_json(args.matrix_json)
    acceptance = read_json(args.acceptance_json)

    # The three summaries are tracked repository artifacts. A test or an ad-hoc
    # probe that forgets one path flag must fail instead of silently rewriting
    # the official acceptance record; only an explicit final build opts in.
    toplevel = git_toplevel()
    targets = [args.out]
    if matrix is not None:
        targets.append(args.matrix_json)
    if acceptance is not None:
        targets.append(args.acceptance_json)
    if not args.allow_repo_write:
        offenders = [p for p in targets if inside_repo(p, toplevel)]
        if offenders:
            print("ledger error: refusing to overwrite tracked acceptance artifacts without "
                  "--allow-repo-write: %s" % ", ".join(offenders), file=sys.stderr)
            return 2

    write_json_atomic(args.out, ledger)

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
        "approvedSingleSide": len(approved_single_side_ids),
        "approvedSingleSideIds": approved_single_side_ids,
        "unresolvedIds": unresolved,
        "generatedAt": generated,
        "codeSha": sha,
        "source": "tests/e2e-diff/ledger.json",
    }

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
            "approvedSingleSideOps": summary["approvedSingleSide"],
            "dualSideVerifiedIds": dual_ids,
            "goOnlyIds": go_ids,
            "failIds": fail_ids,
            "bashOnlyIds": bash_ids,
            "approvedDiffIds": approved_diff_ids,
            "approvedSingleSideIds": approved_single_side_ids,
            "notRunIds": not_run_ids,
            "generatedFrom": "tests/e2e-diff/ledger.json",
            "generatedAt": generated,
            "codeSha": sha,
        }
        write_json_atomic(args.matrix_json, matrix)

    if acceptance is not None:
        acceptance["ops"] = summary
        write_json_atomic(args.acceptance_json, acceptance)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if fail_ids:
        print("ledger: FAIL rows present: %s" % ", ".join(fail_ids), file=sys.stderr)
        return 1
    if unresolved and not args.allow_incomplete:
        print("ledger: %d row(s) have neither dual-side verification nor an external approval: %s"
              % (len(unresolved), ", ".join(unresolved)), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
