#!/usr/bin/env python3
"""Negative tests for the acceptance ledger builder.

The independent audit (D05/D06/D09) found that the old builder silently dropped
unrecognised verdicts, accepted expected-difference verdicts as passes, and
accepted evidence directories with no assertions. These tests pin the corrected
behaviour: a red or an unapproved difference can never be reported green.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "build_ledger.py")


def repo_root():
    try:
        out = subprocess.check_output(
            ["git", "-C", HERE, "rev-parse", "--show-toplevel"],
            text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return out or None


ROOT = repo_root()
OFFICIAL = [
    os.path.join(ROOT, "tests/e2e-diff/ledger.json"),
    os.path.join(ROOT, "tests/e2e-diff/matrix.json"),
    os.path.join(ROOT, "docs/go-evolution/hardening/acceptance.json"),
] if ROOT else []


def digest(path):
    try:
        with open(path, "rb") as fh:
            import hashlib
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        if isinstance(data, str):
            fh.write(data)
        else:
            json.dump(data, fh)


def provenance(root, **overrides):
    run = {
        "productCodeSha": "test",
        "binarySha256": "b" * 64,
        "bashScriptSha256": "a" * 64,
        "driverSha": "c" * 40,
        "runId": os.path.basename(os.path.normpath(root)),
        "layer": "synthetic unit evidence",
        "startedAt": "2026-11-24T00:00:00Z",
    }
    run.update(overrides)
    return run


def contract_details(op_id):
    """Business facts for the rows the audit named explicitly."""
    if op_id in ("OPS-01", "OPS-02"):
        side = {"addedClients": 1, "removedClients": 1, "clientConnected": True}
        return {"bash": dict(side), "go": dict(side)}
    if op_id == "OPS-04":
        side = {"portListening": True, "clientConnected": True, "shareInfo": "vless://example"}
        return {"bash": dict(side), "go": dict(side)}
    if op_id == "OPS-08":
        side = {"sniProbe": {"unknownSniPolicy": "isolate", "knownSniOk": True}}
        return {"bash": dict(side), "go": dict(side)}
    return {}


def ops(root, op_id, verdict, bash_rc=0, go_rc=0, include_rc=True, reasons=None,
        details=None, run=None):
    data = {"id": op_id, "verdict": verdict, "reasons": reasons or [],
            "run": run if run is not None else provenance(root),
            "details": details if details is not None else contract_details(op_id)}
    if include_rc:
        data["opsRc"] = {"bash": bash_rc, "go": go_rc}
    write(os.path.join(root, "p2", op_id, "ops.json"), data)


def approval(op_id, evidence_path, scope="documented difference", **overrides):
    item = {
        "id": op_id, "opId": op_id, "approvedBy": "product-owner",
        "reason": "reviewed and accepted", "scope": scope,
        "expiresAt": "2027-12-31", "fingerprint": digest(evidence_path),
    }
    item.update(overrides)
    return item


def sweep(root, text):
    write(os.path.join(root, "assertions.txt"), text)
    write(os.path.join(root, "run.json"), provenance(root))


class LedgerContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.matrix = os.path.join(self.root, "matrix")
        self.out = os.path.join(self.root, "ledger.json")
        # Snapshot the tracked summaries so any test that accidentally writes to
        # the repository fails loudly instead of polluting the official record.
        self.official = {path: digest(path) for path in OFFICIAL}

    def tearDown(self):
        for path, before in self.official.items():
            self.assertEqual(before, digest(path),
                             "test modified the tracked acceptance artifact %s" % path)
        self.tmp.cleanup()

    def run_ledger(self, matrix=None, ops_dirs=(), approvals=None, allow_incomplete=False):
        cmd = [sys.executable, SCRIPT, "--code-sha", "test", "--out", self.out,
               "--matrix-json", os.path.join(self.root, "matrix.json"),
               "--acceptance-json", os.path.join(self.root, "acceptance.json")]
        if matrix:
            cmd += ["--matrix-evidence", matrix]
        for d in ops_dirs:
            cmd += ["--ops-evidence", d]
        if approvals:
            cmd += ["--approved-diffs", approvals]
        if allow_incomplete:
            cmd.append("--allow-incomplete")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        ledger = None
        if os.path.exists(self.out):
            with open(self.out, encoding="utf-8") as fh:
                ledger = json.load(fh)
        return proc, ledger

    def row(self, ledger, op_id):
        return next(r for r in ledger["results"] if r["id"] == op_id)

    def test_all_dual_verified_exits_zero(self):
        ops(self.matrix, "OPS-01", "PASS")
        proc, ledger = self.run_ledger(matrix=self.matrix, allow_incomplete=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-01")["status"], "DUAL_SIDE_VERIFIED")

    def test_diff_verdict_is_failure_not_dropped(self):
        ops(self.matrix, "OPS-03", "DIFF", bash_rc=0, go_rc=0)
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-03")["status"], "FAIL")

    def test_declared_difference_without_ops_json_is_not_dropped(self):
        # OPS-03's driver writes shortid-difference.json instead of ops.json.
        # That declared difference must surface as a failure, not vanish.
        write(os.path.join(self.matrix, "p2", "OPS-03", "shortid-difference.json"),
              {"id": "OPS-03", "result": "DIFF", "run": provenance(self.matrix),
               "reasons": ["shortId residue after remove"]})
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        row = self.row(ledger, "OPS-03")
        self.assertEqual(row["status"], "FAIL")
        self.assertIn("shortId residue after remove", row["reasons"])
        self.assertTrue(any("approval" in r for r in row["reasons"]))

    def test_pass_with_nonzero_exit_is_failure(self):
        ops(self.matrix, "OPS-02", "PASS", bash_rc=0, go_rc=1)
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-02")["status"], "FAIL")

    def test_pass_without_both_exit_codes_is_incomplete(self):
        ops(self.matrix, "OPS-04", "PASS", include_rc=False)
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-04")["status"], "BLOCKED")

    def test_missing_ops_json_is_blocked_not_silent(self):
        os.makedirs(os.path.join(self.matrix, "p2", "OPS-05"))
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-05")["status"], "BLOCKED")

    def test_expected_diff_without_approval_is_failure(self):
        ops(self.matrix, "OPS-06", "EXPECTED_DIFF")
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-06")["status"], "FAIL")

    def test_approved_diff_is_never_counted_as_verified(self):
        ops(self.matrix, "OPS-07", "EXPECTED_DIFF")
        approvals = os.path.join(self.root, "approvals.json")
        evidence = os.path.join(self.matrix, "p2", "OPS-07", "ops.json")
        write(approvals, {"approved": [approval("OPS-07", evidence)]})
        # Other rows have no evidence, so relax only the exit code; the approval
        # itself must still remove OPS-07 from the unresolved set.
        proc, ledger = self.run_ledger(matrix=self.matrix, approvals=approvals, allow_incomplete=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-07")["status"], "APPROVED_DIFF")
        self.assertNotIn("OPS-07", ledger["dualSideVerifiedIds"])
        self.assertNotIn("OPS-07", ledger["unresolvedIds"])

    def test_raw_diff_verdict_needs_approval_like_declared_diff(self):
        # Drivers write verdict=DIFF for documented differences (OPS-12/13/14/16/25/26).
        ops(self.matrix, "OPS-12", "DIFF")
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-12")["status"], "FAIL")

        approvals = os.path.join(self.root, "approvals.json")
        evidence = os.path.join(self.matrix, "p2", "OPS-12", "ops.json")
        write(approvals, {"approved": [approval("OPS-12", evidence, scope="log source")]})
        proc, ledger = self.run_ledger(matrix=self.matrix, approvals=approvals, allow_incomplete=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-12")["status"], "APPROVED_DIFF")
        self.assertNotIn("OPS-12", ledger["unresolvedIds"])

    def test_approved_single_side_is_resolved_but_not_dual(self):
        sweep_dir = os.path.join(self.root, "sweep")
        sweep(sweep_dir, "PASS\tOPS-18 tcp tuning\n")
        approvals = os.path.join(self.root, "approvals.json")
        write(approvals, {"approved": [approval(
            "OPS-18", os.path.join(sweep_dir, "assertions.txt"),
            scope="host-bbr-requires-real-vps")]})
        proc, ledger = self.run_ledger(ops_dirs=[sweep_dir], approvals=approvals, allow_incomplete=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        row = self.row(ledger, "OPS-18")
        self.assertEqual(row["status"], "APPROVED_SINGLE_SIDE")
        self.assertEqual(row["approval"]["scope"], "host-bbr-requires-real-vps")
        self.assertNotIn("OPS-18", ledger["dualSideVerifiedIds"])
        self.assertNotIn("OPS-18", ledger["unresolvedIds"])
        self.assertEqual(ledger["counts"]["APPROVED_SINGLE_SIDE"], 1)

    def test_single_side_approval_without_scope_is_rejected(self):
        sweep_dir = os.path.join(self.root, "sweep")
        sweep(sweep_dir, "PASS\tOPS-23 speed test\n")
        approvals = os.path.join(self.root, "approvals.json")
        write(approvals, {"approved": [{"id": "OPS-23", "approvedBy": "product-owner",
                                        "reason": "go side proven"}]})
        proc, _ = self.run_ledger(ops_dirs=[sweep_dir], approvals=approvals)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("scope", proc.stderr)

    def test_approval_cannot_rescue_a_failed_row(self):
        sweep_dir = os.path.join(self.root, "sweep")
        sweep(sweep_dir, "FAIL\tOPS-24 geo refresh broke\n")
        approvals = os.path.join(self.root, "approvals.json")
        write(approvals, {"approved": [approval(
            "OPS-24", os.path.join(sweep_dir, "assertions.txt"), scope="external download")]})
        proc, ledger = self.run_ledger(ops_dirs=[sweep_dir], approvals=approvals)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-24")["status"], "FAIL")

    def test_approved_bash_only_row_is_single_side(self):
        ops(self.matrix, "OPS-30", "BASH-ONLY")
        approvals = os.path.join(self.root, "approvals.json")
        evidence = os.path.join(self.matrix, "p2", "OPS-30", "ops.json")
        write(approvals, {"approved": [approval("OPS-30", evidence, scope="language switch")]})
        proc, ledger = self.run_ledger(matrix=self.matrix, approvals=approvals, allow_incomplete=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-30")["status"], "APPROVED_SINGLE_SIDE")
        self.assertNotIn("OPS-30", ledger["unresolvedIds"])

    def test_failure_in_any_run_wins(self):
        good = os.path.join(self.root, "good")
        bad = os.path.join(self.root, "bad")
        ops(good, "OPS-08", "PASS")
        ops(bad, "OPS-08", "FAIL")
        cmd = [sys.executable, SCRIPT, "--code-sha", "test", "--out", self.out,
               "--matrix-json", os.path.join(self.root, "matrix.json"),
               "--acceptance-json", os.path.join(self.root, "acceptance.json"),
               "--matrix-evidence", good, "--matrix-evidence", bad]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        with open(self.out, encoding="utf-8") as fh:
            ledger = json.load(fh)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-08")["status"], "FAIL")

    def test_sweep_without_assertions_is_rejected(self):
        sweep = os.path.join(self.root, "sweep")
        os.makedirs(sweep)
        proc, _ = self.run_ledger(ops_dirs=[sweep])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("assertions.txt", proc.stderr)

    def test_sweep_malformed_assertion_is_rejected(self):
        sweep = os.path.join(self.root, "sweep")
        write(os.path.join(sweep, "assertions.txt"), "OPS-09 looks fine\n")
        proc, _ = self.run_ledger(ops_dirs=[sweep])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("PASS/FAIL", proc.stderr)

    def test_sweep_fail_assertion_wins(self):
        sweep_dir = os.path.join(self.root, "sweep")
        sweep(sweep_dir,
              "PASS\tOPS-10 remove user\nFAIL\tOPS-10 residue still present\n")
        proc, ledger = self.run_ledger(ops_dirs=[sweep_dir])
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.row(ledger, "OPS-10")["status"], "FAIL")

    def test_cert_clear_difference_without_ops_json_is_not_dropped(self):
        # OPS-27's driver writes cert-clear-difference.json instead of ops.json;
        # the safety difference must surface as a failure, never vanish.
        write(os.path.join(self.matrix, "p2", "OPS-27", "cert-clear-difference.json"),
              {"id": "OPS-27", "result": "DIFF", "run": provenance(self.matrix),
               "reasons": ["Bash rm -rf removes the third-party canary"]})
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        row = self.row(ledger, "OPS-27")
        self.assertEqual(row["status"], "FAIL")
        self.assertIn("third-party canary", " ".join(row["reasons"]))

    def test_forgotten_acceptance_path_cannot_pollute_official_record(self):
        # D05 regression: the old test forgot --acceptance-json and rewrote the
        # tracked summary with synthetic test data. The builder must now refuse
        # that write outright, before touching any output.
        ops(self.matrix, "OPS-08", "FAIL")
        before = {path: digest(path) for path in OFFICIAL}
        cmd = [sys.executable, SCRIPT, "--code-sha", "test", "--out", self.out,
               "--matrix-json", os.path.join(self.root, "matrix.json"),
               "--matrix-evidence", self.matrix]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("refusing to overwrite tracked acceptance artifacts", proc.stderr)
        self.assertFalse(os.path.exists(self.out), "no output may be written when the guard trips")
        for path in OFFICIAL:
            self.assertEqual(before[path], digest(path))

    def test_explicit_repo_write_flag_is_required_for_tracked_paths(self):
        # Positive control: the final build can still write deliberately.
        official_copy = os.path.join(self.root, "acceptance-copy.json")
        write(official_copy, {"schemaVersion": 1})
        ops(self.matrix, "OPS-01", "PASS")
        cmd = [sys.executable, SCRIPT, "--code-sha", "test", "--out", self.out,
               "--matrix-json", os.path.join(self.root, "matrix.json"),
               "--acceptance-json", official_copy, "--allow-repo-write",
               "--matrix-evidence", self.matrix, "--allow-incomplete"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(official_copy, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["ops"]["codeSha"], "test")

    def test_allow_incomplete_keeps_evidence_visible(self):
        sweep_dir = os.path.join(self.root, "sweep")
        sweep(sweep_dir, "PASS\tOPS-11 add user\n")
        proc, ledger = self.run_ledger(ops_dirs=[sweep_dir], allow_incomplete=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-11")["status"], "GO_ONLY")

    def test_pass_without_provenance_is_blocked(self):
        # D05/B2 regression: two zero exit codes are not evidence that the frozen
        # candidate produced them.
        write(os.path.join(self.matrix, "p2", "OPS-05", "ops.json"),
              {"id": "OPS-05", "verdict": "PASS", "opsRc": {"bash": 0, "go": 0}})
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        row = self.row(ledger, "OPS-05")
        self.assertEqual(row["status"], "BLOCKED")
        self.assertTrue(any("provenance" in r for r in row["reasons"]))

    def test_stale_candidate_evidence_is_blocked(self):
        ops(self.matrix, "OPS-05", "PASS",
            run=provenance(self.matrix, productCodeSha="deadbeef"))
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        row = self.row(ledger, "OPS-05")
        self.assertEqual(row["status"], "BLOCKED")
        self.assertTrue(any("not the frozen" in r for r in row["reasons"]))

    def test_pass_without_business_fact_is_blocked(self):
        ops(self.matrix, "OPS-01", "PASS", details={})
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        row = self.row(ledger, "OPS-01")
        self.assertEqual(row["status"], "BLOCKED")
        self.assertTrue(any("business evidence" in r for r in row["reasons"]),
                        row["reasons"])

    def test_approval_fingerprint_must_match_cited_evidence(self):
        ops(self.matrix, "OPS-07", "EXPECTED_DIFF")
        approvals = os.path.join(self.root, "approvals.json")
        evidence = os.path.join(self.matrix, "p2", "OPS-07", "ops.json")
        write(approvals, {"approved": [approval("OPS-07", evidence, fingerprint="0" * 64)]})
        proc, ledger = self.run_ledger(matrix=self.matrix, approvals=approvals)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-07")["status"], "FAIL")
        self.assertTrue(any("fingerprint" in r for r in self.row(ledger, "OPS-07")["reasons"]))

    def test_expired_approval_does_not_resolve_a_difference(self):
        ops(self.matrix, "OPS-07", "EXPECTED_DIFF")
        approvals = os.path.join(self.root, "approvals.json")
        evidence = os.path.join(self.matrix, "p2", "OPS-07", "ops.json")
        write(approvals, {"approved": [approval("OPS-07", evidence, expiresAt="2020-01-01")]})
        proc, ledger = self.run_ledger(matrix=self.matrix, approvals=approvals)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-07")["status"], "FAIL")
        self.assertTrue(any("expired" in r for r in self.row(ledger, "OPS-07")["reasons"]))

    def test_failure_can_only_be_superseded_by_an_explicit_later_run(self):
        good = os.path.join(self.root, "good")
        bad = os.path.join(self.root, "bad")
        ops(good, "OPS-09", "PASS",
            run=provenance(good, supersedes="bad", fixedBy="abc1234"))
        ops(bad, "OPS-09", "FAIL")
        cmd = [sys.executable, SCRIPT, "--code-sha", "test", "--out", self.out,
               "--matrix-json", os.path.join(self.root, "matrix.json"),
               "--acceptance-json", os.path.join(self.root, "acceptance.json"),
               "--matrix-evidence", good, "--matrix-evidence", bad, "--allow-incomplete"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        with open(self.out, encoding="utf-8") as fh:
            ledger = json.load(fh)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        row = self.row(ledger, "OPS-09")
        self.assertEqual(row["status"], "DUAL_SIDE_VERIFIED")
        self.assertEqual(row["supersededRuns"], ["bad"])
        self.assertEqual(row["fixedBy"], "abc1234")

    def test_sweep_without_provenance_is_blocked(self):
        sweep_dir = os.path.join(self.root, "sweep")
        write(os.path.join(sweep_dir, "assertions.txt"), "PASS\tOPS-18 tcp tuning\n")
        proc, ledger = self.run_ledger(ops_dirs=[sweep_dir])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-18")["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
