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


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        if isinstance(data, str):
            fh.write(data)
        else:
            json.dump(data, fh)


def ops(root, op_id, verdict, bash_rc=0, go_rc=0, include_rc=True, reasons=None):
    data = {"id": op_id, "verdict": verdict, "reasons": reasons or []}
    if include_rc:
        data["opsRc"] = {"bash": bash_rc, "go": go_rc}
    write(os.path.join(root, "p2", op_id, "ops.json"), data)


class LedgerContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.matrix = os.path.join(self.root, "matrix")
        self.out = os.path.join(self.root, "ledger.json")

    def tearDown(self):
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
              {"id": "OPS-03", "result": "DIFF", "reasons": ["shortId residue after remove"]})
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
        write(approvals, {"approved": [{"id": "OPS-07", "approvedBy": "product-owner", "reason": "known ok"}]})
        proc, ledger = self.run_ledger(matrix=self.matrix, approvals=approvals)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-07")["status"], "APPROVED_DIFF")

    def test_failure_in_any_run_wins(self):
        good = os.path.join(self.root, "good")
        bad = os.path.join(self.root, "bad")
        ops(good, "OPS-08", "PASS")
        ops(bad, "OPS-08", "FAIL")
        cmd = [sys.executable, SCRIPT, "--code-sha", "test", "--out", self.out,
               "--matrix-json", os.path.join(self.root, "matrix.json"),
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
        sweep = os.path.join(self.root, "sweep")
        write(os.path.join(sweep, "assertions.txt"),
              "PASS\tOPS-10 remove user\nFAIL\tOPS-10 residue still present\n")
        proc, ledger = self.run_ledger(ops_dirs=[sweep])
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.row(ledger, "OPS-10")["status"], "FAIL")

    def test_cert_clear_difference_without_ops_json_is_not_dropped(self):
        # OPS-27's driver writes cert-clear-difference.json instead of ops.json;
        # the safety difference must surface as a failure, never vanish.
        write(os.path.join(self.matrix, "p2", "OPS-27", "cert-clear-difference.json"),
              {"id": "OPS-27", "result": "DIFF",
               "reasons": ["Bash rm -rf removes the third-party canary"]})
        proc, ledger = self.run_ledger(matrix=self.matrix)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        row = self.row(ledger, "OPS-27")
        self.assertEqual(row["status"], "FAIL")
        self.assertIn("third-party canary", " ".join(row["reasons"]))

    def test_allow_incomplete_keeps_evidence_visible(self):
        sweep = os.path.join(self.root, "sweep")
        write(os.path.join(sweep, "assertions.txt"), "PASS\tOPS-11 add user\n")
        proc, ledger = self.run_ledger(ops_dirs=[sweep], allow_incomplete=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.row(ledger, "OPS-11")["status"], "GO_ONLY")


if __name__ == "__main__":
    unittest.main()
