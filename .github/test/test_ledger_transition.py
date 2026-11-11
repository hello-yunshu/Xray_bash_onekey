#!/usr/bin/env python3
"""Negative and positive tests for check_ledger_transition.py.

The release rules are only real if a forged ledger is rejected. These tests
drive the script as a subprocess and assert the exit code, so they exercise the
same entry point CI uses.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests/go-parity/parity/scripts/check_ledger_transition.py"
PENDING = "PENDING_GO_IMPLEMENTATION"
VERIFIED = "VERIFIED_GO_PARITY"
APPROVED = "APPROVED_SAFE_DIVERGENCE"


def feature(fid, status, evidence=None):
    return {
        "id": fid,
        "name": fid,
        "priority": "P0",
        "owner_stage": "02",
        "status": status,
        "evidence": evidence,
        "minimum_contract": "same input, same output",
    }


class LedgerTransitionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.write("base.json", [feature("F01", PENDING), feature("F02", PENDING),
                                             feature("F03", PENDING)])

    def write(self, name, features):
        path = self.root / name
        path.write_text(json.dumps({"baseline_commit": "x", "features": features}))
        return path

    def evidence(self, name="evidence/F01.txt", content="proof\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return name

    def invoke(self, head):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--base", str(self.base),
             "--head", str(head), "--root", str(self.root)],
            capture_output=True, text=True,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def assert_rejected(self, head, needle):
        rc, out = self.invoke(head)
        self.assertEqual(rc, 2, out)
        self.assertIn("REJECTED", out)
        self.assertIn(needle, out)

    # --- forged successes -------------------------------------------------

    def test_verified_without_evidence_is_rejected(self):
        head = self.write("head.json", [feature("F01", VERIFIED), feature("F02", PENDING),
                                        feature("F03", PENDING)])
        self.assert_rejected(head, "requires an evidence path")

    def test_verified_with_missing_evidence_is_rejected(self):
        head = self.write("head.json", [feature("F01", VERIFIED, "evidence/nope.txt"),
                                        feature("F02", PENDING), feature("F03", PENDING)])
        self.assert_rejected(head, "does not exist")

    def test_verified_with_empty_evidence_is_rejected(self):
        rel = self.evidence(content="")
        head = self.write("head.json", [feature("F01", VERIFIED, rel), feature("F02", PENDING),
                                        feature("F03", PENDING)])
        self.assert_rejected(head, "is empty")

    def test_verified_with_absolute_evidence_is_rejected(self):
        rel = self.evidence()
        head = self.write("head.json", [feature("F01", VERIFIED, str(self.root / rel)),
                                        feature("F02", PENDING), feature("F03", PENDING)])
        self.assert_rejected(head, "repository-relative")

    def test_evidence_escaping_the_repository_is_rejected(self):
        head = self.write("head.json", [feature("F01", VERIFIED, "../outside.txt"),
                                        feature("F02", PENDING), feature("F03", PENDING)])
        self.assert_rejected(head, "escapes the repository")

    # --- forbidden transitions -------------------------------------------

    def test_reverse_transition_is_rejected(self):
        base = self.write("base.json", [feature("F01", VERIFIED, self.evidence()),
                                        feature("F02", PENDING), feature("F03", PENDING)])
        head = self.write("head.json", [feature("F01", PENDING), feature("F02", PENDING),
                                        feature("F03", PENDING)])
        self.base = base
        self.assert_rejected(head, "forbidden transition")

    def test_verified_to_approved_is_rejected(self):
        base = self.write("base.json", [feature("F01", VERIFIED, self.evidence()),
                                        feature("F02", PENDING), feature("F03", PENDING)])
        head = self.write("head.json", [feature("F01", APPROVED, self.evidence()),
                                        feature("F02", PENDING), feature("F03", PENDING)])
        self.base = base
        self.assert_rejected(head, "forbidden transition")

    def test_pending_to_blocked_is_rejected(self):
        head = self.write("head.json", [feature("F01", "BLOCKED"), feature("F02", PENDING),
                                        feature("F03", PENDING)])
        self.assert_rejected(head, "forbidden transition")

    def test_id_rename_is_rejected(self):
        head = self.write("head.json", [feature("F99", PENDING), feature("F02", PENDING),
                                        feature("F03", PENDING)])
        self.assert_rejected(head, "renamed")

    def test_removed_item_is_rejected(self):
        head = self.write("head.json", [feature("F01", PENDING), feature("F02", PENDING)])
        self.assert_rejected(head, "removed")

    def test_added_item_is_rejected(self):
        head = self.write("head.json", [feature("F01", PENDING), feature("F02", PENDING),
                                        feature("F03", PENDING), feature("F04", PENDING)])
        self.assert_rejected(head, "added")

    def test_reordered_items_are_rejected(self):
        head = self.write("head.json", [feature("F02", PENDING), feature("F01", PENDING),
                                        feature("F03", PENDING)])
        self.assert_rejected(head, "reordered")

    # --- allowed transitions ---------------------------------------------

    def test_verified_with_real_evidence_passes(self):
        rel = self.evidence()
        head = self.write("head.json", [feature("F01", VERIFIED, rel), feature("F02", PENDING),
                                        feature("F03", PENDING)])
        rc, out = self.invoke(head)
        self.assertEqual(rc, 0, out)
        self.assertIn("1 item(s) promoted", out)

    def test_approved_with_evidence_passes(self):
        rel = self.evidence("evidence/approval.txt", "approved by maintainer\n")
        head = self.write("head.json", [feature("F01", APPROVED, rel), feature("F02", PENDING),
                                        feature("F03", PENDING)])
        rc, out = self.invoke(head)
        self.assertEqual(rc, 0, out)

    def test_approved_without_evidence_is_rejected(self):
        head = self.write("head.json", [feature("F01", APPROVED), feature("F02", PENDING),
                                        feature("F03", PENDING)])
        self.assert_rejected(head, "requires an evidence path")

    def test_unchanged_ledger_passes(self):
        rc, out = self.invoke(self.base)
        self.assertEqual(rc, 0, out)
        self.assertIn("no status change", out)

    # --- the committed ledger must satisfy its own policy ----------------

    def test_committed_ledger_is_a_valid_noop_transition(self):
        ledger = ROOT / "tests/go-parity/parity/cases/feature_contracts.json"
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--base", str(ledger),
             "--head", str(ledger), "--root", str(ROOT)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
