#!/usr/bin/env python3
"""Regression tests for digest-based Agent/Xray convergence."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_automation", ROOT / "scripts/release_automation.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ConvergenceTests(unittest.TestCase):
    def fixture(self, root: Path, digest: str, commit: str = "a" * 40) -> tuple[Path, Path, Path]:
        xray = root / "xray"
        rill = root / "rill"
        xray_workflow = xray / ".github/workflows/rill-xray-agent.yml"
        xray_workflow.parent.mkdir(parents=True)
        xray_workflow.write_text(
            f"  RILL_CANONICAL_COMMIT: {commit}\n"
            f"  RILL_CANONICAL_DIGEST: {digest}\n"
        )
        manifest = rill / "integrations/xray_bash_onekey/CANONICAL_MANIFEST.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            "schemaVersion": 1,
            "canonicalDigest": digest,
            "files": {"repository_files/rill_payload/config/default.json": "0" * 64},
        }))
        output = root / "output"
        return xray, rill, output

    def drift(self, xray: Path, rill: Path, output: Path) -> str:
        MODULE.check_rill_drift(xray, rill, output)
        return output.read_text()

    def test_a_xray_pin_commit_change_with_same_digest_is_no_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            xray, rill, output = self.fixture(Path(tmp), "1" * 64, "b" * 40)
            self.assertIn("changed=false", self.drift(xray, rill, output))

    def test_b_real_canonical_change_requires_one_sync_then_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xray, rill, output = self.fixture(root, "1" * 64)
            manifest = rill / "integrations/xray_bash_onekey/CANONICAL_MANIFEST.json"
            manifest.write_text(json.dumps({
                "schemaVersion": 1,
                "canonicalDigest": "2" * 64,
                "files": {},
            }))
            self.assertIn("changed=true", self.drift(xray, rill, output))
            xray_workflow = xray / ".github/workflows/rill-xray-agent.yml"
            xray_workflow.write_text(
                "  RILL_CANONICAL_COMMIT: " + "c" * 40 + "\n"
                "  RILL_CANONICAL_DIGEST: " + "2" * 64 + "\n"
            )
            output.unlink()
            self.assertIn("changed=false", self.drift(xray, rill, output))

    def test_c_audit_only_agent_commit_change_is_no_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            xray, rill, output = self.fixture(Path(tmp), "3" * 64)
            self.assertIn("changed=false", self.drift(xray, rill, output))

    def test_d_runtime_change_syncs_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xray, rill, output = self.fixture(root, "4" * 64)
            manifest = rill / "integrations/xray_bash_onekey/CANONICAL_MANIFEST.json"
            manifest.write_text(json.dumps({
                "schemaVersion": 1,
                "canonicalDigest": "5" * 64,
                "files": {},
            }))
            self.assertIn("changed=true", self.drift(xray, rill, output))
            (xray / ".github/workflows/rill-xray-agent.yml").write_text(
                "  RILL_CANONICAL_COMMIT: " + "d" * 40 + "\n"
                "  RILL_CANONICAL_DIGEST: " + "5" * 64 + "\n"
            )
            output.unlink()
            self.assertIn("changed=false", self.drift(xray, rill, output))


if __name__ == "__main__":
    unittest.main()
