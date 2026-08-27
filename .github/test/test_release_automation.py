#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_automation", ROOT / "scripts/release_automation.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseAutomationTests(unittest.TestCase):
    def _canonical_fixture(self, root: Path) -> tuple[Path, Path]:
        rill = root / "rill"
        xray = root / "xray"
        integration = rill / "integrations/xray_bash_onekey"
        files = {
            "rill_payload/python/rill_xray_agent/new.py": b"new",
            "scripts/rill_xray_agent_new.sh": b"#!/bin/sh\n",
            "systemd/rill-xray-agent-new.service": b"[Unit]\n",
            "assets/rill-xray-agent-xray-bundle.tar.gz": b"bundle",
        }
        manifest_files = {}
        for rel, blob in files.items():
            source = integration / "repository_files" / rel
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(blob)
            manifest_files[f"repository_files/{rel}"] = MODULE.hashlib.sha256(blob).hexdigest()
        manifest = {"schemaVersion": 1, "bundleSha256": MODULE.hashlib.sha256(b"bundle").hexdigest(),
                    "canonicalDigest": "a" * 64, "files": manifest_files}
        integration.mkdir(parents=True, exist_ok=True)
        (integration / "CANONICAL_MANIFEST.json").write_text(json.dumps(manifest))
        for rel, blob in {
                "rill_payload/python/rill_xray_agent/old.py": b"old",
                "scripts/rill_xray_agent_stale.sh": b"old",
                "scripts/host-owned.sh": b"keep",
        }.items():
            target = xray / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
        return xray, rill

    def test_canonical_resolver_covers_all_manifest_owned_roots_and_stale_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            xray, rill = self._canonical_fixture(Path(tmp))
            owned = MODULE.canonical_owned_files(rill)
            self.assertEqual(
                {target.as_posix() for _source, target in owned},
                {
                    "rill_payload/python/rill_xray_agent/new.py",
                    "scripts/rill_xray_agent_new.sh",
                    "systemd/rill-xray-agent-new.service",
                    "assets/rill-xray-agent-xray-bundle.tar.gz",
                },
            )
            changed, stale = MODULE.canonical_drift(xray, rill)
            self.assertEqual({path.as_posix() for path in changed},
                             {path.as_posix() for _source, path in owned})
            self.assertEqual(
                {path.as_posix() for path in stale},
                {"rill_payload/python/rill_xray_agent/old.py",
                 "scripts/rill_xray_agent_stale.sh"},
            )

    def test_package_sums_are_sorted_and_exclude_generated_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "z.txt").write_text("z")
            (root / "a.txt").write_text("a")
            (root / ".git").mkdir()
            (root / ".git/config").write_text("secret")
            (root / "__pycache__").mkdir()
            (root / "__pycache__/x.pyc").write_bytes(b"cache")
            MODULE.write_package_sums(root)
            lines = (root / "PACKAGE_SHA256SUMS").read_text().splitlines()
            self.assertEqual([line.split("  ", 1)[1] for line in lines], ["a.txt", "z.txt"])

    def test_apply_then_stage_includes_stale_canonical_deletions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xray, rill = self._canonical_fixture(root)
            workflow = xray / ".github/workflows/rill-xray-agent.yml"
            workflow.parent.mkdir(parents=True, exist_ok=True)
            workflow.write_text(
                "  RILL_CANONICAL_COMMIT: " + "0" * 40 + "\n"
                "  RILL_CANONICAL_DIGEST: " + "0" * 64 + "\n"
            )
            MODULE.run("git", "init", cwd=xray)
            MODULE.run("git", "config", "user.email", "test@example.com", cwd=xray)
            MODULE.run("git", "config", "user.name", "test", cwd=xray)
            MODULE.run("git", "add", ".", cwd=xray)
            MODULE.run("git", "commit", "-m", "fixture", cwd=xray)

            with mock.patch.object(MODULE, "run") as run_mock:
                MODULE.apply_rill(xray, rill, "a" * 40)
                run_mock.assert_called_once()
            MODULE.stage_rill(xray, rill)
            staged = set(MODULE.subprocess.check_output(
                ["git", "diff", "--cached", "--name-status"],
                cwd=xray, text=True).splitlines())
            self.assertIn("D\trill_payload/python/rill_xray_agent/old.py", staged)
            self.assertIn("D\tscripts/rill_xray_agent_stale.sh", staged)

    def test_update_api_changes_online_fields_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xray = root / "xray"
            api = root / "api"
            xray.mkdir()
            api.mkdir()
            (xray / "install.sh").write_text('shell_version="3.2.0"\n')
            original = {
                "update_date": "old",
                "shell_online_version": "3.1.0",
                "shell_tested_version": "2.8.3",
                "shell_upgrade_details": "old details",
                "xray_online_version": "26.3.27",
            }
            (api / "xray_shell_versions.json").write_text(json.dumps(original))
            changed = MODULE.update_api(xray, api, "new details", "2026-08-14 02:00")
            result = json.loads((api / "xray_shell_versions.json").read_text())
            self.assertTrue(changed)
            self.assertEqual(result["shell_online_version"], "3.2.0")
            self.assertEqual(result["shell_tested_version"], "2.8.3")
            self.assertEqual(result["xray_online_version"], "26.3.27")

    def test_update_api_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xray = root / "xray"
            api = root / "api"
            xray.mkdir()
            api.mkdir()
            (xray / "install.sh").write_text('shell_version="3.2.0"\n')
            manifest = {"shell_online_version": "3.2.0"}
            target = api / "xray_shell_versions.json"
            target.write_text(json.dumps(manifest))
            self.assertFalse(MODULE.update_api(xray, api, "unused", None))
            self.assertEqual(json.loads(target.read_text()), manifest)

    def test_update_api_refuses_downgrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xray = root / "xray"
            api = root / "api"
            xray.mkdir()
            api.mkdir()
            (xray / "install.sh").write_text('shell_version="3.1.0"\n')
            (api / "xray_shell_versions.json").write_text(
                json.dumps({"shell_online_version": "3.2.0"})
            )
            with self.assertRaises(SystemExit):
                MODULE.update_api(xray, api, "details", None)


if __name__ == "__main__":
    unittest.main()
