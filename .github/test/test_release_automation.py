#!/usr/bin/env python3

import importlib.util
import contextlib
import io
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
    def test_automatic_release_intent_uses_version_increase(self):
        spec = importlib.util.spec_from_file_location(
            "release_intent", ROOT / "scripts/check_shell_release_intent.py"
        )
        intent = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(intent)
        self.assertGreater(intent.version('shell_version="3.2.10"\n'),
                           intent.version('shell_version="3.2.9"\n'))
        for invalid in ('', 'shell_version="3.2"',
                        'shell_version="3.2.9"\nshell_version="3.2.10"'):
            with self.assertRaises(ValueError):
                intent.version(invalid)
        workflow = (ROOT / ".github/workflows/publish-shell-version.yml").read_text()
        self.assertIn('branches: [main]', workflow)
        self.assertIn('paths: [install.sh]', workflow)
        self.assertIn('needs: release-intent', workflow)
        self.assertIn("needs.release-intent.outputs.publish == 'true'", workflow)
        self.assertIn('workflow_dispatch:', workflow)

        for previous, current, expected in (
            ('3.2.9', '3.2.10', 'publish=true\n'),
            ('3.2.10', '3.2.10', 'publish=false\n'),
        ):
            output = io.StringIO()
            with mock.patch.object(intent.sys, 'argv', ['check', 'a' * 40]), \
                 mock.patch.object(intent.subprocess, 'check_output', return_value=f'shell_version="{previous}"\n'), \
                 mock.patch.object(intent.Path, 'read_text', return_value=f'shell_version="{current}"\n'), \
                 contextlib.redirect_stdout(output):
                intent.main()
            self.assertEqual(output.getvalue(), expected)
        with mock.patch.object(intent.sys, 'argv', ['check', '0' * 40]):
            with self.assertRaises(SystemExit):
                intent.main()

    def test_release_workflow_keeps_existing_release_immutable(self):
        workflow = (ROOT / ".github/workflows/publish-shell-version.yml").read_text()
        for fragment in (
            'uses: ./.github/workflows/test-install.yml',
            'candidate_commit: ${{ needs.candidate.outputs.candidate_commit }}',
            'canonical_digest: ${{ needs.candidate.outputs.canonical_digest }}',
            'gh release download "$tag"',
            '(cd "$SUMS_DIR/download" && sha256sum -c SHA256SUMS)',
            'release-manifest.json',
            'qualificationRunId',
            'release-candidate-gate',
            'tag_sha" == "$CANDIDATE_COMMIT"',
        ):
            self.assertIn(fragment, workflow)
        release_job = workflow[workflow.index('  release:\n'):]
        self.assertIn('      - candidate\n      - qualify\n', release_job)
        self.assertNotIn('if: always()', release_job)
        self.assertIn('      contents: write\n      actions: read', release_job)
        self.assertLess(release_job.index('Assert completed qualification outputs'),
                        release_job.index('gh release create "$tag"'))
        self.assertLess(release_job.index('gh release create "$tag"'),
                        release_job.index('Publish API promotion after the immutable Release'))

    def test_release_write_calls_are_confined_to_qualified_job(self):
        workflow = (ROOT / ".github/workflows/publish-shell-version.yml").read_text()
        jobs = workflow[workflow.index('jobs:\n'):]
        candidate = jobs[jobs.index('  candidate:\n'):jobs.index('  qualify:\n')]
        qualification = jobs[jobs.index('  qualify:\n'):jobs.index('  release:\n')]
        release = jobs[jobs.index('  release:\n'):]
        for text in (candidate, qualification):
            self.assertNotIn('gh release create', text)
            self.assertNotIn('gh api', text)
            self.assertNotIn('RELEASE_AUTOMATION_TOKEN', text)
        self.assertIn('needs:\n      - candidate\n      - qualify', release)
        self.assertIn('permissions:\n      contents: write', release)
        self.assertIn('gh release create "$tag"', release)

    def test_promotion_probe_is_dispatch_only_and_fails_red(self):
        workflow = (ROOT / ".github/workflows/publish-shell-version.yml").read_text()
        self.assertIn('force_promotion_failure:', workflow)
        self.assertIn('default: false', workflow[workflow.index('force_promotion_failure:'):])
        jobs = workflow[workflow.index('jobs:\n'):]
        release = jobs[jobs.index('  release:\n'):jobs.index('  promote:\n')]
        promote = jobs[jobs.index('  promote:\n'):]
        self.assertNotIn('force_promotion_failure', release)
        self.assertIn('if: inputs.force_promotion_failure', promote)
        self.assertIn('MANUAL ACTION REQUIRED: forced promotion failure', promote)
        self.assertIn('exit 1', promote)
        self.assertNotIn('continue-on-error', promote)
        self.assertNotIn('gh release create', promote)

    def test_legacy_identity_excludes_provenance_bearing_bundle(self):
        manifest = {
            "files": {
                "repository_files/rill_payload/python/rill_xray_agent/new.py": "a" * 64,
                "source/PROVENANCE/upstream.json": "b" * 64,
                "repository_files/rill_payload/PROVENANCE/upstream.json": "c" * 64,
                "repository_files/assets/rill-xray-agent-xray-bundle.tar.gz": "d" * 64,
            }
        }
        before = MODULE.computed_canonical_identity(manifest)
        manifest["files"]["source/PROVENANCE/upstream.json"] = "e" * 64
        manifest["files"]["repository_files/rill_payload/PROVENANCE/upstream.json"] = "f" * 64
        manifest["files"]["repository_files/assets/rill-xray-agent-xray-bundle.tar.gz"] = "0" * 64
        self.assertEqual(before, MODULE.computed_canonical_identity(manifest))

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

    def test_update_api_pairs_immutable_release_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xray = root / "xray"
            api = root / "api"
            xray.mkdir()
            api.mkdir()
            (xray / "install.sh").write_text('shell_version="3.2.3"\n')
            target = api / "xray_shell_versions.json"
            target.write_text(json.dumps({"shell_online_version": "3.2.2"}))
            digest = "a" * 64
            self.assertTrue(MODULE.update_api(xray, api, "Release", None, digest))
            result = json.loads(target.read_text())
            self.assertEqual(result["shell_online_version"], "3.2.3")
            self.assertEqual(result["shell_release_sha256"], digest)

    def test_update_api_creates_compatibility_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xray = root / "xray"
            api = root / "api"
            xray.mkdir()
            api.mkdir()
            (xray / "install.sh").write_text('shell_version="3.3.1"\n')
            (api / "xray_shell_versions.json").write_text(
                json.dumps({"shell_online_version": "3.3.0", "shell_tested_version": "3.3.0"})
            )
            initial = {
                "xrayVersion": "26.3.27",
                "installerRef": "e" * 40,
                "installerSha256": "f" * 64,
            }
            baseline = {
                "schemaVersion": 1,
                "repository": "hello-yunshu/Xray_bash_onekey",
                "minimumDirectUpgradeVersion": "3.3.0",
                "baselines": [{
                    "version": "3.3.0", "tag": "v3.3.0", "commit": "a" * 40,
                    "installSha256": "b" * 64,
                    "scenarios": ["direct", "shell-first", "reinstall"],
                    "initial": initial,
                }],
                "trustedInitials": [initial],
            }
            (api / "compatibility-baselines.json").write_text(json.dumps(baseline))
            scenarios = ("direct", "shell-first", "reinstall",
                         "failure-recovery", "restart-recovery", "fallback")
            changed = MODULE.update_api(
                xray, api, "Release 3.3.1", None, "c" * 64,
                "d" * 40, scenarios,
            )
            self.assertTrue(changed)
            result = json.loads((api / "compatibility-baselines.json").read_text())
            entry = next(item for item in result["baselines"] if item["version"] == "3.3.1")
            self.assertEqual(entry["tag"], "v3.3.1")
            self.assertEqual(entry["commit"], "d" * 40)
            self.assertEqual(entry["installSha256"], "c" * 64)
            self.assertEqual(entry["scenarios"], list(scenarios))
            self.assertEqual(entry["initial"], initial)

    def test_update_api_refreshes_baseline_for_same_version_new_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xray = root / "xray"
            api = root / "api"
            xray.mkdir()
            api.mkdir()
            (xray / "install.sh").write_text('shell_version="3.3.1"\n')
            (api / "xray_shell_versions.json").write_text(
                json.dumps({"shell_online_version": "3.3.1", "shell_release_sha256": "a" * 64})
            )
            entry = {
                "version": "3.3.1", "tag": "v3.3.1", "commit": "b" * 40,
                "installSha256": "a" * 64, "scenarios": ["direct"],
                "initial": {"xrayVersion": "26.3.27",
                            "installerRef": "e" * 40, "installerSha256": "f" * 64},
            }
            baseline = {
                "schemaVersion": 1,
                "repository": "hello-yunshu/Xray_bash_onekey",
                "minimumDirectUpgradeVersion": "3.3.0",
                "baselines": [entry],
                "trustedInitials": [entry["initial"]],
            }
            (api / "compatibility-baselines.json").write_text(json.dumps(baseline))
            scenarios = ("direct", "shell-first", "reinstall",
                         "failure-recovery", "restart-recovery", "fallback")
            changed = MODULE.update_api(
                xray, api, "same version replacement", "2026-11-03 02:00",
                "c" * 64, "d" * 40, scenarios,
            )
            self.assertTrue(changed)
            result = json.loads((api / "compatibility-baselines.json").read_text())
            refreshed = result["baselines"][0]
            self.assertEqual(refreshed["commit"], "d" * 40)
            self.assertEqual(refreshed["installSha256"], "c" * 64)
            self.assertEqual(refreshed["scenarios"], list(scenarios))
            self.assertEqual(json.loads((api / "xray_shell_versions.json").read_text())
                             ["shell_release_sha256"], "c" * 64)

    def test_release_workflow_purges_on_idempotent_rerun_and_updates_baseline(self):
        workflow = (ROOT / ".github/workflows/publish-shell-version.yml").read_text()
        self.assertIn('--shell-commit "$CANDIDATE_COMMIT"', workflow)
        self.assertIn('--baseline-scenarios', workflow)
        self.assertIn('compatibility-baselines.json', workflow)
        self.assertIn('for attempt in 1 2 3 4 5', workflow)
        self.assertIn('CDN/raw did not converge', workflow)


if __name__ == "__main__":
    unittest.main()
