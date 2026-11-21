#!/usr/bin/env python3
"""Guard the matrix environment.txt contract.

`environment.txt` is committed and uploaded, so it must never carry the
caller's absolute path (which contains the user name). This test checks both
the generator and every historical evidence file without needing Docker.
"""
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
GENERATOR = HERE / "run_matrix_container.sh"
EVIDENCE = REPO / "tests/go-parity/evidence"

HOST_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.\-])(?:/Users/|/home/|/root/)[^/\s\"'`<>),;|]+")


class EnvironmentContract(unittest.TestCase):
    def test_generator_strips_checksum_path(self):
        text = GENERATOR.read_text(encoding="utf-8")
        self.assertIn('install_sha="${install_sha%% *}"', text)
        self.assertNotRegex(
            text, r'echo "bash_install_sha256=\$\(sha256sum',
            "environment.txt must not echo the raw checksum line with its path",
        )

    def test_no_committed_environment_file_names_a_host(self):
        files = sorted(EVIDENCE.rglob("environment.txt"))
        self.assertTrue(files, "matrix evidence must exist")
        findings = []
        for path in files:
            for lineno, line in enumerate(path.read_text(encoding="utf-8",
                                                         errors="replace").splitlines(), 1):
                if HOST_PATH_RE.search(line):
                    findings.append(f"{path.relative_to(REPO)}:{lineno}")
        self.assertEqual(findings, [], "\n".join(findings))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(verbosity=2).result.wasSuccessful() else 1)
