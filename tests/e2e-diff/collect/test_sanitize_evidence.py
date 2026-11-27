import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sanitize_evidence


class SanitizeEvidenceOutputTests(unittest.TestCase):
    def test_changed_file_output_is_relative_to_root(self):
        with tempfile.TemporaryDirectory(prefix="private-home-path-") as tmp:
            root = Path(tmp) / "capture"
            target = root / "p2" / "config.txt"
            target.parent.mkdir(parents=True)
            private_home = "/" + "Users/" + "codex-test"
            target.write_text(f"home={private_home}/.config\n", encoding="utf-8")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = sanitize_evidence.main([str(root)])

            self.assertEqual(rc, 0)
            self.assertIn("sanitize: p2/config.txt", output.getvalue())
            self.assertNotIn(tmp, output.getvalue())
            self.assertEqual(target.read_text(encoding="utf-8"), "home=<workspace>/.config\n")


if __name__ == "__main__":
    unittest.main()
