import json
import tempfile
import unittest
from pathlib import Path

from verify_ops24 import verify


class VerifyOPS24Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ops = self.root / "OPS-24"
        for side in ("bash", "go"):
            (self.ops / side).mkdir(parents=True)
        self.hash_ip = "a" * 64
        self.hash_site = "b" * 64
        for side in ("bash", "go"):
            base = self.ops / side
            (base / "after.txt").write_text(
                f"{self.hash_ip} /etc/idleleo/share/xray/geoip.dat\n"
                f"{self.hash_site} /etc/idleleo/share/xray/geosite.dat\nactive\n",
                encoding="utf-8",
            )
            (base / "release.txt").write_text("202611262204\n", encoding="utf-8")
        (self.ops / "bash" / "run.rc").write_text("0\n", encoding="utf-8")
        (self.ops / "bash" / "run.out").write_text("GeoData 手动刷新完成\n", encoding="utf-8")
        (self.ops / "bash" / "geo-update.log").write_text(
            "Pinned GeoData release tag: 202611262204\n"
            "GeoData update completed successfully for 202611262204\n",
            encoding="utf-8",
        )
        (self.ops / "go" / "09-install.rc").write_text("0\n", encoding="utf-8")
        (self.ops / "go" / "10-op.rc").write_text("0\n", encoding="utf-8")
        (self.ops / "go" / "10-op.out").write_text(json.dumps({
            "results": [{"job": "geodata-refresh", "result": "ok"}]
        }), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_nested_schedule_result_and_equal_real_assets_pass(self):
        result = verify(self.root)
        self.assertEqual(result["verdict"], "DUAL_SIDE_VERIFIED")
        self.assertEqual(result["reasons"], [])

    def test_mismatched_real_asset_digest_fails(self):
        path = self.ops / "go" / "after.txt"
        path.write_text(
            f"{'c' * 64} /etc/idleleo/share/xray/geoip.dat\n"
            f"{self.hash_site} /etc/idleleo/share/xray/geosite.dat\nactive\n",
            encoding="utf-8",
        )
        result = verify(self.root)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("Bash and Go GeoData SHA-256 values differ", result["reasons"])


if __name__ == "__main__":
    unittest.main()
