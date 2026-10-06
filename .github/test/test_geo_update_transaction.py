#!/usr/bin/env python3
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/geo_update.sh'


class GeoUpdateTransactionTests(unittest.TestCase):
    def run_update(self, *, fail_mv=False, fail_download='', bad_dat=False,
                   active=False, fail_restart=False, bad_checksum=False,
                   fail_metadata_mv=False, hold_update_lock=False):
        td = tempfile.mkdtemp(prefix='xray-geo-test-')
        self.addCleanup(shutil.rmtree, td, ignore_errors=True)
        try:
            root = Path(td) / 'idleleo'
            geo = root / 'share/xray'
            conf = root / 'conf/xray'
            logs = root / 'logs'
            geo.mkdir(parents=True)
            conf.mkdir(parents=True)
            logs.mkdir(parents=True)
            (geo / 'geoip.dat').write_bytes(b'old-ip')
            (geo / 'geosite.dat').write_bytes(b'old-site')
            conf_file = conf / 'config.json'
            conf_file.write_text('{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[]}}\n')
            (conf / 'geo_version.json').write_text(
                '{"geo_versions":{"geoip.dat":"old","geosite.dat":"old"}}\n')
            fixture_dir = Path(td) / 'fixtures'
            fixture_dir.mkdir()
            ip = b'<html>bad dat</html>' if bad_dat else b'VALID-GEOIP-DAT'
            site = b'VALID-GEOSITE-DAT'
            (fixture_dir / 'geoip.dat').write_bytes(ip)
            (fixture_dir / 'geosite.dat').write_bytes(site)
            stubs = Path(td) / 'bin'
            stubs.mkdir()
            if fail_mv:
                mv = stubs / 'mv'
                mv.write_text(
                    '#!/bin/sh\n'
                    'for arg do last="$arg"; done\n'
                    '[ "$GEO_FAIL_METADATA_MV" != true ] || case "$last" in */geo_version.json) if [ ! -e "$GEO_MV_MARKER" ]; then : >"$GEO_MV_MARKER"; exit 1; fi;; esac\n'
                    'for arg do last="$arg"; done\n'
                    'case "$last" in */geoip.dat) exit 1;; esac\n'
                    'exec /bin/mv "$@"\n')
                mv.chmod(0o755)
            elif fail_metadata_mv:
                mv = stubs / 'mv'
                mv.write_text(
                    '#!/bin/sh\n'
                    'for arg do last="$arg"; done\n'
                    '[ "$GEO_MV_MARKER" != "" ] || true\n'
                    '[ -e "$GEO_MV_MARKER" ] || case "$last" in */geo_version.json) : >"$GEO_MV_MARKER"; exit 1;; esac\n'
                    'exec /bin/mv "$@"\n')
                mv.chmod(0o755)
            curl = stubs / 'curl'
            curl.write_text(
                '#!/bin/sh\n'
                'out=""; url=""; prev=""; format=false\n'
                'for arg do\n'
                '  if [ "$prev" = -o ]; then out="$arg"; fi\n'
                '  [ "$arg" = -o ] && prev=-o || prev=\n'
                '  [ "$arg" = -w ] && format=true\n'
                '  case "$arg" in https://*) url="$arg";; esac\n'
                'done\n'
                'if [ "$format" = true ]; then printf "%s" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/tag/v20261006"; exit 0; fi\n'
                'printf "%s\\n" "$url" >>"$GEO_URL_LOG"\n'
                '[ -z "$GEO_FAIL_FILE" ] || case "$url" in *"$GEO_FAIL_FILE") exit 22;; esac\n'
                'name=${url##*/}\n'
                'if [ "${name##*.}" = sha256sum ]; then data=${name%.sha256sum}; sha=$(sha256sum "$GEO_FIXTURE_DIR/$data" | awk "{print \\$1}"); [ "$GEO_BAD_CHECKSUM" != true ] || sha=0000000000000000000000000000000000000000000000000000000000000000; printf "%s  %s\\n" "$sha" "$data" >"$out"; else cp "$GEO_FIXTURE_DIR/$name" "$out"; fi\n')
            curl.chmod(0o755)
            xray = stubs / 'xray'
            xray.write_text(
                '#!/bin/sh\n'
                '[ -f "$XRAY_LOCATION_ASSET/geoip.dat" ] && [ -f "$XRAY_LOCATION_ASSET/geosite.dat" ] || exit 2\n'
                'grep -q "^VALID-" "$XRAY_LOCATION_ASSET/geoip.dat" || exit 3\n'
                'grep -q "^VALID-" "$XRAY_LOCATION_ASSET/geosite.dat" || exit 4\n')
            xray.chmod(0o755)
            systemctl = stubs / 'systemctl'
            systemctl.write_text(
                '#!/bin/sh\n'
                'printf "%s\\n" "$*" >>"$XRAY_SYSTEMCTL_LOG"\n'
                'case "$1" in\n'
                '  is-active) [ "$XRAY_SERVICE_ACTIVE" = true ] || exit 3; [ "$XRAY_RESTARTED" != true ] || [ "$XRAY_RESTART_FAIL" != true ];;\n'
                '  restart) [ "$XRAY_RESTART_FAIL" != true ] || exit 1; export XRAY_RESTARTED=true;;\n'
                '  *) exit 0;;\n'
                'esac\n')
            systemctl.chmod(0o755)
            env = dict(os.environ)
            env.update({'XRAY_GEO_ROOT': str(root), 'XRAY_GEO_CONFIG': str(conf_file),
                        'XRAY_UPDATE_LOCK_FILE': str(Path(td) / 'update.lock'),
                        'XRAY_BINARY': str(xray), 'PATH': f'{stubs}:{env.get("PATH", "")}',
                        'GEO_FIXTURE_DIR': str(fixture_dir), 'GEO_FAIL_FILE': fail_download,
                        'GEO_BAD_CHECKSUM': str(bad_checksum).lower(),
                        'GEO_FAIL_METADATA_MV': str(fail_metadata_mv).lower(),
                        'GEO_MV_MARKER': str(Path(td) / 'mv-failed-once'),
                        'GEO_URL_LOG': str(Path(td) / 'urls.log'),
                        'XRAY_SYSTEMCTL_LOG': str(Path(td) / 'systemctl.log'),
                        'XRAY_SERVICE_ACTIVE': str(active).lower(),
                        'XRAY_RESTART_FAIL': str(fail_restart).lower()})
            holder = None
            if hold_update_lock:
                ready = Path(td) / 'lock-held'
                holder = subprocess.Popen(
                    ['bash', '-c', 'exec 9>"$1"; flock -n 9; : >"$2"; sleep 30',
                     'lock-holder', env['XRAY_UPDATE_LOCK_FILE'], str(ready)])
                self.addCleanup(lambda: (holder.terminate(), holder.wait(timeout=5)))
                for _ in range(200):
                    if ready.exists(): break
                    __import__('time').sleep(0.01)
                if not ready.exists(): raise RuntimeError('failed to acquire test update lock')
            result = subprocess.run(['bash', str(SCRIPT)], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, timeout=20)
            log = (logs / 'geo_update.log').read_text()
            return result, geo, conf, log
        except Exception:
            raise

    def test_mv_failure_rolls_back_both_assets_and_metadata(self):
        result, geo, conf, log = self.run_update(fail_mv=True)
        self.assertNotEqual(result.returncode, 0, log + result.stdout)
        self.assertNotIn('completed successfully', log)
        self.assertEqual((geo / 'geoip.dat').read_bytes(), b'old-ip')
        self.assertEqual((geo / 'geosite.dat').read_bytes(), b'old-site')
        self.assertEqual('old', __import__('json').loads((conf / 'geo_version.json').read_text())['geo_versions']['geoip.dat'])

    def test_second_download_failure_keeps_previous_generation(self):
        result, geo, conf, log = self.run_update(fail_download='geosite.dat')
        self.assertNotEqual(result.returncode, 0, log + result.stdout)
        self.assertEqual((geo / 'geoip.dat').read_bytes(), b'old-ip')
        self.assertEqual((geo / 'geosite.dat').read_bytes(), b'old-site')
        self.assertIn('old', (conf / 'geo_version.json').read_text())

    def test_checksum_mismatch_keeps_previous_generation(self):
        result, geo, conf, log = self.run_update(bad_checksum=True)
        self.assertNotEqual(result.returncode, 0, log + result.stdout)
        self.assertEqual((geo / 'geoip.dat').read_bytes(), b'old-ip')
        self.assertEqual((geo / 'geosite.dat').read_bytes(), b'old-site')
        self.assertIn('old', (conf / 'geo_version.json').read_text())

    def test_html_or_malformed_dat_is_rejected_before_publication(self):
        result, geo, _conf, log = self.run_update(bad_dat=True)
        self.assertNotEqual(result.returncode, 0, log + result.stdout)
        self.assertEqual((geo / 'geoip.dat').read_bytes(), b'old-ip')
        self.assertEqual((geo / 'geosite.dat').read_bytes(), b'old-site')

    def test_inactive_service_stays_inactive_after_success(self):
        result, geo, conf, log = self.run_update()
        self.assertEqual(result.returncode, 0, log + result.stdout)
        self.assertEqual((geo / 'geoip.dat').read_bytes(), b'VALID-GEOIP-DAT')
        self.assertEqual((geo / 'geosite.dat').read_bytes(), b'VALID-GEOSITE-DAT')
        versions = __import__('json').loads((conf / 'geo_version.json').read_text())['geo_versions']
        self.assertEqual(versions['geoip.dat'], 'v20261006')
        self.assertEqual(versions['geosite.dat'], 'v20261006')
        self.assertIn('completed successfully', log)

    def test_restart_failure_restores_previous_files_and_version(self):
        result, geo, conf, log = self.run_update(active=True, fail_restart=True)
        self.assertNotEqual(result.returncode, 0, log + result.stdout)
        self.assertEqual((geo / 'geoip.dat').read_bytes(), b'old-ip')
        self.assertEqual((geo / 'geosite.dat').read_bytes(), b'old-site')
        self.assertIn('"old"', (conf / 'geo_version.json').read_text())

    def test_metadata_rename_failure_rolls_back_assets_and_version(self):
        result, geo, conf, log = self.run_update(fail_metadata_mv=True)
        self.assertNotEqual(result.returncode, 0, log + result.stdout)
        self.assertEqual((geo / 'geoip.dat').read_bytes(), b'old-ip')
        self.assertEqual((geo / 'geosite.dat').read_bytes(), b'old-site')
        self.assertIn('"old"', (conf / 'geo_version.json').read_text())

    def test_release_tag_is_pinned_and_inactive_service_is_not_restarted(self):
        result, geo, conf, log = self.run_update()
        self.assertEqual(result.returncode, 0, log + result.stdout)
        urls = (Path(str(geo.parent.parent.parent)) / 'urls.log')
        # Temp output is retained by the test fixture until test cleanup.
        self.assertTrue(all('/v20261006/' in line for line in urls.read_text().splitlines()))
        control = Path(str(geo.parent.parent.parent)) / 'systemctl.log'
        self.assertEqual(control.read_text().splitlines(), ['is-active --quiet xray'])

    def test_shared_update_lock_blocks_overlapping_geo_change(self):
        result, geo, conf, log = self.run_update(hold_update_lock=True)
        self.assertNotEqual(result.returncode, 0, log + result.stdout)
        self.assertIn('Another Xray update is holding', log)
        self.assertEqual((geo / 'geoip.dat').read_bytes(), b'old-ip')
        self.assertEqual((geo / 'geosite.dat').read_bytes(), b'old-site')
        urls = Path(str(geo.parent.parent.parent)) / 'urls.log'
        self.assertFalse(urls.exists() and urls.read_text())


if __name__ == '__main__':
    unittest.main()
