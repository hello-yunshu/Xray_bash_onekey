#!/usr/bin/env bash
# Self-check for collect/manifest.sh and collect/normalize.py.
#
# Builds a three-file fixture, asserts the manifest shape, and asserts that
# normalization is stable across two runs on identical input. Runs on the host
# (macOS/Linux) or inside the e2e image; needs only bash + python3.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/e2e-collect-selfcheck.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FIXTURE="$WORK/fixture"
OUT="$WORK/out"
mkdir -p "$FIXTURE"

printf '\033[1;32mOK\033[0m 2026-11-13T12:34:56+08:00 pid=4242 [4242] /tmp/tmp.abc123\nNov 13 12:34:56 plain line  \n' >"$FIXTURE/app.log"
printf '{"alpha":{"ts":"2026-11-13T12:34:56Z","pid":4242},"beta":[3,1,2]}\n' >"$FIXTURE/config.json"
printf 'listen 443\nlisten 8443\n' >"$FIXTURE/ports.conf"
chmod 640 "$FIXTURE/config.json"

fail() {
    echo "SELF-CHECK FAIL: $*" >&2
    exit 1
}

E2E_COLLECT_OUT="$OUT" E2E_MANIFEST_ROOTS="$FIXTURE" bash "$HERE/manifest.sh" >/dev/null

python3 - "$OUT/manifest.json" <<'PY' || exit 1
import json
import sys

data = json.load(open(sys.argv[1]))
required = {'path', 'type', 'mode', 'owner', 'group', 'size', 'sha256', 'target'}
assert data['count'] == len(data['entries']) == 4, data['count']
for entry in data['entries']:
    missing = required - set(entry)
    assert not missing, (entry['path'], missing)
paths = [entry['path'] for entry in data['entries']]
assert paths == sorted(paths), 'manifest not sorted'
files = [entry for entry in data['entries'] if entry['type'] == 'file']
assert len(files) == 3, len(files)
assert all(entry['sha256'] and len(entry['sha256']) == 64 for entry in files)
print('manifest shape ok (%d entries)' % data['count'])
PY

python3 "$HERE/normalize.py" "$FIXTURE/app.log" "$WORK/app.log.1" >/dev/null
python3 "$HERE/normalize.py" "$FIXTURE/app.log" "$WORK/app.log.2" >/dev/null
cmp -s "$WORK/app.log.1" "$WORK/app.log.2" || fail 'normalize output not stable for app.log'
grep -q '<TS>' "$WORK/app.log.1" || fail 'timestamp rule did not fire'
grep -q 'pid=<PID>' "$WORK/app.log.1" || fail 'pid rule did not fire'
grep -q '<TMPDIR>' "$WORK/app.log.1" || fail 'tmpdir rule did not fire'
if grep -q $'\033' "$WORK/app.log.1"; then fail 'ANSI escape survived normalize'; fi

python3 "$HERE/normalize.py" "$FIXTURE/config.json" "$WORK/config.json.1" >/dev/null
python3 "$HERE/normalize.py" "$FIXTURE/config.json" "$WORK/config.json.2" >/dev/null
cmp -s "$WORK/config.json.1" "$WORK/config.json.2" || fail 'normalize output not stable for config.json'
python3 - "$WORK/config.json.1" <<'PY' || exit 1
import json
import sys
data = json.load(open(sys.argv[1]))
assert data['beta'] == [3, 1, 2], 'array order must be preserved'
assert data['alpha']['ts'] == '<TS>', data['alpha']['ts']
assert data['alpha']['pid'] == 4242
print('json normalize ok')
PY

python3 "$HERE/normalize.py" "$FIXTURE/ports.conf" "$WORK/ports.1" --sort-lines >/dev/null
python3 "$HERE/normalize.py" "$FIXTURE/ports.conf" "$WORK/ports.2" --sort-lines >/dev/null
cmp -s "$WORK/ports.1" "$WORK/ports.2" || fail 'normalize output not stable for ports.conf'

echo "collect self-check: PASS"
