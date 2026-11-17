#!/usr/bin/env bash
# Collects L5 logs from a running e2e container.
#
# Usage (inside the container):
#   E2E_COLLECT_OUT=/out bash collect/logs.sh
#
# Outputs:
#   logs.json      per-unit normalized digest + error/warning line counts
#   logs/<unit>.log normalized transcript (ANSI/timestamp/PID removed)
set -uo pipefail

OUT="${E2E_COLLECT_OUT:?E2E_COLLECT_OUT required}"
mkdir -p "$OUT/logs"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

collect_unit() {
    local unit=$1
    local raw="$tmp/$unit.raw"
    {
        journalctl -u "$unit" --no-pager -n 300 2>/dev/null || true
        case $unit in
            xray)  [[ -f /var/log/xray/error.log ]] && tail -n 200 /var/log/xray/error.log ;;
            nginx) [[ -f /var/log/nginx/error.log ]] && tail -n 200 /var/log/nginx/error.log ;;
        esac
    } >"$raw"
    python3 /src/tests/e2e-diff/collect/normalize.py "$raw" "$OUT/logs/$unit.log" >/dev/null 2>&1 || \
        cp "$raw" "$OUT/logs/$unit.log"
}

collect_unit xray
collect_unit nginx

export E2E_LOGS_OUT="$OUT/logs.json" E2E_LOGS_DIR="$OUT/logs"
python3 - <<'PY'
import hashlib
import json
import os
import re

out = os.environ['E2E_LOGS_OUT']
base = os.environ['E2E_LOGS_DIR']
units = {}
for unit in ('xray', 'nginx'):
    path = os.path.join(base, '%s.log' % unit)
    try:
        text = open(path, encoding='utf-8', errors='replace').read()
    except OSError:
        text = ''
    lines = [line for line in text.splitlines() if line.strip()]
    err = [line for line in lines if re.search(r'\b(error|failed|fatal|panic)\b', line, re.I)]
    warn = [line for line in lines if re.search(r'\bwarn(ing)?\b', line, re.I)]
    units[unit] = {
        'lines': len(lines),
        'errorLines': len(err),
        'warningLines': len(warn),
        'sha256': hashlib.sha256(text.encode()).hexdigest() if lines else None,
        'sampleErrors': err[:5],
    }
json.dump({'schemaVersion': 1, 'units': units}, open(out, 'w'), indent=2, sort_keys=True)
print('logs collected')
PY
