#!/usr/bin/env bash
# L6 idempotency comparison between round 1 and round 2 of the same install.
#
# Usage (inside the container):
#   E2E_IDEM_PREV=/out E2E_IDEM_CUR=/out/round2 bash collect/idempotency.sh
#
# Outputs idempotency.json with:
#   * artifact paths added/removed between rounds (content changes are expected
#     for timestamp-bearing files and are only counted, not failed);
#   * inbound count delta plus duplicate (protocol, port) detection;
#   * cron line count delta plus duplicate lines.
set -uo pipefail

PREV="${E2E_IDEM_PREV:?E2E_IDEM_PREV required}"
CUR="${E2E_IDEM_CUR:?E2E_IDEM_CUR required}"

export E2E_IDEM_PREV="$PREV" E2E_IDEM_CUR="$CUR"
python3 - <<'PY'
import json
import os

prev_dir = os.environ['E2E_IDEM_PREV']
cur_dir = os.environ['E2E_IDEM_CUR']

def load_manifest(base):
    try:
        data = json.load(open(os.path.join(base, 'manifest.json')))
    except (OSError, json.JSONDecodeError):
        return None
    return {entry['path']: entry for entry in data.get('entries', [])}

def load_inbounds(base):
    for name in ('config/config.sanitized.json', 'config/config.json'):
        path = os.path.join(base, name)
        if not os.path.exists(path):
            continue
        try:
            cfg = json.load(open(path))
        except (OSError, json.JSONDecodeError):
            return None
        return cfg.get('inbounds') or []
    return None

def cron_lines(base):
    path = os.path.join(base, 'cron.txt')
    if not os.path.exists(path):
        return None
    return [line for line in open(path).read().splitlines() if line.strip()]

prev = load_manifest(prev_dir)
cur = load_manifest(cur_dir)
result = {
    'schemaVersion': 1,
    'manifest': None,
    'inbounds': None,
    'cron': None,
    'ok': True,
}

if prev is not None and cur is not None:
    # Timestamped reinstall backups are expected output of the bash installer,
    # not an idempotency drift: each reinstall deliberately creates a new
    # /etc/idleleo/backup/reinstall-<ts>-<rand>/ directory. They are counted
    # separately so the report still shows them, but they do not fail L6.
    backup_prefix = '/etc/idleleo/backup'
    def is_backup(p):
        return p == backup_prefix or p.startswith(backup_prefix + '/')
    raw_added = sorted(set(cur) - set(prev))
    raw_removed = sorted(set(prev) - set(cur))
    added = [p for p in raw_added if not is_backup(p)]
    removed = [p for p in raw_removed if not is_backup(p)]
    changed = sorted(p for p in set(prev) & set(cur)
                     if prev[p].get('sha256') != cur[p].get('sha256'))
    result['manifest'] = {
        'added': added,
        'removed': removed,
        'changed': changed,
        'addedCount': len(added),
        'removedCount': len(removed),
        'changedCount': len(changed),
        'backupAddedCount': len(raw_added) - len(added),
        'backupRemovedCount': len(raw_removed) - len(removed),
        'stable': not added and not removed,
    }
    if added or removed:
        result['ok'] = False

prev_in = load_inbounds(prev_dir)
cur_in = load_inbounds(cur_dir)
if cur_in is not None:
    keys = [(i.get('protocol'), i.get('port')) for i in cur_in]
    duplicates = sorted({k for k in keys if keys.count(k) > 1}, key=str)
    result['inbounds'] = {
        'prevCount': len(prev_in) if prev_in is not None else None,
        'curCount': len(cur_in),
        'countDelta': (len(cur_in) - len(prev_in)) if prev_in is not None else None,
        'duplicates': duplicates,
        'stable': not duplicates and (prev_in is None or len(prev_in) == len(cur_in)),
    }
    if duplicates or (prev_in is not None and len(prev_in) != len(cur_in)):
        result['ok'] = False

prev_cron = cron_lines(prev_dir)
cur_cron = cron_lines(cur_dir)
if cur_cron is not None:
    dup = sorted({line for line in cur_cron if cur_cron.count(line) > 1})
    result['cron'] = {
        'prevCount': len(prev_cron) if prev_cron is not None else None,
        'curCount': len(cur_cron),
        'duplicates': dup,
        'stable': not dup and (prev_cron is None or len(prev_cron) == len(cur_cron)),
    }
    if dup or (prev_cron is not None and len(prev_cron) != len(cur_cron)):
        result['ok'] = False

json.dump(result, open(os.path.join(cur_dir, 'idempotency.json'), 'w'),
          indent=2, sort_keys=True)
print('idempotency ok=%s' % result['ok'])
PY
