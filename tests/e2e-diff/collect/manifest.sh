#!/usr/bin/env bash
# Collects the L1 artifact manifest from a running e2e container.
#
# Usage (inside the container):
#   E2E_COLLECT_OUT=/out E2E_MANIFEST_ROOTS=/etc/idleleo:/usr/local/bin/xray \
#     bash collect/manifest.sh
#
# E2E_MANIFEST_ROOTS is a colon-separated list of files or directories. Every
# entry is stat'ed and (for regular files) hashed with SHA-256. Only metadata
# and digests leave the container; file contents are never copied here.
set -euo pipefail

OUT="${E2E_COLLECT_OUT:?E2E_COLLECT_OUT required}"
ROOTS="${E2E_MANIFEST_ROOTS:-/etc/idleleo:/usr/local/bin/xray:/usr/local/nginx/sbin/nginx:/etc/systemd/system/xray.service:/etc/systemd/system/nginx.service:/etc/logrotate.d/xray_log_cleanup:/var/spool/cron/crontabs/root}"
mkdir -p "$OUT"

python3 - "$OUT/manifest.json" "$ROOTS" <<'PY'
import hashlib
import json
import os
import stat
import sys

out_path, roots = sys.argv[1], sys.argv[2].split(':')

def owner(path):
    st = os.lstat(path)
    try:
        import pwd, grp
        user = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
    except (KeyError, ImportError):
        user, group = str(st.st_uid), str(st.st_gid)
    return user, group

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

entries = []
seen = set()

def add(path):
    if path in seen:
        return
    seen.add(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    user, group = owner(path)
    if stat.S_ISLNK(st.st_mode):
        kind = 'symlink'
        target = os.readlink(path)
        sha = None
        size = 0
    elif stat.S_ISDIR(st.st_mode):
        kind, target, sha, size = 'dir', None, None, 0
    else:
        kind, target, size = 'file', None, st.st_size
        sha = digest(path)
    entries.append({
        'path': path,
        'type': kind,
        'mode': oct(stat.S_IMODE(st.st_mode)),
        'owner': user,
        'group': group,
        'size': size,
        'sha256': sha,
        'target': target,
    })

for root in roots:
    if not root:
        continue
    if os.path.isdir(root) and not os.path.islink(root):
        add(root)
        for base, dirs, files in os.walk(root):
            dirs.sort()
            for name in sorted(dirs):
                add(os.path.join(base, name))
            for name in sorted(files):
                add(os.path.join(base, name))
    else:
        add(root)

entries.sort(key=lambda item: item['path'])
json.dump({'schemaVersion': 1, 'count': len(entries), 'entries': entries},
          open(out_path, 'w'), indent=2, sort_keys=True)
print('manifest entries=%d' % len(entries))
PY
