#!/usr/bin/env bash
# Stage 2: a fresh process/container recovers the killed transaction, proves all
# four files are byte-identical to the pre-install state, then installs again.
set -euo pipefail

SANDBOX=/work/sandbox
JOURNAL="$SANDBOX/var/lib/idleleo/deploy/journal.json"

[[ -f /work/journal-after-kill.json ]] || { echo "FAIL: no killed journal" >&2; exit 5; }

start_state=$(grep -o '"state": "[A-Z_]*"' "$JOURNAL" | head -1)
echo "recover_start_state=$start_state"

/work/idleleo --root "$SANDBOX" xray recover --container --json >/work/recover.json
cat /work/recover.json
grep -q '"converged": true' /work/recover.json
grep -q '"action": "rolled_back"' /work/recover.json
if [[ -f "$JOURNAL" ]]; then
    echo "FAIL: journal survived recovery" >&2
    exit 6
fi

if ! sha256sum -c /work/before.sha >/work/restore-check.txt 2>&1; then
    cat /work/restore-check.txt >&2
    echo "FAIL: files did not return to pre-install bytes" >&2
    exit 7
fi
cat /work/restore-check.txt
if [[ -e "$SANDBOX/usr/local/bin/xray.tmp" ]]; then
    echo "FAIL: half-written temp file survived" >&2
    exit 8
fi

printf '#!/bin/sh\nexit 0\n' >/work/smallfake
chmod 0755 /work/smallfake
/work/idleleo --root "$SANDBOX" xray install --binary /work/smallfake \
    --container --no-service --mode none --transport ws --port 10081 \
    >/work/reinstall.log 2>&1
cat /work/reinstall.log
[[ ! -f "$JOURNAL" ]] || { echo "FAIL: reinstall left a journal" >&2; exit 9; }
grep -q '"configSha256"' /work/reinstall.log || grep -q 'installed:' /work/reinstall.log

echo "RECOVER_OK restored=$(grep -c . /work/before.sha) journal_removed=yes reinstall=ok"
