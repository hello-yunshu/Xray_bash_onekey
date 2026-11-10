#!/usr/bin/env bash
# Stage 1: start a real install with a slow (250MB) candidate binary, wait for
# the durable journal, then SIGKILL the install while it is mid-transaction.
set -euo pipefail

SANDBOX=/work/sandbox
rm -rf "$SANDBOX"
mkdir -p "$SANDBOX"

go build -o /work/idleleo ./cmd/idleleo

printf '%s\n' 'I_ACCEPT_DISPOSABLE_SANDBOX' >"$SANDBOX/.idleleo-phase01-sandbox"
mkdir -p "$SANDBOX/etc/idleleo/conf/xray" "$SANDBOX/usr/local/bin" \
    "$SANDBOX/etc/systemd/system" "$SANDBOX/etc/idleleo/v1"
printf 'old-config\n' >"$SANDBOX/etc/idleleo/conf/xray/config.json"
printf 'old-binary\n' >"$SANDBOX/usr/local/bin/xray"
printf 'old-unit\n' >"$SANDBOX/etc/systemd/system/xray.service"
printf 'old-meta\n' >"$SANDBOX/etc/idleleo/v1/metadata.json"

{
    sha256sum "$SANDBOX/etc/idleleo/conf/xray/config.json"
    sha256sum "$SANDBOX/usr/local/bin/xray"
    sha256sum "$SANDBOX/etc/systemd/system/xray.service"
    sha256sum "$SANDBOX/etc/idleleo/v1/metadata.json"
} >/work/before.sha

# A valid executable that exits 0 and is large enough that its copy is slow.
printf '#!/bin/sh\nexit 0\n' >/work/bigfake
dd if=/dev/zero bs=1048576 count=250 >>/work/bigfake 2>/dev/null
chmod 0755 /work/bigfake

JOURNAL="$SANDBOX/var/lib/idleleo/deploy/journal.json"
rm -f /work/install.log /work/journal-after-kill.json
/work/idleleo --root "$SANDBOX" xray install --binary /work/bigfake \
    --container --no-service --mode none --transport ws --port 10080 \
    >/work/install.log 2>&1 &
pid=$!

for _ in $(seq 1 20000); do
    [[ -f "$JOURNAL" ]] && break
    sleep 0.005
done
if [[ ! -f "$JOURNAL" ]]; then
    echo "FAIL: install never wrote a journal" >&2
    kill -9 "$pid" 2>/dev/null || true
    exit 3
fi

# The journal snapshot stage is done; the copy of the 250MB candidate is now
# in progress. Kill while live state is half written.
sleep 0.10
kill -9 "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
pkill -9 -f /work/bigfake 2>/dev/null || true

cp "$JOURNAL" /work/journal-after-kill.json
state=$(grep -o '"state": "[A-Z_]*"' "$JOURNAL" | head -1)
{
    sha256sum "$SANDBOX/etc/idleleo/conf/xray/config.json"
    sha256sum "$SANDBOX/usr/local/bin/xray"
    sha256sum "$SANDBOX/etc/systemd/system/xray.service"
    sha256sum "$SANDBOX/etc/idleleo/v1/metadata.json"
} >/work/after-kill.sha
ls -la "$SANDBOX/usr/local/bin" >/work/after-kill-files.txt 2>&1 || true

if ! diff -q /work/before.sha /work/after-kill.sha >/dev/null; then
    partial=yes
else
    partial=no
fi
echo "KILLED pid=$pid journal_state=$state partial_mutation=$partial"
if [[ "$state" != *PREPARED* || "$partial" != yes ]]; then
    echo "FAIL: expected PREPARED journal and partial mutation" >&2
    exit 4
fi
