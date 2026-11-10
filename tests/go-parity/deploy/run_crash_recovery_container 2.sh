#!/usr/bin/env bash
# B4 real injection: SIGKILL a live install mid-write, then converge the
# transaction from a fresh process/container.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMAGE="${B4_IMAGE:-idleleo-phase01-test:1.24}"
EVIDENCE="${B4_EVIDENCE:-$ROOT/tests/go-parity/evidence/b4-2026-11-08}"
WORK="${B4_WORK:-/tmp/idleleo-b4-work}"

rm -rf "$WORK"
mkdir -p "$WORK" "$EVIDENCE"
chmod 0777 "$WORK"

run_go() {
    docker run --rm \
        -v "$ROOT:/src:ro" -v "$WORK:/work:rw" -w /src \
        -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOTOOLCHAIN=local -e GOPROXY=off \
        "$IMAGE" bash "$1" 2>&1 | tee "$EVIDENCE/$(basename "${1%.sh}").log"
}

echo "== stage 1: kill a real install mid-write =="
run_go /src/tests/go-parity/deploy/kill_stage.sh

echo "== stage 2: fresh process/container recovers and reinstalls =="
run_go /src/tests/go-parity/deploy/recover_stage.sh

cp "$WORK/journal-after-kill.json" "$EVIDENCE/journal-after-kill.json"
cp "$WORK/after-kill-files.txt" "$EVIDENCE/after-kill-files.txt" 2>/dev/null || true
cp "$WORK/recover.json" "$EVIDENCE/recover.json"
cp "$WORK/install.log" "$EVIDENCE/install-killed.log"
cp "$WORK/reinstall.log" "$EVIDENCE/reinstall.log"
cp "$WORK/before.sha" "$EVIDENCE/before.sha"
cp "$WORK/after-kill.sha" "$EVIDENCE/after-kill.sha"
cp "$WORK/restore-check.txt" "$EVIDENCE/restore-check.txt"

echo "b4-evidence=$EVIDENCE"
