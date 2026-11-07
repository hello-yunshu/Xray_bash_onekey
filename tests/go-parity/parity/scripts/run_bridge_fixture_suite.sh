#!/usr/bin/env bash
set -euo pipefail
# Explicit per-test timeouts; any timeout exits nonzero and fails CI. No masking.
BASE="$(cd "$(dirname "$0")/../.." && pwd)"
EVIDENCE="$BASE/parity/evidence"
mkdir -p "$EVIDENCE"
(
 cd "$BASE/prototype"
 timeout 180s go test -count=1 ./... | tee "$EVIDENCE/bridge_go_tests.txt"
 timeout 240s go test -race -count=1 ./... | tee "$EVIDENCE/bridge_go_race.txt"
 timeout 120s go vet ./...
)
TMP="$(mktemp -d /tmp/idleleo-parity-bridge.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
timeout 150s bash "$BASE/prototype/run_trial.sh" "$TMP" | tee "$EVIDENCE/bridge_migration_trial.txt"
timeout 240s python3 "$BASE/parity/scripts/run_bridge_contract.py"  # 39 black-box CLI checks; mandatory
