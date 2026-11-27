#!/usr/bin/env bash
# Gate: running the ledger contract tests must never modify the tracked
# acceptance summaries. The audit found a test that silently rewrote
# docs/go-evolution/hardening/acceptance.json with synthetic data.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FILES=(
  "tests/e2e-diff/ledger.json"
  "tests/e2e-diff/matrix.json"
  "docs/go-evolution/hardening/acceptance.json"
)

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

snapshot() {
  cd "$ROOT"
  for f in "${FILES[@]}"; do
    if [ -f "$f" ]; then
      sha256 "$f"
    else
      printf 'MISSING  %s\n' "$f"
    fi
  done
}

before="$(snapshot)"
python3 -m unittest discover -s "$ROOT/tests/e2e-diff/collect" -p 'test_*.py'
after="$(snapshot)"

if [ "$before" != "$after" ]; then
  echo "FAIL: ledger contract tests modified a tracked acceptance artifact" >&2
  diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") >&2 || true
  exit 1
fi
echo "PASS: tracked acceptance artifacts are byte-identical after the ledger tests"
