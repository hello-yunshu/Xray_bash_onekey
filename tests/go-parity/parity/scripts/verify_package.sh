#!/usr/bin/env bash
# Validate package archive files without executing untrusted manager scripts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
sha256sum -c SHA256SUMS.txt
