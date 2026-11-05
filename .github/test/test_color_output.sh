#!/usr/bin/env bash
# Requires: python3. A minimal Debian image may not ship it; report an explicit
# SKIP instead of failing with rc=127 for the interpreter itself.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 required for the ANSI color regression"
    exit 0
fi
exec python3 "${HERE}/test_color_output.py" "$@"
