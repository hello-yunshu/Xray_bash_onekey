#!/usr/bin/env bash

set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
installer=${repo}/install.sh

grep -Fq 'echo "0 1 * * * bash \"${auto_update_file}\""' "${installer}"
if grep -Fq '0 1 15 * *' "${installer}"; then
    echo 'FAIL: monthly VPS auto-update schedule is still present' >&2
    exit 1
fi

echo 'Daily VPS auto-update schedule contract passed'
