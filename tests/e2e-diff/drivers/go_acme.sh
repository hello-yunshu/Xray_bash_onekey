#!/usr/bin/env bash
# M8 ACME driver: one real `xray cert issue` against the scenario-local Pebble,
# then the ordinary Go install with that pair. Kept as a thin wrapper so the
# L0-L5 collection stays byte-for-byte identical to go_install.sh.
set -uo pipefail
export E2E_ACME=1
exec bash /src/tests/e2e-diff/drivers/go_install.sh "$@"
