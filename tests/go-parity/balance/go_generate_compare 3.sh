#!/usr/bin/env bash
# Inside the container: run the Go CLI with the same parameters as the Bash
# reference, xray -test the result, then compare artifacts field by field.
set -uo pipefail

OUT="${BAL_OUT:?BAL_OUT required}"
GO_BIN="${BAL_GO_BIN:?BAL_GO_BIN required}"
XRAY_BIN="${BAL_XRAY_BIN:-/seed/xray}"
PORT="${BAL_PORT:-8443}"
SERVERNAME="${BAL_SERVERNAME:-www.cloudflare.com}"
UUID_VALUE="${BAL_UUID:?BAL_UUID required}"
PRIVATE_KEY="${BAL_PRIVATE_KEY:?BAL_PRIVATE_KEY required}"
SHORT_ID="${BAL_SHORT_ID:?BAL_SHORT_ID required}"

overall=0
mkdir -p /var/log/xray
for role in primary secondary; do
    d="$OUT/$role/go"
    mkdir -p "$d/fragments"
    args=(
        xray generate
        --mode reality-balance --role "$role" --port "$PORT"
        --server-names "$SERVERNAME" --target "$SERVERNAME:443"
        --uuid "$UUID_VALUE" --private-key "$PRIVATE_KEY" --short-id "$SHORT_ID"
        --email "me@hey.run"
        --out "$d/config.json" --force --json
    )
    if [[ "$role" == "primary" ]]; then
        args+=(--nginx-out "$d/00-xray.conf" --fragments-out "$d/fragments")
    fi
    "$GO_BIN" "${args[@]}" >"$d/generate.json" 2>"$d/generate.err"
    gen_rc=$?
    if [[ "$gen_rc" -ne 0 ]]; then
        printf 'go_generate_exit=%s\n' "$gen_rc" >>"$OUT/$role/result.txt"
        overall=1
        continue
    fi
    printf 'go_generate_exit=0\n' >>"$OUT/$role/result.txt"

    "$XRAY_BIN" -test -config "$d/config.json" >"$d/xray-test.log" 2>&1
    test_rc=$?
    printf 'go_xray_test_exit=%s\n' "$test_rc" >>"$OUT/$role/result.txt"
    if [[ "$test_rc" -ne 0 ]]; then
        overall=1
    fi

    cmp_args=(
        --bash-dir "$OUT/$role/bash"
        --go-conf "$d/config.json"
        --role "$role"
        --out "$OUT/$role/compare.json"
    )
    if [[ "$role" == "primary" ]]; then
        cmp_args+=(--go-nginx "$d/00-xray.conf" --go-fragments "$d/fragments")
    fi
    python3 /src/tests/go-parity/balance/compare_balance.py "${cmp_args[@]}" \
        >"$OUT/$role/compare.log" 2>&1
    cmp_rc=$?
    printf 'compare_exit=%s\n' "$cmp_rc" >>"$OUT/$role/result.txt"
    # compare: 0=MATCH, 2=MATCH_CORE_FIELDS (AGP-free CORE), 1=GAP
    if [[ "$cmp_rc" -eq 1 ]]; then
        overall=1
    fi
done

for role in primary secondary; do
    echo "-- $role --"
    cat "$OUT/$role/result.txt"
done
exit "$overall"
