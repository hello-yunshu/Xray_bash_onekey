#!/usr/bin/env bash
# Regression guard for the 3.3.5 contract: the Go migration offer must stay
# invisible to ordinary Bash users.
#
# `-u` / `--update` must never arm or call the offer. The only reachable entry
# is the explicit `--internal-bridge-offer` parameter. A future merge that
# reintroduces the old automatic offer must fail here instead of silently
# exposing a migration prompt to 3.3.5 users.
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SH="$REPO/install.sh"
FAILED=0

fail() {
    echo "FAIL: $*" >&2
    FAILED=1
}

ok() {
    echo "ok: $*"
}

[[ -f "$SH" ]] || { echo "FAIL: install.sh not found" >&2; exit 1; }

# 1. The -u / --update branch must not touch the bridge flag.
if sed -n "/'-u' | '--update')/,/;;/p" "$SH" | grep -q 'bridge_manual_invocation'; then
    fail "-u branch still references bridge_manual_invocation"
else
    ok "-u branch is free of bridge arming"
fi

# 2. The update implementation must not reference or call the offer at all.
# Strip comments so the explaining comment above stays allowed.
impl=$(sed -n '/^_update_sh_impl()/,/^}/p' "$SH" | sed 's/#.*$//')
if printf '%s\n' "$impl" | grep -qE 'bridge_migration_offer|internal-bridge-offer|bridge_manual_invocation'; then
    fail "update implementation can reach the Go migration offer"
else
    ok "update implementation cannot reach the Go migration offer"
fi

# 3. Only explicit parameter branches may arm the flag: exactly two sites,
#    each immediately followed by the offer call, inside an internal-bridge-offer
#    case label.
sites=$(grep -n 'bridge_manual_invocation="on"' "$SH" | cut -d: -f1)
site_count=$(printf '%s\n' "$sites" | grep -c . || true)
if [[ "$site_count" -ne 2 ]]; then
    fail "expected exactly 2 explicit arming sites, found $site_count"
else
    ok "only the 2 explicit parameter branches arm the offer"
fi
for ln in $sites; do
    if ! sed -n "$((ln + 1))p" "$SH" | grep -q 'bridge_migration_offer'; then
        fail "arming site line $ln is not immediately followed by the offer call"
    fi
    if ! sed -n "$((ln - 7)),$((ln))p" "$SH" | grep -q 'internal-bridge-offer'; then
        fail "arming site line $ln is not inside an --internal-bridge-offer branch"
    fi
done

# 4. Dynamic: sourcing leaves the flag off, and `list -u` never arms it.
set +u
_TEST_MODE=1 . "$SH" >/dev/null 2>&1 || { echo "FAIL: cannot source install.sh" >&2; exit 1; }
set -u
[[ "${bridge_manual_invocation:-off}" == "off" ]] \
    && ok "bridge flag is off after load" \
    || fail "bridge flag is armed after load"

update_called=0
update_sh() { update_called=1; return 0; }
list -u >/dev/null 2>&1
[[ "$update_called" -eq 1 ]] \
    && ok "-u still reaches update_sh" \
    || fail "-u did not reach update_sh"
[[ "${bridge_manual_invocation:-off}" == "off" ]] \
    && ok "-u leaves the bridge flag off" \
    || fail "-u armed the bridge flag"

# 5. Dynamic: the explicit parameter must still reach the offer.
probe=$(mktemp)
(
    bridge_migration_offer() { printf 'offer-called\n' >"$probe"; return 0; }
    list --internal-bridge-offer >/dev/null 2>&1
) || true
if grep -q 'offer-called' "$probe" 2>/dev/null; then
    ok "--internal-bridge-offer still reaches the offer"
else
    fail "--internal-bridge-offer no longer reaches the offer"
fi
rm -f "$probe"

if [[ "$FAILED" -ne 0 ]]; then
    echo "bridge offer dormancy check FAILED" >&2
    exit 1
fi
echo "bridge offer dormancy check PASSED"
