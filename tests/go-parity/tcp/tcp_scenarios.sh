#!/usr/bin/env bash
# Container-side scenarios for the Go-native TCP profile.
#
# Everything runs against a disposable sandbox root: /proc/sys reads and writes
# are redirected under the sandbox, so the Docker VM kernel is never touched.
# This is a mock/kernel-file apply, not a host kernel acceptance.
set -uo pipefail
SRC="${1:?repository mount required}"
OUT="${2:?output mount required}"

export PATH=/usr/local/go/bin:$PATH
export GOTOOLCHAIN=local
export CGO_ENABLED=0
export GOCACHE=/tmp/gocache

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "PASS $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
expect_eq() {
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (want=$3 got=$2)"; fi
}
expect_rc() {
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (want rc=$3 got rc=$2)"; fi
}

cd "$SRC" || exit 1
if ! go build -trimpath -o /tmp/idleleo ./cmd/idleleo; then
  echo "FAIL go build ./cmd/idleleo"
  echo "== Result: 0 passed, 1 failed =="
  exit 1
fi
BIN=/tmp/idleleo

sandbox() { # $1 = dir
  mkdir -p "$1/etc/sysctl.d" "$1/proc/sys/net/ipv4" "$1/proc/sys/net/core" "$1/proc/sys/kernel" "$1/var/lib" "$1/run/lock"
  echo I_ACCEPT_DISPOSABLE_SANDBOX >"$1/.idleleo-phase01-sandbox"
  echo 6.8.0-test >"$1/proc/sys/kernel/osrelease"
  echo cubic >"$1/proc/sys/net/ipv4/tcp_congestion_control"
  echo "cubic bbr reno" >"$1/proc/sys/net/ipv4/tcp_available_congestion_control"
  echo fq_codel >"$1/proc/sys/net/core/default_qdisc"
}

# Real kernel files must stay byte-identical: sandbox redirection is the point.
REAL_CC_BEFORE=$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || echo unavailable)
REAL_QDISC_BEFORE=$(cat /proc/sys/net/core/default_qdisc 2>/dev/null || echo unavailable)

SB=/tmp/tcp-sandbox
sandbox "$SB"

echo "--- status (read-only, sandbox) ---"
"$BIN" --root "$SB" --json tcp status >"$OUT/status-before.json" 2>"$OUT/status-before.err"
expect_rc "status exits 0" "$?" 0
if jq -e '.supported == true and (.availableCongestion | index("bbr")) != null and .managedFile.exists == false' "$OUT/status-before.json" >/dev/null; then
  pass "status reports linux+bbr and no managed file"
else
  fail "status JSON shape: $(cat "$OUT/status-before.json")"
fi

echo "--- plan (read-only) ---"
"$BIN" --root "$SB" --json tcp plan >"$OUT/plan.json" 2>"$OUT/plan.err"
expect_rc "plan exits 0" "$?" 0
if jq -e '.fileAction == "create" and .noop == false and .kernelSupportsBbr == true and (.keys | length) == 2' "$OUT/plan.json" >/dev/null; then
  pass "plan previews create + two keys"
else
  fail "plan JSON shape: $(cat "$OUT/plan.json")"
fi
if [ ! -e "$SB/etc/sysctl.d/90-idleleo-tcp.conf" ]; then
  pass "plan wrote no managed file"
else
  fail "plan wrote a managed file"
fi

echo "--- apply without confirmation (non-TTY) ---"
"$BIN" --root "$SB" tcp apply >"$OUT/apply-unconfirmed.out" 2>&1
expect_rc "unconfirmed apply is exit 2" "$?" 2

echo "--- apply --confirm ---"
"$BIN" --root "$SB" --json tcp apply --confirm >"$OUT/apply.json" 2>"$OUT/apply.err"
expect_rc "apply exits 0" "$?" 0
if jq -e '.changed == true and .noop == false and (.applied | length) == 2' "$OUT/apply.json" >/dev/null; then
  pass "apply reports two key changes"
else
  fail "apply JSON shape: $(cat "$OUT/apply.json")"
fi
expect_eq "sandbox qdisc is fq" "$(cat "$SB/proc/sys/net/core/default_qdisc")" fq
expect_eq "sandbox congestion control is bbr" "$(cat "$SB/proc/sys/net/ipv4/tcp_congestion_control")" bbr
if grep -q "Managed by Xray_bash_onekey" "$SB/etc/sysctl.d/90-idleleo-tcp.conf" 2>/dev/null; then
  pass "managed file carries the ownership marker"
else
  fail "managed file missing or unmarked"
fi

echo "--- status after apply ---"
"$BIN" --root "$SB" --json tcp status >"$OUT/status-after.json" 2>&1
if jq -e '.managedFile.exists == true and .managedFile.owned == true and .state.pending == false' "$OUT/status-after.json" >/dev/null; then
  pass "status shows owned file and committed journal"
else
  fail "post-apply status shape: $(cat "$OUT/status-after.json")"
fi

echo "--- second apply is idempotent ---"
"$BIN" --root "$SB" --json tcp apply --confirm >"$OUT/apply-second.json" 2>&1
expect_rc "second apply exits 0" "$?" 0
if jq -e '.changed == false and .noop == true' "$OUT/apply-second.json" >/dev/null; then
  pass "second apply is a no-op"
else
  fail "second apply was not a no-op: $(cat "$OUT/apply-second.json")"
fi

echo "--- rollback ---"
"$BIN" --root "$SB" --json tcp rollback >"$OUT/rollback.json" 2>"$OUT/rollback.err"
expect_rc "rollback exits 0" "$?" 0
if jq -e '.changed == true' "$OUT/rollback.json" >/dev/null; then
  pass "rollback reports a change"
else
  fail "rollback JSON shape: $(cat "$OUT/rollback.json")"
fi
expect_eq "rollback restores sandbox qdisc" "$(cat "$SB/proc/sys/net/core/default_qdisc")" fq_codel
expect_eq "rollback restores sandbox congestion control" "$(cat "$SB/proc/sys/net/ipv4/tcp_congestion_control")" cubic
if [ ! -e "$SB/etc/sysctl.d/90-idleleo-tcp.conf" ]; then
  pass "rollback removed the file it created"
else
  fail "rollback left the managed file"
fi
if [ ! -e "$SB/var/lib/idleleo/tcp/state.json" ]; then
  pass "rollback removed the journal"
else
  fail "rollback left the journal"
fi

echo "--- rollback without journal ---"
"$BIN" --root "$SB" --json tcp rollback >"$OUT/rollback-noop.json" 2>&1
expect_rc "journal-less rollback exits 0" "$?" 0
if jq -e '.changed == false and .noop == true' "$OUT/rollback-noop.json" >/dev/null; then
  pass "journal-less rollback is a no-op"
else
  fail "journal-less rollback JSON shape: $(cat "$OUT/rollback-noop.json")"
fi

echo "--- sandbox marker gate ---"
UNMARKED=/tmp/tcp-unmarked
mkdir -p "$UNMARKED/etc/sysctl.d" "$UNMARKED/proc/sys/net/ipv4" "$UNMARKED/proc/sys/net/core" "$UNMARKED/proc/sys/kernel"
cp "$SB/proc/sys/kernel/osrelease" "$UNMARKED/proc/sys/kernel/osrelease"
cp "$SB/proc/sys/net/ipv4/tcp_congestion_control" "$UNMARKED/proc/sys/net/ipv4/tcp_congestion_control"
cp "$SB/proc/sys/net/ipv4/tcp_available_congestion_control" "$UNMARKED/proc/sys/net/ipv4/tcp_available_congestion_control"
cp "$SB/proc/sys/net/core/default_qdisc" "$UNMARKED/proc/sys/net/core/default_qdisc"
"$BIN" --root "$UNMARKED" tcp apply --confirm >"$OUT/apply-unmarked.out" 2>&1
expect_rc "unmarked sandbox apply is exit 2" "$?" 2

echo "--- foreign sysctl file is refused ---"
FOREIGN=/tmp/tcp-foreign
sandbox "$FOREIGN"
echo "net.core.default_qdisc = fq" >"$FOREIGN/etc/sysctl.d/90-idleleo-tcp.conf"
"$BIN" --root "$FOREIGN" tcp apply --confirm >"$OUT/apply-foreign.out" 2>&1
expect_rc "foreign managed file is exit 7" "$?" 7

echo "--- higher-priority override is refused ---"
OVERRIDE=/tmp/tcp-override
sandbox "$OVERRIDE"
echo "net.ipv4.tcp_congestion_control = reno" >"$OVERRIDE/etc/sysctl.d/99-operator.conf"
"$BIN" --root "$OVERRIDE" --json tcp plan >"$OUT/plan-override.json" 2>&1
if jq -e '(.conflicts | length) >= 1 and .fileAction == "create"' "$OUT/plan-override.json" >/dev/null; then
  pass "plan reports the 99- operator conflict"
else
  fail "plan conflict shape: $(cat "$OUT/plan-override.json")"
fi
"$BIN" --root "$OVERRIDE" tcp apply --confirm >"$OUT/apply-override.out" 2>&1
expect_rc "conflicting apply is exit 7" "$?" 7

echo "--- unknown profile ---"
"$BIN" --root "$SB" tcp plan --profile bbrplus >"$OUT/plan-unknown.out" 2>&1
expect_rc "unknown profile is exit 2" "$?" 2

echo "--- symlinked managed file ---"
LINKED=/tmp/tcp-symlink
sandbox "$LINKED"
ln -s /tmp/tcp-outside-target "$LINKED/etc/sysctl.d/90-idleleo-tcp.conf"
"$BIN" --root "$LINKED" tcp apply --confirm >"$OUT/apply-symlink.out" 2>&1
LINK_RC=$?
if [ "$LINK_RC" -ne 0 ]; then
  pass "symlinked managed file is refused (rc=$LINK_RC)"
else
  fail "symlinked managed file was accepted"
fi

echo "--- real kernel untouched ---"
REAL_CC_AFTER=$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || echo unavailable)
REAL_QDISC_AFTER=$(cat /proc/sys/net/core/default_qdisc 2>/dev/null || echo unavailable)
expect_eq "real tcp_congestion_control unchanged" "$REAL_CC_AFTER" "$REAL_CC_BEFORE"
expect_eq "real default_qdisc unchanged" "$REAL_QDISC_AFTER" "$REAL_QDISC_BEFORE"

echo "== Result: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
