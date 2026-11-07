#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${1:-$(mktemp -d /tmp/idleleo-v2-trial.XXXXXX)}"
mkdir -p "$OUTDIR"
cd "$ROOTDIR"
go build -o "$OUTDIR/bridge-v2" .
PIN="$(sha256sum "$OUTDIR/bridge-v2" | cut -d' ' -f1)"
for mode in reality tls relay; do
  BASE="$OUTDIR/host-$mode"
  python3 testdata/make_v4_sandbox.py "$BASE" "$mode"
  # v4's absolute legacy link points outside a relocated sandbox. Use the
  # equivalent relative target to make the original executable genuinely runnable.
  ln -sfn ../../etc/idleleo/install.sh "$BASE/usr/bin/idleleo"
  test -x "$BASE/usr/bin/idleleo"
  echo "--- $mode: original Bash entry is executable ---"
  "$BASE/usr/bin/idleleo"
  mkdir -p "$BASE/opt/idleleo/bin"
  cp "$OUTDIR/bridge-v2" "$BASE/opt/idleleo/bin/idleleo"
  chmod 0700 "$BASE/opt/idleleo/bin/idleleo"
  if [ "$mode" = relay ];then RUNTIME="$BASE/etc/idleleo/conf/nginx/relay-stream.conf";else RUNTIME="$BASE/etc/idleleo/conf/xray/config.json";fi
  PRE="$(sha256sum "$RUNTIME" | cut -d' ' -f1)"
  "$OUTDIR/bridge-v2" -root "$BASE" -mode inspect > "$OUTDIR/$mode-plan.json"
  "$OUTDIR/bridge-v2" -root "$BASE" -mode prepare -candidate-sha256 "$PIN" > "$OUTDIR/$mode-prepared.json"
  set +e
  "$OUTDIR/bridge-v2" -root "$BASE" -mode activate -fault after-swap > "$OUTDIR/$mode-interrupted.stdout" 2> "$OUTDIR/$mode-interrupted.stderr"
  RC=$?
  set -e
  test "$RC" -eq 86
  "$OUTDIR/bridge-v2" -root "$BASE" -mode status > "$OUTDIR/$mode-pending.json"
  # This is a separate process executing the recovery API, not the switched entry.
  "$OUTDIR/bridge-v2" -root "$BASE" -mode recover > "$OUTDIR/$mode-recovered.json"
  "$OUTDIR/bridge-v2" -root "$BASE" -mode status > "$OUTDIR/$mode-final-status.json"
  test "$(jq -r .state "$OUTDIR/$mode-recovered.json")" = ROLLED_BACK
  test "$(jq -r .entryIsLegacy "$OUTDIR/$mode-final-status.json")" = true
  test "$(jq -r .entryIsGo "$OUTDIR/$mode-final-status.json")" = false
  test "$(sha256sum "$RUNTIME" | cut -d' ' -f1)" = "$PRE"
  test ! -e "$BASE/etc/idleleo/manager/config.json"
  "$BASE/usr/bin/idleleo" # verify the old legacy executable really works
  echo "PASS $mode: interrupted process, separate recover, legacy executable and runtime hash intact"
done
MODE=xtls
BASE="$OUTDIR/host-$MODE"
python3 testdata/make_v4_sandbox.py "$BASE" "$MODE"
ln -sfn ../../etc/idleleo/install.sh "$BASE/usr/bin/idleleo"
set +e
"$OUTDIR/bridge-v2" -root "$BASE" -mode inspect >/dev/null 2> "$OUTDIR/xtls-rejected.txt"
RC=$?
set -e
test "$RC" -eq 2
test ! -e "$BASE/var/lib/idleleo/transactions/bridge-v2.json"
echo "PASS xtls: rejected without journal"
BASE="$OUTDIR/host-success"
python3 testdata/make_v4_sandbox.py "$BASE" reality
ln -sfn ../../etc/idleleo/install.sh "$BASE/usr/bin/idleleo"
mkdir -p "$BASE/opt/idleleo/bin"
cp "$OUTDIR/bridge-v2" "$BASE/opt/idleleo/bin/idleleo"
"$OUTDIR/bridge-v2" -root "$BASE" -mode prepare -candidate-sha256 "$PIN" >/dev/null
"$OUTDIR/bridge-v2" -root "$BASE" -mode activate > "$OUTDIR/success-committed.json"
"$BASE/usr/bin/idleleo" --bridge-self-check > "$OUTDIR/success-real-executable.json"
"$BASE/usr/bin/idleleo" -root "$BASE" -mode status > "$OUTDIR/success-status.json"
test "$(jq -r .state "$OUTDIR/success-status.json")" = COMMITTED
echo "PASS success: real executable available through switched relative link"
echo "EVIDENCE_DIR=$OUTDIR"
