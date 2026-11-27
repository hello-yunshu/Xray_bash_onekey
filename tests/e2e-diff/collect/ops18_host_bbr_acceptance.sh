#!/usr/bin/env bash
# OPS-18 real-kernel acceptance. Run only as root on a disposable Linux VM.
# The caller must make tcp_bbr available; this script never installs a kernel
# module and always rolls the managed profile back before returning.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN="${IDLELEO_BIN:-}"
OUT="${OPS18_EVIDENCE_DIR:-}"
MANAGED=/etc/sysctl.d/90-idleleo-tcp.conf
STATE=/var/lib/idleleo/tcp/state.json
APPLIED=0
RESTORE_RUNTIME=0
ORIGINAL_QDISC=""
ORIGINAL_CC=""

if [[ "$(id -u)" != 0 ]]; then
    echo "OPS-18 requires a root disposable VM" >&2
    exit 2
fi
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    echo "IDLELEO_BIN must name the built Go CLI" >&2
    exit 2
fi
if [[ -z "$OUT" ]]; then
    echo "OPS18_EVIDENCE_DIR must name a temporary evidence directory" >&2
    exit 2
fi
mkdir -p "$OUT"

rollback_on_exit() {
    if [[ "$APPLIED" == 1 ]]; then
        "$BIN" tcp rollback --json >"$OUT/emergency-rollback.json" 2>"$OUT/emergency-rollback.err" || true
    fi
    if [[ "$RESTORE_RUNTIME" == 1 ]]; then
        sysctl -w "net.core.default_qdisc=$ORIGINAL_QDISC" >"$OUT/restore-original-qdisc.log" 2>&1 || true
        sysctl -w "net.ipv4.tcp_congestion_control=$ORIGINAL_CC" >"$OUT/restore-original-congestion.log" 2>&1 || true
    fi
}
trap rollback_on_exit EXIT

if [[ -e "$MANAGED" || -e "$STATE" ]]; then
    echo "refusing a non-clean runner: managed file or state already exists" >&2
    exit 3
fi
if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
    echo "running kernel has no BBR congestion-control module" >&2
    cat /proc/sys/net/ipv4/tcp_available_congestion_control >&2
    exit 78
fi

KERNEL="$(uname -r)"
AVAILABLE="$(cat /proc/sys/net/ipv4/tcp_available_congestion_control)"
printf 'kernel=%s\navailable=%s\n' "$KERNEL" "$AVAILABLE" >"$OUT/host.txt"
printf '%s\n' "$(git -C "$ROOT" rev-parse HEAD)" >"$OUT/checkout-sha.txt"
python3 - "$ROOT/tests/e2e-diff/ledger.json" "$OUT/product-code-sha.txt" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[2]).write_text(json.load(open(sys.argv[1]))["codeSha"] + "\n")
PY

# Set an explicit, conventional baseline on the disposable GitHub runner VM so
# apply must make a real change and rollback has an observable target.
ORIGINAL_QDISC="$(cat /proc/sys/net/core/default_qdisc)"
ORIGINAL_CC="$(cat /proc/sys/net/ipv4/tcp_congestion_control)"
RESTORE_RUNTIME=1
BASE_QDISC="$ORIGINAL_QDISC"
BASE_CC="$ORIGINAL_CC"
printf 'baseline_qdisc=%s\nbaseline_congestion=%s\n' "$BASE_QDISC" "$BASE_CC" >>"$OUT/host.txt"
if [[ "$BASE_QDISC" == fq ]]; then
    sysctl -w net.core.default_qdisc=fq_codel >"$OUT/baseline-qdisc.log"
    BASE_QDISC=fq_codel
fi
if [[ "$BASE_CC" == bbr ]]; then
    sysctl -w net.ipv4.tcp_congestion_control=cubic >"$OUT/baseline-congestion.log"
    BASE_CC=cubic
fi
printf 'test_baseline_qdisc=%s\ntest_baseline_congestion=%s\n' "$BASE_QDISC" "$BASE_CC" >>"$OUT/host.txt"
printf 'original_qdisc=%s\noriginal_congestion=%s\n' "$ORIGINAL_QDISC" "$ORIGINAL_CC" >>"$OUT/host.txt"

"$BIN" tcp status --json >"$OUT/status-before.json" 2>"$OUT/status-before.err"
python3 - "$OUT/status-before.json" "$BASE_QDISC" "$BASE_CC" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["supported"] is True, d
assert "bbr" in d["availableCongestion"], d["availableCongestion"]
assert d["current"]["net.core.default_qdisc"] == sys.argv[2], d["current"]
assert d["current"]["net.ipv4.tcp_congestion_control"] == sys.argv[3], d["current"]
PY

"$BIN" tcp plan --profile bbr-fq --json >"$OUT/plan.json" 2>"$OUT/plan.err"
python3 - "$OUT/plan.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["supported"] is True and d["kernelSupportsBbr"] is True, d
assert any(x["key"] == "net.core.default_qdisc" and x["new"] == "fq" for x in d["keys"]), d
assert any(x["key"] == "net.ipv4.tcp_congestion_control" and x["new"] == "bbr" for x in d["keys"]), d
PY

# Exercise the actual Bash compatibility entry. The wrapper sources the real
# install.sh functions in test mode, then delegates apply to the Go manager.
set +e
_TEST_MODE=1 bash -c 'source "$1/install.sh"; bbr_boost_sh --apply' _ "$ROOT" \
    >"$OUT/bash-apply.log" 2>"$OUT/bash-apply.err"
BASH_APPLY_RC=$?
set -e
printf '%s\n' "$BASH_APPLY_RC" >"$OUT/bash-apply.rc"
if [[ "$BASH_APPLY_RC" != 0 ]]; then
    exit 1
fi
APPLIED=1

"$BIN" tcp status --json >"$OUT/status-applied.json" 2>"$OUT/status-applied.err"
python3 - "$OUT/status-applied.json" "$MANAGED" "$STATE" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1]))
assert d["current"].get("net.core.default_qdisc") == "fq", d["current"]
assert d["current"].get("net.ipv4.tcp_congestion_control") == "bbr", d["current"]
assert d["managedFile"]["exists"] is True and d["managedFile"]["owned"] is True, d["managedFile"]
assert d.get("state", {}).get("pending") is False, d.get("state")
assert os.path.isfile(sys.argv[2]) and os.path.isfile(sys.argv[3])
PY

"$BIN" tcp rollback --json >"$OUT/bash-path-rollback.json" 2>"$OUT/bash-path-rollback.err"
APPLIED=0
"$BIN" tcp status --json >"$OUT/status-bash-rolled-back.json" 2>"$OUT/status-bash-rolled-back.err"
python3 - "$OUT/status-bash-rolled-back.json" "$MANAGED" "$STATE" "$BASE_QDISC" "$BASE_CC" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1]))
assert d["current"].get("net.core.default_qdisc") == sys.argv[4], d["current"]
assert d["current"].get("net.ipv4.tcp_congestion_control") == sys.argv[5], d["current"]
assert d["managedFile"]["exists"] is False, d["managedFile"]
assert d.get("state") is None, d.get("state")
assert not os.path.exists(sys.argv[2]) and not os.path.exists(sys.argv[3])
PY

# Exercise the native Go entry separately from the Bash wrapper path.
"$BIN" tcp apply --profile bbr-fq --confirm --json >"$OUT/go-apply.json" 2>"$OUT/go-apply.err"
APPLIED=1
"$BIN" tcp status --json >"$OUT/status-go-applied.json" 2>"$OUT/status-go-applied.err"
python3 - "$OUT/status-go-applied.json" "$MANAGED" "$STATE" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1]))
assert d["current"].get("net.core.default_qdisc") == "fq", d["current"]
assert d["current"].get("net.ipv4.tcp_congestion_control") == "bbr", d["current"]
assert d["managedFile"]["exists"] is True and d["managedFile"]["owned"] is True, d["managedFile"]
assert os.path.isfile(sys.argv[2]) and os.path.isfile(sys.argv[3])
PY
"$BIN" tcp rollback --json >"$OUT/go-rollback.json" 2>"$OUT/go-rollback.err"
APPLIED=0
"$BIN" tcp status --json >"$OUT/status-after.json" 2>"$OUT/status-after.err"
python3 - "$OUT/status-after.json" "$MANAGED" "$STATE" "$BASE_QDISC" "$BASE_CC" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1]))
assert d["current"].get("net.core.default_qdisc") == sys.argv[4], d["current"]
assert d["current"].get("net.ipv4.tcp_congestion_control") == sys.argv[5], d["current"]
assert d["managedFile"]["exists"] is False, d["managedFile"]
assert d.get("state") is None, d.get("state")
assert not os.path.exists(sys.argv[2]) and not os.path.exists(sys.argv[3])
PY

sysctl -w "net.core.default_qdisc=$ORIGINAL_QDISC" >"$OUT/restore-original-qdisc.log"
sysctl -w "net.ipv4.tcp_congestion_control=$ORIGINAL_CC" >"$OUT/restore-original-congestion.log"
RESTORE_RUNTIME=0
FINAL_QDISC="$(cat /proc/sys/net/core/default_qdisc)"
FINAL_CC="$(cat /proc/sys/net/ipv4/tcp_congestion_control)"
printf 'final_qdisc=%s\nfinal_congestion=%s\n' "$FINAL_QDISC" "$FINAL_CC" >>"$OUT/host.txt"
[[ "$FINAL_QDISC" == "$ORIGINAL_QDISC" && "$FINAL_CC" == "$ORIGINAL_CC" ]]

printf 'PASS: real BBR Bash-wrapper and Go apply/rollback on %s\n' "$KERNEL" >"$OUT/result.txt"
