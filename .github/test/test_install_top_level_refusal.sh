#!/usr/bin/env bash
# S1: a Go-owned root must make the ONLINE mutation entrypoint (install.sh -u)
# exit at the metadata gate, before OS validation, logging, any network or
# package call, and any /etc write.
#
# Position evidence is the runtime trace (bash -x): the gate helper is reached
# and every later stage is absent. That proves the refusal point without
# trusting a line number.
#
# Preconditions: root, and no /etc/idleleo (fresh runner or container).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
META_DIR=/etc/idleleo
META="$META_DIR/v1/metadata.json"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "must run as root (use sudo)"
[[ ! -e "$META_DIR" ]] || fail "$META_DIR already exists; run on a clean runner"

WORK=$(mktemp -d)
cleanup() {
    rm -rf "$WORK"
    rm -rf "$META_DIR"
}
trap cleanup EXIT

mkdir -p "$META_DIR/v1"
printf '{"schemaVersion":1}\n' >"$META"

CALLS="$WORK/calls.log"
: >"$CALLS"
# Exported shell functions take precedence over binaries regardless of the PATH
# that install.sh resets at line 3, so any network/package/service call is both
# blocked and recorded.
mark() {
    printf '%s\n' "$1" >>"$CALLS"
    return 1
}
for cmd in curl wget apt-get apt dnf yum systemctl; do
    eval "$cmd() { mark $cmd; }"
    export -f "$cmd"
done

before=$(cd / && find etc/idleleo | sort)
set +e
bash -x "$ROOT/install.sh" -u >"$WORK/out.log" 2>"$WORK/err.log"
rc=$?
set -e
after=$(cd / && find etc/idleleo | sort)

[[ $rc -eq 1 ]] || fail "exit code $rc, want 1"
grep -q 'Bash 不再执行配置变更/更新/重装（-u）' "$WORK/err.log" ||
    fail "refusal message missing"
[[ ! -s "$CALLS" ]] ||
    fail "network/package/system command ran: $(tr '\n' ' ' <"$CALLS")"
[[ "$before" == "$after" ]] ||
    fail "system directory changed: $(printf '%s\n' "$before" | diff - "$after" || true)"
grep -q '^+ idleleo_go_refuse_bash_mutation' "$WORK/err.log" ||
    fail "refusal helper was not reached"
! grep -q '^+ validate_supported_system' "$WORK/err.log" ||
    fail "validate_supported_system ran before the refusal"
! grep -q '^+ enable_file_logging' "$WORK/err.log" ||
    fail "file logging was enabled before the refusal"
! grep -q '^+ init_language online' "$WORK/err.log" ||
    fail "online language setup ran before the refusal"
! grep -q '^+ check_file_integrity' "$WORK/err.log" ||
    fail "integrity/network check ran before the refusal"

printf 'PASS: refused at the metadata gate (rc=1); no network, package, log or /etc write\n'
