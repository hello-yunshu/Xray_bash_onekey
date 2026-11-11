#!/usr/bin/env bash
# S1: a Go-owned root must make the ONLINE mutation entrypoint (install.sh -u)
# exit at the metadata gate, before OS validation, logging, any network or
# package call, and any system write.
#
# Position evidence is the runtime trace (bash -x): the gate helper is reached
# and every later stage is absent. That proves the refusal point without
# trusting a line number.
#
# Side-effect evidence is a before/after name snapshot of the writable roots
# (/etc, /var, /tmp, /usr/local). The stubs, the call log and its `mark`
# helper are all exported: install.sh runs as a child bash that resets PATH on
# line 3, and an unexported variable/function would make the "no command ran"
# assertion vacuous. A self-check below fails loudly if the stubs are not
# actually visible to a child bash.
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
export CALLS
: >"$CALLS"
# Exported shell functions take precedence over binaries regardless of the PATH
# that install.sh resets at line 3, so any network/package/service call is both
# blocked and recorded. `mark` must be exported too: the exported stub runs
# inside install.sh's process, where an unexported `mark` does not exist.
mark() {
    printf '%s\n' "$1" >>"$CALLS"
    return 1
}
export -f mark
for cmd in curl wget apt-get apt dnf yum systemctl; do
    eval "$cmd() { mark $cmd; }"
    export -f "$cmd"
done

# Self-check: a child bash must see the exported curl stub after the same PATH
# reset install.sh performs. Without this, an empty CALLS proves nothing.
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin \
    bash -c 'curl https://example.invalid' >/dev/null 2>&1 || true
[[ -s "$CALLS" ]] ||
    fail "stub self-check failed: exported curl did not record a call"
: >"$CALLS"

# Name-level snapshots of every writable root. Name-only comparison ignores
# ordinary growth of existing files (journal, logs) while still catching any
# created/removed path. Known churn is pruned: our own $WORK, systemd's
# per-service private tmp dirs and the journal's rolling file names.
snapshot() {
    (
        cd /
        find etc var tmp usr/local -xdev \
            \( -path "tmp/${WORK#/tmp/}" \
            -o -path 'var/log/journal' -o -path 'var/log/journal/*' \
            -o -path 'tmp/systemd-private-*' -o -path 'var/tmp/systemd-private-*' \
            \) -prune -o -print
    ) | sort
}

before=$(snapshot)
set +e
bash -x "$ROOT/install.sh" -u >"$WORK/out.log" 2>"$WORK/err.log"
rc=$?
set -e
after=$(snapshot)

[[ $rc -eq 1 ]] || fail "exit code $rc, want 1"
grep -q 'Bash 不再执行配置变更/更新/重装（-u）' "$WORK/err.log" ||
    fail "refusal message missing"
[[ ! -s "$CALLS" ]] ||
    fail "network/package/system command ran: $(tr '\n' ' ' <"$CALLS")"
[[ "$before" == "$after" ]] ||
    fail "system tree changed: $(diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") || true)"
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

printf 'PASS: refused at the metadata gate (rc=1); no network, package, log or system write\n'
