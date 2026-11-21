#!/usr/bin/env bash
# P2 real-machine driver: exercises doctor/backup/restore/repair/preflight and
# injects real faults (config drift, corrupt config, stale lock, tampered
# archive, a candidate binary that cannot serve) inside an installed container.
#
# Every step records rc/stdout/stderr under $E2E_OUT/<step>/ and one line in
# assertions.txt. A failed assertion is evidence, not a reason to abort the
# remaining independent steps.
set -uo pipefail

OUT="${E2E_OUT:?E2E_OUT required}"
GO=/usr/local/bin/idleleo
CFG=/etc/idleleo/conf/xray/config.json
ART="$OUT/artifacts"
mkdir -p "$OUT" "$ART"
: >"$OUT/assertions.txt"

export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY

log() { printf '%s\n' "$*" | tee -a "$OUT/driver.log"; }
run() {
    local id=$1; shift
    mkdir -p "$OUT/$id"
    "$@" >"$OUT/$id/stdout.txt" 2>"$OUT/$id/stderr.txt"
    local rc=$?
    printf '%s\n' "$rc" >"$OUT/$id/rc.txt"
    return $rc
}
assert() { # assert <ok:0|1> <label>
    if [ "$1" -eq 0 ]; then
        printf 'PASS\t%s\n' "$2" >>"$OUT/assertions.txt"
    else
        printf 'FAIL\t%s\n' "$2" >>"$OUT/assertions.txt"
    fi
}
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

log "driver_start=$(date -u +%Y-%m-%dT%H:%M:%SZ) root=/"

# --- E1 healthy doctor -----------------------------------------------------
run E1-doctor "$GO" doctor --json
rc1=$?
assert $([ "$rc1" -eq 0 ] && echo 0 || echo 1) "doctor exits 0 on an installed root (rc=$rc1)"
assert $(jq -e '.healthy == true and (.checks | length) > 0' "$OUT/E1-doctor/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "doctor reports healthy with checks"

# --- E2 deep doctor: real TCP reachability, Reality stays UNKNOWN ----------
run E2-doctor-deep "$GO" doctor --deep --json
rc2=$?
assert $([ "$rc2" -eq 0 ] && echo 0 || echo 1) "doctor --deep exits 0 (rc=$rc2)"
assert $(jq -e '.checks[] | select(.id=="connectivity") | .status=="unknown" and .evidence=="TCP_REACHABLE"' \
    "$OUT/E2-doctor-deep/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "deep probe proves TCP but refuses to fake a Reality handshake"

# --- E3 backup create/verify with a redacted manifest ----------------------
run E3-backup-create "$GO" backup create --out "$ART/state.tar.gz" --json --container
rc3=$?
assert $([ "$rc3" -eq 0 ] && echo 0 || echo 1) "backup create succeeds (rc=$rc3)"
run E3-backup-verify "$GO" backup verify --archive "$ART/state.tar.gz" --json
assert $([ "$(cat "$OUT/E3-backup-verify/rc.txt")" -eq 0 ] && echo 0 || echo 1) "backup verify accepts its own archive"
tar -xOzf "$ART/state.tar.gz" manifest.json >"$OUT/E3-backup-create/manifest.json" 2>/dev/null
assert $(jq -e '(.entries | length) > 0 and (.restoreLimits | length) >= 3' "$OUT/E3-backup-create/manifest.json" >/dev/null 2>&1 && echo 0 || echo 1) \
    "manifest carries entries and restore limits"
assert $(grep -q 'PRIVATE KEY' "$OUT/E3-backup-create/manifest.json" && echo 1 || echo 0) \
    "manifest carries no private key material"
mode=$(stat -c '%a' "$ART/state.tar.gz")
assert $([ "$mode" = "600" ] && echo 0 || echo 1) "archive is mode 0600 (mode=$mode)"

# --- E4 config drift + dry-run diff proves no write ------------------------
orig=$(sha "$CFG")
printf '\n' >>"$CFG"
drifted=$(sha "$CFG")
assert $([ "$orig" != "$drifted" ] && echo 0 || echo 1) "drift changed the runtime config hash"
run E4-restore-dry-run "$GO" backup restore --archive "$ART/state.tar.gz" --dry-run --json
rc4=$?
same_after=$(sha "$CFG")
assert $([ "$rc4" -eq 0 ] && echo 0 || echo 1) "restore --dry-run exits 0 (rc=$rc4)"
assert $([ "$same_after" = "$drifted" ] && echo 0 || echo 1) "dry run left the drifted config untouched"
assert $(jq -e '[.changes[] | select(.path | endswith("config.json")) | select(.action=="replace")] | length == 1' \
    "$OUT/E4-restore-dry-run/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "dry run reports the config as replace"

# --- E5 real restore returns to the archived state -------------------------
run E5-restore "$GO" backup restore --archive "$ART/state.tar.gz" --container --json
rc5=$?
restored=$(sha "$CFG")
assert $([ "$rc5" -eq 0 ] && echo 0 || echo 1) "restore exits 0 (rc=$rc5)"
assert $([ "$restored" = "$orig" ] && echo 0 || echo 1) "restore reproduced the archived config hash"
pre=$(jq -r '.preBackup // ""' "$OUT/E5-restore/stdout.txt")
assert $([ -n "$pre" ] && [ -f "$pre" ] && echo 0 || echo 1) "restore wrote a pre-restore backup"

# --- E6 tampered archive is rejected without touching live files -----------
cp "$ART/state.tar.gz" "$ART/tampered.tar.gz"
printf 'not-a-gzip-member' >>"$ART/tampered.tar.gz"
run E6-verify-tampered "$GO" backup verify --archive "$ART/tampered.tar.gz" --json
assert $([ "$(cat "$OUT/E6-verify-tampered/rc.txt")" -ne 0 ] && echo 0 || echo 1) "verify rejects a tampered archive"
before6=$(sha "$CFG")
run E6-restore-tampered "$GO" backup restore --archive "$ART/tampered.tar.gz" --container --json
assert $([ "$(cat "$OUT/E6-restore-tampered/rc.txt")" -ne 0 ] && echo 0 || echo 1) "restore rejects a tampered archive"
assert $([ "$(sha "$CFG")" = "$before6" ] && echo 0 || echo 1) "rejected restore did not change the config"

# --- E7 stale lock: doctor warns, repair --fix-lock clears it --------------
mkdir -p /run/lock
touch /run/lock/idleleo-update.lock
touch -d '3 hours ago' /run/lock/idleleo-update.lock
run E7-doctor-lock "$GO" doctor --json
assert $(jq -e '.checks[] | select(.id=="lock") | .status=="warn"' "$OUT/E7-doctor-lock/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "doctor warns about the stale lock"
run E7-repair-dry "$GO" repair --dry-run --json
assert $(jq -e '[.remaining[] | select(test("stale update lock"))] | length == 1' "$OUT/E7-repair-dry/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "repair --dry-run reports the stale lock without removing it"
assert $([ -f /run/lock/idleleo-update.lock ] && echo 0 || echo 1) "dry run kept the lock file"
run E7-repair-fix "$GO" repair --fix-lock --container --json
rc7=$?
assert $([ "$rc7" -eq 0 ] && echo 0 || echo 1) "repair --fix-lock exits healthy (rc=$rc7)"
assert $([ ! -e /run/lock/idleleo-update.lock ] && echo 0 || echo 1) "repair removed the stale lock"

# --- E8 corrupt config: doctor fails, repair refuses, restore recovers ----
cp "$CFG" /tmp/p2-config-backup.json
printf '{"inbounds":[' >"$CFG"
run E8-doctor-corrupt "$GO" doctor --json
assert $([ "$(cat "$OUT/E8-doctor-corrupt/rc.txt")" -ne 0 ] && echo 0 || echo 1) "doctor fails on corrupt JSON"
run E8-repair-corrupt "$GO" repair --dry-run --json
assert $(jq -e '[.remaining[] | select(test("not valid JSON"))] | length == 1' "$OUT/E8-repair-corrupt/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "repair refuses to invent a config and reports it"
run E8-restore-recover "$GO" backup restore --archive "$ART/state.tar.gz" --container --json
assert $([ "$(cat "$OUT/E8-restore-recover/rc.txt")" -eq 0 ] && echo 0 || echo 1) "restore recovers from the corrupt config"
assert $(jq -e . "$CFG" >/dev/null 2>&1 && echo 0 || echo 1) "restored config is valid JSON"

# --- E9 preflight: the installed binary is installable and config-compatible
XVER=$(/usr/local/bin/xray version 2>/dev/null | head -1 | awk '{print $2}')
XSHA=$(sha /usr/local/bin/xray)
XSIZE=$(stat -c '%s' /usr/local/bin/xray)
cat >"$ART/xray-manifest.json" <<EOF
{"schemaVersion":1,"component":"xray","version":"$XVER","sha256":"$XSHA","sizeBytes":$XSIZE,"url":"/usr/local/bin/xray"}
EOF
run E9-preflight "$GO" update preflight --component xray --manifest "$ART/xray-manifest.json" --json
rc9=$?
assert $([ "$rc9" -eq 0 ] && echo 0 || echo 1) "preflight exits 0 for a compatible candidate (rc=$rc9)"
assert $(jq -e '.compatible == true and .digestVerified == true' "$OUT/E9-preflight/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "preflight verifies the digest and marks the candidate compatible"
assert $(jq -e '[.levels[] | select(.name=="installable") | .status=="pass"] | length == 1' "$OUT/E9-preflight/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "installable evidence passes for a real ELF"
assert $(jq -e '[.levels[] | select(.name=="config-parses") | .status=="pass"] | length == 1' "$OUT/E9-preflight/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "config-parses evidence passes for the live config"
assert $(jq -e '[.levels[] | select((.name=="service-starts" or .name=="client-connects") and .status=="not-run")] | length == 2' \
    "$OUT/E9-preflight/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "service/client evidence stays NOT_RUN"

# --- E10 preflight refuses a non-ELF candidate ----------------------------
printf '#!/bin/sh\nexit 0\n' >"$ART/fake-xray"
chmod +x "$ART/fake-xray"
FSHA=$(sha "$ART/fake-xray")
FSIZE=$(stat -c '%s' "$ART/fake-xray")
cat >"$ART/fake-manifest.json" <<EOF
{"schemaVersion":1,"component":"xray","version":"99.0.0","sha256":"$FSHA","sizeBytes":$FSIZE,"url":"$ART/fake-xray"}
EOF
run E10-preflight-nonelf "$GO" update preflight --component xray --manifest "$ART/fake-manifest.json" --json
assert $([ "$(cat "$OUT/E10-preflight-nonelf/rc.txt")" -eq 7 ] && echo 0 || echo 1) "preflight exits 7 for a non-ELF candidate"

# --- E11 preflight refuses a digest mismatch ------------------------------
cat >"$ART/bad-digest.json" <<EOF
{"schemaVersion":1,"component":"xray","version":"$XVER","sha256":"0000000000000000000000000000000000000000000000000000000000000000","sizeBytes":$XSIZE,"url":"/usr/local/bin/xray"}
EOF
run E11-preflight-digest "$GO" update preflight --component xray --manifest "$ART/bad-digest.json" --json
assert $([ "$(cat "$OUT/E11-preflight-digest/rc.txt")" -eq 5 ] && echo 0 || echo 1) "preflight exits 5 on a digest mismatch"

# --- E12 update fault injection: unwritable candidate auto-reverts --------
# /bin/true is a valid ELF, so it installs cleanly and then fails the version
# read. The transaction must restore the previous binary and leave the service
# untouched.
cp /bin/true "$ART/not-xray"
NSHA=$(sha "$ART/not-xray")
NSIZE=$(stat -c '%s' "$ART/not-xray")
cat >"$ART/not-xray.json" <<EOF
{"schemaVersion":1,"component":"xray","version":"99.0.0","sha256":"$NSHA","sizeBytes":$NSIZE,"url":"$ART/not-xray"}
EOF
before12=$(sha /usr/local/bin/xray)
active_before=$(systemctl is-active xray)
run E12-update-rollback "$GO" update xray --manifest "$ART/not-xray.json" --container --json
rc12=$?
assert $([ "$rc12" -eq 6 ] && echo 0 || echo 1) "broken candidate exits 6 (health) (rc=$rc12)"
assert $(jq -e '.rolledBack == true' "$OUT/E12-update-rollback/stdout.txt" >/dev/null 2>&1 && echo 0 || echo 1) \
    "update report marks the rollback"
assert $([ "$(sha /usr/local/bin/xray)" = "$before12" ] && echo 0 || echo 1) "rollback restored the previous xray binary"
assert $([ "$(systemctl is-active xray)" = "$active_before" ] && echo 0 || echo 1) "service state survived the failed update"

# --- E13 post-fault healthy state ----------------------------------------
run E13-doctor-final "$GO" doctor --json
rc13=$?
assert $([ "$rc13" -eq 0 ] && echo 0 || echo 1) "doctor is healthy after every injected fault (rc=$rc13)"

log "driver_done assertions=$(grep -c '^PASS' "$OUT/assertions.txt") pass / $(grep -c '^FAIL' "$OUT/assertions.txt") fail"
grep -q '^FAIL' "$OUT/assertions.txt" && exit 1
exit 0
