#!/usr/bin/env bash
# Phase 01 C01-C12 executable acceptance. Linux container only:
#   bash, coreutils, util-linux (flock/setpriv), git, Go 1.23+.
# Usage: IDLELEO_BIN=/tmp/idleleo GO=/usr/local/go/bin/go bash run_phase01.sh
set -u

BIN=${IDLELEO_BIN:?set IDLELEO_BIN to the built Linux binary}
GO=${GO:-go}
REPO=${REPO:-$(cd "$(dirname "$0")/../../.." && pwd)}
OUT=${PHASE01_EVIDENCE:-$REPO/tests/go-parity/phase01/evidence}
PIN=0fa7052e51b9bd7e6ffb46bc86befb006034da3c
PIN_SHA=a8e4d850da40295303785d17bc3ee629574932b56aef9ae3905baf4e6797358c
WORK=$(mktemp -d "${TMPDIR:-/tmp}/idleleo-p01.XXXXXX")
export TMPDIR="$WORK"
export LANG=C.UTF-8 LC_ALL=C.UTF-8 NO_COLOR=1 TERM=dumb
mkdir -p "$OUT"
TSV="$OUT/c01_c12.tsv"
: >"$TSV"
FAILED=0
TOTAL=0

record() {
  local id=$1 name=$2 cmd=$3 exp=$4 act=$5 pass=$6 detail=$7
  cmd=$(printf '%s' "$cmd" | tr '\t\n' '  ')
  # act may carry a multi-line git diff; keep the TSV one row (and one FAIL row)
  # instead of letting embedded newlines fabricate extra rows and counts.
  act=$(printf '%s' "$act" | tr '\t\n' '  ')
  detail=$(printf '%s' "$detail" | tr '\t\n' '  ')
  TOTAL=$((TOTAL + 1))
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$name" "$cmd" "$exp" "$act" "$pass" "$detail" >>"$TSV"
  if [ "$pass" != 1 ]; then FAILED=$((FAILED + 1)); fi
}

ok() { [ "$1" = 1 ] && echo 1 || echo 0; }

empty_root() {
  local r="$WORK/empty-$1"
  mkdir -p "$r"
  printf '%s' "$r"
}

snapshot() {
  find "$1" -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum 2>/dev/null | sha256sum | cut -d' ' -f1
}

make_sandbox() {
  local name=$1 root="$WORK/sb-$1"
  mkdir -p "$root/etc/idleleo/conf/xray" "$root/etc/idleleo/v1"
  printf '%s\n' 'I_ACCEPT_DISPOSABLE_SANDBOX' >"$root/.idleleo-phase01-sandbox"
  chmod 0600 "$root/.idleleo-phase01-sandbox"
  cat >"$root/etc/idleleo/conf/xray/config.json" <<'JSON'
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "tag": "phase01-synthetic",
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {"clients": [{"id": "00000000-0000-0000-0000-000000000000"}], "decryption": "none"},
    "streamSettings": {"network": "tcp", "security": "reality"}
  }],
  "dns": {"servers": ["203.0.113.53"]},
  "routing": {"rules": [{"type": "field", "ip": ["203.0.113.9"], "outboundTag": "direct"}]},
  "outbounds": [{"protocol": "freedom", "tag": "direct"}],
  "customTop": {"phase": "01", "keep": true}
}
JSON
  local sha
  sha=$(sha256sum "$root/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
  cat >"$root/etc/idleleo/v1/metadata.json" <<JSON
{"schemaVersion":1,"activeEngine":"xray","role":"node","tls":"Reality","transport":"tcp",
 "runtimeConfigPath":"etc/idleleo/conf/xray/config.json","runtimeSha256":"$sha",
 "ownedResources":["xray-config"],"updatedAt":"2026-11-06T00:00:00Z"}
JSON
  printf '%s' "$root"
}

fake() {
  local path=$1 body=$2
  printf '#!/bin/sh\n%s\n' "$body" >"$path"
  chmod 0755 "$path"
}

# C01 read-only commands, zero writes
R=$(empty_root c01)
before=$(snapshot "$R")
"$BIN" version >/dev/null 2>&1
rc=$?
after=$(snapshot "$R")
record C01.1 "version" "$BIN version" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$before" = "$after" ] && echo 1 || echo 0))" "empty root unchanged"
"$BIN" --root "$R" status >/dev/null 2>&1
rc=$?
record C01.2 "status on empty root" "$BIN --root <empty> status" 3 "$rc" "$(ok $([ "$rc" -eq 3 ] && [ "$before" = "$(snapshot "$R")" ] && echo 1 || echo 0))" "not-installed exit, zero files"
SB=$(make_sandbox c01)
before=$(snapshot "$SB")
"$BIN" --root "$SB" --json status >/dev/null 2>&1
rc=$?
record C01.3 "status fixture" "$BIN --root <fixture> --json status" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$before" = "$(snapshot "$SB")" ] && echo 1 || echo 0))" "sha unchanged"
"$BIN" --root "$SB" --json config inspect >/dev/null 2>&1
rc=$?
record C01.4 "config inspect" "$BIN --root <fixture> config inspect --json" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$before" = "$(snapshot "$SB")" ] && echo 1 || echo 0))" "sha unchanged"
"$BIN" --root "$SB" show >/dev/null 2>&1
rc=$?
record C01.5 "show non-root sandbox" "$BIN --root <fixture> show" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$before" = "$(snapshot "$SB")" ] && echo 1 || echo 0))" "sha unchanged"

# C02 no TTY / dumb terminal / no ANSI
timeout 5 "$BIN" </dev/null >"$WORK/c02.out" 2>"$WORK/c02.err"
rc=$?
record C02.1 "no TTY does not hang" "$BIN (stdin=/dev/null)" 2 "$rc" "$(ok $([ "$rc" -eq 2 ] && grep -qi 'TTY' "$WORK/c02.err" && echo 1 || echo 0))" "explained exit 2"
"$BIN" --root "$SB" status >"$WORK/c02.dumb" 2>&1
rc=$?
if grep -q "$(printf '\033')" "$WORK/c02.dumb"; then ansi=0; else ansi=1; fi
record C02.2 "TERM=dumb no ANSI" "TERM=dumb $BIN status" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$ansi" = 1 ] && echo 1 || echo 0))" "no ESC bytes"

# C03 missing/corrupt/schema/unsupported/secret metadata
for item in corrupt:4 schema:5 unsupported:12 secret:4; do
  name=${item%%:*}; exp=${item##*:}
  R=$(empty_root "c03-$name")
  mkdir -p "$R/etc/idleleo/v1"
  case $name in
    corrupt) body='{"schemaVersion":1,' ;;
    schema) body='{"schemaVersion":2,"activeEngine":"xray","role":"node","tls":"Reality"}' ;;
    unsupported) body='{"schemaVersion":1,"activeEngine":"v2ray","role":"node","tls":"Reality"}' ;;
    secret) body='{"schemaVersion":1,"activeEngine":"xray","role":"node","tls":"Reality","uuid":"leak"}' ;;
  esac
  printf '%s' "$body" >"$R/etc/idleleo/v1/metadata.json"
  before=$(snapshot "$R")
  "$BIN" --root "$R" status >/dev/null 2>&1
  rc=$?
  record "C03.$name" "$name metadata" "$BIN --root <$name> status" "$exp" "$rc" "$(ok $([ "$rc" -eq "$exp" ] && [ "$before" = "$(snapshot "$R")" ] && echo 1 || echo 0))" "classified exit"
done
R=$(empty_root c03-missing)
before=$(snapshot "$R")
"$BIN" --root "$R" status >/dev/null 2>&1
rc=$?
record C03.missing "missing metadata" "$BIN --root <empty> status" 3 "$rc" "$(ok $([ "$rc" -eq 3 ] && [ "$before" = "$(snapshot "$R")" ] && echo 1 || echo 0))" "no files created"

# C04 custom fields preserved
SB=$(make_sandbox c04)
before=$(snapshot "$SB")
out=$("$BIN" --root "$SB" --json config inspect 2>&1)
rc=$?
grep -q '"customTop"' <<<"$out"; custom=$?
grep -q '"dns": true' <<<"$out"; dns=$?
record C04.1 "custom dns/routing/top-level" "$BIN config inspect --json" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$custom" -eq 0 ] && [ "$dns" -eq 0 ] && [ "$before" = "$(snapshot "$SB")" ] && echo 1 || echo 0))" "sha unchanged"
"$BIN" --root "$SB" show >"$WORK/c04.show" 2>&1
rc=$?
grep -q 'authority:' "$WORK/c04.show" && auth=0 || auth=1
record C04.2 "show derives authority" "$BIN show" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$auth" -eq 0 ] && echo 1 || echo 0))" "no rewrite"

# C04.3 parse real Bash baseline fixtures (Phase 00 samples)
for fx in reality-direct tls-multi custom-dns-routing; do
  FR=$(empty_root "c04-$fx")
  mkdir -p "$FR/etc/idleleo/conf/xray"
  cp "$REPO/tests/fixtures/legacy/$fx/xray-config.json" "$FR/etc/idleleo/conf/xray/config.json"
  before=$(snapshot "$FR")
  "$BIN" --root "$FR" --json config inspect >/dev/null 2>&1
  rc=$?
  "$BIN" --root "$FR" show >/dev/null 2>&1
  rc2=$?
  record "C04.$fx" "fixture $fx read-only" "$BIN config inspect; $BIN show" 0 "$rc/$rc2" "$(ok $([ "$rc" -eq 0 ] && [ "$rc2" -eq 0 ] && [ "$before" = "$(snapshot "$FR")" ] && echo 1 || echo 0))" "parsed, sha unchanged"
done

# C05 external drift
SB=$(make_sandbox c05)
META="$SB/etc/idleleo/v1/metadata.json"
sed -i 's/"runtimeSha256":"[0-9a-f]*"/"runtimeSha256":"0000000000000000000000000000000000000000000000000000000000000000"/' "$META"
before=$(snapshot "$SB")
"$BIN" --root "$SB" --json status >"$WORK/c05.status" 2>&1
rc=$?
grep -q 'runtime-config-sha-mismatch' "$WORK/c05.status"; drift=$?
record C05.1 "status reports drift" "$BIN status" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$drift" -eq 0 ] && [ "$before" = "$(snapshot "$SB")" ] && echo 1 || echo 0))" "read-only drift report"
"$BIN" --root "$SB" change set-inbound-port --sandbox "$SB" --port 8443 --validator /usr/bin/true >/dev/null 2>&1
rc=$?
record C05.2 "change refuses stale baseline" "$BIN change ... --port 8443" 7 "$rc" "$(ok $([ "$rc" -eq 7 ] && [ "$before" = "$(snapshot "$SB")" ] && echo 1 || echo 0))" "no journal write"

# C06 validator failure
SB=$(make_sandbox c06)
fake "$SB/validator" 'echo synthetic-reject >&2; exit 1'
before=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
"$BIN" --root "$SB" change set-inbound-port --sandbox "$SB" --port 8443 --validator "$SB/validator" >/dev/null 2>"$WORK/c06.err"
rc=$?
after=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
record C06 "validator rejects" "$BIN change --validator <exit 1>" 8 "$rc" "$(ok $([ "$rc" -eq 8 ] && [ "$before" = "$after" ] && grep -q REJECTED "$SB/var/lib/idleleo/transactions/phase01.json" && echo 1 || echo 0))" "target bytes unchanged"

# C07 staged write failure
SB=$(make_sandbox c07)
before=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
"$BIN" --root "$SB" change set-inbound-port --sandbox "$SB" --port 8443 --validator /usr/bin/true --fault write-fail >/dev/null 2>&1
rc=$?
after=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
record C07 "injected write failure" "$BIN change --fault write-fail" 13 "$rc" "$(ok $([ "$rc" -eq 13 ] && [ "$before" = "$after" ] && grep -q FAILED "$SB/var/lib/idleleo/transactions/phase01.json" && echo 1 || echo 0))" "target untouched"

# C08 service failure and rollback without start
SB=$(make_sandbox c08)
fake "$SB/service" 'echo "$@" >>"$0.log"; exit 1'
before=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
"$BIN" --root "$SB" change set-inbound-port --sandbox "$SB" --port 8443 --validator /usr/bin/true --service "$SB/service" >/dev/null 2>&1
rc=$?
after=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
log=$(cat "$SB/service.log" 2>/dev/null)
record C08.1 "service apply failure" "$BIN change --service <exit 1>" 9 "$rc" "$(ok $([ "$rc" -eq 9 ] && [ "$before" = "$after" ] && [ "$log" = apply ] && grep -q ROLLED_BACK "$SB/var/lib/idleleo/transactions/phase01.json" && echo 1 || echo 0))" "restored, only apply invoked"
SB=$(make_sandbox c08b)
before=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
"$BIN" --root "$SB" change set-inbound-port --sandbox "$SB" --port 8443 --validator /usr/bin/true --fault service-fail >/dev/null 2>&1
rc=$?
after=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
record C08.2 "injected service failure" "$BIN change --fault service-fail" 9 "$rc" "$(ok $([ "$rc" -eq 9 ] && [ "$before" = "$after" ] && echo 1 || echo 0))" "restored"

# C06.real: the same transaction against the real Xray validator (optional).
if [ -n "${XRAY_BIN:-}" ] && [ -x "$XRAY_BIN" ]; then
  SB=$(make_sandbox c06real)
  cp "$REPO/tests/fixtures/legacy/reality-direct/xray-config.json" "$SB/etc/idleleo/conf/xray/config.json"
  sha=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
  sed -i "s/\"runtimeSha256\":\"[0-9a-f]*\"/\"runtimeSha256\":\"$sha\"/" "$SB/etc/idleleo/v1/metadata.json"
  before=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
  "$BIN" --root "$SB" change set-inbound-port --sandbox "$SB" --port 8443 --validator "$XRAY_BIN" >/dev/null 2>"$WORK/c06real.err"
  rc=$?
  after=$(sha256sum "$SB/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
  "$XRAY_BIN" -test -config "$SB/etc/idleleo/conf/xray/config.json" >"$WORK/c06real.test" 2>&1
  xrc=$?
  xver=$("$XRAY_BIN" version 2>/dev/null | head -1)
  record C06.real "real xray validator" "$BIN change --validator <xray>" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$xrc" -eq 0 ] && [ "$before" != "$after" ] && echo 1 || echo 0))" "$xver; xray-test=$xrc; committed"
fi

# C09 concurrent mutation
SB=$(make_sandbox c09)
lock="$SB/run/lock/idleleo-update.lock"
mkdir -p "$(dirname "$lock")"
ready="$WORK/lock.ready"
flock -x "$lock" -c "touch '$ready'; sleep 2" &
flockpid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -f "$ready" ] && break; sleep 0.1; done
before=$(snapshot "$SB")
"$BIN" --root "$SB" change set-inbound-port --sandbox "$SB" --port 8443 --validator /usr/bin/true >/dev/null 2>&1
rc=$?
wait "$flockpid" 2>/dev/null
record C09 "lock contention" "flock held; $BIN change" 7 "$rc" "$(ok $([ "$rc" -eq 7 ] && [ "$before" = "$(snapshot "$SB")" ] && echo 1 || echo 0))" "no write under lock"

# C10 non-root
R=${WORK}/sb-c10
mkdir -p "$R/etc/idleleo/conf/xray" "$R/etc/idleleo/v1" "$R/var/lib/idleleo/transactions" "$R/run/lock"
cp "$SB/etc/idleleo/conf/xray/config.json" "$R/etc/idleleo/conf/xray/config.json"
cp "$SB/etc/idleleo/v1/metadata.json" "$R/etc/idleleo/v1/metadata.json"
chmod -R a+rX "$R"
chmod 0711 "$WORK"
chmod 0777 "$R/var/lib/idleleo/transactions" "$R/run/lock"
BEFORE10=$(sha256sum "$R/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)
if [ "$(id -u)" = 0 ] && command -v setpriv >/dev/null; then
  setpriv --reuid=65534 --regid=65534 --clear-groups "$BIN" --root "$R" --json status >/dev/null 2>&1
  rc=$?
  record C10.1 "non-root status" "setpriv nobody $BIN status" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$BEFORE10" = "$(sha256sum "$R/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)" ] && echo 1 || echo 0))" "read-only"
  setpriv --reuid=65534 --regid=65534 --clear-groups "$BIN" frobnicate >/dev/null 2>&1
  rc=$?
  record C10.2 "non-root illegal command" "setpriv nobody $BIN frobnicate" 2 "$rc" "$(ok $([ "$rc" -eq 2 ] && [ "$BEFORE10" = "$(sha256sum "$R/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)" ] && echo 1 || echo 0))" "no mutation"
  setpriv --reuid=65534 --regid=65534 --clear-groups "$BIN" --root "$R" change set-inbound-port --sandbox "$R" --port 8443 --validator /usr/bin/true >/dev/null 2>&1
  rc=$?
  record C10.3 "non-root change refused" "setpriv nobody $BIN change" nonzero "$rc" "$(ok $([ "$rc" -ne 0 ] && [ "$BEFORE10" = "$(sha256sum "$R/etc/idleleo/conf/xray/config.json" | cut -d' ' -f1)" ] && echo 1 || echo 0))" "no write"
else
  record C10.1 "non-root checks" "setpriv" skipped skipped 0 "setpriv unavailable"
fi

# C11 cross build
(cd "$REPO" && GOOS=linux GOARCH=amd64 "$GO" build -trimpath -o "$WORK/idleleo-amd64" ./cmd/idleleo) >"$WORK/c11.log" 2>&1
rc=$?
size=$(stat -c %s "$WORK/idleleo-amd64" 2>/dev/null || echo 0)
record C11.1 "linux/amd64 build" "GOOS=linux GOARCH=amd64 go build" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$size" -gt 0 ] && echo 1 || echo 0))" "bytes=$size"
(cd "$REPO" && GOOS=linux GOARCH=arm64 "$GO" build -trimpath -o "$WORK/idleleo-arm64" ./cmd/idleleo) >>"$WORK/c11.log" 2>&1
rc=$?
size2=$(stat -c %s "$WORK/idleleo-arm64" 2>/dev/null || echo 0)
record C11.2 "linux/arm64 build" "GOOS=linux GOARCH=arm64 go build" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && [ "$size2" -gt 0 ] && echo 1 || echo 0))" "bytes=$size2"
"$BIN" version >/dev/null 2>&1
rc=$?
record C11.3 "current-arch binary runs" "$BIN version" 0 "$rc" "$(ok $([ "$rc" -eq 0 ] && echo 1 || echo 0))" "$(uname -m)"

# C12 legacy Bash entry untouched
actual_sha=$(sha256sum "$REPO/install.sh" | cut -d' ' -f1)
record C12.1 "install.sh bytes match pin" "sha256sum install.sh" "$PIN_SHA" "$actual_sha" "$(ok $([ "$actual_sha" = "$PIN_SHA" ] && echo 1 || echo 0))" "pin $PIN"
diffout=$(cd "$REPO" && git diff --stat "$PIN..HEAD" -- install.sh scripts config 2>&1)
record C12.2 "product code diff empty" "git diff $PIN..HEAD -- install.sh scripts config" empty "$([ -z "$diffout" ] && echo empty || echo "$diffout")" "$(ok $([ -z "$diffout" ] && echo 1 || echo 0))" "no Bash core change"
legacy=$(test -e /etc/idleleo/install.sh && echo LEGACY_TOUCHED || true)
record C12.3 "Go does not install over Bash entry" "test -e /etc/idleleo/install.sh" empty "$legacy" "$(ok $([ -z "$legacy" ] && echo 1 || echo 0))" "legacy path absent"
# C12.4 loads the *published* pin, not the working tree: develop may legitimately
# carry an unreleased 3.3.5, and that must not be reported as a broken legacy.
pinsh=$(mktemp)
git -C "$REPO" show "$PIN:install.sh" >"$pinsh"
ver=$(cd "$REPO" && PIN_SH="$pinsh" bash -c '_TEST_MODE=1 . "$PIN_SH" >/dev/null 2>&1; printf "%s" "$shell_version"')
rm -f "$pinsh"
record C12.4 "published Bash pin still loads" "_TEST_MODE=1 source git $PIN:install.sh; echo shell_version" 3.3.6 "$ver" "$(ok $([ "$ver" = 3.3.6 ] && echo 1 || echo 0))" "published pin untouched"

{
  echo "# Phase 01 C01-C12 evidence"
  echo
  echo "- Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Binary: $BIN (sha256 $(sha256sum "$BIN" | cut -d' ' -f1))"
  echo "- Image: ${PHASE01_IMAGE:-unspecified}"
  echo "- Arch: $(uname -m); kernel: $(uname -r)"
  if [ -n "${XRAY_BIN:-}" ] && [ -x "$XRAY_BIN" ]; then
    echo "- Xray: $("$XRAY_BIN" version 2>/dev/null | head -1) (sha256 $(sha256sum "$XRAY_BIN" | cut -d' ' -f1))"
  else
    echo "- Xray: not supplied (C06.real skipped)"
  fi
  echo "- Pin: $PIN; install.sh sha256: $PIN_SHA"
  echo "- Result: $((TOTAL - FAILED))/$TOTAL passed, $FAILED failed"
  echo
  echo "| ID | Check | Expected | Actual | Pass | Detail |"
  echo "|---|---|---|---|---|---|"
  awk -F '\t' '{printf "| %s | %s | %s | %s | %s | %s |\n", $1,$2,$4,$5,($6==1?"PASS":"FAIL"),$7}' "$TSV"
} >"$OUT/c01_c12.md"

echo "PHASE01: $((TOTAL - FAILED))/$TOTAL passed, $FAILED failed"
echo "evidence: $OUT/c01_c12.tsv"
[ "$FAILED" -eq 0 ]
