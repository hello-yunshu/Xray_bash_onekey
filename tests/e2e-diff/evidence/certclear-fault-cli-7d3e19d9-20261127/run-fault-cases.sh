#!/usr/bin/env bash
set -euo pipefail
BASE="$PWD"
EVID="$BASE/tests/e2e-diff/evidence/certclear-fault-cli-7d3e19d9-20261127"
BIN="$BASE/tests/e2e-diff/evidence/ops-core-7d3e19d9-20261127/p2/build/idleleo"
IMAGE=debian:bookworm-slim
TMPROOT=$(mktemp -d /tmp/xray-certclear-fault.XXXXXX)
trap 'python3 - "$TMPROOT" <<"PYTRAP"
import pathlib, shutil, sys
p=pathlib.Path(sys.argv[1])
if p.parent == pathlib.Path("/tmp") and p.name.startswith("xray-certclear-fault."):
    shutil.rmtree(p, ignore_errors=True)
PYTRAP' EXIT
setup_root() {
  local root="$1"
  mkdir -p "$root/etc/idleleo/cert" "$root/var/lib/idleleo/certclear/staging"
  printf 'I_ACCEPT_DISPOSABLE_SANDBOX\n' > "$root/.idleleo-phase01-sandbox"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=certclear-fault.local" \
    -keyout "$root/etc/idleleo/cert/xray.key" -out "$root/etc/idleleo/cert/xray.crt" >/dev/null 2>&1
  chmod 0644 "$root/etc/idleleo/cert/xray.crt"
  chmod 0600 "$root/etc/idleleo/cert/xray.key"
  local crt key
  crt=$(sha256sum "$root/etc/idleleo/cert/xray.crt" | awk '{print $1}')
  key=$(sha256sum "$root/etc/idleleo/cert/xray.key" | awk '{print $1}')
  cat > "$root/etc/idleleo/cert/.managed-by-idleleo" <<EOF
managed-by=idleleo
format=2
file=xray.crt	type=regular	sha256=$crt
file=xray.key	type=regular	sha256=$key
EOF
  chmod 0600 "$root/etc/idleleo/cert/.managed-by-idleleo"
}
snapshot() {
  local root="$1" dest="$2"
  (cd "$root" && find etc/idleleo/cert -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum) > "$dest.sha256"
  python3 - "$root" > "$dest.modes" <<'PYMODE'
import os, pathlib, sys
r=pathlib.Path(sys.argv[1])
for rel in ('etc/idleleo/cert/xray.crt','etc/idleleo/cert/xray.key','etc/idleleo/cert/.managed-by-idleleo'):
 print(f'{os.stat(r/rel).st_mode & 0o777:04o} {rel}')
PYMODE
}
run_cli() {
  local root="$1" key="$2" log="$3" rcfile="$4" name="$5"
  set +e
  docker run --rm --name "$name" \
    -v "$root:/case" \
    -v "$key:/case/etc/idleleo/cert/xray.key:ro" \
    -v "$BIN:/usr/local/bin/idleleo:ro" \
    "$IMAGE" idleleo --root /case --lang en xray cert clear --yes --container --json >"$log" 2>&1
  local rc=$?
  set -e
  printf '%s\n' "$rc" > "$rcfile"
}
# Case 1: real CLI stages xray.crt then encounters a read-only bind-mounted key.
R1="$TMPROOT/partial-rollback-root"
setup_root "$R1"
snapshot "$R1" "$EVID/partial-before"
run_cli "$R1" "$R1/etc/idleleo/cert/xray.key" "$EVID/partial-cli.log" "$EVID/partial-cli.rc" certclear-partial-rollback
snapshot "$R1" "$EVID/partial-after"
(cd "$R1" && find var/lib/idleleo/certclear -maxdepth 4 -type f -print) > "$EVID/partial-state-files.txt"
# Case 2: emulate process death after the cert was staged under a valid PREPARED journal.
R2="$TMPROOT/interrupted-recovery-root"
setup_root "$R2"
mkdir -p "$R2/var/lib/idleleo/certclear/staging/crash"
mv "$R2/etc/idleleo/cert/xray.crt" "$R2/var/lib/idleleo/certclear/staging/crash/000-xray.crt"
CRT_SHA=$(sha256sum "$R2/var/lib/idleleo/certclear/staging/crash/000-xray.crt" | awk '{print $1}')
KEY_SHA=$(sha256sum "$R2/etc/idleleo/cert/xray.key" | awk '{print $1}')
cat > "$R2/var/lib/idleleo/certclear/journal.json" <<EOF
{"schemaVersion":1,"state":"PREPARED","id":"crash","root":"/case","createdAt":"2026-11-27T00:00:00Z","updatedAt":"2026-11-27T00:00:00Z","moves":[{"from":"/case/etc/idleleo/cert/xray.crt","to":"/case/var/lib/idleleo/certclear/staging/crash/000-xray.crt","kind":"file"},{"from":"/case/etc/idleleo/cert/xray.key","to":"/case/var/lib/idleleo/certclear/staging/crash/001-xray.key","kind":"file"}]}
EOF
chmod 0600 "$R2/var/lib/idleleo/certclear/journal.json"
printf 'staged-cert-sha256=%s\nkey-sha256=%s\n' "$CRT_SHA" "$KEY_SHA" > "$EVID/recovery-seed.txt"
printf 'cert-mode=0644\nkey-mode=0600\nmarker-mode=0600\n' >> "$EVID/recovery-seed.txt"
run_cli "$R2" "$R2/etc/idleleo/cert/xray.key" "$EVID/recovery-cli.log" "$EVID/recovery-cli.rc" certclear-recovery
snapshot "$R2" "$EVID/recovery-after"
(cd "$R2" && find var/lib/idleleo/certclear -maxdepth 4 -type f -print) > "$EVID/recovery-state-files.txt"
# Capture invariant checks without rewriting any result.
python3 - "$EVID" "$R2" <<'PY'
import json, pathlib, sys
p=pathlib.Path(sys.argv[1]); recovery_root=pathlib.Path(sys.argv[2]); checks={}
for name in ('partial','recovery'):
  rc=int((p/f'{name}-cli.rc').read_text().strip())
  after=(p/f'{name}-after.sha256').read_bytes()
  modes_after=(p/f'{name}-after.modes').read_bytes()
  state=(p/f'{name}-state-files.txt').read_text().splitlines()
  if name=='partial':
    before=(p/f'{name}-before.sha256').read_bytes(); modes_before=(p/f'{name}-before.modes').read_bytes()
    hashes_restored=before==after; modes_restored=modes_before==modes_after
  else:
    import hashlib
    root=recovery_root; expected=dict(line.split('=',1) for line in (p/'recovery-seed.txt').read_text().splitlines())
    cert_hash=hashlib.sha256((root/'etc/idleleo/cert/xray.crt').read_bytes()).hexdigest() if (root/'etc/idleleo/cert/xray.crt').exists() else ''
    key_hash=hashlib.sha256((root/'etc/idleleo/cert/xray.key').read_bytes()).hexdigest() if (root/'etc/idleleo/cert/xray.key').exists() else ''
    hashes_restored=(cert_hash==expected['staged-cert-sha256'] and key_hash==expected['key-sha256'])
    modes_restored=all((root/path).stat().st_mode & 0o777 == int(expected[key],8) for key,path in [('cert-mode','etc/idleleo/cert/xray.crt'),('key-mode','etc/idleleo/cert/xray.key'),('marker-mode','etc/idleleo/cert/.managed-by-idleleo')])
  checks[name]={'cli_rc':rc,'hashes_restored':hashes_restored,'modes_restored':modes_restored,'state_files':state,'journal_absent':not any(x.endswith('/journal.json') for x in state),'staging_empty':not state}
if 'recovery' in checks:
  root=recovery_root
  checks['recovery']['recovered_cert_exists']=(root/'etc/idleleo/cert/xray.crt').is_file()
  checks['recovery']['recovered_key_exists']=(root/'etc/idleleo/cert/xray.key').is_file()
  checks['recovery']['recovered_marker_exists']=(root/'etc/idleleo/cert/.managed-by-idleleo').is_file()
(p/'checks.json').write_text(json.dumps(checks,indent=2)+'\n')
PY
printf 'candidate_repo_sha=7d3e19d92ce0dc4f70ab90dedc81c13a41403f91\n' > "$EVID/candidate.txt"
printf 'docker_image=%s\n' "$IMAGE" >> "$EVID/candidate.txt"
docker image inspect "$IMAGE" --format 'image_id={{.Id}} os={{.Os}} arch={{.Architecture}}' >> "$EVID/candidate.txt"
