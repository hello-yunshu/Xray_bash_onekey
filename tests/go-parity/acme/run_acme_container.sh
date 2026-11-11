#!/usr/bin/env bash
# Real ACME v2 protocol run against a local Pebble CA and self-signed local root.
# Evidence label: ACME_LOCAL_CA. This is NOT a public-CA acceptance.
set -uo pipefail

REPO=${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}
EVIDENCE=${1:-"$REPO/tests/go-parity/evidence/acme-2026-11-08"}
WORK=${WORK:-/tmp/idleleo-acme-work}
NET=idleleo-acme-net
PEBBLE=idleleo-pebble
CLIENT=idleleo-acme-client
GO_IMAGE=${GO_IMAGE:-golang:1.27.4}
CLIENT_IMAGE=arm64v8/python:3.12-slim
PEBBLE_IMAGE=ghcr.io/letsencrypt/pebble:latest
PEBBLE_TEST=${PEBBLE_TEST:-/tmp/pebble-test}

if [ ! -f "$PEBBLE_TEST/certs/pebble.minica.pem" ]; then
  mkdir -p "$PEBBLE_TEST"
  cid=$(docker create "$PEBBLE_IMAGE")
  docker cp "$cid":/test/. "$PEBBLE_TEST"/ >/dev/null
  docker rm "$cid" >/dev/null
fi

rm -rf "$WORK"
mkdir -p "$WORK/webroot" "$WORK/certs" "$WORK/state" "$WORK/logs"
rm -rf "$EVIDENCE"
mkdir -p "$EVIDENCE"

cleanup() {
  docker rm -f "$CLIENT" "$PEBBLE" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log() { printf '%s\n' "$*" | tee -a "$EVIDENCE/run.log"; }

log "label=ACME_LOCAL_CA"
log "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "repo_commit=$(git -C "$REPO" rev-parse HEAD)"
log "pebble_image=$(docker image inspect "$PEBBLE_IMAGE" --format '{{.Id}}')"
log "client_image=$(docker image inspect "$CLIENT_IMAGE" --format '{{.Id}}')"
log "pebble_test_assets=$(ls "$PEBBLE_TEST/certs")"

log "--- build go binary"
if ! docker run --rm --entrypoint bash -v "$REPO":/src -v "$WORK":/out -w /src \
  -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache "$GO_IMAGE" \
  -c 'export PATH=/usr/local/go/bin:$PATH; go build -o /out/idleleo ./cmd/idleleo' >>"$EVIDENCE/build.log" 2>&1; then
  log "build=FAIL"
  exit 1
fi
log "build=OK sha256=$(shasum -a 256 "$WORK/idleleo" | awk '{print $1}')"

log "--- start network/pebble/client"
docker network create "$NET" >/dev/null 2>&1 || true
# AUTHZREUSE=0 keeps the webroot-failure negative deterministic: with reuse
# enabled Pebble may skip HTTP-01 and the "unusable webroot" case could succeed.
docker run -d --name "$PEBBLE" --network "$NET" --network-alias pebble \
  -e PEBBLE_VA_NOSLEEP=1 \
  -e PEBBLE_WFE_NONCEREJECT="${PEBBLE_WFE_NONCEREJECT:-5}" \
  -e PEBBLE_AUTHZREUSE="${PEBBLE_AUTHZREUSE:-0}" \
  -v "$PEBBLE_TEST/certs":/test/certs:ro \
  -v "$REPO/tests/go-parity/acme/pebble-config.json":/conf/pebble-config.json:ro \
  --entrypoint /app "$PEBBLE_IMAGE" -config /conf/pebble-config.json -strict >/dev/null
docker run -d --name "$CLIENT" --network "$NET" --network-alias acme.local \
  -v "$WORK":/work -v "$PEBBLE_TEST/certs":/test/certs:ro \
  --entrypoint python3 "$CLIENT_IMAGE" \
  -m http.server 5002 --bind 0.0.0.0 --directory /work/webroot >/dev/null

wait_http() {
  local url=$1 tries=${2:-60} cafile=${3:-}
  for _ in $(seq 1 "$tries"); do
    if docker exec "$CLIENT" python3 -c "
import ssl, urllib.request, urllib.error
ctx = ssl.create_default_context(cafile='$cafile') if '$cafile' else None
try:
    urllib.request.urlopen('$url', timeout=2, context=ctx)
except urllib.error.HTTPError:
    pass
except Exception:
    raise SystemExit(1)
" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

if ! wait_http https://pebble:14000/dir 60 /test/certs/pebble.minica.pem; then
  log "pebble_ready=FAIL"
  docker logs "$PEBBLE" >"$EVIDENCE/pebble-boot.log" 2>&1 || true
  exit 1
fi
if ! wait_http http://127.0.0.1:5002/.well-known/acme-challenge/probe; then
  log "webroot_ready=FAIL"
  exit 1
fi
log "pebble_ready=OK webroot_ready=OK"

docker exec "$CLIENT" python3 -c "
import ssl, urllib.request
ctx = ssl.create_default_context(cafile='/test/certs/pebble.minica.pem')
open('/work/roots.pem', 'wb').write(urllib.request.urlopen('https://pebble:15000/roots/0', context=ctx, timeout=5).read())
" >/dev/null 2>&1
if [ -s "$WORK/roots.pem" ]; then log "pebble_root=fetched"; else log "pebble_root=FAIL"; exit 1; fi
cp "$WORK/roots.pem" "$EVIDENCE/pebble-root.pem"

ISSUE_ARGS=(xray cert issue --domain acme.local --webroot /work/webroot
  --cert-out /work/certs/fullchain.pem --key-out /work/certs/key.pem
  --directory https://pebble:14000/dir --email acme@idleleo.example
  --ca-cert /test/certs/pebble.minica.pem
  --account-key /work/state/account.key --state /work/state/account.json
  --reload-command 'echo reloaded > /work/state/reload.marker' --json)

log "--- issue"
if docker exec "$CLIENT" /work/idleleo "${ISSUE_ARGS[@]}" >"$EVIDENCE/issue.json" 2>"$EVIDENCE/issue.err"; then
  log "issue=OK"
else
  log "issue=FAIL exit=$?"
  exit 1
fi
cp "$WORK/certs/fullchain.pem" "$WORK/certs/fullchain-initial.pem"
cp "$WORK/certs/key.pem" "$WORK/certs/key-initial.pem"

verify() {
  local cert=$1 key=$2 out=$3
  docker run --rm --entrypoint bash -v "$WORK":/work -v "$PEBBLE_TEST/certs":/test/certs:ro \
    -v "$REPO/tests/go-parity/acme":/src/acme -w /src/acme \
    -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache "$GO_IMAGE" \
    -c "export PATH=/usr/local/go/bin:\$PATH; go run verify_cert.go /work/certs/$cert /work/roots.pem acme.local /work/certs/$key" \
    >"$EVIDENCE/$out" 2>"$EVIDENCE/$out.err"
}
verify fullchain.pem key.pem verify-initial.json

if [ -f "$WORK/state/reload.marker" ]; then log "reload_marker=OK"; else log "reload_marker=FAIL"; fi
log "account_key_mode=$(docker exec "$CLIENT" stat -c %a /work/state/account.key)"
log "key_mode=$(docker exec "$CLIENT" stat -c %a /work/certs/key.pem)"

log "--- renew inside window (expect skip)"
RENEW_ARGS=(xray cert renew --domain acme.local --webroot /work/webroot
  --cert-out /work/certs/fullchain.pem --key-out /work/certs/key.pem
  --directory https://pebble:14000/dir --email acme@idleleo.example
  --ca-cert /test/certs/pebble.minica.pem
  --account-key /work/state/account.key --state /work/state/account.json
  --renew-before 24h --json)
if docker exec "$CLIENT" /work/idleleo "${RENEW_ARGS[@]}" >"$EVIDENCE/renew-skip.json" 2>"$EVIDENCE/renew-skip.err"; then
  log "renew_skip_cmd=OK"
else
  log "renew_skip_cmd=FAIL exit=$?"
fi

log "--- renew forced (expect real reissue)"
if docker exec "$CLIENT" /work/idleleo "${RENEW_ARGS[@]}" --force >"$EVIDENCE/renew-force.json" 2>"$EVIDENCE/renew-force.err"; then
  log "renew_force=OK"
else
  log "renew_force=FAIL exit=$?"
fi
verify fullchain.pem key.pem verify-after-force.json
cp "$WORK/certs/fullchain.pem" "$WORK/certs/fullchain-before-failure.pem"
cp "$WORK/certs/key.pem" "$WORK/certs/key-before-failure.pem"

sha() { shasum -a 256 "$1" | awk '{print $1}'; }

log "--- negative: renewal with an unusable challenge webroot must keep the old pair"
cp "$WORK/certs/fullchain.pem" "$WORK/certs/fullchain-pre-webroot-fail.pem"
: >"$WORK/webroot-file"
FAIL_ARGS=(xray cert renew --domain acme.local --webroot /work/webroot-file
  --cert-out /work/certs/fullchain.pem --key-out /work/certs/key.pem
  --directory https://pebble:14000/dir --email acme@idleleo.example
  --ca-cert /test/certs/pebble.minica.pem
  --account-key /work/state/account.key --state /work/state/account.json
  --renew-before 24h --force --json)
if docker exec "$CLIENT" /work/idleleo "${FAIL_ARGS[@]}" >"$EVIDENCE/renew-webroot-fail.out" 2>"$EVIDENCE/renew-webroot-fail.err"; then
  log "renew_webroot_fail=UNEXPECTED_SUCCESS"
else
  log "renew_webroot_fail=FAILED_AS_EXPECTED exit=$?"
fi
if [ "$(sha "$WORK/certs/fullchain.pem")" = "$(sha "$WORK/certs/fullchain-pre-webroot-fail.pem")" ]; then
  log "renew_webroot_fail_old_cert=KEPT"
else
  log "renew_webroot_fail_old_cert=CHANGED"
fi

log "--- negative: reload failure must restore the previous certificate pair"
RELOAD_ARGS=(xray cert renew --domain acme.local --webroot /work/webroot
  --cert-out /work/certs/fullchain.pem --key-out /work/certs/key.pem
  --directory https://pebble:14000/dir --email acme@idleleo.example
  --ca-cert /test/certs/pebble.minica.pem
  --account-key /work/state/account.key --state /work/state/account.json
  --renew-before 24h --force --reload-command 'exit 1' --json)
if docker exec "$CLIENT" /work/idleleo "${RELOAD_ARGS[@]}" >"$EVIDENCE/renew-reload-fail.out" 2>"$EVIDENCE/renew-reload-fail.err"; then
  log "renew_reload_fail=UNEXPECTED_SUCCESS"
else
  log "renew_reload_fail=FAILED_AS_EXPECTED exit=$?"
fi
if [ "$(sha "$WORK/certs/fullchain.pem")" = "$(sha "$WORK/certs/fullchain-before-failure.pem")" ] && \
   [ "$(sha "$WORK/certs/key.pem")" = "$(sha "$WORK/certs/key-before-failure.pem")" ]; then
  log "reload_failure_restored_old_pair=YES"
else
  log "reload_failure_restored_old_pair=NO"
fi
log "cert_mode=$(docker exec "$CLIENT" stat -c %a /work/certs/fullchain.pem)"
log "key_mode=$(docker exec "$CLIENT" stat -c %a /work/certs/key.pem)"

# The restored pair must still be a usable certificate, not merely the same
# bytes: verify chain, SAN and that the certificate matches its private key.
if verify fullchain.pem key.pem verify-after-failures.json; then
  log "old_pair_still_valid=YES"
else
  log "old_pair_still_valid=NO"
fi

log "--- negative: read-only destination must be refused without writing a cert"
RO_ARGS=(xray cert issue --domain acme.local --webroot /work/webroot
  --cert-out /test/certs/ro-fullchain.pem --key-out /test/certs/ro-key.pem
  --directory https://pebble:14000/dir --email acme@idleleo.example
  --ca-cert /test/certs/pebble.minica.pem
  --account-key /work/state/account.key --state /work/state/account.json --json)
if docker exec "$CLIENT" /work/idleleo "${RO_ARGS[@]}" >"$EVIDENCE/negative-readonly.out" 2>"$EVIDENCE/negative-readonly.err"; then
  log "negative_readonly=UNEXPECTED_SUCCESS"
else
  log "negative_readonly=REFUSED exit=$?"
fi
if docker exec "$CLIENT" test -e /test/certs/ro-fullchain.pem; then
  log "negative_readonly_wrote_cert=YES"
else
  log "negative_readonly_wrote_cert=NO"
fi

log "--- negative: blocked domain must be rejected by CA"
NEG_ARGS=(xray cert issue --domain blocked-domain.example --webroot /work/webroot
  --cert-out /work/certs/blocked.pem --key-out /work/certs/blocked.key
  --directory https://pebble:14000/dir --email acme@idleleo.example
  --ca-cert /test/certs/pebble.minica.pem
  --account-key /work/state/account.key --state /work/state/account.json --json)
if docker exec "$CLIENT" /work/idleleo "${NEG_ARGS[@]}" >"$EVIDENCE/negative-blocked.out" 2>"$EVIDENCE/negative-blocked.err"; then
  log "negative_blocked=UNEXPECTED_SUCCESS"
else
  log "negative_blocked=REJECTED exit=$?"
fi
if [ -f "$WORK/certs/blocked.pem" ]; then log "negative_cert_written=YES"; else log "negative_cert_written=NO"; fi

docker logs "$CLIENT" >"$EVIDENCE/client-http.log" 2>&1 || true
docker logs "$PEBBLE" >"$EVIDENCE/pebble.log" 2>&1 || true
cp "$WORK/certs/fullchain.pem" "$EVIDENCE/fullchain.pem"
cp "$WORK/state/account.json" "$EVIDENCE/account.json" 2>/dev/null || true
# Never copy private keys into evidence.

python3 - "$EVIDENCE" <<'PY'
import json, pathlib, sys
ev = pathlib.Path(sys.argv[1])
def load(name):
    try: return json.loads((ev / name).read_text())
    except Exception: return {}
initial = load("issue.json")
skip = load("renew-skip.json")
force = load("renew-force.json")
vi = load("verify-initial.json")
vf = load("verify-after-force.json")
summary = {
    "label": "ACME_LOCAL_CA",
    "protocol": "ACME v2 (RFC 8555), JWS ES256, HTTP-01",
    "ca": "Pebble local test CA + pebble.minica.pem (self-signed; not a public CA)",
    "domain": "acme.local (Docker network alias; no public DNS)",
    "account_reused": initial.get("accountUrl") == force.get("accountUrl") and bool(initial.get("accountUrl")),
    "issue": {"issued": initial.get("issued"), "notAfter": initial.get("notAfter"), "serial": initial.get("serial"), "reloaded": initial.get("reloaded")},
    "renew_in_window": {"skipped": skip.get("skipped"), "issued": skip.get("issued"), "reason": skip.get("reason")},
    "renew_forced": {"issued": force.get("issued"), "serial": force.get("serial"), "notAfter": force.get("notAfter")},
    "serial_changed": initial.get("serial") != force.get("serial"),
    "verify_initial": vi,
    "verify_after_force": vf,
    "negative": {
        "webroot_failure_kept_old_pair": "renew_webroot_fail_old_cert=KEPT" in
            (ev / "run.log").read_text(),
        "reload_failure_restored_old_pair": "reload_failure_restored_old_pair=YES" in
            (ev / "run.log").read_text(),
        "restored_pair_still_valid": "old_pair_still_valid=YES" in
            (ev / "run.log").read_text(),
        "readonly_destination_refused": "negative_readonly=REFUSED" in
            (ev / "run.log").read_text(),
        "readonly_destination_wrote_no_cert": "negative_readonly_wrote_cert=NO" in
            (ev / "run.log").read_text(),
        "blocked_domain_rejected": "negative_blocked=REJECTED" in (ev / "run.log").read_text(),
        "blocked_domain_wrote_no_cert": "negative_cert_written=NO" in (ev / "run.log").read_text(),
    },
}
(ev / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
PY

log "finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
