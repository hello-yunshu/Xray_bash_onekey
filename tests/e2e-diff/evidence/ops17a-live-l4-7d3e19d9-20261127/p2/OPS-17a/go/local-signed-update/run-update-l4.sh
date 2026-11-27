#!/usr/bin/env bash
set -euo pipefail
ROOT="$PWD"
EVID="$ROOT/tests/e2e-diff/evidence/ops17a-live-l4-7d3e19d9-20261127/p2/OPS-17a/go/local-signed-update"
SERVER=e2e-ops17a-live-l4-7d3e19d9-20261127-observe-go
NETWORK=e2e-ops17a-live-l4-7d3e19d9-20261127-observe
TMP=$(mktemp -d /tmp/xray-ops17a-live.XXXXXX)
trap 'python3 - "$TMP" <<"PYTRAP"
import pathlib, shutil, sys
p=pathlib.Path(sys.argv[1])
if p.parent==pathlib.Path("/tmp") and p.name.startswith("xray-ops17a-live."):
    shutil.rmtree(p, ignore_errors=True)
PYTRAP' EXIT
BIN="$TMP/idleleo-linux-arm64"
XRAY="$TMP/xray"
# Build a higher-version local asset from this exact candidate product source.
docker run --rm -v "$ROOT:/src:ro" -v "$TMP:/out" -w /src golang:1.27.4 \
  env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags '-s -w -X github.com/hello-yunshu/Xray_bash_onekey/internal/cli.Version=0.3.0-phase04' \
  -o /out/idleleo-linux-arm64 ./cmd/idleleo

chmod 0755 "$BIN"
sha256sum "$BIN" > "$EVID/asset.sha256"
docker cp "$BIN" "$SERVER:/tmp/idleleo-linux-arm64" >/dev/null
docker exec "$SERVER" chmod 0755 /tmp/idleleo-linux-arm64
docker exec "$SERVER" mkdir -p /tmp/idleleo-update
# A per-run Ed25519 key is created inside this disposable server container.
docker exec "$SERVER" openssl genpkey -algorithm Ed25519 -out /tmp/idleleo-update/test-release-key.pem >/dev/null 2>&1
docker exec "$SERVER" chmod 0600 /tmp/idleleo-update/test-release-key.pem
docker exec "$SERVER" openssl pkey -in /tmp/idleleo-update/test-release-key.pem -pubout -out /tmp/idleleo-update/test-release-pub.pem >/dev/null 2>&1
docker cp scripts/sign_json_ed25519.sh "$SERVER:/tmp/idleleo-update/sign_json_ed25519.sh" >/dev/null
# Manifest digest and size come from the exact asset copied into the server.
docker exec "$SERVER" sh -c 'd=$(sha256sum /tmp/idleleo-linux-arm64 | cut -d" " -f1); n=$(wc -c </tmp/idleleo-linux-arm64); printf "{\"schemaVersion\":1,\"channel\":\"go\",\"version\":\"0.3.0-phase04\",\"assets\":{\"linux-arm64\":{\"name\":\"idleleo-linux-arm64\",\"sha256\":\"%s\",\"size\":%s}}}\n" "$d" "$n" > /tmp/idleleo-update/manifest.unsigned.json'
docker exec "$SERVER" bash /tmp/idleleo-update/sign_json_ed25519.sh /tmp/idleleo-update/manifest.unsigned.json /tmp/idleleo-update/test-release-key.pem signature > "$EVID/manifest.json"
docker cp "$SERVER:/tmp/idleleo-update/test-release-pub.pem" "$EVID/test-release-pub.pem" >/dev/null
docker exec "$SERVER" cp /tmp/idleleo-linux-arm64 /tmp/idleleo-update/idleleo-linux-arm64
docker cp "$EVID/manifest.json" "$SERVER:/tmp/idleleo-update/manifest.json" >/dev/null
docker exec -d "$SERVER" python3 -m http.server 18084 --bind 127.0.0.1 --directory /tmp/idleleo-update > /dev/null 2>&1
for _ in $(seq 1 30); do
  docker exec "$SERVER" curl -fsS http://127.0.0.1:18084/manifest.json >/dev/null 2>&1 && break
  sleep 0.2
done
docker exec "$SERVER" curl -fsS http://127.0.0.1:18084/manifest.json >/dev/null

# Preserve all command outputs and return codes separately.
docker exec "$SERVER" /usr/local/bin/idleleo --version > "$EVID/version-before.txt"
docker exec "$SERVER" sh -c 'sha256sum /usr/local/bin/idleleo' > "$EVID/binary-before.sha256"
docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY -e IDLELEO_RELEASE_PUBKEY_FILE=/tmp/idleleo-update/test-release-pub.pem "$SERVER" \
  /usr/local/bin/idleleo update configure --container --manifest-url http://127.0.0.1:18084/manifest.json \
  --install-path usr/local/bin/idleleo --json > "$EVID/configure.json" 2> "$EVID/configure.err"
printf '%s\n' "$?" > "$EVID/configure.rc"
docker exec -e IDLELEO_RELEASE_PUBKEY_FILE=/tmp/idleleo-update/test-release-pub.pem "$SERVER" \
  /usr/local/bin/idleleo update check --json > "$EVID/check.json" 2> "$EVID/check.err"
printf '%s\n' "$?" > "$EVID/check.rc"
docker exec "$SERVER" sh -c 'sha256sum /usr/local/bin/idleleo' > "$EVID/binary-after-check.sha256"
docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY -e IDLELEO_RELEASE_PUBKEY_FILE=/tmp/idleleo-update/test-release-pub.pem "$SERVER" \
  /usr/local/bin/idleleo update apply --container --json > "$EVID/apply.json" 2> "$EVID/apply.err"
printf '%s\n' "$?" > "$EVID/apply.rc"
docker exec "$SERVER" /usr/local/bin/idleleo --version > "$EVID/version-after.txt"
docker exec "$SERVER" sh -c 'sha256sum /usr/local/bin/idleleo' > "$EVID/binary-after-apply.sha256"
docker exec "$SERVER" sh -c 'systemctl is-active xray; systemctl is-active nginx' > "$EVID/services-after.txt"
docker exec "$SERVER" /usr/local/nginx/sbin/nginx -t > "$EVID/nginx-test.out" 2>&1
printf '%s\n' "$?" > "$EVID/nginx-test.rc"
docker exec "$SERVER" /usr/local/bin/xray -test -config /etc/idleleo/conf/xray/config.json > "$EVID/xray-test.out" 2>&1
printf '%s\n' "$?" > "$EVID/xray-test.rc"
docker cp "$SERVER:/usr/local/bin/xray" "$XRAY" >/dev/null
chmod 0755 "$XRAY"
mkdir -p "$TMP/secret"
bash "$ROOT/tests/e2e-diff/collect/l4.sh" "$SERVER" e2e-ops17a-postupdate-client-7d3e19d9 idleleo-e2e:24.04 "$NETWORK" reality example.com "$XRAY" "$TMP/secret" "$EVID/post-update-l4" reality > "$EVID/l4-command.log" 2>&1
printf '%s\n' "$?" > "$EVID/l4.rc"
python3 - "$EVID" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
read=lambda n:(p/n).read_text().strip()
check=json.loads((p/'check.json').read_text())
apply=json.loads((p/'apply.json').read_text())
l4=json.loads((p/'post-update-l4/connectivity.json').read_text())
result={
 'candidateRepoSha':'7d3e19d92ce0dc4f70ab90dedc81c13a41403f91',
 'oldVersion':read('version-before.txt'), 'newVersion':read('version-after.txt'),
 'configureRc':int(read('configure.rc')), 'checkRc':int(read('check.rc')), 'applyRc':int(read('apply.rc')),
 'checkVerified':check.get('verified'), 'checkLatestVersion':check.get('latestVersion'),
 'checkDidNotAlterBinary':(p/'binary-before.sha256').read_bytes()==(p/'binary-after-check.sha256').read_bytes(),
 'applyAction':apply.get('action'), 'appliedBinaryMatchesManifest':apply.get('newSha256')==read('asset.sha256').split()[0],
 'nginxTestRc':int(read('nginx-test.rc')), 'xrayTestRc':int(read('xray-test.rc')),
 'servicesActive':read('services-after.txt').splitlines()==['active','active'],
 'postUpdateL4':l4,
}
(p/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
PY
