#!/usr/bin/env bash
set -euo pipefail
ROOT=$(git rev-parse --show-toplevel)
CANDIDATE=/tmp/xray-candidate-8ff-ops23
EVID="$ROOT/tests/e2e-diff/evidence/ops17a-update-failure-retry2-8ff26917-20261127"
TARGET=e2e-ops17a-boundary-8ff26917-20261127-OPS-08-go
mkdir -p "$EVID"
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '%s\n' "$(git -C "$CANDIDATE" rev-parse HEAD)" > "$EVID/product-code-sha.txt"
docker inspect -f 'image={{.Config.Image}} imageID={{.Image}} containerID={{.Id}} status={{.State.Status}}' "$TARGET" > "$EVID/container.txt"
docker exec "$TARGET" uname -srm > "$EVID/platform.txt"
# Compile a higher version from the frozen candidate source for a disposable local release origin.
docker run --rm -v "$CANDIDATE:/src:ro" -v "$EVID:/out" -w /src golang:1.27.4 \
  env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags '-s -w -X github.com/hello-yunshu/Xray_bash_onekey/internal/cli.Version=0.3.0-phase04' \
  -o /out/idleleo-linux-arm64 ./cmd/idleleo
chmod 0755 "$EVID/idleleo-linux-arm64"
sha256sum "$EVID/idleleo-linux-arm64" > "$EVID/candidate-asset.sha256"
docker exec "$TARGET" mkdir -p /tmp/idleleo-update-boundary
# Create test-only signing material inside the throwaway container; never export the private key.
docker exec "$TARGET" openssl genpkey -algorithm Ed25519 -out /tmp/idleleo-update-boundary/test-release-key.pem >/dev/null 2>&1
docker exec "$TARGET" chmod 0600 /tmp/idleleo-update-boundary/test-release-key.pem
docker exec "$TARGET" openssl pkey -in /tmp/idleleo-update-boundary/test-release-key.pem -pubout -out /tmp/idleleo-update-boundary/test-release-pub.pem >/dev/null 2>&1
docker cp "$EVID/idleleo-linux-arm64" "$TARGET:/tmp/idleleo-update-boundary/idleleo-linux-arm64" >/dev/null
docker cp "$ROOT/scripts/sign_json_ed25519.sh" "$TARGET:/tmp/idleleo-update-boundary/sign_json_ed25519.sh" >/dev/null
docker exec "$TARGET" sh -c 'd=$(sha256sum /tmp/idleleo-update-boundary/idleleo-linux-arm64 | cut -d" " -f1); n=$(wc -c </tmp/idleleo-update-boundary/idleleo-linux-arm64); printf "{\"schemaVersion\":1,\"channel\":\"go\",\"version\":\"0.3.0-phase04\",\"assets\":{\"linux-arm64\":{\"name\":\"idleleo-linux-arm64\",\"sha256\":\"%s\",\"size\":%s}}}\n" "$d" "$n" > /tmp/idleleo-update-boundary/manifest.unsigned.json'
docker exec "$TARGET" bash /tmp/idleleo-update-boundary/sign_json_ed25519.sh /tmp/idleleo-update-boundary/manifest.unsigned.json /tmp/idleleo-update-boundary/test-release-key.pem signature > "$EVID/manifest.json"
docker cp "$EVID/manifest.json" "$TARGET:/tmp/idleleo-update-boundary/manifest.json" >/dev/null
docker cp "$TARGET:/tmp/idleleo-update-boundary/test-release-pub.pem" "$EVID/test-release-pub.pem" >/dev/null
docker exec -d "$TARGET" python3 -m http.server 18085 --bind 127.0.0.1 --directory /tmp/idleleo-update-boundary > /dev/null 2>&1
for _ in $(seq 1 50); do
  if docker exec "$TARGET" curl -fsS http://127.0.0.1:18085/manifest.json >/dev/null 2>&1; then break; fi
  sleep 0.2
done
docker exec "$TARGET" curl -fsS http://127.0.0.1:18085/manifest.json > /dev/null
# Capture state and configured automatic schedule before the actual CLI boundary checks.
docker exec "$TARGET" /usr/local/bin/idleleo --version > "$EVID/version-before.txt"
docker exec "$TARGET" sha256sum /usr/local/bin/idleleo > "$EVID/binary-before.sha256"
docker exec "$TARGET" sh -c 'systemctl list-timers --all --no-pager 2>&1; printf "\\n--- crontab ---\\n"; (crontab -l 2>&1 || true); printf "\\n--- idleleo cron ---\\n"; (grep -Rni idleleo /etc/cron* /var/spool/cron 2>/dev/null || true)' > "$EVID/schedule-before.txt"
docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY -e IDLELEO_RELEASE_PUBKEY_FILE=/tmp/idleleo-update-boundary/test-release-pub.pem "$TARGET" \
  /usr/local/bin/idleleo update configure --container --manifest-url http://127.0.0.1:18085/manifest.json --install-path usr/local/bin/idleleo --json \
  > "$EVID/configure.json" 2> "$EVID/configure.err"
printf '%s\n' "$?" > "$EVID/configure.rc"
docker exec -e IDLELEO_RELEASE_PUBKEY_FILE=/tmp/idleleo-update-boundary/test-release-pub.pem "$TARGET" \
  /usr/local/bin/idleleo update check --json > "$EVID/check.json" 2> "$EVID/check.err"
printf '%s\n' "$?" > "$EVID/check.rc"
docker exec "$TARGET" sha256sum /usr/local/bin/idleleo > "$EVID/binary-after-check.sha256"
docker exec "$TARGET" /usr/local/bin/idleleo --version > "$EVID/version-after-check.txt"
# Damage only the served asset after the signed manifest has been verified; Apply must refuse it and keep the installed manager intact.
docker exec "$TARGET" sh -c 'printf "not an ELF release asset\\n" > /tmp/idleleo-update-boundary/idleleo-linux-arm64'
set +e
docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY -e IDLELEO_RELEASE_PUBKEY_FILE=/tmp/idleleo-update-boundary/test-release-pub.pem "$TARGET" \
  /usr/local/bin/idleleo update apply --container --json > "$EVID/apply.json" 2> "$EVID/apply.err"
apply_rc=$?
set -e
printf '%s\n' "$apply_rc" > "$EVID/apply.rc"
docker exec "$TARGET" sha256sum /usr/local/bin/idleleo > "$EVID/binary-after-failed-apply.sha256"
docker exec "$TARGET" /usr/local/bin/idleleo --version > "$EVID/version-after-failed-apply.txt"
docker exec "$TARGET" sh -c 'systemctl is-active xray; systemctl is-active nginx' > "$EVID/services-after.txt"
docker exec "$TARGET" /usr/local/nginx/sbin/nginx -t > "$EVID/nginx-test.out" 2>&1
printf '%s\n' "$?" > "$EVID/nginx-test.rc"
docker exec "$TARGET" /usr/local/bin/xray -test -config /etc/idleleo/conf/xray/config.json > "$EVID/xray-test.out" 2>&1
printf '%s\n' "$?" > "$EVID/xray-test.rc"
FINISHED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 - "$EVID" "$STARTED_AT" "$FINISHED_AT" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1])
read=lambda n:(p/n).read_text().strip()
check=json.loads((p/'check.json').read_text())
apply=json.loads((p/'apply.json').read_text())
sha=lambda n:(p/n).read_text().split()[0]
container=(p/'container.txt').read_text().strip()
fields=dict(part.split('=',1) for part in container.split())
script=p/'run-failure-boundary.sh'
started=sys.argv[2]
finished=sys.argv[3]
r={
 'productCodeSha':read('product-code-sha.txt'),
 'configureRc':int(read('configure.rc')),
 'checkRc':int(read('check.rc')),
 'checkVerified':check.get('verified') is True,
 'checkDidNotInstall':sha('binary-before.sha256')==sha('binary-after-check.sha256') and read('version-before.txt')==read('version-after-check.txt'),
 'failedApplyRc':int(read('apply.rc')),
 'applyError':read('apply.err'),
 'failedApplyPreservedBinary':sha('binary-before.sha256')==sha('binary-after-failed-apply.sha256'),
 'failedApplyPreservedVersion':read('version-before.txt')==read('version-after-failed-apply.txt'),
 'servicesActive':read('services-after.txt').splitlines()==['active','active'],
 'nginxTestRc':int(read('nginx-test.rc')),
 'xrayTestRc':int(read('xray-test.rc')),
 'applyReport':apply,
 'passed':int(read('configure.rc'))==0 and int(read('check.rc'))==0 and check.get('verified') is True and int(read('apply.rc'))!=0 and sha('binary-before.sha256')==sha('binary-after-check.sha256')==sha('binary-after-failed-apply.sha256') and read('version-before.txt')==read('version-after-check.txt')==read('version-after-failed-apply.txt') and read('services-after.txt').splitlines()==['active','active'] and int(read('nginx-test.rc'))==0 and int(read('xray-test.rc'))==0,
}
(p/'verification.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
manifest={
 'runId':p.name,
 'productCodeSha':read('product-code-sha.txt'),
 'startedAt':started,
 'finishedAt':finished,
 'binarySha256':sha('binary-before.sha256'),
 'assetSha256':sha('candidate-asset.sha256'),
 'containerImage':fields.get('image'),
 'imageId':fields.get('imageID'),
 'containerId':fields.get('containerID'),
 'platform':read('platform.txt'),
 'driverSha256':hashlib.sha256(script.read_bytes()).hexdigest(),
 'dependencies':[
  {'path':'scripts/sign_json_ed25519.sh','sha256':hashlib.sha256((p.parents[3]/'scripts/sign_json_ed25519.sh').read_bytes()).hexdigest()},
 ],
 'verificationSha256':hashlib.sha256((p/'verification.json').read_bytes()).hexdigest(),
 'evidencePath':str(p.relative_to(p.parents[3]))+'/verification.json',
}
(p/'run.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
PY
cat "$EVID/verification.json"
