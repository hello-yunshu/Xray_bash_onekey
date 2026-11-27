#!/usr/bin/env bash
set -uo pipefail
if [[ $# -ne 6 ]]; then
    echo "usage: run_ops17a_go_update.sh REPO OUT SERVER IMAGE GO_IMAGE PLATFORM" >&2
    exit 2
fi
ROOT=$1 OUT=$2 SERVER=$3 IMAGE=$4 GO_IMAGE=$5 PLATFORM=$6
mkdir -p "$OUT"
arch=$(docker exec "$SERVER" uname -m 2>/dev/null | tr -d '\r')
case "$arch" in aarch64) arch=arm64 ;; x86_64) arch=amd64 ;; esac
if [[ "$arch" != arm64 && "$arch" != amd64 ]]; then
    echo "unsupported container architecture: $arch" >"$OUT/build.err"
    echo 2 >"$OUT/build.rc"
    exit 2
fi
echo "$arch" >"$OUT/arch.txt"
docker run --rm --platform "$PLATFORM" \
    -v "$ROOT:/src:ro" -v "$OUT:/out" -w /src "$GO_IMAGE" \
    sh -c "CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \\
        -ldflags '-s -w -X github.com/hello-yunshu/Xray_bash_onekey/internal/cli.Version=0.3.0-phase04' \\
        -o /out/idleleo-linux-$arch ./cmd/idleleo" \
    >"$OUT/build.out" 2>"$OUT/build.err"
build_rc=$?
echo "$build_rc" >"$OUT/build.rc"
[[ $build_rc == 0 ]] || exit "$build_rc"
sha256sum "$OUT/idleleo-linux-$arch" >"$OUT/asset.sha256"
docker exec "$SERVER" mkdir -p /tmp/ops17a-go-release
docker cp "$OUT/idleleo-linux-$arch" "$SERVER:/tmp/ops17a-go-release/idleleo-linux-$arch" \
    >"$OUT/asset-copy.out" 2>"$OUT/asset-copy.err"
echo "$?" >"$OUT/asset-copy.rc"
docker exec "$SERVER" chmod 0755 "/tmp/ops17a-go-release/idleleo-linux-$arch"
docker exec "$SERVER" openssl genpkey -algorithm Ed25519 \
    -out /tmp/ops17a-go-release/test-release-key.pem >/dev/null 2>&1
docker exec "$SERVER" chmod 0600 /tmp/ops17a-go-release/test-release-key.pem
docker exec "$SERVER" openssl pkey -in /tmp/ops17a-go-release/test-release-key.pem \
    -pubout -out /tmp/ops17a-go-release/test-release-pub.pem >/dev/null 2>&1
docker cp "$ROOT/scripts/sign_json_ed25519.sh" \
    "$SERVER:/tmp/ops17a-go-release/sign_json_ed25519.sh" >/dev/null
docker exec "$SERVER" sh -c \
    'asset="/tmp/ops17a-go-release/idleleo-linux-'"$arch"'"; d=$(sha256sum "$asset" | cut -d" " -f1); n=$(wc -c <"$asset"); printf "{\"schemaVersion\":1,\"channel\":\"go\",\"version\":\"0.3.0-phase04\",\"assets\":{\"linux-'"$arch"'\":{\"name\":\"idleleo-linux-'"$arch"'\",\"sha256\":\"%s\",\"size\":%s}}}\n" "$d" "$n" > /tmp/ops17a-go-release/manifest.unsigned.json'
docker exec "$SERVER" bash /tmp/ops17a-go-release/sign_json_ed25519.sh \
    /tmp/ops17a-go-release/manifest.unsigned.json \
    /tmp/ops17a-go-release/test-release-key.pem signature >"$OUT/manifest.json"
docker cp "$OUT/manifest.json" "$SERVER:/tmp/ops17a-go-release/manifest.json" >/dev/null
docker exec -d "$SERVER" python3 -m http.server 18085 --bind 127.0.0.1 \
    --directory /tmp/ops17a-go-release >/dev/null 2>&1
for _ in $(seq 1 30); do
    docker exec "$SERVER" curl -fsS http://127.0.0.1:18085/manifest.json >/dev/null 2>&1 && break
    sleep 0.2
done
docker exec "$SERVER" curl -fsS http://127.0.0.1:18085/manifest.json \
    >"$OUT/manifest-served.json" 2>"$OUT/manifest-served.err"
echo "$?" >"$OUT/manifest-served.rc"
docker exec "$SERVER" idleleo --version >"$OUT/version-before.txt" 2>&1
docker exec "$SERVER" sha256sum /usr/local/bin/idleleo >"$OUT/binary-before.sha256" 2>&1
docker exec "$SERVER" sh -c 'systemctl list-timers --all --no-pager 2>&1; (crontab -l 2>&1 || true)' \
    >"$OUT/schedule-before.txt" 2>&1
docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY \
    -e IDLELEO_RELEASE_PUBKEY_FILE=/tmp/ops17a-go-release/test-release-pub.pem "$SERVER" \
    idleleo update configure --container --manifest-url http://127.0.0.1:18085/manifest.json \
    --install-path usr/local/bin/idleleo --json >"$OUT/configure.json" 2>"$OUT/configure.err"
echo "$?" >"$OUT/configure.rc"
docker exec -e IDLELEO_RELEASE_PUBKEY_FILE=/tmp/ops17a-go-release/test-release-pub.pem "$SERVER" \
    idleleo update check --json >"$OUT/check.json" 2>"$OUT/check.err"
echo "$?" >"$OUT/check.rc"
docker exec "$SERVER" sha256sum /usr/local/bin/idleleo >"$OUT/binary-after-check.sha256" 2>&1
docker exec -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY \
    -e IDLELEO_RELEASE_PUBKEY_FILE=/tmp/ops17a-go-release/test-release-pub.pem "$SERVER" \
    idleleo update apply --container --json >"$OUT/apply.json" 2>"$OUT/apply.err"
echo "$?" >"$OUT/apply.rc"
docker exec "$SERVER" idleleo --version >"$OUT/version-after.txt" 2>&1
docker exec "$SERVER" sha256sum /usr/local/bin/idleleo >"$OUT/binary-after-apply.sha256" 2>&1
docker exec "$SERVER" sh -c 'systemctl is-active xray; systemctl is-active nginx' \
    >"$OUT/services-after.txt" 2>&1
echo "$?" >"$OUT/services-after.rc"
docker exec "$SERVER" /usr/local/nginx/sbin/nginx -t >"$OUT/nginx-test.out" 2>&1
echo "$?" >"$OUT/nginx-test.rc"
docker exec "$SERVER" /usr/local/bin/xray -test -config /etc/idleleo/conf/xray/config.json \
    >"$OUT/xray-test.out" 2>&1
echo "$?" >"$OUT/xray-test.rc"
