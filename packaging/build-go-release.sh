#!/usr/bin/env bash
# Build the two pinned Go release artifacts and their manifest. This never
# publishes: it only produces files that a separately approved release job may
# upload after every Phase 04 gate is green.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-/tmp/idleleo-go-release}"
VERSION="${VERSION:-0.2.0-phase04}"
GO="${GO:-go}"
if ! command -v "$GO" >/dev/null 2>&1; then
    GO=/tmp/gotoolchain/go/bin/go
fi

rm -rf "$OUT"
mkdir -p "$OUT"
COMMIT=$(git -C "$ROOT" rev-parse HEAD)
GOVER=$("$GO" version | awk '{print $3}')

for arch in amd64 arm64; do
    name="idleleo-linux-$arch"
    (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO" build \
        -trimpath -buildvcs=false \
        -ldflags "-s -w -X github.com/hello-yunshu/Xray_bash_onekey/internal/cli.Version=$VERSION" \
        -o "$OUT/$name" ./cmd/idleleo)
    chmod 0755 "$OUT/$name"
done

(
    cd "$OUT"
    sha256sum idleleo-linux-amd64 idleleo-linux-arm64 >SHA256SUMS
)

python3 - "$OUT" "$VERSION" "$COMMIT" "$GOVER" <<'PY'
import json, os, sys
out, version, commit, gover = sys.argv[1:5]
assets = {}
for arch in ("amd64", "arm64"):
    name = f"idleleo-linux-{arch}"
    path = os.path.join(out, name)
    import hashlib
    h = hashlib.sha256(open(path, "rb").read()).hexdigest()
    assets[f"linux-{arch}"] = {"name": name, "sha256": h, "size": os.path.getsize(path)}
manifest = {
    "schemaVersion": 1,
    "channel": "go",
    "version": version,
    "sourceCommit": commit,
    "goVersion": gover,
    "assets": assets,
}
open(os.path.join(out, "manifest.json"), "w").write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY

echo "release-dir=$OUT"
echo "version=$VERSION commit=$COMMIT go=$GOVER"
cat "$OUT/SHA256SUMS"
cat "$OUT/manifest.json"
