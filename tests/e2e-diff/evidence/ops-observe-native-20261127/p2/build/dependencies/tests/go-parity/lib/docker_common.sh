#!/usr/bin/env bash
# Host-side helpers shared by the Phase 01-04 Docker launchers.
#
# The launchers may run on macOS (no sha256sum, no host /sys/fs/cgroup, no
# Linux Xray binary) or on Linux CI. Keep those differences here instead of
# hardcoding GOARCH=arm64 and host tool names in every launcher.
#
# Contract: callers export ROOT as the repository root before sourcing.

docker_arch() {
    local arch
    arch=$(docker version --format '{{.Server.Arch}}' 2>/dev/null || true)
    case "$arch" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *)
        echo "unsupported Docker Engine arch '${arch:-unknown}'" >&2
        return 2
        ;;
    esac
}

host_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

elf_machine() {
    python3 - "$1" <<'PY'
import struct
import sys

with open(sys.argv[1], 'rb') as handle:
    head = handle.read(20)
if head[:4] != b'\x7fELF':
    print('not-elf')
    raise SystemExit(3)
print({0x3E: 'amd64', 0xB7: 'arm64'}.get(
    struct.unpack('<H', head[18:20])[0], 'unknown'))
PY
}

# Resolve a Linux Xray binary whose ELF machine matches the Docker Engine arch.
# Never pass a macOS Mach-O binary into a Linux container.
ensure_xray_bin() {
    local arch=$1
    local explicit=${IDLELEO_XRAY_BIN:-}
    local cache="$ROOT/tests/go-parity/.cache/xray-linux-$arch/xray"
    local bin machine asset tmp

    if [[ -n "$explicit" ]]; then
        [[ -f "$explicit" ]] || {
            echo "IDLELEO_XRAY_BIN=$explicit does not exist" >&2
            return 2
        }
        bin=$explicit
    elif [[ -f "$cache" ]]; then
        bin=$cache
    else
        case "$arch" in
        amd64) asset=Xray-linux-64.zip ;;
        arm64) asset=Xray-linux-arm64-v8a.zip ;;
        *) echo "no Xray asset for $arch" >&2; return 2 ;;
        esac
        tmp=$(mktemp -d)
        mkdir -p "$(dirname "$cache")"
        echo "downloading $asset for linux/$arch" >&2
        curl -fsSL --retry 3 --retry-all-errors \
            -o "$tmp/xray.zip" \
            "https://github.com/XTLS/Xray-core/releases/latest/download/$asset" || {
            rm -rf "$tmp"
            echo "Xray download failed; set IDLELEO_XRAY_BIN" >&2
            return 2
        }
        python3 - "$tmp/xray.zip" "$cache" <<'PY'
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    with archive.open('xray') as src, open(sys.argv[2], 'wb') as dst:
        dst.write(src.read())
PY
        chmod 0755 "$cache"
        rm -rf "$tmp"
        bin=$cache
    fi

    machine=$(elf_machine "$bin")
    if [[ "$machine" != "$arch" ]]; then
        echo "Xray binary $bin is $machine, Docker Engine needs $arch" >&2
        return 2
    fi
    echo "$bin"
}

# Systemd probes only need --privileged/--cgroupns=host. Mounting the host
# /sys/fs/cgroup is unnecessary on Docker Desktop and breaks on hosts without
# that path; allow it explicitly for older Linux hosts.
cgroup_mount_args() {
    if [[ "${IDLELEO_MOUNT_CGROUP:-0}" == 1 && -e /sys/fs/cgroup ]]; then
        printf '%s\n' -v /sys/fs/cgroup:/sys/fs/cgroup:rw
    fi
}
