#!/usr/bin/env python3
"""Generate the production Bash -> Go bridge asset manifest (one file per arch).

The Bash installer reads `/etc/idleleo/bridge/asset.json` and needs a primary
and a recovery binary URL with pinned SHA-256 values. Test fixtures are not a
release artifact: this generator is the only production source of that file.

It fails closed on missing/non-ELF binaries, non-HTTPS origins (unless
--allow-http is given for local E2E), malformed versions or commits, so a
truncated build can never produce a publishable manifest.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise SystemExit(f"bridge asset error: {message}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def asset(bin_dir: Path, name: str) -> tuple[Path, str, int]:
    path = bin_dir / name
    if not path.is_file():
        fail(f"missing binary: {path}")
    size = path.stat().st_size
    if size <= 0:
        fail(f"empty binary: {path}")
    with path.open("rb") as handle:
        if handle.read(4) != ELF_MAGIC:
            fail(f"not an ELF binary: {path}")
    return path, sha256(path), size


def validate_origin(base_url: str, allow_http: bool) -> str:
    if not base_url:
        fail("base URL is required")
    if base_url.endswith("/"):
        base_url = base_url.rstrip("/")
    scheme = base_url.split("://", 1)[0] if "://" in base_url else ""
    if not scheme:
        fail(f"base URL has no scheme: {base_url}")
    if scheme != "https" and not (allow_http and scheme == "http"):
        fail(f"base URL must be https (got {scheme})")
    if any(ch in base_url for ch in "?#"):
        fail(f"base URL must not contain query/fragment: {base_url}")
    return base_url


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="only for local container E2E; production must be https",
    )
    args = parser.parse_args()

    version = args.version.strip()
    if not version:
        fail("version is empty")
    if not COMMIT_RE.match(args.source_commit):
        fail(f"source commit must be 40 lowercase hex chars: {args.source_commit}")
    base_url = validate_origin(args.base_url, args.allow_http)

    primary_name = f"idleleo-linux-{args.arch}"
    recovery_name = f"idleleo-recover-linux-{args.arch}"
    _, primary_sha, primary_size = asset(args.bin_dir, primary_name)
    _, recovery_sha, recovery_size = asset(args.bin_dir, recovery_name)

    manifest = {
        "schemaVersion": 1,
        "channel": "go",
        "version": version,
        "sourceCommit": args.source_commit,
        "arch": args.arch,
        "url": f"{base_url}/{primary_name}",
        "sha256": primary_sha,
        "size": primary_size,
        "recoveryUrl": f"{base_url}/{recovery_name}",
        "recoverySha256": recovery_sha,
        "recoverySize": recovery_size,
    }
    if not SHA256_RE.match(manifest["sha256"]):
        fail("internal SHA-256 error")
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"bridge-asset={args.output}")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
