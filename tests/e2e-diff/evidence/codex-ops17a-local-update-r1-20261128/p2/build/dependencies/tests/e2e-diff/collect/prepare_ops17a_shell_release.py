#!/usr/bin/env python3
"""Prepare a pinned, local Shell release fixture for the real Bash updater."""

import hashlib
import json
import re
import shutil
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: prepare_ops17a_shell_release.py REPO_ROOT OUTPUT_DIR", file=sys.stderr)
        return 2
    repo = Path(sys.argv[1]).resolve()
    out = Path(sys.argv[2]).resolve()
    source = (repo / "install.sh").read_text(encoding="utf-8")
    match = re.search(r'^shell_version="([0-9]+)\.([0-9]+)\.([0-9]+)"$', source, re.M)
    if not match:
        raise SystemExit("current install.sh has no pinned numeric shell_version")
    major, minor, patch = map(int, match.groups())
    current = f"{major}.{minor}.{patch}"
    candidate_version = f"{major}.{minor}.{patch + 1}"
    candidate = source[:match.start(1)] + str(major) + source[match.end(1):]
    candidate = candidate.replace(
        f'shell_version="{current}"', f'shell_version="{candidate_version}"', 1
    )

    release = out / "releases" / "download" / f"v{candidate_version}"
    raw = out / "raw" / f"v{candidate_version}"
    scripts = repo / "scripts"
    release.mkdir(parents=True, exist_ok=True)
    (raw / "scripts").mkdir(parents=True, exist_ok=True)
    installer = release / "install.sh"
    installer.write_text(candidate, encoding="utf-8")
    installer.chmod(0o755)

    helpers = (
        "fail2ban_manager.sh", "traffic_blocker.sh", "file_manager.sh",
        "auto_update.sh", "ssl_update.sh", "geo_update.sh",
    )
    helper_hashes = {}
    for name in helpers:
        src = scripts / name
        if not src.is_file():
            raise SystemExit(f"required release helper is missing: {name}")
        dst = raw / "scripts" / name
        shutil.copyfile(src, dst)
        dst.chmod(0o755)
        helper_hashes[name] = sha256(dst)

    stats = scripts / "xray_stats.sh"
    if not stats.is_file():
        raise SystemExit("required xray_stats.sh helper is missing")
    shutil.copyfile(stats, release / "xray_stats.sh")
    manifest = {
        "schemaVersion": 1,
        "helperScripts": helper_hashes,
        "statsScriptSha256": sha256(release / "xray_stats.sh"),
    }
    (release / "release-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    versions = {
        "shell_online_version": candidate_version,
        "shell_release_sha256": sha256(installer),
    }
    (out / "versions.unsigned.json").write_text(
        json.dumps(versions, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "fixture.json").write_text(json.dumps({
        "sourceVersion": current,
        "candidateVersion": candidate_version,
        "candidateSha256": versions["shell_release_sha256"],
        "manifestSha256": sha256(release / "release-manifest.json"),
        "helperCount": len(helper_hashes),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
