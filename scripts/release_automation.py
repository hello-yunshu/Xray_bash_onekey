#!/usr/bin/env python3
"""Deterministic helpers for the cross-repository shell release chain."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


RILL_SCRIPTS = (
    "rill_xray_agent_bootstrap.sh",
    "rill_xray_agent_install.sh",
    "rill_xray_agent_manager.sh",
    "rill_xray_agent_uninstall.sh",
    "rill_xray_agent_verify.sh",
)
BUNDLE = "rill-xray-agent-xray-bundle.tar.gz"
VERSION_RE = re.compile(r'^shell_version="([0-9]+\.[0-9]+\.[0-9]+)"$', re.MULTILINE)
PIN_RE = re.compile(r"^  RILL_CANONICAL_COMMIT: [0-9a-f]{40}$", re.MULTILINE)
CANONICAL_ROOTS = {
    "rill_payload": "rill_payload",
    "scripts": "scripts",
    "systemd": "systemd",
    "assets": "assets",
}


def run(*argv: str, cwd: Path) -> None:
    subprocess.run(argv, cwd=cwd, check=True)


def copy_file(source: Path, target: Path) -> None:
    if not source.is_file():
        raise SystemExit(f"missing source file: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def package_files(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "PACKAGE_SHA256SUMS":
            continue
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] == ".git":
            continue
        if any(part in {"__pycache__", ".pytest_cache", "target"} for part in rel.parts):
            continue
        if path.name.endswith(".pyc"):
            continue
        result[rel.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def write_package_sums(root: Path) -> None:
    sums = package_files(root)
    body = "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items()))
    (root / "PACKAGE_SHA256SUMS").write_text(body)


def _canonical_manifest(rill_repo: Path) -> dict:
    path = rill_repo / "integrations/xray_bash_onekey/CANONICAL_MANIFEST.json"
    try:
        manifest = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid canonical manifest: {path}: {exc}") from exc
    if manifest.get("schemaVersion") != 1 or not isinstance(manifest.get("files"), dict):
        raise SystemExit(f"unsupported canonical manifest: {path}")
    return manifest


def canonical_owned_files(rill_repo: Path) -> list[tuple[Path, Path]]:
    """Resolve every manifest-owned repository file to its Xray target.

    The resolver is the single source for drift detection, apply, and staging.
    ``source/*`` manifest entries remain Rill-side evidence and are never
    copied into Xray.
    """
    integration = rill_repo / "integrations/xray_bash_onekey"
    owned: list[tuple[Path, Path]] = []
    for rel in sorted(_canonical_manifest(rill_repo)["files"]):
        if not rel.startswith("repository_files/"):
            continue
        sub = rel[len("repository_files/"):]
        top, separator, rest = sub.partition("/")
        if not separator or top not in CANONICAL_ROOTS:
            raise SystemExit(f"unsupported canonical-owned path: {rel}")
        owned.append((integration / "repository_files" / sub,
                      Path(CANONICAL_ROOTS[top]) / rest))
    if not owned:
        raise SystemExit("canonical manifest contains no repository-owned files")
    return owned


def _canonical_stale_candidates(xray: Path) -> list[Path]:
    """Return only reserved canonical roots/prefixes eligible for stale removal."""
    candidates: set[Path] = set()
    payload = xray / "rill_payload"
    if payload.is_dir():
        candidates.update(p for p in payload.rglob("*") if p.is_file())
    scripts = xray / "scripts"
    if scripts.is_dir():
        candidates.update(p for p in scripts.glob("rill_xray_agent_*") if p.is_file())
    systemd = xray / "systemd"
    if systemd.is_dir():
        candidates.update(p for p in systemd.glob("rill-xray-agent-*") if p.is_file())
    bundle = xray / "assets" / BUNDLE
    if bundle.is_file():
        candidates.add(bundle)

    # apply-rill removes stale files before stage-rill runs. Recover tracked
    # paths from the same narrow canonical scope so those deletions remain
    # explicit git-add targets without staging host-owned files.
    tracked = subprocess.run(
        ("git", "ls-files", "--", "rill_payload", "scripts", "systemd",
         f"assets/{BUNDLE}"), cwd=xray, capture_output=True, text=True,
        check=False)
    if tracked.returncode == 0:
        for rel in tracked.stdout.splitlines():
            if (rel.startswith("rill_payload/")
                    or rel.startswith("scripts/rill_xray_agent_")
                    or rel.startswith("systemd/rill-xray-agent-")
                    or rel == f"assets/{BUNDLE}"):
                candidates.add(xray / rel)
    return sorted(candidates)


def canonical_drift(xray: Path, rill: Path) -> tuple[list[Path], list[Path]]:
    owned = canonical_owned_files(rill)
    expected = {target for _source, target in owned}
    changed: list[Path] = []
    for source, target in owned:
        destination = xray / target
        if not source.is_file() or not destination.is_file():
            changed.append(target)
        elif hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(destination.read_bytes()).digest():
            changed.append(target)
    stale = [path.relative_to(xray) for path in _canonical_stale_candidates(xray)
             if path.relative_to(xray) not in expected]
    return sorted(set(changed)), sorted(set(stale))


def check_rill_drift(xray: Path, rill: Path, github_output: Path) -> None:
    changed, stale = canonical_drift(xray, rill)
    all_changed = sorted(set(changed + stale))
    for path in all_changed:
        print(f"changed: {path}")
    github_output.parent.mkdir(parents=True, exist_ok=True)
    with github_output.open("a") as handle:
        handle.write(f"changed={'true' if all_changed else 'false'}\n")


def stage_rill(xray: Path, rill: Path) -> None:
    _changed, stale = canonical_drift(xray, rill)
    paths = [target.as_posix() for _source, target in canonical_owned_files(rill)]
    paths.extend(path.as_posix() for path in stale)
    paths.append(".github/workflows/rill-xray-agent.yml")
    run("git", "add", "--", *sorted(set(paths)), cwd=xray)


def sync_rill(xray: Path, rill: Path) -> None:
    target_scripts = rill / "integrations/xray_bash_onekey/repository_files/scripts"
    for name in RILL_SCRIPTS:
        copy_file(xray / "scripts" / name, target_scripts / name)

    run(sys.executable, "scripts/sync_xray_payload.py", cwd=rill)
    run(sys.executable, "scripts/build_canonical_manifest.py", cwd=rill)
    write_package_sums(rill)
    run(sys.executable, "scripts/build_canonical_manifest.py", "--check", cwd=rill)
    run(sys.executable, "scripts/verify_xray_integration.py", cwd=rill)
    run(sys.executable, "scripts/verify_package_sums.py", cwd=rill)


def apply_rill(xray: Path, rill: Path, commit: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit("canonical commit must be a full 40-character SHA")
    integration = rill / "integrations/xray_bash_onekey"
    owned = canonical_owned_files(rill)
    expected = {target for _source, target in owned}
    for stale in _canonical_stale_candidates(xray):
        if stale.relative_to(xray) not in expected:
            stale.unlink()
    for source, target in owned:
        copy_file(source, xray / target)

    workflow = xray / ".github/workflows/rill-xray-agent.yml"
    text = workflow.read_text()
    updated, count = PIN_RE.subn(f"  RILL_CANONICAL_COMMIT: {commit}", text, count=1)
    if count != 1:
        raise SystemExit(f"RILL_CANONICAL_COMMIT anchor missing or ambiguous: {workflow}")
    workflow.write_text(updated)

    run(
        sys.executable,
        str(integration / "tools/verify_xray_payload.py"),
        str(xray),
        str(integration / "CANONICAL_MANIFEST.json"),
        cwd=xray,
    )


def version_tuple(value: str) -> tuple[int, int, int]:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise SystemExit(f"invalid shell version: {value}")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def shell_version(xray: Path) -> str:
    matches = VERSION_RE.findall((xray / "install.sh").read_text())
    if len(matches) != 1:
        raise SystemExit("install.sh must contain exactly one shell_version anchor")
    return matches[0]


def update_api(xray: Path, api: Path, details: str, update_date: str | None) -> bool:
    version = shell_version(xray)
    manifest_path = api / "xray_shell_versions.json"
    manifest = json.loads(manifest_path.read_text())
    current = manifest.get("shell_online_version")
    if not isinstance(current, str):
        raise SystemExit("shell_online_version is missing from the API manifest")
    if version_tuple(version) < version_tuple(current):
        raise SystemExit(f"refusing shell version downgrade: {current} -> {version}")
    if version == current:
        print(f"version API already publishes shell {version}")
        return False

    if not details.strip():
        raise SystemExit("release details must not be empty")
    if update_date is None:
        update_date = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")
    manifest["update_date"] = update_date
    manifest["shell_online_version"] = version
    manifest["shell_upgrade_details"] = details.strip()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(f"prepared version API update: {current} -> {version}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    sync = sub.add_parser("sync-rill")
    sync.add_argument("--xray", type=Path, required=True)
    sync.add_argument("--rill", type=Path, required=True)

    apply = sub.add_parser("apply-rill")
    apply.add_argument("--xray", type=Path, required=True)
    apply.add_argument("--rill", type=Path, required=True)
    apply.add_argument("--commit", required=True)

    drift = sub.add_parser("check-rill-drift")
    drift.add_argument("--xray", type=Path, required=True)
    drift.add_argument("--rill", type=Path, required=True)
    drift.add_argument("--github-output", type=Path, required=True)

    stage = sub.add_parser("stage-rill")
    stage.add_argument("--xray", type=Path, required=True)
    stage.add_argument("--rill", type=Path, required=True)

    api = sub.add_parser("update-api")
    api.add_argument("--xray", type=Path, required=True)
    api.add_argument("--api", type=Path, required=True)
    api.add_argument("--details", required=True)
    api.add_argument("--date")

    args = parser.parse_args()
    if args.command == "sync-rill":
        sync_rill(args.xray.resolve(), args.rill.resolve())
    elif args.command == "apply-rill":
        apply_rill(args.xray.resolve(), args.rill.resolve(), args.commit)
    elif args.command == "check-rill-drift":
        check_rill_drift(args.xray.resolve(), args.rill.resolve(),
                         args.github_output.resolve())
    elif args.command == "stage-rill":
        stage_rill(args.xray.resolve(), args.rill.resolve())
    else:
        changed = update_api(args.xray.resolve(), args.api.resolve(), args.details, args.date)
        print(f"changed={'true' if changed else 'false'}")


if __name__ == "__main__":
    main()
