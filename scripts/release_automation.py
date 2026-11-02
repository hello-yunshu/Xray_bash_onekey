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
PIN_FILE = "repository_files/rill_integration/RILL_CANONICAL_PIN.json"
CANONICAL_DERIVED_PATHS = frozenset({
    # Rill's bundle carries provenance for install auditability.  Excluding
    # the derived bundle hash keeps audit metadata out of runtime identity.
    "repository_files/assets/rill-xray-agent-xray-bundle.tar.gz",
})
VERSION_RE = re.compile(r'^shell_version="([0-9]+\.[0-9]+\.[0-9]+)"$', re.MULTILINE)
PIN_RE = re.compile(r"^  RILL_CANONICAL_COMMIT: [0-9a-f]{40}$", re.MULTILINE)
PIN_DIGEST_RE = re.compile(r"^  RILL_CANONICAL_DIGEST: [0-9a-f]{64}$", re.MULTILINE)
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
    if (manifest.get("schemaVersion") != 1
            or not isinstance(manifest.get("files"), dict)):
        raise SystemExit(f"unsupported canonical manifest: {path}")
    return manifest


def computed_canonical_identity(manifest: dict) -> str:
    prefixes = ("source/PROVENANCE/", "repository_files/rill_payload/PROVENANCE/")
    identity = {
        key: value for key, value in manifest["files"].items()
        if not any(key.startswith(prefix) for prefix in prefixes)
        and key not in CANONICAL_DERIVED_PATHS
    }
    payload = json.dumps(
        {"schemaVersion": 1, "files": dict(sorted(identity.items()))},
        ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def canonical_identity(rill_repo: Path) -> str:
    manifest = _canonical_manifest(rill_repo)
    digest = manifest.get("canonicalDigest")
    if digest is None:
        return computed_canonical_identity(manifest)
    if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        raise SystemExit("invalid canonical digest")
    return digest


def pinned_canonical_digest(xray: Path) -> str | None:
    pin = xray / PIN_FILE
    if pin.is_file():
        try:
            value = json.loads(pin.read_text()).get("canonicalDigest")
        except (OSError, json.JSONDecodeError, AttributeError):
            raise SystemExit(f"invalid canonical pin: {pin}")
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise SystemExit(f"invalid canonical digest in pin: {pin}")
        return value

    # Transition fallback for the pre-pin-file main revision. Once the
    # migration PR lands, automated sync never writes workflow files.
    text = (xray / ".github/workflows/rill-xray-agent.yml").read_text()
    match = PIN_DIGEST_RE.search(text)
    return match.group(0).split(":", 1)[1].strip() if match else None


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
    current = canonical_identity(rill)
    pinned = pinned_canonical_digest(xray)
    changed = pinned is None or current != pinned
    print(f"pinned canonical digest: {pinned or '<missing>'}")
    print(f"current canonical digest: {current}")
    print("DRIFT" if changed else "NO_CHANGE")
    github_output.parent.mkdir(parents=True, exist_ok=True)
    with github_output.open("a") as handle:
        handle.write(f"changed={'true' if changed else 'false'}\n")
        handle.write(f"current_canonical_digest={current}\n")
        handle.write(f"pinned_canonical_digest={pinned or 'missing'}\n")


def stage_rill(xray: Path, rill: Path) -> None:
    _changed, stale = canonical_drift(xray, rill)
    paths = [target.as_posix() for _source, target in canonical_owned_files(rill)]
    paths.extend(path.as_posix() for path in stale)
    paths.append(PIN_FILE)
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


def apply_rill(xray: Path, rill: Path, commit: str, digest: str | None = None) -> None:
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

    digest = digest or canonical_identity(rill)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("canonical digest must be a full 64-character SHA-256")
    pin = xray / PIN_FILE
    pin.parent.mkdir(parents=True, exist_ok=True)
    pin.write_text(json.dumps({
        "canonicalCommit": commit,
        "canonicalDigest": digest,
        "schemaVersion": 1,
    }, indent=2, sort_keys=True) + "\n")

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


ALL_BASELINE_SCENARIOS = (
    "direct",
    "shell-first",
    "reinstall",
    "failure-recovery",
    "restart-recovery",
    "fallback",
)
LEGACY_BASELINE_SCENARIOS = ("shell-first", "reinstall")
KNOWN_BASELINE_SCENARIOS = frozenset(ALL_BASELINE_SCENARIOS)


def _default_baseline_scenarios(version: str) -> tuple[str, ...]:
    # 3.3.0 is the minimum direct-upgrade source. Older baselines only
    # qualify the two legacy-compatible paths.
    return ALL_BASELINE_SCENARIOS if version_tuple(version) >= (3, 3, 0) else LEGACY_BASELINE_SCENARIOS


def _parse_baseline_scenarios(value: str | None, version: str) -> tuple[str, ...]:
    if value is None or not value.strip():
        return _default_baseline_scenarios(version)
    scenarios = tuple(part.strip() for part in value.split(",") if part.strip())
    if not scenarios:
        raise SystemExit("baseline scenarios must not be empty")
    unknown = sorted(set(scenarios) - KNOWN_BASELINE_SCENARIOS)
    if unknown:
        raise SystemExit(f"unknown baseline scenarios: {', '.join(unknown)}")
    if len(set(scenarios)) != len(scenarios):
        raise SystemExit("baseline scenarios must be unique")
    return scenarios


def _update_compatibility_baseline(api: Path, version: str, commit: str | None,
                                   install_sha: str | None,
                                   scenarios: tuple[str, ...]) -> bool:
    """Keep the API baseline list in lockstep with the published Release.

    The release workflow used to update only xray_shell_versions.json. The API
    promotion tests require a baseline entry for the online Shell version, so
    the first same-version release necessarily failed. This function adds or
    refreshes the baseline entry when the API repository provides the file.
    Unit tests with a minimal API fixture do not have the file and remain
    unaffected.
    """
    path = api / "compatibility-baselines.json"
    if not path.is_file() or not commit:
        return False
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit("baseline commit must be 40 lowercase hex characters")
    if install_sha is not None and not re.fullmatch(r"[0-9a-f]{64}", install_sha):
        raise SystemExit("baseline install SHA-256 must be 64 lowercase hex characters")
    doc = json.loads(path.read_text())
    baselines = doc.get("baselines")
    if not isinstance(baselines, list):
        raise SystemExit("compatibility-baselines.json has no baselines list")
    if install_sha is None:
        raise SystemExit("an installer SHA-256 is required to update the baseline")

    entry = next((item for item in baselines if item.get("version") == version), None)
    initial = entry.get("initial") if entry else None
    if not initial:
        previous = [
            item for item in baselines
            if isinstance(item.get("version"), str)
            and version_tuple(item["version"]) < version_tuple(version)
        ]
        if previous:
            previous.sort(key=lambda item: version_tuple(item["version"]))
            initial = previous[-1].get("initial")
        if not initial:
            trusted = doc.get("trustedInitials")
            initial = trusted[0] if isinstance(trusted, list) and trusted else None
    if not isinstance(initial, dict):
        raise SystemExit("no usable baseline initial state is available")

    changed = False
    if entry is None:
        entry = {
            "version": version,
            "tag": f"v{version}",
            "commit": commit,
            "installSha256": install_sha,
            "scenarios": list(scenarios),
            "initial": initial,
        }
        baselines.append(entry)
        changed = True
    else:
        desired = {
            "tag": f"v{version}",
            "commit": commit,
            "installSha256": install_sha,
            "scenarios": list(scenarios),
        }
        for key, value in desired.items():
            if entry.get(key) != value:
                entry[key] = value
                changed = True
        if not isinstance(entry.get("initial"), dict):
            entry["initial"] = initial
            changed = True

    if changed:
        path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
    return changed


def update_api(xray: Path, api: Path, details: str, update_date: str | None,
               shell_release_sha256: str | None = None, shell_commit: str | None = None,
               baseline_scenarios: tuple[str, ...] | None = None) -> bool:
    version = shell_version(xray)
    manifest_path = api / "xray_shell_versions.json"
    manifest = json.loads(manifest_path.read_text())
    current = manifest.get("shell_online_version")
    if not isinstance(current, str):
        raise SystemExit("shell_online_version is missing from the API manifest")
    if version_tuple(version) < version_tuple(current):
        raise SystemExit(f"refusing shell version downgrade: {current} -> {version}")
    if shell_release_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", shell_release_sha256):
        raise SystemExit("shell release SHA-256 must be 64 lowercase hex characters")
    if version != current and not details.strip():
        raise SystemExit("release details must not be empty")

    changed = False
    existing_sha = manifest.get("shell_release_sha256")
    if version != current or (shell_release_sha256 is not None and existing_sha != shell_release_sha256):
        if update_date is None:
            update_date = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")
        manifest["update_date"] = update_date
        manifest["shell_online_version"] = version
        if details.strip():
            manifest["shell_upgrade_details"] = details.strip()
        if shell_release_sha256 is not None:
            manifest["shell_release_sha256"] = shell_release_sha256
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        changed = True

    scenarios = baseline_scenarios if baseline_scenarios is not None else _default_baseline_scenarios(version)
    baseline_changed = _update_compatibility_baseline(
        api, version, shell_commit, shell_release_sha256, scenarios
    )
    changed = changed or baseline_changed

    if changed:
        print(f"prepared version API update: {current} -> {version}")
    else:
        print(f"version API already publishes shell {version} with matching metadata")
    return changed


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
    apply.add_argument("--digest")

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
    api.add_argument("--shell-release-sha256")
    api.add_argument("--shell-commit")
    api.add_argument("--baseline-scenarios")

    args = parser.parse_args()
    if args.command == "sync-rill":
        sync_rill(args.xray.resolve(), args.rill.resolve())
    elif args.command == "apply-rill":
        apply_rill(args.xray.resolve(), args.rill.resolve(), args.commit, args.digest)
    elif args.command == "check-rill-drift":
        check_rill_drift(args.xray.resolve(), args.rill.resolve(),
                         args.github_output.resolve())
    elif args.command == "stage-rill":
        stage_rill(args.xray.resolve(), args.rill.resolve())
    else:
        scenarios = _parse_baseline_scenarios(args.baseline_scenarios, shell_version(args.xray.resolve()))
        changed = update_api(args.xray.resolve(), args.api.resolve(), args.details, args.date,
                             args.shell_release_sha256, args.shell_commit, scenarios)
        print(f"changed={'true' if changed else 'false'}")


if __name__ == "__main__":
    main()
