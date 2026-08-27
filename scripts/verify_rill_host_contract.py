#!/usr/bin/env python3
"""Verify an Xray-owned Rill host contract against real source bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


BEGIN = b"# BEGIN RILL XRAY AGENT INTEGRATION"
END = b"# END RILL XRAY AGENT INTEGRATION"
EXPECTED_KEYS = {
    "schemaVersion",
    "contract",
    "repository",
    "hostOwnedFiles",
    "semanticVersion",
    "digest",
}
EXPECTED_SURFACE = "install.sh#RILL_XRAY_AGENT_INTEGRATION"


def host_surface(blob: bytes) -> bytes:
    start = blob.find(BEGIN)
    end_marker = END + b"\n"
    end = blob.find(end_marker, start)
    if start < 0 or end < 0:
        raise SystemExit("Rill host integration markers are missing")
    return blob[start : end + len(end_marker)]


def canonical_payload(contract: dict[str, object]) -> bytes:
    payload = {key: value for key, value in contract.items() if key != "digest"}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def verify(repo: Path, contract_path: Path) -> str:
    try:
        contract = json.loads(contract_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid host contract: {exc}") from exc
    if set(contract) != EXPECTED_KEYS:
        raise SystemExit(f"host contract keys mismatch: {sorted(contract)}")
    if contract["schemaVersion"] != 1 or contract["semanticVersion"] != 1:
        raise SystemExit("unsupported host contract version")
    if contract["contract"] != "xray-rill-host-surface":
        raise SystemExit("unexpected host contract name")
    if contract["repository"] != "hello-yunshu/Xray_bash_onekey":
        raise SystemExit("unexpected host contract repository")
    files = contract["hostOwnedFiles"]
    if not isinstance(files, dict) or set(files) != {EXPECTED_SURFACE}:
        raise SystemExit("host contract must contain only the Rill install surface")
    expected_surface_sha = files[EXPECTED_SURFACE]
    if not isinstance(expected_surface_sha, str) or len(expected_surface_sha) != 64:
        raise SystemExit("invalid host surface SHA-256")
    install_surface_sha = hashlib.sha256(host_surface((repo / "install.sh").read_bytes())).hexdigest()
    if install_surface_sha != expected_surface_sha:
        raise SystemExit(
            f"host surface drift: install.sh block {install_surface_sha} != {expected_surface_sha}"
        )
    expected_digest = contract["digest"]
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        raise SystemExit("invalid host contract digest")
    actual_digest = hashlib.sha256(canonical_payload(contract)).hexdigest()
    if actual_digest != expected_digest:
        raise SystemExit(f"host contract digest mismatch: {actual_digest} != {expected_digest}")
    print(json.dumps({"contract": contract["contract"], "digest": actual_digest}, sort_keys=True))
    print("PASS: Rill host contract matches install.sh source")
    return actual_digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--contract", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    contract = (args.contract or repo / "repository_files/rill_integration/HOST_CONTRACT.json").resolve()
    verify(repo, contract)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
