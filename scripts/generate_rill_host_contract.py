#!/usr/bin/env python3
"""Generate the Xray-owned Rill host contract.

The contract hashes only the Rill integration block in install.sh.  That keeps
unrelated installer, README, translation, and CI changes out of the host
identity while still making real host-glue changes observable.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"
CONTRACT = ROOT / "repository_files/rill_integration/HOST_CONTRACT.json"
BEGIN = b"# BEGIN RILL XRAY AGENT INTEGRATION"
END = b"# END RILL XRAY AGENT INTEGRATION"


def host_surface(blob: bytes) -> bytes:
    start = blob.find(BEGIN)
    if start < 0:
        raise SystemExit("Rill host integration begin marker missing")
    end_marker = END + b"\n"
    end = blob.find(end_marker, start)
    if end < 0:
        raise SystemExit("Rill host integration end marker missing")
    return blob[start : end + len(end_marker)]


def build_contract() -> dict[str, object]:
    install_surface_sha = hashlib.sha256(host_surface(INSTALL.read_bytes())).hexdigest()
    return {
        "schemaVersion": 1,
        "contract": "xray-rill-host-surface",
        "repository": "hello-yunshu/Xray_bash_onekey",
        "hostOwnedFiles": {
            "install.sh#RILL_XRAY_AGENT_INTEGRATION": install_surface_sha,
        },
        "semanticVersion": 1,
    }


def main() -> int:
    contract = build_contract()
    payload = json.dumps(contract, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    contract["digest"] = hashlib.sha256(payload).hexdigest()
    CONTRACT.parent.mkdir(parents=True, exist_ok=True)
    CONTRACT.write_text(json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(f"wrote {CONTRACT} ({contract['digest'][:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
