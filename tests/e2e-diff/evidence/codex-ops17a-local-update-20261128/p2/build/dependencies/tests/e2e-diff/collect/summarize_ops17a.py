#!/usr/bin/env python3
"""Verify both real local-package update paths for OPS-17a."""

import hashlib
import json
import re
import sys
from pathlib import Path


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def rc(path: Path):
    try:
        return int(read(path).strip())
    except ValueError:
        return None


def sha(path: Path):
    text = read(path).split()
    return text[0] if text and re.fullmatch(r"[0-9a-f]{64}", text[0]) else ""


def l4_rc(path: Path):
    try:
        rows = [json.loads(line) for line in read(path).splitlines() if line.strip()]
        return next((r.get("rc") for r in rows if r.get("transport") == "reality"), None)
    except (TypeError, ValueError):
        return None


def no_auto_update_schedule(text: str) -> bool:
    return not re.search(r"(?:install\.sh\s+-u|idleleo\s+update\s+apply)", text, re.I)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize_ops17a.py EVIDENCE_ROOT", file=sys.stderr)
        return 2
    base = Path(sys.argv[1]) / "OPS-17a"
    try:
        fixture = json.loads(read(base / "bash/fixture.json"))
        go_manifest = json.loads(read(base / "go/manifest.json"))
        go_apply = json.loads(read(base / "go/apply.json"))
    except ValueError:
        fixture, go_manifest, go_apply = {}, {}, {}
    shell_before = fixture.get("sourceVersion", "")
    shell_after = read(base / "bash/version-after.txt").strip()
    bash_schedule = read(base / "bash/schedule-before.txt") + read(base / "bash/schedule-after.txt")
    go_schedule = read(base / "go/schedule-before.txt") + read(base / "go/schedule-after.txt")
    bash_services = read(base / "bash/services-after.txt").splitlines()
    go_services = read(base / "go/services-after.txt").splitlines()
    bash_before, bash_after = sha(base / "bash/script-before.sha256"), sha(base / "bash/script-after.sha256")
    go_asset = go_manifest.get("assets", {}).get("linux-" + read(base / "go/arch.txt").strip(), {})
    go_before, go_after = sha(base / "go/binary-before.sha256"), sha(base / "go/binary-after-apply.sha256")
    bash_facts = {
        "updateApplied": bool(shell_after and shell_after == fixture.get("candidateVersion") and shell_after != shell_before),
        "versionChanged": bool(shell_before and shell_after and shell_before != shell_after),
        "assetShaMatched": bool(bash_after and bash_after == fixture.get("candidateSha256")),
        "servicesHealthy": bash_services == ["active", "active"] and all(
            rc(base / f"bash/{name}.rc") == 0 for name in ("run", "services-after", "nginx-test", "xray-test")
        ),
        "postUpdateClientOk": l4_rc(base / "bash/L4/round1.jsonl") == 0,
        "manualOnly": no_auto_update_schedule(bash_schedule),
    }
    go_facts = {
        "updateApplied": bool(go_apply.get("action") == "updated" and go_asset.get("sha256")
                               and go_apply.get("newSha256") == go_asset.get("sha256")),
        "versionChanged": bool(read(base / "go/version-before.txt").strip()
                                and read(base / "go/version-after.txt").strip()
                                and read(base / "go/version-before.txt").strip() != read(base / "go/version-after.txt").strip()),
        "assetShaMatched": bool(go_asset.get("sha256") and go_after == go_asset.get("sha256") and go_before != go_after),
        "servicesHealthy": go_services == ["active", "active"] and all(
            rc(base / f"go/{name}.rc") == 0 for name in ("configure", "check", "apply", "services-after", "nginx-test", "xray-test")
        ),
        "postUpdateClientOk": l4_rc(base / "go/L4/round1.jsonl") == 0,
        "manualOnly": no_auto_update_schedule(go_schedule),
    }
    details = {"bash": bash_facts, "go": go_facts}
    reasons = [f"{side} side failed verified update fact {key}"
               for side, facts in details.items() for key, value in facts.items() if value is not True]
    bash_op_rc = rc(base / "bash/run.rc")
    go_op_rc = rc(base / "go/apply.rc")
    if bash_op_rc != 0:
        reasons.append(f"Bash menu update rc={bash_op_rc!r}")
    if go_op_rc != 0:
        reasons.append(f"Go signed apply rc={go_op_rc!r}")
    row = {
        "id": "OPS-17a",
        "verdict": "PASS" if not reasons else "FAIL",
        "opsRc": {"bash": bash_op_rc, "go": go_op_rc},
        "details": details,
        "reasons": reasons,
        "updateEvidence": {
            "bashCandidateVersion": fixture.get("candidateVersion"),
            "bashCandidateSha256": fixture.get("candidateSha256"),
            "bashInstalledSha256Before": bash_before,
            "bashInstalledSha256After": bash_after,
            "goCandidateVersion": go_manifest.get("version"),
            "goCandidateSha256": go_asset.get("sha256"),
            "goInstalledSha256Before": go_before,
            "goInstalledSha256After": go_after,
        },
    }
    (base / "ops.json").write_text(json.dumps(row, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (base / "verification.json").write_text(json.dumps({"details": details, "reasons": reasons}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(row, ensure_ascii=False, sort_keys=True))
    return 0 if not reasons else 1


if __name__ == "__main__":
    raise SystemExit(main())
