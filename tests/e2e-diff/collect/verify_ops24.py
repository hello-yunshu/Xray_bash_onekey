#!/usr/bin/env python3
"""Verify real Bash/Go GeoData refresh evidence and correct its row verdict."""
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path


def read(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def command_rc(path):
    try:
        return int(read(path).strip())
    except ValueError:
        return None


def snapshot(path):
    body = read(path)
    hashes = {}
    for line in body.splitlines():
        match = re.match(r"^([0-9a-f]{64})\s+.+/(geoip|geosite)\.dat$", line.strip())
        if match:
            hashes[match.group(2)] = match.group(1)
    active = body.splitlines()[-1].strip() == "active" if body.splitlines() else False
    return {"sha256": hashes, "xrayActive": active}


def verify(root):
    ops = root / "OPS-24"
    bash_dir, go_dir = ops / "bash", ops / "go"
    reasons = []
    bash_out = read(bash_dir / "run.out")
    geo_log = read(bash_dir / "geo-update.log")
    bash_tag = read(bash_dir / "release.txt").strip()
    go_tag = read(go_dir / "release.txt").strip()
    if command_rc(bash_dir / "run.rc") != 0:
        reasons.append("Bash management menu did not exit successfully")
    if "GeoData update completed successfully for " + bash_tag not in geo_log:
        reasons.append("Bash updater log does not confirm successful completion")
    if "GeoData 手动刷新完成" not in bash_out:
        reasons.append("Bash menu did not report successful refresh")
    if command_rc(go_dir / "09-install.rc") != 0:
        reasons.append("Go schedule install did not exit successfully")
    if command_rc(go_dir / "10-op.rc") != 0:
        reasons.append("Go geodata-refresh command did not exit successfully")
    try:
        payload = json.loads(read(go_dir / "10-op.out"))
        results = [r for r in payload.get("results", []) if r.get("job") == "geodata-refresh"]
        if len(results) != 1 or results[0].get("result") != "ok":
            reasons.append("Go JSON results[] does not contain exactly one successful geodata-refresh")
    except (json.JSONDecodeError, AttributeError, TypeError):
        reasons.append("Go schedule output is not valid result JSON")
    if not bash_tag or bash_tag != go_tag:
        reasons.append("Bash and Go did not use the same pinned release tag")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", bash_tag):
        reasons.append("GeoData release tag is invalid")

    bash_facts = snapshot(bash_dir / "after.txt")
    go_facts = snapshot(go_dir / "after.txt")
    expected_assets = {"geoip", "geosite"}
    for side, facts in (("Bash", bash_facts), ("Go", go_facts)):
        if set(facts["sha256"]) != expected_assets:
            reasons.append(side + " did not leave both GeoData files with SHA-256 evidence")
        if not facts["xrayActive"]:
            reasons.append(side + " Xray service was not active after refresh")
    if bash_facts["sha256"] != go_facts["sha256"]:
        reasons.append("Bash and Go GeoData SHA-256 values differ")

    return {
        "id": "OPS-24",
        "verdict": "DUAL_SIDE_VERIFIED" if not reasons else "FAIL",
        "reasons": reasons,
        "releaseTag": bash_tag,
        "opsRc": {
            "bash": command_rc(bash_dir / "run.rc"),
            "goInstall": command_rc(go_dir / "09-install.rc"),
            "goRun": command_rc(go_dir / "10-op.rc"),
        },
        "assetFacts": {"bash": bash_facts, "go": go_facts},
    }


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_ops24.py <p2 evidence directory>")
    root = Path(sys.argv[1]).resolve()
    ops = root / "OPS-24"
    result = verify(root)
    result["schemaVersion"] = 1
    try:
        source_run_id = json.loads(read(root / "run.json")).get("runId")
    except (json.JSONDecodeError, AttributeError):
        source_run_id = None
    result["sourceRunId"] = source_run_id
    result["sourceEvidence"] = [
        "OPS-24/bash/run.out", "OPS-24/bash/run.rc", "OPS-24/bash/geo-update.log",
        "OPS-24/bash/release.txt", "OPS-24/bash/after.txt",
        "OPS-24/go/09-install.out", "OPS-24/go/09-install.rc",
        "OPS-24/go/10-op.out", "OPS-24/go/10-op.rc",
        "OPS-24/go/release.txt", "OPS-24/go/after.txt",
    ]
    verifier_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result["verifier"] = {"path": "tests/e2e-diff/collect/verify_ops24.py", "sha256": verifier_sha}

    row_path = ops / "ops.json"
    row = json.loads(row_path.read_text(encoding="utf-8"))
    previous_verdict = row.get("verdict")
    if row.get("verdict") != result["verdict"]:
        initial = ops / "ops.initial-verdict.json"
        if not initial.exists():
            shutil.copyfile(row_path, initial)
    row["verdict"] = "PASS" if result["verdict"] == "DUAL_SIDE_VERIFIED" else "FAIL"
    row["reasons"] = result["reasons"]
    row["opsRc"] = {"bash": result["opsRc"]["bash"], "go": result["opsRc"]["goRun"]}
    row["releaseTag"] = result["releaseTag"]
    row["assetFacts"] = result["assetFacts"]
    row["expectedRc"] = {"bash": 0, "goInstall": 0, "goRun": 0}
    row["verifier"] = result["verifier"]
    row["initialVerdictFile"] = "OPS-24/ops.initial-verdict.json" if (ops / "ops.initial-verdict.json").exists() else None
    if previous_verdict != result["verdict"]:
        row["classificationCorrection"] = {
            "from": previous_verdict,
            "to": result["verdict"],
            "reason": "The first inline parser expected a top-level result field; the real schedule command returns the job result under results[].",
            "previousRecord": "OPS-24/ops.initial-verdict.json",
        }
    payload = json.dumps(row, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".ops24-", dir=str(ops))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, row_path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    out = ops / "verification.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["verdict"] == "DUAL_SIDE_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
