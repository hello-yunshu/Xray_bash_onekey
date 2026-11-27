#!/usr/bin/env python3
"""Signed-stage smoke for the preview workflow.

The preview channel deliberately refuses a signed feature ledger. Once F01-F28
are signed, this script runs instead and proves the signed stage is coherent:
exactly 28 unique features, no pending entries, every referenced evidence file
exists, each run.json matches its fixture with rc=0, and the built binary
answers. It never runs the preview fixtures, never claims a preview PASS and
never grants release authority.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
EXPECTED = {f"F{i:02d}" for i in range(1, 29)}
SIGNED = {"VERIFIED_GO_PARITY", "APPROVED_SAFE_DIVERGENCE"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-bin", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, default=ROOT / "cases" / "feature_contracts.json")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    errors = []
    try:
        manifest = json.loads(args.ledger.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"SIGNED-STAGE SMOKE FAILED: cannot read ledger: {exc}", file=sys.stderr)
        return 2

    features = manifest.get("features") or []
    ids = [f.get("id") for f in features]
    if len(ids) != 28 or set(ids) != EXPECTED:
        errors.append(f"ledger must contain exactly F01-F28, got {len(ids)} id(s)")
    for feature in features:
        fid = feature.get("id", "?")
        if feature.get("status") not in SIGNED:
            errors.append(f"{fid}: status {feature.get('status')!r} is not signed")
        evidence = feature.get("evidence") or []
        if not evidence:
            errors.append(f"{fid}: no evidence files")
            continue
        run_seen = False
        for rel in evidence:
            path = REPO / rel
            if not path.is_file():
                errors.append(f"{fid}: evidence missing: {rel}")
                continue
            if path.name == "run.json":
                run_seen = True
                try:
                    run = json.loads(path.read_text())
                except json.JSONDecodeError as exc:
                    errors.append(f"{fid}: {rel} is not valid JSON: {exc}")
                    continue
                if run.get("fixture") != fid:
                    errors.append(f"{fid}: run.json names fixture {run.get('fixture')!r}")
                if run.get("rc") != 0:
                    errors.append(f"{fid}: run.json rc={run.get('rc')}")
            if path.name == "rc.txt":
                text = path.read_text().strip()
                if text != "0":
                    errors.append(f"{fid}: rc.txt is {text!r}")
        if not run_seen:
            errors.append(f"{fid}: no run.json in evidence")

    go_bin = args.go_bin.resolve()
    if not go_bin.is_file():
        errors.append(f"go binary not found: {go_bin}")
    else:
        for argv in ([str(go_bin), "--help"], [str(go_bin), "version"]):
            res = subprocess.run(argv, text=True, capture_output=True, timeout=30)
            if res.returncode != 0:
                errors.append(f"{' '.join(argv)} exited {res.returncode}")
        version = subprocess.run([str(go_bin), "version"], text=True, capture_output=True, timeout=30)
        if "idleleo" not in version.stdout:
            errors.append("binary version does not identify idleleo")

    report = {
        "stage": "signed",
        "previewRun": False,
        "status": "NOT_APPLICABLE_SIGNED_LEDGER",
        "releaseAuthority": "NONE",
        "features": len(features),
        "ledgerSha256": digest(args.ledger) if args.ledger.is_file() else None,
        "goBinSha256": digest(go_bin) if go_bin.is_file() else None,
        "errors": errors,
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n")

    if errors:
        print("SIGNED-STAGE SMOKE FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 2
    print("SIGNED-STAGE SMOKE PASS: 28/28 signed, evidence present, binary answers")
    print("preview not run (signed ledger); release authority: NONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
