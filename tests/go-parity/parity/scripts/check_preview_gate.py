#!/usr/bin/env python3
"""Preview qualification runner — NOT FOR RELEASE.

This is the preview-channel sibling of check_release_gate.py. It deliberately
reuses the same fixture contract (python3 -I <fixture> --go-bin --bash-repo,
240s per fixture) but has no release authority:

  * the release ledger (feature_contracts.json) must stay 28 x PENDING,
  * check_release_gate.py must match RELEASE_GATE_SHA256, provided by the
    workflow environment rather than pinned in a data file; the ledger digest
    is computed at run time and recorded in preview_qualification.json,
  * evidence may come from a prepared container or GitHub Actions,
  * tag/release events are refused outright.

Everything is decided by the real fixture exit code. JSON alone never grants
success here, and nothing in this file can publish, tag or release.
"""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BANNER = "PREVIEW — NOT FOR RELEASE"
EXPECTED = {f"F{i:02d}" for i in range(1, 29)}
PENDING = "PENDING_GO_IMPLEMENTATION"
FIXTURE_TIMEOUT = 240
GOARCH = {"arm64": 0xB7, "aarch64": 0xB7, "x86_64": 0x3E, "amd64": 0x3E}


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def elf_machine(path):
    """Return (is_elf, e_machine) without trusting the file extension."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(20)
    except OSError:
        return False, None
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return False, None
    little = head[5] == 1
    machine = int.from_bytes(head[18:20], "little" if little else "big")
    return True, machine


def refuse(message, code=2):
    print(f"PREVIEW — NOT FOR RELEASE: {message}", file=sys.stderr)
    return code


def load_contract():
    path = ROOT / "cases/preview_contract.json"
    data = json.loads(path.read_text())
    if data.get("banner") != BANNER or data.get("release_authority") is not False:
        raise ValueError("preview contract must set banner and release_authority=false")
    features = data.get("features") or []
    if not features:
        raise ValueError("preview contract lists no features")
    ids = [f.get("id") for f in features]
    if len(ids) != len(set(ids)):
        raise ValueError("preview contract contains duplicate ids")
    if not set(ids) <= EXPECTED:
        raise ValueError(f"preview contract contains unknown ids: {sorted(set(ids) - EXPECTED)}")
    for f in features:
        fid, fixture = f.get("id"), f.get("fixture")
        if not fid or not fixture:
            raise ValueError("every preview feature needs id and fixture")
        if Path(fixture).name != fixture:
            raise ValueError(f"{fid}: fixture must be a bare file name")
        if f.get("status") not in ("PENDING_PREVIEW", "EXTERNAL_RESOURCE_REQUIRED", "EXTERNAL_RESOURCE_PARTIAL"):
            raise ValueError(f"{fid}: preview status {f.get('status')!r} is not allowed")
    return path, data


def check_gate_and_ledger():
    """Pin the release gate from the environment and keep the ledger read-only.

    The gate digest is no longer a data-file constant: the workflow supplies
    RELEASE_GATE_SHA256 so the reviewed gate cannot drift unnoticed. The ledger
    digest is not a precondition any more; it is computed at run time as an
    audit record in preview_qualification.json. Its 28 x PENDING content and
    the exact F01-F28 ids are still enforced.
    """
    gate = ROOT / "scripts/check_release_gate.py"
    ledger = ROOT / "cases/feature_contracts.json"
    pinned = os.environ.get("RELEASE_GATE_SHA256", "").strip().lower()
    if not pinned:
        raise ValueError("RELEASE_GATE_SHA256 is not set; the preview run must pin a reviewed release gate")
    if digest(gate) != pinned:
        raise ValueError("check_release_gate.py changed; preview may not run against a modified release gate")
    manifest = json.loads(ledger.read_text())
    feats = manifest.get("features") or []
    ids = [f.get("id") for f in feats]
    if len(ids) != 28 or set(ids) != EXPECTED:
        raise ValueError("release ledger is not exactly F01-F28")
    pending = [f["id"] for f in feats if f.get("status") != PENDING]
    if pending:
        raise ValueError("release ledger is no longer all PENDING: " + ",".join(sorted(pending)))
    return gate, ledger, manifest


def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-bin", type=Path, required=True)
    parser.add_argument("--bash-repo", type=Path, required=True)
    parser.add_argument("--container-evidence", default="")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--only", default="", help="comma separated ids (development only)")
    args = parser.parse_args()

    try:
        contract_path, contract = load_contract()
        gate_path, ledger_path, _manifest = check_gate_and_ledger()
        ledger_sha = digest(ledger_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return refuse(str(exc), 2)

    if os.environ.get("GITHUB_REF_TYPE") == "tag" or os.environ.get("GITHUB_EVENT_NAME") == "release":
        return refuse("preview qualification refuses tag/release events", 3)

    in_ci = os.environ.get("GITHUB_ACTIONS") == "true" and bool(os.environ.get("GITHUB_SHA"))
    if not args.container_evidence and not in_ci:
        return refuse("no evidence source: pass --container-evidence or run on GitHub Actions", 3)

    go_bin = args.go_bin.resolve()
    if not go_bin.is_file():
        return refuse(f"go binary not found: {go_bin}", 3)
    is_elf, machine = elf_machine(go_bin)
    expected_machine = GOARCH.get(platform.machine().lower())
    if not is_elf:
        return refuse("go binary is not an ELF executable", 3)
    if expected_machine is None:
        return refuse(f"unsupported host machine {platform.machine()!r}", 3)
    if machine != expected_machine:
        return refuse(f"go binary architecture 0x{machine:x} does not match host 0x{expected_machine:x}", 3)

    bash_repo = args.bash_repo.resolve()
    install_sh = bash_repo / "install.sh"
    if not install_sh.is_file():
        return refuse(f"bash baseline not found: {install_sh}", 3)

    selected = contract["features"]
    if args.only:
        wanted = [x.strip() for x in args.only.split(",") if x.strip()]
        known = {f["id"] for f in selected}
        unknown = [x for x in wanted if x not in known]
        if unknown:
            return refuse(f"--only ids not in the preview contract: {unknown}", 3)
        selected = [f for f in selected if f["id"] in wanted]

    missing = []
    for f in selected:
        fixture = ROOT / "features" / f["fixture"]
        if not fixture.is_file():
            missing.append(f"{f['id']}:{fixture}")
    if missing:
        return refuse("missing executable feature fixtures: " + ", ".join(missing), 2)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence = args.evidence.resolve() if args.evidence else ROOT / "evidence" / f"preview-{stamp}"
    evidence.mkdir(parents=True, exist_ok=True)

    print(f"contract: {contract_path.relative_to(ROOT)} ({len(selected)} feature(s))")
    print("ledger: 28/28 PENDING_GO_IMPLEMENTATION (unchanged)")
    if args.container_evidence:
        print(f"evidence level: CONTAINER_VERIFIED ({args.container_evidence})")
    else:
        print(f"evidence level: GITHUB_ACTIONS_VERIFIED (sha {os.environ.get('GITHUB_SHA')})")
    print(f"go-bin: {go_bin} sha256={digest(go_bin)} arch=0x{machine:x}")
    print(f"bash: {bash_repo} install.sh sha256={digest(install_sh)}")
    print(f"evidence: {evidence}")
    print("release authority: NONE", flush=True)

    results = []
    with tempfile.TemporaryDirectory(prefix="idleleo-preview-") as tmp:
        for feature in selected:
            fid = feature["id"]
            fixture = ROOT / "features" / feature["fixture"]
            feature_evidence = evidence / fid
            feature_evidence.mkdir(parents=True, exist_ok=True)
            env = os.environ.copy()
            env["IDLELEO_PREVIEW_EVIDENCE"] = str(feature_evidence)
            started = time.monotonic()
            try:
                rc = subprocess.run(
                    [sys.executable, "-I", str(fixture), "--go-bin", str(go_bin),
                     "--bash-repo", str(bash_repo)],
                    cwd=tmp, timeout=FIXTURE_TIMEOUT, env=env,
                ).returncode
                timed_out = False
            except subprocess.TimeoutExpired:
                rc, timed_out = 124, True
            elapsed = round(time.monotonic() - started, 2)
            results.append({
                "id": fid,
                "fixture": feature["fixture"],
                "returncode": rc,
                "timed_out": timed_out,
                "elapsed_seconds": elapsed,
                "evidence_level": feature["evidence_level"],
                "status": "PASS" if rc == 0 else "FAIL",
            })
            print(f"{fid} {'PASS' if rc == 0 else 'FAIL'} ({elapsed}s) evidence={feature_evidence}", flush=True)

    report = {
        "banner": BANNER,
        "releaseAuthority": False,
        "channel": "preview",
        "generatedAt": stamp,
        "containerEvidence": args.container_evidence,
        "githubActions": in_ci,
        "githubSha": os.environ.get("GITHUB_SHA", ""),
        "goBin": str(go_bin),
        "goBinSha256": digest(go_bin),
        "bashRepo": str(bash_repo),
        "installShSha256": digest(install_sh),
        "releaseGateSha256": digest(gate_path),
        "featureLedgerSha256": ledger_sha,
        "releaseLedgerStatus": "28/28 PENDING_GO_IMPLEMENTATION",
        "features": results,
    }
    (evidence / "preview_qualification.json").write_text(json.dumps(report, indent=2) + "\n")

    # Re-check the release gate pin and the ledger invariants after running: a
    # fixture or a stray process must not be able to rewrite the release
    # decision mid-run. The ledger digest is compared to the value captured at
    # start so a mid-run rewrite is still caught without a data-file pin.
    try:
        check_gate_and_ledger()
        if digest(ledger_path) != ledger_sha:
            raise ValueError("feature_contracts.json changed during this preview run")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"PREVIEW RESULT: RED — release decision changed during this run: {exc}", file=sys.stderr)
        return 2

    failed = [r["id"] for r in results if r["returncode"] != 0]
    if failed:
        print(f"PREVIEW RESULT: RED ({len(failed)} failed: {','.join(failed)})")
        return 2
    print("PREVIEW FUNCTIONAL RESULT — release authority: NONE; feature_contracts.json unchanged (28 PENDING)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
