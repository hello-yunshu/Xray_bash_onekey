#!/usr/bin/env python3
"""Validate one feature-ledger transition.

This is a policy check, not a release gate. It answers a single question: may
the committed ledger move from --base to --head without weakening the release
decision?

Allowed transitions (nothing else):
    PENDING_GO_IMPLEMENTATION -> VERIFIED_GO_PARITY
    PENDING_GO_IMPLEMENTATION -> APPROVED_SAFE_DIVERGENCE

Reverse moves, PENDING -> BLOCKED, VERIFIED -> APPROVED, removed items, added
items, renamed ids and reordering are all rejected. A feature that leaves
PENDING must carry evidence: one repository-relative path (or a list of them),
each pointing at an existing, non-empty file.

Exit codes: 0 = transition allowed, 2 = policy violation, 3 = bad input.
"""
import argparse
import json
import sys
from pathlib import Path

PENDING = "PENDING_GO_IMPLEMENTATION"
VERIFIED = "VERIFIED_GO_PARITY"
APPROVED = "APPROVED_SAFE_DIVERGENCE"
ALLOWED_FROM_PENDING = {VERIFIED, APPROVED}


class Violation(Exception):
    pass


def load(path):
    data = json.loads(Path(path).read_text())
    feats = data.get("features")
    if not isinstance(feats, list) or not feats:
        raise ValueError(f"{path}: features must be a non-empty list")
    return feats


def evidence_paths(entry):
    value = entry.get("evidence")
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def check_evidence(entry, root):
    fid = entry["id"]
    paths = evidence_paths(entry)
    if not paths:
        raise Violation(f"{fid}: {entry['status']} requires an evidence path")
    for rel in paths:
        if not isinstance(rel, str) or not rel.strip():
            raise Violation(f"{fid}: evidence must be a non-empty repository-relative path")
        candidate = Path(rel)
        if candidate.is_absolute():
            raise Violation(f"{fid}: evidence must be repository-relative, got {rel}")
        resolved = (root / candidate).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            raise Violation(f"{fid}: evidence escapes the repository: {rel}")
        if not resolved.is_file():
            raise Violation(f"{fid}: evidence file does not exist: {rel}")
        if resolved.stat().st_size == 0:
            raise Violation(f"{fid}: evidence file is empty: {rel}")


def compare(base_feats, head_feats, root):
    base_ids = [f.get("id") for f in base_feats]
    head_ids = [f.get("id") for f in head_feats]
    if base_ids != head_ids:
        missing = [i for i in base_ids if i not in head_ids]
        added = [i for i in head_ids if i not in base_ids]
        if missing and added:
            raise Violation("ledger ids were renamed: removed=" + ",".join(str(i) for i in missing)
                            + " added=" + ",".join(str(i) for i in added))
        if missing:
            raise Violation("ledger items were removed: " + ",".join(str(i) for i in missing))
        if added:
            raise Violation("ledger items were added: " + ",".join(str(i) for i in added))
        raise Violation("ledger ids were reordered")

    before = {f.get("id"): f for f in base_feats}
    changed = []
    for head in head_feats:
        fid = head.get("id")
        old = before[fid].get("status")
        new = head.get("status")
        if new == old:
            continue
        if old == PENDING and new in ALLOWED_FROM_PENDING:
            check_evidence(head, root)
            changed.append((fid, old, new))
            continue
        raise Violation(f"{fid}: forbidden transition {old} -> {new}")
    return changed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, type=Path, help="baseline ledger")
    parser.add_argument("--head", type=Path, help="new ledger (default: cases/feature_contracts.json)")
    parser.add_argument("--root", type=Path, help="repository root used to resolve evidence paths")
    args = parser.parse_args()

    parity = Path(__file__).resolve().parents[1]
    root = (args.root or parity.parents[2]).resolve()
    head = args.head or parity / "cases/feature_contracts.json"

    try:
        base_feats = load(args.base)
        head_feats = load(head)
        changed = compare(base_feats, head_feats, root)
    except Violation as exc:
        print(f"LEDGER TRANSITION REJECTED: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"LEDGER TRANSITION ERROR: {exc}", file=sys.stderr)
        return 3

    if changed:
        for fid, old, new in changed:
            print(f"allowed: {fid} {old} -> {new}")
    else:
        print("allowed: no status change")
    print(f"ledger transition OK ({len(changed)} item(s) promoted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
