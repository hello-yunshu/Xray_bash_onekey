#!/usr/bin/env python3
"""Build the single OPS acceptance ledger from real run evidence.

The audit found three disagreeing summaries (matrix.json, acceptance.json and
report prose) that were edited by hand. This script makes one machine-readable
ledger the only source of truth and rewrites both summaries from it.

Inputs are evidence directories produced by the existing drivers:

  --matrix-evidence DIR   run_p2_matrix.sh output tree (dual-side ops)
  --ops-evidence DIR      run_ops_sweep.sh output tree (Go-side ops)

Rows are classified only from recorded verdicts/assertions. A row with no
evidence stays NOT_RUN; the denominator is never reduced.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

OPS_IDS = (
    ["OPS-%02d" % i for i in range(1, 17)]
    + ["OPS-17a", "OPS-17b", "OPS-17c"]
    + ["OPS-%02d" % i for i in range(18, 33)]
)
assert len(OPS_IDS) == 34, len(OPS_IDS)

ASSERT_ID = re.compile(r"\b(PPS-[0-9]{2}[a-c]?|OPS-[0-9]{2}[a-c]?)\b")

# Verdicts that assert the two sides are equivalent. Anything else that reports
# a difference is never silently accepted; DIFF/EXPECTED_DIFF only enter the
# ledger as APPROVED_DIFF when an out-of-band approval file names the row.
PASS_VERDICTS = {"PASS", "MATCH", "GOOD"}
FAIL_VERDICTS = {"FAIL", "MISMATCH", "GAP", "ERROR"}
DIFF_VERDICTS = {"EXPECTED_DIFF", "ALLOWED_DIFF", "DIFF"}
INCOMPLETE_VERDICTS = {"BLOCKED", "SKIP", "NOT_RUN"}

# A row counts as resolved for acceptance when the two sides were verified or
# when a human explicitly accepted the recorded difference/single-side evidence.
RESOLVED_STATUSES = {"DUAL_SIDE_VERIFIED", "APPROVED_DIFF", "APPROVED_SINGLE_SIDE"}

# A driver may record a known behavioural difference without writing ops.json.
# Those declarations are real evidence and must not disappear: they are treated
# exactly like an EXPECTED_DIFF verdict (approval required, otherwise FAIL).
DIFF_DECLARATION_FILES = (
    "shortid-difference.json",
    "cert-clear-difference.json",
    "log-source-difference.json",
    "metadata-difference.json",
    "difference.json",
    "diff.json",
)
DECLARED_DIFF_VERDICTS = DIFF_VERDICTS


class EvidenceError(Exception):
    """Raised when a declared evidence directory is missing or unreadable."""


def load_approvals(path):
    """Return {op_id: approval} from an explicit approval file.

    Approvals are deliberately external input. The ledger never infers that a
    difference is acceptable, and an approved difference is still reported as
    APPROVED_DIFF, never as verified equivalence.
    """
    if not path:
        return {}
    data = read_json(path)
    if not isinstance(data, dict):
        raise EvidenceError("approval file %s is missing or not a JSON object" % path)
    out = {}
    for item in data.get("approved") or []:
        if not isinstance(item, dict) or not item.get("id"):
            raise EvidenceError("approval file %s has an entry without an id" % path)
        if not item.get("approvedBy") or not item.get("reason"):
            raise EvidenceError("approval for %s needs approvedBy and reason" % item["id"])
        if not str(item.get("scope") or "").strip():
            raise EvidenceError("approval for %s has no scope" % item["id"])
        out[item["id"]] = item
    return out


def file_sha256(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


PROVENANCE_FIELDS = (
    "productCodeSha", "binarySha256", "bashScriptSha256",
    "driverSha", "runId", "layer", "image", "platform",
    "startedAt", "finishedAt",
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
IMAGE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _git_fixture_fix_info(commit):
    """Return (changed paths, commit time, is-ancestor) for a test-only fix."""
    root = git_toplevel()
    if not root or not GIT_SHA_RE.fullmatch(str(commit or "")):
        return None
    try:
        paths = subprocess.check_output(
            ["git", "-C", root, "diff-tree", "--no-commit-id", "--name-only", "-r", commit],
            text=True, stderr=subprocess.DEVNULL).splitlines()
        driver = subprocess.check_output(
            ["git", "-C", root, "show", "%s:tests/e2e-diff/run_p2_matrix.sh" % commit],
            stderr=subprocess.DEVNULL)
        committed_at = subprocess.check_output(
            ["git", "-C", root, "show", "-s", "--format=%cI", commit],
            text=True, stderr=subprocess.DEVNULL).strip()
        ancestor = subprocess.run(
            ["git", "-C", root, "merge-base", "--is-ancestor", commit, "HEAD"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except (OSError, subprocess.CalledProcessError):
        return None
    when = _timestamp(committed_at)
    if not when or not paths:
        return None
    return set(paths), when, ancestor, hashlib.sha256(driver).hexdigest()


def _verified_fixture_fix(candidate, prior, code_sha, fixed_by, fixed_by_kind,
                          op_id=None, reuse_impact=None):
    """Allow a same-product retest only for a committed, isolated driver fix.

    Product artifacts must remain byte-identical and the driver's digest must
    change. The commit itself must be an ancestor of HEAD and may modify only
    the audited OPS runner; no product source or acceptance rule can be used as
    a test-fixture supersession.
    """
    if fixed_by_kind != "test-fixture":
        return False
    details = _git_fixture_fix_info(fixed_by)
    if details is None:
        return False
    paths, committed_at, ancestor, committed_driver_sha = details
    candidate_sha = str(candidate.get("productCodeSha") or "")
    if not ancestor or paths != {"tests/e2e-diff/run_p2_matrix.sh"}:
        return False
    if candidate.get("driverSha") != committed_driver_sha:
        return False
    candidate_is_current_or_reusable = candidate_sha == code_sha
    if not candidate_is_current_or_reusable and op_id:
        _, reuse = expected_evidence_sha(candidate, code_sha, op_id, reuse_impact)
        candidate_is_current_or_reusable = reuse is not None
    if not candidate_is_current_or_reusable or candidate_sha != str(prior.get("productCodeSha") or ""):
        return False
    if candidate.get("binarySha256") != prior.get("binarySha256"):
        return False
    if candidate.get("bashScriptSha256") != prior.get("bashScriptSha256"):
        return False
    if not candidate.get("driverSha") or candidate.get("driverSha") == prior.get("driverSha"):
        return False
    started = _timestamp(candidate.get("startedAt"))
    return started is not None and committed_at <= started


def provenance_problems_run(run, code_sha, dirname, evidence_root=None):
    """Return why a run block cannot bind evidence to the frozen candidate.

    Exit codes and verdicts are not provenance. Without the product commit, the
    two build artefacts, the driver commit and the run identity there is no way
    to tell current evidence from a stale run of an older candidate.
    """
    if not isinstance(run, dict):
        return ["no run provenance block; this evidence is not bound to a candidate build"]
    problems = []
    for key in PROVENANCE_FIELDS:
        if not str(run.get(key) or "").strip():
            problems.append("run provenance is missing %s" % key)
    product = str(run.get("productCodeSha") or "")
    if not GIT_SHA_RE.fullmatch(product):
        problems.append("run provenance productCodeSha is not a full Git object id")
    if product and code_sha and product != code_sha:
        problems.append("evidence was produced for product %s, not the frozen %s"
                        % (product[:12], code_sha[:12]))
    for key in ("binarySha256", "bashScriptSha256", "driverSha"):
        if not SHA256_RE.fullmatch(str(run.get(key) or "")):
            problems.append("run provenance %s is not a SHA-256 digest" % key)
    if not IMAGE_RE.fullmatch(str(run.get("image") or "")):
        problems.append("run provenance image is missing or is not an immutable image id")
    if not re.fullmatch(r"linux/(?:amd64|arm64|386|arm/v[0-9]+)", str(run.get("platform") or "")):
        problems.append("run provenance platform is missing or unsupported")
    started = _timestamp(run.get("startedAt"))
    finished = _timestamp(run.get("finishedAt"))
    if started is None:
        problems.append("run provenance startedAt is not a timezone-aware ISO timestamp")
    if finished is None:
        problems.append("run provenance finishedAt is not a timezone-aware ISO timestamp")
    elif started is not None and finished < started:
        problems.append("run provenance finishedAt precedes startedAt")
    run_id = str(run.get("runId") or "")
    if run_id and dirname and run_id != dirname:
        problems.append("run provenance runId %r does not match evidence directory %r"
                        % (run_id, dirname))
    manifest_name = str(run.get("manifestPath") or "").strip()
    manifest_sha = str(run.get("manifestSha256") or "")
    if not manifest_name or not SHA256_RE.fullmatch(manifest_sha) or not evidence_root:
        problems.append("run provenance has no verifiable candidate build manifest")
    else:
        root = os.path.realpath(evidence_root)
        manifest_path = os.path.realpath(os.path.join(root, manifest_name))
        if not inside_repo(manifest_path, root):
            problems.append("candidate build manifest escapes the evidence directory")
        elif file_sha256(manifest_path) != manifest_sha:
            problems.append("candidate build manifest is missing or its SHA-256 does not match")
        else:
            manifest = read_json(manifest_path)
            if not isinstance(manifest, dict):
                problems.append("candidate build manifest is unreadable")
            else:
                for key in ("productCodeSha", "binarySha256", "bashScriptSha256", "driverSha", "image", "platform"):
                    if manifest.get(key) != run.get(key):
                        problems.append("candidate build manifest %s does not match the run" % key)
                artifacts = manifest.get("artifacts")
                artifact_keys = {"binary": "binarySha256", "bashScript": "bashScriptSha256", "driver": "driverSha"}
                if not isinstance(artifacts, dict):
                    problems.append("candidate build manifest has no artifact paths")
                else:
                    for artifact, digest_key in artifact_keys.items():
                        relpath = str(artifacts.get(artifact) or "")
                        path = os.path.realpath(os.path.join(root, relpath)) if relpath else ""
                        if not path or not inside_repo(path, root):
                            problems.append("candidate build manifest %s path escapes the evidence directory" % artifact)
                        elif file_sha256(path) != run.get(digest_key):
                            problems.append("candidate build manifest %s digest does not match the recorded build" % artifact)
                dependencies = manifest.get("dependencies")
                if not isinstance(dependencies, list) or not dependencies:
                    problems.append("candidate build manifest has no driver/dependency list")
                else:
                    for dependency in dependencies:
                        if not isinstance(dependency, dict):
                            problems.append("candidate build manifest contains an invalid dependency record")
                            continue
                        relpath = str(dependency.get("path") or "")
                        digest = str(dependency.get("sha256") or "")
                        path = os.path.realpath(os.path.join(root, relpath)) if relpath else ""
                        if not path or not inside_repo(path, root):
                            problems.append("candidate build manifest dependency path escapes the evidence directory")
                        elif not SHA256_RE.fullmatch(digest) or file_sha256(path) != digest:
                            problems.append("candidate build manifest dependency digest does not match")
    return problems


def provenance_problems(data, code_sha, dirname, evidence_root=None):
    return provenance_problems_run(data.get("run"), code_sha, dirname, evidence_root)


def load_reuse_impact(path, code_sha, require_target=True):
    """Load a narrowly scoped, git-verifiable evidence reuse decision."""
    if not path:
        return None
    data = read_json(path)
    if not isinstance(data, dict) or data.get("schemaVersion") != 1:
        raise EvidenceError("reuse impact must be a schemaVersion 1 JSON object")
    base, target = str(data.get("baseCodeSha") or ""), str(data.get("targetCodeSha") or "")
    if not GIT_SHA_RE.fullmatch(base) or not GIT_SHA_RE.fullmatch(target):
        raise EvidenceError("reuse impact requires full base/target Git SHAs")
    if require_target and target != code_sha:
        raise EvidenceError("reuse impact targetCodeSha does not match the candidate")
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    for sha in (base, target):
        if subprocess.run(["git", "-C", repo, "cat-file", "-e", sha + "^{commit}"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            raise EvidenceError("reuse impact references a missing Git commit")
    if subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor", base, target],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        raise EvidenceError("reuse impact baseCodeSha is not an ancestor of targetCodeSha")
    paths = data.get("changedFiles")
    if not isinstance(paths, list) or not paths or any(not isinstance(p, str) for p in paths):
        raise EvidenceError("reuse impact must list exact changedFiles")
    actual_paths = subprocess.check_output(
        ["git", "-C", repo, "diff", "--name-only", base + ".." + target], text=True
    ).splitlines()
    if sorted(set(paths)) != actual_paths:
        raise EvidenceError("reuse impact changedFiles do not match the committed diff")
    diff = subprocess.Popen(["git", "-C", repo, "diff", "--binary", base + ".." + target],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    actual_diff_hash = hashlib.sha256()
    assert diff.stdout is not None
    for chunk in iter(lambda: diff.stdout.read(1024 * 1024), b""):
        actual_diff_hash.update(chunk)
    if diff.wait() != 0:
        raise EvidenceError("reuse impact diff could not be read")
    if actual_diff_hash.hexdigest() != data.get("diffSha256"):
        raise EvidenceError("reuse impact diffSha256 does not match the committed diff")
    reusable, affected = data.get("reusableOps"), data.get("affectedOps")
    if not isinstance(reusable, list) or not isinstance(affected, list):
        raise EvidenceError("reuse impact must list reusableOps and affectedOps")
    reusable_set, affected_set = set(reusable), set(affected)
    if (reusable_set & affected_set or reusable_set | affected_set != set(OPS_IDS)
            or any(op not in OPS_IDS for op in reusable_set | affected_set)):
        raise EvidenceError("reuse impact must partition all 34 OPS IDs without overlap")
    if not str(data.get("rationale") or "").strip():
        raise EvidenceError("reuse impact requires a concrete rationale")
    return {"baseCodeSha": base, "targetCodeSha": target,
            "reusableOps": reusable_set, "affectedOps": affected_set,
            "diffSha256": data["diffSha256"], "changedFiles": actual_paths,
            "evidence": repo_path(path)}


def expected_evidence_sha(run, code_sha, op_id, reuse_impact):
    product = str((run or {}).get("productCodeSha") or "")
    if product == code_sha:
        return code_sha, None
    if isinstance(reuse_impact, list):
        current = product
        chain = []
        for impact in reuse_impact:
            if impact["baseCodeSha"] != current:
                continue
            if op_id not in impact["reusableOps"]:
                return code_sha, None
            chain.append({"impactEvidence": impact["evidence"],
                          "changedFiles": impact["changedFiles"],
                          "diffSha256": impact["diffSha256"],
                          "sourceCodeSha": current,
                          "targetCodeSha": impact["targetCodeSha"]})
            current = impact["targetCodeSha"]
            if current == code_sha:
                reuse = {"sourceCodeSha": product, "targetCodeSha": code_sha}
                if len(chain) == 1:
                    reuse.update(chain[0])
                else:
                    reuse["impactChain"] = chain
                return product, reuse
        return code_sha, None
    if (reuse_impact and product == reuse_impact["baseCodeSha"]
            and op_id in reuse_impact["reusableOps"]):
        return product, {"sourceCodeSha": product, "targetCodeSha": code_sha,
                         "impactEvidence": reuse_impact["evidence"],
                         "changedFiles": reuse_impact["changedFiles"],
                         "diffSha256": reuse_impact["diffSha256"]}
    return code_sha, None


def _positive(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _true(value):
    return value is True


def _zero(value):
    return isinstance(value, int) and not isinstance(value, bool) and value == 0


def _nonempty(value):
    return bool(value)


def _sni_probe(value):
    if not isinstance(value, dict) or value.get("knownSniOk") is not True:
        return False
    if value.get("knownRc") != 0 or not isinstance(value.get("unknownRc"), int):
        return False
    policy = str(value.get("unknownSniPolicy") or "").strip().lower()
    if policy in ("isolate", "reject", "ssl_reject_handshake"):
        return value["unknownRc"] != 0
    if policy in ("normal", "decoy", "route_to_decoy"):
        return value["unknownRc"] == 0
    return False


# Facts the independent audit named explicitly. A PASS with both exit codes is
# only a necessary condition; the row must also carry the observable business
# result for each side. Rows without a contract still need provenance.
BUSINESS_FACTS = {
    "OPS-01": [("addedClients", _positive), ("removedClients", _positive), ("clientConnected", _true)],
    "OPS-02": [("addedClients", _positive), ("removedClients", _positive), ("clientConnected", _true)],
    "OPS-04": [("portListening", _true), ("clientConnected", _true), ("shareInfo", _nonempty)],
    "OPS-08": [("sniProbe", _sni_probe)],
    "OPS-10": [("serverNames", _nonempty)],
    "OPS-17a": [
        ("updateApplied", _true), ("versionChanged", _true),
        ("assetShaMatched", _true), ("servicesHealthy", _true),
        ("postUpdateClientOk", _true), ("manualOnly", _true),
    ],
    "OPS-20": [("trafficBytes", _positive)],
    "OPS-25": [
        ("createRc", _zero), ("verifyRc", _zero), ("restoreRc", _zero),
        ("archiveModeAndDigest", _true), ("managedFilesRestored", _true),
        ("permissionsRestored", _true), ("servicesAndValidators", _true),
        ("canaryRestored", _true), ("realClient", _true),
    ],
    "OPS-26": [
        ("createRc", _zero), ("verifyRc", _zero), ("restoreRc", _zero),
        ("archiveModeAndDigest", _true), ("managedFilesRestored", _true),
        ("permissionsRestored", _true), ("servicesAndValidators", _true),
        ("canaryRestored", _true), ("realClient", _true),
        ("restoreVerified", _true), ("checksumMatch", _true),
    ],
    "OPS-32": [("faultRemoved", _true), ("recovered", _true)],
}


def business_problems(op_id, details):
    facts = BUSINESS_FACTS.get(op_id)
    if not facts:
        return []
    problems = []
    for side in ("bash", "go"):
        block = details.get(side) if isinstance(details, dict) else None
        if not isinstance(block, dict):
            problems.append("%s side has no business evidence block" % side)
            continue
        for key, predicate in facts:
            if not predicate(block.get(key)):
                problems.append("%s side lacks the required business fact %s" % (side, key))
    return problems


def expected_exit_problems(data, evidence_path):
    """Validate a declared non-zero command result against captured outputs.

    Interactive commands such as Bash's live log tail can be intentionally
    stopped by `timeout` (124). The exception is narrow: the producer must
    declare the exact summary rc and provide per-command rc files plus output
    markers stored under that OPS evidence directory.
    """
    ops_rc = data.get("opsRc") if isinstance(data.get("opsRc"), dict) else {}
    expected = data.get("expectedRc") if isinstance(data.get("expectedRc"), dict) else {}
    proofs = data.get("expectedRcEvidence") if isinstance(data.get("expectedRcEvidence"), dict) else {}
    problems = []
    for side in ("bash", "go"):
        actual = ops_rc.get(side)
        if actual is None and side not in expected and side not in proofs:
            continue
        if side not in expected or expected.get(side) != actual:
            problems.append("non-zero %s rc %r has no matching expectedRc declaration" % (side, actual))
            continue
        proof = proofs.get(side)
        if not isinstance(proof, dict):
            problems.append("non-zero %s rc has no captured-output proof" % side)
            continue
        rc_files = proof.get("rcFiles")
        marker_files = proof.get("markerFiles")
        if not isinstance(rc_files, list) or not rc_files:
            problems.append("non-zero %s rc proof has no command rc files" % side)
        else:
            for item in rc_files:
                if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                    problems.append("non-zero %s rc proof has a malformed rc file entry" % side)
                    continue
                path = os.path.realpath(os.path.join(os.path.dirname(evidence_path), item["path"]))
                base = os.path.realpath(os.path.dirname(evidence_path))
                if not inside_repo(path, base) or not os.path.isfile(path):
                    problems.append("non-zero %s rc proof file is missing or escapes OPS evidence" % side)
                    continue
                try:
                    with open(path, encoding="utf-8") as fh:
                        observed = int(fh.read().strip())
                except (OSError, ValueError):
                    observed = None
                if observed != item.get("expected"):
                    problems.append("non-zero %s rc proof %s does not match its declared value" % (side, item["path"]))
        if not isinstance(marker_files, list) or not marker_files:
            problems.append("non-zero %s rc proof has no output marker checks" % side)
        else:
            for item in marker_files:
                if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                    problems.append("non-zero %s rc proof has a malformed marker file entry" % side)
                    continue
                path = os.path.realpath(os.path.join(os.path.dirname(evidence_path), item["path"]))
                base = os.path.realpath(os.path.dirname(evidence_path))
                if not inside_repo(path, base) or not os.path.isfile(path):
                    problems.append("non-zero %s marker file is missing or escapes OPS evidence" % side)
                    continue
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        output = fh.read()
                except OSError:
                    output = ""
                markers = item.get("contains")
                if not isinstance(markers, list) or not markers or any(str(marker) not in output for marker in markers):
                    problems.append("non-zero %s output %s lacks its declared behavior markers" % (side, item["path"]))
    return problems


def approval_problems(approval, evidence_path, op_id):
    """Validate that an approval names this row, this difference and a deadline."""
    problems = []
    if not approval.get("approvedBy") or not approval.get("reason"):
        problems.append("approval for %s needs approvedBy and reason" % op_id)
    scope = str(approval.get("scope") or "").strip()
    if not scope:
        problems.append("approval for %s has no scope" % op_id)
    if str(approval.get("approvedBy") or "").lower() == "user":
        provenance = approval.get("provenance")
        if (not isinstance(provenance, dict)
                or not str(provenance.get("sourcePath") or "").strip()
                or not str(provenance.get("recordId") or "").strip()
                or not SHA256_RE.fullmatch(str(provenance.get("contentSha256") or ""))):
            problems.append("a user approval needs a verifiable source path, record id, and source content digest")
    if approval.get("opId") and approval["opId"] != op_id:
        problems.append("approval opId %r does not match %s" % (approval["opId"], op_id))
    expires = approval.get("expiresAt")
    if expires:
        try:
            expiry = datetime.date.fromisoformat(str(expires)[:10])
        except ValueError:
            problems.append("approval expiresAt %r is not an ISO date" % expires)
        else:
            today = datetime.datetime.now(datetime.timezone.utc).date()
            if expiry < today:
                problems.append("approval expired on %s" % expires)
    fingerprint = approval.get("fingerprint")
    if not fingerprint:
        problems.append("approval for %s has no evidence fingerprint; it cannot bind a specific difference" % op_id)
    else:
        actual = file_sha256(evidence_path)
        if actual != fingerprint:
            problems.append("approval fingerprint does not match the cited evidence for %s" % op_id)
    return problems


def single_side_approval(approvals, op_id, evidence_path):
    """Return the approval that makes one-sided evidence acceptable.

    The ledger never accepts single-side evidence on its own. Such an approval
    must also carry a scope, so the report can say which side was verified and
    what is still unverified instead of implying dual-side equivalence.
    """
    approval = approvals[op_id]
    if not str(approval.get("scope") or "").strip():
        raise EvidenceError(
            "approval for %s would accept single-side evidence but has no scope (%s)"
            % (op_id, evidence_path))
    return approval


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def git_toplevel():
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return out or None


def inside_repo(path, root):
    if not root:
        return False
    try:
        rel = os.path.relpath(os.path.abspath(path), root)
    except ValueError:
        return False
    return not (rel == ".." or rel.startswith(".." + os.sep) or os.path.isabs(rel))


def approval_applies(approval, evidence_path):
    """Return whether this approval was written for this exact evidence file.

    An approval names one difference in one file. The same op id can have both a
    dual-side ops.json and a Go-only sweep line, so a global per-id binding would
    let one file's approval be judged against the other file's fingerprint and
    poison an unrelated row. When the approval cites fingerprintOf we compare the
    resolved paths; legacy approvals without it keep the fingerprint-only check.
    """
    target = str(approval.get("fingerprintOf") or "").strip()
    if not target:
        return True
    root = git_toplevel() or os.getcwd()

    def resolve(path):
        if not os.path.isabs(path):
            path = os.path.join(root, path)
        return os.path.realpath(path)

    return resolve(target) == resolve(evidence_path)


def write_json_atomic(path, data):
    """Write JSON with a same-directory temp file and an atomic rename.

    A failed or interrupted run must never leave a partially written acceptance
    summary behind; either the previous file survives or the complete new one
    replaces it.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".ledger-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def repo_path(path):
    """Record paths relative to the repo so the ledger carries no host path."""
    if not path:
        return path
    rel = os.path.relpath(os.path.abspath(path))
    return path if rel.startswith("..") or os.path.isabs(rel) else rel


def read_difference_declaration(dirpath):
    """Return (path, data) for a driver-recorded difference, else None."""
    for fname in DIFF_DECLARATION_FILES:
        path = os.path.join(dirpath, fname)
        data = read_json(path)
        if not isinstance(data, dict):
            continue
        verdict = str(data.get("result") or data.get("verdict") or "").upper().replace("-", "_")
        if verdict in DECLARED_DIFF_VERDICTS:
            return path, data
    return None


def matrix_results(root, approvals, code_sha="", reuse_impact=None):
    """Read p2/OPS-*/ops.json verdicts from a matrix run.

    Every declared OPS directory produces a row. A missing/unreadable ops.json,
    an id that disagrees with the directory, or a verdict that cannot be
    classified becomes BLOCKED instead of disappearing. A failure or an
    unapproved difference always wins over a pass.

    A verdict is never enough on its own: the row must also prove which commit
    and artefacts produced it, and (for audited rows) carry the observable
    business fact for both sides.
    """
    out = {}
    if not root:
        return out
    run_id = os.path.basename(os.path.normpath(root))
    p2 = os.path.join(root, "p2")
    if not os.path.isdir(p2):
        raise EvidenceError("matrix evidence %s has no p2 directory" % root)
    for name in sorted(os.listdir(p2)):
        if not name.startswith("OPS-"):
            continue
        evidence_path = os.path.join(p2, name, "ops.json")
        data = read_json(evidence_path)
        if not isinstance(data, dict):
            declaration = read_difference_declaration(os.path.join(p2, name))
            if declaration is not None:
                path, data = declaration
                verdict = str(data.get("result") or data.get("verdict") or "").upper().replace("-", "_")
                reasons = [str(r) for r in (data.get("reasons") or [])]
                run_block = data.get("run") if isinstance(data.get("run"), dict) else {}
                expected_sha, reuse = expected_evidence_sha(run_block, code_sha, name, reuse_impact)
                prov = provenance_problems(data, expected_sha, run_id, p2)
                base = {
                    "verdict": verdict, "reasons": reasons,
                    "evidence": repo_path(path), "runId": run_id,
                    "layer": "L0-L4 driver evidence",
                }
                if prov:
                    base.update(status="BLOCKED", reasons=reasons + prov)
                elif name in approvals and approval_applies(approvals[name], path):
                    problems = approval_problems(approvals[name], path, name)
                    if problems:
                        base.update(status="FAIL", reasons=reasons + problems)
                    else:
                        base.update(status="APPROVED_DIFF", approval=approvals[name])
                else:
                    base.update(status="FAIL", reasons=reasons + [
                        "%s declares a difference but no external approval names %s" % (os.path.basename(path), name)])
                if reuse and not prov:
                    base["evidenceReuse"] = reuse
                out[name] = base
                continue
            out[name] = {
                "status": "BLOCKED",
                "verdict": None,
                "reasons": ["ops.json is missing or unreadable; this row has no acceptable evidence"],
                "evidence": repo_path(evidence_path),
                "runId": run_id,
                "layer": "L0-L4 driver evidence",
            }
            continue
        op_id = str(data.get("id") or name)
        verdict = str(data.get("verdict") or "").upper().replace("-", "_")
        reasons = [str(r) for r in (data.get("reasons") or [])]
        bash_rc = (data.get("opsRc") or {}).get("bash")
        go_rc = (data.get("opsRc") or {}).get("go")
        run_block = data.get("run") if isinstance(data.get("run"), dict) else {}
        base = {
            "verdict": verdict or None,
            "bashExit": bash_rc,
            "goExit": go_rc,
            "expectedRc": data.get("expectedRc"),
            "expectedRcEvidence": data.get("expectedRcEvidence"),
            "reasons": reasons,
            "evidence": repo_path(evidence_path),
            "runId": run_id,
            "layer": "L0-L4 driver evidence",
            "productCodeSha": run_block.get("productCodeSha"),
            "binarySha256": run_block.get("binarySha256"),
            "bashScriptSha256": run_block.get("bashScriptSha256"),
            "driverSha": run_block.get("driverSha"),
            "supersedes": run_block.get("supersedes"),
            "fixedBy": run_block.get("fixedBy"),
            "fixedByKind": run_block.get("fixedByKind"),
            "startedAt": run_block.get("startedAt"),
            "finishedAt": run_block.get("finishedAt"),
        }
        if op_id != name:
            base.update(status="BLOCKED",
                        reasons=reasons + ["ops.json id %r does not match its directory %r" % (op_id, name)])
            out[name] = base
            continue
        expected_sha, reuse = expected_evidence_sha(run_block, code_sha, op_id, reuse_impact)
        prov = provenance_problems(data, expected_sha, run_id, p2)
        if prov:
            status = "BLOCKED"
            base["reasons"] = reasons + prov
        elif verdict in FAIL_VERDICTS:
            status = "FAIL"
        elif verdict in DIFF_VERDICTS:
            if op_id in approvals and approval_applies(approvals[op_id], evidence_path):
                problems = approval_problems(approvals[op_id], evidence_path, op_id)
                if problems:
                    status = "FAIL"
                    base["reasons"] = reasons + problems
                else:
                    status = "APPROVED_DIFF"
                    base["approval"] = approvals[op_id]
            else:
                status = "FAIL"
                base["reasons"] = reasons + ["an expected/allowed difference was declared but no external approval names %s" % op_id]
        elif verdict in PASS_VERDICTS:
            # A non-zero result is accepted only when the producer declares the
            # exact expected rc and provides captured command/output proof.
            bad_rc = [label for label, rc in (("bash", bash_rc), ("go", go_rc)) if rc is not None and rc != 0]
            rc_problems = expected_exit_problems(data, evidence_path) if bad_rc else []
            if bad_rc and rc_problems:
                status = "FAIL"
                base["reasons"] = reasons + rc_problems
            elif bash_rc is None or go_rc is None:
                status = "BLOCKED"
                base["reasons"] = reasons + ["dual-side PASS is missing an exit code; evidence is incomplete"]
            else:
                facts = business_problems(op_id, data.get("details"))
                if facts:
                    status = "BLOCKED"
                    base["reasons"] = reasons + facts
                else:
                    status = "DUAL_SIDE_VERIFIED"
        elif verdict == "BASH_ONLY":
            if op_id in approvals and approval_applies(approvals[op_id], evidence_path):
                problems = approval_problems(approvals[op_id], evidence_path, op_id)
                if problems:
                    status = "FAIL"
                    base["reasons"] = reasons + problems
                else:
                    status = "APPROVED_SINGLE_SIDE"
                    base["approval"] = approvals[op_id]
            else:
                status = "BASH_ONLY"
        elif verdict in INCOMPLETE_VERDICTS:
            status = "BLOCKED"
        else:
            status = "BLOCKED"
            base["reasons"] = reasons + ["unrecognised or missing verdict %r; evidence is not acceptable" % verdict]
        if reuse and not prov:
            base["evidenceReuse"] = reuse
        base["status"] = status
        out[op_id] = base
    return out


def sweep_results(root, approvals=None, code_sha=""):
    """Parse assertions.txt from an ops sweep: an ID passes with no FAIL.

    A declared sweep without a readable assertions.txt, with malformed lines, or
    with no OPS assertion at all is rejected instead of silently contributing an
    empty (and therefore green-looking) result. A clean Go-only row still needs
    an explicit scoped approval before it counts as resolved.

    The sweep script never records the product exit code. The ledger keeps that
    unknown (None) instead of inventing a zero; only the approval can resolve a
    one-sided row, and it must be bound to this file.
    """
    approvals = approvals or {}
    out = {}
    if not root:
        return out
    run_id = os.path.basename(os.path.normpath(root))
    prov = provenance_problems_run(read_json(os.path.join(root, "run.json")), code_sha, run_id, root)
    path = os.path.join(root, "assertions.txt")
    if not os.path.isfile(path):
        raise EvidenceError("ops evidence %s has no assertions.txt" % root)
    try:
        lines = open(path, "r", encoding="utf-8").read().splitlines()
    except OSError as exc:
        raise EvidenceError("cannot read %s: %s" % (path, exc))
    per_id = {}
    for lineno, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        status, sep, text = line.partition("\t")
        if not sep or status not in ("PASS", "FAIL"):
            raise EvidenceError("%s:%d is not a PASS/FAIL assertion line" % (path, lineno))
        for match in ASSERT_ID.findall(text):
            if match.startswith("PPS-"):
                continue
            op_id = match
            if op_id.endswith(("a", "b", "c")) and op_id not in OPS_IDS:
                op_id = op_id[:-1]
            if op_id not in OPS_IDS:
                continue
            entry = per_id.setdefault(op_id, {"pass": 0, "fail": 0, "failText": []})
            if status == "PASS":
                entry["pass"] += 1
            else:
                entry["fail"] += 1
                entry["failText"].append(text)
    if not per_id:
        raise EvidenceError("%s contains no OPS assertion; this is not usable evidence" % path)
    command_path = os.path.join(root, "commands.jsonl")
    command_results = {}
    if os.path.isfile(command_path):
        try:
            with open(command_path, "r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    try:
                        item = json.loads(line)
                    except ValueError as exc:
                        raise EvidenceError("%s:%d is invalid JSON: %s" % (command_path, lineno, exc))
                    if (not isinstance(item, dict) or item.get("id") not in OPS_IDS
                            or not isinstance(item.get("actualRc"), int)
                            or isinstance(item.get("actualRc"), bool)
                            or not isinstance(item.get("expectedRc"), int)
                            or isinstance(item.get("expectedRc"), bool)
                            or not isinstance(item.get("argv"), list) or not item["argv"]):
                        raise EvidenceError("%s:%d is missing command id, actual/expected rc, or argv" % (command_path, lineno))
                    command_results.setdefault(item["id"], []).append(item)
        except OSError as exc:
            raise EvidenceError("cannot read %s: %s" % (command_path, exc))
    for op_id, entry in per_id.items():
        if entry["pass"] == 0 and entry["fail"] == 0:
            continue
        commands = command_results.get(op_id, [])
        rc_problems = ["command output is missing actual rc and expectedRc records"] if not commands else []
        rc_problems.extend("actual rc %s differs from expected rc %s" % (c["actualRc"], c["expectedRc"])
                           for c in commands if c["actualRc"] != c["expectedRc"])
        if commands and not any(c["actualRc"] == 0 for c in commands):
            rc_problems.append("recorded commands only refused; no successful product operation was observed")
        failed = entry["fail"] > 0 or any(c["actualRc"] != c["expectedRc"] for c in commands)
        incomplete = bool(rc_problems)
        row = {
            "status": "FAIL" if failed else ("BLOCKED" if incomplete else "GO_ONLY"),
            "verdict": "FAIL" if failed else ("BLOCKED" if incomplete else "PASS"),
            "goExit": commands[-1]["actualRc"] if commands else None,
            "expectedRc": commands[-1]["expectedRc"] if commands else None,
            "goExitRecorded": bool(commands),
            "commandResults": commands,
            "reasons": entry["failText"] + rc_problems,
            "assertions": entry["pass"] + entry["fail"],
            "evidence": repo_path(path),
            "runId": run_id,
            "layer": "L0-L2 Go CLI evidence",
        }
        if prov:
            row["status"] = "BLOCKED"
            row["reasons"] = entry["failText"] + rc_problems + prov
        elif row["status"] == "GO_ONLY" and op_id in approvals and approval_applies(approvals[op_id], path):
            problems = approval_problems(approvals[op_id], path, op_id)
            if problems:
                row["status"] = "FAIL"
                row["reasons"] = entry["failText"] + problems
            else:
                row["status"] = "APPROVED_SINGLE_SIDE"
                row["approval"] = approvals[op_id]
        out[op_id] = row
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix-evidence", action="append", default=[],
                    help="run_p2_matrix.sh output tree (repeatable; later runs fill gaps)")
    ap.add_argument("--ops-evidence", action="append", default=[],
                    help="run_ops_sweep.sh / run_ops_realroot.sh output tree (repeatable)")
    ap.add_argument("--code-sha", default="")
    ap.add_argument("--approved-diffs", default="",
                    help="explicit approval JSON for declared differences and single-side rows; "
                         "without it both remain FAIL/single-side")
    ap.add_argument("--reuse-impact", action="append", default=[],
                    help="git-verified impact map; repeat in ancestor-to-candidate order to "
                         "prove an uninterrupted evidence reuse chain")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="exit 0 even when rows are not dual-side verified (never for final acceptance)")
    ap.add_argument("--out", default="tests/e2e-diff/ledger.json")
    ap.add_argument("--matrix-json", default="tests/e2e-diff/matrix.json")
    ap.add_argument("--acceptance-json", default="docs/go-evolution/hardening/acceptance.json")
    ap.add_argument("--allow-repo-write", action="store_true",
                    help="allow writing the tracked ledger/matrix/acceptance artifacts; "
                         "tests and ad-hoc runs must keep every output in a temp directory")
    args = ap.parse_args()
    sha = args.code_sha or os.popen("git rev-parse HEAD").read().strip()

    try:
        approvals = load_approvals(args.approved_diffs)
        reuse_impact = None
        if args.reuse_impact:
            reuse_impact = [load_reuse_impact(path, sha, require_target=(i == len(args.reuse_impact) - 1))
                            for i, path in enumerate(args.reuse_impact)]
            if any(reuse_impact[i]["targetCodeSha"] != reuse_impact[i + 1]["baseCodeSha"]
                   for i in range(len(reuse_impact) - 1)):
                raise EvidenceError("reuse impact maps must form a contiguous ancestor-to-candidate chain")
        matrix_runs = [matrix_results(root, approvals, sha, reuse_impact) for root in args.matrix_evidence]
        sweep_runs = [sweep_results(root, approvals, sha) for root in args.ops_evidence]
    except EvidenceError as exc:
        print("ledger error: %s" % exc, file=sys.stderr)
        return 2

    # Strongest evidence per row wins: any failure, then a declared-and-approved
    # difference, then dual verification, then single-side evidence. Nothing is
    # discarded: a row with only weak evidence keeps that weak status.
    rank = {
        "NOT_RUN": 0,
        "BLOCKED": 1,
        "BASH_ONLY": 2,
        "GO_ONLY": 3,
        "APPROVED_SINGLE_SIDE": 4,
        "DUAL_SIDE_VERIFIED": 5,
        "APPROVED_DIFF": 6,
        "FAIL": 7,
    }
    chosen = {}
    history = {}
    for record in matrix_runs + sweep_runs:
        for op_id, entry in record.items():
            history.setdefault(op_id, []).append(entry)
            incoming_current = entry.get("productCodeSha") == sha
            selected_current = (chosen.get(op_id) or {}).get("productCodeSha") == sha
            if (op_id not in chosen or rank[entry["status"]] > rank[chosen[op_id]["status"]]
                    or (rank[entry["status"]] == rank[chosen[op_id]["status"]]
                        and incoming_current and not selected_current)):
                chosen[op_id] = entry

    if reuse_impact:
        for op_id in reuse_impact[-1]["affectedOps"]:
            fresh = [entry for entry in history.get(op_id, [])
                     if entry.get("productCodeSha") == sha]
            if not fresh:
                chosen[op_id] = {
                    "status": "BLOCKED", "verdict": None,
                    "reasons": ["impact marks this row affected; no resolved evidence exists at the target candidate SHA"],
                    "evidence": None, "layer": None,
                }

    # A failure stays a failure unless a later run of the same frozen candidate
    # explicitly names the failed run it supersedes, states the fix commit and
    # carries verified evidence. Silently dropping a red run is impossible.
    for op_id, entries in history.items():
        current = chosen.get(op_id)
        if not current or current["status"] != "FAIL":
            continue
        failed = [e for e in entries if e["status"] == "FAIL"]
        good = [e for e in entries if e["status"] in RESOLVED_STATUSES]
        replacements = {}
        for candidate in good:
            supersedes_value = candidate.get("supersedes")
            if isinstance(supersedes_value, str):
                superseded_runs = [supersedes_value.strip()] if supersedes_value.strip() else []
            elif (isinstance(supersedes_value, list)
                  and all(isinstance(item, str) and item.strip() for item in supersedes_value)):
                superseded_runs = [item.strip() for item in supersedes_value]
                if len(set(superseded_runs)) != len(superseded_runs):
                    continue
            else:
                superseded_runs = []
            fixed_by = str(candidate.get("fixedBy") or "").strip()
            if not superseded_runs or not GIT_SHA_RE.fullmatch(fixed_by):
                continue
            candidate_sha = str(candidate.get("productCodeSha") or "")
            candidate_started = _timestamp(candidate.get("startedAt"))
            candidate_current_or_reusable = candidate_sha == sha
            if not candidate_current_or_reusable:
                _, reuse = expected_evidence_sha(candidate, sha, op_id, reuse_impact)
                candidate_current_or_reusable = reuse is not None
            if not candidate_current_or_reusable or candidate_started is None:
                continue
            for superseded in superseded_runs:
                prior = next((f for f in failed if f.get("runId") == superseded), None)
                if prior is None:
                    continue
                prior_sha = str(prior.get("productCodeSha") or "")
                prior_started = _timestamp(prior.get("startedAt"))
                if prior_started is None or candidate_started <= prior_started:
                    continue
                product_fix = fixed_by == candidate_sha and candidate_sha != prior_sha
                fixture_fix = _verified_fixture_fix(
                    candidate, prior, sha, fixed_by, candidate.get("fixedByKind"),
                    op_id, reuse_impact)
                if product_fix or fixture_fix:
                    replacements[superseded] = candidate
        failed_ids = {str(f.get("runId") or "") for f in failed}
        if failed_ids and failed_ids.issubset(replacements):
            selected = replacements[sorted(replacements)[-1]]
            merged = dict(selected)
            merged["supersededRuns"] = sorted(failed_ids)
            chosen[op_id] = merged

    results = []
    for op_id in OPS_IDS:
        entry = dict(chosen.get(op_id) or {
            "status": "NOT_RUN",
            "verdict": None,
            "reasons": ["no evidence at the frozen commit"],
            "evidence": None,
            "layer": None,
        })
        entry["id"] = op_id
        runs = history.get(op_id) or []
        if len(runs) > 1:
            entry["history"] = [
                {"runId": r.get("runId"), "status": r.get("status"),
                 "verdict": r.get("verdict"), "evidence": r.get("evidence")}
                for r in runs
            ]
        results.append(entry)

    # Every row records the real Bash menu entry, the Go command and the
    # expected contract so the ledger can be audited without cross-reading the
    # matrix. A missing Bash entry stays null instead of inventing a mapping.
    spec = read_json(args.matrix_json) or {}
    spec_ops = {o.get("id"): o for o in spec.get("ops") or [] if isinstance(o, dict)}
    for entry in results:
        o = spec_ops.get(entry["id"]) or {}
        go_cmd = o.get("go")
        entry["name"] = o.get("name")
        entry["bashEntry"] = o.get("bash")
        entry["goCommand"] = " ".join(go_cmd) if isinstance(go_cmd, list) else go_cmd
        entry["contract"] = o.get("verdict")
        entry["layers"] = o.get("layers")
        entry["notes"] = o.get("notes")

    counts = {}
    for e in results:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    dual_ids = [e["id"] for e in results if e["status"] == "DUAL_SIDE_VERIFIED"]
    go_ids = [e["id"] for e in results if e["status"] == "GO_ONLY"]
    fail_ids = [e["id"] for e in results if e["status"] == "FAIL"]
    bash_ids = [e["id"] for e in results if e["status"] == "BASH_ONLY"]
    blocked_ids = [e["id"] for e in results if e["status"] == "BLOCKED"]
    not_run_ids = [e["id"] for e in results if e["status"] == "NOT_RUN"]
    approved_diff_ids = [e["id"] for e in results if e["status"] == "APPROVED_DIFF"]
    approved_single_side_ids = [e["id"] for e in results if e["status"] == "APPROVED_SINGLE_SIDE"]
    unresolved = [e["id"] for e in results if e["status"] not in RESOLVED_STATUSES]

    generated = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    ledger = {
        "schemaVersion": 1,
        "generatedAt": generated,
        "codeSha": sha,
        "opsTotal": len(OPS_IDS),
        "counts": {
            "DUAL_SIDE_VERIFIED": len(dual_ids),
            "GO_ONLY": len(go_ids),
            "FAIL": len(fail_ids),
            "BASH_ONLY": len(bash_ids),
            "BLOCKED": len(blocked_ids),
            "NOT_RUN": len(not_run_ids),
            "APPROVED_DIFF": len(approved_diff_ids),
            "APPROVED_SINGLE_SIDE": len(approved_single_side_ids),
        },
        "dualSideVerifiedIds": dual_ids,
        "goOnlyIds": go_ids,
        "failIds": fail_ids,
        "bashOnlyIds": bash_ids,
        "blockedIds": blocked_ids,
        "notRunIds": not_run_ids,
        "approvedDiffIds": approved_diff_ids,
        "approvedSingleSideIds": approved_single_side_ids,
        "unresolvedIds": unresolved,
        "sources": {
            "matrixEvidence": [repo_path(p) for p in args.matrix_evidence],
            "opsEvidence": [repo_path(p) for p in args.ops_evidence],
        },
        "results": results,
    }
    matrix = read_json(args.matrix_json)
    acceptance = read_json(args.acceptance_json)

    # The three summaries are tracked repository artifacts. A test or an ad-hoc
    # probe that forgets one path flag must fail instead of silently rewriting
    # the official acceptance record; only an explicit final build opts in.
    toplevel = git_toplevel()
    targets = [args.out]
    if matrix is not None:
        targets.append(args.matrix_json)
    if acceptance is not None:
        targets.append(args.acceptance_json)
    if not args.allow_repo_write:
        offenders = [p for p in targets if inside_repo(p, toplevel)]
        if offenders:
            print("ledger error: refusing to overwrite tracked acceptance artifacts without "
                  "--allow-repo-write: %s" % ", ".join(offenders), file=sys.stderr)
            return 2

    write_json_atomic(args.out, ledger)

    summary = {
        "total": len(OPS_IDS),
        "dualSideVerified": len(dual_ids),
        "dualSideVerifiedIds": dual_ids,
        "goOnly": len(go_ids),
        "fail": len(fail_ids),
        "failIds": fail_ids,
        "bashOnly": len(bash_ids),
        "bashOnlyIds": bash_ids,
        "blocked": len(blocked_ids),
        "blockedIds": blocked_ids,
        "notRun": len(not_run_ids),
        "notRunIds": not_run_ids,
        "approvedDiff": len(approved_diff_ids),
        "approvedDiffIds": approved_diff_ids,
        "approvedSingleSide": len(approved_single_side_ids),
        "approvedSingleSideIds": approved_single_side_ids,
        "unresolvedIds": unresolved,
        "generatedAt": generated,
        "codeSha": sha,
        "source": "tests/e2e-diff/ledger.json",
    }

    if matrix is not None:
        matrix["repoCommit"] = sha[:8]
        matrix["acceptance"] = {
            "opsTotal": summary["total"],
            "dualSideVerifiedOps": summary["dualSideVerified"],
            "goOnlyOps": summary["goOnly"],
            "failOps": summary["fail"],
            "bashOnlyOps": summary["bashOnly"],
            "blockedOps": summary["blocked"],
            "notRunOps": summary["notRun"],
            "approvedDiffOps": summary["approvedDiff"],
            "approvedSingleSideOps": summary["approvedSingleSide"],
            "dualSideVerifiedIds": dual_ids,
            "goOnlyIds": go_ids,
            "failIds": fail_ids,
            "bashOnlyIds": bash_ids,
            "blockedIds": blocked_ids,
            "approvedDiffIds": approved_diff_ids,
            "approvedSingleSideIds": approved_single_side_ids,
            "notRunIds": not_run_ids,
            "generatedFrom": "tests/e2e-diff/ledger.json",
            "generatedAt": generated,
            "codeSha": sha,
        }
        write_json_atomic(args.matrix_json, matrix)

    if acceptance is not None:
        acceptance["ops"] = summary
        write_json_atomic(args.acceptance_json, acceptance)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if fail_ids:
        print("ledger: FAIL rows present: %s" % ", ".join(fail_ids), file=sys.stderr)
        return 1
    if unresolved and not args.allow_incomplete:
        print("ledger: %d row(s) have neither dual-side verification nor an external approval: %s"
              % (len(unresolved), ", ".join(unresolved)), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
