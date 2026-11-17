#!/usr/bin/env python3
"""Fail-closed release signing checks for the shell and Go publish workflows.

The audit finding was that both publishers could ship unsigned metadata: the
verifier rejected it, but nothing in CI ever produced a signature. These checks
assert the signing steps exist, run before the upload, and refuse to continue
when the secret is missing. They also execute scripts/preflight_versions_signature.sh
against real fixtures so a weakened preflight turns this file red.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHELL_WORKFLOW = ROOT / ".github" / "workflows" / "publish-shell-version.yml"
GO_WORKFLOW = ROOT / ".github" / "workflows" / "publish-go-bridge.yml"
PREFLIGHT = ROOT / "scripts" / "preflight_versions_signature.sh"
MANIFEST_PREFLIGHT = ROOT / "scripts" / "preflight_manifest_signature.sh"
SIGNATURE_GO = ROOT / "internal" / "release" / "signature.go"

failures: list[str] = []
passes = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global passes
    if condition:
        passes += 1
        print(f"  PASS: {name}")
        return
    failures.append(f"{name}: {detail}" if detail else name)
    print(f"  FAIL: {name}{(': ' + detail) if detail else ''}")


def job_block(text: str, job: str) -> str:
    """Return the YAML text of one top-level job."""
    match = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.S | re.M)
    return match.group(1) if match else ""


def steps(block: str) -> list[tuple[str, str]]:
    """Split a job block into (step name, step body) pairs at six-space indent."""
    parts = re.split(r"^      - (?:name|uses): ", block, flags=re.M)
    out: list[tuple[str, str]] = []
    for part in parts[1:]:
        first, _, rest = part.partition("\n")
        name = first.strip()
        body = rest
        out.append((name, body))
    return out


def step_index(steps_list: list[tuple[str, str]], needle: str) -> int:
    for index, (name, _body) in enumerate(steps_list):
        if needle in name:
            return index
    return -1


def static_shell_workflow() -> None:
    print("--- publish-shell-version.yml signs before publishing ---")
    check("shell workflow exists", SHELL_WORKFLOW.is_file(), str(SHELL_WORKFLOW))
    text = SHELL_WORKFLOW.read_text(encoding="utf-8")
    promote = job_block(text, "promote")
    check("promote job exists", bool(promote))
    promote_steps = steps(promote)
    sign_index = step_index(promote_steps, "Sign version metadata")
    preflight_index = step_index(promote_steps, "Preflight published metadata signature")
    publish_index = step_index(promote_steps, "Publish API promotion")
    check("sign step exists", sign_index >= 0, "no step named 'Sign version metadata'")
    check("preflight step exists", preflight_index >= 0)
    check("publish step exists", publish_index >= 0)
    if sign_index >= 0 and publish_index >= 0:
        check("sign runs before the API promotion", sign_index < publish_index,
              f"sign={sign_index} publish={publish_index}")
    if preflight_index >= 0 and publish_index >= 0:
        check("preflight runs after signing and before publishing",
              sign_index < preflight_index < publish_index,
              f"sign={sign_index} preflight={preflight_index} publish={publish_index}")
    if sign_index >= 0:
        body = promote_steps[sign_index][1]
        check("sign step reads IDLELEO_VERSIONS_ED25519_KEY", "IDLELEO_VERSIONS_ED25519_KEY" in body)
        check("missing secret exits nonzero", re.search(r"exit 1", body) is not None)
        check("sign step calls scripts/sign_json_ed25519.sh", "scripts/sign_json_ed25519.sh" in body)
        check("sign step covers the published file", "api/xray_shell_versions.json" in body)
        check("sign step is not tolerant of failures",
              "continue-on-error" not in body and "|| true" not in body)
    if preflight_index >= 0:
        body = promote_steps[preflight_index][1]
        check("preflight calls scripts/preflight_versions_signature.sh",
              "scripts/preflight_versions_signature.sh" in body)
        check("preflight runs against the JSON being published",
              "api/xray_shell_versions.json" in body)


def static_go_workflow() -> None:
    print("--- publish-go-bridge.yml signs the manifest before release ---")
    check("go workflow exists", GO_WORKFLOW.is_file(), str(GO_WORKFLOW))
    text = GO_WORKFLOW.read_text(encoding="utf-8")
    publish = job_block(text, "publish")
    check("publish job exists", bool(publish))
    publish_steps = steps(publish)
    sign_index = step_index(publish_steps, "Sign the Go release manifest")
    verify_index = step_index(publish_steps, "Verify the Go release manifest signature")
    release_index = step_index(publish_steps, "Create the immutable Go release")
    check("manifest sign step exists", sign_index >= 0)
    check("manifest verify step exists", verify_index >= 0)
    check("release step exists", release_index >= 0)
    if sign_index >= 0 and verify_index >= 0 and release_index >= 0:
        check("manifest is signed, then verified, then released",
              sign_index < verify_index < release_index,
              f"sign={sign_index} verify={verify_index} release={release_index}")
    if verify_index >= 0:
        body = publish_steps[verify_index][1]
        check("manifest verify step runs the anchor-bound preflight",
              "scripts/preflight_manifest_signature.sh" in body)
        check("manifest verify step binds signature.go",
              "internal/release/signature.go" in body)
        check("manifest verify step is not tolerant of failures",
              "continue-on-error" not in body and "|| true" not in body)
    if sign_index >= 0:
        body = publish_steps[sign_index][1]
        check("manifest sign step reads IDLELEO_RELEASE_ED25519_KEY",
              "IDLELEO_RELEASE_ED25519_KEY" in body)
        check("missing manifest secret exits nonzero", re.search(r"exit 1", body) is not None)
        check("manifest sign step signs with the shared signer",
              "scripts/sign_json_ed25519.sh" in body)
        check("manifest sign step asserts the ed25519: prefix", "ed25519:" in body)
        check("manifest sign step is not tolerant of failures",
              "continue-on-error" not in body and "|| true" not in body)


def openssl_supports_rawin() -> bool:
    if not shutil.which("openssl") or not shutil.which("jq"):
        return False
    help_text = subprocess.run(["openssl", "pkeyutl", "-help"], capture_output=True, text=True)
    return "-rawin" in (help_text.stdout + help_text.stderr)


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def functional_preflight() -> None:
    print("--- preflight_versions_signature.sh enforces the cutover ---")
    check("preflight script exists", PREFLIGHT.is_file(), str(PREFLIGHT))
    if not PREFLIGHT.is_file():
        return
    if not openssl_supports_rawin():
        print("  SKIP: openssl 3 (pkeyutl -rawin) and jq are required")
        return

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        key = tmpdir / "key.pem"
        pub = tmpdir / "pub.pem"
        if run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)]).returncode != 0:
            check("can generate an ed25519 fixture key", False)
            return
        run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)])
        anchor = pub.read_text(encoding="utf-8").rstrip("\n")
        install_sh = tmpdir / "install.sh"
        install_sh.write_text(
            "shell_versions_pubkey_pem='%s'\nversions_signature_required_from=\"3.6.0\"\n" % anchor,
            encoding="utf-8",
        )

        def metadata(version: str) -> Path:
            path = tmpdir / f"versions-{version}.json"
            path.write_text(json.dumps({
                "shell_online_version": version,
                "shell_release_sha256": "0" * 64,
            }, indent=2) + "\n", encoding="utf-8")
            return path

        def preflight(path: Path) -> subprocess.CompletedProcess:
            return run(["bash", str(PREFLIGHT), str(path), str(install_sh)], cwd=str(ROOT))

        unsigned_current = metadata("3.6.0")
        result = preflight(unsigned_current)
        check("unsigned metadata at the cutover is refused", result.returncode != 0,
              result.stdout + result.stderr)

        unsigned_old = metadata("3.5.9")
        result = preflight(unsigned_old)
        check("unsigned metadata below the cutover is allowed", result.returncode == 0,
              result.stdout + result.stderr)

        signed = tmpdir / "versions-signed.json"
        signer = run(["bash", str(ROOT / "scripts" / "sign_json_ed25519.sh"),
                      str(unsigned_current), str(key)], cwd=str(ROOT))
        check("signer produced a signature", signer.returncode == 0, signer.stderr)
        signed.write_text(signer.stdout, encoding="utf-8")
        result = preflight(signed)
        check("signed metadata at the cutover is accepted", result.returncode == 0,
              result.stdout + result.stderr)

        tampered = tmpdir / "versions-tampered.json"
        doc = json.loads(signed.read_text(encoding="utf-8"))
        doc["shell_online_version"] = "3.6.1"
        tampered.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        result = preflight(tampered)
        check("tampered metadata is refused", result.returncode != 0,
              result.stdout + result.stderr)

        wrong_prefix = tmpdir / "versions-wrong-prefix.json"
        doc = json.loads(signed.read_text(encoding="utf-8"))
        doc["metadata_signature"] = "rsa:" + doc["metadata_signature"].split(":", 1)[1]
        wrong_prefix.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        result = preflight(wrong_prefix)
        check("non-ed25519 signature prefix is refused", result.returncode != 0,
              result.stdout + result.stderr)

        # install.sh pads missing components and parses 10#, so 3.6, 3.06.0 and
        # 3.6.0 are all the cutover. The publisher must not let sort -V rank
        # them lower and allow unsigned metadata every current client rejects.
        for ambiguous in ("3.6", "3.06.0", "3.6.00", "v3.6.0"):
            result = preflight(metadata(ambiguous))
            check(f"unsigned metadata '{ambiguous}' is treated as the cutover",
                  result.returncode != 0, result.stdout + result.stderr)

        result = preflight(metadata("3.6.0-rc1"))
        check("non-numeric version suffix is refused", result.returncode != 0,
              result.stdout + result.stderr)


def functional_manifest_preflight() -> None:
    print("--- preflight_manifest_signature.sh binds the signature.go anchor ---")
    check("manifest preflight exists", MANIFEST_PREFLIGHT.is_file(), str(MANIFEST_PREFLIGHT))
    if not MANIFEST_PREFLIGHT.is_file() or not SIGNATURE_GO.is_file():
        return
    if not openssl_supports_rawin():
        print("  SKIP: openssl 3 (pkeyutl -rawin) and jq are required")
        return

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        signer_key = tmpdir / "signer.pem"
        anchor_key = tmpdir / "anchor.pem"
        decoy_key = tmpdir / "decoy.pem"
        for path in (signer_key, anchor_key, decoy_key):
            if run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(path)]).returncode != 0:
                check("can generate ed25519 fixture keys", False)
                return
        anchor_pub = tmpdir / "anchor.pub"
        run(["openssl", "pkey", "-in", str(anchor_key), "-pubout", "-out", str(anchor_pub)])
        signature_go = tmpdir / "signature.go"
        signature_go.write_text(
            "const releasePublicKeyPEM = `%s`\n" % anchor_pub.read_text(encoding="utf-8").rstrip("\n"),
            encoding="utf-8",
        )
        manifest = tmpdir / "manifest.json"
        manifest.write_text(json.dumps({
            "schemaVersion": 1,
            "channel": "stable",
            "version": "0.0.0-test",
            "assets": {"linux-amd64": {"sha256": "0" * 64, "size": 1}},
        }, indent=2) + "\n", encoding="utf-8")

        def verify(path: Path) -> subprocess.CompletedProcess:
            return run(["bash", str(MANIFEST_PREFLIGHT), str(path), str(signature_go)], cwd=str(ROOT))

        result = verify(manifest)
        check("unsigned manifest is refused", result.returncode != 0, result.stdout + result.stderr)

        signed = tmpdir / "manifest.signed.json"
        signer = run(["bash", str(ROOT / "scripts" / "sign_json_ed25519.sh"),
                      str(manifest), str(anchor_key), "signature"], cwd=str(ROOT))
        check("manifest signer produced a signature", signer.returncode == 0, signer.stderr)
        signed.write_text(signer.stdout, encoding="utf-8")
        result = verify(signed)
        check("manifest signed with the anchor key is accepted", result.returncode == 0,
              result.stdout + result.stderr)

        # This is the core audit case: a Secret that does not pair with the
        # embedded anchor still yields a well-formed signature.
        mismatched = tmpdir / "manifest.mismatched.json"
        signer = run(["bash", str(ROOT / "scripts" / "sign_json_ed25519.sh"),
                      str(manifest), str(decoy_key), "signature"], cwd=str(ROOT))
        mismatched.write_text(signer.stdout, encoding="utf-8")
        result = verify(mismatched)
        check("manifest signed with a non-matching key is refused", result.returncode != 0,
              result.stdout + result.stderr)

        tampered = tmpdir / "manifest.tampered.json"
        doc = json.loads(signed.read_text(encoding="utf-8"))
        doc["channel"] = "beta"
        tampered.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        result = verify(tampered)
        check("tampered manifest is refused", result.returncode != 0,
              result.stdout + result.stderr)


def main() -> int:
    static_shell_workflow()
    static_go_workflow()
    functional_preflight()
    functional_manifest_preflight()
    print(f"\nSummary: PASS={passes} FAIL={len(failures)}")
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
