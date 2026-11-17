#!/usr/bin/env python3
"""F26 — legacy XTLS ONLY is identified read-only and refused.

Preview evidence level: CONTAINER_VERIFIED.

The fixture builds a throwaway legacy root whose install_config.json carries
the removed XTLS profile. `bridge audit` must classify it as blocked with the
stable finding code `legacy-xtls-removed` and must not change one byte.
`bridge prepare` must then be refused with exit 3 *without leaving a journal*.

The journal assertion walks the whole root instead of trusting the exit code:
"non-zero exit" does not prove that no transaction file survived. The root is
rebuilt on every run, so the fixture is repeatable and never inherits state.
"""
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture, sha256  # noqa: E402

UUID = "11111111-2222-4333-8444-555555555555"
BRIDGE_DIR = "var/lib/idleleo/bridge"

LEGACY_CONFIG = {
    "role": "node",
    "shell_mode": "TLS",
    "transport_mode": "tcp",
    "host": "legacy.example.com",
    "port": 8443,
    "tls": "XTLS",
    "net": "tcp",
    "reality_add_nginx": "off",
    "reality_nginx_sni_guard": "off",
    "relay_backend_host": "",
    "relay_backend_port": 0,
    "relay_listen_port": 0,
    "shell_version": "3.3.4",
    "xray_version": "25.1.1",
}

RUNTIME_CONFIG = {
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "tag": "vless-in",
        "listen": "127.0.0.1",
        "port": 8443,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": UUID, "email": "legacy@example.com", "flow": "xtls-rprx-vision"}],
            "decryption": "none",
        },
        "streamSettings": {"network": "tcp", "security": "xtls"},
    }],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
}


def build_root(root):
    """Recreate a faithful legacy layout from scratch."""
    shutil.rmtree(root, ignore_errors=True)
    files = {
        "etc/idleleo/conf/install_config.json": json.dumps(LEGACY_CONFIG, indent=2) + "\n",
        "etc/idleleo/conf/xray/config.json": json.dumps(RUNTIME_CONFIG, indent=2) + "\n",
        "etc/idleleo/install.sh": "#!/usr/bin/env bash\n# legacy fixture marker\n",
        "etc/systemd/system/xray.service": "[Unit]\nDescription=legacy fixture\n",
    }
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def journal_like(root):
    """Every path whose name looks like a journal, anywhere under root."""
    return sorted(
        str(p.relative_to(root))
        for p in root.rglob("*")
        if "journal" in p.name.lower()
    )


def main(f):
    f.need_root()
    root = f.evidence / "legacy-xtls-root"
    build_root(root)

    config = root / "etc/idleleo/conf/xray/config.json"
    before = f.tree_digest(root)

    # 1) Read-only audit: blocked verdict with the stable finding code.
    audit = f.run([f.go, "--root", str(root), "bridge", "audit", "--json"], timeout=30)
    f.check(audit.rc == 0, "bridge audit exit 0", f"rc={audit.rc} {audit.err[:300]}")
    report = f.json_of(audit, "audit report")
    if report is None:
        return
    f.write_json("audit.json", report)

    f.check(report.get("verdict") == "blocked", "audit verdict is blocked",
            f"expected='blocked' actual={report.get('verdict')!r}")
    f.check(report.get("role") == "node", "audit role is node",
            f"expected='node' actual={report.get('role')!r}")
    f.check(report.get("tls") == "XTLS", "audit preserves the legacy TLS mode",
            f"expected='XTLS' actual={report.get('tls')!r}")
    f.check(report.get("legacyVersion") == "3.3.4", "audit reads the legacy version",
            f"expected='3.3.4' actual={report.get('legacyVersion')!r}")
    f.check(report.get("userCount") == 1, "audit counts the runtime users",
            f"expected=1 actual={report.get('userCount')!r}")
    f.check(report.get("runtimeSha256") == sha256(config),
            "audit fingerprints the real runtime config",
            f"expected={sha256(config)!r} actual={report.get('runtimeSha256')!r}")

    findings = report.get("findings") or []
    by_code = {item.get("code"): item for item in findings if isinstance(item, dict)}
    finding = by_code.get("legacy-xtls-removed")
    f.check(finding is not None, "audit reports legacy-xtls-removed",
            f"codes={sorted(by_code)}")
    if finding is not None:
        f.check(finding.get("severity") == "block", "legacy-xtls-removed is a block",
                f"expected='block' actual={finding.get('severity')!r}")

    after_audit = f.tree_digest(root)
    f.check(before == after_audit, "audit changed no byte under the root",
            f"before={before[:16]} after={after_audit[:16]}")

    # 2) Prepare is refused and must not stage anything.
    candidate = f.evidence / "candidate-idleleo"
    candidate.write_text("#!/bin/sh\necho candidate\n", encoding="utf-8")
    candidate.chmod(0o755)

    prepare = f.run([
        f.go, "--root", str(root), "bridge", "prepare",
        "--candidate", str(candidate), "--container", "--json",
    ], timeout=30)
    f.check(prepare.rc == 3, "bridge prepare refused with exit 3",
            f"expected=3 actual={prepare.rc} {prepare.err[:300]}")
    f.check("migration blocked by audit" in prepare.err,
            "prepare names the audit block", prepare.err.strip()[:300])

    bridge_dir = root / BRIDGE_DIR
    journals = journal_like(root)
    f.check(not bridge_dir.exists(), "prepare created no bridge directory",
            str(bridge_dir))
    f.check(journals == [], "prepare left no journal file anywhere",
            f"found={journals}")
    f.check(not (root / "opt/idleleo/bin/idleleo.candidate").exists(),
            "prepare staged no candidate", "opt/idleleo/bin/idleleo.candidate")
    f.check(not (root / "etc/idleleo/v1/metadata.json").exists(),
            "prepare wrote no manager metadata", "etc/idleleo/v1/metadata.json")
    f.check(not (root / BRIDGE_DIR / "plan.json").exists(),
            "prepare wrote no plan", f"{BRIDGE_DIR}/plan.json")

    after_prepare = f.tree_digest(root)
    f.check(before == after_prepare, "prepare changed no byte under the root",
            f"before={before[:16]} after={after_prepare[:16]}")

    # 3) A second refusal must stay identical and still leave no journal.
    repeat = f.run([
        f.go, "--root", str(root), "bridge", "prepare",
        "--candidate", str(candidate), "--container", "--json",
    ], timeout=30)
    f.check(repeat.rc == 3, "second prepare is still refused with exit 3",
            f"expected=3 actual={repeat.rc}")
    f.check(journal_like(root) == [], "second prepare still left no journal",
            f"found={journal_like(root)}")
    f.check(not bridge_dir.exists(), "second prepare still created no bridge directory",
            str(bridge_dir))

    # Keep the sandbox as evidence; build_root() recreates it on the next run.


if __name__ == "__main__":
    sys.exit(run_fixture("F26", main))
