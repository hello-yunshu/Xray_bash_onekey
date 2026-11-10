#!/usr/bin/env python3
"""F27 — legacy CLI exit codes plus uninstall/purge semantics.

Preview evidence level: CONTAINER_VERIFIED.

Scope is deliberately narrow. Only implemented behaviour is asserted:
`--version`/`--help`/usage exit codes and `xray uninstall` with and without
`--purge` on a disposable sandbox root. `backup`/`restore` are NOT implemented
yet, so the contract keeps them at `not_verified`; this fixture records that
they are absent (exit 2) instead of pretending they pass.

Every sandbox is rebuilt from scratch, so the fixture is repeatable and the
second uninstall is also exercised for idempotency.
"""
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

VERSION = "0.2.0-phase04"
MARKER = ".idleleo-phase01-sandbox"
MARKER_VALUE = "I_ACCEPT_DISPOSABLE_SANDBOX"

UNIT_REL = "etc/systemd/system/xray.service"
BINARY_REL = "usr/local/bin/xray"
METADATA_REL = "etc/idleleo/v1/metadata.json"
CONFIG_REL = "etc/idleleo/conf/xray/config.json"
NGINX_REL = "etc/idleleo/conf/nginx/relay-stream.conf"
LOG_REL = "var/log/xray/access.log"

METADATA = {
    "schemaVersion": 1,
    "activeEngine": "xray",
    "role": "node",
    "tls": "Reality",
    "transport": "tcp",
    "runtimeConfigPath": CONFIG_REL,
    "runtimeSha256": "",
    "ownedResources": [],
    "updatedAt": "2026-01-01T00:00:00Z",
}


def build_sandbox(f, name):
    root = f.evidence / name
    shutil.rmtree(root, ignore_errors=True)
    files = {
        MARKER: MARKER_VALUE + "\n",
        BINARY_REL: "#!/bin/sh\necho fixture\n",
        UNIT_REL: "[Unit]\nDescription=uninstall fixture\n",
        METADATA_REL: json.dumps(METADATA, indent=2) + "\n",
        CONFIG_REL: json.dumps({"inbounds": [], "outbounds": []}, indent=2) + "\n",
        NGINX_REL: "stream {}\n",
        LOG_REL: "fixture\n",
    }
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def leftovers(directory):
    return sorted(str(p.relative_to(directory)) for p in directory.rglob("*"))


def main(f):
    f.need_root()

    # 1) Version and help are read-only and never write to the working dir.
    clean = f.evidence / "no-write-cwd"
    shutil.rmtree(clean, ignore_errors=True)
    clean.mkdir(parents=True)

    version = f.run([f.go, "--version"], timeout=20, cwd=clean)
    f.check(version.rc == 0, "--version exit 0", f"rc={version.rc}")
    f.check(VERSION in version.text, "--version prints the candidate version",
            f"expected={VERSION!r} actual={version.text.strip()[:200]!r}")

    sub_version = f.run([f.go, "version"], timeout=20, cwd=clean)
    f.check(sub_version.rc == 0, "version subcommand exit 0", f"rc={sub_version.rc}")
    f.check(VERSION in sub_version.text, "version subcommand prints the candidate version",
            f"expected={VERSION!r} actual={sub_version.text.strip()[:200]!r}")

    help_top = f.run([f.go, "--help"], timeout=20, cwd=clean)
    f.check(help_top.rc == 0, "--help exit 0", f"rc={help_top.rc}")
    help_xray = f.run([f.go, "xray", "generate", "--help"], timeout=20, cwd=clean)
    f.check(help_xray.rc == 0, "xray generate --help exits before generating",
            f"rc={help_xray.rc}")
    f.check(leftovers(clean) == [], "help paths wrote nothing to the working dir",
            f"found={leftovers(clean)}")

    # 2) Usage errors keep exit code 2 and still write nothing.
    missing_out = f.run([f.go, "xray", "generate"], timeout=20, cwd=clean)
    f.check(missing_out.rc == 2, "xray generate without --out exits 2",
            f"expected=2 actual={missing_out.rc}")

    unknown = f.run([f.go, "definitely-not-a-command"], timeout=20, cwd=clean)
    f.check(unknown.rc == 2, "unknown command exits 2",
            f"expected=2 actual={unknown.rc}")

    user_no_sandbox = f.run([
        f.go, "xray", "user", "add",
        "--uuid", "11111111-2222-4333-8444-555555555555",
        "--validator", "/bin/true",
    ], timeout=20, cwd=clean)
    f.check(user_no_sandbox.rc == 2, "xray user add without --sandbox exits 2",
            f"expected=2 actual={user_no_sandbox.rc}")
    f.check(user_no_sandbox.rc == 2 and user_no_sandbox.text.strip() != "",
            "sandbox refusal has a message", user_no_sandbox.text.strip()[:200])
    f.check(leftovers(clean) == [], "usage errors wrote nothing to the working dir",
            f"found={leftovers(clean)}")

    # 3) backup/restore stay not_verified: they are not implemented, so the CLI
    #    must refuse them as unknown subcommands. This is an observation, not a
    #    pass for the missing feature.
    for sub in ("backup", "restore"):
        r = f.run([f.go, "xray", sub], timeout=20, cwd=clean)
        f.check(r.rc == 2, f"xray {sub} is absent (not_verified)",
                f"expected=2 actual={r.rc}")

    # 4) Sandbox uninstall keeps the config unless --purge is requested.
    root = build_sandbox(f, "uninstall-root")
    uninstall = f.run([f.go, "--root", str(root), "xray", "uninstall",
                       "--container", "--json"], timeout=60)
    f.check(uninstall.rc == 0, "sandbox uninstall exit 0",
            f"rc={uninstall.rc} {uninstall.err[:300]}")
    report = f.json_of(uninstall, "uninstall report")
    if report is None:
        return
    f.write_json("uninstall.json", report)

    removed = set(report.get("removed") or [])
    f.check(UNIT_REL in removed, "uninstall removed the systemd unit",
            f"expected={UNIT_REL!r} removed={sorted(removed)}")
    f.check(BINARY_REL in removed, "uninstall removed the managed binary",
            f"expected={BINARY_REL!r} removed={sorted(removed)}")
    f.check(METADATA_REL in removed, "uninstall removed the manager metadata",
            f"expected={METADATA_REL!r} removed={sorted(removed)}")
    f.check(report.get("configPreserved") is True,
            "uninstall preserves the config by default",
            f"expected=True actual={report.get('configPreserved')!r}")
    f.check(report.get("serviceStopped") is False,
            "sandbox uninstall stops no host service",
            f"expected=False actual={report.get('serviceStopped')!r}")
    f.check((root / CONFIG_REL).is_file(), "config still exists after uninstall",
            str(root / CONFIG_REL))
    f.check(not (root / UNIT_REL).exists() and not (root / BINARY_REL).exists(),
            "unit and binary are gone after uninstall", "unit/binary")

    # 5) --purge removes the config and the project-owned directories.
    purge = f.run([f.go, "--root", str(root), "xray", "uninstall",
                   "--purge", "--container", "--json"], timeout=60)
    f.check(purge.rc == 0, "sandbox purge exit 0", f"rc={purge.rc} {purge.err[:300]}")
    purge_report = f.json_of(purge, "purge report") or {}
    f.write_json("purge.json", purge_report)
    f.check(purge_report.get("configPreserved") is False,
            "purge reports the config as not preserved",
            f"expected=False actual={purge_report.get('configPreserved')!r}")
    f.check(not (root / CONFIG_REL).exists(), "purge removed the runtime config",
            str(root / CONFIG_REL))
    f.check(not (root / "etc/idleleo/conf/nginx").exists(),
            "purge removed the managed nginx directory", "etc/idleleo/conf/nginx")
    f.check(not (root / "var/log/xray").exists(),
            "purge removed the log directory", "var/log/xray")

    # 6) A second purge is a harmless no-op, proving idempotent cleanup.
    again = f.run([f.go, "--root", str(root), "xray", "uninstall",
                   "--purge", "--container", "--json"], timeout=60)
    f.check(again.rc == 0, "second purge exit 0", f"rc={again.rc} {again.err[:300]}")
    f.check(not (root / CONFIG_REL).exists(), "second purge leaves no config",
            str(root / CONFIG_REL))

    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(clean, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_fixture("F27", main))
