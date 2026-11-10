#!/usr/bin/env python3
"""F28 — offline status/show/share field contract and zero-write reads.

Preview evidence level: CONTAINER_VERIFIED.

The fixture builds a disposable root with an info file, a Reality runtime
config and matching manager metadata, then asserts the JSON contract of
`show`, `status` and `share` field by field. Every assertion prints the field
name, the expected value and the actual value, so a lossy diff is never
reported as a bare "mismatch".

The whole root is fingerprinted before and after the three commands: these
reads must not write anything, including a change journal.
"""
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture, sha256  # noqa: E402

UUID = "11111111-2222-4333-8444-555555555555"
SID = "6ba85179e30d4fc2"
DOMAIN = "www.example.com"
PUBLIC_HOST = "cdn.example.com"
PUBLIC_PORT = 8443
EMAIL = "preview@example.com"
FLOW = "xtls-rprx-vision"

CONFIG_REL = "etc/idleleo/conf/xray/config.json"
METADATA_REL = "etc/idleleo/v1/metadata.json"
INFO_REL = "etc/idleleo/info/xray_info.inf"


def key_value(text, labels, skip=()):
    """First `Label: value` line whose lowercased label starts with a candidate."""
    for line in text.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if any(low.startswith(prefix) for prefix in skip):
            continue
        for label in labels:
            if low.startswith(label.lower()):
                return stripped.split(":", 1)[1].strip()
    return ""


def dig(payload, field):
    """Resolve `a.b[0].c` against decoded JSON, returning a marker on miss."""
    cur = payload
    for part in field.split("."):
        index = None
        name = part
        if part.endswith("]") and "[" in part:
            name, raw = part[:-1].split("[", 1)
            index = int(raw)
        if name:
            if not isinstance(cur, dict) or name not in cur:
                return "<missing>"
            cur = cur[name]
        if index is not None:
            if not isinstance(cur, list) or index >= len(cur):
                return "<missing>"
            cur = cur[index]
    return cur


def check_fields(f, label, payload, expected):
    for field, want in expected.items():
        got = dig(payload, field)
        f.check(got == want, f"{label} {field}",
                f"expected={want!r} actual={got!r}")


def check_contains(f, label, text, needle):
    f.check(needle in text, f"{label} contains {needle}",
            f"expected substring={needle!r} actual={text!r}")


def build_root(f, name, private_key):
    root = f.evidence / name
    shutil.rmtree(root, ignore_errors=True)
    config = root / CONFIG_REL
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "port": PUBLIC_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": UUID, "email": EMAIL, "flow": FLOW}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "privateKey": private_key,
                    "shortIds": [SID],
                    "serverNames": [DOMAIN],
                    "fingerprint": "chrome",
                },
            },
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }, indent=2) + "\n", encoding="utf-8")

    metadata = {
        "schemaVersion": 1,
        "activeEngine": "xray",
        "role": "node",
        "tls": "Reality",
        "transport": "tcp",
        "runtimeConfigPath": CONFIG_REL,
        "runtimeSha256": sha256(config),
        "ownedResources": [CONFIG_REL],
        "updatedAt": "2026-01-01T00:00:00Z",
    }
    meta_path = root / METADATA_REL
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    info = root / INFO_REL
    info.parent.mkdir(parents=True, exist_ok=True)
    info.write_text(
        "# idleleo preview fixture info\n"
        f"domain={DOMAIN}\n"
        f"port={PUBLIC_PORT}\n"
        "tls=Reality\n"
        "network=tcp\n"
        f"uuid={UUID}\n",
        encoding="utf-8",
    )
    return root, config


def main(f):
    f.need_root()
    xray = f.xray_bin()

    keys = f.run([xray, "x25519"], timeout=30)
    private_key = key_value(keys.text, ["PrivateKey", "Private key"])
    f.check(bool(private_key), "xray x25519 produced a private key",
            f"expected=<non-empty> actual={private_key!r} output={keys.text.strip()[:300]!r}")
    if not private_key:
        return
    derived = f.run([xray, "x25519", "-i", private_key], timeout=30)
    public_key = key_value(
        derived.text,
        ["Password (PublicKey)", "PublicKey", "Password", "Public key"],
        skip=("private",),
    )
    f.check(bool(public_key), "xray x25519 -i produced a public key",
            f"expected=<non-empty> actual={public_key!r} output={derived.text.strip()[:300]!r}")
    if not public_key:
        return

    root, config = build_root(f, "readonly-root", private_key)
    digest = sha256(config)
    before = f.tree_digest(root)

    # 1) show: info file + runtime config projection.
    show = f.run([f.go, "--root", str(root), "show", "--json"], timeout=30)
    f.check(show.rc == 0, "show exit 0", f"rc={show.rc} {show.err[:300]}")
    show_json = f.json_of(show, "show report")
    if show_json is None:
        return
    f.write_json("show.json", show_json)
    check_fields(f, "show", show_json, {
        "path": str(config),
        "sha256": digest,
        "authority": "127.0.0.1",
        "info.domain": DOMAIN,
        "info.port": str(PUBLIC_PORT),
        "info.tls": "Reality",
        "info.network": "tcp",
        "info.uuid": UUID,
        "inbounds[0].index": 0,
        "inbounds[0].protocol": "vless",
        "inbounds[0].listen": "127.0.0.1",
        "inbounds[0].port": str(PUBLIC_PORT),
        "inbounds[0].network": "tcp",
        "inbounds[0].security": "reality",
        "warnings": [],
    })

    # 2) status: metadata + fingerprint match, sandbox never queries systemd.
    status = f.run([f.go, "--root", str(root), "status", "--json"], timeout=30)
    f.check(status.rc == 0, "status exit 0", f"rc={status.rc} {status.err[:300]}")
    status_json = f.json_of(status, "status report")
    if status_json is None:
        return
    f.write_json("status.json", status_json)
    check_fields(f, "status", status_json, {
        "schemaVersion": 1,
        "installed": True,
        "engine": "xray",
        "role": "node",
        "tls": "Reality",
        "transport": "tcp",
        "config.path": str(config),
        "config.sha256": digest,
        "config.matchesMetadata": True,
        "service.source": "sandbox",
        "service.sandbox": True,
        "service.xray": "sandbox-not-queried",
        "service.nginx": "sandbox-not-queried",
        "service.enabled": "sandbox-not-queried",
        "drift": [],
        "warnings": [],
    })

    # 3) share: rendered client view for the Reality inbound.
    share = f.run([
        f.go, "xray", "share", "--path", str(config),
        "--host", PUBLIC_HOST, "--public-port", str(PUBLIC_PORT), "--json",
    ], timeout=30)
    f.check(share.rc == 0, "share exit 0", f"rc={share.rc} {share.err[:300]}")
    share_json = f.json_of(share, "share report")
    if share_json is None:
        return
    f.write_json("share.json", share_json)
    check_fields(f, "share", share_json, {
        "mode": "reality",
        "transport": "raw",
        "uuid": UUID,
        "email": EMAIL,
        "flow": FLOW,
        "host": PUBLIC_HOST,
        "port": PUBLIC_PORT,
    })
    uri = share_json.get("shareUri") or ""
    f.check(isinstance(uri, str) and uri.startswith(f"vless://{UUID}@{PUBLIC_HOST}:{PUBLIC_PORT}?"),
            "share shareUri targets the public authority",
            f"expected prefix={'vless://' + UUID + '@' + PUBLIC_HOST + ':' + str(PUBLIC_PORT) + '?'!r} actual={uri!r}")
    for needle in (
        "encryption=none",
        f"flow={FLOW}",
        "security=reality",
        f"sni={DOMAIN}",
        "fp=chrome",
        f"pbk={public_key}",
        f"sid={SID}",
        "type=raw",
    ):
        check_contains(f, "share shareUri", uri, needle)
    clash = share_json.get("clashYaml") or ""
    f.check(isinstance(clash, str) and clash.strip() != "",
            "share emits a Clash proxy", f"expected=<non-empty> actual={clash[:120]!r}")
    check_contains(f, "share clashYaml", clash, UUID)
    f.check(isinstance(share_json.get("warnings"), list),
            "share warnings is a list",
            f"expected=list actual={type(share_json.get('warnings')).__name__}")

    # 4) All three commands are read-only.
    after = f.tree_digest(root)
    f.check(before == after, "show/status/share changed no byte under the root",
            f"before={before[:16]} after={after[:16]}")
    f.check(not (root / "var/lib/idleleo/transactions").exists(),
            "no transaction journal was created",
            "var/lib/idleleo/transactions")

    shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_fixture("F28", main))
