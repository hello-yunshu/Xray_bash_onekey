#!/usr/bin/env python3
"""F19 — metadata import/export/deactivate preserve the legacy install.

Preview evidence level: CONTAINER_VERIFIED.

The fixture builds disposable legacy roots (reality-direct node layout and a
relay layout) and drives the real Go manager. It proves:

  * `metadata import` derives provenance=legacy metadata from the existing
    `install_config.json` without ever rewriting the source, the runtime
    config, certificates, the entry symlink or cron,
  * a second import never overwrites the single source of truth, an arbitrary
    `--from` target and an unmarked root are refused before any write,
  * missing/corrupt `install_config.json` and a missing runtime config leave the
    root byte-identical,
  * `metadata export` is read-only by default, writes a 0600 document outside
    the root, and refuses managed directories and the metadata file itself,
  * runtime drift is reported (`matchesMetadata=false`) and `bridge deactivate`
    refuses with exit 6 while leaving every file in place,
  * after restoring the runtime bytes, deactivate archives the metadata (it is
    not deleted), keeps the entry/cron/certs/runtime unchanged, and reports
    RELEASED,
  * the Bash baseline's `--backup` / `--restore` archive features are recorded
    as not implemented instead of being claimed as aligned.

The Bash side is static-only: its backup archive bundles certificates and ACME
account keys, which the Go manager deliberately does not copy. That divergence
is written to bash-baseline.json, not hidden behind a passing fixture.
"""
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture, sha256  # noqa: E402

SANDBOX_MARKER = ".idleleo-phase01-sandbox"
SANDBOX_VALUE = "I_ACCEPT_DISPOSABLE_SANDBOX"
CONFIG_REL = "etc/idleleo/conf/install_config.json"
RUNTIME_REL = "etc/idleleo/conf/xray/config.json"
METADATA_REL = "etc/idleleo/v1/metadata.json"
CERT_REL = "etc/idleleo/cert/fullchain.pem"
KEY_REL = "etc/idleleo/cert/privkey.pem"
SERVICE_REL = "etc/systemd/system/xray.service"
SCRIPT_REL = "etc/idleleo/install.sh"
ENTRY_REL = "usr/bin/idleleo"
CRON_REL = "var/spool/cron/crontabs/root"
RELAY_CONF_REL = "etc/idleleo/conf/nginx/relay-stream.conf"
ARCHIVE_REL = "var/lib/idleleo/bridge/snapshot/metadata.deactivated.json"

UUID = "11111111-2222-4333-8444-555555555555"
REALITY_PRIVATE = "oD7nlMJVY4oXH5eom_ijOe741Y4WDjpCm6_bzYRCvmk"
SHORT_ID = "0123456789abcdef"
SECRET_KEYS = ("uuid", "privatekey", "private_key", "shortid", "shortids",
               "password", "secret")

NODE_CONFIG = {
    "role": "node",
    "shell_mode": "Reality",
    "transport_mode": "None",
    "host": "203.0.113.10",
    "port": 9443,
    "tls": "Reality",
    "net": "raw",
    "reality_add_nginx": "off",
    "reality_nginx_sni_guard": "off",
    "shell_version": "3.3.4",
    "xray_version": "26.10.31",
    "email": "fixture@example.invalid",
}

NODE_RUNTIME = {
    "log": {"loglevel": "warning"},
    "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
    "routing": {"rules": [{
        "type": "field",
        "domain": ["example.invalid"],
        "outboundTag": "direct",
    }]},
    "inbounds": [{
        "tag": "vless-in",
        "listen": "0.0.0.0",
        "port": 9443,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": UUID, "email": "fixture@example.invalid"}],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "raw",
            "security": "reality",
            "realitySettings": {
                "target": "www.example.invalid:443",
                "serverNames": ["www.example.invalid"],
                "privateKey": REALITY_PRIVATE,
                "shortIds": [SHORT_ID],
            },
        },
    }],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
}

RELAY_CONFIG = {
    "role": "relay",
    "shell_mode": "Relay",
    "host": "203.0.113.20",
    "port": 443,
    "tls": "None",
    "net": "tcp",
    "reality_add_nginx": "off",
    "shell_version": "3.3.4",
    "xray_version": "26.10.31",
}

RELAY_STREAM = (
    "upstream relay_backend {\n"
    "    server 203.0.113.21:443;\n"
    "}\n"
    "server {\n"
    "    listen 443;\n"
    "    proxy_pass relay_backend;\n"
    "}\n"
)

CRON_BODY = (
    "0 4 * * * /etc/idleleo/scripts/geo_update.sh >> /var/log/idleleo/geo.log 2>&1\n"
    "30 2 * * * /usr/local/bin/user-task --quiet\n"
)


def write(path, body, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(body, (dict, list)):
        body = json.dumps(body, indent=2) + "\n"
    path.write_text(body, encoding="utf-8")
    os.chmod(path, mode)
    return path


def build_node_root(work, name, marked=True, with_config=True, with_runtime=True):
    root = Path(work) / name
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    if marked:
        write(root / SANDBOX_MARKER, SANDBOX_VALUE + "\n", 0o600)
    if with_config:
        write(root / CONFIG_REL, NODE_CONFIG, 0o640)
    if with_runtime:
        write(root / RUNTIME_REL, NODE_RUNTIME, 0o644)
    write(root / CERT_REL, "-----BEGIN CERTIFICATE-----\nf19-fixture\n"
          "-----END CERTIFICATE-----\n", 0o644)
    write(root / KEY_REL, "-----BEGIN PRIVATE KEY-----\nf19-fixture\n"
          "-----END PRIVATE KEY-----\n", 0o644)
    write(root / SERVICE_REL,
          "[Service]\nUser=xray\nGroup=xray\n"
          "ExecStart=/usr/local/bin/xray run -config /etc/idleleo/conf/xray/config.json\n",
          0o644)
    write(root / SCRIPT_REL, "#!/usr/bin/env bash\n# legacy fixture marker\n", 0o755)
    write(root / CRON_REL, CRON_BODY, 0o600)
    entry = root / ENTRY_REL
    entry.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(str(root / SCRIPT_REL), entry)
    return root


def build_relay_root(work, name):
    root = Path(work) / name
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    write(root / SANDBOX_MARKER, SANDBOX_VALUE + "\n", 0o600)
    write(root / CONFIG_REL, RELAY_CONFIG, 0o640)
    write(root / RELAY_CONF_REL, RELAY_STREAM, 0o640)
    write(root / SCRIPT_REL, "#!/usr/bin/env bash\n# relay legacy marker\n", 0o755)
    entry = root / ENTRY_REL
    entry.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(str(root / SCRIPT_REL), entry)
    return root


def snapshot(root):
    root = Path(root)
    return {
        "config": sha256(root / CONFIG_REL),
        "runtime": sha256(root / RUNTIME_REL),
        "cert": sha256(root / CERT_REL),
        "key": sha256(root / KEY_REL),
        "service": sha256(root / SERVICE_REL),
        "script": sha256(root / SCRIPT_REL),
        "cron": sha256(root / CRON_REL),
        "entry": os.readlink(root / ENTRY_REL),
    }


def state_digest(f, root):
    """Digest every install-owned subtree, excluding the update lock under run/."""
    root = Path(root)
    parts = [sha256(root / SANDBOX_MARKER)]
    for sub in ("etc", "var", "usr"):
        parts.append(f.tree_digest(root / sub))
    return "|".join(parts)


def assert_unchanged(f, root, before, label):
    after = snapshot(root)
    for key, digest in before.items():
        f.check(after[key] == digest, f"{label}: {key} is byte-identical",
                f"before={digest} after={after[key]}")


def meta_cmd(f, root, *args):
    return f.run([f.go, "--root", str(root), "--json", "metadata", *args], timeout=60)


def bridge_cmd(f, root, *args):
    return f.run([f.go, "--root", str(root), "--json", "bridge", *args], timeout=60)


def mode_of(path):
    return oct(Path(path).stat().st_mode & 0o777)


def read_json(path):
    return json.loads(Path(path).read_text())


def secret_keys(node, found):
    if isinstance(node, dict):
        for key, child in node.items():
            found.append(str(key).lower())
            secret_keys(child, found)
    elif isinstance(node, list):
        for child in node:
            secret_keys(child, found)
    return found


def import_success(f, work):
    root = build_node_root(work, "node")
    before = snapshot(root)
    config_path = root / CONFIG_REL
    runtime_path = root / RUNTIME_REL
    meta_path = root / METADATA_REL

    imp = meta_cmd(f, root, "import")
    doc = f.json_of(imp, "metadata import") if imp.rc == 0 else {}
    f.check(imp.rc == 0, "node import exits 0", f"rc={imp.rc} {imp.err[:300]}")
    f.check(doc.get("schemaVersion") == 1, "report schemaVersion is 1",
            str(doc.get("schemaVersion")))
    f.check(doc.get("state") == "IMPORTED", "report state is IMPORTED",
            str(doc.get("state")))
    f.check(doc.get("provenance") == "legacy", "provenance is legacy",
            str(doc.get("provenance")))
    f.check(doc.get("role") == "node", "role is node", str(doc.get("role")))
    f.check(doc.get("tls") == "Reality", "tls is Reality", str(doc.get("tls")))
    f.check(doc.get("transport") == "raw", "transport is raw", str(doc.get("transport")))
    f.check(doc.get("sourcePath") == str(config_path),
            "sourcePath points at install_config.json", str(doc.get("sourcePath")))
    f.check(doc.get("sourceSha256") == sha256(config_path),
            "sourceSha256 matches the real source", str(doc.get("sourceSha256")))
    f.check(doc.get("metadataPath") == str(meta_path),
            "metadataPath points at v1/metadata.json", str(doc.get("metadataPath")))
    f.check(doc.get("runtimeSha256") == sha256(runtime_path),
            "runtimeSha256 matches the runtime config", str(doc.get("runtimeSha256")))
    f.check(meta_path.is_file(), "metadata file exists", str(meta_path))
    if not meta_path.is_file():
        return root, before
    meta_bytes = meta_path.read_bytes()
    f.check(doc.get("metadataSha256") == sha256(meta_path),
            "metadataSha256 matches the written file", str(doc.get("metadataSha256")))
    f.check(mode_of(meta_path) == "0o640", "metadata is 0640", mode_of(meta_path))

    meta = read_json(meta_path)
    f.check(meta.get("schemaVersion") == 1, "metadata schemaVersion is 1",
            str(meta.get("schemaVersion")))
    f.check(meta.get("activeEngine") == "xray", "activeEngine is xray",
            str(meta.get("activeEngine")))
    f.check(meta.get("provenance") == "legacy", "metadata provenance is legacy",
            str(meta.get("provenance")))
    f.check(meta.get("role") == "node", "metadata role is node", str(meta.get("role")))
    f.check(meta.get("tls") == "Reality", "metadata tls is Reality", str(meta.get("tls")))
    f.check(meta.get("transport") == "raw", "metadata transport is raw",
            str(meta.get("transport")))
    f.check(meta.get("runtimeConfigPath") == RUNTIME_REL,
            "metadata pins the runtime path", str(meta.get("runtimeConfigPath")))
    f.check(meta.get("runtimeSha256") == sha256(runtime_path),
            "metadata pins the runtime digest", str(meta.get("runtimeSha256")))
    owned = meta.get("ownedResources") or []
    f.check(sorted(owned) == sorted([RUNTIME_REL, SERVICE_REL, "etc/idleleo/cert"]),
            "ownedResources cover runtime, unit and certs", str(owned))
    f.check(isinstance(meta.get("updatedAt"), str) and "T" in meta.get("updatedAt", ""),
            "updatedAt is an RFC3339 timestamp", str(meta.get("updatedAt")))

    found = secret_keys(meta, [])
    leaked = sorted({k for k in found if k in SECRET_KEYS})
    f.check(not leaked, "metadata stores no secret keys", str(leaked))
    text = meta_bytes.decode("utf-8", "replace")
    f.check(UUID not in text and REALITY_PRIVATE not in text and SHORT_ID not in text,
            "metadata contains no UUID/privateKey/shortId values")
    assert_unchanged(f, root, before, "import")

    meta_digest = sha256(meta_path)

    # A second import must never overwrite the single source of truth.
    again = meta_cmd(f, root, "import")
    again_text = again.out + again.err
    f.check(again.rc == 3, "second import exits 3", f"rc={again.rc} {again_text[:300]}")
    f.check("already exists" in again_text, "second import explains the refusal",
            again_text[:300])
    f.check(sha256(meta_path) == meta_digest, "second import keeps metadata intact")
    f.check(sha256(config_path) == before["config"],
            "second import keeps install_config.json intact")
    return root, before


def import_boundaries(f, work):
    # Arbitrary --from is refused before any write; the documented alias works.
    root = build_node_root(work, "from-root")
    meta_path = root / METADATA_REL
    arbitrary = meta_cmd(f, root, "import", "--from", "/tmp/f19-anything.json")
    text = arbitrary.out + arbitrary.err
    f.check(arbitrary.rc == 2, "arbitrary --from exits 2",
            f"rc={arbitrary.rc} {text[:300]}")
    f.check("only reads" in text, "arbitrary --from explains the allowed path",
            text[:300])
    f.check(not meta_path.exists(), "arbitrary --from writes no metadata")

    alias = meta_cmd(f, root, "import", "--from", "install_config.json")
    f.check(alias.rc == 0, "documented --from alias exits 0",
            f"rc={alias.rc} {alias.err[:300]}")
    f.check(meta_path.is_file(), "documented --from alias writes metadata")

    unmarked = build_node_root(work, "unmarked", marked=False)
    refused = meta_cmd(f, unmarked, "import")
    text = refused.out + refused.err
    f.check(refused.rc == 2, "unmarked root import exits 2",
            f"rc={refused.rc} {text[:300]}")
    f.check("write access refused" in text, "unmarked root reports the write gate",
            text[:300])
    f.check(not (unmarked / METADATA_REL).exists(),
            "unmarked root gets no metadata")


def import_failures(f, work):
    cases = []

    missing = build_node_root(work, "missing-config", with_config=False)
    cases.append(("missing install_config.json", missing, 2))

    corrupt = build_node_root(work, "corrupt-config")
    write(corrupt / CONFIG_REL, "{ this is not json\n", 0o640)
    cases.append(("corrupt install_config.json", corrupt, 2))

    no_runtime = build_node_root(work, "missing-runtime", with_runtime=False)
    cases.append(("missing runtime config", no_runtime, 3))

    for label, root, want in cases:
        before = state_digest(f, root)
        result = meta_cmd(f, root, "import")
        text = result.out + result.err
        f.check(result.rc == want, f"{label}: import exits {want}",
                f"rc={result.rc} {text[:300]}")
        f.check(not (root / METADATA_REL).exists(),
                f"{label}: no metadata is written")
        f.check(state_digest(f, root) == before,
                f"{label}: the install-owned tree is byte-identical")
        f.check((root / "run/lock/idleleo-update.lock").is_file(),
                f"{label}: only the update lock was created")


def relay_case(f, work):
    root = build_relay_root(work, "relay")
    imp = meta_cmd(f, root, "import")
    doc = f.json_of(imp, "relay import") if imp.rc == 0 else {}
    f.check(imp.rc == 0, "relay import exits 0", f"rc={imp.rc} {imp.err[:300]}")
    f.check(doc.get("role") == "relay", "relay role is reported", str(doc.get("role")))
    f.check(doc.get("tls") == "None", "relay tls is None", str(doc.get("tls")))
    f.check(doc.get("transport") == "stream", "relay transport is stream",
            str(doc.get("transport")))
    f.check(not doc.get("runtimeSha256"), "relay has no runtime digest",
            str(doc.get("runtimeSha256")))
    meta_path = root / METADATA_REL
    f.check(meta_path.is_file(), "relay metadata file exists", str(meta_path))
    if meta_path.is_file():
        meta = read_json(meta_path)
        owned = meta.get("ownedResources") or []
        f.check(meta.get("role") == "relay", "metadata relay role",
                str(meta.get("role")))
        f.check(meta.get("runtimeSha256") == "", "metadata relay runtime digest is empty",
                str(meta.get("runtimeSha256")))
        f.check(RELAY_CONF_REL in owned or "etc/idleleo/conf/nginx" in owned,
                "metadata owns the relay config", str(owned))


def export_cases(f, work, root, before):
    runtime_path = root / RUNTIME_REL
    meta_path = root / METADATA_REL
    meta_digest = sha256(meta_path)

    plain = meta_cmd(f, root, "export")
    doc = f.json_of(plain, "metadata export") if plain.rc == 0 else {}
    f.check(plain.rc == 0, "export without --out exits 0",
            f"rc={plain.rc} {plain.err[:300]}")
    f.check(doc.get("schemaVersion") == 1, "export schemaVersion is 1",
            str(doc.get("schemaVersion")))
    f.check(doc.get("matchesMetadata") is True,
            "fresh export matches the metadata", str(doc.get("matchesMetadata")))
    f.check(doc.get("metadataSha256") == meta_digest,
            "export records the metadata digest", str(doc.get("metadataSha256")))
    f.check(doc.get("runtimeSha256") == sha256(runtime_path),
            "export records the runtime digest", str(doc.get("runtimeSha256")))
    f.check(doc.get("metadataRuntimeSha256") == doc.get("runtimeSha256"),
            "export sees metadata and runtime agree",
            str(doc.get("metadataRuntimeSha256")))
    f.check(doc.get("runtimeConfigPath") == RUNTIME_REL,
            "export reports the runtime path", str(doc.get("runtimeConfigPath")))
    f.check(isinstance(doc.get("exportedAt"), str) and doc.get("exportedAt"),
            "export records exportedAt", str(doc.get("exportedAt")))
    f.check(not doc.get("out"), "export without --out reports no out path",
            str(doc.get("out")))
    f.check(sha256(meta_path) == meta_digest, "plain export does not write metadata")
    f.check(sha256(runtime_path) == before["runtime"],
            "plain export does not write the runtime config")

    out_dir = Path(work) / "exports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "export.json"
    if out_path.exists():
        out_path.unlink()
    written = meta_cmd(f, root, "export", "--out", str(out_path))
    written_doc = f.json_of(written, "metadata export --out") if written.rc == 0 else {}
    f.check(written.rc == 0, "export --out exits 0",
            f"rc={written.rc} {written.err[:300]}")
    f.check(out_path.is_file(), "export --out writes the document", str(out_path))
    if out_path.is_file():
        f.check(mode_of(out_path) == "0o600", "export document is 0600",
                mode_of(out_path))
        on_disk = read_json(out_path)
        f.check(on_disk.get("metadataSha256") == meta_digest,
                "export file carries the metadata digest",
                str(on_disk.get("metadataSha256")))
        f.check(on_disk.get("runtimeSha256") == written_doc.get("runtimeSha256"),
                "export file agrees with the command report",
                f"{on_disk.get('runtimeSha256')} != {written_doc.get('runtimeSha256')}")
        f.check(on_disk.get("matchesMetadata") is True,
                "export file records matchesMetadata=true",
                str(on_disk.get("matchesMetadata")))
        f.check(on_disk.get("out") == str(out_path),
                "export file records its own path", str(on_disk.get("out")))
    f.check(sha256(meta_path) == meta_digest, "export --out does not write metadata")
    f.check(sha256(runtime_path) == before["runtime"],
            "export --out does not write the runtime config")

    managed = root / "etc/idleleo/conf/export.json"
    refused = meta_cmd(f, root, "export", "--out", str(managed))
    text = refused.out + refused.err
    f.check(refused.rc == 2, "export into the managed config dir exits 2",
            f"rc={refused.rc} {text[:300]}")
    f.check("refusing to export into managed path" in text,
            "managed export target explains the refusal", text[:300])
    f.check(not managed.exists(), "managed export target is not created")

    over = meta_cmd(f, root, "export", "--out", str(meta_path))
    text = over.out + over.err
    f.check(over.rc == 2, "export over metadata exits 2",
            f"rc={over.rc} {text[:300]}")
    f.check("refusing to export over manager metadata" in text,
            "metadata overwrite explains the refusal", text[:300])
    f.check(sha256(meta_path) == meta_digest, "refused export keeps metadata intact")
    return out_path


def drift_and_deactivate(f, work, root, before, old_export):
    runtime_path = root / RUNTIME_REL
    meta_path = root / METADATA_REL
    archive = root / ARCHIVE_REL
    original = runtime_path.read_bytes()
    meta_bytes = meta_path.read_bytes()

    no_export = bridge_cmd(f, root, "deactivate")
    text = no_export.out + no_export.err
    f.check(no_export.rc == 2, "deactivate without an export exits 2",
            f"rc={no_export.rc} {text[:300]}")
    f.check("--export is required" in text, "deactivate asks for the export document",
            text[:300])
    f.check(meta_path.is_file(), "deactivate without export keeps metadata")

    # Drift: a trailing newline keeps JSON valid but changes the digest.
    runtime_path.write_bytes(original + b"\n")
    drift_export = meta_cmd(f, root, "export")
    drift = f.json_of(drift_export, "drift export") if drift_export.rc == 0 else {}
    f.check(drift_export.rc == 0, "drift export still exits 0",
            f"rc={drift_export.rc} {drift_export.err[:300]}")
    f.check(drift.get("matchesMetadata") is False,
            "drift export reports matchesMetadata=false",
            str(drift.get("matchesMetadata")))
    f.check(drift.get("runtimeSha256") == sha256(runtime_path),
            "drift export fingerprints the changed runtime",
            str(drift.get("runtimeSha256")))
    f.check(drift.get("runtimeSha256") != drift.get("metadataRuntimeSha256"),
            "drift export exposes the mismatch",
            f"{drift.get('runtimeSha256')} == {drift.get('metadataRuntimeSha256')}")

    stale = bridge_cmd(f, root, "deactivate", "--export", str(old_export))
    text = stale.out + stale.err
    f.check(stale.rc == 6, "deactivate with a stale export exits 6",
            f"rc={stale.rc} {text[:300]}")
    f.check("runtime config changed since the export" in text,
            "stale deactivate names the drift", text[:300])
    f.check(meta_path.is_file(), "stale deactivate keeps metadata")
    f.check(not archive.exists(), "stale deactivate writes no archive")
    f.check(os.readlink(root / ENTRY_REL) == before["entry"],
            "stale deactivate keeps the entry link")
    f.check(sha256(root / CRON_REL) == before["cron"],
            "stale deactivate keeps cron")
    f.check(sha256(root / CERT_REL) == before["cert"],
            "stale deactivate keeps the certificate")

    drift_path = Path(work) / "exports" / "drift.json"
    made = meta_cmd(f, root, "export", "--out", str(drift_path))
    f.check(made.rc == 0, "drift export --out exits 0",
            f"rc={made.rc} {made.err[:300]}")
    inconsistent = bridge_cmd(f, root, "deactivate", "--export", str(drift_path))
    text = inconsistent.out + inconsistent.err
    f.check(inconsistent.rc == 6, "deactivate with a drifted export exits 6",
            f"rc={inconsistent.rc} {text[:300]}")
    f.check("metadata and the runtime config disagreed" in text,
            "drifted export explains why deactivate refuses", text[:300])
    f.check(meta_path.is_file(), "drifted deactivate keeps metadata")

    # Restore the exact runtime bytes, export again, then hand the root back.
    runtime_path.write_bytes(original)
    fresh_path = Path(work) / "exports" / "fresh.json"
    fresh = meta_cmd(f, root, "export", "--out", str(fresh_path))
    fresh_doc = f.json_of(fresh, "fresh export") if fresh.rc == 0 else {}
    f.check(fresh.rc == 0, "restored export exits 0",
            f"rc={fresh.rc} {fresh.err[:300]}")
    f.check(fresh_doc.get("matchesMetadata") is True,
            "restored export matches again", str(fresh_doc.get("matchesMetadata")))

    released = bridge_cmd(f, root, "deactivate", "--export", str(fresh_path))
    doc = f.json_of(released, "bridge deactivate") if released.rc == 0 else {}
    f.check(released.rc == 0, "deactivate exits 0 after restoring the runtime",
            f"rc={released.rc} {released.err[:300]}")
    f.check(doc.get("state") == "RELEASED", "deactivate state is RELEASED",
            str(doc.get("state")))
    f.check(doc.get("exportPath") == str(fresh_path),
            "deactivate reports the export document", str(doc.get("exportPath")))
    f.check(doc.get("runtimeSha256") == before["runtime"],
            "deactivate reports the original runtime digest",
            str(doc.get("runtimeSha256")))
    f.check(doc.get("metadataArchive") == str(archive),
            "deactivate reports the metadata archive", str(doc.get("metadataArchive")))
    f.check(doc.get("rillUnchanged") is True, "deactivate leaves Rill unchanged",
            str(doc.get("rillUnchanged")))
    actions = doc.get("actions") or []
    f.check(any("archived manager metadata" in a for a in actions),
            "deactivate records the archive action", str(actions))

    f.check(not meta_path.exists(), "deactivate removes the live metadata path")
    f.check(archive.is_file(), "deactivate keeps an archived copy", str(archive))
    if archive.is_file():
        f.check(archive.read_bytes() == meta_bytes,
                "archive is byte-identical to the metadata")
        f.check(mode_of(archive) == "0o640", "archive keeps the 0640 mode",
                mode_of(archive))
    f.check(os.readlink(root / ENTRY_REL) == before["entry"],
            "deactivate keeps the entry link")
    f.check(sha256(root / CRON_REL) == before["cron"], "deactivate keeps cron")
    f.check(sha256(root / CERT_REL) == before["cert"],
            "deactivate keeps the certificate")
    f.check(sha256(root / KEY_REL) == before["key"],
            "deactivate keeps the private key")
    f.check(sha256(root / "etc/idleleo/install.sh") == before["script"],
            "deactivate keeps the legacy script")
    f.check(runtime_path.read_bytes() == original,
            "deactivate keeps the runtime config byte-identical")
    f.check(sha256(root / CONFIG_REL) == before["config"],
            "deactivate keeps install_config.json byte-identical")


def bash_baseline(f, work):
    text = ""
    script = (f.bash_repo or Path(".")) / "install.sh"
    if script.is_file():
        text = script.read_text(encoding="utf-8", errors="replace")
    f.check("--backup" in text, "Bash baseline advertises --backup")
    f.check("--restore" in text, "Bash baseline advertises --restore")

    help_run = f.run([f.go, "help"], timeout=30)
    help_text = help_run.out + help_run.err
    f.check(help_run.rc == 0, "Go help exits 0",
            f"rc={help_run.rc} {help_text[:200]}")
    f.check("metadata import|export" in help_text,
            "Go help documents metadata import|export")
    f.check("--backup" not in help_text and "--restore" not in help_text,
            "Go help does not claim a backup/restore archive")

    payload = {
        "fixture": "F19",
        "bashBaseline": str(script),
        "bashHelpHasBackup": "--backup" in text,
        "bashHelpHasRestore": "--restore" in text,
        "goHelpHasMetadataImportExport": "metadata import|export" in help_text,
        "goHelpClaimsBackup": "--backup" in help_text,
        "contracts": [
            {
                "contract": "bash-backup-archive",
                "bashEvidence": "install.sh help: --backup bundles script-managed files, certificates and ACME account keys",
                "goStatus": "not-implemented",
                "reason": "metadata export records only the metadata/runtime digests; it copies no certificates or ACME keys",
            },
            {
                "contract": "bash-restore-archive",
                "bashEvidence": "install.sh help: --restore restores script-managed files; install.sh:966 refuses it because rebuilding the runtime config conflicts with the single source of truth",
                "goStatus": "not-implemented",
                "reason": "Go has no archive restore; bridge deactivate only releases metadata after proving the runtime digest is unchanged",
            },
            {
                "contract": "metadata-import",
                "bashEvidence": "Bash writes install_config.json and never derives a Go metadata record",
                "goStatus": "implemented",
                "reason": "covered by the import scenarios in this fixture",
            },
            {
                "contract": "metadata-export",
                "bashEvidence": "Bash has no metadata digest export",
                "goStatus": "implemented",
                "reason": "covered by the export scenarios in this fixture",
            },
        ],
    }
    f.write_json("bash-baseline.json", payload)


def main(f):
    f.need_root()
    work = f.evidence / "metadata-work"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)

    root, before = import_success(f, work)
    import_boundaries(f, work)
    import_failures(f, work)
    relay_case(f, work)
    old_export = export_cases(f, work, root, before)
    drift_and_deactivate(f, work, root, before, old_export)
    bash_baseline(f, work)


if __name__ == "__main__":
    sys.exit(run_fixture("F19", main))
