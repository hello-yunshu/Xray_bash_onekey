#!/usr/bin/env python3
"""F06 — user list/add/remove and single-point UUID rotation.

Preview evidence level: CONTAINER_VERIFIED (config-only, no Xray binary).

The fixture drives the real CLI against a marked sandbox root with two VLESS
inbounds. It proves:

  * `user list` reports the real clients and protects index 0 as primary,
  * `user add` appends exactly one client (and optionally one Reality shortId)
    through the change transaction: COMMITTED journal entry, atomic 0640 write,
    rollback/candidate files removed, every non-user field untouched,
  * generated UUIDs are RFC4122 v4 and duplicate email/UUID/shortId, invalid
    UUID/shortId, a missing sandbox and an unmarked root are refused with exit 2
    and zero writes,
  * `user remove` deletes exactly one secondary client, refuses the primary and
    unknown users, and keeps the rest of the document byte-identical,
  * `user uuid` rewrites every inbound that holds the email/uuid inside one
    mutation, supports `--inbound` narrowing and the `--dry-run`/no-change
    previews, and refuses a duplicate target UUID,
  * validator rejection (exit 8), injected write failure (exit 13) and injected
    service failure (exit 9) never leave a half-written config; the journal
    records REJECTED/FAILED/ROLLED_BACK,
  * Bash's UUIDv5 mapping (`UUIDv5_tranc`, `--uuid-reset`) is recorded as not
    implemented instead of being claimed as aligned.
"""
import hashlib
import json
import os
import re
import shutil
import sys
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture, sha256  # noqa: E402

SANDBOX_MARKER = ".idleleo-phase01-sandbox"
SANDBOX_VALUE = "I_ACCEPT_DISPOSABLE_SANDBOX"
CONFIG_REL = "etc/idleleo/conf/xray/config.json"
JOURNAL_REL = "var/lib/idleleo/transactions/phase01.json"

PRIMARY_UUID = "aaaaaaaa-1111-4111-8111-111111111111"
ALICE_UUID = "bbbbbbbb-2222-4222-8222-222222222222"
ALICE_2 = "bbbbbbbb-2222-4222-8222-333333333333"
ALICE_3 = "bbbbbbbb-2222-4222-8222-444444444444"
CAROL_UUID = "cccccccc-3333-4333-8333-333333333333"
DAVE_UUID = "dddddddd-4444-4444-8444-444444444444"
EVE_UUID = "eeeeeeee-5555-4555-8555-555555555555"
REALITY_KEY = "oD7nlMJVY4oXH5eom_ijOe741Y4WDjpCm6_bzYRCvmk"
SID_1 = "1111111111111111"
SID_2 = "2222222222222222"

UUID_V4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def inbound(tag, port, listen):
    return {
        "tag": tag,
        "listen": listen,
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [
                {"id": PRIMARY_UUID, "level": 0,
                 "email": "primary@example.invalid"},
                {"id": ALICE_UUID, "level": 0,
                 "email": "alice@example.invalid"},
            ],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "raw",
            "security": "reality",
            "realitySettings": {
                "target": "www.example.invalid:443",
                "serverNames": ["www.example.invalid"],
                "privateKey": REALITY_KEY,
                "shortIds": [SID_1],
            },
        },
    }


def base_config():
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "routing": {"rules": [{
            "type": "field",
            "domain": ["blocked.example.invalid"],
            "outboundTag": "direct",
        }]},
        "inbounds": [
            inbound("vless-a", 9443, "0.0.0.0"),
            inbound("vless-b", 10443, "127.0.0.1"),
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }


def build_root(work, name, marked=True, config=None):
    root = Path(work) / name
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    if marked:
        marker = root / SANDBOX_MARKER
        marker.write_text(SANDBOX_VALUE + "\n", encoding="utf-8")
        os.chmod(marker, 0o600)
    path = root / CONFIG_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config or base_config(), indent=2) + "\n",
                    encoding="utf-8")
    os.chmod(path, 0o640)
    # Real installs always have the manager state directory; post-commit
    # finalize lstats it before looking for (absent) metadata.
    v1 = root / "etc/idleleo/v1"
    v1.mkdir(parents=True, exist_ok=True)
    os.chmod(v1, 0o755)
    return root


def config_path(root):
    return Path(root) / CONFIG_REL


def load(root):
    return json.loads(config_path(root).read_text())


def clients(cfg, index=0):
    return cfg["inbounds"][index]["settings"]["clients"]


def short_ids(cfg, index=0):
    return cfg["inbounds"][index]["streamSettings"]["realitySettings"]["shortIds"]


def skeleton(cfg):
    """Deep copy with clients[] and reality shortIds[] removed."""
    out = deepcopy(cfg)
    for item in out.get("inbounds", []):
        settings = item.get("settings") or {}
        settings.pop("clients", None)
        stream = item.get("streamSettings") or {}
        reality = stream.get("realitySettings") or {}
        reality.pop("shortIds", None)
    return out


def user_cmd(f, root, *args):
    return f.run([f.go, "--root", str(root), "--json", "xray", "user", *args],
                 timeout=60)


def change_flags(root, validator="/bin/true"):
    return ["--sandbox", str(root), "--validator", validator,
            "--service", "/bin/true"]


def read_journal(root):
    path = Path(root) / JOURNAL_REL
    if not path.is_file():
        return []
    return json.loads(path.read_text())


def leftover_files(root):
    return sorted(p.name for p in config_path(root).parent.iterdir()
                  if p.name.startswith(".idleleo-phase01-"))


def mode_of(path):
    return oct(Path(path).stat().st_mode & 0o777)


def expect_added_user(f, doc, cfg, label):
    entry = (doc or {}).get("entry") or {}
    view = (doc or {}).get("user") or {}
    f.check(entry.get("state") == "COMMITTED", f"{label}: entry is COMMITTED",
            str(entry.get("state")))
    f.check(view.get("index") == len(clients(cfg)) - 1,
            f"{label}: new user index is the last client", str(view.get("index")))
    f.check(view.get("primary") is False, f"{label}: new user is not primary",
            str(view.get("primary")))
    return entry, view


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def list_cases(f, root):
    path = config_path(root)
    result = user_cmd(f, root, "list", "--path", str(path))
    doc = f.json_of(result, "user list") if result.rc == 0 else None
    f.check(result.rc == 0, "list exits 0", f"rc={result.rc} {result.err[:300]}")
    f.check(isinstance(doc, list) and len(doc) == 2,
            "list reports two clients", json.dumps(doc)[:300])
    if isinstance(doc, list) and len(doc) == 2:
        f.check(doc[0].get("uuid") == PRIMARY_UUID and doc[0].get("primary") is True,
                "list marks index 0 as primary", json.dumps(doc[0]))
        f.check(doc[1].get("uuid") == ALICE_UUID
                and doc[1].get("email") == "alice@example.invalid"
                and doc[1].get("primary") is False,
                "list reports the secondary client", json.dumps(doc[1]))
    unsupported = user_cmd(f, root, "list")
    f.check(unsupported.rc == 2, "list without --path exits 2",
            f"rc={unsupported.rc}")


def add_cases(f, work, root):
    cfg_path = config_path(root)
    before_raw = cfg_path.read_bytes()
    before_cfg = load(root)

    result = user_cmd(f, root, "add", *change_flags(root),
                      "--uuid", CAROL_UUID, "--email", "carol@example.invalid",
                      "--flow", "xtls-rprx-vision", "--level", "2",
                      "--short-id", SID_2)
    doc = f.json_of(result, "user add") if result.rc == 0 else {}
    f.check(result.rc == 0, "add exits 0", f"rc={result.rc} {result.err[:300]}")
    after_cfg = load(root)
    entry, view = expect_added_user(f, doc, after_cfg, "add")
    f.check(view.get("uuid") == CAROL_UUID, "add reports the explicit uuid",
            str(view.get("uuid")))
    f.check(view.get("email") == "carol@example.invalid",
            "add reports the email", str(view.get("email")))
    f.check(view.get("flow") == "xtls-rprx-vision", "add reports the flow",
            str(view.get("flow")))
    f.check(view.get("level") == 2, "add reports the level", str(view.get("level")))
    f.check(entry.get("target") == str(cfg_path),
            "add targets the runtime config", str(entry.get("target")))
    f.check(entry.get("servicePath") == "/bin/true",
            "add records the service command", str(entry.get("servicePath")))
    f.check(entry.get("oldSha256") == sha256_bytes(before_raw),
            "add records the old digest", str(entry.get("oldSha256")))
    f.check(entry.get("newSha256") == sha256(cfg_path),
            "add records the committed digest", str(entry.get("newSha256")))

    new_clients = clients(after_cfg)
    f.check(len(new_clients) == 3, "add appends exactly one client",
            str(len(new_clients)))
    last = new_clients[-1] if new_clients else {}
    f.check(last.get("id") == CAROL_UUID and last.get("email") == "carol@example.invalid"
            and last.get("flow") == "xtls-rprx-vision" and last.get("level") == 2,
            "add writes the client fields", json.dumps(last))
    f.check(short_ids(after_cfg) == [SID_1, SID_2],
            "add appends one Reality shortId", str(short_ids(after_cfg)))
    f.check(short_ids(after_cfg, 1) == [SID_1],
            "add leaves the other inbound shortIds alone", str(short_ids(after_cfg, 1)))
    f.check(skeleton(after_cfg) == skeleton(before_cfg),
            "add changes nothing outside clients/shortIds")
    f.check(mode_of(cfg_path) == "0o640", "add keeps the config 0640",
            mode_of(cfg_path))
    f.check(not leftover_files(root), "add leaves no rollback/candidate file",
            str(leftover_files(root)))
    journal = read_journal(root)
    f.check(bool(journal) and journal[-1].get("id") == entry.get("id")
            and journal[-1].get("state") == "COMMITTED",
            "add records a COMMITTED journal entry", json.dumps(journal[-1:])[:300])

    # Generated UUIDs are v4, and the report matches the file.
    generated = user_cmd(f, root, "add", *change_flags(root),
                         "--email", "dave@example.invalid")
    gen_doc = f.json_of(generated, "generated add") if generated.rc == 0 else {}
    gen_user = gen_doc.get("user") or {}
    f.check(generated.rc == 0, "add without --uuid exits 0",
            f"rc={generated.rc} {generated.err[:300]}")
    f.check(bool(UUID_V4.match(gen_user.get("uuid") or "")),
            "generated uuid is RFC4122 v4", str(gen_user.get("uuid")))
    dave = clients(load(root))[-1]
    f.check(dave.get("id") == gen_user.get("uuid"),
            "generated uuid reaches the runtime config", json.dumps(dave))
    f.check(dave.get("level") == 0 and not dave.get("flow"),
            "generated user defaults level=0 and no flow", json.dumps(dave))

    return before_cfg


def add_refusal_cases(f, work, root, before_cfg):
    cfg_path = config_path(root)
    before_raw = cfg_path.read_bytes()
    journal_before = len(read_journal(root))

    cases = [
        ("duplicate email", ["--uuid", "ffffffff-6666-4666-8666-666666666666",
                             "--email", "alice@example.invalid"], "email already exists"),
        ("duplicate uuid", ["--uuid", ALICE_UUID,
                            "--email", "unique@example.invalid"], "uuid already exists"),
        ("invalid uuid", ["--uuid", "not-a-uuid",
                          "--email", "bad@example.invalid"], "valid RFC4122"),
        ("invalid shortId", ["--uuid", "ffffffff-6666-4666-8666-666666666666",
                             "--email", "sid@example.invalid",
                             "--short-id", "xyz"], "1-16 hex"),
        ("duplicate shortId", ["--uuid", "ffffffff-6666-4666-8666-666666666666",
                               "--email", "dup@example.invalid",
                               "--short-id", SID_1], "shortId already present"),
    ]
    for label, args, needle in cases:
        result = user_cmd(f, root, "add", *change_flags(root), *args)
        text = result.out + result.err
        f.check(result.rc == 2, f"{label}: add exits 2",
                f"rc={result.rc} {text[:300]}")
        f.check(needle in text, f"{label}: add explains the refusal", text[:300])
        f.check(cfg_path.read_bytes() == before_raw,
                f"{label}: config is byte-identical")
        f.check(len(read_journal(root)) == journal_before,
                f"{label}: no journal entry is written")

    without_sandbox = user_cmd(f, root, "add", "--validator", "/bin/true",
                               "--email", "nosandbox@example.invalid")
    text = without_sandbox.out + without_sandbox.err
    f.check(without_sandbox.rc == 2, "add without --sandbox exits 2",
            f"rc={without_sandbox.rc} {text[:300]}")
    f.check(cfg_path.read_bytes() == before_raw,
            "add without --sandbox writes nothing")

    unmarked = build_root(work, "unmarked", marked=False, config=before_cfg)
    refused = user_cmd(f, unmarked, "add", *change_flags(unmarked),
                       "--email", "x@example.invalid")
    text = refused.out + refused.err
    f.check(refused.rc == 2, "add in an unmarked root exits 2",
            f"rc={refused.rc} {text[:300]}")
    f.check("write access refused" in text or "sandbox" in text.lower(),
            "unmarked add names the write gate", text[:300])
    f.check(config_path(unmarked).read_bytes() == before_raw,
            "unmarked add writes nothing")


def remove_cases(f, root):
    cfg_path = config_path(root)

    dave_uuid = clients(load(root))[-1]["id"]
    result = user_cmd(f, root, "remove", *change_flags(root),
                      "--email", "dave@example.invalid")
    doc = f.json_of(result, "user remove") if result.rc == 0 else {}
    f.check(result.rc == 0, "remove by email exits 0",
            f"rc={result.rc} {result.err[:300]}")
    f.check((doc.get("entry") or {}).get("state") == "COMMITTED",
            "remove entry is COMMITTED",
            str((doc.get("entry") or {}).get("state")))
    f.check((doc.get("user") or {}).get("uuid") == dave_uuid,
            "remove reports the removed uuid",
            str((doc.get("user") or {}).get("uuid")))
    ids = [c["id"] for c in clients(load(root))]
    f.check(dave_uuid not in ids and ALICE_2 in ids,
            "remove deletes exactly the requested user", str(ids))

    result = user_cmd(f, root, "remove", *change_flags(root),
                      "--uuid", ALICE_2)
    f.check(result.rc == 0, "remove by uuid exits 0",
            f"rc={result.rc} {result.err[:300]}")
    remaining = clients(load(root))
    f.check(len(remaining) == 2
            and [c.get("email") for c in remaining]
            == ["primary@example.invalid", "carol@example.invalid"],
            "remove by uuid deletes exactly that client", json.dumps(remaining))

    before_raw = cfg_path.read_bytes()
    primary = user_cmd(f, root, "remove", *change_flags(root),
                       "--email", "primary@example.invalid")
    text = primary.out + primary.err
    f.check(primary.rc == 2, "removing the primary user exits 2",
            f"rc={primary.rc} {text[:300]}")
    f.check("refusing to remove the primary user" in text,
            "primary removal explains the refusal", text[:300])
    f.check(cfg_path.read_bytes() == before_raw,
            "primary removal writes nothing")

    missing = user_cmd(f, root, "remove", *change_flags(root),
                       "--email", "ghost@example.invalid")
    text = missing.out + missing.err
    f.check(missing.rc == 2, "removing an unknown user exits 2",
            f"rc={missing.rc} {text[:300]}")
    f.check("user not found" in text, "unknown removal explains the refusal",
            text[:300])
    f.check(cfg_path.read_bytes() == before_raw,
            "unknown removal writes nothing")


def failure_cases(f, root):
    cfg_path = config_path(root)
    before_raw = cfg_path.read_bytes()
    journal_before = len(read_journal(root))

    rejected = user_cmd(f, root, "add", *change_flags(root, validator="/bin/false"),
                        "--uuid", EVE_UUID, "--email", "eve@example.invalid")
    doc = f.json_of(rejected, "validator rejection") if rejected.rc == 8 else {}
    text = rejected.out + rejected.err
    f.check(rejected.rc == 8, "validator rejection exits 8",
            f"rc={rejected.rc} {text[:300]}")
    f.check(doc.get("state") == "REJECTED", "validator rejection is REJECTED",
            str(doc.get("state")))
    f.check(doc.get("validatorExit") == 1, "validator rejection records exit 1",
            str(doc.get("validatorExit")))
    f.check(cfg_path.read_bytes() == before_raw,
            "validator rejection leaves the config byte-identical")
    f.check(not leftover_files(root), "validator rejection cleans candidates",
            str(leftover_files(root)))
    journal = read_journal(root)
    f.check(len(journal) == journal_before + 1
            and journal[-1].get("state") == "REJECTED",
            "validator rejection records REJECTED", json.dumps(journal[-1:])[:300])

    write_fail = user_cmd(f, root, "add", *change_flags(root),
                          "--uuid", EVE_UUID, "--email", "eve@example.invalid",
                          "--fault", "write-fail")
    doc = f.json_of(write_fail, "write-fail") if write_fail.rc == 13 else {}
    text = write_fail.out + write_fail.err
    f.check(write_fail.rc == 13, "injected write failure exits 13",
            f"rc={write_fail.rc} {text[:300]}")
    f.check(doc.get("state") == "FAILED", "write failure is FAILED",
            str(doc.get("state")))
    f.check(cfg_path.read_bytes() == before_raw,
            "write failure leaves the config byte-identical")
    journal = read_journal(root)
    f.check(journal[-1].get("state") == "FAILED",
            "write failure records FAILED", json.dumps(journal[-1:])[:300])

    service_fail = user_cmd(f, root, "add", *change_flags(root),
                            "--uuid", EVE_UUID, "--email", "eve@example.invalid",
                            "--fault", "service-fail")
    doc = f.json_of(service_fail, "service-fail") if service_fail.rc == 9 else {}
    text = service_fail.out + service_fail.err
    f.check(service_fail.rc == 9, "injected service failure exits 9",
            f"rc={service_fail.rc} {text[:300]}")
    f.check(doc.get("state") == "ROLLED_BACK", "service failure is ROLLED_BACK",
            str(doc.get("state")))
    f.check(cfg_path.read_bytes() == before_raw,
            "service failure restores the config byte-identical")
    f.check(not leftover_files(root),
            "service failure removes the rollback snapshot",
            str(leftover_files(root)))
    journal = read_journal(root)
    f.check(journal[-1].get("state") == "ROLLED_BACK",
            "service failure records ROLLED_BACK", json.dumps(journal[-1:])[:300])

    unknown = user_cmd(f, root, "add", *change_flags(root),
                       "--uuid", EVE_UUID, "--email", "eve@example.invalid",
                       "--fault", "bogus")
    text = unknown.out + unknown.err
    f.check(unknown.rc == 2, "unknown fault injector exits 2",
            f"rc={unknown.rc} {text[:300]}")
    f.check(cfg_path.read_bytes() == before_raw,
            "unknown fault injector writes nothing")


def uuid_cases(f, root):
    cfg_path = config_path(root)
    before_cfg = load(root)
    before_raw = cfg_path.read_bytes()

    result = user_cmd(f, root, "uuid", "--email", "alice@example.invalid",
                      "--new-uuid", ALICE_2, *change_flags(root))
    doc = f.json_of(result, "user uuid") if result.rc == 0 else {}
    entry = doc.get("entry") or {}
    change = doc.get("change") or {}
    f.check(result.rc == 0, "uuid rotation exits 0",
            f"rc={result.rc} {result.err[:300]}")
    f.check(entry.get("state") == "COMMITTED", "uuid rotation is COMMITTED",
            str(entry.get("state")))
    f.check(entry.get("newSha256") == sha256(cfg_path),
            "uuid rotation records the committed digest",
            str(entry.get("newSha256")))
    previous = change.get("Previous") or []
    updated = change.get("Updated") or []
    f.check(len(previous) == 2 and len(updated) == 2,
            "uuid rotation matches both inbounds", f"{len(previous)}/{len(updated)}")
    f.check(sorted(ref.get("Inbound") for ref in previous) == [0, 1],
            "uuid rotation reports both inbound indices",
            str([ref.get("Inbound") for ref in previous]))
    f.check(all((ref.get("User") or {}).get("uuid") == ALICE_UUID for ref in previous),
            "uuid rotation reports the old credential",
            json.dumps(previous)[:300])
    f.check(all((ref.get("User") or {}).get("uuid") == ALICE_2 for ref in updated),
            "uuid rotation reports the new credential",
            json.dumps(updated)[:300])
    after_cfg = load(root)
    for index in (0, 1):
        f.check(clients(after_cfg, index)[1]["id"] == ALICE_2,
                f"inbound {index} carries the new alice uuid",
                str(clients(after_cfg, index)[1]["id"]))
        f.check(clients(after_cfg, index)[0]["id"] == PRIMARY_UUID,
                f"inbound {index} keeps the primary uuid",
                str(clients(after_cfg, index)[0]["id"]))
    f.check(skeleton(after_cfg) == skeleton(before_cfg),
            "uuid rotation changes nothing outside clients[].id")
    f.check(mode_of(cfg_path) == "0o640", "uuid rotation keeps the config 0640",
            mode_of(cfg_path))
    f.check(not leftover_files(root), "uuid rotation leaves no temporary files",
            str(leftover_files(root)))

    # Current credential: explicit no-change preview, no transaction.
    after_rotation_raw = cfg_path.read_bytes()
    journal_before = len(read_journal(root))
    same = user_cmd(f, root, "uuid", "--email", "alice@example.invalid",
                    "--new-uuid", ALICE_2, *change_flags(root))
    same_doc = f.json_of(same, "no-change uuid") if same.rc == 0 else {}
    f.check(same.rc == 0, "no-change uuid exits 0", f"rc={same.rc} {same.err[:300]}")
    f.check((same_doc.get("change") or {}).get("NoChanges") is True,
            "no-change uuid is reported",
            str((same_doc.get("change") or {}).get("NoChanges")))
    f.check(cfg_path.read_bytes() == after_rotation_raw,
            "no-change uuid writes nothing")
    f.check(len(read_journal(root)) == journal_before,
            "no-change uuid records no journal entry")

    dry = user_cmd(f, root, "uuid", "--email", "alice@example.invalid",
                   "--new-uuid", "ffffffff-7777-4777-8777-777777777777",
                   "--dry-run", *change_flags(root))
    dry_doc = f.json_of(dry, "dry-run uuid") if dry.rc == 0 else {}
    f.check(dry.rc == 0, "dry-run uuid exits 0", f"rc={dry.rc} {dry.err[:300]}")
    f.check(dry_doc.get("dryRun") is True, "dry-run uuid reports dryRun",
            str(dry_doc.get("dryRun")))
    f.check(cfg_path.read_bytes() == after_rotation_raw,
            "dry-run uuid writes nothing")

    # --inbound narrowing touches one inbound and leaves the other alone.
    narrowed = user_cmd(f, root, "uuid", "--uuid", ALICE_2,
                        "--new-uuid", ALICE_3, "--inbound", "1",
                        *change_flags(root))
    narrow_doc = f.json_of(narrowed, "narrowed uuid") if narrowed.rc == 0 else {}
    narrow_change = narrow_doc.get("change") or {}
    f.check(narrowed.rc == 0, "narrowed uuid rotation exits 0",
            f"rc={narrowed.rc} {narrowed.err[:300]}")
    f.check(len(narrow_change.get("Previous") or []) == 1
            and (narrow_change.get("Previous") or [{}])[0].get("Inbound") == 1,
            "narrowed rotation only reports inbound 1",
            json.dumps(narrow_change.get("Previous"))[:300])
    after_cfg = load(root)
    f.check(clients(after_cfg, 0)[1]["id"] == ALICE_2
            and clients(after_cfg, 1)[1]["id"] == ALICE_3,
            "narrowed rotation leaves inbound 0 on the old uuid",
            f"{clients(after_cfg, 0)[1]['id']} / {clients(after_cfg, 1)[1]['id']}")

    narrowed_raw = cfg_path.read_bytes()

    duplicate = user_cmd(f, root, "uuid", "--email", "alice@example.invalid",
                         "--new-uuid", PRIMARY_UUID, *change_flags(root))
    text = duplicate.out + duplicate.err
    f.check(duplicate.rc == 2, "uuid rotation onto another user exits 2",
            f"rc={duplicate.rc} {text[:300]}")
    f.check("uuid already used" in text, "duplicate uuid explains the refusal",
            text[:300])
    f.check(cfg_path.read_bytes() == narrowed_raw,
            "duplicate uuid leaves the config untouched")

    invalid = user_cmd(f, root, "uuid", "--email", "alice@example.invalid",
                       "--new-uuid", "nope", *change_flags(root))
    text = invalid.out + invalid.err
    f.check(invalid.rc == 2, "invalid --new-uuid exits 2",
            f"rc={invalid.rc} {text[:300]}")
    f.check(cfg_path.read_bytes() == narrowed_raw,
            "invalid --new-uuid leaves the config untouched")

    failed = user_cmd(f, root, "uuid", "--email", "alice@example.invalid",
                      "--new-uuid", "ffffffff-7777-4777-8777-777777777777",
                      "--fault", "service-fail", *change_flags(root))
    failed_doc = f.json_of(failed, "uuid service-fail") if failed.rc == 9 else {}
    f.check(failed.rc == 9, "uuid service failure exits 9",
            f"rc={failed.rc} {(failed.out + failed.err)[:300]}")
    f.check(failed_doc.get("state") == "ROLLED_BACK",
            "uuid service failure is ROLLED_BACK", str(failed_doc.get("state")))
    f.check(cfg_path.read_bytes() == narrowed_raw,
            "uuid service failure restores every inbound")
    f.check(not leftover_files(root),
            "uuid service failure removes the rollback snapshot",
            str(leftover_files(root)))

    f.check(sha256(cfg_path) != sha256_bytes(before_raw),
            "uuid scenarios actually rewrote the config")


def uuidv5_baseline(f, work):
    text = ""
    script = (f.bash_repo or Path(".")) / "install.sh"
    if script.is_file():
        text = script.read_text(encoding="utf-8", errors="replace")
    f.check("UUIDv5_tranc" in text, "Bash baseline implements UUIDv5_tranc")
    f.check("--uuid-reset" in text, "Bash baseline advertises --uuid-reset")

    help_run = f.run([f.go, "help"], timeout=30)
    help_text = (help_run.out + help_run.err).lower()
    f.check("uuidv5" not in help_text,
            "Go help does not claim UUIDv5 mapping")
    f.check("user list|add|remove" in help_text,
            "Go help documents user list|add|remove")

    payload = {
        "fixture": "F06",
        "bashBaseline": str(script),
        "bashHasUUIDv5Tranc": "UUIDv5_tranc" in text,
        "bashHasUUIDReset": "--uuid-reset" in text,
        "goHelpClaimsUUIDv5": "uuidv5" in help_text,
        "contracts": [
            {
                "contract": "user list/add/remove",
                "bashEvidence": "install.sh user menu edits the runtime config directly",
                "goStatus": "implemented",
                "reason": "covered by the list/add/remove scenarios in this fixture",
            },
            {
                "contract": "single-user uuid rotation",
                "bashEvidence": "install.sh --uuid-reset rewrites the selected client",
                "goStatus": "implemented",
                "reason": "covered by the multi-inbound uuid scenarios in this fixture",
            },
            {
                "contract": "UUIDv5 mapping",
                "bashEvidence": "install.sh:4291 asks for a UUIDv5 mapping string and install.sh:4650 defines UUIDv5_tranc",
                "goStatus": "not-implemented",
                "reason": "Go generates random RFC4122 v4 for new users and has no UUIDv5 mapping flag",
            },
        ],
    }
    f.write_json("baseline-compare.json", payload)


def main(f):
    f.need_root()
    work = f.evidence / "user-work"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)

    root = build_root(work, "node")
    list_cases(f, root)
    before_cfg = add_cases(f, work, root)
    add_refusal_cases(f, work, root, load(root))
    uuid_cases(f, root)
    failure_cases(f, root)
    remove_cases(f, root)
    uuidv5_baseline(f, work)

    # The untouched skeleton still matches the original document.
    f.check(skeleton(load(root)) == skeleton(before_cfg),
            "the final config still matches the original skeleton")


if __name__ == "__main__":
    sys.exit(run_fixture("F06", main))
