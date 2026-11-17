#!/usr/bin/env python3
"""F07 — Reality shortId, spiderX and per-client binding.

Preview evidence level: CONTAINER_VERIFIED (config-level: the real Go binary is
executed against real Xray JSON configs; the fixed Bash baseline functions are
extracted from install.sh and executed for real; no Xray data plane, no systemd,
no root on the host, no network).

The fixture proves what the Go manager really does with shortIds:

* `xray generate --mode reality` writes one accepted shortId into the runtime
  config and into the share URI, and it is 8 lowercase hex characters;
* explicit shortIds survive byte for byte, while odd/over-long/non-hex values
  are refused with rc=2 and leave no file behind;
* `xray user add --short-id` appends the sID and the client in one committed
  transaction, refuses duplicates, invalid values and non-Reality inbounds, and
  writes nothing on every refusal;
* `xray share` derives `sid` from the inbound sID list, applies metadata
  `shareLinkOnly` fingerprint/spiderX without touching the runtime config, and
  rejects unknown users;
* `xray config edit --short-id-list` prints one link per accepted sID and does
  not write.

Everything the Bash baseline does differently is recorded in
`baseline-compare.json` instead of being claimed as parity: Bash generates a
16-hex sID, requires exactly 16 hex for custom values, auto-creates a spiderX
and a per-user `reality_clients` map, and URL-quotes spiderX in the link.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

SID_PRIMARY = "1111111111111111"
SID_NEW = "2222222222222222"
HEX8 = re.compile(r"^[0-9a-f]{8}$")
HEX16 = re.compile(r"^[0-9a-f]{16}$")
PBK = re.compile(r"^[A-Za-z0-9_-]{43}$")
SPIDERX = re.compile(r"^/(assets|static|docs|api)/[A-Za-z0-9._/-]*$")
LIST_LINE = re.compile(r'^short-id="([^"]+)" share: (\S+)$')
BASH_FUNCTIONS = ("generate_reality_short_id", "generate_spiderx")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path, payload, mode=0o600):
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, mode)


def split_uri(uri):
    parts = urlsplit(uri)
    return parts, parse_qs(parts.query)


def short_ids(config):
    return config["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"]


def clients(config):
    return config["inbounds"][0]["settings"]["clients"]


def inbound_without_users(config):
    """Return inbound 0 with the two user-bearing fields neutralized."""
    clone = json.loads(json.dumps(config))
    clone["inbounds"][0]["settings"]["clients"] = None
    clone["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"] = None
    return clone


def extract_bash_function(text, name):
    match = re.search(rf"^{name}\(\) \{{\n(.*?)^\}}$", text, re.MULTILINE | re.DOTALL)
    return match.group(0) if match else None


def mark_sandbox(root):
    root = Path(root)
    marker = root / ".idleleo-phase01-sandbox"
    marker.write_text("I_ACCEPT_DISPOSABLE_SANDBOX\n", encoding="utf-8")
    os.chmod(marker, 0o600)


def native_metadata(root, config_path, link_only=None):
    meta = {
        "schemaVersion": 1,
        "activeEngine": "xray",
        "provenance": "native",
        "role": "node",
        "tls": "Reality",
        "transport": "raw",
        "runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
        "runtimeSha256": sha256_file(config_path),
        "ownedResources": ["etc/idleleo/conf/xray/config.json"],
        "updatedAt": "2026-11-17T00:00:00Z",
    }
    if link_only:
        meta["shareLinkOnly"] = link_only
    path = Path(root) / "etc/idleleo/v1/metadata.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, meta)
    return path


def main(f):
    f.need(f.bash_repo is not None,
           "F07 requires --bash-repo for the fixed Bash shortId/spiderX baseline")

    work = f.evidence / "f07-work"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    install_sh = f.bash_repo / "install.sh"
    install_text = install_sh.read_text(encoding="utf-8")
    observed = {"autoShortIds": [], "explicitShortIds": []}

    # ---- S1: generate auto shortId --------------------------------------
    gen1 = work / "gen1.json"
    gen2 = work / "gen2.json"
    r1 = f.run([f.go, "xray", "generate", "--mode", "reality", "--domain",
                "example.com", "--port", "8443", "--out", gen1, "--json"])
    r2 = f.run([f.go, "xray", "generate", "--mode", "reality", "--domain",
                "example.com", "--port", "8443", "--out", gen2, "--json"])
    payload1 = f.json_of(r1, "generate#1") if f.check(r1.rc == 0, "generate#1 rc=0", r1.text[:200]) else None
    payload2 = f.json_of(r2, "generate#2") if r2.rc == 0 else None
    f.check(r1.rc == 0 and gen1.is_file(), "generate#1 wrote config", str(gen1))
    f.check(r2.rc == 0 and gen2.is_file(), "generate#2 wrote config", str(gen2))
    if payload1 and payload2:
        sid1 = payload1["shortId"]
        sid2 = payload2["shortId"]
        observed["autoShortIds"] = [sid1, sid2]
        cfg1 = read_json(gen1)
        f.check(HEX8.match(sid1) is not None,
                "auto shortId is 8 lowercase hex", sid1)
        f.check(sid1 != sid2, "two runs generate different shortId", f"{sid1} != {sid2}")
        f.check(short_ids(cfg1) == [sid1],
                "runtime config shortIds equals generated value", json.dumps(short_ids(cfg1)))
        f.check(payload1["shortIds"] == [sid1], "JSON shortIds mirrors config")
        parts, query = split_uri(payload1["shareUri"])
        f.check(parts.scheme == "vless", "share URI scheme is vless", parts.scheme)
        f.check(parts.username == payload1["uuid"], "share URI carries the client UUID")
        f.check(parts.hostname == "example.com" and parts.port == 8443,
                "share URI host/port", f"{parts.hostname}:{parts.port}")
        f.check(query.get("sid") == [sid1], "share URI sid equals generated shortId",
                str(query.get("sid")))
        f.check(query.get("security") == ["reality"], "share URI security=reality")
        f.check(query.get("flow") == ["xtls-rprx-vision"], "share URI flow")
        f.check(query.get("fp") == ["chrome"], "share URI default fingerprint is chrome")
        f.check(query.get("type") == ["raw"], "share URI type=raw")
        f.check("target" not in query,
                "share URI has no target (Bash template does)", str(query.keys()))
        f.check("spx" not in query, "auto generate does not invent spiderX")
        f.check(PBK.match(query.get("pbk", [""])[0]) is not None,
                "share URI public key is 43-char base64url")
        f.check(stat.S_IMODE(gen1.stat().st_mode) == 0o600,
                "generated config mode is 0600", oct(stat.S_IMODE(gen1.stat().st_mode)))

    # ---- S2: explicit shortId and refusals ------------------------------
    explicit16 = work / "sid16.json"
    r = f.run([f.go, "xray", "generate", "--mode", "reality", "--domain",
               "example.com", "--port", "8443", "--out", explicit16,
               "--short-id", SID_PRIMARY, "--json"])
    payload = f.json_of(r, "generate explicit16") if r.rc == 0 else None
    f.check(r.rc == 0 and explicit16.is_file(), "explicit 16-hex shortId accepted", r.text[:120])
    if payload:
        observed["explicitShortIds"].append(payload["shortId"])
        f.check(payload["shortId"] == SID_PRIMARY, "explicit shortId echoed", payload["shortId"])
        f.check(short_ids(read_json(explicit16)) == [SID_PRIMARY],
                "explicit shortId written to config")
        _, query = split_uri(payload["shareUri"])
        f.check(query.get("sid") == [SID_PRIMARY], "explicit shortId in share URI")

    explicit4 = work / "sid4.json"
    r = f.run([f.go, "xray", "generate", "--mode", "reality", "--domain",
               "example.com", "--port", "8443", "--out", explicit4,
               "--short-id", "abcd", "--json"])
    payload4 = f.json_of(r, "generate explicit4") if r.rc == 0 else None
    f.check(r.rc == 0 and explicit4.is_file(),
            "4-hex shortId accepted (Bash requires 16)", r.text[:120])
    if payload4:
        observed["explicitShortIds"].append(payload4["shortId"])
        f.check(short_ids(read_json(explicit4)) == ["abcd"], "4-hex shortId persisted")

    bad_values = {
        "odd": "abc",
        "too_long": "0123456789abcdef0",
        "not_hex": "zzzz",
        "space": "ab cd",
    }
    for label, value in bad_values.items():
        out = work / f"bad-{label}.json"
        r = f.run([f.go, "xray", "generate", "--mode", "reality", "--domain",
                   "example.com", "--port", "8443", "--out", out,
                   "--short-id", value])
        f.check(r.rc == 2, f"invalid shortId ({label}) rc=2", r.text[:160])
        f.check(not out.exists(), f"invalid shortId ({label}) writes no file")

    empty = work / "sid-empty.json"
    r = f.run([f.go, "xray", "generate", "--mode", "reality", "--domain",
               "example.com", "--port", "8443", "--out", empty,
               "--short-id", "", "--json"])
    payload_empty = f.json_of(r, "generate empty shortId") if r.rc == 0 else None
    f.check(r.rc == 0, "empty shortId falls back to auto generation", r.text[:160])
    if payload_empty:
        f.check(HEX8.match(payload_empty["shortId"]) is not None,
                "empty shortId produced 8-hex value", payload_empty["shortId"])

    # ---- S3: user add --short-id ---------------------------------------
    root = work / "root"
    cfg_path = root / "etc/idleleo/conf/xray/config.json"
    cfg_path.parent.mkdir(parents=True)
    (root / "etc/idleleo/v1").mkdir(parents=True)
    shutil.copyfile(gen1, cfg_path)
    os.chmod(cfg_path, 0o640)
    mark_sandbox(root)
    auto_sid = short_ids(read_json(cfg_path))[0]
    before = inbound_without_users(read_json(cfg_path))

    def add_user(email, extra=(), config_root=root):
        return f.run([f.go, "--root", config_root, "xray", "user", "add",
                      "--sandbox", config_root, "--validator", "/bin/true",
                      "--service", "/bin/true", "--email", email, "--json", *extra])

    r = add_user("sid@example.invalid", ["--short-id", SID_NEW])
    payload = f.json_of(r, "user add with shortId") if r.rc == 0 else None
    f.check(r.rc == 0, "user add --short-id rc=0", r.text[:200])
    if payload:
        f.check(payload["entry"]["state"] == "COMMITTED",
                "user add transaction COMMITTED", payload["entry"]["state"])
        f.check(payload["user"]["email"] == "sid@example.invalid",
                "user add returned the new client")
    after = read_json(cfg_path)
    f.check(short_ids(after) == [auto_sid, SID_NEW],
            "user add appends the shortId", json.dumps(short_ids(after)))
    f.check(len(clients(after)) == 2, "user add appends exactly one client",
            str(len(clients(after))))
    f.check(inbound_without_users(after) == before,
            "user add leaves non-user fields unchanged")
    f.check(stat.S_IMODE(cfg_path.stat().st_mode) == 0o640,
            "user add keeps config mode 0640", oct(stat.S_IMODE(cfg_path.stat().st_mode)))

    r = add_user("nosid@example.invalid")
    f.check(r.rc == 0, "user add without --short-id rc=0", r.text[:200])
    after = read_json(cfg_path)
    f.check(short_ids(after) == [auto_sid, SID_NEW],
            "user add without shortId does not mint one (Bash mints a fresh sID)")
    f.check(len(clients(after)) == 3, "plain user add appended a client")

    stable = sha256_file(cfg_path)
    r = add_user("dup@example.invalid", ["--short-id", SID_NEW])
    f.check(r.rc == 2, "duplicate shortId rc=2", r.text[:160])
    f.check("shortId already present" in r.text, "duplicate shortId is named in the error")
    f.check(sha256_file(cfg_path) == stable, "duplicate shortId writes nothing")

    r = add_user("bad@example.invalid", ["--short-id", "abc"])
    f.check(r.rc == 2, "invalid shortId on user add rc=2", r.text[:160])
    f.check(sha256_file(cfg_path) == stable, "invalid shortId on user add writes nothing")

    leftovers = [p.name for p in cfg_path.parent.iterdir() if ".idleleo-phase01-" in p.name]
    f.check(not leftovers, "no transaction leftovers after refusals", str(leftovers))

    ws_root = work / "ws-root"
    ws_cfg = ws_root / "etc/idleleo/conf/xray/config.json"
    ws_cfg.parent.mkdir(parents=True)
    (ws_root / "etc/idleleo/v1").mkdir(parents=True)
    ws_payload = read_json(gen1)
    ws_payload["inbounds"][0]["streamSettings"] = {
        "network": "ws", "security": "tls", "wsSettings": {"path": "/ws"}}
    write_json(ws_cfg, ws_payload)
    mark_sandbox(ws_root)
    ws_before = sha256_file(ws_cfg)
    r = add_user("reality-only@example.invalid", ["--short-id", SID_NEW], ws_root)
    f.check(r.rc == 2, "--short-id on a non-Reality inbound rc=2", r.text[:160])
    f.check("requires a Reality inbound" in r.text,
            "non-Reality refusal explains the requirement")
    f.check(sha256_file(ws_cfg) == ws_before, "non-Reality refusal writes nothing")

    # ---- S4: share derives sid and honours link-only preferences --------
    cfg_sha = sha256_file(cfg_path)
    r = f.run([f.go, "--root", root, "xray", "share", "--path", cfg_path,
               "--host", "example.com", "--json"])
    share = f.json_of(r, "share#1") if r.rc == 0 else None
    f.check(r.rc == 0, "share rc=0", r.text[:200])
    if share:
        _, query = split_uri(share["shareUri"])
        f.check(query.get("sid") == [auto_sid],
                "share sid is the first accepted inbound shortId", str(query.get("sid")))
        f.check("spx" not in query, "share has no spx without metadata preference")
        f.check(query.get("fp") == ["chrome"], "share defaults to chrome")
    f.check(sha256_file(cfg_path) == cfg_sha, "share does not modify the runtime config")

    native_metadata(root, cfg_path, link_only={
        "fingerprint": "firefox", "spiderX": "/assets/abc.css"})
    r = f.run([f.go, "--root", root, "xray", "share", "--path", cfg_path,
               "--host", "example.com", "--json"])
    share_pref = f.json_of(r, "share#2") if r.rc == 0 else None
    f.check(r.rc == 0, "share with link-only metadata rc=0", r.text[:200])
    if share_pref:
        _, query = split_uri(share_pref["shareUri"])
        f.check(query.get("fp") == ["firefox"],
                "metadata fingerprint decorates the link", str(query.get("fp")))
        f.check(query.get("spx") == ["/assets/abc.css"],
                "metadata spiderX decorates the link (literal, Bash quotes it)",
                str(query.get("spx")))
        f.check(query.get("sid") == [auto_sid], "link preferences keep the inbound sid")
    f.check(sha256_file(cfg_path) == cfg_sha,
            "link-only preferences never rewrite the runtime config")

    r = f.run([f.go, "--root", root, "xray", "share", "--path", cfg_path,
               "--host", "example.com", "--user", "sid@example.invalid", "--json"])
    share_user = f.json_of(r, "share by user") if r.rc == 0 else None
    f.check(r.rc == 0, "share --user rc=0", r.text[:200])
    if share_user:
        _, query = split_uri(share_user["shareUri"])
        f.check(share_user["email"] == "sid@example.invalid",
                "share --user selects the requested client")
        f.check(query.get("sid") == [auto_sid],
                "share keeps the inbound sid for a client added with another sID")
        f.check(query.get("sid") != [SID_NEW],
                "share has no per-client sID binding (Bash mapping missing)")

    r = f.run([f.go, "--root", root, "xray", "share", "--path", cfg_path,
               "--host", "example.com", "--user", "ghost@example.invalid", "--json"])
    f.check(r.rc == 1, "share with unknown user rc=1", r.text[:160])
    f.check("not found" in r.text, "unknown user error is explicit")
    f.check("vless://" not in r.out, "unknown user produces no URI")

    # ---- S5: short-id-list is read-only ---------------------------------
    list_before = sha256_file(cfg_path)
    r = f.run([f.go, "--root", root, "xray", "config", "edit", "--path",
               cfg_path, "--short-id-list"])
    lines = [line for line in r.out.splitlines() if line.strip()]
    f.check(r.rc == 0, "short-id-list rc=0", r.text[:200])
    f.check(len(lines) == len(short_ids(read_json(cfg_path))),
            "short-id-list prints one line per accepted sid",
            f"{len(lines)} lines / {len(short_ids(read_json(cfg_path)))} sids")
    parsed = []
    for line in lines:
        match = LIST_LINE.match(line)
        if not match:
            f.bad("short-id-list line shape", line[:200])
            continue
        parsed.append((match.group(1), match.group(2)))
    f.check(len(parsed) == len(lines), "every listed line is short-id/share shape")
    f.check([sid for sid, _ in parsed] == short_ids(read_json(cfg_path)),
            "listed shortIds match the config order")
    for sid, uri in parsed:
        _, query = split_uri(uri)
        f.check(query.get("sid") == [sid], f"listed link carries sid={sid}")
    f.check(sha256_file(cfg_path) == list_before,
            "short-id-list writes nothing")

    # ---- S6: fixed Bash baseline ---------------------------------------
    bash_runs = {}
    for name in BASH_FUNCTIONS:
        definition = extract_bash_function(install_text, name)
        f.check(definition is not None, f"Bash function {name} found in install.sh")
        if not definition:
            bash_runs[name] = []
            continue
        script = definition + f"\nfor i in 1 2 3; do {name}; done\n"
        r = f.run(["/bin/bash", "-c", script])
        f.check(r.rc == 0, f"Bash {name} executed", r.text[:160])
        bash_runs[name] = [line for line in r.out.splitlines() if line.strip()]
        f.check(len(bash_runs[name]) == 3, f"Bash {name} produced 3 values",
                str(len(bash_runs[name])))

    for value in bash_runs.get("generate_reality_short_id", []):
        f.check(HEX16.match(value) is not None, "Bash auto shortId is 16 hex", value)
    for value in bash_runs.get("generate_spiderx", []):
        f.check(SPIDERX.match(value) is not None, "Bash spiderX shape", value)

    f.check("^[0-9a-fA-F]{16}$" in install_text,
            "Bash custom shortId must be exactly 16 hex")
    f.check('.reality_clients[$uuid] = {"shortIds": $shortId, "spiderx_path": $spx}'
            in install_text, "Bash keeps a per-user reality_clients mapping")
    f.check('spx_param="&spx=$(vless_urlquote "${spx}")"' in install_text,
            "Bash URL-quotes spiderX in the link")
    f.check("&target=${target}" in install_text,
            "Bash reality link template includes target")

    f.write_json("baseline-compare.json", {
        "fixture": "F07",
        "bashBaseline": {
            "installShSha256": sha256_file(install_sh),
            "bashFunctionsExecuted": bash_runs,
        },
        "contracts": [
            {
                "id": "generate.auto.shortId.shape",
                "go": "8 lowercase hex",
                "bash": "16 hex from openssl rand -hex 8",
                "status": "divergent-shape",
                "note": "both are legal Xray sIDs; Go is narrower but valid",
            },
            {
                "id": "generate.shortId.validation",
                "go": "any 1-16 hex characters with even length",
                "bash": "custom value must match ^[0-9a-fA-F]{16}$",
                "status": "divergent-validation",
                "note": "Go accepts 4-hex and shorter even-length sIDs",
            },
            {
                "id": "user.add.shortId.auto",
                "go": "no sID is minted unless --short-id is passed",
                "bash": "every new Reality user gets a fresh shortId",
                "status": "not-implemented",
            },
            {
                "id": "install.spiderX.auto",
                "go": "no spiderX is generated at generate/install time",
                "bash": "spiderx_set generates /assets|/static|/docs|/api paths",
                "status": "not-implemented",
            },
            {
                "id": "install.reality_clients.mapping",
                "go": "no per-user shortId/spiderX map",
                "bash": "install_config.reality_clients[uuid]={shortIds,spiderx_path}",
                "status": "not-implemented",
            },
            {
                "id": "share.reality.link.template",
                "go": "encryption=none...type=raw, no target parameter",
                "bash": "starts at security=reality and includes target=",
                "status": "divergent-link-template",
            },
            {
                "id": "share.spiderX.encoding",
                "go": "spx=/assets/abc.css (literal slash)",
                "bash": "spx=%2Fassets%2Fabc.css via vless_urlquote",
                "status": "divergent-encoding",
            },
        ],
        "observations": {
            "goAutoShortIds": observed["autoShortIds"],
            "goExplicitShortIds": observed["explicitShortIds"],
            "goSpiderX": "/assets/abc.css",
            "goCustomShortIdsRejected": list(bad_values.values()),
        },
    })


if __name__ == "__main__":
    raise SystemExit(run_fixture("F07", main))
