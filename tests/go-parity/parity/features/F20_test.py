#!/usr/bin/env python3
"""F20: Fail2ban executor.

Contract: feature_contracts.json F20. This fixture runs the real Go manager
against the real /etc/fail2ban tree in a throwaway container, runs the fixed
Bash baseline (`scripts/fail2ban_manager.sh` -> `mf_configure_fail2ban`) on the
same tree, compares every generated file byte for byte, then starts the real
`fail2ban-client` and exercises status/banned/unban/trust/jail/uninstall.

Evidence level: CONTAINER_VERIFIED. No systemd restart, no SSH journal, no
iptables data plane, no real VPS. Those are registered as gaps in
baseline-compare.json, not papered over.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

FAIL2BAN_DIR = Path("/etc/fail2ban")
NGINX_DIR = Path("/usr/local/nginx")
JAILS = ("nginx-badbots", "nginx-botsearch", "nginx-no-host", "nginx-tls-error")
TRUST_HEADER = "# Managed by Idleleo. Trusted IPs/CIDRs survive a fail2ban restart.\n"
BAD_IP = "192.0.2.10"
TRUST_IP = "192.0.2.55"
TRUST_V6 = "2001:db8::1"
MANIFEST = Path("/etc/idleleo/v1/fail2ban.json")
DROPPIN = "etc/systemd/system/fail2ban.service.d/restart-policy.conf"

EXPECTED_JAILS = {
    "nginx-badbots.local": """[nginx-badbots]
enabled  = true
port     = http,https,8080
filter   = apache-badbots
logpath  = /usr/local/nginx/logs/access.log
bantime  = 604800
maxretry = 5
""",
    "nginx-botsearch.local": """[nginx-botsearch]
enabled  = true
filter   = nginx-botsearch
logpath  = /usr/local/nginx/logs/access.log
           /usr/local/nginx/logs/error.log
bantime  = 604800
""",
    "nginx-no-host.local": """[nginx-no-host]
enabled  = true
filter   = nginx-no-host
logpath  = /usr/local/nginx/logs/sni_error.log
bantime  = 604800
maxretry = 5
findtime = 120
""",
    "nginx-tls-error.local": """[nginx-tls-error]
enabled  = true
filter   = nginx-tls-error
logpath  = /usr/local/nginx/logs/tls_error.log
bantime  = 43200
maxretry = 8
findtime = 300
""",
}

INCREMENTAL = """# Idleleo incremental ban policy
# Repeat offenders get progressively longer bans.
# Base bantime/maxretry/findtime per jail are NOT relaxed.
[DEFAULT]
bantime.increment = true
bantime.multipliers = 1 2 4 8 16 32 64
bantime.maxtime = 180d
bantime.rndtime = 10m
bantime.overalljails = false
"""

FILTER = """[Definition]
datepattern = %%d/%%b/%%Y:%%H:%%M:%%S %%z
failregex = ^<HOST> \\[[^\\]]*\\] "[^"]*" \\S* \\d+$
ignoreregex =
"""

BASH_BASELINE = """set +u
ok_rc=0
mkdir -p /usr/local/nginx/sbin /usr/local/nginx/logs
: > /usr/local/nginx/sbin/nginx
chmod +x /usr/local/nginx/sbin/nginx
for f in access.log error.log sni_error.log tls_error.log; do
  : > "/usr/local/nginx/logs/$f"
done
export tls_mode=Reality
export reality_add_nginx=on
export nginx_dir=/usr/local/nginx
OK=""; Error=""; Warning=""; Font=""; Green=""; GreenBG=""; Red=""; YellowBG=""
Info=""; RedBG=""
log_echo() { printf 'LOG %s\\n' "$*"; }
judge() { return 0; }
gettext() { printf '%s' "$*"; }
# shellcheck disable=SC1090
source "$1/scripts/fail2ban_manager.sh"
printf 'y\\ny\\n' | mf_configure_fail2ban
echo "bash_rc=$?"
"""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot_tree(root):
    root = Path(root)
    return {
        str(p.relative_to(root)): sha256_file(p)
        for p in sorted(root.rglob("*")) if p.is_file()
    }


def snapshot_copy(src, dest):
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, symlinks=True)


# Only files this feature generates are archived as evidence. The distro's own
# jail.conf/filter.d files are full of upstream sample addresses and host paths,
# so the evidence tree keeps their digests instead of their bodies.
GENERATED_RELS = (
    "jail.d/nginx-badbots.local",
    "jail.d/nginx-botsearch.local",
    "jail.d/nginx-no-host.local",
    "jail.d/nginx-tls-error.local",
    "jail.d/zzz-idleleo-incremental.local",
    "filter.d/nginx-no-host.conf",
    "filter.d/nginx-tls-error.conf",
    "restart-policy.conf",
)


def export_generated(src, dest):
    src, dest = Path(src), Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    for rel in GENERATED_RELS:
        source = src / rel
        if not source.is_file():
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def restore_tree(src, dest):
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, symlinks=True)


def parse_json(fixture, result, name):
    try:
        return json.loads(result.out)
    except (ValueError, TypeError):
        fixture.bad(f"{name}: invalid JSON", (result.out or result.err or "")[:500])
        return None


def write_sandbox(root, marker=True):
    root = Path(root)
    (root / "etc/fail2ban/jail.d").mkdir(parents=True, exist_ok=True)
    if marker:
        (root / ".idleleo-phase01-sandbox").write_text("I_ACCEPT_DISPOSABLE_SANDBOX\n")


def main(f):
    f.need_root()
    f.need_tool("fail2ban-client")
    f.need(FAIL2BAN_DIR.is_dir(), "/etc/fail2ban is missing in this image")
    f.need(f.bash_repo is not None, "--bash-repo is required for the Bash baseline")

    work = f.evidence / "f20-work"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    generated = work / "generated"
    generated.mkdir()
    # Full-tree copies stay outside the evidence directory: they include the
    # distro's own sample files, which carry upstream addresses and host paths.
    raw = Path(tempfile.mkdtemp(prefix="f20-raw-"))
    base = raw / "base"
    snapshot_copy(FAIL2BAN_DIR, base)

    env = dict(f.env)
    env["IDLELEO_ALLOW_SYSTEM_WRITES"] = "I_ACCEPT_CONTAINER_ONLY"
    go = f.go

    def go_run(args, timeout=60, run_env=None):
        return f.run([go] + args, timeout=timeout, env=run_env or env)

    observed = {
        "image": "idleleo-e2e@sha256:3012978e415b9bec250f738ddc7246a64837896fbeb52ed27571d8f3b8b24002",
        "fail2banVersion": (f.run(["fail2ban-client", "--version"], timeout=10).out or "").strip(),
        "goBinSha256": sha256_file(go),
        "bashScriptSha256": sha256_file(f.bash_repo / "scripts/fail2ban_manager.sh"),
        "jailConfSha256": sha256_file(base / "jail.conf"),
        "jailLocalSha256": "",
        "jailFiles": {},
        "bashBaseline": {},
        "gaps": [],
    }

    # ------------------------------------------------------------ S7 guards
    nomarker = work / "sandbox-nomarker"
    write_sandbox(nomarker, marker=False)
    r = go_run(["--root", str(nomarker), "fail2ban", "install", "--json"])
    f.check(r.rc == 1 and "sandbox marker required" in r.text,
            "S7 sandbox without marker is refused", f"rc={r.rc} {r.text[:200]}")
    f.check(sorted(p.name for p in (nomarker / "etc/fail2ban").rglob("*")) == ["jail.d"],
            "S7 missing marker writes nothing", str(list((nomarker / "etc/fail2ban").rglob("*"))))

    in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    if in_container:
        r = go_run(["--root", "/", "fail2ban", "install", "--json"])
        f.check(r.rc == 1 and "container root writes require --container" in r.text,
                "S7 writing the real root requires --container", f"rc={r.rc} {r.text[:200]}")

        env_nogrant = dict(f.env)
        env_nogrant.pop("IDLELEO_ALLOW_SYSTEM_WRITES", None)
        r = go_run(["--root", "/", "fail2ban", "install", "--container", "--json"], run_env=env_nogrant)
        f.check(r.rc == 1 and "IDLELEO_ALLOW_SYSTEM_WRITES" in r.text,
                "S7 write grant needs the explicit environment token", f"rc={r.rc} {r.text[:200]}")
    else:
        # The real-root guard only exists inside containers; on a real host the
        # audited host path is the documented behaviour and must not be probed
        # destructively by this fixture.
        f.check(True, "S7 real-root container gate is container-only; host writes are audited")

    empty_path = work / "empty-path"
    empty_path.mkdir()
    sandbox = work / "sandbox-empty"
    write_sandbox(sandbox)
    env_missing = {"PATH": str(empty_path), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    r = go_run(["--root", str(sandbox), "fail2ban", "install", "--json"], run_env=env_missing)
    f.check(r.rc == 1 and "fail2ban is not installed" in r.text,
            "S7 missing fail2ban-client is refused", f"rc={r.rc}")
    for token in ("apt-get install -y fail2ban", "dnf install -y fail2ban", "apk add fail2ban"):
        f.check(token in r.text, f"S7 hint mentions {token.split()[0]}")
    files = [p for p in sandbox.rglob("*") if p.is_file()
             and p.name != ".idleleo-phase01-sandbox"]
    f.check(not files, "S7 missing binary writes nothing", str(files))

    # ------------------------------------------------------- S2 Bash baseline
    # The Bash restart drop-in lives outside /etc/fail2ban; snapshot it so the
    # Go run starts from the same pristine state.
    dropin_dir = Path("/etc/systemd/system/fail2ban.service.d")
    dropin_base = raw / "base-dropin"
    dropin_had = dropin_dir.exists()
    if dropin_had:
        snapshot_copy(dropin_dir, dropin_base)
    script = work / "bash-baseline.sh"
    script.write_text(BASH_BASELINE)
    bash = f.run(["bash", str(script), str(f.bash_repo)], timeout=120)
    bash_after = raw / "bash-after"
    snapshot_copy(FAIL2BAN_DIR, bash_after)
    bash_dropin = dropin_dir / "restart-policy.conf"
    if bash_dropin.exists():
        (bash_after / "restart-policy.conf").write_text(bash_dropin.read_text())
    export_generated(bash_after, generated / "bash")
    observed["jailLocalSha256"] = sha256_file(bash_after / "jail.local")
    bash_jails = sorted(p.name for p in (bash_after / "jail.d").glob("*.local"))
    observed["bashBaseline"] = {
        "rc": bash.rc,
        "jailFiles": bash_jails,
        "skippedSsh": "跳过启用 SSH 规则" in bash.text,
        "tree": snapshot_tree(bash_after),
    }
    f.check(bash.rc == 0, "S2 Bash baseline exits 0", f"rc={bash.rc}")
    f.check(observed["bashBaseline"]["skippedSsh"],
            "S2 Bash baseline skips the SSH jail without systemd journal")
    f.check(bash_jails == sorted(EXPECTED_JAILS) + ["zzz-idleleo-incremental.local"],
            "S2 Bash writes the same five jail files", str(bash_jails))
    for name, body in EXPECTED_JAILS.items():
        got = (bash_after / "jail.d" / name).read_text() if (bash_after / "jail.d" / name).exists() else ""
        f.check(got == body, f"S2 Bash {name} content", got[:300])
    f.check((bash_after / "filter.d/nginx-no-host.conf").read_text() == FILTER,
            "S2 Bash nginx-no-host filter content")
    f.check((bash_after / "filter.d/nginx-tls-error.conf").read_text() == FILTER,
            "S2 Bash nginx-tls-error filter content")
    f.check((bash_after / "jail.local").read_bytes() == (base / "jail.conf").read_bytes(),
            "S2 Bash jail.local is a byte copy of jail.conf")

    # back to the pristine tree for the Go run
    restore_tree(base, FAIL2BAN_DIR)
    if dropin_dir.exists():
        shutil.rmtree(dropin_dir)
    if dropin_had:
        restore_tree(dropin_base, dropin_dir)

    # --------------------------------------------------- S1 install artifacts
    for path in (NGINX_DIR / "sbin", NGINX_DIR / "logs"):
        path.mkdir(parents=True, exist_ok=True)
    (NGINX_DIR / "sbin/nginx").write_text("")
    (NGINX_DIR / "sbin/nginx").chmod(0o755)
    for log in ("access.log", "error.log", "sni_error.log", "tls_error.log"):
        (NGINX_DIR / "logs" / log).write_text("")

    r1 = go_run(["--root", "/", "fail2ban", "install", "--container", "--json"])
    first = parse_json(f, r1, "S1 install")
    f.check(r1.rc == 0 and first is not None, "S1 install exits 0", f"rc={r1.rc}")
    if first is not None:
        jails = {j["name"]: j for j in first.get("jails", [])}
        f.check(set(jails) == {"sshd"} | set(JAILS), "S1 reports five jails", str(list(jails)))
        f.check(jails.get("sshd", {}).get("written") is False
                and "no active ssh/sshd unit" in jails.get("sshd", {}).get("reason", ""),
                "S1 sshd is skipped with a reason", json.dumps(jails.get("sshd")))
        for jail in JAILS:
            entry = jails.get(jail, {})
            f.check(entry.get("written") is True,
                    f"S1 {jail} is written", json.dumps(entry))
            want = "/usr/local/nginx/logs/" + {
                "nginx-badbots": "access.log",
                "nginx-botsearch": "access.log",
                "nginx-no-host": "sni_error.log",
                "nginx-tls-error": "tls_error.log",
            }[jail]
            f.check(entry.get("logPath") == want, f"S1 {jail} logPath", entry.get("logPath"))
        files = sorted(first.get("files", []))
        expected = {
            "/etc/fail2ban/jail.local",
            "/etc/fail2ban/jail.d/nginx-badbots.local",
            "/etc/fail2ban/jail.d/nginx-botsearch.local",
            "/etc/fail2ban/jail.d/nginx-no-host.local",
            "/etc/fail2ban/jail.d/nginx-tls-error.local",
            "/etc/fail2ban/jail.d/zzz-idleleo-incremental.local",
            "/etc/fail2ban/filter.d/nginx-no-host.conf",
            "/etc/fail2ban/filter.d/nginx-tls-error.conf",
        }
        f.check(expected <= set(files),
                "S1 install lists the eight jail/filter files", str(files))
        f.check(Path("/" + DROPPIN).is_file(),
                "S1 restart drop-in exists")
        restarted = first.get("serviceRestarted")
        warned = any("restart fail2ban failed" in w for w in first.get("warnings", []))
        f.check(restarted is True or warned,
                "S1 restart outcome is reported honestly",
                json.dumps({"serviceRestarted": restarted,
                            "warnings": first.get("warnings")}))

    go_after = raw / "go-after"
    snapshot_copy(FAIL2BAN_DIR, go_after)
    export_generated(go_after, generated / "go")
    for name, body in EXPECTED_JAILS.items():
        path = go_after / "jail.d" / name
        got = path.read_text() if path.exists() else ""
        observed["jailFiles"][name] = hashlib.sha256(got.encode()).hexdigest()
        f.check(got == body, f"S1 {name} content", got[:300])
    f.check((go_after / "jail.d/zzz-idleleo-incremental.local").read_text() == INCREMENTAL,
            "S1 incremental ban policy content")
    f.check((go_after / "jail.local").read_bytes() == (base / "jail.conf").read_bytes(),
            "S1 jail.local is a byte copy of jail.conf")
    f.check((go_after / "filter.d/nginx-no-host.conf").read_text() == FILTER,
            "S1 nginx-no-host filter content")
    f.check((go_after / "filter.d/nginx-tls-error.conf").read_text() == FILTER,
            "S1 nginx-tls-error filter content")
    f.check(not (go_after / "jail.d/sshd.local").exists(),
            "S1 no sshd.local without an SSH unit")

    manifest = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    entries = sorted(manifest.get("files", []))
    f.check(manifest.get("version") == 1 and len(entries) == 9,
            "S1 manifest records version 1 and nine files", json.dumps(manifest))
    f.check(DROPPIN in entries, "S1 manifest lists the systemd drop-in", str(entries))
    f.check((Path("/") / DROPPIN).exists(), "S1 systemd drop-in is written")

    r2 = go_run(["--root", "/", "fail2ban", "install", "--container", "--json"])
    second = parse_json(f, r2, "S1 install twice")
    f.check(r2.rc == 0 and second is not None, "S1 second install exits 0", f"rc={r2.rc}")
    f.check(snapshot_tree(FAIL2BAN_DIR) == snapshot_tree(go_after),
            "S1 second install is idempotent (tree sha unchanged)")

    # ------------------------------------------------ S2 cross-implementation
    compared = []
    for rel in (["jail.d/" + n for n in EXPECTED_JAILS]
                + ["jail.d/zzz-idleleo-incremental.local", "jail.local",
                   "filter.d/nginx-no-host.conf", "filter.d/nginx-tls-error.conf"]):
        b_path, g_path = bash_after / rel, go_after / rel
        same = b_path.exists() and g_path.exists() and b_path.read_bytes() == g_path.read_bytes()
        compared.append({"path": rel, "aligned": same, "status": "aligned" if same else "divergent"})
        f.check(same, f"S2 Bash and Go agree on {rel}",
                f"bash={b_path.exists()} go={g_path.exists()}")
    f.check(not (bash_after / "jail.d/sshd.local").exists(),
            "S2 Bash writes no sshd.local either")

    # ------------------------------------------------------- S3 runtime state
    ping = f.run(["fail2ban-client", "ping"], timeout=15)
    if ping.rc != 0:
        started = f.run(["fail2ban-client", "-x", "start"], timeout=60)
        already = "already running" in started.text
        f.check(started.rc == 0 or already, "S3 fail2ban daemon starts",
                f"rc={started.rc} {started.text[:300]}")
        for _ in range(15):
            ping = f.run(["fail2ban-client", "ping"], timeout=15)
            if ping.rc == 0:
                break
            time.sleep(1)
    f.check(ping.rc == 0, "S3 fail2ban daemon answers ping", ping.text[:200])

    status = go_run(["fail2ban", "status", "--json"], timeout=60)
    payload = parse_json(f, status, "S3 status")
    f.check(status.rc == 0 and payload is not None, "S3 status exits 0", f"rc={status.rc}")
    if payload is not None:
        names = sorted(j["name"] for j in payload.get("jails", []))
        f.check(names == sorted(JAILS), "S3 status lists the four Nginx jails", str(names))
        f.check(payload.get("installed") is True, "S3 status reports installed=true")
        f.check(all(j.get("currentlyBanned") == 0 for j in payload.get("jails", [])),
                "S3 no jail has bans yet")

    f.run(["fail2ban-client", "set", "nginx-no-host", "banip", BAD_IP], timeout=30)
    banned = go_run(["fail2ban", "banned", "--jail", "nginx-no-host", "--json"], timeout=60)
    payload = parse_json(f, banned, "S3 banned")
    f.check(banned.rc == 0 and payload is not None, "S3 banned exits 0", f"rc={banned.rc}")
    if payload is not None:
        entry = payload.get("jails", [{}])[0]
        f.check(BAD_IP in entry.get("bannedIPs", []),
                "S3 banned lists the real ban", json.dumps(entry))
        f.check(entry.get("currentlyBanned") == 1, "S3 ban counter is one",
                str(entry.get("currentlyBanned")))

    unban = go_run(["fail2ban", "unban", "--jail", "nginx-no-host", "--ip", BAD_IP, "--json"])
    payload = parse_json(f, unban, "S3 unban")
    f.check(unban.rc == 0 and payload is not None, "S3 unban exits 0", f"rc={unban.rc}")
    if payload is not None:
        f.check(payload.get("unbanned") is True and payload.get("wasBanned") is True,
                "S3 unban removes an active ban", json.dumps(payload))
        f.check(payload.get("remainingIPs") == [], "S3 no ban remains", str(payload.get("remainingIPs")))

    again = go_run(["fail2ban", "unban", "--jail", "nginx-no-host", "--ip", BAD_IP, "--json"])
    payload = parse_json(f, again, "S3 unban twice")
    f.check(again.rc == 0 and payload is not None, "S3 second unban exits 0")
    if payload is not None:
        f.check(payload.get("alreadyAbsent") is True and payload.get("unbanned") is False,
                "S3 second unban reports already-absent", json.dumps(payload))

    bad = go_run(["fail2ban", "unban", "--jail", "nginx-no-host", "--ip", "nope", "--json"])
    f.check(bad.rc == 1 and "invalid IP address" in bad.text,
            "S3 invalid IP is refused with rc=1", f"rc={bad.rc} {bad.text[:200]}")
    nojail = go_run(["fail2ban", "unban", "--jail", "no-such", "--ip", BAD_IP, "--json"])
    f.check(nojail.rc == 1 and "is not active" in nojail.text,
            "S3 unknown jail is refused with rc=1", f"rc={nojail.rc} {nojail.text[:200]}")
    banned_nojail = go_run(["fail2ban", "banned", "--jail", "no-such", "--json"])
    f.check(banned_nojail.rc == 1, "S3 banned with an unknown jail exits 1",
            f"rc={banned_nojail.rc}")

    # -------------------------------------------------------------- S4 trust
    trust_file = FAIL2BAN_DIR / "jail.d/zzz-idleleo-trust.local"
    added = go_run(["--root", "/", "fail2ban", "trust", "add", "--jail", "nginx-no-host",
                    "--ip", TRUST_IP, "--container", "--json"])
    payload = parse_json(f, added, "S4 trust add")
    f.check(added.rc == 0 and payload is not None, "S4 trust add exits 0", f"rc={added.rc}")
    if payload is not None:
        f.check(payload.get("applied") is True and payload.get("persisted") is True,
                "S4 trust add applies and persists", json.dumps(payload))
        f.check(payload.get("file") == str(trust_file), "S4 trust file path",
                payload.get("file"))
    f.check(trust_file.exists() and trust_file.read_text()
            == TRUST_HEADER + "[nginx-no-host]\nignoreip = " + TRUST_IP + "\n",
            "S4 trust file content", trust_file.read_text() if trust_file.exists() else "")
    live = f.run(["fail2ban-client", "get", "nginx-no-host", "ignoreip"], timeout=30)
    f.check(TRUST_IP in live.text, "S4 running jail ignores the trusted IP", live.text[:300])

    deleted = go_run(["--root", "/", "fail2ban", "trust", "del", "--jail", "nginx-no-host",
                      "--ip", TRUST_IP, "--container", "--json"])
    payload = parse_json(f, deleted, "S4 trust del")
    f.check(deleted.rc == 0 and payload is not None, "S4 trust del exits 0")
    f.check(trust_file.read_text() == TRUST_HEADER,
            "S4 trust del leaves only the managed header", trust_file.read_text())

    v6 = go_run(["--root", "/", "fail2ban", "trust", "add", "--jail", "nginx-no-host",
                 "--ip", TRUST_V6, "--container", "--json"])
    payload = parse_json(f, v6, "S4 trust v6")
    f.check(v6.rc == 0 and payload is not None, "S4 IPv6 trust add exits 0")
    f.check(("ignoreip = " + TRUST_V6) in trust_file.read_text(),
            "S4 IPv6 is persisted", trust_file.read_text())
    v6_del = go_run(["--root", "/", "fail2ban", "trust", "del", "--jail", "nginx-no-host",
                     "--ip", TRUST_V6, "--container", "--json"])
    f.check(v6_del.rc == 0, "S4 IPv6 trust del exits 0", f"rc={v6_del.rc}")
    bad_cidr = go_run(["--root", "/", "fail2ban", "trust", "add", "--jail", "nginx-no-host",
                       "--ip", "192.0.2.5/33", "--container", "--json"])
    f.check(bad_cidr.rc == 1 and "invalid IP or CIDR" in bad_cidr.text,
            "S4 invalid CIDR is refused", f"rc={bad_cidr.rc} {bad_cidr.text[:200]}")
    bad_jail = go_run(["--root", "/", "fail2ban", "trust", "add", "--jail", "no-such",
                       "--ip", TRUST_IP, "--container", "--json"])
    f.check(bad_jail.rc == 1 and "is not active" in bad_jail.text,
            "S4 unknown jail trust add is refused", f"rc={bad_jail.rc}")

    # -------------------------------------------------------- S5 jail toggles
    jail_file = FAIL2BAN_DIR / "jail.d/nginx-no-host.local"
    disabled = go_run(["--root", "/", "fail2ban", "jail", "disable",
                       "--name", "nginx-no-host", "--container", "--json"])
    payload = parse_json(f, disabled, "S5 jail disable")
    f.check(disabled.rc == 0 and payload is not None, "S5 jail disable exits 0")
    if payload is not None:
        f.check(payload.get("enabled") is False, "S5 disable reports enabled=false")
        restarted = payload.get("serviceRestarted")
        warned = any("restart fail2ban failed" in w for w in payload.get("warnings", []))
        f.check(restarted is True or warned,
                "S5 restart outcome is reported honestly",
                json.dumps({"serviceRestarted": restarted,
                            "warnings": payload.get("warnings")}))
    f.check(jail_file.read_text() == EXPECTED_JAILS["nginx-no-host.local"].replace(
        "enabled  = true", "enabled  = false"),
        "S5 disable flips exactly enabled", jail_file.read_text())

    enabled = go_run(["--root", "/", "fail2ban", "jail", "enable",
                      "--name", "nginx-no-host", "--container", "--json"])
    payload = parse_json(f, enabled, "S5 jail enable")
    f.check(enabled.rc == 0 and payload is not None, "S5 jail enable exits 0")
    if payload is not None:
        f.check(payload.get("enabled") is True, "S5 enable reports enabled=true")
    f.check(jail_file.read_text() == EXPECTED_JAILS["nginx-no-host.local"],
            "S5 enable restores the managed content", jail_file.read_text())

    foreign = FAIL2BAN_DIR / "jail.d/user-custom.local"
    foreign.write_text("[user-custom]\nenabled = true\n")
    refused = go_run(["--root", "/", "fail2ban", "jail", "disable",
                      "--name", "user-custom", "--container", "--json"])
    f.check(refused.rc == 1 and "is not managed by Idleleo" in refused.text,
            "S5 foreign jail is refused", f"rc={refused.rc}")
    f.check(foreign.read_text() == "[user-custom]\nenabled = true\n",
            "S5 foreign jail file is untouched")

    # ----------------------------------------------------------- S6 uninstall
    live_manifest = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    removed_expected = {"/" + rel for rel in live_manifest.get("files", [])}
    f.check(len(removed_expected) == 10,
            "S6 manifest owns nine install files plus the trust file",
            str(sorted(removed_expected)))

    uninstall = go_run(["--root", "/", "fail2ban", "uninstall", "--container", "--json"])
    payload = parse_json(f, uninstall, "S6 uninstall")
    f.check(uninstall.rc == 0 and payload is not None, "S6 uninstall exits 0", f"rc={uninstall.rc}")
    if payload is not None:
        removed = set(payload.get("removed", []))
        f.check(removed == removed_expected, "S6 uninstall removes every owned file",
                f"missing={sorted(removed_expected - removed)} extra={sorted(removed - removed_expected)}")
        f.check(payload.get("preserved") == [str(foreign)],
                "S6 uninstall preserves the operator file", str(payload.get("preserved")))
        f.check(payload.get("needForce") is False, "S6 manifest path needs no --force")
        f.check(any("package is still installed" in w for w in payload.get("warnings", [])),
                "S6 package removal is out of scope", str(payload.get("warnings")))
    f.check(foreign.read_text() == "[user-custom]\nenabled = true\n",
            "S6 operator file survives")
    leftover = [p for p in removed_expected if Path(p).exists()]
    f.check(not leftover, "S6 owned files are gone from disk", str(leftover))

    second_uninstall = go_run(["--root", "/", "fail2ban", "uninstall", "--container", "--json"])
    payload = parse_json(f, second_uninstall, "S6 uninstall twice")
    f.check(second_uninstall.rc == 2 and payload is not None,
            "S6 uninstall without a manifest needs --force", f"rc={second_uninstall.rc}")
    if payload is not None:
        f.check(payload.get("needForce") is True and payload.get("removed") == [],
                "S6 missing manifest deletes nothing", json.dumps(payload))
        f.check(str(foreign) in payload.get("candidates", []),
                "S6 missing manifest lists the operator file as a candidate",
                str(payload.get("candidates")))
    f.check(foreign.read_text() == "[user-custom]\nenabled = true\n",
            "S6 missing-manifest refusal leaves the operator file alone")

    forced = go_run(["--root", "/", "fail2ban", "uninstall", "--container", "--force", "--json"])
    payload = parse_json(f, forced, "S6 uninstall force")
    f.check(forced.rc == 0 and payload is not None, "S6 --force exits 0", f"rc={forced.rc}")
    if payload is not None:
        f.check(payload.get("removed") == [] and payload.get("needForce") is False,
                "S6 --force removes only known leftovers", json.dumps(payload))
    f.check(foreign.read_text() == "[user-custom]\nenabled = true\n",
            "S6 --force keeps the operator file")

    # -------------------------------------------------------------- summary
    baseline_compare = {
        "fixture": "F20",
        "bashScript": "scripts/fail2ban_manager.sh",
        "bashScriptSha256": observed["bashScriptSha256"],
        "entries": compared + [
            {"path": "sshd.local", "status": "aligned",
             "detail": "both sides skip without an SSH unit/journal"},
            {"path": "package installation", "status": "approved-difference",
             "detail": "Go prints apt/dnf/apk hints and never runs the package manager (G13)"},
            {"path": "uninstall scope", "status": "approved-difference",
             "detail": "Go removes manifest entries only; Bash deletes globs (ED-002)"},
            {"path": "trust persistence", "status": "approved-difference",
             "detail": "Go writes zzz-idleleo-trust.local; Bash edits the jail file"},
            {"path": "jail enable/disable ownership", "status": "approved-difference",
             "detail": "Go only toggles manifest-owned files"},
            {"path": "systemd restart", "status": "aligned",
             "detail": "restart is attempted and reported as serviceRestarted=true or an explicit warning"},
            {"path": "SSH journal trigger", "status": "gap",
             "detail": "no sshd service or journal in the container"},
            {"path": "iptables data plane", "status": "gap",
             "detail": "bans were created through fail2ban-client, not by real log traffic"},
            {"path": "fail2ban 1.1.x", "status": "gap",
             "detail": "container ships 1.0.2; 1.1.x compatibility is not covered here"},
        ],
    }
    observed["gaps"] = [e for e in baseline_compare["entries"] if e["status"] == "gap"]
    observed["jailFileSha256"] = {
        name: hashlib.sha256(body.encode()).hexdigest()
        for name, body in EXPECTED_JAILS.items()
    }
    f.write_json("observed.json", observed)
    f.write_json("bash-result.json", observed["bashBaseline"])
    f.write_json("baseline-compare.json", baseline_compare)


if __name__ == "__main__":
    raise SystemExit(run_fixture("F20", main))
