#!/usr/bin/env python3
"""F17 — dual-stack DNS qualification and managed firewall reconciliation.

Preview evidence level: CONTAINER_VERIFIED (the real Go binary talks to a real
UDP DNS server, real iptables shim binaries installed in the fixed PATH, and a
real sandbox root; the Bash reference functions are extracted from install.sh
and executed on the same tables; no host writes, no VPS, no real netfilter).

Scenarios:

* S1  `net dns` auto/ipv4/ipv6 against per-family answers, including a stale
      AAAA record and an NXDOMAIN;
* S2  first apply, port diff, dual -> ipv4 -> dual family switch;
* S3  injected `ip6tables -I` failure rolls every rule back;
* S4  dry-run lists commands and writes nothing;
* S5  policy/family/port/flag/root gates return 2;
* S6  status sees present/missing rules, revert empties the state and is
      idempotent;
* S7  a missing ip6tables fails closed before any rule is touched;
* S8  Bash classify_resolved_ips and managed_fw_families_for_mode match Go.
"""
import json
import os
import re
import shutil
import socket
import socketserver
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

MARKER = "I_ACCEPT_DISPOSABLE_SANDBOX\n"
SBIN = Path("/usr/local/sbin")
FIXED_PATH_DIRS = tuple(Path(p) for p in (
    "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"))


def hide_ip6tables():
    """Hide every ip6tables visible in the manager's fixed PATH."""
    hidden = []
    for directory in FIXED_PATH_DIRS:
        binary = directory / "ip6tables"
        if binary.exists():
            moved = binary.with_name("ip6tables.f17-hidden")
            binary.rename(moved)
            hidden.append((binary, moved))
    return hidden


def restore_binaries(hidden):
    for binary, moved in hidden:
        if moved.exists() and not binary.exists():
            moved.rename(binary)


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def write_text(path, text, mode=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if mode is not None:
        path.chmod(mode)
    return path


def read_rules(state, fam):
    path = Path(state) / f"{fam}.rules"
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines() if line.strip()]


def expected_rules(port):
    """The canonical shim lines for one managed port in one family."""
    return {f"{chain} -p {proto} {flag} {port} -j ACCEPT"
            for proto in ("tcp", "udp")
            for chain, flag in (("INPUT", "--dport"), ("OUTPUT", "--sport"))}


def ports_of(report, key):
    block = report.get(key) or {}
    return block.get("tcp") or [], block.get("udp") or []


def seed_root(root):
    root = Path(root)
    (root / "etc/idleleo").mkdir(parents=True, exist_ok=True)
    write_text(root / ".idleleo-phase01-sandbox", MARKER)
    return root


def extract_bash_function(text, name):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", text, re.MULTILINE | re.DOTALL)
    return match.group(0) if match else None


# --------------------------------------------------------------------------
# fake netfilter binaries (installed in the fixed PATH)
# --------------------------------------------------------------------------
def rule_shim(state_dir, fam):
    return f"""#!/bin/bash
STATE="{state_dir}"
FAM="{fam}"
BIN="$(basename "$0")"
FILE="$STATE/$FAM.rules"
touch "$FILE"
FAIL="$STATE/fail-on"
if [ -f "$FAIL" ]; then
    while IFS= read -r pattern || [ -n "$pattern" ]; do
        [ -z "$pattern" ] && continue
        if [[ "$BIN $*" == *"$pattern"* ]]; then
            grep -vxF -- "$pattern" "$FAIL" > "$FAIL.tmp" 2>/dev/null || : > "$FAIL.tmp"
            mv "$FAIL.tmp" "$FAIL"
            [ -s "$FAIL" ] || rm -f "$FAIL"
            exit 1
        fi
    done < "$FAIL"
fi
op="${{1:-}}"
shift || true
key="$*"
case "$op" in
    -C)
        grep -qxF -- "$key" "$FILE" && exit 0
        exit 1
        ;;
    -I|-A)
        grep -qxF -- "$key" "$FILE" || printf '%s\\n' "$key" >> "$FILE"
        exit 0
        ;;
    -D)
        if grep -qxF -- "$key" "$FILE"; then
            grep -vxF -- "$key" "$FILE" > "$FILE.tmp"
            mv "$FILE.tmp" "$FILE"
            exit 0
        fi
        exit 1
        ;;
    -S)
        sed 's/^/-A /' "$FILE"
        exit 0
        ;;
esac
exit 1
"""


def save_shim(state_dir, fam):
    return f"""#!/bin/bash
STATE="{state_dir}"
BIN="$(basename "$0") "
FAIL="$STATE/fail-on"
if [ -f "$FAIL" ]; then
    while IFS= read -r pattern || [ -n "$pattern" ]; do
        [ -z "$pattern" ] && continue
        if [[ "$BIN" == *"$pattern"* ]]; then
            grep -vxF -- "$pattern" "$FAIL" > "$FAIL.tmp" 2>/dev/null || : > "$FAIL.tmp"
            mv "$FAIL.tmp" "$FAIL"
            [ -s "$FAIL" ] || rm -f "$FAIL"
            exit 1
        fi
    done < "$FAIL"
fi
cat "$STATE/{fam}.rules" 2>/dev/null || true
exit 0
"""


def install_shims(state_dir):
    SBIN.mkdir(parents=True, exist_ok=True)
    for name, fam in (("iptables", "v4"), ("ip6tables", "v6")):
        write_text(SBIN / name, rule_shim(state_dir, fam), 0o755)
    for name, fam in (("iptables-save", "v4"), ("ip6tables-save", "v6")):
        write_text(SBIN / name, save_shim(state_dir, fam), 0o755)


# --------------------------------------------------------------------------
# tiny authoritative UDP DNS server
# --------------------------------------------------------------------------
def make_rr(rtype, packed):
    return b"\xc0\x0c" + rtype.to_bytes(2, "big") + b"\x00\x01" + (60).to_bytes(4, "big") \
        + len(packed).to_bytes(2, "big") + packed


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if len(data) < 12:
            return
        pos, labels = 12, []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos += 1
                break
            labels.append(data[pos + 1:pos + 1 + length].decode("ascii", "replace"))
            pos += 1 + length
        if pos + 4 > len(data):
            return
        qtype = int.from_bytes(data[pos:pos + 2], "big")
        question = data[12:pos + 4]
        name = ".".join(labels).lower()
        a_records, aaaa_records = self.server.RECORDS.get(name, ([], []))
        rcode = 3 if name in self.server.NXDOMAIN else 0
        answers, count = b"", 0
        if rcode == 0:
            if qtype == 1:
                for ip in a_records:
                    answers += make_rr(1, socket.inet_pton(socket.AF_INET, ip))
                    count += 1
            elif qtype == 28:
                for ip in aaaa_records:
                    answers += make_rr(28, socket.inet_pton(socket.AF_INET6, ip))
                    count += 1
        flags = 0x8180 | rcode
        response = (data[:2] + flags.to_bytes(2, "big") + (1).to_bytes(2, "big")
                    + count.to_bytes(2, "big") + b"\x00\x00" + b"\x00\x00"
                    + question + answers)
        sock.sendto(response, self.client_address)


def start_dns(records, nxdomain):
    server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), DNSHandler)
    server.daemon_threads = True
    server.RECORDS = records
    server.NXDOMAIN = set(nxdomain)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def go_json(f, root, args, name):
    run = f.run([f.go, "--root", root] + args + ["--json"])
    payload = None
    if run.out.strip():
        try:
            payload = json.loads(run.out)
        except ValueError:
            payload = None
    f.check(payload is not None, f"{name}: JSON report parsed", run.text[:240])
    return run, payload


def main(f):
    f.need(os.geteuid() == 0, "F17 needs root inside the container to install the PATH shims")
    f.need(f.bash_repo is not None, "F17 requires --bash-repo for the Bash baseline")
    install_sh = (f.bash_repo / "install.sh")
    f.need(install_sh.is_file(), f"Bash baseline not found: {install_sh}")
    bash_text = install_sh.read_text(encoding="utf-8")
    classify_fn = extract_bash_function(bash_text, "classify_resolved_ips")
    families_fn = extract_bash_function(bash_text, "managed_fw_families_for_mode")
    needed = ["normalize_ip_literal", "is_ipv4_literal", "is_ipv6_literal"]
    helpers = {name: extract_bash_function(bash_text, name) for name in needed}
    f.need(classify_fn and families_fn and all(helpers.values()),
           "Bash classify_resolved_ips/managed_fw_families_for_mode not found")

    work = Path(f.evidence) / "f17-work"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    state = work / "fw"
    state.mkdir()
    install_shims(state)
    observed = {"dns": {}, "firewall": {}, "gates": {}, "baseline": {}}
    compare = {}

    # ---- S1: DNS qualification ------------------------------------------
    records = {
        "dual.f17.test": (["203.0.113.10"], ["2001:db8::10"]),
        "staleaaaa.f17.test": (["203.0.113.10"], ["2001:db8::99"]),
        "v4only.f17.test": (["203.0.113.10"], []),
        "v6only.f17.test": ([], ["2001:db8::10"]),
        "none.f17.test": ([], []),
    }
    dns_server, dns_port = start_dns(records, {"nx.f17.test"})
    resolver = f"127.0.0.1:{dns_port}"
    root = seed_root(work / "dns-root")

    def dns(args, name):
        return go_json(f, root, ["net", "dns", "--resolver", resolver] + args, name)

    run, report = dns(["--domain", "dual.f17.test", "--policy", "auto",
                       "--server-ipv4", "203.0.113.10", "--server-ipv6", "2001:db8::10"], "dual")
    f.check(run.rc == 0, "dual domain rc=0", run.text[:240])
    if report:
        f.check(report["mode"] == "dual" and report["hasA"] and report["hasAAAA"]
                and report["aOK"] and report["aaaaOK"],
                "dual mode and both families match", json.dumps(report, sort_keys=True))
        f.check(report["resolved4"] == ["203.0.113.10"], "resolved4 order", str(report["resolved4"]))
        f.check(report["resolved6"] == ["2001:db8::10"], "resolved6 order", str(report["resolved6"]))
        observed["dns"]["dual"] = report["mode"]

    run, report = dns(["--domain", "staleaaaa.f17.test", "--policy", "auto",
                       "--server-ipv4", "203.0.113.10", "--server-ipv6", "2001:db8::10"], "stale-aaaa")
    f.check(run.rc == 2, "stale AAAA exits 2", run.text[:240])
    if report:
        f.check(report["mode"] == "ipv4" and report["badAAAA"] and not report["badA"],
                "stale AAAA reports badAAAA", json.dumps(report, sort_keys=True))

    run, report = dns(["--domain", "staleaaaa.f17.test", "--policy", "ipv4",
                       "--server-ipv4", "203.0.113.10", "--server-ipv6", "2001:db8::10"], "explicit-ipv4")
    f.check(run.rc == 2 and report and report["badAAAA"],
            "explicit ipv4 still rejects a foreign AAAA", run.text[:240])

    run, report = dns(["--domain", "v4only.f17.test", "--policy", "ipv4",
                       "--server-ipv4", "203.0.113.10", "--server-ipv6", "2001:db8::10"], "v4-only")
    f.check(run.rc == 0 and report and report["mode"] == "ipv4" and not report["badAAAA"],
            "ipv4-only domain passes an explicit ipv4 policy", run.text[:240])

    run, report = dns(["--domain", "v6only.f17.test", "--policy", "auto",
                       "--server-ipv4", "203.0.113.10", "--server-ipv6", "2001:db8::10"], "v6-only")
    f.check(run.rc == 0 and report and report["mode"] == "ipv6" and not report["badA"],
            "AAAA-only domain passes auto", run.text[:240])

    run, report = dns(["--domain", "v6only.f17.test", "--policy", "ipv4",
                       "--server-ipv4", "203.0.113.10", "--server-ipv6", "2001:db8::10"], "v6only-ipv4")
    f.check(run.rc == 1 and report and report["mode"] == "none",
            "no ipv4 match exits 1 with mode=none", run.text[:240])

    run, report = dns(["--domain", "nx.f17.test", "--policy", "auto",
                       "--server-ipv4", "203.0.113.10", "--server-ipv6", "2001:db8::10"], "nxdomain")
    f.check(run.rc == 1 and report and report["mode"] == "none",
            "NXDOMAIN exits 1 with mode=none", run.text[:240])

    # ---- S2: first apply, diff, family switch ---------------------------
    fw_root = seed_root(work / "fw-root")
    run, report = go_json(f, fw_root, ["net", "firewall", "apply",
                                       "--tcp", "443", "--udp", "443", "--family", "dual"], "apply-first")
    f.check(run.rc == 0 and report and report["persisted"] is True,
            "first apply persists", run.text[:300])
    f.check(len(read_rules(state, "v4")) == 4, "v4 has 4 rules after the first apply",
            str(read_rules(state, "v4")))
    f.check(len(read_rules(state, "v6")) == 4, "v6 has 4 rules after the first apply",
            str(read_rules(state, "v6")))
    if report:
        tcp, udp = ports_of(report, "new")
        f.check(tcp == [443] and udp == [443], "report new ports 443/443", json.dumps(report["new"]))
        f.check(report["newFamilies"] == ["iptables", "ip6tables"],
                "report families dual", str(report["newFamilies"]))
    state_file = fw_root / "etc/idleleo/managed_ports.json"
    f.check(state_file.is_file(), "managed_ports.json written")
    f.check((fw_root / "etc/iptables/rules.v4").is_file()
            and (fw_root / "etc/iptables/rules.v6").is_file(),
            "both persisted rulesets written")

    run, report = go_json(f, fw_root, ["net", "firewall", "apply",
                                       "--tcp", "8443", "--udp", "8443"], "apply-diff")
    f.check(run.rc == 0, "port diff apply rc=0", run.text[:300])
    if report:
        tcp, _ = ports_of(report, "old")
        f.check(tcp == [443], "report old ports [443]", str(report["old"]))
    v4_rules = read_rules(state, "v4")
    f.check(set(v4_rules) == expected_rules(8443),
            "v4 holds exactly the 8443 rules", str(v4_rules))
    f.check(len(read_rules(state, "v4")) == 4, "no duplicate rules after the diff",
            str(read_rules(state, "v4")))

    run, report = go_json(f, fw_root, ["net", "firewall", "apply",
                                       "--tcp", "8443", "--udp", "8443", "--family", "ipv4"],
                          "apply-switch-v4")
    f.check(run.rc == 0, "dual -> ipv4 rc=0", run.text[:300])
    f.check(read_rules(state, "v6") == [], "the ip6tables ruleset is empty after dual -> ipv4",
            str(read_rules(state, "v6")))
    families_file = fw_root / "etc/idleleo/managed_families.json"
    f.check(families_file.is_file() and "ip6tables" not in families_file.read_text(),
            "state families no longer contain ip6tables")

    run, report = go_json(f, fw_root, ["net", "firewall", "apply",
                                       "--tcp", "8443", "--udp", "8443", "--family", "dual"],
                          "apply-switch-dual")
    f.check(run.rc == 0, "ipv4 -> dual rc=0", run.text[:300])
    f.check(len(read_rules(state, "v6")) == 4, "ip6tables rules are re-created on ipv4 -> dual",
            str(read_rules(state, "v6")))

    run, report = go_json(f, fw_root, ["net", "firewall", "apply",
                                       "--tcp", "8443", "--udp", "8443", "--family", "ipv6"],
                          "apply-switch-v6")
    f.check(run.rc == 0 and read_rules(state, "v4") == [],
            "dual -> ipv6 removes the managed v4 rules",
            f"rc={run.rc} {read_rules(state, 'v4')}")
    f.check(len(read_rules(state, "v6")) == 4, "the v6 rules survive dual -> ipv6",
            str(read_rules(state, "v6")))
    run, report = go_json(f, fw_root, ["net", "firewall", "apply",
                                       "--tcp", "8443", "--udp", "8443", "--family", "dual"],
                          "apply-restore-dual")
    f.check(run.rc == 0 and len(read_rules(state, "v4")) == 4,
            "ipv6 -> dual restores the v4 rules", str(read_rules(state, "v4")))

    # ---- S3: injected failure rolls everything back ---------------------
    before_v4 = read_rules(state, "v4")
    before_v6 = read_rules(state, "v6")
    write_text(state / "fail-on", "ip6tables -I\n")
    run, report = go_json(f, fw_root, ["net", "firewall", "apply",
                                       "--tcp", "9443", "--family", "dual"], "rollback")
    f.check(run.rc == 1, "injected rule failure exits 1", run.text[:300])
    f.check(report is not None and report["rolledBack"] is True,
            "rollback reported", json.dumps(report or {}, sort_keys=True))
    f.check(sorted(read_rules(state, "v4")) == sorted(before_v4), "v4 rules restored",
            f"{before_v4} -> {read_rules(state, 'v4')}")
    f.check(sorted(read_rules(state, "v6")) == sorted(before_v6), "v6 rules restored",
            f"{before_v6} -> {read_rules(state, 'v6')}")
    f.check("9443" not in " ".join(read_rules(state, "v4")), "the failed port never stuck")
    f.check(json.loads(state_file.read_text())["tcp"] == [8443],
            "state still points at 8443", state_file.read_text()[:200])

    # A failing undo is rc=10, not a silent half-applied ruleset. The second
    # pattern only matches the undo of the 10443 insert, never a reconcile
    # command (which only deletes the old 8443 rules).
    write_text(state / "fail-on", "ip6tables -I\niptables -D INPUT -p tcp --dport 10443\n")
    run, report = go_json(f, fw_root, ["net", "firewall", "apply",
                                       "--tcp", "10443", "--family", "dual"], "rollback-failed")
    f.check(run.rc == 10, "a failing undo exits 10", run.text[:300])
    f.check(report is not None and report["rolledBack"] is True,
            "the failed undo still reports rolledBack")
    for fam in ("v4", "v6"):
        kept = [line for line in read_rules(state, fam) if "10443" not in line]
        write_text(state / f"{fam}.rules", "".join(line + "\n" for line in kept))
    (state / "fail-on").unlink(missing_ok=True)
    # The failed undo may have left the 8443 rules partly removed; a normal
    # apply must converge back to the persisted set before S4 compares.
    repair = f.run([f.go, "--root", fw_root, "net", "firewall", "apply",
                    "--tcp", "8443", "--udp", "8443", "--family", "dual"])
    f.check(repair.rc == 0 and len(read_rules(state, "v4")) == 4,
            "a normal apply repairs the failed rollback", repair.text[:200])

    # ---- S4: dry-run -----------------------------------------------------
    state_before = state_file.read_bytes()
    rules_before = (read_rules(state, "v4"), read_rules(state, "v6"))
    run, report = go_json(f, fw_root, ["net", "firewall", "apply",
                                       "--tcp", "2053", "--family", "dual", "--dry-run"], "dry-run")
    f.check(run.rc == 0, "dry-run rc=0", run.text[:240])
    f.check(report is not None and report["dryRun"] is True and len(report["commands"]) > 0,
            "dry-run lists commands", json.dumps(report or {}, sort_keys=True)[:300])
    f.check((read_rules(state, "v4"), read_rules(state, "v6")) == rules_before,
            "dry-run touched no rule")
    f.check(state_file.read_bytes() == state_before, "dry-run did not rewrite the state")

    # ---- S5: gates -------------------------------------------------------
    # The gate probe runs on its own shim state: a shared ruleset would let the
    # gate's 443 rules leak into the S6 revert expectations below.
    gate_state = work / "gate-fw"
    gate_state.mkdir()
    install_shims(gate_state)
    gate_root = seed_root(work / "gate-root")
    gate_ok = go_json(f, gate_root, ["net", "firewall", "apply", "--tcp", "443", "--family", "ipv4"],
                      "gate-open")[0]
    f.check(gate_ok.rc == 0, "the gate sandbox is usable", gate_ok.text[:200])
    gate_digest = f.tree_digest(gate_root)
    checks = [
        (["net", "dns", "--domain", "x.f17.test", "--policy", "bogus"], 2, "unknown policy"),
        (["net", "firewall", "apply", "--tcp", "0"], 2, "port 0"),
        (["net", "firewall", "apply", "--tcp", "65536"], 2, "port 65536"),
        (["net", "firewall", "apply", "--tcp", "abc"], 2, "non-numeric port"),
        (["net", "firewall", "apply", "--family", "bogus"], 2, "unknown family"),
        (["net", "firewall", "apply", "--bogus"], 2, "unknown flag"),
        (["net", "firewall", "status", "--json", "--bogus"], 2, "unknown status flag"),
    ]
    for args, want, label in checks:
        result = f.run([f.go, "--root", gate_root] + args)
        f.check(result.rc == want, f"{label} exits {want}", result.text[:200])
    real_root = f.run([f.go, "--root", "/", "net", "firewall", "apply", "--tcp", "443"])
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        f.check(real_root.rc == 2 and "--container" in real_root.text,
                "real root without --container exits 2", real_root.text[:200])
    else:
        f.check(real_root.rc in (0, 1), "real host uses the audited host path",
                real_root.text[:200])
    unmarked = work / "unmarked-root"
    unmarked.mkdir()
    unmarked_run = f.run([f.go, "--root", unmarked, "net", "firewall",
                          "apply", "--tcp", "443", "--family", "ipv4"])
    f.check(unmarked_run.rc == 2 and "sandbox" in unmarked_run.text,
            "unmarked sandbox exits 2", unmarked_run.text[:200])
    f.check(f.tree_digest(gate_root) == gate_digest, "rejected requests wrote nothing")
    f.check(not (unmarked / "etc").exists(), "the unmarked sandbox got no state directory")
    install_shims(state)
    observed["gates"] = {"policy": 2, "ports": 2, "family": 2, "flag": 2,
                         "realRoot": real_root.rc, "unmarked": unmarked_run.rc}

    # ---- S6: status and revert ------------------------------------------
    run, report = go_json(f, fw_root, ["net", "firewall", "status"], "status")
    f.check(run.rc == 0 and report and report["installed"] is True, "status sees the state",
            run.text[:300])
    if report:
        states = {(c["family"], c["proto"], c["port"]): (c["input"], c["output"])
                  for c in report["checks"]}
        f.check(states.get(("iptables", "tcp", 8443)) == ("present", "present"),
                "status reports present rules", str(states))
    # Delete the two live OUTPUT rules (tcp and udp) and confirm status is
    # honest about both families: iptables must be missing, ip6tables intact.
    shim_rules = state / "v4.rules"
    kept = [line for line in read_rules(state, "v4") if "sport 8443" not in line]
    write_text(shim_rules, "".join(line + "\n" for line in kept))
    run, report = go_json(f, fw_root, ["net", "firewall", "status"], "status-missing")
    if report:
        missing = [c for c in report["checks"] if c["output"] == "missing"]
        f.check(len(missing) == 2 and {c["family"] for c in missing} == {"iptables"},
                "status reports the missing OUTPUT rules", str(report["checks"]))

    run, report = go_json(f, fw_root, ["net", "firewall", "revert"], "revert")
    f.check(run.rc == 0 and read_rules(state, "v4") == [] and read_rules(state, "v6") == [],
            "revert empties both rulesets", f"{read_rules(state, 'v4')} {read_rules(state, 'v6')}")
    f.check(json.loads(state_file.read_text())["tcp"] == [], "revert empties the state port set")
    run, report = go_json(f, fw_root, ["net", "firewall", "revert"], "revert-again")
    f.check(run.rc == 0 and report is not None and report["commands"] == [],
            "second revert is a no-op", json.dumps(report or {}, sort_keys=True)[:200])
    run, report = go_json(f, fw_root, ["net", "firewall", "status"], "status-after-revert")
    f.check(run.rc == 0 and report and report["installed"] is True and report["checks"] == [],
            "status after revert has no rules to check", run.text[:240])

    # ---- S6b: status only inspects the managed families ------------------
    # ip6tables is installed but the state manages only iptables: the empty
    # ip6tables ruleset must not be reported as drift.
    subset_state = work / "subset-fw"
    subset_state.mkdir()
    install_shims(subset_state)
    subset_root = seed_root(work / "subset-root")
    subset_apply = go_json(f, subset_root, ["net", "firewall", "apply",
                                            "--tcp", "443", "--family", "ipv4"], "subset-apply")[0]
    f.check(subset_apply.rc == 0, "the ipv4-only apply is accepted", subset_apply.text[:200])
    run, report = go_json(f, subset_root, ["net", "firewall", "status"], "status-subset")
    f.check(run.rc == 0 and report is not None and report["families"] == ["iptables"],
            "status reports only the managed family", (run.text or "")[:300])
    f.check(report is not None
            and len(report["checks"]) == 1
            and {c["family"] for c in report["checks"]} == {"iptables"},
            "status does not inspect an unmanaged family", str(report and report["checks"]))
    f.check(not (subset_root / "etc/iptables/rules.v6").exists(),
            "an ipv4-only apply did not persist an ip6tables ruleset")
    install_shims(state)

    # ---- S7: fail closed without ip6tables ------------------------------
    hidden = hide_ip6tables()
    rules_before = (read_rules(state, "v4"), read_rules(state, "v6"))
    state_before = state_file.read_bytes()
    run, report = go_json(f, fw_root, ["net", "firewall", "apply",
                                       "--tcp", "8443", "--family", "dual"], "no-ip6tables")
    f.check(run.rc == 1, "dual without ip6tables exits 1", run.text[:240])
    f.check("ip6tables" in run.text, "the error names the missing family", run.text[:240])
    f.check((read_rules(state, "v4"), read_rules(state, "v6")) == rules_before,
            "fail-closed added no rule")
    f.check(state_file.read_bytes() == state_before, "fail-closed left the state untouched")
    restore_binaries(hidden)

    # ---- S8: Bash baselines --------------------------------------------
    classify_inputs = {
        "c1": ["203.0.113.10", "2001:db8::10"],
        "c2": ["203.0.113.10", "2001:db8::99", "203.0.113.11"],
        "c3": ["2001:db8::10"],
        "c4": [],
        "c5": ["198.51.100.7"],
        "c6": ["198.51.100.7", "2001:db8::10", "2001:db8::11"],
    }
    classify_server, classify_port = start_dns({}, set())
    for name, items in classify_inputs.items():
        a_records = [ip for ip in items if "." in ip and ":" not in ip]
        aaaa_records = [ip for ip in items if ":" in ip]
        classify_server.RECORDS[f"{name}.f17.test"] = (a_records, aaaa_records)
    script = "set -uo pipefail\n"
    script += "\n".join(helpers[name] for name in needed) + "\n"
    script += classify_fn + "\n"
    script += """input="$1"
classify_resolved_ips "$input"
printf 'v4=%s\\n' "$(printf '%b' "$resolved_ipv4s" | sed '/^$/d' | tr '\\n' ',')"
printf 'v6=%s\\n' "$(printf '%b' "$resolved_ipv6s" | sed '/^$/d' | tr '\\n' ',')"
"""
    script_path = write_text(work / "baseline-classify.sh", script)
    mismatches = []
    for name, items in classify_inputs.items():
        bash_run = f.run(["bash", script_path, "\n".join(items)])
        bash_v4, bash_v6 = "", ""
        for line in bash_run.out.splitlines():
            if line.startswith("v4="):
                bash_v4 = line[3:].rstrip(",")
            elif line.startswith("v6="):
                bash_v6 = line[3:].rstrip(",")
        dns_run, dns_report = go_json(
            f, root,
            ["net", "dns", "--resolver", f"127.0.0.1:{classify_port}",
             "--domain", f"{name}.f17.test", "--policy", "auto",
             "--server-ipv4", "198.51.100.7", "--server-ipv6", "2001:db8::10"],
            f"classify-{name}")
        got_v4 = ",".join(sorted(dns_report["resolved4"])) if dns_report else "<none>"
        got_v6 = ",".join(sorted(dns_report["resolved6"])) if dns_report else "<none>"
        want_v4 = ",".join(sorted(p for p in bash_v4.split(",") if p))
        want_v6 = ",".join(sorted(p for p in bash_v6.split(",") if p))
        if (want_v4, want_v6) != (got_v4, got_v6):
            mismatches.append(f"{name}: bash=({want_v4}|{want_v6}) go=({got_v4}|{got_v6}) rc={dns_run.rc}")
    f.check(not mismatches, "Bash classify_resolved_ips matches Go", "; ".join(mismatches[:3]))

    families_script = "set -uo pipefail\n"
    families_script += families_fn + "\n"
    families_script += """command_available() { [ "${FW_HAS_V6:-0}" = "1" ]; }
for mode in auto ipv4 ipv6 dual manual; do
    printf '%s=%s\\n' "$mode" "$(managed_fw_families_for_mode "$mode" | paste -sd, -)"
done
"""
    families_path = write_text(work / "baseline-families.sh", families_script)
    mode_table = {}
    for has_v6 in (1, 0):
        bash_run = f.run(["bash", families_path], env=dict(os.environ, FW_HAS_V6=str(has_v6)))
        bash_rows = dict(line.split("=", 1) for line in bash_run.out.splitlines() if "=" in line)
        hidden = hide_ip6tables() if has_v6 == 0 else []
        for mode, want in bash_rows.items():
            run, report = go_json(f, fw_root, ["net", "firewall", "apply", "--dry-run",
                                               "--tcp", "443", "--family", mode], f"families-{mode}")
            got = ",".join(report["newFamilies"]) if report else "<none>"
            # Without ip6tables a family set that names it must fail closed
            # (rc=1) instead of silently reconciling one family.
            want_rc = 1 if (has_v6 == 0 and "ip6tables" in want.split(",")) else 0
            mode_table[f"{mode}/{has_v6}"] = {"bash": want, "go": got, "rc": run.rc}
            if want != got or run.rc != want_rc:
                mismatches.append(f"families {mode}/{has_v6}: bash={want} go={got} "
                                  f"rc={run.rc} want_rc={want_rc}")
        restore_binaries(hidden)
    f.check(not mismatches, "Bash managed_fw_families_for_mode matches Go",
            "; ".join(mismatches[:3]))
    observed["baseline"] = {"classificationCases": len(classify_inputs), "familyRows": len(mode_table)}
    compare["classification"] = {
        "classification": "aligned",
        "go": "netcfg.Classify (IPv6 before IPv4, order preserved, no dedupe)",
        "bash": "classify_resolved_ips from install.sh",
        "cases": len(classify_inputs),
    }
    compare["familySet"] = {
        "classification": "aligned",
        "go": "netcfg.FamiliesForMode(mode, ip6tables present)",
        "bash": "managed_fw_families_for_mode from install.sh",
        "rows": len(mode_table),
    }
    compare["dnsProbe"] = {
        "classification": "approved-difference",
        "go": "no outbound echo probe; the server address comes from --server-ipv4/6 or the local interfaces",
        "bash": "validate_domain_network_records probes an external echo service to learn the public address",
    }
    compare["badRecordsExit"] = {
        "classification": "aligned",
        "go": "rc=2 and the install must stop for confirmation",
        "bash": "returns 2 from validate_domain_network_records",
    }
    compare["stateLayout"] = {
        "classification": "new-go-behavior",
        "go": "etc/idleleo/managed_ports.json + managed_families.json, rules under etc/iptables/rules.v{4,6}",
        "bash": "no explicit managed-state file; the Bash config is the source of truth",
    }
    compare["ipv6FailClosed"] = {
        "classification": "new-go-behavior",
        "go": "a dual/ipv6 mode without ip6tables refuses before touching any rule",
        "bash": "falls back to iptables alone in auto mode",
    }

    dns_server.shutdown()
    classify_server.shutdown()
    f.write_json("observed.json", observed)
    f.write_json("baseline-compare.json", compare)


if __name__ == "__main__":
    sys.exit(run_fixture("F17", main))
