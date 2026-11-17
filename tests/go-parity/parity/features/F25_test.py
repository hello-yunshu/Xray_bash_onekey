#!/usr/bin/env python3
"""F25 — native TCP sysctl profile transaction.

Preview evidence level: CONTAINER_VERIFIED (sandboxed kernel files).

The fixture mirrors the fixed Bash baseline's *absence of automation*: the
legacy `-tcp` entry executes a local `tcp.sh` (and refuses to download one), so
it cannot be run as a hermetic baseline. Instead the fixture proves the Go
contract on a disposable root whose `/proc/sys` files are regular files:

  * status/plan are read-only,
  * apply is explicit (`--confirm`), transactional and idempotent,
  * rollback restores the runtime values, the managed file and the journal,
  * unmarked roots, foreign/managed conflicts, symlinks, pending journals,
    kernel-without-bbr and drift fail with the documented exit codes,
  * non-root cannot mutate a real root, and
  * the manager never shells out to curl/wget/tcp.sh.

The Bash entry is captured in evidence for the D3 safety divergence (the Go
manager does not execute unpinned remote scripts), not as an equality oracle.
"""
import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

CONF_REL = "etc/sysctl.d/90-idleleo-tcp.conf"
STATE_REL = "var/lib/idleleo/tcp/state.json"
REAL_CC = "/proc/sys/net/ipv4/tcp_congestion_control"
REAL_QDISC = "/proc/sys/net/core/default_qdisc"


def read(path, default=""):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return default


def write(path, body, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body if body.endswith("\n") else body + "\n", encoding="utf-8")
    os.chmod(path, mode)


def sandbox(root, bbr=True):
    root = Path(root)
    for rel in ("etc/sysctl.d", "proc/sys/net/ipv4", "proc/sys/net/core",
                "proc/sys/kernel", "var/lib", "run/lock"):
        (root / rel).mkdir(parents=True, exist_ok=True)
    write(root / ".idleleo-phase01-sandbox", "I_ACCEPT_DISPOSABLE_SANDBOX")
    write(root / "proc/sys/kernel/osrelease", "6.8.0-test")
    write(root / "proc/sys/net/ipv4/tcp_congestion_control", "cubic")
    write(root / "proc/sys/net/ipv4/tcp_available_congestion_control",
          "cubic bbr reno" if bbr else "cubic reno")
    write(root / "proc/sys/net/core/default_qdisc", "fq_codel")
    return root


def tcp(f, root, *args, env=None):
    return f.run([f.go, "--root", str(root), *args], timeout=90, env=env)


def tcp_json(f, root, *args, env=None):
    r = tcp(f, root, "--json", *args, env=env)
    return r, (f.json_of(r, "tcp " + " ".join(args)) if r.rc == 0 else None)


def main(f):
    f.need_root()
    f.need_tool("setpriv")
    script = f.bash_repo / "install.sh" if f.bash_repo else None
    f.check(script is not None and script.is_file(), "Bash install.sh baseline is present",
            str(script))
    if script is None:
        return

    work = f.evidence / "tcp-work"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    # Capture the legacy entry: it is a menu item that executes a local tcp.sh.
    lines = [line.strip() for line in script.read_text(encoding="utf-8").splitlines()
             if "tcp.sh" in line]
    (f.evidence / "bash-tcp-entry.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    f.check(bool(lines), "Bash -tcp entry references the legacy tcp.sh",
            lines[0][:120] if lines else "")
    joined = "\n".join(lines)
    f.check("已不再自动下载" in joined or "no longer download" in joined,
            "Bash -tcp entry no longer downloads the script")
    f.check("./tcp.sh" in joined, "Bash -tcp entry still executes a local tcp.sh")

    real_cc_before = read(REAL_CC, "unavailable")
    real_qdisc_before = read(REAL_QDISC, "unavailable")

    sb = sandbox(work / "primary")
    before_status = f.tree_digest(sb)

    # 1) status / plan are read-only.
    r, st = tcp_json(f, sb, "tcp", "status")
    f.check(r.rc == 0, "tcp status exits 0", f"rc={r.rc} {r.err[:200]}")
    st = st or {}
    f.write_json("status-before.json", st)
    f.check(st.get("supported") is True, "status reports linux support")
    f.check("bbr" in (st.get("availableCongestion") or []),
            "status lists bbr as available", str(st.get("availableCongestion")))
    f.check((st.get("managedFile") or {}).get("exists") is False,
            "status reports no managed file")
    f.check(st.get("state") in (None, {}), "status reports no journal",
            str(st.get("state")))
    f.check(read(sb / "proc/sys/net/ipv4/tcp_congestion_control") == "cubic",
            "status leaves the runtime value alone")

    r, plan = tcp_json(f, sb, "tcp", "plan")
    f.check(r.rc == 0, "tcp plan exits 0", f"rc={r.rc}")
    plan = plan or {}
    f.write_json("plan.json", plan)
    f.check(plan.get("fileAction") == "create", "plan previews a create",
            str(plan.get("fileAction")))
    f.check(plan.get("kernelSupportsBbr") is True, "plan confirms bbr support")
    f.check(len(plan.get("keys") or []) == 2, "plan previews two sysctl keys",
            str(len(plan.get("keys") or [])))
    f.check(plan.get("noop") is False, "initial plan is not a no-op")
    f.check(any("does not install" in item for item in plan.get("impact") or []),
            "plan states that no third-party script is installed")
    f.check(not (sb / CONF_REL).exists(), "plan writes no managed file")
    f.check(f.tree_digest(sb) == before_status, "status+plan leave the root unchanged")

    # 2) apply needs confirmation and a marked sandbox.
    r = tcp(f, sb, "tcp", "apply")
    f.check(r.rc == 2, "unconfirmed non-TTY apply exits 2", f"rc={r.rc}")
    f.check("--confirm" in r.err, "unconfirmed apply names --confirm", r.err.strip()[:160])

    unmarked = sandbox(work / "unmarked")
    (unmarked / ".idleleo-phase01-sandbox").unlink()
    r = tcp(f, unmarked, "tcp", "apply", "--confirm")
    f.check(r.rc == 2, "unmarked root apply exits 2", f"rc={r.rc}")
    f.check("sandbox" in r.err, "unmarked refusal explains the sandbox gate",
            r.err.strip()[:160])

    # 3) the real transaction.
    r, applied = tcp_json(f, sb, "tcp", "apply", "--confirm")
    f.check(r.rc == 0, "apply --confirm exits 0", f"rc={r.rc} {r.err[:200]}")
    applied = applied or {}
    f.write_json("apply.json", applied)
    f.check(applied.get("changed") is True, "apply reports a change")
    f.check(applied.get("noop") is False, "apply is not a no-op")
    f.check(len(applied.get("applied") or []) == 2, "apply changed two keys",
            str(len(applied.get("applied") or [])))
    f.check(read(sb / "proc/sys/net/core/default_qdisc") == "fq",
            "sandbox qdisc is fq")
    f.check(read(sb / "proc/sys/net/ipv4/tcp_congestion_control") == "bbr",
            "sandbox congestion control is bbr")
    managed = sb / CONF_REL
    f.check(managed.is_file(), "managed sysctl file exists")
    f.check("Managed by Xray_bash_onekey" in read(managed),
            "managed file carries the ownership marker")
    f.check((managed.stat().st_mode & 0o777) == 0o644, "managed file is 0644",
            oct(managed.stat().st_mode & 0o777))
    state_file = sb / STATE_REL
    f.check(state_file.is_file(), "apply writes a rollback journal")
    state = json.loads(state_file.read_text()) if state_file.is_file() else {}
    f.write_json("journal-applied.json", state)
    f.check(state.get("pending") is False, "journal is committed after apply")
    f.check(bool(state.get("appliedHash")), "journal records the applied hash")
    f.check(state.get("oldValues", {}).get("net.ipv4.tcp_congestion_control") == "cubic",
            "journal snapshots the old congestion control")

    r, st = tcp_json(f, sb, "tcp", "status")
    st = st or {}
    f.write_json("status-after.json", st)
    f.check((st.get("managedFile") or {}).get("owned") is True,
            "post-apply status sees an owned file")
    f.check((st.get("state") or {}).get("pending") is False,
            "post-apply status sees a committed journal")
    text = tcp(f, sb, "tcp", "status")
    f.check("managed:" in text.out and "profile=bbr-fq" in text.out,
            "status text names the managed profile", text.out.strip()[:200])

    # 4) idempotency.
    r, again = tcp_json(f, sb, "tcp", "apply", "--confirm")
    again = again or {}
    f.write_json("apply-second.json", again)
    f.check(r.rc == 0 and again.get("noop") is True and again.get("changed") is False,
            "second apply is a no-op", json.dumps(again)[:160])

    # 5) rollback restores the snapshot, and a second rollback is a no-op.
    r, rolled = tcp_json(f, sb, "tcp", "rollback")
    rolled = rolled or {}
    f.write_json("rollback.json", rolled)
    f.check(r.rc == 0, "rollback exits 0", f"rc={r.rc} {r.err[:200]}")
    f.check(rolled.get("changed") is True, "rollback reports a change")
    f.check(read(sb / "proc/sys/net/ipv4/tcp_congestion_control") == "cubic",
            "rollback restores congestion control")
    f.check(read(sb / "proc/sys/net/core/default_qdisc") == "fq_codel",
            "rollback restores the qdisc")
    f.check(not managed.exists(), "rollback removes the file it created")
    f.check(not state_file.exists(), "rollback removes the journal")

    r, noop = tcp_json(f, sb, "tcp", "rollback")
    noop = noop or {}
    f.check(r.rc == 0 and noop.get("noop") is True and noop.get("changed") is False,
            "journal-less rollback is a no-op", json.dumps(noop)[:160])

    # 6) out-of-band drift is refused by apply *and* rollback; once the drift is
    #    removed the journal can still recover the original snapshot.
    r, _ = tcp_json(f, sb, "tcp", "apply", "--confirm")
    applied_content = managed.read_text()
    with open(managed, "a", encoding="utf-8") as fh:
        fh.write("# operator drift\n")
    r = tcp(f, sb, "tcp", "apply", "--confirm")
    f.check(r.rc == 7, "out-of-band drift refuses apply with exit 7", f"rc={r.rc}")
    f.check("changed outside idleleo" in r.err, "drift refusal is explicit",
            r.err.strip()[:200])
    r = tcp(f, sb, "tcp", "rollback")
    f.check(r.rc == 7, "out-of-band drift also refuses rollback with exit 7",
            f"rc={r.rc}")
    f.check("refusing to roll back" in r.err,
            "drift rollback refusal asks for manual review", r.err.strip()[:200])
    managed.write_text(applied_content)
    r, rolled = tcp_json(f, sb, "tcp", "rollback")
    f.check(r.rc == 0, "rollback succeeds after the drift is removed", f"rc={r.rc}")
    f.check(read(sb / "proc/sys/net/ipv4/tcp_congestion_control") == "cubic",
            "post-drift rollback restores the snapshot")
    f.check(not managed.exists() and not state_file.exists(),
            "post-drift rollback removes the file and journal")

    # 7) a pending journal blocks a new apply until rollback recovers it.
    r, _ = tcp_json(f, sb, "tcp", "apply", "--confirm")
    state = json.loads(state_file.read_text())
    state["pending"] = True
    state_file.write_text(json.dumps(state, indent=2) + "\n")
    r = tcp(f, sb, "tcp", "apply", "--confirm")
    f.check(r.rc == 7, "pending journal blocks apply with exit 7", f"rc={r.rc}")
    f.check("pending" in r.err, "pending refusal is explicit", r.err.strip()[:160])
    r, recovered = tcp_json(f, sb, "tcp", "rollback")
    recovered = recovered or {}
    f.write_json("rollback-pending.json", recovered)
    f.check(r.rc == 0, "rollback recovers a pending journal", f"rc={r.rc}")
    f.check(read(sb / "proc/sys/net/ipv4/tcp_congestion_control") == "cubic",
            "pending rollback restores the snapshot")
    f.check(not managed.exists() and not state_file.exists(),
            "pending rollback removes the file and journal")

    # 8) foreign file, higher-priority conflict, symlink, unknown profile.
    foreign = sandbox(work / "foreign")
    write(foreign / CONF_REL, "net.core.default_qdisc = fq")
    r = tcp(f, foreign, "tcp", "apply", "--confirm")
    f.check(r.rc == 7, "foreign managed file exits 7", f"rc={r.rc}")
    f.check("not owned" in r.err, "foreign-file refusal is explicit", r.err.strip()[:160])

    override = sandbox(work / "override")
    write(override / "etc/sysctl.d/99-operator.conf",
          "net.ipv4.tcp_congestion_control = reno")
    r, plan = tcp_json(f, override, "tcp", "plan")
    f.check((plan or {}).get("conflicts"), "plan reports the 99- operator conflict",
            str((plan or {}).get("conflicts")))
    r = tcp(f, override, "tcp", "apply", "--confirm")
    f.check(r.rc == 7, "conflicting apply exits 7", f"rc={r.rc}")

    linked = sandbox(work / "symlink")
    os.symlink("/tmp/tcp-outside-target", linked / CONF_REL)
    r = tcp(f, linked, "tcp", "apply", "--confirm")
    f.check(r.rc != 0 and "symlink" in r.err,
            "symlinked managed file is refused explicitly", f"rc={r.rc} {r.err[:120]}")
    f.check(not Path("/tmp/tcp-outside-target").exists(), "symlink target is never written")

    r = tcp(f, sb, "tcp", "plan", "--profile", "bbrplus")
    f.check(r.rc == 2, "unknown profile exits 2", f"rc={r.rc}")

    # 8) a kernel without bbr is refused, not faked.
    nobbr = sandbox(work / "nobbr", bbr=False)
    r, plan = tcp_json(f, nobbr, "tcp", "plan")
    f.check((plan or {}).get("kernelSupportsBbr") is False,
            "plan reports missing bbr support")
    f.check(bool((plan or {}).get("conflicts")), "plan explains the missing bbr")
    r = tcp(f, nobbr, "tcp", "apply", "--confirm")
    f.check(r.rc == 12, "kernel without bbr refuses apply with exit 12", f"rc={r.rc}")
    f.check("does not list bbr" in r.err, "missing-bbr refusal is explicit",
            r.err.strip()[:160])
    f.check(not (nobbr / CONF_REL).exists() and not (nobbr / STATE_REL).exists(),
            "refused apply writes neither file nor journal")

    # 9) non-root cannot mutate a real root; read-only status still works.
    nonroot_apply = f.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
                           str(f.go), "--root", "/", "tcp", "apply", "--confirm"], timeout=60)
    f.check(nonroot_apply.rc == 6, "non-root real-root apply exits 6",
            f"rc={nonroot_apply.rc} {nonroot_apply.err[:120]}")
    rootless = sandbox(work / "rootless")
    for base, dirs, files in os.walk(rootless):
        for name in dirs:
            os.chmod(os.path.join(base, name), 0o755)
        for name in files:
            os.chmod(os.path.join(base, name), 0o644)
    nonroot_status = f.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
                            str(f.go), "--root", str(rootless), "--json", "tcp", "status"],
                           timeout=60)
    f.check(nonroot_status.rc == 0, "non-root tcp status is allowed",
            f"rc={nonroot_status.rc} {nonroot_status.err[:160]}")
    nonroot_doc = f.json_of(nonroot_status, "non-root status") or {}
    f.check(nonroot_doc.get("supported") is True, "non-root status still reports support")

    # 10) never execute the legacy remote script.
    poison = work / "poison"
    poison.mkdir()
    marker = poison / "called.log"
    for name in ("curl", "wget", "tcp.sh"):
        path = poison / name
        path.write_text("#!/bin/sh\necho \"$0 $*\" >>" + str(marker) + "\n", encoding="utf-8")
        os.chmod(path, 0o755)
    env = dict(f.env, PATH=str(poison) + ":" + f.env.get("PATH", ""))
    isolated = sandbox(work / "isolated")
    r = tcp(f, isolated, "tcp", "apply", "--confirm", env=env)
    f.check(r.rc == 0, "apply works with a poisoned PATH", f"rc={r.rc}")
    r = tcp(f, isolated, "tcp", "rollback", env=env)
    f.check(r.rc == 0, "rollback works with a poisoned PATH", f"rc={r.rc}")
    f.check(not marker.exists(), "apply/rollback never call curl, wget or tcp.sh")

    # 11) the real kernel was never touched.
    f.check(read(REAL_CC, "unavailable") == real_cc_before,
            "real tcp_congestion_control is unchanged", real_cc_before)
    f.check(read(REAL_QDISC, "unavailable") == real_qdisc_before,
            "real default_qdisc is unchanged", real_qdisc_before)

    (f.evidence / "baseline-absence.json").write_text(json.dumps({
        "baseline": "install.sh -tcp / menu item",
        "automation": "none; the entry executes a local tcp.sh and refuses to download one (D3/R09)",
        "goContract": "native bbr-fq transaction; no remote download or execution",
        "remoteReferences": lines,
        "assertions": {
            "noCurlWgetOrTcpSh": not marker.exists(),
            "realKernelUnchanged": read(REAL_CC, "unavailable") == real_cc_before
                                  and read(REAL_QDISC, "unavailable") == real_qdisc_before,
        },
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(run_fixture("F25", main))
