#!/usr/bin/env python3
"""Builds the P2 install matrix report from evidence.

Classification per scenario:
  MATCH              both sides installed, both L4 probes passed, round 2 stable,
                     and the L1 artifact layout has no unsuppressed difference.
  ED-xxx             an L1 difference is exactly covered by a registered
                     EXPECTED-DIFF (cited); pending/expired/unknown is still a
                     BLOCKER per policy.
  BLOCKER            install/L4/idempotency failure or an unregistered layout diff.
  HARNESS-ERROR      driver rc=124 / HARNESS-ERROR marker / missing evidence.
  HARNESS-BLOCKED    scenario explicitly ineligible (M8 ACME).
  NOT-RUN            the run's scope.json proves the scenario/side was never
                     executed (E2E_ONLY partial run). Evidence from before
                     scope.json existed keeps the old full-matrix semantics.

L1 comparison is layout-level: full path sets are compared, then grouped by
top-level root so the report stays readable. L2 semantic field diffing is not
claimed here; the sanitized config digest is reported for follow-up inspection.
"""
import argparse
import datetime
import json
import os
import sys

LAYERS = ("L0", "L1", "L2", "L3", "L4", "L5", "L6")

# SCOPE is the current run's executed scope (from <evidence>/scope.json), or
# None for evidence written before scope.json existed.
SCOPE = None


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def load_scope(evidence):
    """Returns the executed scope, or None when this evidence predates it.

    A partial run leaves no directory for scenarios it never touched, so
    "missing evidence" alone cannot distinguish "not executed" from "harness
    broke". scope.json is written by the runner and is the only authority.
    """
    data = read_json(os.path.join(evidence, "scope.json"))
    if not isinstance(data, dict):
        return None
    # A full run (no E2E_ONLY) keeps the historical semantics: missing evidence
    # is a harness error, not "not executed". Only partial runs opt into scope.
    if not str(data.get("only") or "").strip():
        return None
    scope = {}
    for key in ("installs", "edits", "ops"):
        value = data.get(key)
        if isinstance(value, list):
            scope[key] = set(str(item) for item in value)
    if not scope:
        return None
    return scope


def in_scope(key, item):
    if SCOPE is None or key not in SCOPE:
        return True
    return item in SCOPE[key]


def install_rc(side_dir):
    value = read_text(os.path.join(side_dir, "install.rc")).strip()
    try:
        return int(value)
    except ValueError:
        return None


def l4_results(side_dir, round_dir):
    base = os.path.join(side_dir, "L4") if not round_dir else os.path.join(side_dir, round_dir, "L4")
    results = {}
    if not os.path.isdir(base):
        return results
    for name in sorted(os.listdir(base)):
        conn = read_json(os.path.join(base, name, "connectivity.json"))
        if conn is not None:
            results[name] = bool(conn.get("ok"))
    return results


def relay_l4(side_dir, round_dir):
    path = os.path.join(side_dir, "L4-relay.json") if not round_dir else \
        os.path.join(side_dir, round_dir, "L4-relay.json")
    data = read_json(path)
    if data is None:
        return None
    return data.get("rc") == 0


def manifest_paths(side_dir):
    data = read_json(os.path.join(side_dir, "manifest.json"), {})
    return {entry.get("path") for entry in data.get("entries", []) if entry.get("path")}


def idempotency(side_dir):
    return read_json(os.path.join(side_dir, "round2", "idempotency.json"))


def harness_error(side_dir):
    if install_rc(side_dir) == 124:
        return "driver rc=124"
    log = read_text(os.path.join(side_dir, "install.log"))
    if "HARNESS-ERROR" in log:
        return "HARNESS-ERROR marker in install.log"
    if install_rc(side_dir) is None and not os.path.isdir(side_dir):
        return "missing evidence directory"
    return None


def group_roots(paths):
    groups = {}
    for path in paths:
        parts = [p for p in path.split("/") if p]
        root = "/" + "/".join(parts[:3]) if len(parts) >= 3 else path
        groups.setdefault(root, 0)
        groups[root] += 1
    return groups


def diff_manifests(bash_paths, go_paths):
    added = sorted(go_paths - bash_paths)
    removed = sorted(bash_paths - go_paths)
    return removed, added


def ed_suppression(diffs, scenario, layer, entries):
    """Returns (suppressed, unsuppressed).

    Class-level EDs match an exact path set and an explicit scenario list:
    a new file under an approved directory, or a new scenario, is never
    absorbed by an existing approval.
    """
    suppressed, unsuppressed = {}, []
    active = [e for e in entries
              if e.get("layer") == layer and scenario in (e.get("scenarios") or [])]
    for path in diffs:
        hit = None
        for entry in active:
            if path in (entry.get("paths") or []):
                hit = entry
                break
        if hit is None:
            unsuppressed.append(path)
        else:
            suppressed[path] = hit
    return suppressed, unsuppressed


def ed_state(entry):
    status = entry.get("status")
    expires = entry.get("expires")
    if status != "approved":
        return "BLOCKER(%s)" % (status or "unknown")
    if not entry.get("owner") or not entry.get("approved_by") or not expires:
        return "BLOCKER(missing-owner/approver/expires)"
    try:
        if datetime.date.fromisoformat(expires) < datetime.date.today():
            return "BLOCKER(expired)"
    except ValueError:
        return "BLOCKER(bad-expires)"
    return "ED"


def side_summary(side_dir):
    return {
        "rc": install_rc(side_dir),
        "l4": l4_results(side_dir, None),
        "relayL4": relay_l4(side_dir, None),
        "rc2": install_rc(os.path.join(side_dir, "round2")),
        "l4Round2": l4_results(side_dir, "round2"),
        "relayL4Round2": relay_l4(side_dir, "round2"),
        "idempotency": idempotency(side_dir),
        "harness": harness_error(side_dir),
        "logs": read_json(os.path.join(side_dir, "logs.json"), {}),
    }


def verdict_for(scenario, bash, go, entries):
    sid = scenario["id"]
    if not scenario.get("eligible", True):
        return "HARNESS-BLOCKED", ["scenario ineligible: " + scenario.get("notes", "")]

    # A subset run (E2E_ONLY) never creates the other scenario directories;
    # that is "not executed", not a harness error.
    if bash["harness"] == go["harness"] == "missing evidence directory":
        return "NOT-RUN", ["scenario not executed in this run"]

    reasons = []
    for side_name, side in (("bash", bash), ("go", go)):
        if side["harness"]:
            return "HARNESS-ERROR", ["%s: %s" % (side_name, side["harness"])]
        if side["rc"] != 0:
            return "BLOCKER", ["%s install rc=%s" % (side_name, side["rc"])]
        if side["rc2"] not in (0, None):
            return "BLOCKER", ["%s repeat install rc=%s" % (side_name, side["rc2"])]
        bad = [name for name, ok in side["l4"].items() if not ok]
        if side["relayL4"] is False:
            bad.append("relay")
        if bad:
            return "BLOCKER", ["%s L4 failed: %s" % (side_name, ",".join(sorted(bad)))]
        bad2 = [name for name, ok in (side.get("l4Round2") or {}).items() if not ok]
        if side.get("relayL4Round2") is False:
            bad2.append("relay")
        if bad2:
            return "BLOCKER", ["%s L4 round2 failed: %s" % (side_name, ",".join(sorted(bad2)))]
        idem = side["idempotency"]
        if idem is not None and not idem.get("ok"):
            return "BLOCKER", ["%s idempotency failed" % side_name]

    bash_paths, go_paths = manifest_paths(os.path.join(EVID, sid, "bash")), \
        manifest_paths(os.path.join(EVID, sid, "go"))
    removed, added = diff_manifests(bash_paths, go_paths)
    diffs = removed + added
    if diffs:
        suppressed, unsuppressed = ed_suppression(diffs, sid, "L1", entries)
        if unsuppressed:
            return "BLOCKER", ["unregistered L1 layout diff (%d paths)" % len(unsuppressed)]
        blocked = [p for p, e in suppressed.items() if ed_state(e).startswith("BLOCKER")]
        if blocked:
            return "BLOCKER", ["ED not approved for %d L1 paths" % len(blocked)]
        if suppressed:
            return ",".join(sorted({e["id"] for e in suppressed.values()})), \
                ["%d L1 paths suppressed by registered ED" % len(suppressed)]
        return "BLOCKER", ["unregistered L1 layout diff (%d paths)" % len(unsuppressed)]
    return "MATCH", []


def render_edits(evidence, matrix):
    """Go-only config-edit rows: before/after plus restart-failure rollback."""
    entries = matrix.get("edits", [])
    if not entries:
        return []
    lines = ["## 配置编辑场景（xray config edit，Go）", "",
             "| 场景 | 编辑 rc | SHA 改前 → 改后 | 检查项 | L4 改前/改后 | 判定 | 说明 |",
             "|---|---|---|---|---|---|---|"]
    sha_notes = []
    for entry in entries:
        eid = entry["id"]
        if not in_scope("edits", eid):
            lines.append("| %s %s | — | — | — | — / — | **NOT-RUN** | 未在本轮 scope 内 |" % (
                eid, entry.get("name", "")))
            continue
        base = os.path.join(evidence, eid, "go")
        checks = read_json(os.path.join(base, "edit", "checks.json"), {})
        before = read_json(os.path.join(base, "edit", "L4-before", "connectivity.json"), {})
        after = read_json(os.path.join(base, "edit", "L4-after", "connectivity.json"), {})
        got = checks.get("checks", {})
        wanted = checks.get("wanted") or entry.get("checks", [])

        def mark(value):
            return "ok" if value is True else ("fail" if value is False else "-")

        def short(value):
            return (value or "-")[:12]

        passed = bool(checks) and checks.get("allPassed") is True and \
            before.get("ok") is True and after.get("ok") is True
        notes = []
        if not checks:
            notes.append("缺 checks.json")
        if before.get("ok") is not True:
            notes.append("改前 L4 未通过")
        if after.get("ok") is not True:
            notes.append("改后/回滚后 L4 未通过")
        if eid == "E2" and got.get("configRestored") is True:
            notes.append("回滚后 SHA 还原")
        if eid == "E3" and got.get("probeRefused") is True:
            notes.append("回源不可达被拒绝，零落盘")
        if eid == "E4" and got.get("probeReported") is True:
            notes.append("回源探测通过后落盘")
        detail = ", ".join("%s:%s" % (name, mark(got.get(name))) for name in wanted) or "-"
        lines.append("| %s %s | %s | %s → %s | %s | %s / %s | **%s** | %s |" % (
            eid, entry.get("name", ""), checks.get("editRc", "-"),
            short(checks.get("beforeSha")), short(checks.get("afterSha")), detail,
            mark(before.get("ok")), mark(after.get("ok")),
            "PASS" if passed else "BLOCKER",
            ("; ".join(notes) or entry.get("notes", "")).replace("|", "/")))
        if checks:
            sha_notes.append("- %s SHA：改前 `%s` → 改后 `%s`（%s）" % (
                eid, checks.get("beforeSha", "-"), checks.get("afterSha", "-"),
                "已还原" if checks.get("beforeSha") == checks.get("afterSha") else "已变更"))
    lines.append("")
    lines.extend(sha_notes)
    lines.append("")
    return lines


def cell_parts(side):
    return {
        "rc": side["rc"],
        "l4": side["l4"] if side["l4"] else ({"relay": side["relayL4"]} if side["relayL4"] is not None else {}),
        "l4r2": side["l4Round2"] if side["l4Round2"] else (
            {"relay": side["relayL4Round2"]} if side["relayL4Round2"] is not None else {}),
        "rc2": side["rc2"],
        "l6": (side["idempotency"] or {}).get("ok"),
    }


def cell_label(bash, go, verdict):
    def fmt_side(side):
        parts = cell_parts(side)
        l4 = ",".join("%s:%s" % (k, "ok" if v is True else "fail") for k, v in sorted(parts["l4"].items())) or "-"
        l4r2 = ",".join("%s:%s" % (k, "ok" if v is True else "fail") for k, v in sorted(parts["l4r2"].items())) or "-"
        l6 = "-" if parts["l6"] is None else ("ok" if parts["l6"] else "fail")
        return "%s / %s / %s / %s / %s" % (
            parts["rc"] if parts["rc"] is not None else "-", l4, l4r2,
            parts["rc2"] if parts["rc2"] is not None else "-", l6)
    return "%s / %s / %s" % (fmt_side(bash), fmt_side(go), verdict)


def runtime_ports(evidence, sid, side, loopback=False):
    """Ports owned by the install, excluding docker DNS and the 80/443 front."""
    data = read_json(os.path.join(evidence, sid, side, "runtime.json"), {})
    ports = set()
    for item in data.get("listeners", []):
        local = item.get("local", "")
        if local.startswith("127.0.0.11"):
            continue
        host, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        if loopback:
            if host != "127.0.0.1":
                continue
        elif host in ("0.0.0.0", "[::]", "*") and port in ("80", "443"):
            continue
        ports.add(int(port))
    return ", ".join(str(p) for p in sorted(ports)) or "-"


def nginx_files(evidence, sid, side):
    data = read_json(os.path.join(evidence, sid, side, "manifest.json"), {})
    root = "/etc/idleleo/conf/nginx"
    names = [os.path.basename(e.get("path", "")) for e in data.get("entries", [])
             if e.get("path", "").startswith(root + "/")
             and e.get("path", "").count("/") == root.count("/") + 1]
    return ", ".join(sorted(names)) or "-"


def render_step_changes(evidence, baseline):
    if not baseline or not os.path.isdir(baseline):
        return []
    lines = ["## 三步改动落地证据", "",
             "| 主题 | 基线 go | 本轮 go | 本轮 bash | 关联 |",
             "|---|---|---|---|---|",
             "| M10 relay nginx 文件 | %s | %s | %s | G8 |" % (
                 nginx_files(baseline, "M10", "go"), nginx_files(evidence, "M10", "go"),
                 nginx_files(evidence, "M10", "bash")),
             "| M3 附加传输端口 | %s | %s | %s | G9 |" % (
                 runtime_ports(baseline, "M3", "go"), runtime_ports(evidence, "M3", "go"),
                 runtime_ports(evidence, "M3", "bash")),
             "| M7 附加传输端口 | %s | %s | %s | G9 |" % (
                 runtime_ports(baseline, "M7", "go"), runtime_ports(evidence, "M7", "go"),
                 runtime_ports(evidence, "M7", "bash")),
             "| M4 TLS 回环端口 | %s | %s（公网 443） | %s | G10 |" % (
                 runtime_ports(baseline, "M4", "go", True), runtime_ports(evidence, "M4", "go", True),
                 runtime_ports(evidence, "M4", "bash", True)),
             "| E1/E2 配置编辑 | 无 | 2 场景 PASS（见上表） | — | G11 |",
             ""]
    return lines


def render_baseline(evidence, baseline, matrix, entries):
    """Per-scenario diff against an earlier run; only changed cells are named."""
    if not baseline or not os.path.isdir(baseline):
        return []
    global EVID
    lines = ["## 与基线对比（%s）" % os.path.basename(baseline.rstrip("/")), "",
             "| 场景 | 基线（bash ‖ go ‖ 判定；每侧 rc/L4r1/L4r2/rc2/L6） | "
             "本轮（bash ‖ go ‖ 判定；每侧 rc/L4r1/L4r2/rc2/L6） | 变化格子 |",
             "|---|---|---|---|"]
    current = EVID
    changed_total = 0
    try:
        for scenario in matrix.get("install", []):
            sid = scenario["id"]
            snapshots = []
            for root in (baseline, evidence):
                EVID = root
                bash = side_summary(os.path.join(root, sid, "bash"))
                go = side_summary(os.path.join(root, sid, "go"))
                verdict, _ = verdict_for(scenario, bash, go, entries)
                snapshots.append((bash, go, verdict))
            (bb, bg, bv), (cb, cg, cv) = snapshots
            changes = []
            for side_name, old, new in (("bash", bb, cb), ("go", bg, cg)):
                op, np_ = cell_parts(old), cell_parts(new)
                for key in ("rc", "l4", "l4r2", "rc2", "l6"):
                    if op[key] != np_[key]:
                        if key in ("l4", "l4r2"):
                            changes.append("%s.%s 变化" % (side_name, key))
                            continue
                        changes.append("%s.%s %s→%s" % (
                            side_name, key, op[key] if op[key] is not None else "-",
                            np_[key] if np_[key] is not None else "-"))
            if bv != cv:
                changes.append("判定 %s→%s" % (bv, cv))
            if changes:
                changed_total += 1
            lines.append("| %s | %s | %s | %s |" % (
                sid, cell_label(bb, bg, bv), cell_label(cb, cg, cv),
                "; ".join(changes) if changes else "—"))
        edit_changes = []
        for entry in matrix.get("edits", []):
            eid = entry["id"]
            base_dir = os.path.join(baseline, eid, "go", "edit", "checks.json")
            cur_dir = os.path.join(evidence, eid, "go", "edit", "checks.json")
            if os.path.exists(cur_dir) and not os.path.exists(base_dir):
                edit_changes.append("%s 新增" % eid)
        if edit_changes:
            lines.append("| %s | 无 | 已执行 | %s |" % (
                ",".join(e.get("id", "") for e in matrix.get("edits", [])),
                "; ".join(edit_changes)))
        lines.append("")
        lines.append("本轮预期变化：G8 → M10 文件集合；G9 → M3/M7 端口；"
                     "G10 → M4/M7 重启；G11 → E1/E2 新增。")
        lines.append("")
    finally:
        EVID = current
    return lines


def render_ops(evidence, matrix):
    """OPS rows backed by a real execution record.

    A row is rendered from `<evidence>/<id>/ops.json`, so PASS only ever comes
    from two-sided observations. A row declared `must-match` without that file
    is NOT-RUN: the declaration has no execution behind it and must never read
    as a pass.
    """
    rows = []
    for entry in matrix.get("ops", []):
        oid = entry.get("id", "")
        data = read_json(os.path.join(evidence, oid, "ops.json"))
        if data is None:
            if entry.get("verdict") == "must-match":
                rows.append((oid, entry.get("name", ""), "-", "-", "-",
                             "**NOT-RUN**", "未执行，不得视为通过"))
            continue
        rcs = data.get("bothInstallRc") or {}
        rcs_text = "bash=%s / go=%s" % (
            rcs.get("bash") if rcs.get("bash") is not None else "-",
            rcs.get("go") if rcs.get("go") is not None else "-")

        def mark(value):
            return "true" if value is True else ("false" if value is False else "-")

        upstreams = data.get("upstreams")
        backends = data.get("backends")
        if upstreams:
            # OPS-32 drills several upstreams; show each one per side.
            def upstream_text(side):
                parts = []
                for name in sorted(upstreams):
                    items = ((upstreams.get(name) or {}).get("backends") or {}).get(side) or []
                    parts.append("%s: %s" % (name, ",".join(items) if items else "-"))
                return "%s: %s" % (side, " ‖ ".join(parts))
            observation = "%s ‖ %s" % (upstream_text("bash"), upstream_text("go"))
            detail = " / ".join(
                "%s %s" % (name, (upstreams.get(name) or {}).get("verdict"))
                for name in sorted(upstreams))
        elif backends is not None:
            # Load-balancer rows (OPS-09 / OPS-31) observe backends and files.
            def backend_text(side):
                items = backends.get(side) or []
                return "%s: %s" % (side, ",".join(items) if items else "-")
            observation = "%s ‖ %s" % (backend_text("bash"), backend_text("go"))
            files = data.get("files") or {}

            def files_text(side):
                entry = files.get(side) or {}
                created = ",".join(entry.get("created") or []) or "-"
                after = ",".join(entry.get("afterRemove") or []) or "-"
                return "%s: 创建 %s / 删除后 %s" % (side, created, after)
            detail = "%s ‖ %s" % (files_text("bash"), files_text("go"))
        else:
            jails = data.get("jails") or {}

            def jail_text(side):
                names = jails.get(side) or []
                return "%s: %s" % (side, ",".join(names) if names else "-")
            observation = "%s ‖ %s" % (jail_text("bash"), jail_text("go"))
            detail = "%s / %s" % (mark(data.get("bannedBefore")),
                                  mark(data.get("bannedAfter")))

        rows.append((oid, entry.get("name", ""), rcs_text, observation, detail,
                     "**%s**" % (data.get("verdict") or "HARNESS-ERROR"),
                     "; ".join(data.get("reasons") or [])))
    if not rows:
        return []
    lines = ["## OPS 运营场景（实跑证据）", "",
             "只有两侧观测一致才渲染 PASS；声明 `must-match` 却没有 `ops.json` 的 OPS "
             "一律渲染为 NOT-RUN（未执行，不得视为通过）。", "",
             "| 场景 | 两侧 install rc | 两侧后端 / jail | 文件（创建 / 删除后）或封禁前 / 解封后 | 判定 | 说明 |",
             "|---|---|---|---|---|---|"]
    for row in rows:
        lines.append("| %s %s | %s | %s | %s | %s | %s |" % (
            row[0], row[1], row[2], row[3], row[4], row[5],
            (row[6] or "-").replace("|", "/")))
    lines.append("")
    return lines


def render(evidence, matrix, entries, baseline=None):
    scenarios = matrix.get("install", [])
    global SCOPE
    SCOPE = load_scope(evidence)
    lines = []
    lines.append("# P2 install matrix — %s" % os.path.basename(evidence.rstrip("/")))
    lines.append("")
    lines.append("Generated %s. Round 1 is primary; round 2 is the idempotency round." %
                 datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("")
    if SCOPE is not None:
        ran = []
        for key, label in (("installs", "安装"), ("edits", "编辑"), ("ops", "OPS")):
            items = sorted(SCOPE.get(key, set()))
            if items:
                ran.append("%s %s" % (label, "/".join(items)))
        lines.append("> 局部跑（scope.json）：本轮只执行 %s；未跑场景记 NOT-RUN，"
                     "不计入阻塞，也不得作为全量通过的证据。" % ("；".join(ran) or "-"))
        lines.append("")
    lines.append("| 场景 | bash rc / L4r1 / L4r2 / rc2 / L6 | go rc / L4r1 / L4r2 / rc2 / L6 | 判定 | 说明 |")
    lines.append("|---|---|---|---|---|")
    details = []
    for scenario in scenarios:
        sid = scenario["id"]
        bash = side_summary(os.path.join(evidence, sid, "bash"))
        go = side_summary(os.path.join(evidence, sid, "go"))

        def fmt(side):
            def mark(v):
                return "ok" if v is True else ("fail" if v is False else "-")
            l4 = ",".join("%s:%s" % (k, mark(v)) for k, v in sorted(side["l4"].items())) or \
                ("relay:" + mark(side["relayL4"]) if side["relayL4"] is not None else "-")
            l4r2 = ",".join("%s:%s" % (k, mark(v)) for k, v in sorted(side["l4Round2"].items())) or \
                ("relay:" + mark(side["relayL4Round2"]) if side["relayL4Round2"] is not None else "-")
            idem = side["idempotency"]
            return "%s / %s / %s / %s / %s" % (
                side["rc"] if side["rc"] is not None else "-", l4, l4r2,
                side["rc2"] if side["rc2"] is not None else "-",
                ("ok" if idem.get("ok") else "fail") if idem else "-")

        in_run = in_scope("installs", sid)
        if in_run:
            verdict, reasons = verdict_for(scenario, bash, go, entries)
            bash_cell, go_cell = fmt(bash), fmt(go)
        else:
            # Not executed. Never let a partial run inherit MATCH or report a
            # missing-evidence harness error for a scenario it never touched.
            verdict, reasons = "NOT-RUN", ["未在本轮 scope 内（E2E_ONLY 局部跑）"]
            bash_cell = go_cell = "—"
        lines.append("| %s %s | %s | %s | **%s** | %s |" % (
            sid, scenario.get("name", ""), bash_cell, go_cell, verdict,
            "; ".join(reasons).replace("|", "/")))
        details.append((sid, scenario, bash, go, verdict, reasons))

    lines.append("")
    counts = {}
    for _, _, _, _, verdict, _ in details:
        counts[verdict] = counts.get(verdict, 0) + 1
    summary = "，".join("%s=%d" % (k, counts[k]) for k in sorted(counts))
    lines.append("本轮判定：" + summary + "。NOT-RUN 表示该场景未在本轮执行，不得视为通过。")
    lines.append("")
    lines.extend(render_ops(evidence, matrix))
    lines.append("## 未验 / 阻塞项")
    lines.append("")
    for sid, scenario, bash, go, verdict, reasons in details:
        if verdict in ("HARNESS-BLOCKED",) or "HARNESS" in verdict:
            lines.append("- **%s %s** — %s：%s" % (sid, scenario.get("name"), verdict,
                                                  "; ".join(reasons) or scenario.get("notes", "")))
    lines.append("")
    lines.append("## L1 布局差异（未抑制）")
    lines.append("")
    found = False
    for sid, scenario, bash, go, verdict, reasons in details:
        if verdict not in ("BLOCKER",):
            continue
        bp = manifest_paths(os.path.join(evidence, sid, "bash"))
        gp = manifest_paths(os.path.join(evidence, sid, "go"))
        removed, added = diff_manifests(bp, gp)
        if not removed and not added:
            continue
        found = True
        lines.append("### %s（bash 有 / go 无 %d；go 有 / bash 无 %d）" %
                     (sid, len(removed), len(added)))
        for label, items in (("bash-only", removed), ("go-only", added)):
            if not items:
                continue
            roots = group_roots(set(items))
            lines.append("- %s roots: %s" % (label, ", ".join(
                "%s(%d)" % (k, v) for k, v in sorted(roots.items())[:8])))
            lines.append("  samples: %s" % ", ".join(items[:5]))
        lines.append("")
    if not found:
        lines.append("无。")
    lines.append("")
    lines.append("## EXPECTED-DIFF 登记表（按类审批）")
    lines.append("")
    lines.append("匹配口径：`paths` 精确匹配 + `scenarios` 显式列举。新增文件或新增场景"
                 "不会被已批准类别吸收，一律重新 BLOCKER。")
    lines.append("")
    lines.append("| ED | 类别 | 场景数 | 层 | 路径数 | owner | approved_by | expires | supersedes | 状态 |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for entry in entries:
        lines.append("| %s | %s | %d | %s | %d | %s | %s | %s | %d | %s |" % (
            entry.get("id"), entry.get("title"), len(entry.get("scenarios") or []),
            entry.get("layer"), len(entry.get("paths") or []),
            entry.get("owner") or "-", entry.get("approved_by") or "-",
            entry.get("expires") or "-", len(entry.get("supersedes") or []),
            ed_state(entry)))
    lines.append("")
    rejected = [e for e in entries if e.get("decision") == "fix-go"]
    if rejected:
        lines.append("### 不予批准（转 Go 待办）")
        lines.append("")
        lines.append("| ED | 待办 | 理由 |")
        lines.append("|---|---|---|")
        for entry in rejected:
            lines.append("| %s | %s | %s |" % (
                entry.get("id"), entry.get("backlog") or "-",
                (entry.get("rejected_reason") or "").replace("|", "/")))
        lines.append("")
    lines.append("批准性质：`approved_by=release-gate` 为流程批准，当前无第二维护者账号，"
                 "**不是双人批准**；`expires=2027-03-31` 到期自动回落 BLOCKER，"
                 "发布前须完成到期复核。")
    lines.append("")
    lines.extend(render_edits(evidence, matrix))
    if SCOPE is not None:
        lines.append("## 与基线对比")
        lines.append("")
        lines.append("本轮为局部跑，跳过基线与三步改动对比，避免把未跑场景渲染成变化。")
        lines.append("")
    else:
        lines.extend(render_baseline(evidence, baseline, matrix, entries))
        lines.extend(render_step_changes(evidence, baseline))
    lines.append("## 未覆盖/未验证")
    lines.append("")
    ineligible = [s for s in matrix.get("install", []) if not s.get("eligible", True)]
    for scenario in ineligible:
        lines.append("- %s（%s）：`eligible:false`，按计划记 HARNESS-BLOCKED。"
                     % (scenario.get("id"), scenario.get("name")))
    if not ineligible:
        lines.append("- 全部安装场景 eligible；M8 走真实本地 Pebble ACME，"
                     "ACME 专属产物（cert/、.well-known、schedule/）两侧已对齐。")
    lines.append("- L2 仅记录 sanitized config 摘要，未做全字段语义 diff；L3/L5 以采集件为准。")
    return "\n".join(lines) + "\n"


def self_test():
    """Minimal assertions against a synthetic evidence tree."""
    import tempfile

    def dump(base, rel, obj):
        path = os.path.join(base, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            if isinstance(obj, str):
                fh.write(obj)
            else:
                json.dump(obj, fh)

    with tempfile.TemporaryDirectory() as tmp:
        dump(tmp, "M1/bash/install.rc", "0")
        dump(tmp, "M1/go/install.rc", "0")
        for side in ("bash", "go"):
            dump(tmp, "M1/%s/L4/ws/connectivity.json" % side, {"ok": True})
            dump(tmp, "M1/%s/manifest.json" % side,
                 {"entries": [{"path": "/etc/idleleo/conf/xray/config.json", "sha256": "x"}]})
        matrix = {"install": [{"id": "M1", "name": "t", "eligible": True,
                               "go": {"argv": ["x"], "verified": True}}]}
        global EVID
        EVID = tmp
        text = render(tmp, matrix, [])
        assert "**MATCH**" in text, text
        approved = [{"id": "ED-C01", "layer": "L1", "scenarios": ["M1"],
                     "paths": ["/usr/local/nginx/sbin/nginx"], "status": "approved",
                     "owner": "o", "approved_by": "release-gate", "expires": "2099-01-01"}]
        dump(tmp, "M1/bash/manifest.json",
             {"entries": [{"path": "/usr/local/nginx/sbin/nginx", "sha256": "y"},
                          {"path": "/etc/idleleo/conf/xray/config.json", "sha256": "x"}]})
        text = render(tmp, matrix, approved)
        assert "ED-C01" in text and "**MATCH**" not in text, text
        # guardrail 1: a new file under an approved directory must not be absorbed
        dump(tmp, "M1/bash/manifest.json",
             {"entries": [{"path": "/usr/local/nginx/sbin/nginx", "sha256": "y"},
                          {"path": "/usr/local/nginx/sbin/nginx.new", "sha256": "z"},
                          {"path": "/etc/idleleo/conf/xray/config.json", "sha256": "x"}]})
        text = render(tmp, matrix, approved)
        assert "unregistered L1 layout diff" in text, text
        # guardrail 2: an approved class does not extend to a new scenario
        matrix2 = dict(matrix)
        matrix2["install"] = matrix["install"] + [{"id": "M11", "name": "t2", "eligible": True}]
        for side in ("bash", "go"):
            dump(tmp, "M11/%s/install.rc" % side, "0")
            dump(tmp, "M11/%s/L4/ws/connectivity.json" % side, {"ok": True})
        dump(tmp, "M11/bash/manifest.json", {"entries": [{"path": "/usr/local/nginx/sbin/nginx",
                                                          "sha256": "y"}]})
        dump(tmp, "M11/go/manifest.json", {"entries": []})
        text = render(tmp, matrix2, approved)
        assert "M11" in text and "unregistered L1 layout diff" in text, text
        # rejected decisions stay BLOCKER even with all fields filled
        rejected = dict(approved[0])
        rejected.update({"status": "rejected", "decision": "fix-go"})
        text = render(tmp, matrix, [rejected])
        assert "BLOCKER(rejected)" in text, text
        # guardrail 3: a must-match OPS row without ops.json is NOT-RUN, never a pass
        matrix3 = dict(matrix)
        matrix3["ops"] = [{"id": "OPS-19", "name": "Fail2ban", "verdict": "must-match"}]
        text = render(tmp, matrix3, [])
        assert "**NOT-RUN**" in text and "未执行，不得视为通过" in text, text
        assert "**PASS**" not in text, text
        dump(tmp, "OPS-19/ops.json", {
            "id": "OPS-19", "verdict": "PASS",
            "bothInstallRc": {"bash": 0, "go": 0},
            "jails": {"bash": ["nginx-badbots"], "go": ["nginx-badbots"]},
            "bannedBefore": True, "unbanned": True, "bannedAfter": False,
            "reasons": []})
        text = render(tmp, matrix3, [])
        assert "**PASS**" in text and "**NOT-RUN**" not in text, text
        # an executed failure must not be laundered into a pass either
        dump(tmp, "OPS-19/ops.json", {
            "id": "OPS-19", "verdict": "BLOCKER",
            "bothInstallRc": {"bash": 0, "go": 1},
            "jails": {"bash": ["nginx-badbots"], "go": []},
            "bannedBefore": False, "unbanned": False, "bannedAfter": False,
            "reasons": ["go fail2ban install rc=1"]})
        text = render(tmp, matrix3, [])
        assert "**BLOCKER**" in text and "go fail2ban install rc=1" in text, text
        # guardrail 4: load-balancer rows must show both sides' backends and files
        matrix3["ops"] = [{"id": "OPS-09", "name": "Nginx 负载均衡", "verdict": "must-match"}]
        text = render(tmp, matrix3, [])
        assert "**NOT-RUN**" in text, text
        dump(tmp, "OPS-09/ops.json", {
            "id": "OPS-09", "verdict": "PASS",
            "bothInstallRc": {"bash": 0, "go": 0},
            "backends": {"bash": ["10.99.0.7:9447 weight=60"],
                         "go": ["10.99.0.7:9447 weight=60"]},
            "files": {"bash": {"created": ["10.99.0.7.wsServers"], "afterRemove": []},
                      "go": {"created": ["10.99.0.7.wsServers"], "afterRemove": []}},
            "reasons": []})
        text = render(tmp, matrix3, [])
        assert "**PASS**" in text and "10.99.0.7.wsServers" in text, text
        assert "bash: 10.99.0.7:9447 weight=60" in text and \
            "go: 10.99.0.7:9447 weight=60" in text, text
        # guardrail 5: a partial run marks unexecuted scenarios NOT-RUN, while an
        # in-scope scenario with no evidence is still a harness error.
        with tempfile.TemporaryDirectory() as tmp2:
            for side in ("bash", "go"):
                dump(tmp2, "M1/%s/install.rc" % side, "0")
                dump(tmp2, "M1/%s/L4/ws/connectivity.json" % side, {"ok": True})
                dump(tmp2, "M1/%s/manifest.json" % side,
                     {"entries": [{"path": "/etc/idleleo/conf/xray/config.json",
                                   "sha256": "x"}]})
            matrixp = {"install": [
                {"id": "M1", "name": "t", "eligible": True,
                 "go": {"argv": ["x"], "verified": True}},
                {"id": "M2", "name": "t2", "eligible": True}]}
            dump(tmp2, "scope.json", {"only": "M1", "installs": ["M1"],
                                      "edits": [], "ops": [], "sides": ["bash", "go"]})
            EVID = tmp2
            text = render(tmp2, matrixp, [])
            assert "**MATCH**" in text, text
            assert "M2" in text and "**NOT-RUN**" in text, text
            assert "missing evidence" not in text and "HARNESS-ERROR" not in text, text
            dump(tmp2, "scope.json", {"only": "M1,M2", "installs": ["M1", "M2"],
                                      "edits": [], "ops": [], "sides": ["bash", "go"]})
            # In scope but only one side produced evidence: still a harness gap,
            # never a NOT-RUN, so a broken side cannot hide behind a partial run.
            dump(tmp2, "M2/bash/install.rc", "0")
            text = render(tmp2, matrixp, [])
            assert "HARNESS-ERROR" in text and "missing evidence" in text, text
    print("self-test ok")


def main():
    global EVID
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence")
    parser.add_argument("--matrix")
    parser.add_argument("--diffs")
    parser.add_argument("--baseline", help="earlier run directory to diff against")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    for required in ("evidence", "matrix", "diffs"):
        if not getattr(args, required):
            parser.error("--%s required" % required)
    EVID = args.evidence
    matrix = read_json(args.matrix, {})
    diffs = read_json(args.diffs, {})
    entries = diffs.get("entries", [])
    text = render(args.evidence, matrix, entries, args.baseline)
    out = os.path.join(args.evidence, "install-matrix.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(out)


if __name__ == "__main__":
    sys.exit(main())
