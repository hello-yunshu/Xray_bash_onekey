#!/usr/bin/env python3
"""OPS-32 verdict analyzer.

Reads one upstream's evidence directory (bash/ and go/) and writes ops.json.

Measurement rules (the "full window + stable recovery" revision):
  * the recovery probe runs its whole window instead of stopping at the first
    A. First-A is still recorded, but a side only counts as recovered when the
    trailing run of the window is all A (>= --stable-min consecutive A).
  * per-worker max_fails counters are reported as `perWorkerFails`, plus a
    summary and the jitter range of the quiet stretches. There is no shared
    zone, so one worker can remove the peer while another never reaches
    max_fails: a single probe's first-A is a sampling point, not the global
    recovery time.

Usage:
    ops32_analyze.py <base> <mode> <suffix> <a_host> <a_port> <b_host> <b_port>
                     <weight> <recovery_count> <recovery_interval> [stable_min]
"""

import calendar
import datetime
import json
import os
import re
import sys

(base, mode, suffix, a_host, a_port, b_host, b_port, weight,
 recovery_count, recovery_interval) = sys.argv[1:11]
stable_min = int(sys.argv[11]) if len(sys.argv) > 11 else 3
a_port, b_port, weight = int(a_port), int(b_port), int(weight)
recovery_cap = float(recovery_count) * float(recovery_interval)
sides = ("bash", "go")
max_fails = 2
fail_timeout = 10


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def read_rc(path):
    raw = read_text(path)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def read_state(path):
    state = {}
    for line in (read_text(path) or "").splitlines():
        if "\t" not in line:
            continue
        key, value = line.split("\t", 1)
        state[key] = value
    return state


def read_probe(path):
    rows = []
    for line in (read_text(path) or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        try:
            epoch = float(parts[0])
        except ValueError:
            continue
        rows.append({
            "epoch": epoch, "phase": parts[1], "seq": parts[2],
            "rc": parts[3], "code": parts[4], "body": parts[5],
        })
    return rows


def probe_stats(rows):
    bodies = {}
    fivexx = 0
    failures = 0
    for row in rows:
        bodies[row["body"] or "<empty>"] = bodies.get(row["body"] or "<empty>", 0) + 1
        code = row["code"]
        if code.isdigit() and 500 <= int(code) < 600:
            fivexx += 1
        if row["rc"] != "0" or code in ("000", ""):
            failures += 1
    return {
        "requests": len(rows),
        "fivexx": fivexx,
        "connectionFailures": failures,
        "bodies": bodies,
    }


def snapshot(path):
    text = read_text(path)
    if text is None:
        return None
    files, cur = {}, None
    for line in text.splitlines():
        if line.startswith("== "):
            cur = line[3:].strip()
            files[cur] = []
        elif cur is not None:
            files[cur].append(line)
    return {name: "\n".join(body).strip() for name, body in files.items()}


def parse_ts(raw):
    try:
        return calendar.timegm(datetime.datetime.strptime(
            raw, "%Y/%m/%d %H:%M:%S").timetuple())
    except ValueError:
        return None


def fmt_ts(epoch):
    if epoch is None:
        return None
    return datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc).strftime("%Y/%m/%d %H:%M:%S")


FAIL_RE = re.compile(
    r'^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[error\] (\d+)#\d+: \*\d+ '
    r'connect\(\) failed \([^)]*\) while connecting to upstream,.*?'
    r'upstream: "(?:https?://)?([^/"]+)')


def dead_attempts(errlog, since):
    """Failures that targeted backend A.

    Nginx logs the resolved peer, not the upstream host name, so the peer is
    identified by host:port. The worker pid is kept because max_fails counters
    are per worker when the upstream has no shared zone.
    """
    out = []
    for line in (errlog or "").splitlines():
        match = FAIL_RE.match(line.strip())
        if not match:
            continue
        host, _, port = match.group(3).rpartition(":")
        if port != str(a_port):
            continue
        if host not in (a_host, "127.0.0.1", "localhost", "[::1]"):
            continue
        epoch = parse_ts(match.group(1))
        if epoch is None or (since and epoch < since):
            continue
        out.append({
            "at": match.group(1), "epoch": epoch,
            "worker": match.group(2), "line": line.strip(),
        })
    return out


def worker_violations(dead, window):
    """No worker may exceed max_fails failures in any fail_timeout window."""
    by_worker = {}
    for entry in dead:
        by_worker.setdefault(entry["worker"], []).append(entry["epoch"])
    violations = []
    for worker, epochs in by_worker.items():
        epochs.sort()
        for start in range(len(epochs)):
            count = 1
            for nxt in epochs[start + 1:]:
                if nxt - epochs[start] < window:
                    count += 1
            if count > max_fails:
                violations.append((worker, count))
    return by_worker, violations


def stable_recovery(rows, gap_cap, min_samples):
    """Earliest A after which A keeps being selected for the rest of the window.

    Both peers are healthy after recovery, so nginx round-robins A and B: an
    all-A tail is not the definition of recovery. Instead, A is stable when the
    chain of A responses that reaches the end of the window never has a gap
    longer than `gap_cap` seconds and holds at least `min_samples` responses.
    A single A followed by B-only traffic (some workers re-enabled A, others
    did not) breaks the chain and is reported as first-A only.
    """
    hits = [row["epoch"] for row in rows
            if row["body"] == "A" and row["rc"] == "0"]
    if not hits or not rows:
        return 0, None
    if rows[-1]["epoch"] - hits[-1] > gap_cap:
        return 1, None
    chain = [hits[-1]]
    for epoch in reversed(hits[:-1]):
        if chain[-1] - epoch <= gap_cap:
            chain.append(epoch)
        else:
            break
    if len(chain) < min_samples:
        return len(chain), None
    return len(chain), chain[-1]


report = {
    "id": "OPS-32",
    "name": "后端故障摘除",
    "mode": mode,
    "suffix": suffix,
    "bothInstallRc": {},
    "backends": {},
    "configLine": {},
    "warmup": {},
    "duringOutage": {},
    "deadAttempts": {},
    "removedAt": {},
    "recoveredAt": {},
    "files": {},
    "reasons": [],
}
harness, blockers = [], []
per_side_ok = {}

for side in sides:
    d = os.path.join(base, side)
    install_rc = read_rc(os.path.join(d, "install.rc"))
    report["bothInstallRc"][side] = install_rc
    state = read_state(os.path.join(d, "state.tsv"))
    warmup = read_probe(os.path.join(d, "probe-warmup.tsv"))
    outage = (read_probe(os.path.join(d, "probe-outage-burst.tsv")) +
              read_probe(os.path.join(d, "probe-outage-steady.tsv")))
    recovery = read_probe(os.path.join(d, "probe-recovery.tsv"))
    errlog = read_text(os.path.join(d, "error-after-recovery.log"))
    restart_check = (read_text(os.path.join(d, "backend-a-restart-check.txt")) or "").strip()
    report.setdefault("backendRestartCheck", {})[side] = restart_check
    report.setdefault("nginxVersion", {})[side] = (
        read_text(os.path.join(d, "nginx-version.txt")) or "").strip()
    if restart_check != "A":
        harness.append("%s: restarted backend A did not answer its local "
                       "probe (got %r)" % (side, restart_check))
    files_add = snapshot(os.path.join(d, "files-after-add.txt"))
    files_setup = snapshot(os.path.join(d, "servers-after-drop.txt"))
    loc = (read_text(os.path.join(d, "location.txt")) or "").strip()

    missing = []
    if install_rc is None:
        missing.append("install.rc")
    if not state:
        missing.append("state.tsv")
    if not warmup:
        missing.append("probe-warmup.tsv")
    if not outage:
        missing.append("probe-outage.tsv")
    if not recovery:
        missing.append("probe-recovery.tsv")
    if errlog is None:
        missing.append("error-after-recovery.log")
    if not loc:
        missing.append("location.txt")
    if missing:
        harness.append("%s: missing %s" % (side, ", ".join(missing)))
        report["backends"][side] = []
        per_side_ok[side] = False
        continue

    warm = probe_stats(warmup)
    dur = probe_stats(outage)
    report["warmup"][side] = warm
    report["duringOutage"][side] = dur

    since = None
    if state.get("runStartUtc"):
        since = parse_ts(state["runStartUtc"])
    dead = dead_attempts(errlog, since)
    report["deadAttempts"][side] = dead
    with open(os.path.join(d, "dead-attempts.txt"), "w", encoding="utf-8") as fh:
        for entry in dead:
            fh.write("%s\n" % entry["line"])

    by_worker, violations = worker_violations(dead, fail_timeout)
    counts = {worker: len(epochs) for worker, epochs in sorted(by_worker.items())}
    report.setdefault("perWorkerFails", {})[side] = counts
    reached = [worker for worker, count in counts.items() if count >= max_fails]
    below = {worker: count for worker, count in counts.items() if count < max_fails}
    report.setdefault("perWorkerFailSummary", {})[side] = {
        "workers": len(counts),
        "min": min(counts.values()) if counts else None,
        "max": max(counts.values()) if counts else None,
        "reachedMaxFails": sorted(reached),
        "belowMaxFails": below,
    }
    # Per-worker view of the removal: after a worker has seen max_fails
    # failures it must leave the peer alone for fail_timeout. The observed
    # quiet stretch runs from that failure either to the worker's next attempt
    # or to the end of the outage probe.
    outage_end = outage[-1]["epoch"]
    quiet_by_worker = {}
    removed_at = None
    removed_line = None
    for worker, epochs in sorted(by_worker.items()):
        epochs = sorted(epochs)
        if len(epochs) < max_fails:
            continue
        down_at = epochs[max_fails - 1]
        nxt = epochs[max_fails] if len(epochs) > max_fails else None
        quiet_by_worker[worker] = round((nxt if nxt else outage_end) - down_at, 1)
        if removed_at is None or down_at < removed_at:
            removed_at = down_at
            removed_line = next(e["line"] for e in dead
                                if e["epoch"] == down_at and e["worker"] == worker)
    report.setdefault("perWorkerQuietSeconds", {})[side] = quiet_by_worker
    quiet_values = list(quiet_by_worker.values())
    report.setdefault("perWorkerJitter", {})[side] = {
        "quietMin": min(quiet_values) if quiet_values else None,
        "quietMax": max(quiet_values) if quiet_values else None,
        "quietSpread": (round(max(quiet_values) - min(quiet_values), 1)
                        if quiet_values else None),
    }
    report["removedAt"][side] = fmt_ts(removed_at)
    report.setdefault("removedAtBasis", {})[side] = removed_line
    report.setdefault("lastDeadAttemptAt", {})[side] = (
        dead[-1]["at"] if dead else None)
    max_quiet = max(quiet_values) if quiet_values else None

    # Full window + stable recovery. A probe that stopped at first A is only
    # possible in evidence recorded before the measurement revision; it is
    # reported as truncated and cannot claim a stable recovery.
    expected = int(recovery_count)
    truncated = len(recovery) < expected and recovery[-1]["body"] == "A" and recovery[-1]["rc"] == "0"
    window = {
        "requests": len(recovery),
        "expected": expected,
        "capSeconds": recovery_cap,
        "complete": len(recovery) >= expected,
        "stopReason": "first-A (pre-revision evidence)" if truncated else (
            "full window" if len(recovery) >= expected else "probe stopped early"),
    }
    report.setdefault("recoveryWindow", {})[side] = window

    first = next((row for row in recovery
                  if row["body"] == "A" and row["rc"] == "0"), None)
    report["recoveredAt"][side] = fmt_ts(first["epoch"]) if first else None
    report.setdefault("firstRecoveryLatencySeconds", {})[side] = (
        round(first["epoch"] - float(state["restartReady"]), 3)
        if first and state.get("restartReady") else None)

    chain_len, chain_start = stable_recovery(recovery, fail_timeout, stable_min)
    stable = chain_start is not None and window["complete"]
    report.setdefault("stableRecovery", {})[side] = {
        "reached": stable,
        "rule": "A keeps being selected to the end of the window with no gap "
                "longer than %ds and at least %d A responses in the chain"
                % (fail_timeout, stable_min),
        "chainLength": chain_len,
        "at": fmt_ts(chain_start) if stable else None,
        "latencySeconds": (
            round(chain_start - float(state["restartReady"]), 3)
            if stable and state.get("restartReady") else None),
        "observable": window["complete"],
    }
    report.setdefault("lastAAt", {})[side] = fmt_ts(max(
        (row["epoch"] for row in recovery
         if row["body"] == "A" and row["rc"] == "0"), default=None))
    report.setdefault("recoveryFailuresAfterFirstA", {})[side] = (
        sum(1 for row in recovery
            if first and row["epoch"] > first["epoch"]
            and (row["rc"] != "0" or row["code"] in ("000", "")))
        if first else None)

    lines = []
    loopback = "127.0.0.1.%s" % suffix
    for name, body in (files_setup or {}).items():
        if name != loopback:
            lines.append("%s: %s" % (name, body.replace("\n", " ").strip()))
    report["backends"][side] = sorted(lines)
    config = next((body.strip() for name, body in (files_setup or {}).items()
                   if name == "%s.%s" % (a_host, suffix)), "")
    report["configLine"][side] = config
    report["files"][side] = {
        "dir": "/etc/idleleo/conf/nginx",
        "suffix": suffix,
        "created": sorted(files_add or {}),
        "afterRemove": sorted(files_setup or {}),
        "content": files_setup or {},
        "loopbackFragment": (read_text(os.path.join(
            d, "loopback-fragment.txt")) or "").strip(),
        "location": loc,
    }

    problems = []
    if install_rc != 0:
        problems.append("%s: install rc=%s" % (side, install_rc))
    if side == "bash":
        add_rcs = [read_rc(os.path.join(d, "fm-add-%s.rc" % a_host)),
                   read_rc(os.path.join(d, "fm-add-%s.rc" % b_host))]
    else:
        add_rcs = [read_rc(os.path.join(d, "add-%s.rc" % a_host)),
                   read_rc(os.path.join(d, "add-%s.rc" % b_host))]
    if add_rcs != [0, 0]:
        harness.append("%s: balance add rc=%s (backend creation failed)"
                       % (side, add_rcs))
    if state.get("killFailed"):
        problems.append("%s: backend A never went down" % side)
    if state.get("restartFailed"):
        problems.append("%s: backend A never came back" % side)
    if warm["bodies"].get("A", 0) < 1 or warm["bodies"].get("B", 0) < 1:
        problems.append("%s: warmup bodies=%s (both A and B required)"
                        % (side, warm["bodies"]))
    if warm["fivexx"] or warm["connectionFailures"]:
        problems.append("%s: warmup had %d 5xx / %d connection failures"
                        % (side, warm["fivexx"], warm["connectionFailures"]))
    if dur["fivexx"] or dur["connectionFailures"]:
        problems.append("%s: outage had %d 5xx / %d connection failures"
                        % (side, dur["fivexx"], dur["connectionFailures"]))
    if dur["bodies"].get("B", 0) != dur["requests"]:
        problems.append("%s: outage bodies=%s, every request must come from %s"
                        % (side, dur["bodies"], b_host))
    if not dead:
        problems.append("%s: no connect() failure to %s:%d in the error log; "
                        "cannot prove passive removal"
                        % (side, a_host, a_port))
    if violations:
        problems.append(
            "%s: worker(s) %s exceeded max_fails=%d within fail_timeout=%ds; "
            "the dead peer kept being tried"
            % (side, ", ".join("%s=%dx" % v for v in violations),
               max_fails, fail_timeout))
    if not quiet_by_worker:
        harness.append("%s: no worker reached max_fails=%d, not enough "
                       "requests to observe removal" % (side, max_fails))
    elif max_quiet is None or max_quiet < fail_timeout - 2:
        problems.append(
            "%s: best per-worker quiet stretch after removal is %ss "
            "(fail_timeout=%ds)" % (side, max_quiet, fail_timeout))
    if not first:
        problems.append("%s: %s never answered again within %.0fs after "
                        "restart" % (side, a_host, recovery_cap))
    elif window["complete"] and not stable:
        problems.append(
            "%s: %s answered again but the A chain reaching the end of the "
            "window is only %d long (need %d, max gap %ds); first-A alone is "
            "not a recovery"
            % (side, a_host, chain_len, stable_min, fail_timeout))
    elif not window["complete"] and not truncated:
        harness.append("%s: recovery probe stopped after %d/%d requests"
                       % (side, len(recovery), expected))
    missing_fragments = [host for host in (a_host, b_host)
                         if not (files_setup or {}).get("%s.%s" % (host, suffix), "").strip()]
    if missing_fragments:
        harness.append("%s: upstream fragments missing after setup: %s"
                       % (side, ", ".join(missing_fragments)))
    if loopback in (files_setup or {}):
        harness.append("%s: loopback fragment still in the upstream" % side)
    blockers.extend(problems)
    per_side_ok[side] = not problems

if harness:
    verdict = "HARNESS-ERROR"
    report["reasons"] = harness + blockers
else:
    if per_side_ok.get("bash") != per_side_ok.get("go"):
        blockers.append("sides disagree: bash=%s go=%s" %
                        (per_side_ok.get("bash"), per_side_ok.get("go")))
    verdict = "BLOCKER" if blockers else "PASS"
    report["reasons"] = blockers

report["config"] = {
    "maxFails": max_fails,
    "failTimeout": fail_timeout,
    "weight": weight,
    "upstreamCounters": "per nginx worker; the upstream has no shared zone, so "
                        "each worker removes the peer on its own",
    "effectiveWeightDecay": "nginx also decays a failed peer's effective weight "
                            "by weight/max_fails, so re-entry after "
                            "fail_timeout ramps back in over a few requests",
    "recoveryPollSeconds": recovery_cap,
    "recoveryProbe": "the recovery phase runs the whole window (%d probes every "
                     "%.1fs); it does not stop at the first A"
                     % (int(recovery_count), float(recovery_interval)),
    "stableRecoveryRule": "a side counts as recovered only when A keeps being "
                          "selected to the end of the complete window with no "
                          "gap longer than %ds and at least %d A responses"
                          % (fail_timeout, stable_min),
    "loopbackRemovedBy": "harness rm + systemctl reload nginx on both sides",
}
if mode == "stream":
    # A Reality upstream is a raw TCP stream, not an HTTP upstream: there is no
    # response status to count. The marker peers also answer in clear text, so
    # the probe proves *which peer nginx dialled*, not a Reality handshake.
    report["config"]["probe"] = (
        "raw TLS 1.3 ClientHello with the configured SNI over the stream "
        "listener; ssl_preread selects the reality upstream")
    report["config"]["failureMetric"] = (
        "connection failures (rc!=0 / empty reply) instead of HTTP 5xx")
    report["limitations"] = [
        "the marker peers do not implement the Reality handshake; this proves "
        "nginx stream peer selection and passive removal, not an end-to-end "
        "Reality/VLESS session",
        "nginx retries on connect failure before any payload reaches the peer, "
        "so a client-visible failure during the outage is a real blocker",
    ]
report["scenarioNote"] = {
    "perWorkerJitter": "max_fails counters are per nginx worker (the upstream "
                       "has no zone), so failure counts, removal instants and "
                       "quiet stretches differ per worker. perWorkerJitter "
                       "reports that spread; a single probe is one sample, not "
                       "a global recovery time.",
    "recovery": "first-A and stable-A are both recorded. The verdict uses "
                "stable-A; first-A is sampling bias when only some workers "
                "removed the peer.",
}
report["sidesMatch"] = per_side_ok.get("bash") == per_side_ok.get("go")
report["verdict"] = verdict
with open(os.path.join(base, "ops.json"), "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(verdict)
