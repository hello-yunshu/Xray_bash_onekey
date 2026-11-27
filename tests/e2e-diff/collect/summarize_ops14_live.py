#!/usr/bin/env python3
"""Summarize the real iftop versus bounded stats-watch probe."""
import glob
import json
import os
import sys

bash_dir, go_dir, output = sys.argv[1:4]


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def rc(path):
    try:
        return int(read(path).strip())
    except ValueError:
        return None


def client_runs(directory):
    rows = []
    for path in sorted(glob.glob(os.path.join(directory, "L4-*.rc"))):
        name = os.path.basename(path)[:-3]
        try:
            with open(os.path.join(directory, name, "L4", "reality", "connectivity.json"), encoding="utf-8") as fh:
                ok = json.load(fh).get("ok") is True
        except (OSError, ValueError):
            ok = False
        rows.append({"id": name, "rc": rc(path), "ok": ok})
    return rows


transcript = read(os.path.join(bash_dir, "run.out")) + read(os.path.join(bash_dir, "run.log"))
try:
    with open(os.path.join(go_dir, "11-watch.out"), encoding="utf-8") as fh:
        samples = json.load(fh)
except (OSError, ValueError):
    samples = []
points = [point for sample in samples for point in sample.get("stats", [])]
positive_rates = [point for point in points
                  if isinstance(point.get("bytesPerSecond"), (int, float))
                  and point["bytesPerSecond"] > 0]
positive_proxy_rates = [point for point in positive_rates
                        if point.get("name", "").startswith("inbound>>>VLESS-Reality-in>>>")]
result = {
    "id": "OPS-14",
    "verdict": "DIFF",
    "scope": "Bash 3>4 iftop versus Go bounded Xray API rate sampling",
    "bash": {
        "iftopInstallRc": rc(os.path.join(bash_dir, "iftop-install.rc")),
        "driverRc": rc(os.path.join(bash_dir, "run.rc")),
        "ready": read(os.path.join(bash_dir, "iftop-ready.txt")).strip() == "1",
        "uiObserved": "STEP[iftopPrompt]=observed" in transcript and "STEP[iftopCounters]=visible" in transcript,
        "l4": client_runs(bash_dir),
    },
    "go": {
        "apiEnableRc": rc(os.path.join(go_dir, "10-enable.rc")),
        "watchRc": rc(os.path.join(go_dir, "11-watch.rc")),
        "sampleCount": len(samples),
        "positiveRatePoints": len(positive_rates),
        "positiveProxyRatePoints": len(positive_proxy_rates),
        "stats": points,
        "l4": client_runs(go_dir),
    },
    "tradeoff": {
        "goAvoidsPacketAndPeerAddressCapture": True,
        "goBoundedSamples": len(samples) == 30,
        "bashProvidesPerPeerPacketView": True,
    },
}
with open(output, "w", encoding="utf-8") as fh:
    json.dump(result, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
print(json.dumps({"bash": result["bash"], "go": {k: result["go"][k] for k in
      ("apiEnableRc", "watchRc", "sampleCount", "positiveRatePoints", "positiveProxyRatePoints", "l4")}}, ensure_ascii=False, sort_keys=True))
passed = (
    result["bash"]["iftopInstallRc"] == 0 and result["bash"]["driverRc"] == 0
    and result["bash"]["ready"] and result["bash"]["uiObserved"]
    and result["go"]["apiEnableRc"] == 0 and result["go"]["watchRc"] == 0
    and len(samples) == 30 and bool(positive_proxy_rates)
    and all(run["rc"] == 0 and run["ok"] for side in (result["bash"], result["go"])
            for run in side["l4"])
)
if not passed:
    raise SystemExit(1)
