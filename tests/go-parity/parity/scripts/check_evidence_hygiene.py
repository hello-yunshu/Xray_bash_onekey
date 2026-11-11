#!/usr/bin/env python3
"""Fail when committed evidence leaks a host absolute path or a private address.

Evidence is published verbatim, so it must never carry the machine that
produced it. This checks every tracked text file under the given evidence
roots and exits 1 on the first class of leak, printing file:line:match.

Loopback (127.0.0.0/8) is intentionally allowed: it is produced by the
fixtures themselves and identifies no host.
"""
import re
import sys
from pathlib import Path

HOST_PATHS = re.compile(r"/Users/[^/\s\"']+|/home/[^/\s\"']+|/root/")
PRIVATE_IPV4 = re.compile(
    r"(?<![\d.])("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r")(?![\d.])"
)


def scan(path):
    raw = path.read_bytes()
    if b"\x00" in raw:
        return []
    hits = []
    for lineno, line in enumerate(raw.decode("utf-8", "surrogateescape").splitlines(), 1):
        for pattern in (HOST_PATHS, PRIVATE_IPV4):
            match = pattern.search(line)
            if match:
                hits.append(f"{path}:{lineno}: {match.group(0)}")
    return hits


def main(roots):
    hits = []
    for root in roots:
        base = Path(root)
        if not base.exists():
            print(f"ERROR: evidence root not found: {root}", file=sys.stderr)
            return 2
        for path in sorted(base.rglob("*")):
            if path.is_file():
                hits.extend(scan(path))
    if hits:
        print("EVIDENCE HYGIENE FAILED: host path or private address published", file=sys.stderr)
        for hit in hits:
            print(hit, file=sys.stderr)
        return 1
    print(f"evidence hygiene OK: {len(roots)} root(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
