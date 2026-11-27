#!/usr/bin/env python3
"""Rewrite host-identifying values in captured evidence.

The Bash installer auto-detects the machine's public address, so its real menu
transcript and the `nginx -T` dump embed it. Evidence keeps the behaviour but
must not name the capture host: public addresses become documentation-range
values and home directories lose the user name.

Values are rewritten in place; only regular text files under the given roots
are touched, and a file is only rewritten when its content actually changed.

Usage: sanitize_evidence.py ROOT [ROOT ...]
Exit: 0 success, 2 usage error.
"""
import ipaddress
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".cache", "__pycache__"}

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
HOME_RE = re.compile(r"(?<![A-Za-z0-9_.\-])/(?:Users|home)/[^/\s\"'`<>),;|]+")

NON_PUBLIC_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.2.0/24", "198.18.0.0/15",
    "192.168.0.0/16", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
    "240.0.0.0/4",
)]
NON_PUBLIC_V6 = [ipaddress.ip_network(n) for n in (
    "::/128", "::1/128", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
)]

DOC_V4 = "198.51.100.10"
DOC_V6 = "2001:db8::1"
DOC_HOME = "<workspace>"


def public_v4(value):
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not any(addr in net for net in NON_PUBLIC_V4)


def public_v6(value):
    try:
        addr = ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return not any(addr in net for net in NON_PUBLIC_V6)


def sanitize(text):
    text = IPV4_RE.sub(lambda m: DOC_V4 if public_v4(m.group(0)) else m.group(0), text)
    text = IPV6_RE.sub(lambda m: DOC_V6 if public_v6(m.group(0)) else m.group(0), text)
    return HOME_RE.sub(DOC_HOME, text)


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    changed = 0
    for entry in argv:
        root = Path(entry)
        if not root.exists():
            print(f"sanitize: no such path: {root}", file=sys.stderr)
            return 2
        paths = [root] if root.is_file() else [
            p for p in sorted(root.rglob("*"))
            if p.is_file() and not any(part in SKIP_DIRS for part in p.parts)
        ]
        for path in paths:
            raw = path.read_bytes()
            if b"\x00" in raw:
                continue
            text = raw.decode("utf-8", "surrogateescape")
            fixed = sanitize(text)
            if fixed != text:
                path.write_text(fixed, encoding="utf-8", errors="surrogateescape")
                changed += 1
                relative = path.relative_to(root) if root.is_dir() else Path(path.name)
                print(f"sanitize: {relative.as_posix()}")
    print(f"sanitize: {changed} file(s) updated")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
