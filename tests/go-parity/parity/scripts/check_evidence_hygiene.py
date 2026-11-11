#!/usr/bin/env python3
"""Evidence hygiene: fail on host-identifying values in committed files.

Rules
  * Public IPv4 literals. Private, loopback, link-local, CGNAT, multicast,
    reserved and documentation ranges are ignored because they do not name a
    host.
  * Public IPv6 literals. Loopback, unspecified, ULA, link-local, multicast
    and the documentation prefix are ignored for the same reason.
  * Absolute home directories that carry a user name.

Any finding must be covered by a value-level allowlist entry; there is
deliberately no way to skip a whole file.

Usage: check_evidence_hygiene.py [--allowlist PATH] ROOT [ROOT ...]
Exit: 0 clean, 1 findings, 2 usage or allowlist error.
"""
import argparse
import ipaddress
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".cache", "__pycache__"}

# Built by concatenation so this file never matches its own host-path rule.
_USERS = "/" + "Users/"
_HOMES = "/" + "home/"
_ROOTS = "/" + "root/"

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
HOST_RE = re.compile(
    # A leading path segment such as .../root/usr is repository-relative, not a
    # host home, so the slash must not follow an identifier character.
    r"(?<![A-Za-z0-9_.\-])(?:" + re.escape(_USERS) + "|" + re.escape(_HOMES)
    + "|" + re.escape(_ROOTS) + r")[^/\s\"'`<>]+"
)

NON_PUBLIC_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)]
NON_PUBLIC_V6 = [ipaddress.ip_network(n) for n in (
    "::/128",
    "::1/128",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)]


def in_networks(addr, networks):
    return any(addr in net for net in networks)


def load_allowlist(path):
    entries = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SystemExit(f"hygiene: cannot read allowlist {path}: {exc}")
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        value, sep, reason = line.partition("#")
        value, reason = value.strip(), reason.strip()
        if not sep or not reason:
            raise SystemExit(f"hygiene: {path}:{lineno}: allowlist needs '<value>  # <reason>'")
        entries[value] = reason
    return entries


def text_files(root):
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts) or not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue
        yield path, raw.decode("utf-8", "surrogateescape")


def scan_file(display, text, allow):
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        seen = set()
        for match in IPV4_RE.finditer(line):
            value = match.group(0)
            try:
                addr = ipaddress.IPv4Address(value)
            except ValueError:
                continue
            if in_networks(addr, NON_PUBLIC_V4) or (value, match.start()) in seen:
                continue
            seen.add((value, match.start()))
            findings.append((display, lineno, value, "public IPv4"))
        for match in IPV6_RE.finditer(line):
            value = match.group(0)
            try:
                addr = ipaddress.IPv6Address(value)
            except ValueError:
                continue
            if in_networks(addr, NON_PUBLIC_V6) or (value, match.start()) in seen:
                continue
            seen.add((value, match.start()))
            findings.append((display, lineno, value, "public IPv6"))
        for match in HOST_RE.finditer(line):
            value = match.group(0)
            if (value, match.start()) in seen:
                continue
            seen.add((value, match.start()))
            findings.append((display, lineno, value, "host user path"))
    return [finding for finding in findings if finding[2] not in allow]


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", help="files or directories to scan")
    parser.add_argument("--allowlist", default=str(Path(__file__).with_name(
        "evidence_hygiene_allowlist.txt")))
    args = parser.parse_args(argv)

    allow = load_allowlist(Path(args.allowlist))
    findings = []
    scanned = 0
    for entry in args.roots:
        root = Path(entry)
        if not root.exists():
            print(f"hygiene: no such path: {root}", file=sys.stderr)
            return 2
        if root.is_file():
            try:
                raw = root.read_bytes()
            except OSError:
                continue
            scanned += 1
            if b"\x00" not in raw:
                findings.extend(scan_file(str(root),
                                          raw.decode("utf-8", "surrogateescape"), allow))
            continue
        for path, text in text_files(root):
            scanned += 1
            findings.extend(scan_file(str(path), text, allow))

    for path, lineno, value, rule in findings:
        print(f"{path}:{lineno}: {value} ({rule})")
    print(f"hygiene: {len(findings)} finding(s) in {scanned} file(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
