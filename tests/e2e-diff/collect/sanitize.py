#!/usr/bin/env python3
"""Redacts secrets from captured logs before they enter the evidence tree.

Usage: sanitize.py <in-place file> [more files...]

The installers print a share URI that embeds the client UUID, and debug logs
can echo the Reality private key. Both are replaced here; the original bytes
are discarded.
"""
import ipaddress
import re
import sys

RULES = [
    (re.compile(r'vless://[^\s"\']+'), 'vless://REDACTED'),
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), '<UUID>'),
    (re.compile(r'("privateKey"\s*:\s*")[^"]+(")'), r'\1REDACTED\2'),
    (re.compile(r'(privateKey["\s:=]+)[A-Za-z0-9_+/=-]+'), r'\1REDACTED'),
    (re.compile(r'("id"\s*:\s*")[^"]+(")'), r'\1REDACTED\2'),
]

# Public resolvers and OS mirrors that make logs meaningful; every other
# global address is host-specific and must not enter the evidence tree.
ALLOWED_IPS = {
    '1.0.0.1', '1.1.1.1', '1.2.3.4', '8.8.4.4', '8.8.8.8', '9.9.9.9',
    '11.0.0.2', '20.205.243.166', '91.189.91.104', '104.16.179.112',
    '104.16.180.112', '149.112.112.112', '176.58.119.54',
    '185.199.108.133', '185.199.109.133', '185.199.110.133',
    '185.199.111.133', '208.67.220.220', '208.67.222.222', '223.5.5.5',
    '2606:4700:4700::1001', '2606:4700:4700::1111', '2001:7b8:32a::2',
}
IPV4_RE = re.compile(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])')
IPV6_RE = re.compile(
    r'(?<![:0-9a-fA-F])([0-9a-fA-F]{2,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![:0-9a-fA-F])'
)
HOME_RE = re.compile(
    r'(?<![A-Za-z0-9._-])(?P<prefix>/Users/|/home/|(?i:[A-Za-z]:[\\/]Users[\\/]))'
    r'(?P<name>[A-Za-z0-9._-]+)'
)
SAFE_HOME_NAMES = {
    '<user>', 'bar', 'example', 'foo', 'me', 'node', 'runner', 'test',
    'tester', 'ubuntu', 'user', 'username', 'vscode', 'you', 'yourname',
}

_ipv4_ph = {}
_ipv6_ph = {}


def _placeholder(address, mapping, template):
    if address not in mapping:
        index = len(mapping) + 10
        mapping[address] = template % index
    return mapping[address]


def _redact_ipv4(match):
    value = match.group(1)
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        return value
    if value in ALLOWED_IPS or not addr.is_global or addr.is_multicast or addr.is_reserved:
        return value
    return _placeholder(value, _ipv4_ph, '203.0.113.%d')


def _redact_ipv6(match):
    value = match.group(1)
    try:
        addr = ipaddress.IPv6Address(value)
    except ValueError:
        return value
    if value in ALLOWED_IPS or not addr.is_global or addr.is_multicast:
        return value
    return _placeholder(value, _ipv6_ph, '2001:db8::%d')


def _redact_home(match):
    if match.group('name').lower() in SAFE_HOME_NAMES:
        return match.group(0)
    return match.group('prefix') + '<user>'


def redact(text):
    for pattern, replacement in RULES:
        text = pattern.sub(replacement, text)
    text = IPV4_RE.sub(_redact_ipv4, text)
    text = IPV6_RE.sub(_redact_ipv6, text)
    return HOME_RE.sub(_redact_home, text)


def main(paths):
    for path in paths:
        try:
            with open(path, encoding='utf-8', errors='replace') as fh:
                text = fh.read()
        except FileNotFoundError:
            continue
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(redact(text))
        print('sanitized %s' % path)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
