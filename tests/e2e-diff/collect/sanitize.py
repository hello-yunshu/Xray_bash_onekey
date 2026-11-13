#!/usr/bin/env python3
"""Redacts secrets from captured logs before they enter the evidence tree.

Usage: sanitize.py <in-place file> [more files...]

The installers print a share URI that embeds the client UUID, and debug logs
can echo the Reality private key. Both are replaced here; the original bytes
are discarded.
"""
import re
import sys

RULES = [
    (re.compile(r'vless://[^\s"\']+'), 'vless://REDACTED'),
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), '<UUID>'),
    (re.compile(r'("privateKey"\s*:\s*")[^"]+(")'), r'\1REDACTED\2'),
    (re.compile(r'(privateKey["\s:=]+)[A-Za-z0-9_+/=-]+'), r'\1REDACTED'),
    (re.compile(r'("id"\s*:\s*")[^"]+(")'), r'\1REDACTED\2'),
]


def redact(text):
    for pattern, replacement in RULES:
        text = pattern.sub(replacement, text)
    return text


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
