#!/usr/bin/env python3
"""Versioned normalization for e2e-diff artifacts.

Usage:
    normalize.py <input> <output> [--sort-lines] [--rules-version N]

Rules (v1) remove only variability that is genuinely incidental:
  * ANSI SGR/escape sequences
  * ISO-8601 and syslog timestamps, bare dates
  * process ids in pid=, [pid] and "PID n" forms
  * temporary directory/file names (/tmp/tmp.*, mktemp suffixes)
  * trailing whitespace, CRLF

Semantic values (ports, UUID hashes, paths, counts) are never rewritten.
JSON input is normalized recursively and re-serialized with sorted keys while
array order is preserved (inbound order matters).
"""
import argparse
import json
import re
import sys

RULES_VERSION = 1

ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')
RULES = [
    (re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?'), '<TS>'),
    (re.compile(r'\b[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}\b'), '<TS>'),
    (re.compile(r'\b\d{4}-\d{2}-\d{2}\b'), '<DATE>'),
    (re.compile(r'\bpid=\d+'), 'pid=<PID>'),
    (re.compile(r'\bPID \d+'), 'PID <PID>'),
    (re.compile(r'\[\d{3,}\]'), '[<PID>]'),
    (re.compile(r'/tmp/tmp\.[A-Za-z0-9._-]+'), '<TMPDIR>'),
    (re.compile(r'/tmp/e2e-[A-Za-z0-9._-]+'), '<TMPDIR>'),
]


def normalize_text(text):
    text = text.replace('\r\n', '\n')
    text = ANSI.sub('', text)
    for pattern, replacement in RULES:
        text = pattern.sub(replacement, text)
    return '\n'.join(line.rstrip() for line in text.splitlines())


def normalize_value(value):
    if isinstance(value, str):
        return normalize_text(value)
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize_value(item) for key, item in value.items()}
    return value


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('input')
    parser.add_argument('output')
    parser.add_argument('--sort-lines', action='store_true',
                        help='sort text lines (unordered outputs such as listeners)')
    parser.add_argument('--rules-version', type=int, default=RULES_VERSION)
    args = parser.parse_args(argv)

    if args.rules_version != RULES_VERSION:
        print('unsupported rules version %d (supported: %d)' % (args.rules_version, RULES_VERSION),
              file=sys.stderr)
        return 2

    try:
        with open(args.input, encoding='utf-8', errors='replace') as fh:
            raw = fh.read()
    except OSError as exc:
        print('cannot read %s: %s' % (args.input, exc), file=sys.stderr)
        return 2

    if args.input.endswith('.json'):
        try:
            payload = normalize_value(json.loads(raw))
        except json.JSONDecodeError as exc:
            print('invalid json %s: %s' % (args.input, exc), file=sys.stderr)
            return 2
        text = json.dumps(payload, indent=2, sort_keys=True) + '\n'
    else:
        text = normalize_text(raw) + '\n'
        if args.sort_lines:
            text = '\n'.join(sorted(text.splitlines())) + '\n'

    with open(args.output, 'w', encoding='utf-8') as fh:
        fh.write(text)
    print('normalized %s -> %s (rules v%d)' % (args.input, args.output, RULES_VERSION))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
