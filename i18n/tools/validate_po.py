import sys

import polib


def validate(path):
    po = polib.pofile(path)
    bad = []
    for entry in po:
        if entry.obsolete or not entry.msgid:
            continue
        if not entry.msgstr.strip():
            bad.append((entry.msgid, 'empty'))
        elif 'fuzzy' in entry.flags:
            bad.append((entry.msgid, 'fuzzy'))
    return bad


def main(paths):
    failed = False
    for path in paths:
        bad = validate(path)
        if not bad:
            print(f'{path}: complete')
            continue
        failed = True
        print(f'{path}: {len(bad)} incomplete entries', file=sys.stderr)
        for msgid, reason in bad[:10]:
            print(f'  {reason}: {msgid!r}', file=sys.stderr)
    return 1 if failed else 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: validate_po.py PO_FILE...', file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1:]))
