#!/usr/bin/env python3
"""Emits non-reversible identity fingerprints for a runtime Xray config.

Only SHA-256 digests of client UUIDs, the derived Reality public key and the
short IDs are written; no secret ever reaches the evidence tree.

Usage: identity.py <runtime-config.json> <out.json>
"""
import hashlib
import json
import subprocess
import sys


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def reality_public_key(private_key):
    proc = subprocess.run(['/usr/local/bin/xray', 'x25519', '-i', private_key],
                          capture_output=True, text=True)
    for line in proc.stdout.splitlines():
        if 'ublic key' in line or 'ublicKey' in line:
            return line.split(':', 1)[-1].strip()
    return ''


def main(src, out):
    cfg = json.load(open(src))
    rows = []
    for inbound in cfg.get('inbounds') or []:
        stream = inbound.get('streamSettings') or {}
        reality = stream.get('realitySettings') or {}
        clients = (inbound.get('settings') or {}).get('clients') or []
        ids = [client.get('id') for client in clients if client.get('id')]
        private_key = reality.get('privateKey') or (reality.get('settings') or {}).get('privateKey')
        public_key = reality_public_key(private_key) if private_key else ''
        rows.append({
            'tag': inbound.get('tag'),
            'uuidSha256': sorted(sha(value) for value in ids),
            'realityPublicKeySha256': sha(public_key) if public_key else None,
            'realityPublicKeyPresent': bool(public_key),
            'shortIdsSha256': sorted(sha(value) for value in reality.get('shortIds') or []),
        })
    with open(out, 'w') as fh:
        json.dump({'inbounds': rows}, fh, indent=2, sort_keys=True)
        fh.write('\n')
    print('identity fingerprints written to %s' % out)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: identity.py <runtime-config.json> <out.json>')
    main(sys.argv[1], sys.argv[2])
