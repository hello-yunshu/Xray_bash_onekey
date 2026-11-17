#!/usr/bin/env python3
"""Builds a client-side Xray config from the server runtime config (L4 helper).

Runs INSIDE the server container where the real runtime config (UUIDs, Reality
private key) lives, and writes the client config to a caller-provided path that
must live outside the evidence tree. The evidence tree only ever sees the
connectivity verdict, never the secrets this file contains.

Usage:
    client_config.py --config /etc/idleleo/conf/xray/config.json \
        --mode reality|tls --server-address 172.18.0.2 --server-port 443 \
        --domain example.com --output /client/client.json
"""
import argparse
import hashlib
import json
import subprocess
import sys


def vless_inbounds(cfg):
    return [inbound for inbound in cfg.get('inbounds') or []
            if (inbound.get('protocol') or '').lower() == 'vless']


def pick_inbound(cfg, transport):
    inbounds = vless_inbounds(cfg)
    if not inbounds:
        raise SystemExit('no vless inbound in server config')
    if not transport or transport in ('auto', 'first'):
        return inbounds[0]
    for inbound in inbounds:
        stream = inbound.get('streamSettings') or {}
        network = (stream.get('network') or 'tcp').lower()
        security = (stream.get('security') or 'none').lower()
        if transport == 'reality' and security == 'reality':
            return inbound
        if network == transport.lower():
            return inbound
    raise SystemExit('no vless inbound with transport %s' % transport)


def reality_public_key(private_key):
    proc = subprocess.run(['/usr/local/bin/xray', 'x25519', '-i', private_key],
                          capture_output=True, text=True)
    for line in proc.stdout.splitlines():
        if 'ublic key' in line or 'ublicKey' in line:
            return line.split(':', 1)[-1].strip()
    raise SystemExit('cannot derive reality public key: %s' % proc.stderr.strip())


def cert_sha256(path):
    proc = subprocess.run(['openssl', 'x509', '-in', path, '-outform', 'der'],
                          capture_output=True)
    if proc.returncode != 0:
        raise SystemExit('cannot decode certificate %s: %s' % (path, proc.stderr.decode(errors='replace')))
    return hashlib.sha256(proc.stdout).hexdigest()


def build(args):
    cfg = json.load(open(args.config))
    inbound = pick_inbound(cfg, args.transport)
    stream = inbound.get('streamSettings') or {}
    server_port = inbound.get('port') if args.use_inbound_port else args.server_port
    clients = (inbound.get('settings') or {}).get('clients') or []
    if not clients:
        raise SystemExit('no client entry in server config')
    client = clients[0]

    outbound = {
        'protocol': 'vless',
        'settings': {'vnext': [{
            'address': args.server_address,
            'port': server_port,
            'users': [{'id': client['id'], 'encryption': 'none'}],
        }]},
        'streamSettings': {},
    }
    user = outbound['settings']['vnext'][0]['users'][0]
    if client.get('flow'):
        user['flow'] = client['flow']

    if args.mode == 'reality' and stream.get('security') == 'reality':
        rs = stream.get('realitySettings') or {}
        private_key = rs.get('privateKey') or (rs.get('settings') or {}).get('privateKey')
        if not private_key:
            raise SystemExit('reality inbound has no privateKey')
        server_names = rs.get('serverNames') or [args.domain]
        short_ids = rs.get('shortIds') or ['']
        outbound['streamSettings'] = {
            'network': stream.get('network') or 'tcp',
            'security': 'reality',
            'realitySettings': {
                'serverName': server_names[0],
                'fingerprint': rs.get('fingerprint') or 'chrome',
                'publicKey': reality_public_key(private_key),
                'shortId': short_ids[0],
                'spiderX': rs.get('spiderX') or '/',
            },
        }
    elif args.mode == 'reality':
        # Reality's extra transport inbound (bash reality_add_more) listens with
        # security=none on its own port, so the client mirrors that plain
        # transport instead of applying the Reality handshake.
        network = (stream.get('network') or 'tcp').lower()
        settings = {'network': network, 'security': 'none'}
        if network == 'ws':
            ws = stream.get('wsSettings') or {}
            settings['wsSettings'] = {'path': ws.get('path') or '/'}
        elif network == 'grpc':
            grpc = stream.get('grpcSettings') or {}
            settings['grpcSettings'] = {'serviceName': grpc.get('serviceName') or ''}
        elif network == 'xhttp':
            xhttp = stream.get('xhttpSettings') or {}
            settings['xhttpSettings'] = {'path': xhttp.get('path') or '/'}
        outbound['streamSettings'] = settings
    elif args.mode in ('tls', 'none'):
        network = (stream.get('network') or 'tcp').lower()
        domain = args.domain
        settings = {'network': network, 'security': args.mode}
        if args.mode == 'tls':
            # Xray 26.x removed allowInsecure and still chain-validates under
            # verifyPeerCertByName; pinning the DER digest is the supported way
            # to trust the self-signed certificate.
            settings['tlsSettings'] = {
                'serverName': domain,
                'pinnedPeerCertSha256': cert_sha256(args.cert),
            }
        if network == 'ws':
            ws = stream.get('wsSettings') or {}
            ws_settings = {'path': ws.get('path') or '/'}
            if args.mode == 'tls':
                ws_settings['headers'] = {'Host': domain}
            settings['wsSettings'] = ws_settings
        elif network == 'grpc':
            grpc = stream.get('grpcSettings') or {}
            settings['grpcSettings'] = {'serviceName': grpc.get('serviceName') or ''}
        elif network == 'xhttp':
            xhttp = stream.get('xhttpSettings') or {}
            settings['xhttpSettings'] = {'path': xhttp.get('path') or '/'}
        outbound['streamSettings'] = settings
    else:
        raise SystemExit('unsupported client mode %s' % args.mode)

    return {
        'log': {'loglevel': 'warning'},
        'inbounds': [{
            'listen': '127.0.0.1', 'port': 1080, 'protocol': 'socks',
            'settings': {'udp': False},
        }],
        'outbounds': [outbound],
    }


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--mode', required=True, choices=['reality', 'tls', 'none'])
    parser.add_argument('--transport', default='auto',
                        help='auto|ws|grpc|xhttp|reality; selects the matching inbound')
    parser.add_argument('--server-address', required=True)
    parser.add_argument('--server-port', default=443, type=int)
    parser.add_argument('--use-inbound-port', action='store_true',
                        help='connect to the inbound listen port (ws-only mode)')
    parser.add_argument('--domain', required=True)
    parser.add_argument('--cert', default='/etc/idleleo/cert/xray.crt',
                        help='server certificate whose DER digest is pinned (tls mode)')
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    with open(args.output, 'w') as fh:
        json.dump(build(args), fh, indent=2)
        fh.write('\n')
    print('client config written to %s' % args.output)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
