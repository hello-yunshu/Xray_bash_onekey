#!/usr/bin/env python3
"""Actual Bash install_config_* / relay_render_stream_conf vs current Go CLI.

This harness must run IN AN ISOLATED CONTAINER with the repository checked out at
--repo. It sources the real Bash install.sh in _TEST_MODE=1 and compiles the Go
CLI from the exact current checkout. Does not start or edit host services.

Important scope: install_config_* creates Bash INSTALL METADATA, not Xray runtime
config. The Go CLI creates the Xray runtime. Assertions compare common semantics
and do NOT claim byte-identical artifacts. Full Bash install E2E is separate.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

UUID = '7a4ab30c-b199-4840-a31e-316f4f73a72b'
SECOND_UUID = 'f0ca9bf0-07d9-44c0-9371-035e4160aa2b'
HOST = 'example.com'


def matrix():
    rows=[]
    for mode in ('reality','reality-nginx','tls','none'):
        transports = ('raw',) if mode.startswith('reality') else ('ws','grpc','xhttp','ws+grpc+xhttp')
        for trans in transports:
            for port in (443,8443,10086,65535):
                rows.append(dict(id=f'{mode}_{trans}_{port}', kind='node',mode=mode,transport=trans,port=port,
                                 expected_gap=trans=='ws+grpc+xhttp'))
    for ip in ('127.0.0.1','0.0.0.0','::1','2001:db8::1'):
        for port in (443,8443,10086,65535):
            for host in ('example.org','192.0.2.100','2001:db8::2'):
                rows.append(dict(id=f'relay_{ip.replace(":","_")}_{port}_{host.replace(":","_")}',
                    kind='relay',listen=ip,port=port,target=host,backend_port=9443,expected_gap=True))
    for mode, transports in (("tls",("ws","grpc","xhttp")), ("none",("ws",)), ("reality",("raw",))):
        for trans in transports:
            rows.append(dict(id=f'share_{mode}_{trans}',kind='share',mode=mode,transport=trans,port=10086))
    rows.append(dict(id='multiuser_share_tls',kind='multiuser_share',mode='tls',transport='ws',port=10086))
    for tag, kwargs in (
        ('empty_server_name',dict(mode='reality',transport='raw',port=443,server_name='')),
        ('bad_port_low',dict(mode='tls',transport='ws',port=-1)),
        ('bad_port_high',dict(mode='none',transport='ws',port=65536)),
        ('bad_short_id_odd',dict(mode='reality',transport='raw',port=443,short_id='abc')),
    ):
        rows.append(dict(id='negative_'+tag,kind='negative',**kwargs))
    return rows


def run(argv, env=None, timeout=45, cwd=None):
    try:
        r=subprocess.run(argv,env=env,text=True,capture_output=True,timeout=timeout,cwd=cwd)
        return dict(exit=r.returncode, stdout=r.stdout[-12000:],stderr=r.stderr[-12000:])
    except subprocess.TimeoutExpired as e:
        return dict(exit=124,stdout=str(e.stdout or '')[-2000:],stderr='TIMEOUT: '+str(e))


def sha_file(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

BASH_NODE = r'''
set -eo pipefail
export _TEST_MODE=1
. "$PROJECT_INSTALL_SH" >/dev/null
xray_install_config_file="$AUDIT_OUTPUT"
mkdir -p "$(dirname "$xray_install_config_file")"
shell_version="${shell_version:-3.3.6}"
shell_mode="$AUDIT_SHELL_MODE"
transport_mode="$AUDIT_TRANSPORT"
port="$AUDIT_PORT"
ip_version=4
network_mode=ipv4
ipv4_address=192.0.2.5
ipv6_address=''
local_ip=192.0.2.5
domain=example.com
custom_email='audit@example.com'
UUID5_char=''
UUID="$AUDIT_UUID"
artnet="$AUDIT_TRANSPORT"
artpath='/audit-ws/'
artserviceName='audit-grpc'
artxhttppath='/audit-xhttp/'
artxport=10086
artgport=10087
artxhttpport=10088
xray_version='26.10.31'
nginx_build_version='test'
target='example.org:443'
serverNames='example.org'
privateKey='test-private-key-not-live'
password='test-public-key-not-live'
shortIds='aabbccdd'
spiderx_path='/spider'
reality_add_nginx=off
reality_add_balance=off
reality_balance_role=none
reality_add_more=off
reality_nginx_sni_guard=off
unknown_sni_policy=reject
decoy_domain=''
if [ "$AUDIT_MODE" = reality-nginx ]; then reality_add_nginx=on; fi
if [ "$AUDIT_MODE" = tls ]; then install_config_tls_ws;
elif [ "$AUDIT_MODE" = none ]; then install_config_ws_only;
else install_config_reality; fi
jq -e 'type=="object"' "$AUDIT_OUTPUT" >/dev/null
'''
BASH_RELAY = r'''
set -eo pipefail
export _TEST_MODE=1
. "$PROJECT_INSTALL_SH" >/dev/null
relay_render_stream_conf "$AUDIT_LISTEN" "$AUDIT_PORT" "$AUDIT_TARGET" "$AUDIT_BACKEND_PORT"
'''


def stable_json(obj):return json.dumps(obj,sort_keys=True,ensure_ascii=False,separators=(',',':'))


def test_node(row,repo,go_bin,work):
    out=work/f'{row["id"]}-bash.json'
    env=os.environ.copy(); env.update(PROJECT_INSTALL_SH=str(repo/'install.sh'), AUDIT_OUTPUT=str(out),
        AUDIT_SHELL_MODE='Reality' if row['mode'].startswith('reality') else ('TLS' if row['mode']=='tls' else 'None'),
        AUDIT_MODE=row['mode'],AUDIT_TRANSPORT=row['transport'],AUDIT_PORT=str(row['port']), AUDIT_UUID=UUID,
        _TEST_MODE='1',NO_COLOR='1',LANG='C')
    bs=run(['bash','-c',BASH_NODE],env,timeout=35,cwd=repo)
    if bs['exit'] or not out.is_file():return {'status':'BASH_FAILED','bash':bs}
    bm=json.loads(out.read_text()); goout=work/f'{row["id"]}-go.json'
    trans=row['transport']; cmd=[str(go_bin),'xray','generate','--mode',row['mode'],
        '--transport',trans,'--port',str(row['port']),'--uuid',UUID,
        '--email','audit@example.com','--domain','example.com','--server-names','example.org',
        '--target','example.org:443','--path','/audit-ws/','--service-name','audit-grpc',
        '--out',str(goout),'--json']
    gg=run(cmd,timeout=35,cwd=repo)
    if gg['exit'] or not goout.is_file():
        return {'status':'GAP' if row['expected_gap'] else 'GO_FAILED','bash_schema':sorted(bm),
                'go':gg,'reason':'Go generate refused this Bash-supported selection' if row['expected_gap'] else 'Go failed a supported selection'}
    gc=json.loads(goout.read_text()); inb=gc.get('inbounds',[{}])[0]; st=inb.get('streamSettings',{}); cli=inb.get('settings',{}).get('clients',[{}])[0]
    expected_transport='raw' if row['mode'].startswith('reality') else trans
    expected_tls='reality' if row['mode'].startswith('reality') else 'none'  # TLS is terminated by Nginx
    checks={'uuid':cli.get('id')==bm.get('id'),
            'transport':st.get('network')==expected_transport,
            'security':st.get('security')==expected_tls,
            'email':cli.get('email')==bm.get('email'),
            'port':inb.get('port')==row['port'],
            'legacy_mode':bm.get('tls')==('Reality' if row['mode'].startswith('reality') else ('TLS' if row['mode']=='tls' else 'None'))}
    # Verify Bash merge preservation with an explicit unique key in second run.
    # Go --keep-config and field-level reconfiguration have different semantics.
    return {'status':'MATCH_CORE_FIELDS' if all(checks.values()) else 'GAP', 'checks':checks,
            'bash_meta_sha':sha_file(out),'go_runtime_sha':sha_file(goout),'bash_fields':sorted(bm)}


def test_relay(row,repo,go_bin,work):
    env=os.environ.copy(); env.update(PROJECT_INSTALL_SH=str(repo/'install.sh'),AUDIT_LISTEN=row['listen'],
        AUDIT_PORT=str(row['port']), AUDIT_TARGET=row['target'],AUDIT_BACKEND_PORT=str(row['backend_port']),
        _TEST_MODE='1',NO_COLOR='1')
    bs=run(['bash','-c',BASH_RELAY],env,timeout=35,cwd=repo)
    if bs['exit']:return {'status':'BASH_FAILED','bash':bs}
    bout=work/f'{row["id"]}-bash.conf';bout.write_text(bs['stdout'])
    gout=work/f'{row["id"]}-go.conf'
    target=f'[{row["target"]}]:{row["backend_port"]}' if ':' in row['target'] else f'{row["target"]}:{row["backend_port"]}'
    gg=run([str(go_bin),'xray','relay','--target',target,'--listen-address',row['listen'],
            '--listen-port',str(row['port']),'--out',str(gout),'--json'],timeout=35,cwd=repo)
    if gg['exit'] or not gout.is_file():return {'status':'GO_FAILED','go':gg}
    text=gout.read_text(); bash=bs['stdout']
    expected=f'[{row["listen"]}]:{row["port"]}' if ':' in row['listen'] else f'{row["listen"]}:{row["port"]}'
    checks={'listen_address':f'listen {expected};' in text,
            'backend':(f'[{row["target"]}]:{row["backend_port"]}' if ':' in row['target'] else target) in text,
            'timeout':('proxy_timeout 720m;' in text),
            'keepalive':('proxy_socket_keepalive on;' in text)}
    return {'status':'MATCH' if all(checks.values()) else 'GAP','checks':checks,
            'bash_sha':sha_file(bout),'go_sha':sha_file(gout),
            'bash_listen':re.findall(r'listen\s+[^;]+;',bash),
            'go_listen':re.findall(r'listen\s+[^;]+;',text)}


def test_negative(row,repo,go_bin,work):
    args=[str(go_bin),'xray','generate','--mode',row['mode'],'--transport',row['transport'],
          '--port',str(row['port']),'--domain',row.get('server_name','example.org'),
          '--out',str(work/(row['id']+'.json'))]
    if 'short_id' in row:args+=['--short-id',row['short_id']]
    rr=run(args,cwd=repo)
    return {'status':'REFUSED' if rr['exit'] !=0 else 'ACCEPTED_REVIEW', 'exit':rr['exit'],
            'error':rr['stderr'][-600:]}


def test_share(row,repo,go_bin,work):
    # Generate a Go backend with a real TLS-terminated-by-Nginx topology,
    # then ASK GO TO DERIVE a share URI from its runtime config again.
    generated=work/(row['id']+'-runtime.json')
    cmds=[str(go_bin),'xray','generate','--mode',row['mode'],'--transport',row['transport'],
          '--port',str(row['port']),'--uuid',UUID,'--email','audit@example.com',
          '--domain','example.com','--server-names','example.com','--target','example.com:443',
          '--out',str(generated),'--json']
    gen=run(cmds,cwd=repo)
    if gen['exit'] or not generated.exists():return {'status':'GO_FAILED','generate':gen}
    if row['kind']=='multiuser_share':
        root=json.loads(generated.read_text())
        root['inbounds'][0]['settings']['clients'].append({'id':SECOND_UUID,'email':'second@example.com','level':0})
        generated.write_text(json.dumps(root))
    sr=run([str(go_bin),'xray','share','--path',str(generated),'--host','example.com','--public-port','443',
            '--public-security',row['mode']] +
           (['--user','second@example.com'] if row['kind']=='multiuser_share' else []) + ['--json'],cwd=repo)
    if sr['exit']:
        return {'status':'GO_FAILED','share':sr}
    try: obj=json.loads(sr['stdout'])
    except Exception:
        return {'status':'GO_FAILED','share':sr,'reason':'non-JSON share output'}
    uri=obj.get('shareUri','')
    if row['kind']=='multiuser_share':
        # A command with only --inbound has no selector for the second client.
        return {'status':'GAP' if SECOND_UUID not in uri else 'MATCH','share_uuid':obj.get('uuid'),
                'missing_second_user_link':SECOND_UUID not in uri}
    expected='tls' if row['mode']=='tls' else ('reality' if row['mode']=='reality' else 'none')
    match=f'security={expected}' in uri
    return {'status':'MATCH' if match else 'GAP','expected_security':expected,
            'reported_mode':obj.get('mode'),'uri_security':re.findall(r'security=([^&#]+)',uri)}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--repo',type=Path,default=Path.cwd())
    ap.add_argument('--out',type=Path,default=Path('bash-go-matrix-evidence'))
    ap.add_argument('--manifest-only',action='store_true')
    ap.add_argument('--go-bin',type=Path)
    a=ap.parse_args()
    rows=matrix()
    if a.manifest_only:
        print(json.dumps({'cases':rows,'total':len(rows)},ensure_ascii=False,indent=2));return 0
    repo=a.repo.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
    if not (repo/'install.sh').is_file() or not (repo/'go.mod').is_file():
        print('BLOCKED: actual repository checkout with install.sh and go.mod required',file=sys.stderr);return 3
    if not Path('/.dockerenv').exists() and not Path('/run/.containerenv').exists():
        print('BLOCKED: run in a disposable Docker/Podman container; refusing host run',file=sys.stderr);return 3
    if os.geteuid()!=0:
        print('BLOCKED: test container must use an isolated root namespace',file=sys.stderr);return 3
    if not shutil.which('jq') or not shutil.which('go'):
        print('BLOCKED: jq and Go compiler required',file=sys.stderr);return 3
    sha=run(['git','rev-parse','HEAD'],cwd=repo)
    gitsha=sha['stdout'].strip() if sha['exit']==0 else 'UNKNOWN'
    if a.go_bin: go_bin=a.go_bin.resolve()
    else:
        go_bin=out/'idleleo-current'
        rr=run(['go','build','-trimpath','-o',str(go_bin),'./cmd/idleleo'],timeout=180,cwd=repo)
        if rr['exit']:
            (out/'build-error.json').write_text(json.dumps(rr,indent=2));print('BLOCKED: current Go build failed');return 3
    results=[]
    with tempfile.TemporaryDirectory(prefix='xray-bash-go-') as wd:
        work=Path(wd)
        for row in rows:
            kind=row['kind']
            result=(test_node(row,repo,go_bin,work) if kind=='node' else
                    test_relay(row,repo,go_bin,work) if kind=='relay' else
                    test_share(row,repo,go_bin,work) if kind in ('share','multiuser_share') else
                    test_negative(row,repo,go_bin,work))
            results.append(dict(case=row, result=result))
            print(f"{row['id']}: {result['status']}",flush=True)
        # The harness keeps ONLY hashes/field names, not actual keys or configs.
    status={}
    for e in results:status[e['result']['status']]=status.get(e['result']['status'],0)+1
    report=dict(schema=1,git_commit=gitsha,go_sha=sha_file(go_bin),
                bash_sha=sha_file(repo/'install.sh'), scope='Bash install metadata + relay render vs current Go generate/relay; NO full Bash deploy or live service claim',
                total=len(rows),status=status,results=results)
    (out/'summary.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print('SUMMARY:',json.dumps(status,ensure_ascii=False))
    return 0 if not any(k in status for k in ('BASH_FAILED','GO_FAILED','ACCEPTED_REVIEW','GAP')) else 1

if __name__=='__main__':sys.exit(main())
