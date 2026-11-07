#!/usr/bin/env python3
"""Black-box CLI acceptance fixture for the existing Go v2 bridge prototype.
Only disposable sandbox roots. All configs are synthetic. No root required.
"""
from pathlib import Path
import subprocess,tempfile,shutil,os,json,hashlib,sys
base=Path(__file__).resolve().parents[2]
p=base/'prototype'
evidence=base/'parity/evidence'
evidence.mkdir(parents=True,exist_ok=True)
results=[]
def sh(cmd,**kw):
 return subprocess.run([str(x) for x in cmd],capture_output=True,text=True,timeout=60,**kw)
def sha(x):return hashlib.sha256(x.read_bytes()).hexdigest()
def check(test,condition,detail=''):
 results.append({'test':test,'ok':bool(condition),'detail':detail})
 if not condition: print('FAIL',test,detail,file=sys.stderr)
with tempfile.TemporaryDirectory(prefix='idleleo-bridge-cli-') as wd:
 t=Path(wd)
 bin=t/'bridge-cli-v2'
 build=sh(['go','build','-o',bin,'.'],cwd=p)
 if build.returncode:sys.exit('go build failed: '+build.stderr)
 pin=sha(bin)
 def create(name,mode):
  r=t/name
  z=sh(['python3',p/'testdata/make_v4_sandbox.py',r,mode])
  if z.returncode:raise RuntimeError(z.stderr)
  entry=r/'usr/bin/idleleo'
  entry.unlink()
  entry.symlink_to('../../etc/idleleo/install.sh')
  candidate=r/'opt/idleleo/bin/idleleo'
  candidate.parent.mkdir(parents=True)
  shutil.copy2(bin,candidate)
  candidate.chmod(0o700)
  return r
 def go(r,mode,fault='',candidate_pin=pin):
  cmd=[bin,'-root',r,'-mode',mode]
  if mode=='prepare':cmd+=['-candidate-sha256',candidate_pin]
  if fault:cmd+=['-fault',fault]
  return sh(cmd)
 def runt(r,mode):return r/('etc/idleleo/conf/nginx/relay-stream.conf' if mode=='relay' else 'etc/idleleo/conf/xray/config.json')
 for mode in ['reality','tls','relay']:
  r=create('interrupted-'+mode,mode)
  runtime=runt(r,mode);legacy=r/'etc/idleleo/conf/install_config.json'
  before=(sha(runtime),sha(legacy))
  q=go(r,'inspect');check('inspect-'+mode,q.returncode==0,'read-only')
  check('inspect-no-journal-'+mode,not (r/'var/lib/idleleo/transactions/bridge-v2.json').exists())
  q=go(r,'prepare');check('prepare-'+mode,q.returncode==0,q.stderr)
  meta=(r/'etc/idleleo/manager/config.json').read_text()
  check('secrets-not-duplicated-'+mode,all(x not in meta for x in ['TEST_PRIVATE_KEY_NOT_REAL','SYNTHETIC_PUBLIC_KEY','11111111-1111-4111-8111-111111111111']))
  q=go(r,'activate','after-swap');check('injected-after-swap-'+mode,q.returncode==86,q.stderr)
  q=go(r,'recover');check('recovered-'+mode,q.returncode==0 and json.loads(q.stdout).get('state')=='ROLLED_BACK',q.stderr)
  q=go(r,'status');h=json.loads(q.stdout) if q.returncode==0 else {}
  check('status-restored-'+mode,h.get('entryIsLegacy') is True and h.get('entryIsGo') is False)
  check('runtime-unchanged-'+mode, before==(sha(runtime),sha(legacy)))
  check('old-entry-exists-'+mode,(r/'usr/bin/idleleo').is_symlink())
 r=create('normal-commit','reality')
 q=go(r,'prepare');check('normal-prepare',q.returncode==0)
 q=go(r,'activate');check('normal-activate',q.returncode==0 and json.loads(q.stdout).get('state')=='COMMITTED',q.stderr)
 q=sh([r/'usr/bin/idleleo','--bridge-self-check']);check('real-entry-executable',q.returncode==0 and 'idleleo-bridge-probe-v2' in q.stdout,q.stderr)
 r=create('xtls-reject','xtls')
 q=go(r,'inspect');check('xtls-rejected',q.returncode==2 and not (r/'var/lib/idleleo/transactions/bridge-v2.json').exists(),q.stderr)
 r=create('candidate-change','reality')
 check('candidate-change-prepare',go(r,'prepare').returncode==0)
 with (r/'opt/idleleo/bin/idleleo').open('ab') as f:f.write(b'changed')
 check('candidate-change-blocked',go(r,'activate').returncode!=0)
 r=create('entry-change','reality');check('entry-change-prepare',go(r,'prepare').returncode==0)
 entry=r/'usr/bin/idleleo';entry.unlink();entry.write_text('unrelated')
 check('entry-change-blocked',go(r,'activate').returncode!=0 and entry.read_text()=='unrelated')
 r=create('recover-change','reality');check('recover-change-prepare',go(r,'prepare').returncode==0)
 check('recover-change-after-swap',go(r,'activate','after-swap').returncode==86)
 entry=r/'usr/bin/idleleo';entry.unlink();entry.write_text('unrelated')
 check('recover-change-preserved',go(r,'recover').returncode!=0 and entry.read_text()=='unrelated')
 r=create('fake-executable','reality')
 candidate=r/'opt/idleleo/bin/idleleo';candidate.write_text('#!/bin/sh\necho fake\n');candidate.chmod(0o700)
 fakepin=sha(candidate)
 check('fake-executable-refused',go(r,'prepare',candidate_pin=fakepin).returncode!=0)

report={'suite':'GO_V2_BRIDGE_CLI_SYNTHETIC','total':len(results),'passed':sum(x['ok'] for x in results),'failed':sum(not x['ok'] for x in results),'production_migration_certified':False,'results':results}
(evidence/'bridge_cli_contract.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print('GO v2 bridge CLI:',report['passed'],'/',report['total'],'checks passed; production_migration_certified=False')
if report['failed']:sys.exit(1)
