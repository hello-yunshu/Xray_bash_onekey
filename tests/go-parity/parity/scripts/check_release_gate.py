#!/usr/bin/env python3
"""Release qualification runner (RED until real Go production and F01-F28 tests).

Crucial: DOES NOT accept evidence JSON as authority. It checks the source tree,
builds Go from clean exact checkout, executes L0, and runs real per-feature
black-box test files in this CI job. Only protected CI can authorize publish.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from run_parity import clean_pinned_bash, clean_native_source, build_native

ROOT=Path(__file__).resolve().parents[1]
EXPECTED={f'F{i:02d}' for i in range(1,29)}


def main():
 p=argparse.ArgumentParser()
 p.add_argument('--bash-repo',type=Path)
 p.add_argument('--native-go-dir',type=Path)
 p.add_argument('--require-package')
 p.add_argument('--native-package',default='./cmd/parity-adapter')
 p.add_argument('--go-cli-package',default='./cmd/idleleo')
 a=p.parse_args()
 manifest=json.loads((ROOT/'cases/feature_contracts.json').read_text())
 feats=manifest['features']
 ids=[f['id'] for f in feats]
 if len(ids)!=28 or set(ids)!=EXPECTED or len(ids)!=len(set(ids)):
  print('RELEASE BLOCKED: feature ledger is incomplete/duplicated',file=sys.stderr);return 2
 pending=[f['id'] for f in feats if f['status'] not in ('VERIFIED_GO_PARITY','APPROVED_SAFE_DIVERGENCE')]
 missing=[name for name in sorted(EXPECTED) if not (ROOT/'features'/f'{name}_test.py').is_file()]
 if pending or missing:
  print(f'RELEASE BLOCKED: pending {len(pending)}; missing executable feature tests {len(missing)}; JSON statuses alone never grant success')
  print('PENDING:',','.join(pending))
  print('MISSING TESTS:',','.join(missing))
  return 2
 if not a.bash_repo or not a.native_go_dir or not a.require_package:
  print('RELEASE BLOCKED: full pinned Bash checkout, Go source checkout and required production package mandatory',file=sys.stderr)
  return 3
 if os.environ.get('GITHUB_ACTIONS')!='true' or not os.environ.get('GITHUB_SHA'):
  print('RELEASE BLOCKED: only a checked CI runner may issue a release qualification result',file=sys.stderr)
  return 3
 try:
  clean_pinned_bash(a.bash_repo)
  sha=clean_native_source(a.native_go_dir)
  if sha!=os.environ['GITHUB_SHA']:
   raise ValueError('checked-out Go source commit != CI event SHA')
  with tempfile.TemporaryDirectory(prefix='idleleo-release-') as tmp:
   tmp=Path(tmp)
   # Go adapter is built in L0 by run_parity.py, never supplied as an opaque binary.
   l0=subprocess.run([sys.executable,str(ROOT/'scripts/run_parity.py'),'--bash-repo',str(a.bash_repo),
      '--require-live','--native-go-dir',str(a.native_go_dir),
      '--native-package',a.native_package,'--require-package',a.require_package,
      '--require-native-l0','--evidence',str(tmp/'l0')],timeout=240)
   if l0.returncode:
    print('RELEASE BLOCKED: native source-built L0 failed',file=sys.stderr);return 2
   build_native(a.native_go_dir,a.go_cli_package,a.require_package,tmp/'idleleo')
   results=[]
   for fid in sorted(EXPECTED):
    fixture=ROOT/'features'/f'{fid}_test.py'
    # CI must review this fixture to ensure it tests actual system behavior, not exit(0).
    r=subprocess.run([sys.executable,'-I',str(fixture),'--go-bin',str(tmp/'idleleo'),
       '--bash-repo',str(a.bash_repo)],cwd=tmp,timeout=240)
    results.append((fid,r.returncode))
    print(fid,'PASS' if r.returncode==0 else 'FAIL')
   if any(rc for _,rc in results):
    print('RELEASE BLOCKED: core fixture failed',file=sys.stderr);return 2
 except (ValueError, OSError,subprocess.TimeoutExpired) as e:
  print('RELEASE BLOCKED:',e,file=sys.stderr);return 3
 print('RELEASE FUNCTIONAL QUALIFICATION PASS — still requires independent VM/systemd, multi-distro and protected publishing gate')
 return 0

if __name__=='__main__':sys.exit(main())
