#!/usr/bin/env python3
"""Phase00/01 smoke gate; never claims Phase02 business parity or release readiness."""
import argparse
import pathlib
import subprocess
import sys
ROOT=pathlib.Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser()
p.add_argument('--bash-repo',type=pathlib.Path,required=True)
a=p.parse_args()
checks=[
 ['python3',ROOT/'parity/scripts/run_parity.py','--bash-repo',a.bash_repo,'--require-live','--evidence',ROOT/'parity/evidence'],
 ['bash',ROOT/'parity/scripts/run_bridge_fixture_suite.sh'],
 ['python3','-m','unittest','discover','-s',ROOT/'parity/tests','-p','test_*.py'],
]
for i,cmd in enumerate(checks,1):
 print('STAGE CHECK',i,flush=True)
 r=subprocess.run([str(x) for x in cmd],timeout=300)
 if r.returncode:
  print('STAGE BLOCKED: check',i,'exit',r.returncode,file=sys.stderr)
  sys.exit(r.returncode)
print('STAGE GATE PASS: baseline/differential/Bridge/fail-closed tests only; NOT a production release')
