"""Negative gate regressions: a forged report or an opaque executable must not certify Go."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
PARITY=ROOT/'scripts/run_parity.py'
GATE=ROOT/'scripts/check_release_gate.py'

class FailClosedTests(unittest.TestCase):
 def invoke(self,*args,env=None):
  return subprocess.run([sys.executable,*map(str,args)],text=True,capture_output=True,timeout=60,env=env)

 def isolated_gate(self,t,status):
  (t/'scripts').mkdir();(t/'cases').mkdir();(t/'features').mkdir()
  shutil.copy2(GATE,t/'scripts/check_release_gate.py')
  shutil.copy2(PARITY,t/'scripts/run_parity.py')
  ledger=json.loads((ROOT/'cases/feature_contracts.json').read_text())
  for f in ledger['features']:
   f['status']=status;f['evidence']=[]
  (t/'cases/feature_contracts.json').write_text(json.dumps(ledger))
  return t/'scripts/check_release_gate.py'

 def test_unverified_release_must_fail(self):
  # The real ledger is signed at this commit, so the pending-stage contract is
  # exercised on an isolated copy instead of pretending the repository is
  # still unverified.
  with tempfile.TemporaryDirectory() as tmp:
   gate=self.isolated_gate(Path(tmp),'PENDING_GO_IMPLEMENTATION')
   res=self.invoke(gate)
  self.assertEqual(res.returncode,2,res.stdout+res.stderr)
  self.assertIn('pending 28',res.stdout)

 def test_signed_ledger_still_needs_pinned_evidence_and_ci(self):
  res=self.invoke(GATE)
  self.assertEqual(res.returncode,3,res.stdout+res.stderr)
  self.assertIn('full pinned Bash checkout',res.stderr)

 def test_forged_all_pass_manifest_with_fake_evidence_is_rejected(self):
  # Isolated copy: intentionally mock 28 statuses and fake evidence files.
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp)
   (t/'scripts').mkdir();(t/'cases').mkdir();(t/'evidence').mkdir()
   shutil.copy2(GATE,t/'scripts/check_release_gate.py')
   shutil.copy2(PARITY,t/'scripts/run_parity.py')
   ledger=json.loads((ROOT/'cases/feature_contracts.json').read_text())
   for f in ledger['features']:
    f['status']='VERIFIED_GO_PARITY';f['evidence']='evidence/fake.json'
   (t/'cases/feature_contracts.json').write_text(json.dumps(ledger))
   (t/'evidence/fake.json').write_text(json.dumps({'verdict':'PASS','go_commit':'fake','ci_run_url':'https://example.invalid/1','test_command':'echo pass'}))
   res=self.invoke(t/'scripts/check_release_gate.py')
   self.assertEqual(res.returncode,2,res.stdout+res.stderr)
   self.assertIn('missing executable feature tests 28',res.stdout)

 def test_arbitrary_binary_cannot_be_native_l0(self):
  with tempfile.TemporaryDirectory() as tmp:
   wrapper=Path(tmp)/'pretend_go';wrapper.write_text('#!/bin/sh\necho \'{"protocol":"idleleo-native-parity-v1","go_commit":"fake","package":"fake"}\'\n')
   wrapper.chmod(0o755)
   res=self.invoke(PARITY,'--go-binary',wrapper,'--require-native-l0')
   self.assertEqual(res.returncode,3,res.stdout+res.stderr)
   self.assertIn('BLOCKED',res.stderr)

 def test_retired_require_release_is_blocked(self):
  res=self.invoke(PARITY,'--require-release')
  self.assertEqual(res.returncode,3)
  self.assertIn('retired',res.stderr)

 def test_live_checkout_cannot_be_claimed_without_checkout(self):
  res=self.invoke(PARITY,'--require-live')
  self.assertEqual(res.returncode,3)

 def test_random_git_checkout_not_accepted_as_fixed_bash(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp)
   subprocess.run(['git','init','-q',str(t)],check=True)
   (t/'install.sh').write_text('#!/bin/bash\necho not-the-pinned-source\n')
   subprocess.run(['git','-C',str(t),'add','install.sh'],check=True)
   subprocess.run(['git','-C',str(t),'-c','user.email=ci@example.invalid','-c','user.name=test','commit','-qm','local'],check=True)
   res=self.invoke(PARITY,'--bash-repo',t,'--require-live')
   self.assertEqual(res.returncode,3,res.stdout+res.stderr)
   self.assertIn('fixed commit',res.stderr)

 def test_ci_template_has_both_stage_and_release_gate(self):
  stage=(ROOT/'ci/go-parity-stage.yml').read_text()
  release=(ROOT/'ci/go-release-qualification.yml').read_text()
  self.assertIn('run_stage_gate.py',stage)
  self.assertIn('run_bridge_contract.py',(ROOT/'scripts/run_bridge_fixture_suite.sh').read_text())
  self.assertIn('check_release_gate.py',release)
  self.assertIn('workflow_call:',release)

 def test_preview_refuses_signed_ledger(self):
  import hashlib
  gate=ROOT/'scripts/check_release_gate.py'
  env=dict(os.environ);env['RELEASE_GATE_SHA256']=hashlib.sha256(gate.read_bytes()).hexdigest()
  res=self.invoke(ROOT/'scripts/check_preview_gate.py','--go-bin',sys.executable,
                  '--bash-repo',ROOT.parents[2],env=env)
  self.assertEqual(res.returncode,2,res.stdout+res.stderr)
  self.assertIn('no longer all PENDING',res.stderr)

 def test_signed_stage_smoke_runs_without_claiming_preview(self):
  with tempfile.TemporaryDirectory() as tmp:
   fake=Path(tmp)/'idleleo'
   fake.write_text('#!/bin/sh\necho "idleleo 0.0.0-test"\n')
   fake.chmod(0o755)
   res=self.invoke(ROOT/'scripts/check_signed_stage.py','--go-bin',fake)
  self.assertEqual(res.returncode,0,res.stdout+res.stderr)
  self.assertIn('preview not run',res.stdout.lower())
  self.assertIn('release authority: NONE',res.stdout)

if __name__=='__main__':unittest.main()
