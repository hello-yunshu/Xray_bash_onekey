import os,shutil,time
from pathlib import Path
from .canonical import atomic_write_bytes,atomic_write_json,digest,file_sha256,read_json
from .errors import TransactionError
from .locking import FileLock
class RootTransaction:
 def __init__(self,root,delivery,generation_file):self.root=Path(root);self.delivery=Path(delivery);self.generation_file=Path(generation_file);self.lock=self.root/'.single-flight.lock'
 def generation(self):
  try:return int(self.generation_file.read_text().strip())
  except FileNotFoundError:return 0
 def state(self,w,s,x=None):atomic_write_json(w/'state.json',{'schemaVersion':1,'state':s,**(x or {})})
 def apply(self,request,managed,apply_fn,verify_fn):
  did=request['recommendationId'];w=self.root/did
  with FileLock(self.lock):
   if (w/'commit-bundle.json').exists():return self.materialize(w)
   w.mkdir(parents=True,exist_ok=True);old=self.generation()
   if old!=request['configurationGeneration']:raise TransactionError('generation mismatch')
   existed=managed.exists();backup=w/'managed.backup'
   if existed and not backup.exists():shutil.copy2(managed,backup)
   meta={'schemaVersion':1,'managedExisted':existed,'backupSha256':file_sha256(backup) if existed else None,'oldGeneration':old,'newGeneration':old+1};atomic_write_json(w/'backup-metadata.json',meta);atomic_write_json(w/'request.json',request);self.state(w,'prepared')
   try:
    apply_fn();self.state(w,'applied')
    if not verify_fn():raise TransactionError('verify failed')
    outcome='success';terminal='committed'
   except Exception:
    if existed:atomic_write_bytes(managed,backup.read_bytes(),0o640)
    elif managed.exists():managed.unlink()
    atomic_write_bytes(self.generation_file,(str(old)+'\n').encode(),0o640);outcome='rolledBack';terminal='rolledBack'
   body={'schemaVersion':2,'decisionId':did,'outcome':outcome,'observedAtEpochSeconds':int(time.time()),'configurationGeneration':old,'nextConfigurationGeneration':old+1 if terminal=='committed' else old};result={**body,'resultSha256':digest(body)};receipt={'schemaVersion':1,'decisionId':did,'resultSha256':result['resultSha256'],'transactionSha256':digest({'request':request,'result':result}),'createdAtEpochSeconds':int(time.time())};base={'schemaVersion':1,'terminalState':terminal,'nextConfigurationGeneration':result['nextConfigurationGeneration'],'result':result,'receipt':receipt,'delivery':{'schemaVersion':1,'request':request,'result':result,'receipt':receipt}};bundle={**base,'commitSha256':digest(base)};atomic_write_json(w/'commit-bundle.json',bundle)
   if os.environ.get('RILL_FAIL_AFTER_COMMIT_BUNDLE')=='1':raise TransactionError('fault after commit bundle')
   return self.materialize(w)
 def materialize(self,w):
  b=read_json(w/'commit-bundle.json');base={k:v for k,v in b.items() if k!='commitSha256'}
  if digest(base)!=b['commitSha256']:raise TransactionError('commit digest')
  atomic_write_bytes(self.generation_file,(str(b['nextConfigurationGeneration'])+'\n').encode(),0o640);atomic_write_json(w/'result.json',b['result']);atomic_write_json(w/'receipt.json',b['receipt']);self.state(w,b['terminalState'],{'commitSha256':b['commitSha256']});self.delivery.mkdir(parents=True,exist_ok=True);atomic_write_json(self.delivery/'route-delivery.json',b['delivery'],0o640);return {'status':b['terminalState'],'result':b['result'],'receipt':b['receipt']}
 def recover_all(self):
  out=[]
  if not self.root.exists():return out
  for w in self.root.iterdir():
   if w.is_dir() and not w.is_symlink() and (w/'commit-bundle.json').exists():self.materialize(w);out.append(w.name)
  return out
