import time
from pathlib import Path
from .canonical import atomic_write_json,digest,read_json
from .errors import ContractError,DecisionIdentityConflict
from .locking import FileLock
class RuntimeState:
 def __init__(self,path,max_completed=4096):self.path=Path(path);self.lock=self.path.with_suffix('.lock');self.max_completed=max_completed
 def empty(self):return {'schemaVersion':3,'mode':'observe-only','routeAssistEnabled':False,'pending':{},'completed':{},'closed':{},'restartCount':0}
 def load(self):
  if not self.path.exists():return self.empty()
  v=read_json(self.path)
  if v.get('schemaVersion') not in {1,2,3}:raise ContractError('unsupported state')
  if v['schemaVersion']!=3:
   m=self.empty();m.update({k:x for k,x in v.items() if k in m});v=m;self.save(v)
  return v
 def save(self,v):atomic_write_json(self.path,v)
 def transact(self,fn):
  with FileLock(self.lock):
   s=self.load();c={**s,'pending':dict(s['pending']),'completed':dict(s['completed']),'closed':dict(s['closed'])};r=fn(c);self.save(c);return r
 def register(self,capability,decision_id,generation,created):
  ident={'capability':capability,'decisionId':decision_id,'modelGeneration':generation,'createdAtEpochSeconds':created}
  def tx(s):
   e=s['pending'].get(decision_id) or s['completed'].get(decision_id) or s['closed'].get(decision_id)
   if e:
    if e.get('identity')==ident:return {'status':'idempotent'}
    raise DecisionIdentityConflict('decision ID different identity')
   s['pending'][decision_id]={'identity':ident,'rootResult':None,'registeredAtEpochSeconds':int(time.time())};return {'status':'registered'}
  return self.transact(tx)
 def commit_root_result(self,did,result):
  def tx(s):
   p=s['pending'].get(did)
   if not p:raise ContractError('unknown pending decision')
   if p.get('rootResult'):
    if digest(p['rootResult'])==digest(result):return {'status':'idempotent'}
    raise ContractError('conflicting result')
   p['rootResult']=result;return {'status':'committed'}
  return self.transact(tx)
 def feedback(self,payload):
  did=payload.get('decisionId');psha=digest(payload)
  def tx(s):
   c=s['completed'].get(did)
   if c:
    if c['payloadSha256']==psha:return {'status':'idempotent','accepted':True}
    raise ContractError('conflicting completed feedback')
   p=s['pending'].get(did)
   if not p:raise ContractError('feedback unknown')
   i=p['identity']
   if payload.get('capability')!=i['capability'] or payload.get('modelGeneration')!=i['modelGeneration']:raise DecisionIdentityConflict('feedback identity conflict')
   if i['capability']=='route' and not p.get('rootResult'):raise ContractError('feedback before root result')
   s['completed'][did]={'identity':i,'payload':payload,'payloadSha256':psha,'acceptedAtEpochSeconds':int(time.time())};del s['pending'][did]
   while len(s['completed'])>self.max_completed:del s['completed'][sorted(s['completed'])[0]]
   return {'status':'accepted','accepted':True}
  return self.transact(tx)
