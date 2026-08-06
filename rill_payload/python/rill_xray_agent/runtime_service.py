import json,os,socket,uuid,threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .audit import AuditLog
from .canonical import canonical_bytes
from .health import health
from .state import RuntimeState
ALLOWED={'health','metrics','mode','config','register','rootResult','feedback','inspect','snapshot'}
class RuntimeService:
 def __init__(self,state_root,txn_root):self.state_root=Path(state_root);self.state_root.mkdir(parents=True,exist_ok=True);self.txn_root=Path(txn_root);self.state=RuntimeState(self.state_root/'runtime-state.json');self.audit=AuditLog(self.state_root/'audit');self.pool=ThreadPoolExecutor(max_workers=32);self._stop=threading.Event();self._socket_path=None
 def handle(self,e,peer_uid=None):
  rid=e.get('requestId') or str(uuid.uuid4());m=e.get('method');b=e.get('body') or {}
  try:
   if e.get('schemaVersion')!=3 or m not in ALLOWED:raise ValueError('invalid envelope/method')
   if m=='health':r=health(self.state_root,self.txn_root,self.audit)
   elif m=='metrics':s=self.state.load();r={'pending':len(s['pending']),'completed':len(s['completed']),'closed':len(s['closed'])}
   elif m=='mode':
    mode=b.get('mode')
    if mode not in {'normal','observe-only','safe-disabled'}:raise ValueError('invalid mode')
    def tx(s):s['mode']=mode;s['routeAssistEnabled']=False if mode!='normal' else s['routeAssistEnabled'];return {'mode':mode}
    r=self.state.transact(tx);self.audit.append('runtime.mode.changed',actor_id=str(peer_uid),details=r)
   elif m=='config':s=self.state.load();r={'mode':s['mode'],'routeAssistEnabled':s['routeAssistEnabled'],'boundedAutoAllowed':False}
   elif m=='register':r=self.state.register(b['capability'],b['decisionId'],int(b['modelGeneration']),int(b['createdAtEpochSeconds']));self.audit.append('decision.registered',details={'decisionId':b['decisionId']})
   elif m=='rootResult':r=self.state.commit_root_result(b['decisionId'],b['result']);self.audit.append('decision.root_result',details={'decisionId':b['decisionId']})
   elif m=='feedback':r=self.state.feedback(b);self.audit.append('decision.feedback',details={'decisionId':b.get('decisionId')})
   elif m=='inspect':s=self.state.load();did=b.get('decisionId');r={'pending':s['pending'].get(did),'completed':s['completed'].get(did),'closed':s['closed'].get(did)}
   else:r=self.state.load()
   return {'schemaVersion':3,'requestId':rid,'ok':True,'result':r}
  except Exception as x:return {'schemaVersion':3,'requestId':rid,'ok':False,'error':{'code':getattr(x,'code','contractViolation'),'message':str(x)[:512]}}
 def client(self,c):
  c.settimeout(5)
  try:
   d=b''
   while b'\n' not in d and len(d)<=1048576:
    x=c.recv(65536)
    if not x:break
    d+=x
   if len(d)>1048576:raise ValueError('too large')
   c.sendall(canonical_bytes(self.handle(json.loads(d.split(b'\n',1)[0])))+b'\n')
  except Exception as x:
   try:c.sendall(canonical_bytes({'schemaVersion':3,'requestId':'unknown','ok':False,'error':{'code':'transportError','message':str(x)[:256]}})+b'\n')
   except Exception:pass
  finally:c.close()
 def stop(self):
  self._stop.set()
  if self._socket_path:
   try:
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as wake:wake.settimeout(.2);wake.connect(str(self._socket_path))
   except Exception:pass
 def serve(self,path):
  path=Path(path);self._socket_path=path;path.parent.mkdir(parents=True,exist_ok=True);path.unlink(missing_ok=True);s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(str(path));os.chmod(path,0o660);s.listen(32);s.settimeout(1)
  try:
   while not self._stop.is_set():
    try:c,_=s.accept()
    except socket.timeout:continue
    self.pool.submit(self.client,c)
  finally:s.close();self.pool.shutdown(wait=True,cancel_futures=True);path.unlink(missing_ok=True);self._socket_path=None
