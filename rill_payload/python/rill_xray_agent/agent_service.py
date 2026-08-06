import json,os,socket,threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .canonical import canonical_bytes
ALLOWED={'health','metrics','mode','config','register','rootResult','feedback','inspect','snapshot'}
class AgentService:
 def __init__(self,runtime_socket):self.runtime_socket=Path(runtime_socket);self.pool=ThreadPoolExecutor(max_workers=32);self._stop=threading.Event();self._socket_path=None
 def proxy(self,e):
  if e.get('method') not in ALLOWED:return {'schemaVersion':3,'requestId':e.get('requestId','unknown'),'ok':False,'error':{'code':'forbiddenMethod','message':'not allowed'}}
  try:
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
    s.settimeout(5);s.connect(str(self.runtime_socket));s.sendall(canonical_bytes(e)+b'\n');d=b''
    while b'\n' not in d and len(d)<=1048576:
     x=s.recv(65536)
     if not x:break
     d+=x
    return json.loads(d.split(b'\n',1)[0])
  except Exception as x:return {'schemaVersion':3,'requestId':e.get('requestId','unknown'),'ok':False,'error':{'code':'runtimeUnavailable','message':str(x)[:256]}}
 def client(self,c):
  c.settimeout(5)
  try:
   d=b''
   while b'\n' not in d and len(d)<=1048576:
    x=c.recv(65536)
    if not x:break
    d+=x
   c.sendall(canonical_bytes(self.proxy(json.loads(d.split(b'\n',1)[0])))+b'\n')
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
