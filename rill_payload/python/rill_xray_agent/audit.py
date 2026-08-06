import json,os,time
from pathlib import Path
from .canonical import atomic_write_json,canonical_bytes,digest,read_json,fsync_dir
from .errors import AuditError
from .locking import FileLock
GENESIS='0'*64
SENSITIVE=('privatekey','password','token','secret','uuid','shortid','credential','authorization','vless://')
def redact(v,key=''):
 if any(x in key.lower() for x in SENSITIVE):return '<redacted>'
 if isinstance(v,dict):return {k:redact(x,k) for k,x in v.items()}
 if isinstance(v,list):return [redact(x,key) for x in v]
 if isinstance(v,str) and any(x in v.lower() for x in SENSITIVE):return '<redacted>'
 return v
class AuditLog:
 def __init__(self,root,segment_bytes=1048576,total_bytes=8388608):
  self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.segment_bytes=segment_bytes;self.total_bytes=total_bytes;self.head=self.root/'head.json';self.intent=self.root/'append-intent.json';self.lock=self.root/'.lock'
 def segments(self):return sorted(self.root.glob('events-*.jsonl'))
 def verify(self):
  prev=GENESIS;seq=0
  for p in self.segments():
   if p.is_symlink():raise AuditError('symlink segment')
   for line in p.read_text().splitlines():
    e=json.loads(line);sup=e.pop('eventHash')
    if e.get('sequence')!=seq+1 or e.get('previousEventHash')!=prev or digest(e)!=sup:raise AuditError(f'chain invalid {seq+1}')
    seq+=1;prev=sup
  if self.head.exists() and read_json(self.head)!={'schemaVersion':1,'sequence':seq,'headHash':prev}:raise AuditError('head mismatch')
  if seq and not self.head.exists():raise AuditError('head missing')
  return {'events':seq,'headHash':prev}
 def reconcile(self):
  if not self.intent.exists():return self.verify()
  i=read_json(self.intent);e=i['event'];seg=self.root/i['segment'];found=seg.exists() and any(json.loads(x).get('eventHash')==e['eventHash'] for x in seg.read_text().splitlines())
  if not found:
   with seg.open('ab') as f:f.write(canonical_bytes(e)+b'\n');f.flush();os.fsync(f.fileno())
   fsync_dir(seg.parent)
  atomic_write_json(self.head,{'schemaVersion':1,'sequence':e['sequence'],'headHash':e['eventHash']});self.intent.unlink();fsync_dir(self.root);return self.verify()
 def append(self,event_type,actor_type='system',actor_id='runtime',details=None,now=None):
  with FileLock(self.lock):
   st=self.reconcile() if self.intent.exists() else (self.verify() if self.head.exists() else {'events':0,'headHash':GENESIS})
   e={'schemaVersion':1,'sequence':st['events']+1,'eventType':event_type,'timestampEpochSeconds':int(now or time.time()),'actorType':actor_type,'actorId':actor_id,'details':redact(details or {}),'previousEventHash':st['headHash']};e['eventHash']=digest(e);line=canonical_bytes(e)+b'\n';segs=self.segments();seg=segs[-1] if segs else self.root/'events-000001.jsonl'
   if seg.exists() and seg.stat().st_size+len(line)>self.segment_bytes:seg=self.root/f'events-{len(segs)+1:06d}.jsonl'
   if sum(p.stat().st_size for p in segs)+len(line)>self.total_bytes:raise AuditError('audit capacity exhausted')
   atomic_write_json(self.intent,{'schemaVersion':1,'segment':seg.name,'event':e})
   if os.environ.get('RILL_AUDIT_FAIL_AFTER_INTENT')=='1':raise AuditError('fault after intent')
   with seg.open('ab') as f:f.write(line);f.flush();os.fsync(f.fileno())
   fsync_dir(seg.parent)
   if os.environ.get('RILL_AUDIT_FAIL_AFTER_EVENT')=='1':raise AuditError('fault after event')
   atomic_write_json(self.head,{'schemaVersion':1,'sequence':e['sequence'],'headHash':e['eventHash']});self.intent.unlink();fsync_dir(self.root);return e
