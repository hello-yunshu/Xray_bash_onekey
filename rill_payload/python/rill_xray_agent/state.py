import time
from pathlib import Path
from .canonical import atomic_write_json,digest,read_json
from .errors import ContractError,DecisionIdentityConflict
from .locking import FileLock


class LedgerFullError(ContractError):
    """Closed ledger is at capacity; failing closed rather than silently
    dropping a tombstone that may still be inside its replay-protection
    window."""


class ClosedLedger:
    """Externalized, bounded closed-decision ledger.

    Tombstones are stored one-per-file under <root>/ as sha256(decisionId).json.
    A tombstone NEVER stores the plaintext decision id, only its hash plus the
    identity/payload hashes and the close timestamp. The ledger has an explicit
    capacity (entries or bytes) and fails closed when full; it never silently
    drops a tombstone. Corrupted files are treated as unsafe on query.
    """

    def __init__(self, root, max_entries=None, max_bytes=None,
                 replay_protection_seconds=21600):
        self.root = Path(root)
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.replay_protection_seconds = replay_protection_seconds
        self.lock = self.root / '.lock'
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _path(root, did):
        return Path(root) / f'{digest(did)}.json'

    def _bytes(self):
        total = 0
        for p in self.root.glob('*.json'):
            try:
                total += p.stat().st_size
            except OSError:
                continue
        return total

    def count(self):
        return len(list(self.root.glob('*.json')))

    def _corrupt(self, p):
        return p.is_symlink() or not p.is_file()

    def get(self, did):
        p = ClosedLedger._path(self.root, did)
        if not p.is_file() or p.is_symlink():
            return None
        try:
            data = read_json(p)
        except Exception:
            return {'corrupt': True, 'decisionIdHash': digest(did)}
        if data.get('schemaVersion') != 1 or data.get('decisionIdHash') != digest(did):
            return {'corrupt': True, 'decisionIdHash': digest(did)}
        return data

    def put(self, did, identity_hash, payload_sha, closed_at):
        with FileLock(self.lock):
            if self.max_entries and self.count() >= self.max_entries:
                raise LedgerFullError('closed ledger at max entries')
            if self.max_bytes and (self._bytes() + 256) > self.max_bytes:
                raise LedgerFullError('closed ledger at max bytes')
            existing = ClosedLedger._path(self.root, did)
            if existing.exists() and not existing.is_symlink():
                try:
                    data = read_json(existing)
                    if (time.time() - data.get('closedAtEpochSeconds', 0)) < self.replay_protection_seconds:
                        raise LedgerFullError('tombstone still in replay-protection window')
                except LedgerFullError:
                    raise
                except Exception:
                    pass
            atomic_write_json(existing, {
                'schemaVersion': 1,
                'decisionIdHash': digest(did),
                'identityHash': identity_hash,
                'payloadHash': payload_sha,
                'closedAtEpochSeconds': int(closed_at),
            })
            return True


class RuntimeState:
 def __init__(self,path,max_completed=4096,ledger_dir=None,max_ledger_entries=0):self.path=Path(path);self.lock=self.path.with_suffix('.lock');self.max_completed=max_completed;self.ledger=ClosedLedger(ledger_dir or (self.path.parent/'closed-ledger'),max_entries=max_ledger_entries)
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
 def _tombstone(self,ident,payload_sha,closed_at):
  return {'decisionIdHash':digest(ident['decisionId']),'identityHash':digest(ident),'payloadHash':payload_sha,'closedAtEpochSeconds':closed_at}
 def ledger_tombstone(self,ident,payload_sha,closed_at):return self._tombstone(ident,payload_sha,closed_at)
 def register(self,capability,decision_id,generation,created):
  ident={'capability':capability,'decisionId':decision_id,'modelGeneration':generation,'createdAtEpochSeconds':created}
  def tx(s):
   e=s['pending'].get(decision_id) or s['completed'].get(decision_id)
   if e:
    if e.get('identity')==ident:return {'status':'idempotent'}
    raise DecisionIdentityConflict('decision ID different identity')
   c=self.ledger.get(decision_id)
   if c:
    if c.get('corrupt'):raise ContractError('closed ledger corrupt')
    if c['identityHash']==digest(ident):return {'status':'idempotent'}
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
   t=self.ledger.get(did)
   if t:
    if t.get('corrupt'):raise ContractError('closed ledger corrupt')
    if t['payloadHash']==psha:return {'status':'idempotent','accepted':True}
    raise ContractError('conflicting closed feedback')
   p=s['pending'].get(did)
   if not p:raise ContractError('feedback unknown')
   i=p['identity']
   if payload.get('capability')!=i['capability'] or payload.get('modelGeneration')!=i['modelGeneration']:raise DecisionIdentityConflict('feedback identity conflict')
   if i['capability']=='route' and not p.get('rootResult'):raise ContractError('feedback before root result')
   from .payload_policy import sanitize_payload
   payload_meta=sanitize_payload(payload)
   s['completed'][did]={'identity':i,'payloadMeta':payload_meta,'payloadSha256':psha,'acceptedAtEpochSeconds':int(time.time())};del s['pending'][did]
   while len(s['completed'])>self.max_completed:
    evicted=sorted(s['completed'])[0];e=s['completed'].pop(evicted)
    self.ledger.put(evicted,digest(e['identity']),e['payloadSha256'],e['acceptedAtEpochSeconds'])
    s['closed'][evicted]=self._tombstone(e['identity'],e['payloadSha256'],e['acceptedAtEpochSeconds'])
   return {'status':'accepted','accepted':True}
  return self.transact(tx)