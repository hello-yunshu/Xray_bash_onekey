from pathlib import Path
from .canonical import read_json
TERMINAL={'committed','rolledBack','rollbackUnverified','rejected','noChange'}
def scan_transactions(root):
  root=Path(root);r={'total':0,'incomplete':0,'unsafe':0,'states':{}}
  if not root.exists():return r
  for e in root.iterdir():
   if not e.is_dir():
    continue
   r['total']+=1
   if e.is_symlink():r['unsafe']+=1;continue
   try:name=str(read_json(e/'state.json')['state'])
   except Exception:r['unsafe']+=1;continue
   r['states'][name]=r['states'].get(name,0)+1
   if name not in TERMINAL:r['incomplete']+=1
   if name=='committed' and not (e/'commit-bundle.json').is_file():r['unsafe']+=1
  return r
def health(state_root, txn_root, audit=None, operations=None):
    tx = scan_transactions(txn_root)
    reasons = []
    if tx['incomplete'] or tx['unsafe']:
        reasons.append('incomplete_or_unsafe_root_transaction')
    if audit:
        try:
            audit.verify()
        except Exception:
            reasons.append('audit_chain_invalid')
    if operations is not None and operations.pending_count():
        reasons.append('unfinished_operations')
    status = 'recovery-required' if reasons else 'ready'
    return {'status': status, 'canObserve': True, 'canRecommend': not reasons, 'canApply': False,
            'reasons': reasons, 'rootTransactions': tx}
