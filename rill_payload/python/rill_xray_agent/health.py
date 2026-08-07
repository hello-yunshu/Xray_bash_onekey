from pathlib import Path
from .canonical import digest, read_json
TERMINAL={'committed','rolledBack','rollbackUnverified','rejected','noChange'}


def _bundle_integrity(w):
    """Returns terminal_state only when the commit bundle exists, its hash is
    valid and every durable artifact (result/receipt) is present."""
    b = w / 'commit-bundle.json'
    if not b.is_file():
        return None
    try:
        data = read_json(b)
    except Exception:
        return None
    base = {k: v for k, v in data.items() if k != 'commitSha256'}
    try:
        if digest(base) != data['commitSha256']:
            return None
    except Exception:
        return None
    for artifact in ('result.json', 'receipt.json'):
        if not (w / artifact).is_file():
            return None
    return data.get('terminalState')


def scan_transactions(root, delivery_file=None):
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
   if name=='committed':
    if _bundle_integrity(e)!='committed':r['unsafe']+=1
    elif delivery_file is not None and not Path(delivery_file).is_file():r['unsafe']+=1
   elif name=='rolledBack':
    # A rolledBack state is only trustworthy with its full rollback bundle.
    if _bundle_integrity(e)!='rolledBack':r['unsafe']+=1
    elif delivery_file is not None and not Path(delivery_file).is_file():r['unsafe']+=1
   elif name=='rollbackUnverified':
    # rollbackUnverified is NEVER a safe terminal state.
    r['incomplete']+=1;r['unsafe']+=1
  return r

def health(state_root, txn_root, audit=None, operations=None, delivery_file=None):
    tx = scan_transactions(txn_root, delivery_file)
    reasons = []
    if tx['incomplete'] or tx['unsafe']:
        reasons.append('incomplete_or_unsafe_root_transaction')
    if 'rollbackUnverified' in tx['states']:
        reasons.append('rollback_unverified')
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