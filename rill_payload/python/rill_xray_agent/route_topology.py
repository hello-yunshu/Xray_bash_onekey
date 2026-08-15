import hashlib,json,time
from .canonical import digest
_MANAGED_PREFIX='rill-managed-'
_SELECTOR_KEYS=('domain','ip','network','port','protocol','source','inboundTag','user','email')
def _kind(rule):
 if isinstance(rule.get('domain'),(list,str)):return 'domain'
 if isinstance(rule.get('ip'),(list,str)):return 'ip'
 if rule.get('type')=='field' or any(k in rule for k in _SELECTOR_KEYS[2:]):return 'field'
 return 'other'
def _selector(rule):
 for k in _SELECTOR_KEYS:
  if k in rule and rule[k] is not None:return k,rule[k]
 return None,None
def _marker():
 return _MANAGED_PREFIX+hashlib.sha256(b'rill-xray-agent-ownership').hexdigest()[:6]
class RouteTopologyProjection:
 def __init__(self,routing,config_generation=0,whole_config_safe_digest=None,captured_at_epoch_seconds=None):
  self._routing=routing if isinstance(routing,dict) else {}
  self._generation=int(config_generation)
  self._whole_digest=whole_config_safe_digest
  self._captured_at=int(captured_at_epoch_seconds) if captured_at_epoch_seconds is not None else int(time.time())
  rules=self._routing.get('rules');self._rules=rules if isinstance(rules,list) else []
 @staticmethod
 def ownership_marker():return _marker()
 def _managed(self,rule):
  tag=rule.get('tag');return isinstance(tag,str) and tag.startswith(_MANAGED_PREFIX)
 def _safe_rule(self,index,rule,position):
  k=_kind(rule);st,sv=_selector(rule)
  return {'ruleIndex':index,'ruleKind':k,'selectorType':st if st is not None else 'none','selectorDigest':digest({'v':sv}) if sv is not None else '','outboundTag':rule.get('outboundTag',''),'isManaged':self._managed(rule),'hasCatchAll':sv is None,'position':position}
 def project(self):
  rules=[self._safe_rule(i,r,p) for p,(i,r) in enumerate(enumerate(self._rules))]
  d=self._whole_digest or ''
  return {'schemaVersion':1,'capturedAtEpochSeconds':self._captured_at,'configGeneration':self._generation,'wholeConfigSha256':d,'wholeConfigSafeDigest':d,'routingRulesCount':len(self._rules),'rules':rules}
 def managed_rules(self):return [i for i,r in enumerate(self._rules) if self._managed(r)]
 def unreachable_rules(self):
  seen={};shadowed={}
  for i,r in enumerate(self._rules):
   st,sv=_selector(r)
   if st in ('domain','ip') and sv is not None:
    key=(st,digest({'v':sv}))
    if key in seen:shadowed[i]=seen[key]
    else:seen[key]=i
  return shadowed
