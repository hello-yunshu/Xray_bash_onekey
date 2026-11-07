#!/usr/bin/env python3
"""Construct disposable legacy fixtures from the repository's v3.3.4 field model.
Values are synthetic; none is copied from a real user's VPS.
"""
from pathlib import Path
import json, os, sys

root=Path(sys.argv[1]).resolve()
role=sys.argv[2] if len(sys.argv)>2 else "reality"
if root.exists() and any(root.iterdir()): raise SystemExit("fixture root must start empty")
root.mkdir(parents=True,exist_ok=True)
(root/'.idleleo-probe-sandbox').write_text('I_ACCEPT_DISPOSABLE_SANDBOX\n')
def write(rel,data,mode=0o600):
 p=root/rel;p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text(data if isinstance(data,str) else json.dumps(data,indent=2,ensure_ascii=False)+'\n')
 os.chmod(p,mode)
write('etc/idleleo/install.sh','#!/usr/bin/env bash\n# synthetic legacy entrypoint\n',0o700)
link=root/'usr/bin/idleleo';link.parent.mkdir(parents=True,exist_ok=True)
link.symlink_to('/etc/idleleo/install.sh')
if role=='relay':
 legacy={'role':'relay','tls':'None','transport_mode':'None','shell_version':'3.3.4','relay_backend_host':'192.0.2.30','relay_backend_port':'443','relay_listen_addr':'0.0.0.0','relay_listen_port':'9443','relay_enabled':'yes'}
 write('etc/idleleo/conf/install_config.json',legacy)
 write('etc/idleleo/conf/nginx/relay-stream.conf','stream { server { listen 9443; proxy_pass 192.0.2.30:443; } }\n')
elif role in ('reality','xtls','tls'):
 u='11111111-1111-4111-8111-111111111111'
 sec='TEST_PRIVATE_KEY_NOT_REAL'
 if role=='tls':
  legacy={'shell_mode':'Nginx+ws+TLS','transport_mode':'onlyws','tls':'TLS','host':'203.0.113.9','port':443,'email':'example@example.org','id':u,'shell_version':'3.3.4','ws_port':'10086','ws_path':'/ray/'}
  inbound={'port':10086,'listen':'127.0.0.1','tag':'VLESS-ws-in','protocol':'vless','settings':{'clients':[{'id':u,'level':0,'email':'example@example.org'}],'decryption':'none'},'streamSettings':{'network':'ws','security':'none','wsSettings':{'path':'/ray/'}}}
 else:
  legacy={'shell_mode':'XTLS ONLY' if role=='xtls' else 'Reality','transport_mode':'onlyws','tls':'None' if role=='xtls' else 'Reality','host':'203.0.113.9','network_mode':'dual','ipv4_address':'203.0.113.9','ipv6_address':'2001:db8::9','port':443,'email':'example@example.org','id':u,'privateKey':sec,'password':'SYNTHETIC_PUBLIC_KEY','shortIds':'abcdef12','spiderx_path':'/','reality_add_nginx':'off','shell_version':'3.3.4','xray_version':'26.10.31','unknown_custom_property':{'preserve':True}}
  inbound={'port':443,'listen':'0.0.0.0','tag':'VLESS-Reality-in','protocol':'vless','settings':{'clients':[{'id':u,'flow':'xtls-rprx-vision','level':0,'email':'example@example.org'},{'id':'22222222-2222-4222-8222-222222222222','level':0,'email':'second@example.org'}],'decryption':'none'},'streamSettings':{'network':'raw','security':'reality','realitySettings':{'target':'example.org:443','serverNames':['example.org'],'privateKey':sec,'shortIds':['abcdef12']}}}
 native={'log':{'access':'/var/log/xray/access.log','error':'/var/log/xray/error.log','loglevel':'warning'},'inbounds':[inbound], 'outbounds':[{'protocol':'freedom','tag':'direct'},{'protocol':'blackhole','tag':'blocked'},{'protocol':'freedom','tag':'custom-route'}],'dns':{'servers':['https+local://dns.google/dns-query'],'disableCache':False},'routing':{'domainStrategy':'AsIs','rules':[{'type':'field','inboundTag':[inbound['tag']],'outboundTag':'custom-route'}]}}
 write('etc/idleleo/conf/install_config.json',legacy)
 write('etc/idleleo/conf/xray/config.json',native)
 write('etc/idleleo/cert/xray.key','NOT_A_REAL_PRIVATE_KEY\n')
else: raise SystemExit('unknown role')
print(f'fixture_created={root} mode={role} (synthetic data)')
