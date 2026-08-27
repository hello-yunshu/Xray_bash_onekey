# Canonical adapter observations remain summaries; host commands use the
# fixed environment below so diagnostics never depend on caller state.
import hashlib,os,subprocess,time
from pathlib import Path
from .canonical import atomic_write_json,file_sha256
def run(cmd):
 try:r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20,env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'})
 except (OSError,subprocess.TimeoutExpired) as e:return {'ok':False,'returnCode':124 if isinstance(e,subprocess.TimeoutExpired) else 127,'outputSha256':hashlib.sha256(str(e).encode()).hexdigest()}
 return {'ok':r.returncode==0,'returnCode':r.returncode,'outputSha256':hashlib.sha256(r.stdout[:1048576]).hexdigest()}
def summary(p):
 p=Path(p)
 if not p.exists():return {'present':False}
 if p.is_symlink():return {'present':True,'safe':False}
 if p.is_file():return {'present':True,'safe':True,'sha256':file_sha256(p),'size':p.stat().st_size}
 h=hashlib.sha256();count=0
 for f in sorted(p.rglob('*')):
  if f.is_file() and not f.is_symlink():h.update(f.relative_to(p).as_posix().encode()+b'\0'+bytes.fromhex(file_sha256(f)));count+=1
 return {'present':True,'safe':True,'treeSha256':h.hexdigest(),'files':count}
def observe(root=None,xray_bin=Path('/usr/local/bin/xray'),nginx_bin=Path('/usr/local/nginx/sbin/nginx')):
 root=Path(root or os.environ.get('RILL_XRAY_HOST_ROOT','/etc/rill-xray-agent/host'));xc=root/'conf/xray/config.json';nc=root/'conf/nginx';ic=root/'conf/install_config.json';missing={'ok':False,'returnCode':66,'outputSha256':hashlib.sha256(b'missing').hexdigest()}
 return {'schemaVersion':1,'capturedAtEpochSeconds':int(time.time()),'xrayConfig':summary(xc),'nginxConfig':summary(nc),'installConfig':summary(ic),'xrayValidation':run([str(xray_bin),'run','-test','-config',str(xc)]) if xc.exists() and xray_bin.exists() else missing,'nginxValidation':run([str(nginx_bin),'-t']) if nginx_bin.exists() else missing,'services':{'xray':run(['/bin/systemctl','is-active','--quiet','xray']),'nginx':run(['/bin/systemctl','is-active','--quiet','nginx'])}}
def write_observation(out,**kw):v=observe(**kw);atomic_write_json(out,v,0o640);return v
