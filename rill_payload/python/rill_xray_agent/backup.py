import hashlib,json,os,platform,stat,zipfile
from pathlib import Path,PurePosixPath
from .canonical import canonical_bytes
from .errors import BackupError
from .safe_fs import reject_ancestor_symlinks,safe_relative,write_beneath
NAMES=('private','secret','token','password','credential','xray.key');VALUES=('vless://','privatekey','password','token','authorization','github_pat_','ghp_','-----begin');MAX_ENTRIES=4096;MAX_MEMBER=16777216;MAX_TOTAL=268435456;MAX_RATIO=200
def safe_content(p,d):return not any(x in p.name.lower() for x in NAMES) and not any(x in d[:2097152].decode('utf-8','ignore').lower() for x in VALUES)
def create_backup(out,sources,meta=None,now=0):
 entries=[];payload=[]
 for label,root in sources:
  reject_ancestor_symlinks(root)
  if not Path(root).exists():continue
  for p in sorted(Path(root).rglob('*')):
   if p.is_file() and not p.is_symlink():
    d=p.read_bytes()
    if safe_content(p,d):
     rel=f'data/{label}/{p.relative_to(root).as_posix()}';entries.append({'path':rel,'sha256':hashlib.sha256(d).hexdigest(),'size':len(d),'mode':stat.S_IMODE(p.stat().st_mode)});payload.append((rel,d,stat.S_IMODE(p.stat().st_mode)))
 m={'schemaVersion':2,'kind':'state','createdAtEpochSeconds':now,'candidateVersion':'0.1.0','platform':platform.system().lower(),'entries':entries,**(meta or {})};epoch=(2026,8,4,0,0,0)
 with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  i=zipfile.ZipInfo('MANIFEST.json',epoch);i.external_attr=0o100600<<16;z.writestr(i,canonical_bytes(m)+b'\n')
  for rel,d,mode in payload:i=zipfile.ZipInfo(rel,epoch);i.external_attr=((0o100000|mode)<<16);z.writestr(i,d)
 return m
def verify_backup(path):
 with zipfile.ZipFile(path) as z:
  infos=z.infolist();names=[i.filename for i in infos]
  if len(names)!=len(set(names)) or len(names)>MAX_ENTRIES or 'MANIFEST.json' not in names:raise BackupError('members invalid')
  m=json.loads(z.read('MANIFEST.json'));expected={e['path']:e for e in m['entries']};actual=set(names)-{'MANIFEST.json'}
  if actual!=set(expected):raise BackupError('coverage')
  total=0
  for i in infos:
   if i.filename=='MANIFEST.json':continue
   p=safe_relative(i.filename)
   if p.parts[0]!='data':raise BackupError('prefix')
   total+=i.file_size
   if i.file_size>MAX_MEMBER or total>MAX_TOTAL or (i.compress_size and i.file_size/max(1,i.compress_size)>MAX_RATIO):raise BackupError('limits')
   d=z.read(i);e=expected[i.filename]
   if len(d)!=e['size'] or hashlib.sha256(d).hexdigest()!=e['sha256']:raise BackupError('digest')
  return m
def restore_backup(path,target,force=False):
 m=verify_backup(path);target=Path(target);reject_ancestor_symlinks(target.parent)
 if target.exists() and any(target.iterdir()) and not force:raise BackupError('non-empty')
 staging=target.parent/f'.{target.name}.restore.{os.getpid()}'
 if staging.exists():import shutil;shutil.rmtree(staging)
 staging.mkdir(mode=0o700)
 with zipfile.ZipFile(path) as z:
  for e in m['entries']:write_beneath(staging,'/'.join(PurePosixPath(e['path']).parts[1:]),z.read(e['path']),e['mode'])
 old=None
 if target.exists():old=target.parent/f'.{target.name}.previous.{os.getpid()}';os.replace(target,old)
 os.replace(staging,target)
 if old:import shutil;shutil.rmtree(old)
 return m
