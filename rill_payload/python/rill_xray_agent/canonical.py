import hashlib,json,os,tempfile
from pathlib import Path
def canonical_bytes(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def digest(v):return hashlib.sha256(canonical_bytes(v)).hexdigest()
def file_sha256(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def fsync_dir(path):
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
 try:os.fsync(fd)
 finally:os.close(fd)
def atomic_write_bytes(path,data,mode=0o600):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 if path.is_symlink():raise ValueError(f'symlink target: {path}')
 fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.chmod(tmp,mode);os.replace(tmp,path);fsync_dir(path.parent)
 finally:
  try:os.unlink(tmp)
  except FileNotFoundError:pass
def atomic_write_json(path,v,mode=0o600):atomic_write_bytes(path,canonical_bytes(v)+b'\n',mode)
def read_json(path):
 path=Path(path)
 if path.is_symlink() or not path.is_file():raise ValueError(f'unsafe/missing JSON: {path}')
 return json.loads(path.read_text())
