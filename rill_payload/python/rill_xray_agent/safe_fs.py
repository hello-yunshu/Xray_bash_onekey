import errno
import os
import secrets
import stat
from pathlib import Path,PurePosixPath
from .errors import UnsafePathError
def safe_relative(name):
 p=PurePosixPath(name)
 if p.is_absolute() or not p.parts or any(x in {'','..','.'} for x in p.parts):raise UnsafePathError(name)
 return p
def _trusted_root_alias(p):
 return p.parent==Path(p.anchor) and os.path.realpath(p)!=os.fspath(p)
def reject_ancestor_symlinks(path):
 p=Path(path).absolute()
 while True:
  if p.is_symlink() and not _trusted_root_alias(p):raise UnsafePathError(f'symlink ancestor: {p}')
  if p.parent==p:break
  p=p.parent
def write_beneath(root,rel,data,mode=0o600):
 p=safe_relative(rel);root=Path(root);reject_ancestor_symlinks(root);fd=os.open(root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
 try:
  for part in p.parts[:-1]:
   try:os.mkdir(part,0o700,dir_fd=fd)
   except FileExistsError:pass
   nxt=os.open(part,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0),dir_fd=fd);os.close(fd);fd=nxt
  name=p.parts[-1];token=secrets.token_hex(12);tmp=f'.{name}.tmp.{token}';backup=f'.{name}.old.{token}';out=None;published=False;had_old=False;owns_tmp=False
  try:
   out=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),mode,dir_fd=fd)
   owns_tmp=True
   view=memoryview(data);offset=0
   while offset<len(view):
    try:n=os.write(out,view[offset:])
    except InterruptedError:continue
    if n<=0:raise OSError(errno.EIO,'write made no progress')
    offset+=n
   os.fchmod(out,mode & 0o777)
   os.fsync(out);os.close(out);out=None
   try:
    existing=os.stat(name,dir_fd=fd,follow_symlinks=False)
    if not stat.S_ISREG(existing.st_mode):raise UnsafePathError(f'unsafe target: {name}')
    os.link(name,backup,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False);had_old=True
   except FileNotFoundError:pass
   os.replace(tmp,name,src_dir_fd=fd,dst_dir_fd=fd);published=True;os.fsync(fd)
   if had_old:
    try:os.unlink(backup,dir_fd=fd)
    except FileNotFoundError:pass
  except Exception:
   if published:
    if had_old:os.replace(backup,name,src_dir_fd=fd,dst_dir_fd=fd)
    else:
     try:os.unlink(name,dir_fd=fd)
     except FileNotFoundError:pass
   raise
  finally:
   if out is not None:os.close(out)
   for leftover in ((tmp,) if owns_tmp else ()) + ((backup,) if had_old else ()):
    try:os.unlink(leftover,dir_fd=fd)
    except FileNotFoundError:pass
 finally:os.close(fd)
