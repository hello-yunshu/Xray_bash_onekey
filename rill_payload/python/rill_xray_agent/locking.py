import fcntl
from pathlib import Path
class FileLock:
 def __init__(self,path):self.path=Path(path);self.f=None
 def __enter__(self):self.path.parent.mkdir(parents=True,exist_ok=True);self.f=self.path.open('a+b');fcntl.flock(self.f.fileno(),fcntl.LOCK_EX);return self
 def __exit__(self,*_):fcntl.flock(self.f.fileno(),fcntl.LOCK_UN);self.f.close()
