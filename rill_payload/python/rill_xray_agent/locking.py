import errno
import fcntl
import os
import time
from pathlib import Path


class FileLock:
    def __init__(self, path):
        self.path = Path(path)
        self.f = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.f = self.path.open('a+b')
        fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *_):
        fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        self.f.close()


class LockTimeoutError(Exception):
    """Raised when the observer mutex could not be acquired within its bound."""


class ObserverLock:
    """Cross-process mutex over the WHOLE observer transition.

    A systemd timer/path observer and a direct manager/install call can
    otherwise run the (read checkpoint -> recover pending transition -> read
    previous observation -> read live observation -> derive -> journal append
    -> observation replace -> checkpoint clear) transaction concurrently. This
    lock serializes them: it is acquired BEFORE recovery and released only
    AFTER the observation is replaced and the checkpoint cleared, so two
    observers can never interleave the crash-safe exactly-once commit.

    - The lock file is a root-owned regular file (created 0o600, opened with
      O_NOFOLLOW): a pre-existing symlink at the path fails closed (ELOOP)
      instead of being followed.
    - Blocking with a bounded timeout. flock is released automatically by the
      kernel if the holder process dies, so a crashed observer cannot wedge
      later observers into a permanent wait.
    - The lock is a mutual-exclusion device, not a data store; its contents
      are never read.
    """

    def __init__(self, path, timeout=60.0):
        self.path = Path(path)
        self.timeout = timeout
        self._fd = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self._fd = fd
        try:
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN):
                        raise
                    if time.monotonic() >= deadline:
                        raise LockTimeoutError(
                            f'acquire observer lock timed out: {self.path}')
                    time.sleep(0.02)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            self._fd = None
            raise
        return self

    def __exit__(self, *_):
        if self._fd is None:
            return False
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(self._fd)
        except OSError:
            pass
        self._fd = None
        return False