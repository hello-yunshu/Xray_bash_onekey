import os
import pwd
import socket
import struct
import sys


def peer_credentials(sock):
    """Best-effort SO_PEERCRED (Linux) / LOCAL_PEERCRED (macOS) extraction.

    Returns (pid, uid, gid); unavailable fields are None.
    """
    if sys.platform.startswith('linux') and hasattr(socket, 'SO_PEERCRED'):
        try:
            pid, uid, gid = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            return (pid, uid, gid)
        except (OSError, struct.error):
            return (None, None, None)
    if sys.platform == 'darwin' and hasattr(socket, 'LOCAL_PEERCRED'):
        try:
            cred = sock.getsockopt(0, socket.LOCAL_PEERCRED, 200)
            uid, gid = struct.unpack_from('ii', cred, 4)
            return (None, uid, gid)
        except (OSError, struct.error):
            return (None, None, None)
    return (None, None, None)


class AccessControl:
    """Fail-closed UID allowlist.

    An empty set is a VALID empty allowlist (deny everyone): it is never
    treated as "open". The only way to open access is to explicitly construct
    with open_allow=True, which tests and throwaway setups must do on purpose.
    """

    def __init__(self, allowed_uids=None, open_allow=False):
        if open_allow:
            self.allowed_uids = None
        else:
            self.allowed_uids = set(allowed_uids) if allowed_uids is not None else set()

    def authorize(self, creds):
        return self._uid_allowed(creds)

    def write_permitted(self, uid):
        if self.allowed_uids is None:
            return True
        return uid is not None and uid in self.allowed_uids

    def _uid_allowed(self, creds):
        if self.allowed_uids is None:
            return True
        uid = creds[1] if creds else None
        return uid is not None and uid in self.allowed_uids

    def describe(self):
        return {'mode': 'open' if self.allowed_uids is None else 'allowlist',
                'allowedUids': sorted(self.allowed_uids) if self.allowed_uids is not None else []}


def production_allowed_uids(service_user='rill-xray-agent', extra_operators=()):
    """Explicit production allowlist UIDs.

    Never hardcodes a magic numeric uid: built at runtime from root (0),
    the current process owner, and the rill-xray-agent service account.
    Always includes root so a privileged operator can recover.
    """
    uids = {0, os.getuid()}
    try:
        uids.add(pwd.getpwnam(service_user).pw_uid)
    except KeyError:
        if not extra_operators:
            uids.add(os.getuid())
    for name in extra_operators:
        try:
            uids.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            pass
    return sorted(uids)