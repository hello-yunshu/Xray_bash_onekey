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
    def __init__(self, allowed_uids=None):
        self.allowed_uids = set(allowed_uids) if allowed_uids else None

    def authorize(self, creds):
        if self.allowed_uids is None:
            return True
        uid = creds[1] if creds else None
        return uid is not None and uid in self.allowed_uids

    def describe(self):
        return {'mode': 'allowlist' if self.allowed_uids is not None else 'open',
                'allowedUids': sorted(self.allowed_uids) if self.allowed_uids is not None else None}