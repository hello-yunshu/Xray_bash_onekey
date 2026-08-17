"""Dependency-free RFC 8032 Ed25519 for release-index signature verification.

The downstream rill-xray-agent payload is pure standard-library Python, so the
upstream rill-ml release index (``stable-index.json``) Ed25519 signature is
verified here without importing ``cryptography``/``PyNaCl``. Only the verifier
is used by production paths; the signing helpers exist solely to build
deterministic test fixtures and are explicitly TEST_ONLY.
"""
from __future__ import annotations

import hashlib

__all__ = ['verify', 'sign', 'public_key_from_seed', 'verify_hex']

# Curve25519 prime and Ed25519 group order.
_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = x * _I % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY % _Q)


def _edwards_add(p, q):
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q) % _Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q) % _Q
    return x3, y3


def _edwards_mul(p, n):
    r = (0, 1)
    while n > 0:
        if n & 1:
            r = _edwards_add(r, p)
        p = _edwards_add(p, p)
        n >>= 1
    return r


def _encodepoint(p):
    x, y = p
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i] << i for i in range(256)).to_bytes(32, 'little'))


def _decodepoint(s):
    y = int.from_bytes(s, 'little') & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7):
        x = _Q - x
    p = (x, y)
    if not (_edwards_mul(p, _L) == (0, 1)):
        raise ValueError('invalid Ed25519 point')
    return p


def _sha512_modl(*msgs):
    h = hashlib.sha512()
    for m in msgs:
        h.update(m)
    return int.from_bytes(h.digest(), 'little') % _L


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a 64-byte Ed25519 ``signature`` over ``message``.

    Returns False (never raises) on any invalid key/signature input.
    """
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        return False
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    try:
        a = _decodepoint(public_key)
        r = _decodepoint(signature[:32])
        s = int.from_bytes(signature[32:], 'little')
        if s >= _L:
            return False
        k = _sha512_modl(signature[:32], public_key, message)
        if _edwards_mul(_B, s) != _edwards_add(r, _edwards_mul(a, k)):
            return False
        return True
    except (ValueError, ArithmeticError, OverflowError):
        return False


def verify_hex(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """Hex-string convenience wrapper around :func:`verify`."""
    try:
        return verify(bytes.fromhex(public_key_hex), message, bytes.fromhex(signature_hex))
    except ValueError:
        return False


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive the Ed25519 public key from a 32-byte seed. TEST_ONLY."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _encodepoint(_edwards_mul(_B, a))


def sign(seed: bytes, message: bytes) -> bytes:
    """Create an Ed25519 signature with a 32-byte seed. TEST_ONLY (fixtures)."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    r = _sha512_modl(prefix, message)
    r_point = _edwards_mul(_B, r)
    r_encoded = _encodepoint(r_point)
    k = _sha512_modl(r_encoded, public_key_from_seed(seed), message)
    s = (r + k * a) % _L
    return r_encoded + s.to_bytes(32, 'little')
