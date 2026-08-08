#!/usr/bin/env python3
"""
Read-only decryption of public-key OpenPGP messages (feature #5, phase 3).

Builds on the symmetric machinery in :mod:`.openpgp` (packet framing, S2K,
SEIPD v1) and adds:

- parsing of an exported OpenPGP secret key (armored or binary), unlocking the
  protected secret material with the key passphrase;
- the Public-Key Encrypted Session Key packet (PKESK, tag 1); and
- session-key unwrap for **RSA** (PKCS#1 v1.5) and **ECDH** (RFC 6637 KDF +
  RFC 3394 AES key-wrap) over Curve25519 and NIST P-256/384/521.

Everything is on pyca ``cryptography``; no GnuPG runtime dependency. The input
(both the message and the supplied key file) is treated as untrusted: sizes are
bounded, integrity (the SEIPD MDC) is verified before any plaintext is returned,
and unsupported algorithms/curves fail closed.
"""

import hashlib
import struct
from typing import List, Optional

from cryptography.exceptions import InternalError, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

from . import openpgp as _pgp
from .openpgp import (
    _CIPHERS,
    _MAX_INPUT,
    CFB,
    OpenPGPError,
    OpenPGPFormatError,
    OpenPGPIntegrityError,
    OpenPGPWrongPassphrase,
    _cipher_algo,
    _decrypt_seipd_v1,
    _extract_plaintext,
    _iter_packets,
    _maybe_dearmor,
    _s2k_derive,
)

# Public-key algorithm IDs (RFC 4880 §9.1)
_PK_RSA = (1, 2)  # RSA (encrypt+sign / encrypt)
_PK_ECDH = 18

# Curve OIDs (bytes after the 1-octet length prefix) -> name
_CURVES = {
    bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]): "cv25519",
    bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]): "nistp256",
    bytes([0x2B, 0x81, 0x04, 0x00, 0x22]): "nistp384",
    bytes([0x2B, 0x81, 0x04, 0x00, 0x23]): "nistp521",
}
_NIST_CURVES = {
    "nistp256": (ec.SECP256R1(), 32),
    "nistp384": (ec.SECP384R1(), 48),
    "nistp521": (ec.SECP521R1(), 66),
}

# S2K usage hashes for KDF (RFC 6637) reuse openpgp's table indirectly.
_S2K_HASHES = _pgp._S2K_HASHES


class OpenPGPNoMatchingKey(OpenPGPError):
    """No supplied secret key matches the message's recipient key ID."""


# --------------------------------------------------------------------------- #
# MPI / field helpers
# --------------------------------------------------------------------------- #


def _read_mpi(data: bytes, off: int):
    """Read an OpenPGP MPI; return (int_value, raw_bytes, next_off)."""
    if off + 2 > len(data):
        raise OpenPGPFormatError("truncated MPI")
    bits = int.from_bytes(data[off : off + 2], "big")
    nbytes = (bits + 7) // 8
    off += 2
    raw = data[off : off + nbytes]
    if len(raw) != nbytes:
        raise OpenPGPFormatError("truncated MPI body")
    return int.from_bytes(raw, "big"), raw, off + nbytes


# --------------------------------------------------------------------------- #
# Secret key parsing
# --------------------------------------------------------------------------- #


class _SecretKey:
    __slots__ = ("key_id", "fingerprint", "algo", "curve", "kdf", "rsa", "ecc_scalar")

    def __init__(self):
        self.key_id = None
        self.fingerprint = None
        self.algo = None
        self.curve = None
        self.kdf = None  # (hash_id, sym_id) for ECDH
        self.rsa = None  # cryptography RSA private key
        self.ecc_scalar = None  # (int, raw_bytes)


def _v4_fingerprint(pub_body: bytes) -> bytes:
    h = hashlib.sha1()
    h.update(b"\x99" + len(pub_body).to_bytes(2, "big") + pub_body)
    return h.digest()


def _parse_public_material(body: bytes, off: int, algo: int):
    """Parse the algo-specific public key material; return a dict and new off."""
    info = {}
    if algo in _PK_RSA:
        n, _, off = _read_mpi(body, off)
        e, _, off = _read_mpi(body, off)
        info["n"] = n
        info["e"] = e
    elif algo in (18, 19, 22):  # ECDH / ECDSA / EdDSA
        oid_len = body[off]
        off += 1
        oid = bytes(body[off : off + oid_len])
        off += oid_len
        info["curve"] = _CURVES.get(oid)
        _point, point_raw, off = _read_mpi(body, off)
        info["point"] = point_raw
        if algo == 18:  # ECDH carries KDF params
            kdf_len = body[off]
            kdf = body[off + 1 : off + 1 + kdf_len]
            off += 1 + kdf_len
            # kdf = 0x01 (reserved) || hash_id || sym_id
            info["kdf"] = (kdf[1], kdf[2])
    else:
        raise OpenPGPFormatError(f"unsupported public-key algorithm {algo}")
    return info, off


def _parse_secret_key_packet(body: bytes, passphrase: bytes) -> Optional[_SecretKey]:
    """Parse a Secret-Key/Secret-Subkey packet body into a usable _SecretKey,
    or None if the (sub)key is not a decryption key we support."""
    if not body or body[0] != 4:
        return None  # only v4 keys
    off = 1
    off += 4  # creation time
    algo = body[off]
    off += 1
    pub_start = 0  # body[0:off_after_public] is the public key body for the fp
    pub_info, after_pub = _parse_public_material(body, off, algo)
    pub_body = body[pub_start:after_pub]
    fingerprint = _v4_fingerprint(pub_body)

    key = _SecretKey()
    key.key_id = fingerprint[-8:]
    key.fingerprint = fingerprint
    key.algo = algo

    if algo not in _PK_RSA and algo != _PK_ECDH:
        return None  # sign-only (EdDSA/ECDSA/DSA) — cannot decrypt

    # Secret material (possibly S2K-encrypted).
    i = after_pub
    usage = body[i]
    i += 1
    if usage == 0:
        secret = body[i:]
        # plaintext secret MPIs (+2-byte checksum) — skip checksum verification
        secret = secret[:-2]
    elif usage in (254, 255):
        sym = body[i]
        i += 1
        _name, key_len, block = _CIPHERS[sym]
        s2k_key, consumed = _s2k_derive(body[i:], passphrase, key_len)
        i += consumed
        iv = body[i : i + block]
        i += block
        enc = body[i:]
        dec = _pgp.Cipher(_cipher_algo(sym, s2k_key), CFB(iv)).decryptor()
        plain = dec.update(enc) + dec.finalize()
        if usage == 254:
            if hashlib.sha1(plain[:-20]).digest() != plain[-20:]:
                raise OpenPGPWrongPassphrase(
                    "secret-key integrity check failed (wrong passphrase?)"
                )
            secret = plain[:-20]
        else:
            secret = plain[:-2]  # 2-byte checksum (not verified — SHA-1 form is used by gpg)
    else:
        raise OpenPGPFormatError(f"unsupported secret-key S2K usage {usage}")

    if algo in _PK_RSA:
        d, _, p_off = _read_mpi(secret, 0)
        p, _, p_off = _read_mpi(secret, p_off)
        q, _, p_off = _read_mpi(secret, p_off)
        # u (p^-1 mod q) is also present but we recompute CRT params.
        key.rsa = _build_rsa_private(pub_info["n"], pub_info["e"], d, p, q)
    else:  # ECDH
        scalar, scalar_raw, _ = _read_mpi(secret, 0)
        key.curve = pub_info.get("curve")
        key.kdf = pub_info.get("kdf")
        key.ecc_scalar = (scalar, scalar_raw)
    return key


def _build_rsa_private(n, e, d, p, q):
    if p < q:  # pyca expects p > q
        p, q = q, p
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)
    pub = rsa.RSAPublicNumbers(e, n)
    return rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub).private_key()


def parse_secret_keys(data: bytes, passphrase: str) -> List[_SecretKey]:
    """Parse all usable decryption (sub)keys from an exported secret key blob."""
    data = _maybe_dearmor(data)
    pw = passphrase.encode("utf-8")
    keys = []
    for tag, body in _iter_packets(data):
        if tag in (5, 7):  # Secret-Key, Secret-Subkey
            try:
                k = _parse_secret_key_packet(body, pw)
            except OpenPGPWrongPassphrase:
                raise
            except OpenPGPError:
                continue
            if k is not None:
                keys.append(k)
    if not keys:
        raise OpenPGPFormatError("no usable decryption key found in the key file")
    return keys


# --------------------------------------------------------------------------- #
# Session-key unwrap
# --------------------------------------------------------------------------- #


def _unwrap_rsa(key: _SecretKey, esk: bytes) -> bytes:
    c, _, _ = _read_mpi(esk, 0)
    size = key.rsa.key_size // 8
    c_bytes = c.to_bytes(size, "big")
    try:
        return key.rsa.decrypt(c_bytes, padding.PKCS1v15())
    except Exception:
        raise OpenPGPWrongPassphrase("RSA session-key decryption failed")


def _ecdh_shared(key: _SecretKey, ephemeral_point: bytes) -> bytes:
    scalar_int, scalar_raw = key.ecc_scalar
    if key.curve == "cv25519":
        # X25519 scalar is the secret in little-endian (gpg stores big-endian MPI).
        le = scalar_int.to_bytes(32, "big")[::-1]
        priv = X25519PrivateKey.from_private_bytes(le)
        # Ephemeral point is 0x40 || 32-byte u-coordinate.
        if len(ephemeral_point) != 33 or ephemeral_point[0] != 0x40:
            raise OpenPGPFormatError("malformed Curve25519 ephemeral point")
        peer = X25519PublicKey.from_public_bytes(ephemeral_point[1:])
        return priv.exchange(peer)
    if key.curve in _NIST_CURVES:
        curve, flen = _NIST_CURVES[key.curve]
        priv = ec.derive_private_key(scalar_int, curve)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(curve, ephemeral_point)
        shared = priv.exchange(ec.ECDH(), peer)
        return shared.rjust(flen, b"\x00")
    raise OpenPGPFormatError(f"unsupported ECDH curve {key.curve}")


def _ecdh_oid_bytes(curve: str) -> bytes:
    for oid, name in _CURVES.items():
        if name == curve:
            return oid
    raise OpenPGPFormatError(f"unknown curve {curve}")


def _unwrap_ecdh(key: _SecretKey, esk: bytes) -> bytes:
    # ESK: MPI(ephemeral point) || 1-octet len || wrapped key
    _v, point_raw, off = _read_mpi(esk, 0)
    if off >= len(esk):
        # A well-formed MPI followed by nothing: the MPI reader is happy and
        # this index used to raise a raw IndexError, outside the taxonomy
        # (gitlab#196).
        raise OpenPGPFormatError("truncated ECDH session key: no wrapped-key length")
    wrapped_len = esk[off]
    wrapped = esk[off + 1 : off + 1 + wrapped_len]
    if len(wrapped) != wrapped_len:
        raise OpenPGPFormatError("truncated ECDH wrapped session key")

    shared = _ecdh_shared(key, point_raw)
    hash_id, sym_id = key.kdf
    if hash_id not in _S2K_HASHES:
        raise OpenPGPFormatError(f"unsupported ECDH KDF hash {hash_id}")
    if sym_id not in _CIPHERS:
        raise OpenPGPFormatError(f"unsupported ECDH KEK cipher {sym_id}")
    kek_len = _CIPHERS[sym_id][1]

    oid = _ecdh_oid_bytes(key.curve)
    fp = _key_fingerprint(key)
    param = (
        bytes([len(oid)])
        + oid
        + bytes([_PK_ECDH, 0x03, 0x01, hash_id, sym_id])
        + b"Anonymous Sender    "
        + fp
    )
    digest = hashlib.new(_S2K_HASHES[hash_id])
    digest.update(b"\x00\x00\x00\x01" + shared + param)
    kek = digest.digest()[:kek_len]

    try:
        m = aes_key_unwrap(kek, wrapped)
    except Exception:
        raise OpenPGPWrongPassphrase("ECDH key unwrap failed")
    # m is PKCS#5-padded: strip trailing pad bytes (value == count).
    if not m:
        raise OpenPGPFormatError("empty ECDH key-wrap result")
    pad = m[-1]
    if pad < 1 or pad > 8 or pad > len(m):
        raise OpenPGPFormatError("bad ECDH key-wrap padding")
    return m[:-pad]


def _key_fingerprint(key: _SecretKey) -> bytes:
    """The recipient (sub)key's v4 fingerprint (used in the ECDH KDF param)."""
    return key.fingerprint


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def _recover_session_key(keys, key_id, algo, esk):
    for key in keys:
        if key.key_id != key_id:
            continue
        if algo in _PK_RSA and key.algo in _PK_RSA:
            return _unwrap_rsa(key, esk)
        if algo == _PK_ECDH and key.algo == _PK_ECDH:
            return _unwrap_ecdh(key, esk)
    return None


def decrypt(data: bytes, *, secret_keys: List[_SecretKey]) -> bytes:
    """Decrypt a public-key OpenPGP message using the supplied secret keys.

    Raises:
        OpenPGPFormatError: Malformed or unsupported message.
        OpenPGPIntegrityError: MDC verification failed.
    """
    try:
        return _decrypt_impl(data, secret_keys=secret_keys)
    except OpenPGPError:
        raise
    except InvalidTag as exc:
        raise OpenPGPIntegrityError("OpenPGP AEAD authentication failed") from exc
    except (UnsupportedAlgorithm, InternalError) as exc:
        raise OpenPGPFormatError(f"unsupported OpenPGP algorithm for this build ({exc})") from exc
    except (IndexError, struct.error, ValueError, KeyError, TypeError, OverflowError) as exc:
        # Same taxonomy guarantee as the symmetric path (gitlab#196). This
        # side matters at least as much: a PUBLIC-key message is authored by
        # anyone holding the recipient's public key, so reaching this parser
        # with hostile input needs no shared secret at all.
        raise OpenPGPFormatError(f"malformed OpenPGP message ({type(exc).__name__})") from exc


def _decrypt_impl(data: bytes, *, secret_keys: List[_SecretKey]) -> bytes:
    """The body of :func:`decrypt`; see it for the contract."""
    if len(data) > _MAX_INPUT:
        raise OpenPGPFormatError("OpenPGP input too large")
    data = _maybe_dearmor(data)
    pkesks = []
    seipd = None
    for tag, body in _iter_packets(data):
        if tag == 1:
            pkesks.append(body)
        elif tag == 18:
            seipd = body
        elif tag == 9:
            raise OpenPGPFormatError("refusing unauthenticated OpenPGP data (SED)")
    if not pkesks:
        raise OpenPGPFormatError("no Public-Key Encrypted Session Key packet")
    if seipd is None:
        raise OpenPGPFormatError("no integrity-protected encrypted data packet")

    session = None
    for esk_body in pkesks:
        if len(esk_body) < 10 or esk_body[0] != 3:
            continue  # PKESK v3 only
        key_id = bytes(esk_body[1:9])
        algo = esk_body[9]
        m = _recover_session_key(secret_keys, key_id, algo, esk_body[10:])
        if m is not None:
            session = m
            break
    if session is None:
        raise OpenPGPNoMatchingKey("none of the supplied keys match this message's recipient(s)")

    # session = sym_algo(1) || session_key || 2-byte checksum
    sym = session[0]
    if sym not in _CIPHERS:
        raise OpenPGPFormatError(f"unsupported session cipher {sym}")
    key_len = _CIPHERS[sym][1]
    session_key = session[1 : 1 + key_len]
    checksum = session[1 + key_len : 3 + key_len]
    if len(checksum) == 2:
        if (sum(session_key) % 65536) != int.from_bytes(checksum, "big"):
            raise OpenPGPWrongPassphrase("session-key checksum mismatch")

    inner = _decrypt_seipd_v1(seipd, sym, session_key)
    return _extract_plaintext(inner)
