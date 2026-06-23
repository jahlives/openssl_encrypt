#!/usr/bin/env python3
"""
Read-only decryption of passphrase-based OpenPGP messages (``gpg -c``).

Implemented directly on ``cryptography`` (pyca) — no GnuPG runtime dependency.
Scope (phase 2): the *symmetric* (passphrase) path of RFC 4880 / RFC 9580:

- ASCII armor (``-----BEGIN PGP MESSAGE-----``) and binary input.
- Symmetric-Key Encrypted Session Key packet (SKESK, tag 3) with String-to-Key
  (S2K) types simple/salted/iterated-salted.
- Symmetrically Encrypted Integrity Protected Data packet (SEIPD v1, tag 18):
  CFB + SHA-1 MDC. The legacy unauthenticated Symmetrically Encrypted Data
  packet (SED, tag 9) is REFUSED (EFAIL / no integrity).
- Inner compressed (tag 8: ZIP/ZLIB/BZIP2, bounded) and literal (tag 11) data.

Supported ciphers: 3DES, CAST5, AES-128/192/256, Camellia-128/192/256.
Supported S2K hashes: SHA-1/224/256/384/512. Anything else fails closed.

Security model — UNTRUSTED input: integrity (the MDC) is verified before any
plaintext is returned; decompression output is bounded; partial/again-bounded
packet lengths are capped; unsupported algorithms raise rather than guess.

NOTE: OpenPGP public-key messages and SEIPD v2 (AEAD/OCB) are out of scope here.
"""

import base64
import hashlib
import struct
import zlib
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

# 3DES/CAST5/CFB are legacy; prefer the `decrepit` location (cryptography >=44)
# and fall back to `primitives` on older releases.
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import CAST5, TripleDES
except ImportError:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.algorithms import CAST5, TripleDES
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.modes import CFB

# --- limits (untrusted input) ---
_MAX_INPUT = 256 * 1024 * 1024
_MAX_DECOMPRESS = 256 * 1024 * 1024
_MAX_PACKET = 256 * 1024 * 1024

# OpenPGP symmetric cipher algorithms (RFC 4880 §9.2): (pyca algo, key_len, block_len)
_CIPHERS = {
    2: ("3des", 24, 8),
    3: ("cast5", 16, 8),
    7: ("aes", 16, 16),
    8: ("aes", 24, 16),
    9: ("aes", 32, 16),
    11: ("camellia", 16, 16),
    12: ("camellia", 24, 16),
    13: ("camellia", 32, 16),
}

# S2K hash algorithms (RFC 4880 §9.4)
_S2K_HASHES = {2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}


class OpenPGPError(Exception):
    """Base class for OpenPGP decryption errors."""


class OpenPGPFormatError(OpenPGPError):
    """Malformed or unsupported OpenPGP message."""


class OpenPGPIntegrityError(OpenPGPError):
    """MDC / integrity verification failed (tamper or wrong passphrase)."""


class OpenPGPWrongPassphrase(OpenPGPError):
    """The passphrase did not decrypt the message (quick-check failure)."""


# --------------------------------------------------------------------------- #
# Armor
# --------------------------------------------------------------------------- #

_ARMOR_BEGIN = b"-----BEGIN PGP MESSAGE-----"
_ARMOR_END = b"-----END PGP MESSAGE-----"
# Generic prefixes so any PGP armor (MESSAGE, PRIVATE KEY BLOCK, …) de-armors.
_ARMOR_BEGIN_PREFIX = b"-----BEGIN PGP "
_ARMOR_END_PREFIX = b"-----END PGP "


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def _maybe_dearmor(data: bytes) -> bytes:
    stripped = data.lstrip()
    if not stripped.startswith(_ARMOR_BEGIN_PREFIX):
        return data
    lines = stripped.split(b"\n")
    body_lines = []
    crc_line = None
    in_body = False
    blank_seen = False
    for line in lines:
        s = line.rstrip(b"\r")
        if s.startswith(_ARMOR_BEGIN_PREFIX):
            in_body = True
            continue
        if s.startswith(_ARMOR_END_PREFIX):
            break
        if not in_body:
            continue
        if not blank_seen:
            # Armor headers ("Version: …") end at the first blank line.
            if s == b"":
                blank_seen = True
            continue
        if s.startswith(b"="):  # CRC line "=XXXX"
            crc_line = s[1:5]
            continue
        body_lines.append(s)
    try:
        payload = base64.b64decode(b"".join(body_lines), validate=True)
    except Exception as exc:
        raise OpenPGPFormatError(f"invalid base64 in PGP armor: {exc}")
    if crc_line is not None:
        want = base64.b64encode(_crc24(payload).to_bytes(3, "big"))[:4]
        if want != crc_line:
            raise OpenPGPFormatError("PGP armor CRC-24 mismatch")
    return payload


# --------------------------------------------------------------------------- #
# Packet framing (RFC 4880 §4.2)
# --------------------------------------------------------------------------- #


def _read_packet(data: bytes, off: int) -> Tuple[int, bytes, int]:
    """Read one packet starting at ``off``; return (tag, body, next_off)."""
    if off >= len(data):
        raise OpenPGPFormatError("unexpected end of OpenPGP data")
    ctb = data[off]
    if not (ctb & 0x80):
        raise OpenPGPFormatError("invalid OpenPGP packet tag byte")
    off += 1
    new_format = bool(ctb & 0x40)

    if new_format:
        tag = ctb & 0x3F
        body = bytearray()
        partial = True
        while partial:
            if off >= len(data):
                raise OpenPGPFormatError("truncated packet length")
            n = data[off]
            off += 1
            if n < 192:
                length = n
                partial = False
            elif n < 224:
                length = ((n - 192) << 8) + data[off] + 192
                off += 1
                partial = False
            elif n == 255:
                length = struct.unpack(">I", data[off : off + 4])[0]
                off += 4
                partial = False
            else:
                length = 1 << (n & 0x1F)  # partial body length
            if length > _MAX_PACKET or len(body) + length > _MAX_PACKET:
                raise OpenPGPFormatError("OpenPGP packet too large")
            chunk = data[off : off + length]
            if len(chunk) != length:
                raise OpenPGPFormatError("truncated OpenPGP packet body")
            body += chunk
            off += length
        return tag, bytes(body), off

    # Old format
    tag = (ctb >> 2) & 0x0F
    ltype = ctb & 0x03
    if ltype == 0:
        length = data[off]
        off += 1
    elif ltype == 1:
        length = struct.unpack(">H", data[off : off + 2])[0]
        off += 2
    elif ltype == 2:
        length = struct.unpack(">I", data[off : off + 4])[0]
        off += 4
    else:
        length = len(data) - off  # indeterminate: to end
    if length > _MAX_PACKET:
        raise OpenPGPFormatError("OpenPGP packet too large")
    body = data[off : off + length]
    if len(body) != length:
        raise OpenPGPFormatError("truncated OpenPGP packet body")
    return tag, body, off + length


def _iter_packets(data: bytes):
    off = 0
    while off < len(data):
        tag, body, off = _read_packet(data, off)
        yield tag, body


# --------------------------------------------------------------------------- #
# String-to-Key (RFC 4880 §3.7)
# --------------------------------------------------------------------------- #


def _s2k_derive(s2k: bytes, passphrase: bytes, key_len: int) -> Tuple[bytes, int]:
    """Derive a key of ``key_len`` bytes; return (key, bytes_consumed)."""
    if not s2k:
        raise OpenPGPFormatError("missing S2K specifier")
    s2k_type = s2k[0]
    if s2k_type == 0:
        hash_id = s2k[1]
        salt = b""
        count = None
        consumed = 2
    elif s2k_type == 1:
        hash_id = s2k[1]
        salt = s2k[2:10]
        count = None
        consumed = 10
    elif s2k_type == 3:
        hash_id = s2k[1]
        salt = s2k[2:10]
        coded = s2k[10]
        count = (16 + (coded & 15)) << ((coded >> 4) + 6)
        consumed = 11
    else:
        raise OpenPGPFormatError(f"unsupported S2K type {s2k_type}")

    if hash_id not in _S2K_HASHES:
        raise OpenPGPFormatError(f"unsupported S2K hash algorithm {hash_id}")
    hash_name = _S2K_HASHES[hash_id]

    base = salt + passphrase
    out = bytearray()
    ctx_index = 0
    while len(out) < key_len:
        h = hashlib.new(hash_name)
        h.update(b"\x00" * ctx_index)  # preload zero bytes for extra contexts
        if count is None:
            h.update(base)  # simple/salted: hash once
        else:
            total = max(count, 0)
            if total < len(base):
                total = len(base)
            # Feed exactly `total` bytes of the cyclically repeated `base`.
            full, rem = divmod(total, len(base)) if base else (0, 0)
            for _ in range(full):
                h.update(base)
            if rem:
                h.update(base[:rem])
        out += h.digest()
        ctx_index += 1
    return bytes(out[:key_len]), consumed


# --------------------------------------------------------------------------- #
# Cipher helpers
# --------------------------------------------------------------------------- #


def _cipher_algo(cipher_id: int, key: bytes):
    name, _klen, _blk = _CIPHERS[cipher_id]
    if name == "aes":
        return algorithms.AES(key)
    if name == "3des":
        return TripleDES(key)
    if name == "cast5":
        return CAST5(key)
    if name == "camellia":
        return algorithms.Camellia(key)
    raise OpenPGPFormatError(f"unsupported cipher {cipher_id}")


# --------------------------------------------------------------------------- #
# SEIPD v1 (tag 18): CFB + SHA-1 MDC
# --------------------------------------------------------------------------- #


def _decrypt_seipd_v1(body: bytes, cipher_id: int, key: bytes) -> bytes:
    if not body or body[0] != 1:
        raise OpenPGPFormatError("unsupported SEIPD version")
    if cipher_id not in _CIPHERS:
        raise OpenPGPFormatError(f"unsupported cipher {cipher_id}")
    _name, _klen, block = _CIPHERS[cipher_id]
    ct = body[1:]

    decryptor = Cipher(_cipher_algo(cipher_id, key), CFB(b"\x00" * block)).decryptor()
    plain = decryptor.update(ct) + decryptor.finalize()

    if len(plain) < block + 2 + 22:
        raise OpenPGPFormatError("SEIPD payload too short")
    # Quick check: last 2 of the random prefix repeat as the next 2 bytes.
    if plain[block - 2 : block] != plain[block : block + 2]:
        raise OpenPGPWrongPassphrase("OpenPGP quick-check failed (wrong passphrase?)")

    # MDC: trailing 22 bytes = 0xD3 0x14 + SHA-1(everything up to and incl 0xD3 0x14).
    mdc_packet = plain[-22:]
    if mdc_packet[0] != 0xD3 or mdc_packet[1] != 0x14:
        raise OpenPGPIntegrityError("malformed or missing MDC packet")
    digest = hashlib.sha1(plain[:-20]).digest()
    if not _ct_eq(digest, mdc_packet[2:]):
        raise OpenPGPIntegrityError("MDC verification failed (tampered ciphertext)")

    return plain[block + 2 : -22]


def _ct_eq(a: bytes, b: bytes) -> bool:
    import hmac

    return hmac.compare_digest(a, b)


# --------------------------------------------------------------------------- #
# Inner packets (compressed / literal)
# --------------------------------------------------------------------------- #


def _decompress(body: bytes) -> bytes:
    algo = body[0]
    data = body[1:]
    try:
        if algo == 0:
            return data
        if algo == 1:  # ZIP: raw DEFLATE
            return _bounded(zlib.decompressobj(-15), data)
        if algo == 2:  # ZLIB
            return _bounded(zlib.decompressobj(15), data)
        if algo == 3:  # BZIP2
            import bz2

            return _bounded(bz2.BZ2Decompressor(), data)
    except OpenPGPError:
        raise
    except Exception as exc:
        raise OpenPGPFormatError(f"decompression failed: {exc}")
    raise OpenPGPFormatError(f"unsupported compression algorithm {algo}")


def _bounded(decomp, data: bytes) -> bytes:
    out = decomp.decompress(data, _MAX_DECOMPRESS + 1)
    if len(out) > _MAX_DECOMPRESS:
        raise OpenPGPFormatError("decompressed data exceeds the size bound")
    return out


def _extract_literal(body: bytes) -> bytes:
    if len(body) < 2:
        raise OpenPGPFormatError("malformed literal data packet")
    fname_len = body[1]
    pos = 2 + fname_len + 4  # skip format, filename, 4-byte date
    if pos > len(body):
        raise OpenPGPFormatError("malformed literal data packet header")
    return body[pos:]


def _extract_plaintext(inner: bytes) -> bytes:
    """From decrypted SEIPD content, return the literal data (handling one
    optional layer of compression)."""
    tag, body, _ = _read_packet(inner, 0)
    if tag == 8:  # compressed
        decompressed = _decompress(body)
        tag, body, _ = _read_packet(decompressed, 0)
    if tag != 11:
        raise OpenPGPFormatError(f"expected literal data, got packet tag {tag}")
    return _extract_literal(body)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def is_openpgp_file(data: bytes) -> bool:
    """Heuristic: armored PGP message, or a binary packet stream starting with
    an SKESK (tag 3) packet."""
    s = data.lstrip()
    if s.startswith(_ARMOR_BEGIN):
        return True
    if not data:
        return False
    ctb = data[0]
    if not (ctb & 0x80):
        return False
    tag = (ctb & 0x3F) if (ctb & 0x40) else ((ctb >> 2) & 0x0F)
    return tag == 3  # Symmetric-Key Encrypted Session Key


def decrypt(data: bytes, *, passphrase: str) -> bytes:
    """Decrypt a passphrase-based (``gpg -c``) OpenPGP message.

    Args:
        data: The OpenPGP message (binary or ASCII-armored).
        passphrase: The symmetric passphrase.

    Raises:
        OpenPGPFormatError: Malformed or unsupported message.
        OpenPGPIntegrityError: MDC verification failed.
        OpenPGPWrongPassphrase: The passphrase did not decrypt the message.
    """
    if len(data) > _MAX_INPUT:
        raise OpenPGPFormatError("OpenPGP input too large")
    data = _maybe_dearmor(data)
    pw = passphrase.encode("utf-8")

    skesk = None
    seipd = None
    for tag, body in _iter_packets(data):
        if tag == 3 and skesk is None:
            skesk = body
        elif tag == 18:
            seipd = body
        elif tag == 9:
            raise OpenPGPFormatError(
                "refusing unauthenticated OpenPGP data (SED/tag 9, no integrity " "protection)"
            )

    if skesk is None:
        raise OpenPGPFormatError(
            "no Symmetric-Key Encrypted Session Key packet (not a gpg -c message?)"
        )
    if seipd is None:
        raise OpenPGPFormatError("no integrity-protected encrypted data packet found")

    # Parse SKESK (tag 3): version, cipher, S2K [, encrypted session key].
    if len(skesk) < 2 or skesk[0] != 4:
        raise OpenPGPFormatError("unsupported SKESK version")
    cipher_id = skesk[1]
    if cipher_id not in _CIPHERS:
        raise OpenPGPFormatError(f"unsupported cipher algorithm {cipher_id}")
    _name, key_len, block = _CIPHERS[cipher_id]
    s2k_key, consumed = _s2k_derive(skesk[2:], pw, key_len)
    enc_session_key = skesk[2 + consumed :]

    if enc_session_key:
        # Optional: session key wrapped under the S2K key (CFB, zero IV).
        dec = Cipher(_cipher_algo(cipher_id, s2k_key), CFB(b"\x00" * block)).decryptor()
        unwrapped = dec.update(enc_session_key) + dec.finalize()
        if not unwrapped:
            raise OpenPGPFormatError("empty wrapped session key")
        session_cipher = unwrapped[0]
        session_key = unwrapped[1:]
        if session_cipher not in _CIPHERS:
            raise OpenPGPFormatError(f"unsupported session cipher {session_cipher}")
    else:
        # gpg -c: the S2K key IS the session key.
        session_cipher = cipher_id
        session_key = s2k_key

    inner = _decrypt_seipd_v1(seipd, session_cipher, session_key)
    return _extract_plaintext(inner)
