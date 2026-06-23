#!/usr/bin/env python3
"""
Read-only decryption of `age` (age-encryption.org/v1) files.

Implemented directly on ``cryptography`` (pyca) primitives — no `age`/`rage`
dependency. Supports the two standard recipient/unlock modes:

- **X25519** recipients: unlocked with the user's age secret key
  (``AGE-SECRET-KEY-1…``).
- **scrypt** passphrase files (``age -p``): unlocked with a passphrase.

Security model — the input is UNTRUSTED:

- The header MAC (HMAC-SHA256 keyed by a value derived from the file key) is
  verified before any payload byte is returned; a bad MAC raises
  :class:`AgeIntegrityError`.
- Each payload chunk is ChaCha20-Poly1305 authenticated; a forged/truncated
  payload fails the AEAD tag.
- A ``scrypt`` stanza must be the file's ONLY stanza (mirrors age, which refuses
  to mix passphrase and key recipients), and its work factor is capped to bound
  a malicious file's CPU cost.
- Only the spec's algorithms are accepted; anything else fails closed.

Spec: https://age-encryption.org/v1 and the C2SP age specification.

NOTE: the `age` binary was unavailable in this environment, so the test suite
exercises this code via an independent in-test encoder (round-trip) plus RFC
primitive KATs and negative tests, rather than vectors from the reference
implementation. Validate against real `age` output before relying on it.
"""

import hashlib
import hmac
import io
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# age constants
AGE_V1_LINE = b"age-encryption.org/v1"
ARMOR_BEGIN = b"-----BEGIN AGE ENCRYPTED FILE-----"
ARMOR_END = b"-----END AGE ENCRYPTED FILE-----"

_FILE_KEY_SIZE = 16  # age FileKey is 128-bit
_CHUNK_SIZE = 64 * 1024  # plaintext chunk size in the STREAM payload
_TAG_SIZE = 16
_PAYLOAD_NONCE_SIZE = 16

# HKDF info / labels (exact strings from the spec)
_X25519_INFO = b"age-encryption.org/v1/X25519"
_SCRYPT_LABEL = b"age-encryption.org/v1/scrypt"
_HEADER_INFO = b"header"
_PAYLOAD_INFO = b"payload"

# Bound scrypt cost so a hostile file cannot request an absurd work factor.
MAX_SCRYPT_WORK_FACTOR = 22  # N = 2**22 ~ 4M; well above real-world use

# Safety bound on a single armored/secret-key file we will read.
_MAX_SECRET_KEY_FILE = 1 * 1024 * 1024


class AgeError(Exception):
    """Base class for age decryption errors."""


class AgeFormatError(AgeError):
    """The input is not a well-formed age file (or uses an unsupported mode)."""


class AgeIntegrityError(AgeError):
    """Header MAC or payload authentication failed (tamper/corruption)."""


class NoMatchingIdentityError(AgeError):
    """None of the supplied identities/passphrase could unwrap the file key."""


# --------------------------------------------------------------------------- #
# Bech32 (BIP-0173) — age secret keys are bech32-encoded
# --------------------------------------------------------------------------- #

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _bech32_polymod(values: List[int]) -> int:
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= _BECH32_GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_decode(s: str) -> tuple:
    """Decode a bech32 string into (hrp, 5-bit data values), verifying checksum."""
    if any(ord(c) < 33 or ord(c) > 126 for c in s):
        raise AgeFormatError("invalid character in bech32 string")
    if s.lower() != s and s.upper() != s:
        raise AgeFormatError("mixed-case bech32 string")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise AgeFormatError("malformed bech32 string")
    hrp = s[:pos]
    data = []
    for c in s[pos + 1 :]:
        if c not in _BECH32_CHARSET:
            raise AgeFormatError("invalid bech32 data character")
        data.append(_BECH32_CHARSET.index(c))
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise AgeFormatError("bad bech32 checksum")
    return hrp, data[:-6]


def _convert_bits(data: List[int], frombits: int, tobits: int, pad: bool) -> bytes:
    acc = 0
    bits = 0
    out = bytearray()
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise AgeFormatError("invalid padding in bech32 data")
    return bytes(out)


def decode_age_secret_key(s: str) -> bytes:
    """Decode an ``AGE-SECRET-KEY-1…`` string into the 32-byte X25519 scalar."""
    s = s.strip()
    hrp, data = _bech32_decode(s)
    if hrp != "age-secret-key-":
        raise AgeFormatError(f"not an age secret key (hrp={hrp!r})")
    scalar = _convert_bits(data, 5, 8, False)
    if len(scalar) != 32:
        raise AgeFormatError("age secret key is not 32 bytes")
    return scalar


def parse_identities_file(path: str) -> List[bytes]:
    """Parse an age identities file, returning a list of 32-byte X25519 scalars.

    Blank lines and ``#`` comments are ignored, matching age's keys.txt format.
    """
    with open(path, "rb") as f:
        raw = f.read(_MAX_SECRET_KEY_FILE + 1)
    if len(raw) > _MAX_SECRET_KEY_FILE:
        raise AgeFormatError("age identities file too large")
    scalars = []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("AGE-SECRET-KEY-1"):
            scalars.append(decode_age_secret_key(line))
    if not scalars:
        raise AgeFormatError("no age secret keys found in identities file")
    return scalars


# --------------------------------------------------------------------------- #
# Base64 (age uses RawStdEncoding — standard alphabet, NO padding)
# --------------------------------------------------------------------------- #


def _b64_nopad_decode(s: bytes) -> bytes:
    import base64

    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + b"=" * pad, validate=True)
    except Exception as exc:
        raise AgeFormatError(f"invalid base64 in age header: {exc}")


# --------------------------------------------------------------------------- #
# Header parsing
# --------------------------------------------------------------------------- #


class _Stanza:
    __slots__ = ("args", "body")

    def __init__(self, args: List[bytes], body: bytes):
        self.args = args  # e.g. [b"X25519", b"<b64 share>"]
        self.body = body  # decoded stanza body bytes


def _parse_header(data: bytes):
    """Parse an age header.

    Returns (stanzas, mac, mac_input, payload_offset). ``mac_input`` is the exact
    byte range the header MAC is computed over (through the ``---`` marker).
    """
    if not data.startswith(AGE_V1_LINE + b"\n"):
        raise AgeFormatError("not an age file (missing v1 intro line)")

    lines = data.split(b"\n")
    stanzas: List[_Stanza] = []
    i = 1  # line 0 is the intro line
    mac_line_index = None
    while i < len(lines):
        line = lines[i]
        if line.startswith(b"---"):
            mac_line_index = i
            break
        if not line.startswith(b"-> "):
            raise AgeFormatError("malformed age header (expected a stanza)")
        args = line[3:].split(b" ")
        if not args or not all(args):
            raise AgeFormatError("malformed stanza arguments")
        # Body: subsequent base64 lines until a line shorter than 64 chars.
        body_b64 = b""
        i += 1
        while True:
            if i >= len(lines):
                raise AgeFormatError("unterminated stanza body")
            bline = lines[i]
            body_b64 += bline
            i += 1
            if len(bline) < 64:
                break
        stanzas.append(_Stanza(args, _b64_nopad_decode(body_b64)))

    if mac_line_index is None:
        raise AgeFormatError("age header has no MAC line")

    mac_line = lines[mac_line_index]
    if not mac_line.startswith(b"--- "):
        raise AgeFormatError("malformed age MAC line")
    mac = _b64_nopad_decode(mac_line[4:])

    # The MAC covers the header text up to and including the literal "---"
    # (no trailing space, no MAC, no newline).
    prefix = b"\n".join(lines[:mac_line_index]) + b"\n---"
    payload_offset = len(prefix) + (len(mac_line) - 3) + 1  # +1 for trailing \n
    return stanzas, mac, prefix, payload_offset


# --------------------------------------------------------------------------- #
# Stanza unwrapping
# --------------------------------------------------------------------------- #


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _aead_unwrap(key: bytes, body: bytes) -> Optional[bytes]:
    """ChaCha20-Poly1305 decrypt a stanza body (nonce = 12 zero bytes)."""
    try:
        return ChaCha20Poly1305(key).decrypt(b"\x00" * 12, body, None)
    except Exception:
        return None


def _unwrap_x25519(stanza: _Stanza, scalars: List[bytes]) -> Optional[bytes]:
    if len(stanza.args) != 2:
        raise AgeFormatError("X25519 stanza must have exactly one argument")
    ephemeral_share = _b64_nopad_decode(stanza.args[1])
    if len(ephemeral_share) != 32:
        raise AgeFormatError("X25519 ephemeral share is not 32 bytes")
    for scalar in scalars:
        priv = X25519PrivateKey.from_private_bytes(scalar)
        try:
            shared = priv.exchange(X25519PublicKey.from_public_bytes(ephemeral_share))
        except Exception:
            continue
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        our_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        salt = ephemeral_share + our_pub
        key = _hkdf(shared, salt, _X25519_INFO)
        file_key = _aead_unwrap(key, stanza.body)
        if file_key is not None and len(file_key) == _FILE_KEY_SIZE:
            return file_key
    return None


def _unwrap_scrypt(stanza: _Stanza, passphrase: str) -> Optional[bytes]:
    if len(stanza.args) != 3:
        raise AgeFormatError("scrypt stanza must have salt and work factor")
    salt = _b64_nopad_decode(stanza.args[1])
    if len(salt) != 16:
        raise AgeFormatError("scrypt salt is not 16 bytes")
    try:
        work_factor = int(stanza.args[2])
    except ValueError:
        raise AgeFormatError("scrypt work factor is not an integer")
    if work_factor < 1 or work_factor > MAX_SCRYPT_WORK_FACTOR:
        raise AgeFormatError(
            f"scrypt work factor {work_factor} out of allowed range "
            f"(1..{MAX_SCRYPT_WORK_FACTOR})"
        )
    derived = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=_SCRYPT_LABEL + salt,
        n=1 << work_factor,
        r=8,
        p=1,
        dklen=32,
        maxmem=0x7FFFFFFF,
    )
    file_key = _aead_unwrap(derived, stanza.body)
    if file_key is not None and len(file_key) == _FILE_KEY_SIZE:
        return file_key
    return None


# --------------------------------------------------------------------------- #
# Payload (STREAM: ChaCha20-Poly1305, 64 KiB chunks)
# --------------------------------------------------------------------------- #


def _decrypt_payload(file_key: bytes, payload: bytes) -> bytes:
    if len(payload) < _PAYLOAD_NONCE_SIZE:
        raise AgeFormatError("age payload too short (missing nonce)")
    nonce = payload[:_PAYLOAD_NONCE_SIZE]
    body = payload[_PAYLOAD_NONCE_SIZE:]

    stream_key = _hkdf(file_key, nonce, _PAYLOAD_INFO)
    aead = ChaCha20Poly1305(stream_key)

    out = io.BytesIO()
    enc_chunk = _CHUNK_SIZE + _TAG_SIZE
    counter = 0
    offset = 0
    n = len(body)
    if n == 0:
        raise AgeFormatError("age payload has no chunks")
    while True:
        remaining = n - offset
        chunk = body[offset : offset + enc_chunk]
        is_last = remaining <= enc_chunk
        if len(chunk) < _TAG_SIZE:
            raise AgeFormatError("truncated age payload chunk")
        if not is_last and len(chunk) != enc_chunk:
            raise AgeFormatError("short non-final age payload chunk")
        chunk_nonce = counter.to_bytes(11, "big") + (b"\x01" if is_last else b"\x00")
        try:
            pt = aead.decrypt(chunk_nonce, chunk, None)
        except Exception:
            raise AgeIntegrityError("age payload authentication failed")
        # A zero-length chunk is only valid as the sole/first (empty file).
        if len(pt) == 0 and not (is_last and counter == 0):
            raise AgeFormatError("invalid empty age payload chunk")
        out.write(pt)
        offset += len(chunk)
        counter += 1
        if is_last:
            break
    return out.getvalue()


# --------------------------------------------------------------------------- #
# Armor
# --------------------------------------------------------------------------- #


def _maybe_dearmor(data: bytes) -> bytes:
    stripped = data.lstrip()
    if not stripped.startswith(ARMOR_BEGIN):
        return data
    import base64

    lines = stripped.split(b"\n")
    body = []
    started = False
    for line in lines:
        line = line.strip()
        if line.startswith(ARMOR_BEGIN):
            started = True
            continue
        if line.startswith(ARMOR_END):
            break
        if started:
            body.append(line)
    try:
        return base64.b64decode(b"".join(body), validate=True)
    except Exception as exc:
        raise AgeFormatError(f"invalid base64 in age armor: {exc}")


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def is_age_file(data: bytes) -> bool:
    """Return True if ``data`` looks like an age file (binary or armored)."""
    stripped = data.lstrip()
    return stripped.startswith(AGE_V1_LINE) or stripped.startswith(ARMOR_BEGIN)


def decrypt(
    data: bytes,
    *,
    identities: Optional[List[bytes]] = None,
    passphrase: Optional[str] = None,
) -> bytes:
    """Decrypt an age file and return its plaintext.

    Args:
        data: The full age file bytes (binary or ASCII-armored).
        identities: X25519 secret scalars (32 bytes each) to try.
        passphrase: Passphrase for a scrypt (``age -p``) file.

    Raises:
        AgeFormatError: Malformed or unsupported file.
        AgeIntegrityError: Header MAC or payload authentication failed.
        NoMatchingIdentityError: No identity/passphrase unwrapped the file key.
    """
    identities = identities or []
    data = _maybe_dearmor(data)
    stanzas, mac, mac_input, payload_offset = _parse_header(data)

    if not stanzas:
        raise AgeFormatError("age header has no recipient stanzas")

    types = [s.args[0] for s in stanzas]
    has_scrypt = b"scrypt" in types
    if has_scrypt and len(stanzas) != 1:
        # age refuses to mix a passphrase recipient with any other.
        raise AgeFormatError("scrypt stanza must be the only stanza")

    # Try to recover the file key.
    file_key = None
    for stanza in stanzas:
        stype = stanza.args[0]
        if stype == b"X25519":
            if identities:
                file_key = _unwrap_x25519(stanza, identities)
        elif stype == b"scrypt":
            if passphrase is not None:
                file_key = _unwrap_scrypt(stanza, passphrase)
        # Unknown stanza types are skipped (a file may list several recipients).
        if file_key is not None:
            break

    if file_key is None:
        raise NoMatchingIdentityError("no matching age identity or passphrase for this file")

    # Verify the header MAC before trusting/returning any payload.
    hmac_key = _hkdf(file_key, b"", _HEADER_INFO)
    expected = hmac.new(hmac_key, mac_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise AgeIntegrityError("age header MAC verification failed")

    return _decrypt_payload(file_key, data[payload_offset:])
