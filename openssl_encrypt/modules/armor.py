#!/usr/bin/env python3
"""
ASCII-armor transport codec for encrypted files.

ASCII armor wraps the binary encrypted-file output in a PEM-style Base64
envelope so that ciphertext survives email, chat, YAML and copy-paste. It is
a *pure transport wrapper*: ``armor`` is fully reversible and
``dearmor(armor(x)) == x`` for every byte string ``x``.

Format (OpenPGP-inspired)::

    -----BEGIN OPENSSL-ENCRYPT MESSAGE-----
    <base64 of the whole encrypted-file blob, wrapped at 64 chars>
    ...
    =Qh8d                         # CRC-24 checksum of the decoded payload
    -----END OPENSSL-ENCRYPT MESSAGE-----

Security notes:
- The CRC-24 line is **integrity-of-transport only** (paste truncation / typo
  detection). It is NOT a cryptographic MAC and provides no authenticity; the
  real integrity guarantee comes from the AEAD inside the encrypted payload.
- ``dearmor`` treats its input as untrusted: it validates the Base64 alphabet
  and verifies the CRC before returning, and raises :class:`ArmorError` on any
  malformed or truncated input rather than returning partial data.
"""

import base64
import binascii
from typing import Union

# Envelope markers. Kept stable for forward/backward compatibility.
ARMOR_BEGIN = b"-----BEGIN OPENSSL-ENCRYPT MESSAGE-----"
ARMOR_END = b"-----END OPENSSL-ENCRYPT MESSAGE-----"

# Base64 characters per body line (PEM convention).
LINE_WIDTH = 64

# OpenPGP CRC-24 parameters (RFC 4880 §6.1).
_CRC24_INIT = 0xB704CE
_CRC24_POLY = 0x1864CFB


class ArmorError(ValueError):
    """Raised when armored input is malformed, truncated or corrupted."""


def _crc24(data: bytes) -> int:
    """Compute the OpenPGP CRC-24 of ``data``.

    Args:
        data: The bytes to checksum.

    Returns:
        The 24-bit CRC as an ``int`` in ``[0, 2**24)``.
    """
    crc = _CRC24_INIT
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= _CRC24_POLY
    return crc & 0xFFFFFF


def _crc24_line(data: bytes) -> bytes:
    """Build the ``=XXXX`` CRC checksum line for ``data``."""
    crc = _crc24(data)
    packed = bytes(((crc >> 16) & 0xFF, (crc >> 8) & 0xFF, crc & 0xFF))
    return b"=" + base64.b64encode(packed)


def _as_bytes(data: Union[bytes, bytearray, str]) -> bytes:
    """Coerce text/bytes input to ``bytes`` (ASCII for text)."""
    if isinstance(data, str):
        return data.encode("ascii", errors="strict")
    return bytes(data)


def armor(data: Union[bytes, bytearray]) -> bytes:
    """Wrap binary ``data`` in an ASCII-armored PEM envelope.

    Args:
        data: The raw encrypted-file bytes to encode.

    Returns:
        The armored representation as ``bytes`` (ASCII, newline-terminated).
    """
    payload = bytes(data)
    encoded = base64.b64encode(payload)

    lines = [ARMOR_BEGIN]
    for i in range(0, len(encoded), LINE_WIDTH):
        lines.append(encoded[i : i + LINE_WIDTH])
    lines.append(_crc24_line(payload))
    lines.append(ARMOR_END)
    return b"\n".join(lines) + b"\n"


def is_armored(data: Union[bytes, bytearray, str]) -> bool:
    """Return ``True`` if ``data`` looks like an armored message.

    Detection is based solely on the presence of the BEGIN marker at the start
    of the (whitespace-stripped) content, so it is cheap enough to run on a
    short prefix of a file.

    Args:
        data: Candidate bytes or text.

    Returns:
        ``True`` if the BEGIN marker is present at the start.
    """
    try:
        raw = _as_bytes(data)
    except UnicodeEncodeError:
        return False
    return raw.lstrip().startswith(ARMOR_BEGIN)


def dearmor(data: Union[bytes, bytearray, str]) -> bytes:
    """Decode an ASCII-armored message back to its original bytes.

    Args:
        data: The armored message (bytes or text).

    Returns:
        The original binary payload.

    Raises:
        ArmorError: If the markers are missing, the Base64 body is invalid, or
            the CRC-24 checksum does not match (truncation/corruption).
    """
    try:
        raw = _as_bytes(data)
    except UnicodeEncodeError as exc:
        raise ArmorError("armored input is not valid ASCII") from exc

    # Normalise line endings and split into logical lines.
    lines = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    stripped = [ln.strip() for ln in lines]

    # Locate the envelope markers.
    try:
        begin = stripped.index(ARMOR_BEGIN)
    except ValueError:
        raise ArmorError("missing BEGIN marker: input is not ASCII-armored")
    try:
        end = stripped.index(ARMOR_END, begin + 1)
    except ValueError:
        raise ArmorError("missing END marker: armored input is truncated")

    body_lines = []
    crc_expected = None
    seen_blank = False
    in_headers = False
    for ln in stripped[begin + 1 : end]:
        if not ln:
            # A blank line terminates an optional header block (OpenPGP style).
            seen_blank = True
            in_headers = False
            continue
        if ln.startswith(b"=") and len(ln) == 5:
            crc_expected = ln[1:]
            continue
        # Optional header lines ("Key: value") may precede the first blank line.
        if not seen_blank and not body_lines and b":" in ln and b" " in ln:
            in_headers = True
            continue
        if in_headers:
            continue
        body_lines.append(ln)

    try:
        payload = base64.b64decode(b"".join(body_lines), validate=True)
    except (ValueError, binascii.Error) as exc:  # binascii.Error is a ValueError subclass
        raise ArmorError(f"invalid Base64 in armored body: {exc}")

    if crc_expected is not None:
        if _crc24_line(payload)[1:] != crc_expected:
            raise ArmorError("CRC-24 checksum mismatch: armored input is corrupted or truncated")

    return payload


# --------------------------------------------------------------------------- #
# File-level convenience helpers used by the CLI wiring.
# --------------------------------------------------------------------------- #

# Bytes to read when sniffing a file for the armor marker.
_SNIFF_BYTES = 256


def is_armored_file(path: str) -> bool:
    """Return ``True`` if the file at ``path`` begins with the armor marker.

    Reads only a short prefix; safe to call on large files.

    Args:
        path: Filesystem path to inspect.

    Returns:
        ``True`` if the file is ASCII-armored.
    """
    try:
        with open(path, "rb") as f:
            prefix = f.read(_SNIFF_BYTES)
    except OSError:
        return False
    return is_armored(prefix)


def armor_file(path: str) -> None:
    """Re-encode the file at ``path`` in place as ASCII armor.

    Args:
        path: Path to a binary encrypted file; overwritten with its armored
            form.
    """
    with open(path, "rb") as f:
        data = f.read()
    wrapped = armor(data)
    with open(path, "wb") as f:
        f.write(wrapped)


def dearmor_file(path: str) -> bytes:
    """Read an armored file and return its decoded binary payload.

    Args:
        path: Path to an ASCII-armored file.

    Returns:
        The decoded binary payload.

    Raises:
        ArmorError: If the file is not valid armor.
    """
    with open(path, "rb") as f:
        return dearmor(f.read())
