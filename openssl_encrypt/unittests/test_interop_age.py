#!/usr/bin/env python3
"""
Tests for read-only `age` decryption (feature #5, phase 1).

The `age` binary was unavailable here, so functional coverage uses an
INDEPENDENT in-test age encoder (`_AgeEncoder`, written separately from the
decryptor) for round-trips, plus bech32 round-trips and adversarial/integrity
negative tests. The encoder follows the age v1 spec; round-trip green means the
decryptor parses and authenticates what the encoder produces.

Test classes:
- TestBech32: age secret-key decoding + identities file parsing.
- TestAgeRoundTrip: X25519 + scrypt round-trips across payload sizes / armor.
- TestAgeRejection: wrong key/passphrase, tamper, mixed stanzas, bounds.
"""

import base64
import hashlib
import hmac
import os
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from openssl_encrypt.modules.interop.age import (
    AgeFormatError,
    AgeIntegrityError,
    NoMatchingIdentityError,
    decode_age_secret_key,
    decrypt,
    is_age_file,
    parse_identities_file,
)

_CHUNK = 64 * 1024


def _b64(data: bytes) -> bytes:
    return base64.b64encode(data).rstrip(b"=")


def _hkdf(ikm, salt, info, length=32):
    return HKDF(algorithm=SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _wrap_body_lines(body: bytes) -> list:
    """age stanza body: base64 lines of <=64 chars; a <64 line terminates."""
    enc = _b64(body)
    lines = [enc[i : i + 64] for i in range(0, len(enc), 64)] or [b""]
    if len(lines[-1]) == 64:
        lines.append(b"")  # terminator
    return lines


class _AgeEncoder:
    """A minimal, independent age v1 encoder used only for tests."""

    def __init__(self):
        self.file_key = os.urandom(16)

    def _x25519_stanza(self, recipient_pub: bytes) -> list:
        eph = X25519PrivateKey.generate()
        share = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
        key = _hkdf(shared, share + recipient_pub, b"age-encryption.org/v1/X25519")
        body = ChaCha20Poly1305(key).encrypt(b"\x00" * 12, self.file_key, None)
        return [b"-> X25519 " + _b64(share)] + _wrap_body_lines(body)

    def _scrypt_stanza(self, passphrase: str, work_factor: int = 4) -> list:
        salt = os.urandom(16)
        derived = hashlib.scrypt(
            passphrase.encode(),
            salt=b"age-encryption.org/v1/scrypt" + salt,
            n=1 << work_factor,
            r=8,
            p=1,
            dklen=32,
        )
        body = ChaCha20Poly1305(derived).encrypt(b"\x00" * 12, self.file_key, None)
        head = b"-> scrypt " + _b64(salt) + b" " + str(work_factor).encode()
        return [head] + _wrap_body_lines(body)

    def encode(self, plaintext: bytes, stanzas: list) -> bytes:
        lines = [b"age-encryption.org/v1"]
        for st in stanzas:
            lines.extend(st)
        prefix = b"\n".join(lines) + b"\n---"
        hmac_key = _hkdf(self.file_key, b"", b"header")
        mac = hmac.new(hmac_key, prefix, hashlib.sha256).digest()
        header = prefix + b" " + _b64(mac) + b"\n"

        nonce = os.urandom(16)
        stream_key = _hkdf(self.file_key, nonce, b"payload")
        aead = ChaCha20Poly1305(stream_key)
        chunks = [plaintext[i : i + _CHUNK] for i in range(0, len(plaintext), _CHUNK)]
        if not chunks:
            chunks = [b""]
        out = bytearray(nonce)
        for idx, ch in enumerate(chunks):
            last = idx == len(chunks) - 1
            cn = idx.to_bytes(11, "big") + (b"\x01" if last else b"\x00")
            out += aead.encrypt(cn, ch, None)
        return header + bytes(out)


def _bech32_encode(hrp: str, data5: list) -> str:
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)

    def polymod(values):
        chk = 1
        for v in values:
            b = chk >> 25
            chk = ((chk & 0x1FFFFFF) << 5) ^ v
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk

    def hrp_expand(h):
        return [ord(c) >> 5 for c in h] + [0] + [ord(c) & 31 for c in h]

    values = hrp_expand(hrp) + data5
    polymod_val = polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod_val >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data5 + checksum)


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    return out


def _scalar_to_age_secret(scalar: bytes) -> str:
    return _bech32_encode("age-secret-key-", _convertbits(list(scalar), 8, 5)).upper()


def _age_pub(scalar: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(scalar)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


class TestBech32(unittest.TestCase):
    def test_secret_key_roundtrip(self):
        scalar = os.urandom(32)
        s = _scalar_to_age_secret(scalar)
        self.assertTrue(s.startswith("AGE-SECRET-KEY-1"))
        self.assertEqual(decode_age_secret_key(s), scalar)

    def test_bad_checksum_rejected(self):
        scalar = os.urandom(32)
        s = _scalar_to_age_secret(scalar)
        bad = s[:-1] + ("Q" if s[-1] != "Q" else "P")
        with self.assertRaises(AgeFormatError):
            decode_age_secret_key(bad)

    def test_identities_file(self):
        tmp = tempfile.mkdtemp()
        try:
            scalars = [os.urandom(32), os.urandom(32)]
            path = os.path.join(tmp, "keys.txt")
            with open(path, "w") as f:
                f.write("# created by test\n\n")
                for sc in scalars:
                    f.write(_scalar_to_age_secret(sc) + "\n")
            self.assertEqual(parse_identities_file(path), scalars)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestAgeRoundTrip(unittest.TestCase):
    def setUp(self):
        self.scalar = os.urandom(32)
        self.pub = _age_pub(self.scalar)

    def _roundtrip_x25519(self, pt):
        enc = _AgeEncoder()
        blob = enc.encode(pt, [enc._x25519_stanza(self.pub)])
        self.assertTrue(is_age_file(blob))
        self.assertEqual(decrypt(blob, identities=[self.scalar]), pt)

    def test_empty(self):
        self._roundtrip_x25519(b"")

    def test_small(self):
        self._roundtrip_x25519(b"hello age world")

    def test_exact_chunk(self):
        self._roundtrip_x25519(os.urandom(_CHUNK))

    def test_chunk_plus_one(self):
        self._roundtrip_x25519(os.urandom(_CHUNK + 1))

    def test_multi_chunk(self):
        self._roundtrip_x25519(os.urandom(3 * _CHUNK + 1234))

    def test_scrypt_roundtrip(self):
        enc = _AgeEncoder()
        blob = enc.encode(b"passphrase secret", [enc._scrypt_stanza("hunter2")])
        self.assertEqual(decrypt(blob, passphrase="hunter2"), b"passphrase secret")

    def test_multiple_recipients_one_ours(self):
        other = _age_pub(os.urandom(32))
        enc = _AgeEncoder()
        blob = enc.encode(b"multi", [enc._x25519_stanza(other), enc._x25519_stanza(self.pub)])
        self.assertEqual(decrypt(blob, identities=[self.scalar]), b"multi")

    def test_armored_roundtrip(self):
        enc = _AgeEncoder()
        blob = enc.encode(b"armored payload", [enc._x25519_stanza(self.pub)])
        armored = (
            b"-----BEGIN AGE ENCRYPTED FILE-----\n"
            + b"\n".join(
                base64.b64encode(blob)[i : i + 64]
                for i in range(0, len(base64.b64encode(blob)), 64)
            )
            + b"\n-----END AGE ENCRYPTED FILE-----\n"
        )
        self.assertTrue(is_age_file(armored))
        self.assertEqual(decrypt(armored, identities=[self.scalar]), b"armored payload")


class TestAgeRejection(unittest.TestCase):
    def setUp(self):
        self.scalar = os.urandom(32)
        self.pub = _age_pub(self.scalar)
        enc = _AgeEncoder()
        self.blob = enc.encode(b"secret data", [enc._x25519_stanza(self.pub)])

    def test_wrong_identity(self):
        with self.assertRaises(NoMatchingIdentityError):
            decrypt(self.blob, identities=[os.urandom(32)])

    def test_no_identity(self):
        with self.assertRaises(NoMatchingIdentityError):
            decrypt(self.blob, identities=[])

    def test_wrong_passphrase(self):
        enc = _AgeEncoder()
        blob = enc.encode(b"x", [enc._scrypt_stanza("right")])
        with self.assertRaises(NoMatchingIdentityError):
            decrypt(blob, passphrase="wrong")

    def test_tampered_header_mac(self):
        # Flip a byte in the MAC value itself: the file key still unwraps, but
        # the header MAC verification must fail.
        b = bytearray(self.blob)
        mac_pos = self.blob.index(b"\n--- ") + 6  # into the base64 MAC
        b[mac_pos] = ord(b"A") if b[mac_pos] != ord(b"A") else ord(b"B")
        with self.assertRaises(AgeIntegrityError):
            decrypt(bytes(b), identities=[self.scalar])

    def test_tampered_other_recipient_stanza(self):
        # With two recipients, modifying a recipient we DON'T use must still be
        # caught by the header MAC (age authenticates the whole recipient list).
        other_pub = _age_pub(os.urandom(32))
        enc = _AgeEncoder()
        blob = enc.encode(b"secret", [enc._x25519_stanza(other_pub), enc._x25519_stanza(self.pub)])
        b = bytearray(blob)
        idx = blob.index(b"-> X25519 ") + 12  # inside the FIRST (other) stanza
        b[idx] ^= 0x01
        with self.assertRaises((AgeIntegrityError, NoMatchingIdentityError)):
            decrypt(bytes(b), identities=[self.scalar])

    def test_tampered_payload(self):
        b = bytearray(self.blob)
        b[-1] ^= 0x01  # flip last payload byte
        with self.assertRaises(AgeIntegrityError):
            decrypt(bytes(b), identities=[self.scalar])

    def test_scrypt_mixed_with_x25519_rejected(self):
        enc = _AgeEncoder()
        blob = enc.encode(b"x", [enc._scrypt_stanza("pw"), enc._x25519_stanza(self.pub)])
        with self.assertRaises(AgeFormatError):
            decrypt(blob, passphrase="pw")

    def test_scrypt_workfactor_cap(self):
        enc = _AgeEncoder()
        # Build a scrypt stanza claiming an absurd work factor (don't run it).
        salt = os.urandom(16)
        body = ChaCha20Poly1305(os.urandom(32)).encrypt(b"\x00" * 12, enc.file_key, None)
        stanza = [b"-> scrypt " + _b64(salt) + b" 99"] + _wrap_body_lines(body)
        blob = enc.encode(b"x", [stanza])
        with self.assertRaises(AgeFormatError):
            decrypt(blob, passphrase="pw")

    def test_not_an_age_file(self):
        self.assertFalse(is_age_file(os.urandom(64)))
        with self.assertRaises(AgeFormatError):
            decrypt(os.urandom(64), identities=[self.scalar])


class TestAgeReferenceVectors(unittest.TestCase):
    """Known-answer vectors generated by the `age` reference impl (pyrage/rage).

    These are real age files (not produced by our in-test encoder), captured
    once and hardcoded so CI needs no `age`/pyrage at runtime. The X25519 vector
    also contains a reference GREASE stanza, exercising unknown-stanza skipping.
    """

    X25519_SK = "AGE-SECRET-KEY-1WK95G077CU2H2G6NCTV85NJYKESJCDL2DQPJU0QCX73NTY4F40FQC5FYNE"
    X25519_CT = (
        "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBmd2JPbkl0NTFTc3ZzK21NZmpXVnI2Vk91WFMw"
        "YlZ5bThHTXIwbjM2R1dFCk96aCtQTEN5VGtvd0haSDYvT3NxTENZQ1l6b01HVEIyWmlCdzhYOHlZdFkK"
        "LT4gJnxWMi1ncmVhc2UgcHMKb3d5aE9QQlJReVB6Nno1L05qdXBERmxkcDVkYWoxeWlJMUhxOFhsMG5o"
        "NGhJajMxCi0tLSBlQjN1MkQwMG9HbHZuZDJZMVpRamNLMVhtUVloRnZnd1NTeHdvdlZsUHd3Cv0Smdek"
        "2sm3MD9mXSa/bST0uxWPsi/+P63nCJhKyfSG3lHOK0X4zqT6lRmegQ=="
    )
    SCRYPT_CT = (
        "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBOSGhsNXowWmYwcmhuTVNWS3VnbEp3IDIwCnFy"
        "b05kZ1hwcE14OTlkOXBMaE1wRmc4aEhxMkFaQk5HZlhnWDRTb2FlVFkKLS0tICt0NGNrNXU5OFY0c3gr"
        "RXZraFp1YklSZkhOZkxRb21Xd1MvcWV6RFphN0EKWFB5+/74iq+mRPO46cMGmaw8oQnjFCTVrRg3a3KN"
        "3Fv+vccEgDAmHb10"
    )

    def test_reference_x25519(self):
        ct = base64.b64decode(self.X25519_CT)
        scalar = decode_age_secret_key(self.X25519_SK)
        self.assertEqual(decrypt(ct, identities=[scalar]), b"hardcoded KAT")

    def test_reference_scrypt(self):
        ct = base64.b64decode(self.SCRYPT_CT)
        self.assertEqual(decrypt(ct, passphrase="pw-fixed"), b"KAT scrypt")


if __name__ == "__main__":
    unittest.main()
