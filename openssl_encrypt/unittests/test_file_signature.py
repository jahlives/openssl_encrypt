#!/usr/bin/env python3
"""
Tests for the detached file-signing core (feature #1).

The core (openssl_encrypt.modules.file_signature) produces and verifies a
detached, post-quantum (ML-DSA-65) signature over an arbitrary file:

- the signature covers a DOMAIN-SEPARATED canonical payload binding the file's
  SHA-512 digest to the algorithm, signer fingerprint and timestamp;
- the .sig is a JSON sidecar (optionally ASCII-armored with the SIGNATURE
  label) carrying a `signatures` list so a classical component can be added
  later without a format break;
- verification recomputes the file hash, checks it matches the signed hash, and
  verifies each signature component, reporting which one(s) passed.

Test classes:
- TestSignedPayload / TestHashing / TestSerialize: pure, no liboqs.
- TestFileSignatureCrypto: sign/verify round-trips (gated on liboqs).
"""

import hashlib
import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.file_signature import (
    ARMOR_LABEL,
    SIGNATURE_FORMAT_VERSION,
    FileSignatureError,
    build_signature,
    hash_bytes,
    hash_file,
    parse_signature,
    serialize_signature,
    verify_signature,
)


class TestHashing(unittest.TestCase):
    def test_hash_bytes_matches_sha512(self):
        data = b"the quick brown fox"
        self.assertEqual(hash_bytes(data), hashlib.sha512(data).hexdigest())

    def test_hash_file_streams_correctly(self):
        tmp = tempfile.mkdtemp()
        try:
            data = os.urandom(3 * 1024 * 1024 + 7)  # > chunk size, non-aligned
            p = os.path.join(tmp, "blob")
            with open(p, "wb") as f:
                f.write(data)
            self.assertEqual(hash_file(p), hashlib.sha512(data).hexdigest())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestSignedPayload(unittest.TestCase):
    """The to-be-signed payload is deterministic and domain-separated."""

    def test_payload_is_deterministic(self):
        from openssl_encrypt.modules.file_signature import _signed_payload

        a = _signed_payload("abc", "ML-DSA-65", "fp", "2026-01-01T00:00:00Z")
        b = _signed_payload("abc", "ML-DSA-65", "fp", "2026-01-01T00:00:00Z")
        self.assertEqual(a, b)
        self.assertIsInstance(a, bytes)

    def test_payload_has_domain_tag(self):
        from openssl_encrypt.modules.file_signature import _DOMAIN_TAG, _signed_payload

        payload = _signed_payload("abc", "ML-DSA-65", "fp", "t")
        self.assertTrue(payload.startswith(_DOMAIN_TAG))

    def test_payload_changes_with_each_field(self):
        from openssl_encrypt.modules.file_signature import _signed_payload

        base = _signed_payload("h", "ML-DSA-65", "fp", "t")
        self.assertNotEqual(base, _signed_payload("h2", "ML-DSA-65", "fp", "t"))
        self.assertNotEqual(base, _signed_payload("h", "ML-DSA-87", "fp", "t"))
        self.assertNotEqual(base, _signed_payload("h", "ML-DSA-65", "fp2", "t"))
        self.assertNotEqual(base, _signed_payload("h", "ML-DSA-65", "fp", "t2"))


class TestSerialize(unittest.TestCase):
    """Serialization / parsing of the .sig JSON sidecar."""

    def _sample(self):
        return {
            "openssl_encrypt_signature": SIGNATURE_FORMAT_VERSION,
            "algorithm": "ML-DSA-65",
            "hash_algorithm": "SHA-512",
            "file_hash": "deadbeef",
            "signer_fingerprint": "fp",
            "signed_at": "2026-01-01T00:00:00Z",
            "signatures": [{"component": "ml-dsa-65", "value": "AAAA"}],
        }

    def test_armored_roundtrip_uses_signature_label(self):
        blob = serialize_signature(self._sample(), armored=True)
        self.assertIn(b"-----BEGIN OPENSSL-ENCRYPT SIGNATURE-----", blob)
        self.assertEqual(parse_signature(blob), self._sample())

    def test_raw_roundtrip(self):
        blob = serialize_signature(self._sample(), armored=False)
        self.assertNotIn(b"BEGIN OPENSSL-ENCRYPT", blob)
        self.assertEqual(parse_signature(blob), self._sample())

    def test_parse_rejects_garbage(self):
        with self.assertRaises(FileSignatureError):
            parse_signature(b"not json at all {{{")

    def test_parse_rejects_wrong_armor_label(self):
        from openssl_encrypt.modules.armor import armor

        # A MESSAGE-labelled armor is not a signature file.
        with self.assertRaises(FileSignatureError):
            parse_signature(armor(b'{"a":1}', label="MESSAGE"))


try:
    from openssl_encrypt.modules.identity import Identity
    from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE
except Exception:  # pragma: no cover
    LIBOQS_AVAILABLE = False


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestFileSignatureCrypto(unittest.TestCase):
    """End-to-end sign/verify at the crypto layer."""

    def setUp(self):
        self.signer = Identity.generate("Signer", "s@example.com", "pw")
        self.other = Identity.generate("Other", "o@example.com", "pw")
        self.file_data = b"contract text to be signed \x00\x01\xff"
        self.file_hash = hash_bytes(self.file_data)
        self.ts = "2026-06-23T12:00:00Z"

    def _sign(self):
        return build_signature(self.file_hash, self.signer, self.ts)

    def test_valid_roundtrip(self):
        sig = self._sign()
        self.assertEqual(sig["signer_fingerprint"], self.signer.fingerprint)
        self.assertEqual(sig["algorithm"], "ML-DSA-65")
        res = verify_signature(self.file_hash, sig, self.signer.signing_public_key)
        self.assertTrue(res.valid)
        self.assertTrue(res.file_match)
        self.assertTrue(res.signature_valid)
        self.assertEqual(res.signer_fingerprint, self.signer.fingerprint)
        self.assertTrue(all(c["valid"] for c in res.components))

    def test_serialize_parse_then_verify(self):
        blob = serialize_signature(self._sign(), armored=True)
        parsed = parse_signature(blob)
        res = verify_signature(self.file_hash, parsed, self.signer.signing_public_key)
        self.assertTrue(res.valid)

    def test_wrong_file_hash_fails_file_match(self):
        sig = self._sign()
        res = verify_signature(hash_bytes(b"different file"), sig, self.signer.signing_public_key)
        self.assertFalse(res.valid)
        self.assertFalse(res.file_match)

    def test_tampered_signature_value_invalid(self):
        sig = self._sign()
        # Flip the base64 signature.
        v = bytearray(sig["signatures"][0]["value"].encode())
        v[0] = ord("A") if v[0] != ord("A") else ord("B")
        sig["signatures"][0]["value"] = v.decode()
        res = verify_signature(self.file_hash, sig, self.signer.signing_public_key)
        self.assertFalse(res.valid)
        self.assertFalse(res.signature_valid)

    def test_wrong_public_key_invalid(self):
        sig = self._sign()
        res = verify_signature(self.file_hash, sig, self.other.signing_public_key)
        self.assertFalse(res.valid)
        self.assertFalse(res.signature_valid)

    def test_tampered_signed_field_invalid(self):
        """Changing a bound field (signed_at) must break the signature."""
        sig = self._sign()
        sig["signed_at"] = "2099-01-01T00:00:00Z"
        res = verify_signature(self.file_hash, sig, self.signer.signing_public_key)
        self.assertFalse(res.valid)


if __name__ == "__main__":
    unittest.main()
