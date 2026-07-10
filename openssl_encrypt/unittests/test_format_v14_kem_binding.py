#!/usr/bin/env python3
"""
format_version 14 — KEM ciphertext transcript binding (finding #83,
v14 implementation plan Phase 3).

For v12/v13 the PQC KEM symmetric key is HKDF(shared_secret) with only the
algorithm name as domain separation; nothing binds the derived key to the KEM
encapsulation ciphertext or the AEAD choice. For format_version >= 14 the
derivation binds the full transcript:

    HKDF-SHA256(ikm=shared_secret, salt=None, length=key_length,
                info = b"openssl_encrypt.kem.v14|" + algorithm_name
                       + b"|" + encryption_data
                       + b"|ct=" + sha256(kem_ciphertext))

A missing ciphertext at fv >= 14 raises — no silent fallback. The legacy
bare-SHA256 decrypt retry (for files written by 1.4.x <= 1.4.7) is scoped to
fv 12-13: no v14 file can carry a legacy key, so v14 never retries.

Golden values are pinned for cross-line (1.4.x/1.5.x) byte-identity.
DO NOT CHANGE them.
"""

import hashlib
import unittest

from openssl_encrypt.modules.pqc import LIBOQS_AVAILABLE, PQCipher

FIXED_SECRET = bytes(range(32))
FIXED_CT = bytes(range(256)) * 4  # stand-in KEM ciphertext (1088 bytes for ML-KEM-768)

# Pinned after implementation; MUST match on feature/v1.4.x and v1.5.x.
GOLDEN_V14_KEM_KEY_HEX = "916e86ba10023751e011e9349814a093001e83e0f1abb8ec5b60da2691ebe100"


def _ref_v14_kem_key(secret, ct, algorithm="ML-KEM-768", encryption_data="aes-gcm", length=32):
    """Independent reimplementation of the v14 KEM derivation (spec anchor)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    info = (
        b"openssl_encrypt.kem.v14|"
        + algorithm.encode()
        + b"|"
        + encryption_data.encode()
        + b"|ct="
        + hashlib.sha256(ct).digest()
    )
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(secret)


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestV14KemDerivation(unittest.TestCase):
    def _cipher(self, fv, encryption_data="aes-gcm"):
        return PQCipher(
            "ML-KEM-768", quiet=True, encryption_data=encryption_data, format_version=fv
        )

    def test_v14_matches_reference_and_golden(self):
        derived = self._cipher(14)._derive_symmetric_key(FIXED_SECRET, kem_ciphertext=FIXED_CT)
        self.assertEqual(derived, _ref_v14_kem_key(FIXED_SECRET, FIXED_CT))
        self.assertEqual(derived.hex(), GOLDEN_V14_KEM_KEY_HEX)

    def test_v14_differs_from_v12_and_legacy(self):
        v14 = self._cipher(14)._derive_symmetric_key(FIXED_SECRET, kem_ciphertext=FIXED_CT)
        v12 = self._cipher(12)._derive_symmetric_key(FIXED_SECRET)
        self.assertNotEqual(v14, v12)
        self.assertNotEqual(v14, hashlib.sha256(FIXED_SECRET).digest())

    def test_wrong_ciphertext_changes_key(self):
        cipher = self._cipher(14)
        a = cipher._derive_symmetric_key(FIXED_SECRET, kem_ciphertext=FIXED_CT)
        wrong = bytearray(FIXED_CT)
        wrong[0] ^= 0x01
        b = cipher._derive_symmetric_key(FIXED_SECRET, kem_ciphertext=bytes(wrong))
        self.assertNotEqual(a, b)

    def test_encryption_data_is_bound(self):
        a = self._cipher(14, "aes-gcm")._derive_symmetric_key(FIXED_SECRET, kem_ciphertext=FIXED_CT)
        b = self._cipher(14, "chacha20-poly1305")._derive_symmetric_key(
            FIXED_SECRET, kem_ciphertext=FIXED_CT
        )
        self.assertNotEqual(a, b)

    def test_missing_ciphertext_raises_at_v14(self):
        with self.assertRaises(ValueError):
            self._cipher(14)._derive_symmetric_key(FIXED_SECRET)

    def test_below_v14_ignores_ciphertext(self):
        # v12/v13 derivation is pinned by Phase 0 goldens; passing the
        # ciphertext must not change those bytes.
        for fv in (12, 13):
            with_ct = self._cipher(fv)._derive_symmetric_key(FIXED_SECRET, kem_ciphertext=FIXED_CT)
            without = self._cipher(fv)._derive_symmetric_key(FIXED_SECRET)
            self.assertEqual(with_ct, without, f"fv={fv}")


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestV14KemRoundTrip(unittest.TestCase):
    def test_v14_roundtrip(self):
        cipher = PQCipher("ML-KEM-768", quiet=True, format_version=14)
        public_key, private_key = cipher.generate_keypair()
        encrypted = cipher.encrypt(b"v14 transcript binding probe", public_key)
        self.assertEqual(cipher.decrypt(encrypted, private_key), b"v14 transcript binding probe")

    def test_v14_never_retries_legacy(self):
        # The legacy bare-SHA256 retry exists for files written by <= 1.4.7,
        # which are only v12/v13. A corrupted v14 file must fail after a
        # single attempt.
        cipher = PQCipher("ML-KEM-768", quiet=True, format_version=14)
        public_key, private_key = cipher.generate_keypair()
        encrypted = bytearray(cipher.encrypt(b"single attempt v14", public_key))
        encrypted[-1] ^= 0xFF
        calls = []
        original = cipher._decrypt_impl

        def counting(*args, **kwargs):
            calls.append(kwargs.get("legacy_kem_kdf", False))
            return original(*args, **kwargs)

        cipher._decrypt_impl = counting
        with self.assertRaises(Exception):
            cipher.decrypt(bytes(encrypted), private_key)
        self.assertEqual(calls, [False])

    def test_v13_still_retries_legacy(self):
        # Phase 0 behavior must survive: legacy-written v13 files decrypt via
        # the retry.
        legacy_writer = PQCipher("ML-KEM-768", quiet=True)
        reader = PQCipher("ML-KEM-768", quiet=True, format_version=13)
        public_key, private_key = legacy_writer.generate_keypair()
        encrypted = legacy_writer.encrypt(b"legacy retry still works", public_key)
        self.assertEqual(reader.decrypt(encrypted, private_key), b"legacy retry still works")

    def test_v14_adapter_liboqs_roundtrip(self):
        from openssl_encrypt.modules.pqc import check_pqc_support
        from openssl_encrypt.modules.pqc_adapter import ExtendedPQCipher

        supported = check_pqc_support(quiet=True)[2]
        hqc = next((a for a in ("HQC-128", "HQC-192", "HQC-256") if a in supported), None)
        if hqc is None:
            self.skipTest("no HQC algorithm available for the liboqs branch")
        cipher = ExtendedPQCipher(hqc, quiet=True, format_version=14)
        public_key, private_key = cipher.generate_keypair()
        encrypted = cipher.encrypt(b"v14 adapter probe", public_key)
        self.assertEqual(cipher.decrypt(encrypted, private_key), b"v14 adapter probe")


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestV14FileLevelRoundTrip(unittest.TestCase):
    """End-to-end v14 PQC round-trips through encrypt_file/decrypt_file.

    Exercises the metadata path so the encryption_data value bound into the
    v14 KEM derivation on encrypt is proven equal to the value the decrypt
    side reads back from metadata — including the ml-kem-*-chacha20 alias
    where encryption_data differs from the default.
    """

    def setUp(self):
        import os
        import tempfile

        self.tmp = tempfile.mkdtemp()
        self.infile = f"{self.tmp}/in.txt"
        with open(self.infile, "wb") as f:
            f.write(b"v14 file-level transcript binding probe")
        self.keypair = PQCipher("ML-KEM-768", quiet=True).generate_keypair()

    def _roundtrip(self, algorithm, encryption_data):
        from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file

        outfile = f"{self.tmp}/{algorithm}-{encryption_data}.enc"
        recovered = f"{outfile}.out"
        encrypt_file(
            self.infile,
            outfile,
            b"v14-kem-binding-password",
            {"sha256": 10, "pbkdf2_iterations": 1000},
            algorithm=algorithm,
            encryption_data=encryption_data,
            format_version=14,
            pqc_keypair=self.keypair,
            quiet=True,
        )
        decrypt_file(
            outfile,
            recovered,
            b"v14-kem-binding-password",
            quiet=True,
            pqc_private_key=self.keypair[1],
        )
        with open(recovered, "rb") as f:
            self.assertEqual(f.read(), b"v14 file-level transcript binding probe")

    def test_v14_file_roundtrip_aes_gcm(self):
        self._roundtrip("ml-kem-768-hybrid", "aes-gcm")

    def test_v14_file_roundtrip_chacha20_alias(self):
        self._roundtrip("ml-kem-768-chacha20", "chacha20-poly1305")


if __name__ == "__main__":
    unittest.main()
