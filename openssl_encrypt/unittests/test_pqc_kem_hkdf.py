"""Tests for PQCipher._derive_symmetric_key — finding #83 v12 HKDF backport.

The format_version >= 12 KEM-key derivation (HKDF-SHA256 with algorithm-name
domain separation) shipped on 1.5.x but was missing on the 1.4.x line, which
derived every KEM symmetric key as bare sha256(shared_secret). That made
v12/v13 PQC files cross-line incompatible (confirmed empirically 2026-07-10:
a 1.4.x-written v13 PQC file fails with InvalidTag under the 1.5.x
derivation). These tests pin the backported behavior.

GOLDEN VALUES are pinned to the 1.5.x derivation spec and MUST match on both
maintenance branches byte-for-byte. DO NOT CHANGE them.
"""

import hashlib
import unittest

from openssl_encrypt.modules.pqc import LIBOQS_AVAILABLE, PQCipher

# Fixed 32-byte shared secret 00 01 02 ... 1f
FIXED_SECRET = bytes(range(32))

# HKDF-SHA256(salt=None, info=b"openssl_encrypt-kem-key-ML-KEM-768",
#             length=32).derive(FIXED_SECRET) — 1.5.x spec value.
GOLDEN_HKDF_MLKEM768_HEX = "431176e0833d6f94de5a5fdea7a17568a76283aece613ad59a9bbffdfb007678"

# sha256(FIXED_SECRET) — legacy (< v12) derivation.
GOLDEN_SHA256_HEX = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"


def _ref_hkdf(secret: bytes, algorithm_name: str, length: int = 32) -> bytes:
    """Independent reimplementation of the v12+ derivation spec."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b"openssl_encrypt-kem-key-" + algorithm_name.encode(),
    ).derive(secret)


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestKemHkdfDerivation(unittest.TestCase):
    """Unit tests for the format_version-gated KEM key derivation."""

    def _cipher(self, format_version):
        return PQCipher("ML-KEM-768", quiet=True, format_version=format_version)

    def test_v12_uses_hkdf_golden(self):
        cipher = self._cipher(12)
        derived = cipher._derive_symmetric_key(FIXED_SECRET)
        self.assertEqual(derived.hex(), GOLDEN_HKDF_MLKEM768_HEX)

    def test_v12_matches_reference_reimplementation(self):
        cipher = self._cipher(12)
        derived = cipher._derive_symmetric_key(FIXED_SECRET)
        self.assertEqual(derived, _ref_hkdf(FIXED_SECRET, cipher.algorithm_name))

    def test_v13_and_v14_use_same_hkdf_as_v12(self):
        for fv in (13, 14):
            derived = self._cipher(fv)._derive_symmetric_key(FIXED_SECRET)
            self.assertEqual(derived.hex(), GOLDEN_HKDF_MLKEM768_HEX, f"fv={fv}")

    def test_legacy_versions_use_bare_sha256(self):
        for fv in (None, 5, 9, 10, 11):
            derived = self._cipher(fv)._derive_symmetric_key(FIXED_SECRET)
            self.assertEqual(derived.hex(), GOLDEN_SHA256_HEX, f"fv={fv}")

    def test_gate_boundary_11_vs_12(self):
        legacy = self._cipher(11)._derive_symmetric_key(FIXED_SECRET)
        modern = self._cipher(12)._derive_symmetric_key(FIXED_SECRET)
        self.assertNotEqual(legacy, modern)
        self.assertEqual(legacy, hashlib.sha256(FIXED_SECRET).digest())

    def test_default_constructor_is_legacy(self):
        # No format_version argument -> legacy derivation (backward compat
        # for every caller that does not thread a version, e.g. keystore).
        cipher = PQCipher("ML-KEM-768", quiet=True)
        derived = cipher._derive_symmetric_key(FIXED_SECRET)
        self.assertEqual(derived.hex(), GOLDEN_SHA256_HEX)

    def test_hkdf_domain_separation_by_algorithm(self):
        c768 = PQCipher("ML-KEM-768", quiet=True, format_version=12)
        c1024 = PQCipher("ML-KEM-1024", quiet=True, format_version=12)
        self.assertNotEqual(
            c768._derive_symmetric_key(FIXED_SECRET),
            c1024._derive_symmetric_key(FIXED_SECRET),
        )

    def test_key_length_parameter(self):
        derived = self._cipher(12)._derive_symmetric_key(FIXED_SECRET, key_length=64)
        self.assertEqual(len(derived), 64)
        self.assertEqual(derived[:32], _ref_hkdf(FIXED_SECRET, "ML-KEM-768", 64)[:32])


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestKemHkdfRoundTrip(unittest.TestCase):
    """End-to-end KEM round-trips across the version gate."""

    def test_roundtrip_v13(self):
        cipher = PQCipher("ML-KEM-768", quiet=True, format_version=13)
        public_key, private_key = cipher.generate_keypair()
        encrypted = cipher.encrypt(b"phase-0 hkdf roundtrip", public_key)
        decrypted = cipher.decrypt(encrypted, private_key)
        self.assertEqual(decrypted, b"phase-0 hkdf roundtrip")

    def test_roundtrip_legacy(self):
        cipher = PQCipher("ML-KEM-768", quiet=True)
        public_key, private_key = cipher.generate_keypair()
        encrypted = cipher.encrypt(b"phase-0 legacy roundtrip", public_key)
        decrypted = cipher.decrypt(encrypted, private_key)
        self.assertEqual(decrypted, b"phase-0 legacy roundtrip")

    def test_legacy_written_v13_file_decrypts_via_fallback(self):
        # Released 1.4.x clients (<= 1.4.7) wrote v12/v13 PQC files with the
        # legacy bare-sha256 KEM key. Decrypt MUST keep reading them: the
        # v12+ decrypt path tries HKDF first and falls back to the legacy
        # derivation when authentication fails.
        legacy_writer = PQCipher("ML-KEM-768", quiet=True)
        modern_reader = PQCipher("ML-KEM-768", quiet=True, format_version=13)
        public_key, private_key = legacy_writer.generate_keypair()
        encrypted = legacy_writer.encrypt(b"pre-backport 1.4.x file", public_key)
        decrypted = modern_reader.decrypt(encrypted, private_key)
        self.assertEqual(decrypted, b"pre-backport 1.4.x file")

    def test_modern_written_file_decrypts_without_fallback(self):
        # 1.5.x-written v12/v13 PQC files (HKDF keys) must decrypt on the
        # primary path — this is the cross-line fix itself.
        writer = PQCipher("ML-KEM-768", quiet=True, format_version=13)
        reader = PQCipher("ML-KEM-768", quiet=True, format_version=13)
        public_key, private_key = writer.generate_keypair()
        encrypted = writer.encrypt(b"1.5.x-style file", public_key)
        self.assertEqual(reader.decrypt(encrypted, private_key), b"1.5.x-style file")

    def test_corrupted_file_fails_both_derivations(self):
        cipher = PQCipher("ML-KEM-768", quiet=True, format_version=13)
        public_key, private_key = cipher.generate_keypair()
        encrypted = bytearray(cipher.encrypt(b"tamper target", public_key))
        encrypted[-1] ^= 0xFF  # break the AEAD tag
        with self.assertRaises(Exception):
            cipher.decrypt(bytes(encrypted), private_key)

    def test_wrong_private_key_fails_cleanly_on_v12(self):
        # The fallback must not turn a wrong-key error into anything but a
        # clean failure: implicit rejection yields a different shared secret,
        # both derivations fail authentication.
        cipher = PQCipher("ML-KEM-768", quiet=True, format_version=13)
        public_key, _ = cipher.generate_keypair()
        _, wrong_private_key = cipher.generate_keypair()
        encrypted = cipher.encrypt(b"wrong key probe", public_key)
        with self.assertRaises(ValueError):
            cipher.decrypt(encrypted, wrong_private_key)

    def test_no_retry_below_v12(self):
        # The compatibility retry is scoped to format_version >= 12: a legacy
        # cipher must attempt decryption exactly once.
        cipher = PQCipher("ML-KEM-768", quiet=True, format_version=11)
        public_key, private_key = cipher.generate_keypair()
        encrypted = bytearray(cipher.encrypt(b"single attempt", public_key))
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

    def test_fallback_notice_respects_quiet(self):
        import contextlib
        import io

        legacy_writer = PQCipher("ML-KEM-768", quiet=True)
        public_key, private_key = legacy_writer.generate_keypair()
        encrypted = legacy_writer.encrypt(b"notice probe", public_key)

        loud_reader = PQCipher("ML-KEM-768", quiet=False, format_version=13)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(loud_reader.decrypt(encrypted, private_key), b"notice probe")
        self.assertIn("legacy (pre-1.4.8) KEM key derivation", stderr.getvalue())

        quiet_reader = PQCipher("ML-KEM-768", quiet=True, format_version=13)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(quiet_reader.decrypt(encrypted, private_key), b"notice probe")
        self.assertNotIn("legacy (pre-1.4.8)", stderr.getvalue())


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestExtendedPQCipherHkdf(unittest.TestCase):
    """ExtendedPQCipher must thread format_version through both branches."""

    def test_native_branch_derivation(self):
        from openssl_encrypt.modules.pqc_adapter import ExtendedPQCipher

        cipher = ExtendedPQCipher("ML-KEM-768", quiet=True, format_version=12)
        derived = cipher._derive_symmetric_key(FIXED_SECRET)
        self.assertEqual(derived.hex(), GOLDEN_HKDF_MLKEM768_HEX)

    def test_liboqs_branch_derivation(self):
        from openssl_encrypt.modules.pqc import check_pqc_support
        from openssl_encrypt.modules.pqc_adapter import ExtendedPQCipher

        supported = check_pqc_support(quiet=True)[2]
        hqc = next((a for a in ("HQC-128", "HQC-192", "HQC-256") if a in supported), None)
        if hqc is None:
            self.skipTest("no HQC algorithm available for the liboqs branch")
        cipher = ExtendedPQCipher(hqc, quiet=True, format_version=12)
        derived = cipher._derive_symmetric_key(FIXED_SECRET)
        self.assertEqual(derived, _ref_hkdf(FIXED_SECRET, cipher.algorithm_name))
        legacy = ExtendedPQCipher(hqc, quiet=True)
        self.assertEqual(
            legacy._derive_symmetric_key(FIXED_SECRET),
            hashlib.sha256(FIXED_SECRET).digest(),
        )

    def test_liboqs_branch_legacy_fallback_roundtrip(self):
        # Behavioral coverage for the adapter's retry loop: a legacy-written
        # (bare-sha256) liboqs-KEM payload must decrypt under a fv>=12 reader
        # via the fallback, with the NOTICE on stderr unless quiet.
        import contextlib
        import io

        from openssl_encrypt.modules.pqc import check_pqc_support
        from openssl_encrypt.modules.pqc_adapter import ExtendedPQCipher

        supported = check_pqc_support(quiet=True)[2]
        hqc = next((a for a in ("HQC-128", "HQC-192", "HQC-256") if a in supported), None)
        if hqc is None:
            self.skipTest("no HQC algorithm available for the liboqs branch")

        legacy_writer = ExtendedPQCipher(hqc, quiet=True)
        public_key, private_key = legacy_writer.generate_keypair()
        encrypted = legacy_writer.encrypt(b"adapter fallback probe", public_key)

        loud_reader = ExtendedPQCipher(hqc, quiet=False, format_version=13)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            decrypted = loud_reader.decrypt(encrypted, private_key)
        self.assertEqual(decrypted, b"adapter fallback probe")
        self.assertIn("legacy (pre-1.4.8) KEM key derivation", stderr.getvalue())

        modern_writer = ExtendedPQCipher(hqc, quiet=True, format_version=13)
        encrypted_modern = modern_writer.encrypt(b"adapter modern probe", public_key)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            decrypted = modern_writer.decrypt(encrypted_modern, private_key)
        self.assertEqual(decrypted, b"adapter modern probe")
        self.assertNotIn("legacy (pre-1.4.8)", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
