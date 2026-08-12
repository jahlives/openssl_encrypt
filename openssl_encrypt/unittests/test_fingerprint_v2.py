"""Regression tests for GitLab #98 [KDF-6]: fingerprint domain separation.

The identity fingerprint hashed the bare concatenation of the encryption
and signing public keys — no length prefixes (boundary-ambiguous: moving
bytes across the enc/sig boundary yields the same fingerprint) and no
algorithm binding (algorithm substitution is not reflected).

Decision (confirmed): new identities mint a v2 fingerprint with a domain
tag, algorithm ids and length-prefixed fields; existing v1 bundles keep
verifying (dual-accept), so no stored identity, TOFU pin, or
out-of-band-verified fingerprint breaks.
"""

import unittest

from openssl_encrypt.modules.pqc_signing import calculate_fingerprint, calculate_fingerprint_v2


class TestFingerprintV2Encoding(unittest.TestCase):
    """The v2 encoding must remove ambiguity and bind algorithms."""

    def test_v1_boundary_ambiguity_fixed_in_v2(self) -> None:
        """Moving bytes across the enc/sig boundary must change v2.

        v1 hashes enc_pub + sig_pub, so (a+b, c) and (a, b+c) collide.
        """
        a, b, c = b"A" * 100, b"B" * 50, b"C" * 100

        v1_first = calculate_fingerprint(a + b + c)  # (enc=a+b, sig=c) concatenated
        v1_second = calculate_fingerprint(a + b + c)  # (enc=a, sig=b+c) concatenated
        self.assertEqual(v1_first, v1_second)  # the v1 flaw, by construction

        v2_first = calculate_fingerprint_v2("ML-KEM-768", a + b, "ML-DSA-65", c)
        v2_second = calculate_fingerprint_v2("ML-KEM-768", a, "ML-DSA-65", b + c)
        self.assertNotEqual(v2_first, v2_second)

    def test_v2_binds_algorithm_ids(self) -> None:
        """Same key bytes under different algorithm ids must differ in v2."""
        enc, sig = b"E" * 64, b"S" * 64
        fp_mlkem = calculate_fingerprint_v2("ML-KEM-768", enc, "ML-DSA-65", sig)
        fp_kyber = calculate_fingerprint_v2("Kyber768", enc, "ML-DSA-65", sig)
        self.assertNotEqual(fp_mlkem, fp_kyber)

    def test_v2_differs_from_v1(self) -> None:
        enc, sig = b"E" * 64, b"S" * 64
        self.assertNotEqual(
            calculate_fingerprint_v2("ML-KEM-768", enc, "ML-DSA-65", sig),
            calculate_fingerprint(enc + sig),
        )

    def test_v2_deterministic_and_formatted(self) -> None:
        enc, sig = b"E" * 64, b"S" * 64
        fp1 = calculate_fingerprint_v2("ML-KEM-768", enc, "ML-DSA-65", sig)
        fp2 = calculate_fingerprint_v2("ML-KEM-768", enc, "ML-DSA-65", sig)
        self.assertEqual(fp1, fp2)
        parts = fp1.split(":")
        self.assertEqual(len(parts), 32)  # SHA-256, colon-separated bytes
        self.assertTrue(all(len(p) == 2 for p in parts))


class TestIdentityFingerprintVersioning(unittest.TestCase):
    """New identities mint v2; legacy v1 identities keep verifying."""

    @classmethod
    def setUpClass(cls):
        from openssl_encrypt.modules.identity import Identity

        cls.identity = Identity.generate("FpV2Test", None, "test_pass_1234")

    def test_new_identity_mints_v2(self) -> None:
        expected_v2 = calculate_fingerprint_v2(
            self.identity.encryption_algorithm,
            self.identity.encryption_public_key,
            self.identity.signing_algorithm,
            self.identity.signing_public_key,
        )
        self.assertEqual(self.identity.fingerprint, expected_v2)

    def test_new_identity_consistency_check_passes(self) -> None:
        self.assertTrue(self.identity.check_fingerprint_consistency())

    def test_legacy_v1_identity_still_consistent(self) -> None:
        """An identity carrying a v1 fingerprint must keep verifying."""
        import copy

        legacy = copy.copy(self.identity)
        legacy.fingerprint = calculate_fingerprint(
            legacy.encryption_public_key + legacy.signing_public_key
        )
        self.assertTrue(legacy.check_fingerprint_consistency())

    def test_wrong_fingerprint_still_rejected(self) -> None:
        """Dual-accept must not turn into accept-anything."""
        import copy

        tampered = copy.copy(self.identity)
        tampered.fingerprint = "00:" * 31 + "00"
        self.assertFalse(tampered.check_fingerprint_consistency())


if __name__ == "__main__":
    unittest.main()
