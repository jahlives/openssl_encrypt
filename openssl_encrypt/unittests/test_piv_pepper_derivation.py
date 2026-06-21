"""Unit tests for the PIV backend's HKDF challenge/pepper derivation.

Covers verification-table item 13 (HKDF output length matches requested length)
plus the deterministic-challenge and pepper-derivation constructions from the
spec.  These tests recompute the expected HKDF outputs independently with the
``cryptography`` library so the salt/info constants are pinned and cannot drift.

No hardware and no PKCS#11 needed, but we import the shared mock first so that
importing the engine module (which does ``import pkcs11`` at top level) resolves
to the fake binding.
"""

import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from openssl_encrypt.modules.piv_backend import PepperDerivation
from openssl_encrypt.unittests import _piv_mocks  # noqa: F401  (installs fake pkcs11)


def _expected_hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"openssl_encrypt-piv-v1",
        info=info,
    ).derive(ikm)


class TestChallengeDerivation(unittest.TestCase):
    def setUp(self):
        self.deriver = PepperDerivation()

    def test_challenge_length_is_64(self):
        challenge = self.deriver.derive_challenge(b"some input data")
        self.assertEqual(len(challenge), 64)

    def test_challenge_is_deterministic(self):
        a = self.deriver.derive_challenge(b"identical")
        b = self.deriver.derive_challenge(b"identical")
        self.assertEqual(a, b)

    def test_different_input_yields_different_challenge(self):
        a = self.deriver.derive_challenge(b"input-A")
        b = self.deriver.derive_challenge(b"input-B")
        self.assertNotEqual(a, b)

    def test_challenge_matches_independent_hkdf(self):
        ikm = b"the data openssl_encrypt wants to protect"
        expected = _expected_hkdf(ikm, b"piv-challenge", 64)
        self.assertEqual(self.deriver.derive_challenge(ikm), expected)

    def test_empty_input_rejected(self):
        with self.assertRaises(ValueError):
            self.deriver.derive_challenge(b"")


class TestPepperDerivation(unittest.TestCase):
    def setUp(self):
        self.deriver = PepperDerivation()

    def test_default_pepper_length_is_32(self):
        pepper = self.deriver.derive_pepper(b"\x01" * 256)
        self.assertEqual(len(pepper), 32)

    def test_pepper_length_is_configurable(self):
        deriver = PepperDerivation(pepper_length=48)
        self.assertEqual(len(deriver.derive_pepper(b"\x02" * 64)), 48)

    def test_pepper_is_deterministic(self):
        sig = b"\x07" * 512
        self.assertEqual(self.deriver.derive_pepper(sig), self.deriver.derive_pepper(sig))

    def test_different_signature_yields_different_pepper(self):
        a = self.deriver.derive_pepper(b"\x00" * 64)
        b = self.deriver.derive_pepper(b"\xff" * 64)
        self.assertNotEqual(a, b)

    def test_pepper_matches_independent_hkdf(self):
        sig = bytes(range(64))
        expected = _expected_hkdf(sig, b"piv-pepper", 32)
        self.assertEqual(self.deriver.derive_pepper(sig), expected)

    def test_pepper_length_normalizes_regardless_of_signature_size(self):
        # RSA-2048 (256), RSA-4096 (512), Ed25519 (64) signatures all -> 32 bytes.
        for sig_len in (64, 256, 512):
            self.assertEqual(len(self.deriver.derive_pepper(b"\x05" * sig_len)), 32)

    def test_empty_signature_rejected(self):
        with self.assertRaises(ValueError):
            self.deriver.derive_pepper(b"")


class TestPepperDerivationConfigValidation(unittest.TestCase):
    def test_zero_pepper_length_rejected(self):
        with self.assertRaises(ValueError):
            PepperDerivation(pepper_length=0)

    def test_negative_pepper_length_rejected(self):
        with self.assertRaises(ValueError):
            PepperDerivation(pepper_length=-1)

    def test_excessive_pepper_length_rejected(self):
        # HKDF-SHA256 caps output at 255*32 = 8160 bytes.
        with self.assertRaises(ValueError):
            PepperDerivation(pepper_length=8161)


if __name__ == "__main__":
    unittest.main()
