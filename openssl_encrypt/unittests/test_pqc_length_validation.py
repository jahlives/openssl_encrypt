"""Regression tests for GitLab #107 [PQC-10]: pre-validate KEM/DSA input lengths.

Public keys, secret keys, ciphertexts and signatures were handed to
liboqs without any length/structure pre-validation, relying entirely on
liboqs internal checks. The wrappers must reject wrong-length inputs
with a clean ValueError before the bytes ever reach the C library
(defense in depth). Lengths liboqs reports as 0/unknown (e.g. the HQC
length_ciphertext quirk) are not enforced.
"""

import unittest

try:
    import oqs  # noqa: F401

    from openssl_encrypt.modules.pqc_liboqs import LIBOQS_AVAILABLE, PQEncapsulator, PQSigner
except ImportError:  # pragma: no cover
    LIBOQS_AVAILABLE = False


# Names passed through LIBOQS_ALGORITHM_MAPPING unchanged, so they work on
# any liboqs build (the ML-KEM-* mapping targets underscore names not present
# in every build).
KEM_ALG = "Kyber768"
SIG_ALG = "Dilithium3"


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestKEMLengthValidation(unittest.TestCase):
    """PQEncapsulator must reject malformed inputs before liboqs sees them."""

    @classmethod
    def setUpClass(cls):
        cls.kem = PQEncapsulator(KEM_ALG, quiet=True)
        cls.public_key, cls.secret_key = cls.kem.generate_keypair()
        cls.ciphertext, cls.shared_secret = cls.kem.encapsulate(cls.public_key)

    def test_roundtrip_still_works(self):
        recovered = self.kem.decapsulate(self.ciphertext, self.secret_key)
        self.assertEqual(recovered, self.shared_secret)

    def test_encapsulate_rejects_truncated_public_key(self):
        with self.assertRaises(ValueError):
            self.kem.encapsulate(self.public_key[:-1])

    def test_encapsulate_rejects_oversized_public_key(self):
        with self.assertRaises(ValueError):
            self.kem.encapsulate(self.public_key + b"\x00")

    def test_encapsulate_rejects_non_bytes_public_key(self):
        with self.assertRaises(ValueError):
            self.kem.encapsulate("not-bytes")

    def test_decapsulate_rejects_truncated_ciphertext(self):
        with self.assertRaises(ValueError):
            self.kem.decapsulate(self.ciphertext[:-1], self.secret_key)

    def test_decapsulate_rejects_oversized_ciphertext(self):
        with self.assertRaises(ValueError):
            self.kem.decapsulate(self.ciphertext + b"\x00", self.secret_key)

    def test_decapsulate_rejects_wrong_length_secret_key(self):
        with self.assertRaises(ValueError):
            self.kem.decapsulate(self.ciphertext, self.secret_key[:-1])


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestSignerLengthValidation(unittest.TestCase):
    """PQSigner must reject malformed inputs before liboqs sees them."""

    @classmethod
    def setUpClass(cls):
        cls.signer = PQSigner(SIG_ALG, quiet=True)
        cls.public_key, cls.secret_key = cls.signer.generate_keypair()
        cls.message = b"length validation test message"
        cls.signature = cls.signer.sign(cls.message)

    def test_roundtrip_still_works(self):
        self.assertTrue(self.signer.verify(self.message, self.signature, self.public_key))

    def test_verify_rejects_wrong_length_public_key(self):
        with self.assertRaises(ValueError):
            self.signer.verify(self.message, self.signature, self.public_key[:-1])

    def test_verify_rejects_oversized_signature(self):
        max_len = self.signer.sig.details["length_signature"]
        bogus = b"\x00" * (max_len + 1)
        with self.assertRaises(ValueError):
            self.signer.verify(self.message, bogus, self.public_key)

    def test_verify_rejects_empty_signature(self):
        with self.assertRaises(ValueError):
            self.signer.verify(self.message, b"", self.public_key)

    def test_sign_rejects_wrong_length_secret_key(self):
        with self.assertRaises(ValueError):
            self.signer.sign(self.message, self.secret_key[:-1])


if __name__ == "__main__":
    unittest.main()
