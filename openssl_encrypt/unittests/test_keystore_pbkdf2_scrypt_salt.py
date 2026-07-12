"""Regression test for the salt_b64 NameError in keystore fallback branches (#108 / PQC-8).

_encrypt_private_key defined salt_b64 only inside the Argon2 branch, so the
SCRYPT_CHACHA20 and PBKDF2_AES_GCM branches (used when Argon2 is unavailable or
explicitly selected) referenced an undefined salt_b64 and raised NameError. It is
now defined once before the branch chain.
"""

import unittest

from openssl_encrypt.modules.pqc_keystore import KeystoreProtectionMethod, PQCKeystore


class TestKeystoreFallbackSalt(unittest.TestCase):
    def test_pbkdf2_and_scrypt_branches_roundtrip(self):
        ks = PQCKeystore()
        private_key = b"private-key-material-0123456789abcdef"
        for method in (
            KeystoreProtectionMethod.PBKDF2_AES_GCM,
            KeystoreProtectionMethod.SCRYPT_CHACHA20,
        ):
            with self.subTest(method=method.value):
                encrypted = ks._encrypt_private_key(private_key, "passw0rd", method)
                recovered = ks._decrypt_private_key(encrypted, "passw0rd")
                self.assertEqual(recovered, private_key)


if __name__ == "__main__":
    unittest.main()
