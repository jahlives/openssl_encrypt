"""Contract test for keystore header-AAD binding (#85 / PQC-5).

_encrypt_with_derived_key binds the {method, params} header as AES-GCM associated
data. _decrypt_with_derived_key previously tried empty/None AAD before the real
header, preferring an unbound interpretation. AES-GCM binds the AAD, so this was
not exploitable for current records (an empty-AAD decrypt cannot succeed on a
header-AAD ciphertext), but the decrypt now tries the header first for
consistency. This test guards the binding: a header-AAD record round-trips, and
tampering the stored method/params makes decryption fail.
"""

import copy
import unittest

from openssl_encrypt.modules.pqc_keystore import KeystoreProtectionMethod, PQCKeystore


class TestKeystoreAadBinding(unittest.TestCase):
    def setUp(self):
        self.ks = PQCKeystore()
        self.key = bytes(range(32))
        self.data = b"secret private key material"

    def _encrypt(self, method):
        return self.ks._encrypt_with_derived_key(self.data, self.key, method)

    def test_roundtrip_and_tampered_header_rejected_aes_gcm(self):
        enc = self._encrypt(KeystoreProtectionMethod.ARGON2ID_AES_GCM)
        self.assertEqual(self.ks._decrypt_with_derived_key(enc, self.key), self.data)

        tampered = copy.deepcopy(enc)
        tampered["params"]["kdf_version"] = 999  # a param bound into the header AAD
        with self.assertRaises(Exception):
            self.ks._decrypt_with_derived_key(tampered, self.key)

    def test_wrong_key_rejected(self):
        enc = self._encrypt(KeystoreProtectionMethod.ARGON2ID_AES_GCM)
        with self.assertRaises(Exception):
            self.ks._decrypt_with_derived_key(enc, b"\x00" * 32)


if __name__ == "__main__":
    unittest.main()
