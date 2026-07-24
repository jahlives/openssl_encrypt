"""Regression tests for the .pqc keyfile private-key wrapping KDF (gitlab#131 / F16).

Before the fix, a ``--pqc-keyfile`` wrapped the long-lived PQC private key with
PBKDF2-HMAC-SHA256 at only 100,000 iterations (below the OWASP floor). New
keyfiles now derive the wrapping key with Argon2id and record a self-describing
``key_kdf`` descriptor; keyfiles written before the fix carry no descriptor and
still decrypt via the legacy PBKDF2 path.

These tests pin: the Argon2id descriptor shape, that Argon2id and the legacy
PBKDF2 path derive DIFFERENT keys (the upgrade actually happened), that the
legacy path reproduces the exact pre-fix computation (old keyfiles still open),
that Argon2 cost read from an untrusted keyfile is bounded (no pre-auth OOM),
and a full AES-GCM wrap/unwrap round-trip through both paths.
"""

import hashlib
import unittest

from openssl_encrypt.modules.crypt_cli import (
    _PQC_KEYFILE_ARGON2_MAX_MEMORY,
    _derive_pqc_keyfile_key,
    _new_pqc_keyfile_kdf,
)


class TestPqcKeyfileKdf(unittest.TestCase):
    def setUp(self):
        self.password = b"correct horse battery staple"
        self.salt = bytes(range(16))  # deterministic 16-byte salt

    def test_new_descriptor_is_argon2id(self):
        kdf = _new_pqc_keyfile_kdf()
        self.assertEqual(kdf["type"], "argon2id")
        for field in ("time_cost", "memory_cost", "parallelism"):
            self.assertIsInstance(kdf[field], int)
            self.assertGreater(kdf[field], 0)

    def test_argon2id_key_is_32_bytes_and_deterministic(self):
        kdf = _new_pqc_keyfile_kdf()
        k1 = _derive_pqc_keyfile_key(self.password, self.salt, kdf)
        k2 = _derive_pqc_keyfile_key(self.password, self.salt, kdf)
        self.assertEqual(len(k1), 32)
        self.assertEqual(k1, k2)

    def test_legacy_path_matches_pre_fix_computation(self):
        # kdf=None must reproduce the exact pre-fix derivation so existing
        # keyfiles keep decrypting.
        expected = hashlib.sha256(
            hashlib.pbkdf2_hmac("sha256", self.password, self.salt, 100000)
        ).digest()
        self.assertEqual(_derive_pqc_keyfile_key(self.password, self.salt, None), expected)

    def test_argon2id_differs_from_legacy(self):
        legacy = _derive_pqc_keyfile_key(self.password, self.salt, None)
        argon = _derive_pqc_keyfile_key(self.password, self.salt, _new_pqc_keyfile_kdf())
        self.assertNotEqual(legacy, argon)

    def test_oversized_memory_cost_is_rejected(self):
        # A tampered keyfile must not be able to OOM the host pre-auth.
        bad = {
            "type": "argon2id",
            "time_cost": 3,
            "memory_cost": _PQC_KEYFILE_ARGON2_MAX_MEMORY + 1,
            "parallelism": 4,
        }
        with self.assertRaises(ValueError):
            _derive_pqc_keyfile_key(self.password, self.salt, bad)

    def test_non_int_cost_is_rejected(self):
        for bad_value in ("100000", 3.0, True, None):
            bad = {"type": "argon2id", "time_cost": 3, "memory_cost": bad_value, "parallelism": 4}
            with self.assertRaises(ValueError):
                _derive_pqc_keyfile_key(self.password, self.salt, bad)

    def test_unknown_kdf_type_is_rejected(self):
        with self.assertRaises(ValueError):
            _derive_pqc_keyfile_key(self.password, self.salt, {"type": "scrypt"})

    def test_wrap_unwrap_round_trip_both_paths(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        secret_private_key = b"\x11" * 64
        for kdf in (_new_pqc_keyfile_kdf(), None):
            key = _derive_pqc_keyfile_key(self.password, self.salt, kdf)
            nonce = b"\x00" * 12
            blob = AESGCM(key).encrypt(nonce, secret_private_key, None)
            # Re-derive (as the read path does) and decrypt.
            key2 = _derive_pqc_keyfile_key(self.password, self.salt, kdf)
            recovered = AESGCM(key2).decrypt(nonce, blob, None)
            self.assertEqual(recovered, secret_private_key)

    def test_wrong_password_fails_to_unwrap(self):
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        kdf = _new_pqc_keyfile_kdf()
        key = _derive_pqc_keyfile_key(self.password, self.salt, kdf)
        nonce = b"\x00" * 12
        blob = AESGCM(key).encrypt(nonce, b"private-key-material", None)
        wrong = _derive_pqc_keyfile_key(b"wrong password", self.salt, kdf)
        with self.assertRaises(InvalidTag):
            AESGCM(wrong).decrypt(nonce, blob, None)


if __name__ == "__main__":
    unittest.main()
