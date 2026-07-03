"""Regression tests for GitLab #99 [KDF-7]: HKDF-only KDF configs must be rejected.

HKDF is an extractor/expander, not a password-stretching KDF: a config
that enables only HKDF (no Argon2/scrypt/balloon/RandomX/PBKDF2 and no
hash rounds) derives the file key with a single cheap pass, leaving
password brute force essentially free. Encryption must refuse such a
config; decryption of existing files (metadata-driven) must keep
working.
"""

import secrets
import unittest

from openssl_encrypt.modules.crypt_core import generate_key
from openssl_encrypt.modules.crypt_errors import ValidationError


def _hkdf_only_config(from_decryption: bool = False) -> dict:
    config = {
        "hkdf": {"enabled": True, "algorithm": "sha256"},
        "argon2": {"enabled": False},
        "scrypt": {"enabled": False},
        "balloon": {"enabled": False},
        "randomx": {"enabled": False},
        "pbkdf2_iterations": 0,
    }
    if from_decryption:
        config["_is_from_decryption_metadata"] = True
    return config


class TestHKDFOnlyConfigRejected(unittest.TestCase):
    """Encryption-time key derivation must require a stretching component."""

    def setUp(self) -> None:
        self.password = b"correct horse battery staple"
        self.salt = secrets.token_bytes(16)

    def test_hkdf_only_rejected_for_encryption(self) -> None:
        with self.assertRaises(ValidationError):
            generate_key(
                self.password,
                self.salt,
                _hkdf_only_config(),
                pbkdf2_iterations=0,
                quiet=True,
            )

    def test_hkdf_only_allowed_when_decrypting_existing_file(self) -> None:
        """Existing weak files must remain decryptable (metadata-driven path)."""
        key, _salt, _config = generate_key(
            self.password,
            self.salt,
            _hkdf_only_config(from_decryption=True),
            pbkdf2_iterations=0,
            quiet=True,
        )
        self.assertTrue(key)

    def test_hkdf_plus_memory_hard_component_accepted(self) -> None:
        """HKDF combined with a stretching KDF stays valid (XOR combiner)."""
        config = _hkdf_only_config()
        config["pbkdf2_iterations"] = 1000
        key, _salt, _config = generate_key(
            self.password,
            self.salt,
            config,
            pbkdf2_iterations=1000,
            quiet=True,
        )
        self.assertTrue(key)

    def test_hkdf_only_with_hash_rounds_accepted(self) -> None:
        """Iterated hash rounds count as stretching."""
        config = _hkdf_only_config()
        config["sha256"] = {"rounds": 10000}
        key, _salt, _config = generate_key(
            self.password,
            self.salt,
            config,
            pbkdf2_iterations=0,
            quiet=True,
        )
        self.assertTrue(key)


if __name__ == "__main__":
    unittest.main()
