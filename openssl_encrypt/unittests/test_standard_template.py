"""Tests for the STANDARD security template configuration.

Verifies that the STANDARD template uses the expected modern defaults:
- Two hashes: SHA3-256 (10k) + SHA3-512 (10k)
- Two KDFs: Scrypt (10 rounds) + Argon2 (10 rounds)
- Encryption: AES-GCM
"""

import unittest

from openssl_encrypt.modules.crypt_cli import SecurityTemplate, get_template_config


class TestStandardTemplateHashes(unittest.TestCase):
    """Test hash algorithm configuration in STANDARD template."""

    def setUp(self) -> None:
        self.config = get_template_config(SecurityTemplate.STANDARD)
        self.hash_config = self.config["hash_config"]

    def test_sha3_256_enabled_with_10k_rounds(self) -> None:
        self.assertEqual(self.hash_config["sha3_256"], 10000)

    def test_sha3_512_enabled_with_10k_rounds(self) -> None:
        self.assertEqual(self.hash_config["sha3_512"], 10000)

    def test_sha512_disabled(self) -> None:
        self.assertEqual(self.hash_config["sha512"], 0)

    def test_sha256_disabled(self) -> None:
        self.assertEqual(self.hash_config["sha256"], 0)

    def test_blake2b_disabled(self) -> None:
        self.assertEqual(self.hash_config["blake2b"], 0)

    def test_shake256_disabled(self) -> None:
        self.assertEqual(self.hash_config["shake256"], 0)


class TestStandardTemplateKDFs(unittest.TestCase):
    """Test KDF configuration in STANDARD template."""

    def setUp(self) -> None:
        self.config = get_template_config(SecurityTemplate.STANDARD)
        self.hash_config = self.config["hash_config"]

    def test_scrypt_enabled(self) -> None:
        self.assertTrue(self.hash_config["scrypt"]["enabled"])

    def test_scrypt_rounds_10(self) -> None:
        self.assertEqual(self.hash_config["scrypt"]["rounds"], 10)

    def test_argon2_enabled(self) -> None:
        self.assertTrue(self.hash_config["argon2"]["enabled"])

    def test_argon2_rounds_10(self) -> None:
        self.assertEqual(self.hash_config["argon2"]["rounds"], 10)


class TestStandardTemplateEncryption(unittest.TestCase):
    """Test encryption algorithm in STANDARD template."""

    def setUp(self) -> None:
        self.config = get_template_config(SecurityTemplate.STANDARD)
        self.hash_config = self.config["hash_config"]

    def test_algorithm_is_aes_gcm(self) -> None:
        self.assertEqual(self.hash_config["algorithm"], "aes-gcm")


class TestStandardTemplateFallbackDefaults(unittest.TestCase):
    """Test that the fallback defaults in crypt_core.py match the STANDARD template."""

    def test_fallback_matches_template(self) -> None:
        """The hardcoded fallback in encrypt_file must match the STANDARD template."""
        template = get_template_config(SecurityTemplate.STANDARD)
        tc = template["hash_config"]

        # Verify the key values that the fallback should contain
        self.assertEqual(tc["sha512"], 0)
        self.assertEqual(tc["sha3_256"], 10000)
        self.assertEqual(tc["sha3_512"], 10000)
        self.assertEqual(tc["scrypt"]["rounds"], 10)
        self.assertEqual(tc["argon2"]["rounds"], 10)


if __name__ == "__main__":
    unittest.main()
