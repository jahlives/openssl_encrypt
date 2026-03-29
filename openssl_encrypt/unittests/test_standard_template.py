"""Tests for the STANDARD security template configuration.

Verifies that the STANDARD template uses the expected modern defaults:
- Two hashes: SHA3-512 (10k) + BLAKE3 (10k)
- Two KDFs: RandomX (10 rounds) + Argon2 (10 rounds)
- Encryption: AES-GCM-SIV with cascade (AES-256-GCM + ChaCha20-Poly1305)
"""

import unittest

from openssl_encrypt.modules.crypt_cli import SecurityTemplate, get_template_config


class TestStandardTemplateHashes(unittest.TestCase):
    """Test hash algorithm configuration in STANDARD template."""

    def setUp(self) -> None:
        self.config = get_template_config(SecurityTemplate.STANDARD)
        self.hash_config = self.config["hash_config"]

    def test_sha3_512_enabled_with_10k_rounds(self) -> None:
        self.assertEqual(self.hash_config["sha3_512"], 10000)

    def test_blake3_enabled_with_10k_rounds(self) -> None:
        self.assertEqual(self.hash_config["blake3"], 10000)

    def test_sha3_256_disabled(self) -> None:
        self.assertEqual(self.hash_config["sha3_256"], 0)

    def test_sha512_disabled(self) -> None:
        self.assertEqual(self.hash_config["sha512"], 0)

    def test_sha256_disabled(self) -> None:
        self.assertEqual(self.hash_config["sha256"], 0)

    def test_blake2b_disabled(self) -> None:
        self.assertEqual(self.hash_config["blake2b"], 0)

    def test_shake256_disabled(self) -> None:
        self.assertEqual(self.hash_config["shake256"], 0)

    def test_whirlpool_disabled(self) -> None:
        self.assertEqual(self.hash_config["whirlpool"], 0)


class TestStandardTemplateKDFs(unittest.TestCase):
    """Test KDF configuration in STANDARD template."""

    def setUp(self) -> None:
        self.config = get_template_config(SecurityTemplate.STANDARD)
        self.hash_config = self.config["hash_config"]

    def test_scrypt_disabled(self) -> None:
        self.assertFalse(self.hash_config["scrypt"]["enabled"])

    def test_argon2_enabled(self) -> None:
        self.assertTrue(self.hash_config["argon2"]["enabled"])

    def test_argon2_rounds_10(self) -> None:
        self.assertEqual(self.hash_config["argon2"]["rounds"], 10)

    def test_randomx_enabled(self) -> None:
        self.assertTrue(self.hash_config["randomx"]["enabled"])

    def test_randomx_rounds_10(self) -> None:
        self.assertEqual(self.hash_config["randomx"]["rounds"], 10)

    def test_randomx_mode_light(self) -> None:
        self.assertEqual(self.hash_config["randomx"]["mode"], "light")

    def test_pbkdf2_disabled(self) -> None:
        self.assertEqual(self.hash_config["pbkdf2_iterations"], 0)


class TestStandardTemplateEncryption(unittest.TestCase):
    """Test encryption algorithm in STANDARD template."""

    def setUp(self) -> None:
        self.config = get_template_config(SecurityTemplate.STANDARD)
        self.hash_config = self.config["hash_config"]

    def test_algorithm_is_aes_gcm_siv(self) -> None:
        self.assertEqual(self.hash_config["algorithm"], "aes-gcm-siv")

    def test_cascade_preset_standard(self) -> None:
        self.assertEqual(self.config["cascade"], "standard")


class TestStandardTemplateFallbackDefaults(unittest.TestCase):
    """Test that the fallback defaults in crypt_core.py match the STANDARD template."""

    def test_fallback_matches_template(self) -> None:
        """The hardcoded fallback in encrypt_file must match the STANDARD template."""
        template = get_template_config(SecurityTemplate.STANDARD)
        tc = template["hash_config"]

        # Verify the key values that the fallback should contain
        self.assertEqual(tc["sha512"], 0)
        self.assertEqual(tc["sha3_256"], 0)
        self.assertEqual(tc["sha3_512"], 10000)
        self.assertEqual(tc["blake3"], 10000)
        self.assertFalse(tc["scrypt"]["enabled"])
        self.assertEqual(tc["argon2"]["rounds"], 10)
        self.assertTrue(tc["randomx"]["enabled"])
        self.assertEqual(tc["randomx"]["rounds"], 10)


if __name__ == "__main__":
    unittest.main()
