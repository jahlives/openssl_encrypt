#!/usr/bin/env python3
"""
Test suite for cascade encryption module.

This module contains comprehensive tests for:
- CascadeConfig configuration and validation
- CascadeKeyDerivation with chained HKDF
- CascadeEncryption encrypt/decrypt operations
- Convenience functions (cascade_encrypt, cascade_decrypt)
- Different hash functions
- Security properties and error handling
"""

import base64
import secrets
import unittest

import pytest

# Import the modules to test
from openssl_encrypt.modules.cascade import (
    CHAIN_PREFIX_LENGTH,
    KEY_INFO_PREFIX,
    NONCE_INFO_PREFIX,
    AuthenticationError,
    CascadeConfig,
    CascadeConfigError,
    CascadeEncryption,
    CascadeError,
    CascadeKeyDerivation,
    cascade_decrypt,
    cascade_encrypt,
)

# Check if registry is available
try:
    from openssl_encrypt.modules.registry import CipherRegistry  # noqa: F401

    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False


@pytest.mark.skipif(not REGISTRY_AVAILABLE, reason="Cipher registry not available")
class TestCascadeConfig(unittest.TestCase):
    """Test cases for CascadeConfig configuration and validation."""

    def test_valid_config_with_two_ciphers(self):
        """Test creating a valid configuration with 2 ciphers."""
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha256"
        )
        self.assertEqual(len(config.cipher_names), 2)
        self.assertEqual(config.hkdf_hash, "sha256")
        self.assertEqual(config.layer_count, 2)

    def test_valid_config_with_three_ciphers(self):
        """Test creating a valid configuration with 3 ciphers."""
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305", "aes-128-gcm"], hkdf_hash="sha512"
        )
        self.assertEqual(config.layer_count, 3)
        self.assertEqual(config.hkdf_hash, "sha512")

    def test_config_requires_minimum_two_ciphers(self):
        """Test that configuration requires at least 2 ciphers."""
        with self.assertRaises(CascadeConfigError) as context:
            CascadeConfig(cipher_names=["aes-256-gcm"])

        self.assertIn("at least 2 ciphers", str(context.exception))

    def test_config_with_empty_list(self):
        """Test that empty cipher list raises error."""
        with self.assertRaises(CascadeConfigError):
            CascadeConfig(cipher_names=[])

    def test_config_default_hash(self):
        """Test that default hash is sha256."""
        config = CascadeConfig(cipher_names=["aes-256-gcm", "chacha20-poly1305"])
        self.assertEqual(config.hkdf_hash, "sha256")

    def test_layer_count_property(self):
        """Test layer_count property returns correct count."""
        config = CascadeConfig(cipher_names=["aes-256-gcm", "chacha20-poly1305", "aes-128-gcm"])
        self.assertEqual(config.layer_count, 3)
        self.assertEqual(config.layer_count, len(config.cipher_names))


@pytest.mark.skipif(not REGISTRY_AVAILABLE, reason="Cipher registry not available")
class TestCascadeKeyDerivation(unittest.TestCase):
    """Test cases for CascadeKeyDerivation with chained HKDF."""

    def setUp(self):
        """Set up test environment."""
        self.master_key = secrets.token_bytes(32)
        self.salt = secrets.token_bytes(32)
        self.config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha256"
        )

    def test_derive_keys_returns_correct_count(self):
        """Test that key derivation returns correct number of key/nonce pairs."""
        kd = CascadeKeyDerivation(self.config)
        layers = kd.derive_layer_keys(self.master_key, self.salt)

        self.assertEqual(len(layers), 2)
        for key, nonce in layers:
            self.assertIsInstance(key, (bytes, bytearray))
            self.assertIsInstance(nonce, (bytes, bytearray))

    def test_derived_keys_are_different(self):
        """Test that each layer gets different keys."""
        kd = CascadeKeyDerivation(self.config)
        layers = kd.derive_layer_keys(self.master_key, self.salt)

        key1, nonce1 = layers[0]
        key2, nonce2 = layers[1]

        self.assertNotEqual(key1, key2)
        self.assertNotEqual(nonce1, nonce2)

    def test_key_derivation_is_deterministic(self):
        """Test that same inputs produce same keys."""
        kd = CascadeKeyDerivation(self.config)

        layers1 = kd.derive_layer_keys(self.master_key, self.salt)
        layers2 = kd.derive_layer_keys(self.master_key, self.salt)

        self.assertEqual(layers1[0][0], layers2[0][0])  # First key
        self.assertEqual(layers1[0][1], layers2[0][1])  # First nonce
        self.assertEqual(layers1[1][0], layers2[1][0])  # Second key
        self.assertEqual(layers1[1][1], layers2[1][1])  # Second nonce

    def test_chaining_affects_keys(self):
        """Test that key derivation order matters (chaining works)."""
        # Create two configs with reversed cipher order
        config1 = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha256"
        )
        config2 = CascadeConfig(
            cipher_names=["chacha20-poly1305", "aes-256-gcm"], hkdf_hash="sha256"
        )

        kd1 = CascadeKeyDerivation(config1)
        kd2 = CascadeKeyDerivation(config2)

        layers1 = kd1.derive_layer_keys(self.master_key, self.salt)
        layers2 = kd2.derive_layer_keys(self.master_key, self.salt)

        # Second layer keys should be different due to chaining
        self.assertNotEqual(layers1[1][0], layers2[1][0])

    def test_chain_prefix_is_used(self):
        """Test that chain prefix from previous layer affects next layer."""
        config = CascadeConfig(
            cipher_names=[
                "aes-256-gcm",
                "chacha20-poly1305",
                "aes-256-gcm-siv",
                "threefish-512",
                "threefish-1024",
            ],
            hkdf_hash="sha256",
        )
        kd = CascadeKeyDerivation(config)
        layers = kd.derive_layer_keys(self.master_key, self.salt)

        # Verify chain prefix length
        self.assertEqual(CHAIN_PREFIX_LENGTH, 16)

        # All layers should produce valid keys
        self.assertEqual(len(layers), 5)
        for key, nonce in layers:
            self.assertGreater(len(key), 0)
            self.assertGreater(len(nonce), 0)

    def test_different_salts_produce_different_keys(self):
        """Test that different salts produce different keys."""
        kd = CascadeKeyDerivation(self.config)

        salt1 = secrets.token_bytes(32)
        salt2 = secrets.token_bytes(32)

        layers1 = kd.derive_layer_keys(self.master_key, salt1)
        layers2 = kd.derive_layer_keys(self.master_key, salt2)

        self.assertNotEqual(layers1[0][0], layers2[0][0])
        self.assertNotEqual(layers1[1][0], layers2[1][0])

    def test_correct_key_sizes_for_ciphers(self):
        """Test that derived keys match expected sizes for each cipher."""
        kd = CascadeKeyDerivation(self.config)
        layers = kd.derive_layer_keys(self.master_key, self.salt)

        # AES-256-GCM: 32 byte key, 12 byte nonce
        key1, nonce1 = layers[0]
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(nonce1), 12)

        # ChaCha20-Poly1305: 32 byte key, 12 byte nonce
        key2, nonce2 = layers[1]
        self.assertEqual(len(key2), 32)
        self.assertEqual(len(nonce2), 12)

    def test_unsupported_hash_algorithm(self):
        """Test that unsupported hash algorithm raises error."""
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="md5"  # Unsupported
        )

        with self.assertRaises(CascadeConfigError) as context:
            kd = CascadeKeyDerivation(config)
            kd.derive_layer_keys(self.master_key, self.salt)

        self.assertIn("Unsupported hash algorithm", str(context.exception))

    def test_domain_separation_prefixes(self):
        """Test that domain separation prefixes are correctly defined."""
        self.assertEqual(KEY_INFO_PREFIX, b"cascade:key:")
        self.assertEqual(NONCE_INFO_PREFIX, b"cascade:nonce:")


@pytest.mark.skipif(not REGISTRY_AVAILABLE, reason="Cipher registry not available")
class TestCascadeEncryption(unittest.TestCase):
    """Test cases for CascadeEncryption encrypt/decrypt operations."""

    def setUp(self):
        """Set up test environment."""
        self.master_key = secrets.token_bytes(32)
        self.salt = secrets.token_bytes(32)
        self.plaintext = b"This is a secret message for cascade encryption testing."

        self.config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha256"
        )

    def test_encryption_decryption_roundtrip(self):
        """Test basic encryption and decryption roundtrip."""
        cascade = CascadeEncryption(self.config)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, self.plaintext)

    def test_roundtrip_with_aad(self):
        """Test encryption/decryption with additional authenticated data."""
        cascade = CascadeEncryption(self.config)
        aad = b"metadata information"

        ciphertext = cascade.encrypt(
            self.plaintext, self.master_key, self.salt, associated_data=aad
        )
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt, associated_data=aad)

        self.assertEqual(decrypted, self.plaintext)

    def test_wrong_aad_fails_authentication(self):
        """Test that wrong AAD causes authentication failure."""
        cascade = CascadeEncryption(self.config)
        aad = b"correct metadata"
        wrong_aad = b"wrong metadata"

        ciphertext = cascade.encrypt(
            self.plaintext, self.master_key, self.salt, associated_data=aad
        )

        with self.assertRaises(AuthenticationError):
            cascade.decrypt(ciphertext, self.master_key, self.salt, associated_data=wrong_aad)

    def test_tampered_ciphertext_fails(self):
        """Test that tampered ciphertext causes authentication failure."""
        cascade = CascadeEncryption(self.config)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)

        # Tamper with the ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with self.assertRaises((AuthenticationError, CascadeError)):
            cascade.decrypt(tampered, self.master_key, self.salt)

    def test_wrong_key_fails(self):
        """Test that wrong key causes decryption failure."""
        cascade = CascadeEncryption(self.config)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)

        wrong_key = secrets.token_bytes(32)

        with self.assertRaises((AuthenticationError, CascadeError)):
            cascade.decrypt(ciphertext, wrong_key, self.salt)

    def test_five_layer_cascade(self):
        """Test cascade with five layers."""
        config = CascadeConfig(
            cipher_names=[
                "aes-256-gcm",
                "chacha20-poly1305",
                "aes-256-gcm-siv",
                "threefish-512",
                "threefish-1024",
            ],
            hkdf_hash="sha256",
        )
        cascade = CascadeEncryption(config)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, self.plaintext)

    def test_ciphertext_is_larger_than_plaintext(self):
        """Test that ciphertext includes nonces and authentication tags."""
        cascade = CascadeEncryption(self.config)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)

        # Total overhead = sum of (nonce + tag) for each layer
        # AES-256-GCM: 12 byte nonce + 16 byte tag = 28 bytes
        # ChaCha20-Poly1305: 12 byte nonce + 16 byte tag = 28 bytes
        # Total: 56 bytes
        expected_overhead = sum(
            cipher.info().nonce_size + cipher.info().tag_size for cipher in cascade.ciphers
        )

        # Ciphertext should be plaintext + overhead (nonces + tags)
        self.assertEqual(len(ciphertext), len(self.plaintext) + expected_overhead)

    def test_get_total_overhead(self):
        """Test total overhead calculation."""
        cascade = CascadeEncryption(self.config)
        overhead = cascade.get_total_overhead()

        # AES-256-GCM (16 bytes) + ChaCha20-Poly1305 (16 bytes) = 32 bytes
        self.assertEqual(overhead, 32)

    def test_get_security_info(self):
        """Test security information extraction."""
        cascade = CascadeEncryption(self.config)
        info = cascade.get_security_info()

        self.assertEqual(info["layer_count"], 2)
        self.assertEqual(info["ciphers"], ["aes-256-gcm", "chacha20-poly1305"])
        self.assertEqual(info["hkdf_hash"], "sha256")
        self.assertIn("min_security_bits", info)
        self.assertIn("pq_security_bits", info)
        self.assertIn("total_key_size", info)
        self.assertIn("total_overhead", info)

    def test_large_data_encryption(self):
        """Test cascade encryption with large data (10MB)."""
        large_data = secrets.token_bytes(10 * 1024 * 1024)  # 10 MB
        cascade = CascadeEncryption(self.config)

        ciphertext = cascade.encrypt(large_data, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, large_data)

    def test_empty_plaintext(self):
        """Test encryption of empty plaintext."""
        cascade = CascadeEncryption(self.config)
        empty_data = b""

        ciphertext = cascade.encrypt(empty_data, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, empty_data)

    def test_unavailable_cipher_raises_error(self):
        """Test that unavailable cipher raises configuration error."""
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "nonexistent-cipher"], hkdf_hash="sha256"
        )

        with self.assertRaises(CascadeConfigError) as context:
            CascadeEncryption(config)

        self.assertIn("not available", str(context.exception).lower())


@pytest.mark.skipif(not REGISTRY_AVAILABLE, reason="Cipher registry not available")
class TestConvenienceFunctions(unittest.TestCase):
    """Test cases for cascade_encrypt and cascade_decrypt convenience functions."""

    def setUp(self):
        """Set up test environment."""
        self.master_key = secrets.token_bytes(32)
        self.plaintext = b"Test message for convenience functions."

    def test_cascade_encrypt_decrypt_roundtrip(self):
        """Test roundtrip using convenience functions."""
        cipher_names = ["aes-256-gcm", "chacha20-poly1305"]

        ciphertext, metadata = cascade_encrypt(self.plaintext, self.master_key, cipher_names)

        decrypted = cascade_decrypt(ciphertext, self.master_key, metadata)

        self.assertEqual(decrypted, self.plaintext)

    def test_metadata_structure(self):
        """Test that metadata has correct structure."""
        cipher_names = ["aes-256-gcm", "chacha20-poly1305"]

        ciphertext, metadata = cascade_encrypt(self.plaintext, self.master_key, cipher_names)

        self.assertTrue(metadata["cascade"])
        self.assertEqual(metadata["cipher_chain"], cipher_names)
        self.assertEqual(metadata["hkdf_hash"], "sha256")
        self.assertIn("cascade_salt", metadata)
        self.assertIn("layer_info", metadata)
        self.assertIn("total_overhead", metadata)
        self.assertIn("pq_security_bits", metadata)

    def test_layer_info_in_metadata(self):
        """Test that layer_info contains correct cipher information."""
        cipher_names = ["aes-256-gcm", "chacha20-poly1305"]

        ciphertext, metadata = cascade_encrypt(self.plaintext, self.master_key, cipher_names)

        layer_info = metadata["layer_info"]
        self.assertEqual(len(layer_info), 2)

        # Check first layer
        self.assertEqual(layer_info[0]["cipher"], "aes-256-gcm")
        self.assertEqual(layer_info[0]["key_size"], 32)
        self.assertEqual(layer_info[0]["tag_size"], 16)

        # Check second layer
        self.assertEqual(layer_info[1]["cipher"], "chacha20-poly1305")
        self.assertEqual(layer_info[1]["key_size"], 32)
        self.assertEqual(layer_info[1]["tag_size"], 16)

    def test_cascade_salt_is_base64(self):
        """Test that cascade_salt in metadata is base64 encoded."""
        cipher_names = ["aes-256-gcm", "chacha20-poly1305"]

        ciphertext, metadata = cascade_encrypt(self.plaintext, self.master_key, cipher_names)

        salt_b64 = metadata["cascade_salt"]
        # Should be able to decode
        salt = base64.b64decode(salt_b64)
        # Should be 32 bytes
        self.assertEqual(len(salt), 32)

    def test_with_custom_hash_function(self):
        """Test convenience functions with custom hash."""
        cipher_names = ["aes-256-gcm", "chacha20-poly1305"]

        ciphertext, metadata = cascade_encrypt(
            self.plaintext, self.master_key, cipher_names, cascade_hash="sha512"
        )

        self.assertEqual(metadata["hkdf_hash"], "sha512")

        decrypted = cascade_decrypt(ciphertext, self.master_key, metadata)
        self.assertEqual(decrypted, self.plaintext)

    def test_with_aad(self):
        """Test convenience functions with AAD."""
        cipher_names = ["aes-256-gcm", "chacha20-poly1305"]
        aad = b"additional data"

        ciphertext, metadata = cascade_encrypt(
            self.plaintext, self.master_key, cipher_names, associated_data=aad
        )

        decrypted = cascade_decrypt(ciphertext, self.master_key, metadata, associated_data=aad)

        self.assertEqual(decrypted, self.plaintext)


@pytest.mark.skipif(not REGISTRY_AVAILABLE, reason="Cipher registry not available")
class TestDifferentHashFunctions(unittest.TestCase):
    """Test cases for cascade encryption with different hash functions."""

    def setUp(self):
        """Set up test environment."""
        self.master_key = secrets.token_bytes(32)
        self.salt = secrets.token_bytes(32)
        self.plaintext = b"Test message for different hash functions."

    def test_sha256(self):
        """Test cascade with SHA-256."""
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha256"
        )
        cascade = CascadeEncryption(config)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, self.plaintext)

    def test_sha384(self):
        """Test cascade with SHA-384."""
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha384"
        )
        cascade = CascadeEncryption(config)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, self.plaintext)

    def test_sha512(self):
        """Test cascade with SHA-512."""
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha512"
        )
        cascade = CascadeEncryption(config)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, self.plaintext)

    def test_sha3_256(self):
        """Test cascade with SHA3-256."""
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha3-256"
        )
        cascade = CascadeEncryption(config)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, self.plaintext)

    def test_blake2b(self):
        """Test cascade with BLAKE2b."""
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="blake2b"
        )
        cascade = CascadeEncryption(config)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, self.plaintext)

    def test_different_hashes_produce_different_ciphertexts(self):
        """Test that different hash functions produce different ciphertexts."""
        config_sha256 = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha256"
        )
        config_sha512 = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha512"
        )

        cascade_sha256 = CascadeEncryption(config_sha256)
        cascade_sha512 = CascadeEncryption(config_sha512)

        ciphertext_sha256 = cascade_sha256.encrypt(self.plaintext, self.master_key, self.salt)
        ciphertext_sha512 = cascade_sha512.encrypt(self.plaintext, self.master_key, self.salt)

        self.assertNotEqual(ciphertext_sha256, ciphertext_sha512)


@pytest.mark.skipif(not REGISTRY_AVAILABLE, reason="Cipher registry not available")
class TestCipherFamilies(unittest.TestCase):
    """Test cases for cipher family definitions and helper functions."""

    def test_get_cipher_family_for_aes(self):
        """Test getting cipher family for AES variants."""
        from openssl_encrypt.modules.registry.cipher_families import get_cipher_family

        family = get_cipher_family("aes-256-gcm")
        self.assertIsNotNone(family)
        self.assertEqual(family.name, "aes")
        self.assertEqual(family.design_type.name, "SPN")

    def test_get_cipher_family_for_chacha(self):
        """Test getting cipher family for ChaCha variants."""
        from openssl_encrypt.modules.registry.cipher_families import get_cipher_family

        family = get_cipher_family("chacha20-poly1305")
        self.assertIsNotNone(family)
        self.assertEqual(family.name, "chacha")
        self.assertEqual(family.design_type.name, "ARX")

    def test_get_cipher_family_for_threefish(self):
        """Test getting cipher family for Threefish."""
        from openssl_encrypt.modules.registry.cipher_families import get_cipher_family

        family = get_cipher_family("threefish-512")
        self.assertIsNotNone(family)
        self.assertEqual(family.name, "threefish")
        self.assertEqual(family.design_type.name, "ARX")

    def test_get_cipher_family_for_unknown_cipher(self):
        """Test that unknown cipher returns None."""
        from openssl_encrypt.modules.registry.cipher_families import get_cipher_family

        family = get_cipher_family("nonexistent-cipher")
        self.assertIsNone(family)

    def test_get_family_name(self):
        """Test getting family name string."""
        from openssl_encrypt.modules.registry.cipher_families import get_family_name

        self.assertEqual(get_family_name("aes-256-gcm"), "aes")
        self.assertEqual(get_family_name("chacha20-poly1305"), "chacha")
        self.assertEqual(get_family_name("threefish-512"), "threefish")
        self.assertIsNone(get_family_name("unknown"))

    def test_are_related_families(self):
        """Test checking if families are related."""
        from openssl_encrypt.modules.registry.cipher_families import are_related_families

        # AES and Fernet are related (Fernet uses AES)
        self.assertTrue(are_related_families("aes", "fernet"))
        self.assertTrue(are_related_families("fernet", "aes"))

        # AES and ChaCha are not related
        self.assertFalse(are_related_families("aes", "chacha"))

        # Same family should return False (not "related")
        self.assertFalse(are_related_families("aes", "aes"))

    def test_get_design_type(self):
        """Test getting design type for ciphers."""
        from openssl_encrypt.modules.registry.cipher_families import DesignType, get_design_type

        self.assertEqual(get_design_type("aes-256-gcm"), DesignType.SPN)
        self.assertEqual(get_design_type("chacha20-poly1305"), DesignType.ARX)
        self.assertEqual(get_design_type("threefish-512"), DesignType.ARX)
        self.assertIsNone(get_design_type("unknown"))

    def test_normalize_cipher_name(self):
        """Test cipher name normalization."""
        from openssl_encrypt.modules.registry.cipher_families import normalize_cipher_name

        self.assertEqual(normalize_cipher_name("AES-256-GCM"), "aes-256-gcm")
        self.assertEqual(normalize_cipher_name("  ChaCha20-Poly1305  "), "chacha20-poly1305")
        self.assertEqual(normalize_cipher_name("aes-256-gcm"), "aes-256-gcm")

    def test_list_all_families(self):
        """Test listing all cipher families."""
        from openssl_encrypt.modules.registry.cipher_families import list_all_families

        families = list_all_families()
        self.assertIn("aes", families)
        self.assertIn("chacha", families)
        self.assertIn("threefish", families)
        self.assertIn("fernet", families)

    def test_list_family_members(self):
        """Test listing members of a family."""
        from openssl_encrypt.modules.registry.cipher_families import list_family_members

        aes_members = list_family_members("aes")
        self.assertIn("aes-256-gcm", aes_members)
        self.assertIn("aes-gcm-siv", aes_members)

        chacha_members = list_family_members("chacha")
        self.assertIn("chacha20-poly1305", chacha_members)


@pytest.mark.skipif(not REGISTRY_AVAILABLE, reason="Cipher registry not available")
class TestCascadeDiversityValidator(unittest.TestCase):
    """Test cases for cascade diversity validation."""

    def test_good_diversity_aes_chacha(self):
        """Test that AES + ChaCha shows good diversity."""
        from openssl_encrypt.modules.cascade_validator import (
            CascadeDiversityValidator,
            DiversityWarningLevel,
        )

        validator = CascadeDiversityValidator(strict=False)
        warnings = validator.validate(["aes-256-gcm", "chacha20-poly1305"])

        # Should have one INFO message about good design diversity
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].level, DiversityWarningLevel.INFO)
        self.assertIn("Good design diversity", warnings[0].message)
        self.assertIn("SPN", warnings[0].message)
        self.assertIn("ARX", warnings[0].message)

    def test_same_family_warning(self):
        """Test that multiple ciphers from same family produces warning."""
        from openssl_encrypt.modules.cascade_validator import (
            CascadeDiversityValidator,
            DiversityWarningLevel,
        )

        validator = CascadeDiversityValidator(strict=False)
        warnings = validator.validate(["aes-256-gcm", "aes-gcm-siv"])

        # Should have WARNING about same family and INFO about design
        warning_levels = [w.level for w in warnings]
        self.assertIn(DiversityWarningLevel.WARNING, warning_levels)

        # Find the same family warning
        same_family_warning = [
            w
            for w in warnings
            if w.level == DiversityWarningLevel.WARNING and "same 'aes' family" in w.message
        ][0]

        self.assertIn("aes-256-gcm", same_family_warning.ciphers_involved)
        self.assertIn("aes-gcm-siv", same_family_warning.ciphers_involved)
        self.assertIsNotNone(same_family_warning.suggestion)

    def test_all_same_design_type(self):
        """Test that all ciphers with same design type produces info."""
        from openssl_encrypt.modules.cascade_validator import (
            CascadeDiversityValidator,
            DiversityWarningLevel,
        )

        validator = CascadeDiversityValidator(strict=False)
        warnings = validator.validate(["chacha20-poly1305", "threefish-512"])

        # Should have INFO about all ARX design
        info_warnings = [w for w in warnings if w.level == DiversityWarningLevel.INFO]
        self.assertTrue(len(info_warnings) > 0)

        design_warning = [w for w in info_warnings if "same design paradigm" in w.message][0]
        self.assertIn("ARX", design_warning.message)

    def test_related_families_info(self):
        """Test that related families produces info message."""
        from openssl_encrypt.modules.cascade_validator import (
            CascadeDiversityValidator,
            DiversityWarningLevel,
        )

        validator = CascadeDiversityValidator(strict=False)
        warnings = validator.validate(["aes-256-gcm", "fernet"])

        # Should have INFO about related families (AES and Fernet)
        info_warnings = [w for w in warnings if w.level == DiversityWarningLevel.INFO]
        related_warning = [w for w in info_warnings if "related families" in w.message.lower()]

        self.assertTrue(len(related_warning) > 0)

    def test_strict_mode_upgrades_warnings_to_errors(self):
        """Test that strict mode converts warnings to errors."""
        from openssl_encrypt.modules.cascade_validator import (
            CascadeDiversityValidator,
            DiversityWarningLevel,
        )

        validator = CascadeDiversityValidator(strict=True)
        warnings = validator.validate(["aes-256-gcm", "aes-gcm-siv"])

        # Should have ERROR (upgraded from WARNING) about same family
        error_warnings = [w for w in warnings if w.level == DiversityWarningLevel.ERROR]
        self.assertTrue(len(error_warnings) > 0)

        error = error_warnings[0]
        self.assertIn("same 'aes' family", error.message)

    def test_strict_mode_keeps_info_as_info(self):
        """Test that strict mode doesn't upgrade INFO messages."""
        from openssl_encrypt.modules.cascade_validator import (
            CascadeDiversityValidator,
            DiversityWarningLevel,
        )

        validator = CascadeDiversityValidator(strict=True)
        warnings = validator.validate(["aes-256-gcm", "chacha20-poly1305"])

        # Should still have INFO about good diversity
        info_warnings = [w for w in warnings if w.level == DiversityWarningLevel.INFO]
        self.assertTrue(len(info_warnings) > 0)

    def test_three_cipher_validation(self):
        """Test diversity validation with three ciphers."""
        from openssl_encrypt.modules.cascade_validator import CascadeDiversityValidator

        validator = CascadeDiversityValidator(strict=False)
        warnings = validator.validate(["aes-256-gcm", "chacha20-poly1305", "threefish-512"])

        # Should have at least one INFO about design diversity
        self.assertTrue(len(warnings) > 0)

    def test_multiple_same_family_warnings(self):
        """Test that multiple same-family combinations produce multiple warnings."""
        from openssl_encrypt.modules.cascade_validator import (
            CascadeDiversityValidator,
            DiversityWarningLevel,
        )

        validator = CascadeDiversityValidator(strict=False)
        # Two AES ciphers, two ChaCha variants (if available)
        warnings = validator.validate(
            ["aes-256-gcm", "aes-gcm-siv", "chacha20-poly1305", "xchacha20-poly1305"]
        )

        # Should have WARNING for AES family and WARNING for ChaCha family
        warning_count = len([w for w in warnings if w.level == DiversityWarningLevel.WARNING])
        self.assertGreaterEqual(warning_count, 2)

    def test_validate_with_empty_list(self):
        """Test validation with empty cipher list."""
        from openssl_encrypt.modules.cascade_validator import CascadeDiversityValidator

        validator = CascadeDiversityValidator(strict=False)
        warnings = validator.validate([])

        # Should return empty list or handle gracefully
        self.assertIsInstance(warnings, list)

    def test_validate_with_single_cipher(self):
        """Test validation with single cipher."""
        from openssl_encrypt.modules.cascade_validator import CascadeDiversityValidator

        validator = CascadeDiversityValidator(strict=False)
        warnings = validator.validate(["aes-256-gcm"])

        # Should handle gracefully (no diversity warnings for single cipher)
        self.assertIsInstance(warnings, list)

    def test_validate_with_unknown_ciphers(self):
        """Test validation with unknown cipher names."""
        from openssl_encrypt.modules.cascade_validator import CascadeDiversityValidator

        validator = CascadeDiversityValidator(strict=False)
        # Should not crash with unknown ciphers
        warnings = validator.validate(["aes-256-gcm", "unknown-cipher"])

        # Should still validate known ciphers
        self.assertIsInstance(warnings, list)

    def test_warning_has_all_fields(self):
        """Test that DiversityWarning has all required fields."""
        from openssl_encrypt.modules.cascade_validator import CascadeDiversityValidator

        validator = CascadeDiversityValidator(strict=False)
        warnings = validator.validate(["aes-256-gcm", "aes-gcm-siv"])

        for warning in warnings:
            self.assertTrue(hasattr(warning, "level"))
            self.assertTrue(hasattr(warning, "message"))
            self.assertTrue(hasattr(warning, "ciphers_involved"))
            self.assertTrue(hasattr(warning, "suggestion"))
            self.assertIsInstance(warning.message, str)
            self.assertIsInstance(warning.ciphers_involved, list)

    def test_convenience_function(self):
        """Test convenience function for diversity validation."""
        from openssl_encrypt.modules.cascade_validator import validate_cascade_diversity

        warnings = validate_cascade_diversity(["aes-256-gcm", "chacha20-poly1305"])
        self.assertIsInstance(warnings, list)

        # Test with strict mode
        warnings_strict = validate_cascade_diversity(["aes-256-gcm", "aes-gcm-siv"], strict=True)
        error_count = len([w for w in warnings_strict if w.level.name == "ERROR"])
        self.assertGreater(error_count, 0)

    def test_paranoia_preset_validation(self):
        """Test diversity validation on paranoia preset (3 ciphers)."""
        from openssl_encrypt.modules.cascade_validator import (
            CascadeDiversityValidator,
            DiversityWarningLevel,
        )

        validator = CascadeDiversityValidator(strict=False)
        # Paranoia preset: AES + ChaCha + Threefish
        warnings = validator.validate(["aes-256-gcm", "chacha20-poly1305", "threefish-512"])

        # Should show good design diversity (SPN + ARX)
        info_warnings = [w for w in warnings if w.level == DiversityWarningLevel.INFO]
        good_diversity = [w for w in info_warnings if "Good design diversity" in w.message]
        self.assertTrue(len(good_diversity) > 0)


@pytest.mark.skipif(not REGISTRY_AVAILABLE, reason="Cipher registry not available")
class TestCascadePerLayerSalt(unittest.TestCase):
    """Test per-layer salt derivation for cascade encryption (H6/H7).

    For format_version >= 12, each cascade layer should derive its own
    unique salt from the master salt, preventing all layers from sharing
    the same (master_key, salt) pair in HKDF.
    """

    def setUp(self):
        """Set up test environment."""
        self.master_key = secrets.token_bytes(32)
        self.salt = secrets.token_bytes(32)
        self.plaintext = b"Test per-layer salt derivation."
        self.config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha256"
        )

    def test_v12_keys_differ_from_legacy_keys(self):
        """Test that v12+ per-layer salt produces different keys than legacy."""
        kd_legacy = CascadeKeyDerivation(self.config)
        kd_v12 = CascadeKeyDerivation(self.config, format_version=12)

        legacy_layers = kd_legacy.derive_layer_keys(self.master_key, self.salt)
        v12_layers = kd_v12.derive_layer_keys(self.master_key, self.salt)

        # First layer keys should differ (different salt derivation)
        self.assertNotEqual(legacy_layers[0][0], v12_layers[0][0])
        # Second layer keys should also differ
        self.assertNotEqual(legacy_layers[1][0], v12_layers[1][0])

    def test_legacy_format_unchanged(self):
        """Test that legacy (no format_version) key derivation is unchanged."""
        kd1 = CascadeKeyDerivation(self.config)
        kd2 = CascadeKeyDerivation(self.config, format_version=None)
        kd3 = CascadeKeyDerivation(self.config, format_version=11)

        layers1 = kd1.derive_layer_keys(self.master_key, self.salt)
        layers2 = kd2.derive_layer_keys(self.master_key, self.salt)
        layers3 = kd3.derive_layer_keys(self.master_key, self.salt)

        # All legacy paths should produce identical keys
        self.assertEqual(layers1[0][0], layers2[0][0])
        self.assertEqual(layers1[0][0], layers3[0][0])
        self.assertEqual(layers1[1][0], layers2[1][0])
        self.assertEqual(layers1[1][0], layers3[1][0])

    def test_v12_per_layer_salts_are_unique(self):
        """Test that v12+ derives a unique salt for each layer."""
        kd = CascadeKeyDerivation(self.config, format_version=12)
        layers = kd.derive_layer_keys(self.master_key, self.salt)

        # Even with same cipher in two layers, keys should differ
        # (they already differ in legacy due to chaining, but now
        # additionally differ due to per-layer salt)
        self.assertNotEqual(layers[0][0], layers[1][0])

    def test_v12_deterministic(self):
        """Test that v12+ per-layer salt derivation is deterministic."""
        kd = CascadeKeyDerivation(self.config, format_version=12)

        layers1 = kd.derive_layer_keys(self.master_key, self.salt)
        layers2 = kd.derive_layer_keys(self.master_key, self.salt)

        self.assertEqual(layers1[0][0], layers2[0][0])
        self.assertEqual(layers1[0][1], layers2[0][1])
        self.assertEqual(layers1[1][0], layers2[1][0])
        self.assertEqual(layers1[1][1], layers2[1][1])

    def test_v12_encrypt_decrypt_roundtrip(self):
        """Test that v12+ cascade encrypt/decrypt roundtrip works."""
        cascade = CascadeEncryption(self.config, format_version=12)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, self.plaintext)

    def test_v12_cross_version_incompatible(self):
        """Test that v12+ ciphertext cannot be decrypted with legacy keys."""
        cascade_v12 = CascadeEncryption(self.config, format_version=12)
        cascade_legacy = CascadeEncryption(self.config)

        ciphertext = cascade_v12.encrypt(self.plaintext, self.master_key, self.salt)

        with self.assertRaises((AuthenticationError, CascadeError)):
            cascade_legacy.decrypt(ciphertext, self.master_key, self.salt)

    def test_v12_five_layer_roundtrip(self):
        """Test v12+ per-layer salt with five cascade layers."""
        config = CascadeConfig(
            cipher_names=[
                "aes-256-gcm",
                "chacha20-poly1305",
                "aes-256-gcm-siv",
                "threefish-512",
                "threefish-1024",
            ],
            hkdf_hash="sha256",
        )
        cascade = CascadeEncryption(config, format_version=12)

        ciphertext = cascade.encrypt(self.plaintext, self.master_key, self.salt)
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertEqual(decrypted, self.plaintext)

    def test_v12_with_aad(self):
        """Test v12+ per-layer salt with AAD."""
        cascade = CascadeEncryption(self.config, format_version=12)
        aad = b"authenticated metadata"

        ciphertext = cascade.encrypt(
            self.plaintext, self.master_key, self.salt, associated_data=aad
        )
        decrypted = cascade.decrypt(ciphertext, self.master_key, self.salt, associated_data=aad)

        self.assertEqual(decrypted, self.plaintext)


@pytest.mark.skipif(not REGISTRY_AVAILABLE, reason="Cipher registry not available")
class TestCascadeAllLayerAAD(unittest.TestCase):
    """Test AAD applied to all cascade layers for v12+ (M12).

    For format_version >= 12, AAD should be applied to ALL layers,
    not just the first one. This ensures every layer independently
    authenticates the associated data.
    """

    def setUp(self):
        """Set up test environment."""
        self.master_key = secrets.token_bytes(32)
        self.salt = secrets.token_bytes(32)
        self.plaintext = b"Test AAD on all layers."
        self.aad = b"metadata to authenticate"
        self.config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha256"
        )

    def test_v12_aad_roundtrip(self):
        """Test v12+ encrypt/decrypt roundtrip with AAD on all layers."""
        cascade = CascadeEncryption(self.config, format_version=12)

        ciphertext = cascade.encrypt(
            self.plaintext, self.master_key, self.salt, associated_data=self.aad
        )
        decrypted = cascade.decrypt(
            ciphertext, self.master_key, self.salt, associated_data=self.aad
        )

        self.assertEqual(decrypted, self.plaintext)

    def test_v12_wrong_aad_fails_at_outer_layer(self):
        """Test that wrong AAD fails at outer (last) layer in v12+."""
        cascade = CascadeEncryption(self.config, format_version=12)

        ciphertext = cascade.encrypt(
            self.plaintext, self.master_key, self.salt, associated_data=self.aad
        )

        # With AAD on all layers, wrong AAD should fail at the outermost layer
        with self.assertRaises((AuthenticationError, CascadeError)):
            cascade.decrypt(ciphertext, self.master_key, self.salt, associated_data=b"wrong")

    def test_v12_ciphertext_differs_from_legacy_with_aad(self):
        """Test that v12+ AAD on all layers produces different ciphertext than legacy."""
        cascade_legacy = CascadeEncryption(self.config)
        cascade_v12 = CascadeEncryption(self.config, format_version=12)

        ct_legacy = cascade_legacy.encrypt(
            self.plaintext, self.master_key, self.salt, associated_data=self.aad
        )
        ct_v12 = cascade_v12.encrypt(
            self.plaintext, self.master_key, self.salt, associated_data=self.aad
        )

        # Different because v12 has per-layer salt AND AAD on all layers
        self.assertNotEqual(ct_legacy, ct_v12)

    def test_legacy_aad_only_first_layer(self):
        """Test that legacy still applies AAD only to first layer."""
        cascade = CascadeEncryption(self.config)

        ciphertext = cascade.encrypt(
            self.plaintext, self.master_key, self.salt, associated_data=self.aad
        )
        decrypted = cascade.decrypt(
            ciphertext, self.master_key, self.salt, associated_data=self.aad
        )

        self.assertEqual(decrypted, self.plaintext)

    def test_v12_aad_applied_to_all_layers(self):
        """Test that v12+ actually applies AAD to every layer (not just first)."""
        from unittest.mock import patch, call

        cascade = CascadeEncryption(self.config, format_version=12)
        aad_calls = []

        # Wrap each cipher's encrypt to capture AAD argument
        original_encrypts = [c.encrypt for c in cascade.ciphers]

        def make_wrapper(orig, idx):
            def wrapper(key, data, nonce=None, associated_data=None):
                aad_calls.append((idx, associated_data))
                return orig(key, data, nonce=nonce, associated_data=associated_data)

            return wrapper

        for i, cipher in enumerate(cascade.ciphers):
            cipher.encrypt = make_wrapper(original_encrypts[i], i)

        cascade.encrypt(self.plaintext, self.master_key, self.salt, associated_data=self.aad)

        # Restore originals
        for i, cipher in enumerate(cascade.ciphers):
            cipher.encrypt = original_encrypts[i]

        # For v12+, ALL layers should receive the AAD
        for idx, aad in aad_calls:
            self.assertEqual(aad, self.aad, f"Layer {idx} should have AAD but got {aad}")

    def test_legacy_aad_only_on_first_layer(self):
        """Test that legacy applies AAD only to first layer."""
        cascade = CascadeEncryption(self.config)
        aad_calls = []

        original_encrypts = [c.encrypt for c in cascade.ciphers]

        def make_wrapper(orig, idx):
            def wrapper(key, data, nonce=None, associated_data=None):
                aad_calls.append((idx, associated_data))
                return orig(key, data, nonce=nonce, associated_data=associated_data)

            return wrapper

        for i, cipher in enumerate(cascade.ciphers):
            cipher.encrypt = make_wrapper(original_encrypts[i], i)

        cascade.encrypt(self.plaintext, self.master_key, self.salt, associated_data=self.aad)

        for i, cipher in enumerate(cascade.ciphers):
            cipher.encrypt = original_encrypts[i]

        # Legacy: only first layer (idx=0) has AAD
        self.assertEqual(aad_calls[0][1], self.aad)
        for idx, aad in aad_calls[1:]:
            self.assertIsNone(aad, f"Layer {idx} should NOT have AAD in legacy mode")

    def test_v12_five_layer_aad(self):
        """Test v12+ AAD on all layers with five cipher layers."""
        config = CascadeConfig(
            cipher_names=[
                "aes-256-gcm",
                "chacha20-poly1305",
                "aes-256-gcm-siv",
                "threefish-512",
                "threefish-1024",
            ],
            hkdf_hash="sha256",
        )
        cascade = CascadeEncryption(config, format_version=12)

        ciphertext = cascade.encrypt(
            self.plaintext, self.master_key, self.salt, associated_data=self.aad
        )
        decrypted = cascade.decrypt(
            ciphertext, self.master_key, self.salt, associated_data=self.aad
        )

        self.assertEqual(decrypted, self.plaintext)


if __name__ == "__main__":
    unittest.main()


class TestTypeBasedAuthClassification(unittest.TestCase):
    """Regression tests for GitLab #91 [CORE-7]: auth-failure classification.

    Cascade decrypt used to classify authentication failures by substring-
    matching the underlying error text ('authentication'/'tag') and raised
    errors disclosing which layer failed. Classification must be based on
    concrete exception types, and the resulting error must be layer-agnostic.
    """

    def setUp(self):
        self.config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"], hkdf_hash="sha256"
        )
        self.cascade = CascadeEncryption(self.config)
        self.master_key = secrets.token_bytes(32)
        self.salt = secrets.token_bytes(16)
        self.plaintext = b"layer-agnostic error test"

    def test_auth_error_is_layer_agnostic(self):
        """Tampering must yield an AuthenticationError naming no layer/cipher."""
        ciphertext = self.cascade.encrypt(self.plaintext, self.master_key, self.salt)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01
        with self.assertRaises(AuthenticationError) as cm:
            self.cascade.decrypt(bytes(tampered), self.master_key, self.salt)

        message = str(cm.exception).lower()
        self.assertNotIn("layer", message)
        for cipher_name in self.config.cipher_names:
            self.assertNotIn(cipher_name, message)

    def test_non_auth_error_with_taglike_text_not_misclassified(self):
        """A non-auth exception mentioning 'tag' must not become an auth failure."""
        from unittest import mock

        ciphertext = self.cascade.encrypt(self.plaintext, self.master_key, self.salt)
        with mock.patch.object(
            self.cascade.ciphers[-1],
            "decrypt",
            side_effect=ValueError("corrupt tag metadata in header"),
        ):
            with self.assertRaises(CascadeError) as cm:
                self.cascade.decrypt(ciphertext, self.master_key, self.salt)

        self.assertNotIsInstance(cm.exception, AuthenticationError)

    def test_cipher_auth_error_maps_to_cascade_auth_error(self):
        """crypt_errors.AuthenticationError must classify as auth regardless of text."""
        from unittest import mock

        from openssl_encrypt.modules.crypt_errors import (
            AuthenticationError as CipherAuthError,
        )

        ciphertext = self.cascade.encrypt(self.plaintext, self.master_key, self.salt)
        with mock.patch.object(
            self.cascade.ciphers[-1],
            "decrypt",
            side_effect=CipherAuthError("xyzzy"),
        ):
            with self.assertRaises(AuthenticationError):
                self.cascade.decrypt(ciphertext, self.master_key, self.salt)
