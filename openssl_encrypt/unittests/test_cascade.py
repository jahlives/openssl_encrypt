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
            self.assertIsInstance(key, bytes)
            self.assertIsInstance(nonce, bytes)

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
            cipher_names=["aes-256-gcm", "chacha20-poly1305", "aes-256-ocb3"], hkdf_hash="sha256"
        )
        kd = CascadeKeyDerivation(config)
        layers = kd.derive_layer_keys(self.master_key, self.salt)

        # Verify chain prefix length
        self.assertEqual(CHAIN_PREFIX_LENGTH, 16)

        # All layers should produce valid keys
        self.assertEqual(len(layers), 3)
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

    def test_three_layer_cascade(self):
        """Test cascade with three layers."""
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305", "aes-256-ocb3"], hkdf_hash="sha256"
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


if __name__ == "__main__":
    unittest.main()
