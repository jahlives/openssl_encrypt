#!/usr/bin/env python3
"""
Unit tests for cipher registry.

Tests all symmetric cipher implementations and registry functionality.
All code in English as per project requirements.
"""

import pytest

from openssl_encrypt.modules.registry import (
    AES256GCM,
    AESGCMSIV,
    AESOCB3,
    AESSIV,
    AlgorithmCategory,
    AuthenticationError,
    ChaCha20Poly1305,
    CipherRegistry,
    SecurityLevel,
    Threefish512,
    Threefish1024,
    ValidationError,
    XChaCha20Poly1305,
    get_cipher,
)


class TestCipherRegistry:
    """Tests for CipherRegistry class."""

    def test_singleton(self):
        """Test that default() returns singleton."""
        registry1 = CipherRegistry.default()
        registry2 = CipherRegistry.default()
        assert registry1 is registry2

    def test_all_ciphers_registered(self):
        """Test that all ciphers are registered."""
        registry = CipherRegistry.default()

        expected_ciphers = [
            "aes-256-gcm",
            "aes-256-gcm-siv",
            "aes-256-siv",
            "aes-256-ocb3",
            "chacha20-poly1305",
            "xchacha20-poly1305",
        ]

        for cipher_name in expected_ciphers:
            assert registry.exists(cipher_name), f"{cipher_name} not registered"

    def test_get_cipher_function(self):
        """Test get_cipher convenience function."""
        cipher = get_cipher("aes-256-gcm")
        assert isinstance(cipher, AES256GCM)

    def test_cipher_aliases(self):
        """Test that cipher aliases work."""
        registry = CipherRegistry.default()

        # Test AES-GCM aliases
        assert registry.exists("aes-gcm")
        assert registry.exists("aes256-gcm")

        # Test ChaCha20 aliases
        assert registry.exists("chacha20")


class TestAES256GCM:
    """Tests for AES-256-GCM cipher."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = AES256GCM.info()
        assert info.name == "aes-256-gcm"
        assert info.category == AlgorithmCategory.CIPHER
        assert info.security_bits == 256
        assert info.key_size == 32
        assert info.nonce_size == 12
        assert info.tag_size == 16

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption roundtrip."""
        cipher = AES256GCM()
        key = b"0" * 32  # 32-byte key
        plaintext = b"Hello, World! This is a test message."

        # Encrypt
        ciphertext = cipher.encrypt(key, plaintext)

        # Should be: nonce (12) + encrypted + tag (16)
        assert len(ciphertext) == len(plaintext) + 12 + 16

        # Decrypt
        decrypted = cipher.decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_with_aad(self):
        """Test encryption with associated data."""
        cipher = AES256GCM()
        key = b"1" * 32
        plaintext = b"Secret message"
        aad = b"Additional authenticated data"

        # Encrypt with AAD
        ciphertext = cipher.encrypt(key, plaintext, associated_data=aad)

        # Decrypt with correct AAD
        decrypted = cipher.decrypt(key, ciphertext, associated_data=aad)
        assert decrypted == plaintext

    def test_decrypt_with_wrong_aad_fails(self):
        """Test that decryption with wrong AAD fails."""
        cipher = AES256GCM()
        key = b"2" * 32
        plaintext = b"Secret message"
        aad = b"Correct AAD"
        wrong_aad = b"Wrong AAD"

        ciphertext = cipher.encrypt(key, plaintext, associated_data=aad)

        with pytest.raises(AuthenticationError):
            cipher.decrypt(key, ciphertext, associated_data=wrong_aad)

    def test_decrypt_with_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        cipher = AES256GCM()
        key = b"3" * 32
        wrong_key = b"4" * 32
        plaintext = b"Secret message"

        ciphertext = cipher.encrypt(key, plaintext)

        with pytest.raises(AuthenticationError):
            cipher.decrypt(wrong_key, ciphertext)

    def test_invalid_key_size(self):
        """Test that invalid key size raises error."""
        cipher = AES256GCM()
        short_key = b"short"
        plaintext = b"test"

        with pytest.raises(ValidationError, match="32-byte key"):
            cipher.encrypt(short_key, plaintext)

    def test_generate_nonce(self):
        """Test nonce generation."""
        cipher = AES256GCM()
        nonce1 = cipher.generate_nonce()
        nonce2 = cipher.generate_nonce()

        assert len(nonce1) == 12
        assert len(nonce2) == 12
        assert nonce1 != nonce2  # Should be random


class TestAESGCMSIV:
    """Tests for AES-256-GCM-SIV cipher."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = AESGCMSIV.info()
        assert info.name == "aes-256-gcm-siv"
        assert info.security_level == SecurityLevel.HIGH
        assert info.key_size == 32

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption."""
        cipher = AESGCMSIV()
        key = b"5" * 32
        plaintext = b"Test message for GCM-SIV"

        ciphertext = cipher.encrypt(key, plaintext)
        decrypted = cipher.decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_nonce_reuse_resistance(self):
        """Test that nonce reuse doesn't leak plaintext equality."""
        cipher = AESGCMSIV()
        key = b"6" * 32
        plaintext1 = b"Message one"
        plaintext2 = b"Message two"
        nonce = cipher.generate_nonce()

        # Same nonce, different plaintexts
        ct1 = cipher.encrypt(key, plaintext1, nonce=nonce)
        ct2 = cipher.encrypt(key, plaintext2, nonce=nonce)

        # Ciphertexts should be different
        assert ct1 != ct2


class TestAESSIV:
    """Tests for AES-256-SIV cipher."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = AESSIV.info()
        assert info.name == "aes-256-siv"
        assert info.key_size == 64  # SIV uses 2 keys
        assert info.nonce_size == 0  # Deterministic

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption."""
        cipher = AESSIV()
        key = b"7" * 64  # 64 bytes for SIV
        plaintext = b"Deterministic encryption test"

        ciphertext = cipher.encrypt(key, plaintext)
        decrypted = cipher.decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_deterministic_encryption(self):
        """Test that SIV is deterministic."""
        cipher = AESSIV()
        key = b"8" * 64
        plaintext = b"Same plaintext"

        ct1 = cipher.encrypt(key, plaintext)
        ct2 = cipher.encrypt(key, plaintext)

        # Should produce identical ciphertext
        assert ct1 == ct2

    def test_nonce_generation_returns_empty(self):
        """Test that nonce generation returns empty bytes."""
        cipher = AESSIV()
        nonce = cipher.generate_nonce()
        assert nonce == b""


class TestAESOCB3:
    """Tests for AES-256-OCB3 cipher (deprecated)."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = AESOCB3.info()
        assert info.name == "aes-256-ocb3"
        assert info.security_level == SecurityLevel.LEGACY
        assert "DEPRECATED" in info.display_name

    def test_deprecation_warning(self):
        """Test that using OCB3 triggers deprecation warning."""
        cipher = AESOCB3()
        key = b"9" * 32
        plaintext = b"test"

        with pytest.warns(DeprecationWarning, match="deprecated"):
            cipher.encrypt(key, plaintext)

    def test_encrypt_decrypt_roundtrip(self):
        """Test basic functionality still works."""
        cipher = AESOCB3()
        key = b"A" * 32
        plaintext = b"OCB3 test message"

        with pytest.warns(DeprecationWarning):
            ciphertext = cipher.encrypt(key, plaintext)

        decrypted = cipher.decrypt(key, ciphertext)
        assert decrypted == plaintext


class TestChaCha20Poly1305:
    """Tests for ChaCha20-Poly1305 cipher."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = ChaCha20Poly1305.info()
        assert info.name == "chacha20-poly1305"
        assert info.key_size == 32
        assert info.nonce_size == 12
        assert info.block_size == 64

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption."""
        cipher = ChaCha20Poly1305()
        key = b"B" * 32
        plaintext = b"ChaCha20 test message with some length"

        ciphertext = cipher.encrypt(key, plaintext)
        decrypted = cipher.decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_with_associated_data(self):
        """Test encryption with AAD."""
        cipher = ChaCha20Poly1305()
        key = b"C" * 32
        plaintext = b"Secret data"
        aad = b"Public header"

        ciphertext = cipher.encrypt(key, plaintext, associated_data=aad)
        decrypted = cipher.decrypt(key, ciphertext, associated_data=aad)
        assert decrypted == plaintext


class TestXChaCha20Poly1305:
    """Tests for XChaCha20-Poly1305 cipher."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = XChaCha20Poly1305.info()
        assert info.name == "xchacha20-poly1305"
        assert info.key_size == 32
        assert info.nonce_size == 24  # Extended nonce
        assert info.security_level == SecurityLevel.HIGH

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption."""
        cipher = XChaCha20Poly1305()
        key = b"D" * 32
        plaintext = b"XChaCha20 test with extended nonce space"

        ciphertext = cipher.encrypt(key, plaintext)

        # Should start with 24-byte nonce
        assert len(ciphertext) >= len(plaintext) + 24 + 16

        decrypted = cipher.decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_24_byte_nonce(self):
        """Test that XChaCha20 uses 24-byte nonces."""
        cipher = XChaCha20Poly1305()
        nonce = cipher.generate_nonce()
        assert len(nonce) == 24

    def test_nonce_processing(self):
        """Test internal nonce processing."""
        cipher = XChaCha20Poly1305()
        key = b"E" * 32
        plaintext = b"test"
        nonce_24 = b"F" * 24

        # Should accept 24-byte nonce
        ciphertext = cipher.encrypt(key, plaintext, nonce=nonce_24)
        decrypted = cipher.decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_backward_compat_12_byte_nonce(self):
        """Test backward compatibility with 12-byte nonces."""
        cipher = XChaCha20Poly1305()
        key = b"G" * 32
        plaintext = b"test"
        nonce_12 = b"H" * 12

        # Should also accept 12-byte nonce for compatibility
        ciphertext = cipher.encrypt(key, plaintext, nonce=nonce_12)
        # Extract just the ciphertext part (skip nonce)
        ct_data = ciphertext[12:]
        decrypted = cipher.decrypt(key, ct_data, nonce=nonce_12)
        assert decrypted == plaintext


class TestCipherErrorHandling:
    """Tests for cipher error handling."""

    def test_tampered_ciphertext(self):
        """Test that tampering with ciphertext is detected."""
        cipher = AES256GCM()
        key = b"I" * 32
        plaintext = b"Important data"

        ciphertext = cipher.encrypt(key, plaintext)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01  # Flip one bit in the tag

        with pytest.raises(AuthenticationError):
            cipher.decrypt(key, bytes(tampered))

    def test_truncated_ciphertext(self):
        """Test that truncated ciphertext is rejected."""
        cipher = AES256GCM()
        key = b"J" * 32
        plaintext = b"test"

        ciphertext = cipher.encrypt(key, plaintext)
        truncated = ciphertext[:10]  # Too short

        with pytest.raises(ValidationError, match="too short"):
            cipher.decrypt(key, truncated)

    def test_invalid_nonce_size(self):
        """Test that invalid nonce size is rejected."""
        cipher = AES256GCM()
        key = b"K" * 32
        plaintext = b"test"
        bad_nonce = b"short"

        with pytest.raises(ValidationError, match="12 bytes"):
            cipher.encrypt(key, plaintext, nonce=bad_nonce)


class TestCipherComparison:
    """Comparative tests across different ciphers."""

    def test_all_ciphers_encrypt_decrypt(self):
        """Test that all ciphers can encrypt and decrypt."""
        registry = CipherRegistry.default()
        plaintext = b"Test message for all ciphers"

        for cipher_name in registry.list_names():
            if cipher_name == "aes-256-siv":
                key = b"L" * 64  # SIV needs 64 bytes
            elif cipher_name == "threefish-512":
                key = b"M" * 64  # Threefish-512 needs 64 bytes
            elif cipher_name == "threefish-1024":
                key = b"M" * 128  # Threefish-1024 needs 128 bytes
            else:
                key = b"M" * 32

            cipher = registry.get(cipher_name)

            # Skip deprecation warning for OCB3
            if cipher_name == "aes-256-ocb3":
                import warnings

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    ciphertext = cipher.encrypt(key, plaintext)
            else:
                ciphertext = cipher.encrypt(key, plaintext)

            decrypted = cipher.decrypt(key, ciphertext)
            assert decrypted == plaintext, f"Failed for {cipher_name}"


# Skip Threefish tests if extension not installed
threefish_available = pytest.importorskip(
    "threefish_native", reason="threefish_native extension not installed"
)


@pytest.mark.skipif(not Threefish512.is_available(), reason="threefish_native not available")
class TestThreefish512:
    """Tests for Threefish-512 cipher."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = Threefish512.info()
        assert info.name == "threefish-512"
        assert info.category == AlgorithmCategory.CIPHER
        assert info.security_bits == 512
        assert info.pq_security_bits == 256
        assert info.security_level == SecurityLevel.HIGH
        assert info.key_size == 64
        assert info.nonce_size == 32
        assert info.tag_size == 16

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption roundtrip."""
        import threefish_native

        cipher = Threefish512()
        key = threefish_native.generate_key_512()
        nonce = threefish_native.generate_nonce_512()
        plaintext = b"Hello, Threefish-512! This is a test message."

        # Encrypt
        ciphertext = cipher.encrypt(key, plaintext, nonce=nonce)

        # Should be: nonce (32) + encrypted + tag (16)
        assert len(ciphertext) == 32 + len(plaintext) + 16

        # Decrypt (nonce is extracted from ciphertext)
        decrypted = cipher.decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_with_aad(self):
        """Test encryption with associated data."""
        import threefish_native

        cipher = Threefish512()
        key = threefish_native.generate_key_512()
        nonce = threefish_native.generate_nonce_512()
        plaintext = b"Secret message"
        aad = b"Additional authenticated data"

        ciphertext = cipher.encrypt(key, plaintext, nonce=nonce, associated_data=aad)
        decrypted = cipher.decrypt(key, ciphertext, associated_data=aad)

        assert decrypted == plaintext

    def test_decrypt_with_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        import threefish_native

        cipher = Threefish512()
        key = threefish_native.generate_key_512()
        wrong_key = threefish_native.generate_key_512()
        nonce = threefish_native.generate_nonce_512()

        ciphertext = cipher.encrypt(key, b"Secret", nonce=nonce)

        with pytest.raises(AuthenticationError):
            cipher.decrypt(wrong_key, ciphertext)

    def test_tampered_ciphertext_fails(self):
        """Test that tampered ciphertext fails authentication."""
        import threefish_native

        cipher = Threefish512()
        key = threefish_native.generate_key_512()
        nonce = threefish_native.generate_nonce_512()

        ciphertext = bytearray(cipher.encrypt(key, b"Important data", nonce=nonce))
        ciphertext[0] ^= 0x01  # Flip one bit

        with pytest.raises(AuthenticationError):
            cipher.decrypt(key, bytes(ciphertext))

    def test_invalid_key_size(self):
        """Test that invalid key size raises error."""
        cipher = Threefish512()
        with pytest.raises(ValidationError, match="64-byte key"):
            cipher.encrypt(b"short_key", b"test")

    def test_invalid_nonce_size(self):
        """Test that invalid nonce size raises error."""
        cipher = Threefish512()
        with pytest.raises(ValidationError, match="32 bytes"):
            cipher.encrypt(b"K" * 64, b"test", nonce=b"short_nonce")

    def test_nonce_embedded_in_ciphertext(self):
        """Test that nonce is embedded in ciphertext and can be extracted."""
        import threefish_native

        cipher = Threefish512()
        key = threefish_native.generate_key_512()
        nonce = threefish_native.generate_nonce_512()

        ciphertext = cipher.encrypt(key, b"test", nonce=nonce)

        # Nonce should be embedded, so decrypt works without explicit nonce
        decrypted = cipher.decrypt(key, ciphertext)
        assert decrypted == b"test"

    def test_large_data(self):
        """Test with 1MB of data."""
        import secrets

        import threefish_native

        cipher = Threefish512()
        key = threefish_native.generate_key_512()
        nonce = threefish_native.generate_nonce_512()
        plaintext = secrets.token_bytes(1024 * 1024)  # 1 MB

        ciphertext = cipher.encrypt(key, plaintext, nonce=nonce)
        decrypted = cipher.decrypt(key, ciphertext)

        assert decrypted == plaintext


@pytest.mark.skipif(not Threefish1024.is_available(), reason="threefish_native not available")
class TestThreefish1024:
    """Tests for Threefish-1024 cipher."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = Threefish1024.info()
        assert info.name == "threefish-1024"
        assert info.category == AlgorithmCategory.CIPHER
        assert info.security_bits == 1024
        assert info.pq_security_bits == 512
        assert info.security_level == SecurityLevel.PARANOID
        assert info.key_size == 128
        assert info.nonce_size == 64
        assert info.tag_size == 16

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption roundtrip."""
        import threefish_native

        cipher = Threefish1024()
        key = threefish_native.generate_key_1024()
        nonce = threefish_native.generate_nonce_1024()
        plaintext = b"Hello, Threefish-1024! Maximum security mode."

        # Encrypt
        ciphertext = cipher.encrypt(key, plaintext, nonce=nonce)

        # Should be: nonce (64) + encrypted + tag (16)
        assert len(ciphertext) == 64 + len(plaintext) + 16

        # Decrypt (nonce is extracted from ciphertext)
        decrypted = cipher.decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_with_aad(self):
        """Test encryption with associated data."""
        import threefish_native

        cipher = Threefish1024()
        key = threefish_native.generate_key_1024()
        nonce = threefish_native.generate_nonce_1024()
        plaintext = b"Top secret data"
        aad = b"Header information"

        ciphertext = cipher.encrypt(key, plaintext, nonce=nonce, associated_data=aad)
        decrypted = cipher.decrypt(key, ciphertext, associated_data=aad)

        assert decrypted == plaintext

    def test_decrypt_with_wrong_aad_fails(self):
        """Test that wrong AAD fails authentication."""
        import threefish_native

        cipher = Threefish1024()
        key = threefish_native.generate_key_1024()
        nonce = threefish_native.generate_nonce_1024()

        ciphertext = cipher.encrypt(key, b"Secret", nonce=nonce, associated_data=b"correct_aad")

        with pytest.raises(AuthenticationError):
            cipher.decrypt(key, ciphertext, associated_data=b"wrong_aad")

    def test_tampered_tag_fails(self):
        """Test that tampered tag fails authentication."""
        import threefish_native

        cipher = Threefish1024()
        key = threefish_native.generate_key_1024()
        nonce = threefish_native.generate_nonce_1024()

        ciphertext = bytearray(cipher.encrypt(key, b"test", nonce=nonce))

        # Tamper with tag (last 16 bytes)
        ciphertext[-1] ^= 0xFF

        with pytest.raises(AuthenticationError):
            cipher.decrypt(key, bytes(ciphertext))

    def test_invalid_key_size(self):
        """Test that invalid key size raises error."""
        cipher = Threefish1024()
        with pytest.raises(ValidationError, match="128-byte key"):
            cipher.encrypt(b"short_key", b"test")

    def test_invalid_nonce_size(self):
        """Test that invalid nonce size raises error."""
        cipher = Threefish1024()
        with pytest.raises(ValidationError, match="64 bytes"):
            cipher.encrypt(b"K" * 128, b"test", nonce=b"short_nonce")

    def test_large_data(self):
        """Test with 1MB of data."""
        import secrets

        import threefish_native

        cipher = Threefish1024()
        key = threefish_native.generate_key_1024()
        nonce = threefish_native.generate_nonce_1024()
        plaintext = secrets.token_bytes(1024 * 1024)  # 1 MB

        ciphertext = cipher.encrypt(key, plaintext, nonce=nonce)
        decrypted = cipher.decrypt(key, ciphertext)

        assert decrypted == plaintext


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
