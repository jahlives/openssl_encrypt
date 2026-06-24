#!/usr/bin/env python3
"""
Test suite for streaming chunked encryption/decryption (format version 12).

This module contains comprehensive tests for:
- Core streaming primitives (nonce derivation, chunk encryption/decryption)
- StreamingEncryptor / StreamingDecryptor roundtrips
- Multi-algorithm support (AES-GCM, ChaCha20, XChaCha20, AES-GCM-SIV, AES-OCB3, AES-SIV, Threefish)
- Cascade streaming
- Threshold logic (one-shot vs streaming)
- Adversarial tests (corruption, reordering, truncation)
- Backward compatibility with v10/v11
- Edge cases (empty file, exact chunk boundary, etc.)
"""

import base64
import hashlib
import json
import os
import secrets
import struct
import tempfile
import unittest

import pytest

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
)
from openssl_encrypt.modules.crypt_errors import (
    AuthenticationError,
    DecryptionError,
    ValidationError,
)
from openssl_encrypt.modules.streaming import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_STREAMING_THRESHOLD,
    STREAMING_MAGIC,
    STREAMING_SUPPORTED_ALGORITHMS,
    STREAMING_UNSUPPORTED_ALGORITHMS,
    StreamingDecryptor,
    StreamingEncryptor,
    build_chunk_aad,
    calculate_hash_streaming,
    decrypt_chunk,
    derive_chunk_nonce,
    encrypt_chunk,
    parse_size_string,
    should_use_streaming,
)

# ============================================================
# Helper functions
# ============================================================


def _create_temp_file(data: bytes) -> str:
    """Create a temporary file with the given data and return its path."""
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _default_hash_config():
    """Return a minimal hash config for testing (fast)."""
    return {
        "sha256": 1,
        "pbkdf2_iterations": 0,
    }


# ============================================================
# Test: Core Primitives
# ============================================================


class TestDeriveChunkNonce(unittest.TestCase):
    """Tests for derive_chunk_nonce()."""

    def test_deterministic(self):
        """Same inputs produce same nonce."""
        prefix = secrets.token_bytes(8)
        n1 = derive_chunk_nonce(prefix, 0, 12)
        n2 = derive_chunk_nonce(prefix, 0, 12)
        self.assertEqual(n1, n2)

    def test_different_indices_produce_different_nonces(self):
        """Different chunk indices produce different nonces."""
        prefix = secrets.token_bytes(8)
        n0 = derive_chunk_nonce(prefix, 0, 12)
        n1 = derive_chunk_nonce(prefix, 1, 12)
        n2 = derive_chunk_nonce(prefix, 2, 12)
        self.assertNotEqual(n0, n1)
        self.assertNotEqual(n1, n2)
        self.assertNotEqual(n0, n2)

    def test_different_prefixes_produce_different_nonces(self):
        """Different nonce prefixes produce different nonces."""
        p1 = secrets.token_bytes(8)
        p2 = secrets.token_bytes(8)
        n1 = derive_chunk_nonce(p1, 0, 12)
        n2 = derive_chunk_nonce(p2, 0, 12)
        self.assertNotEqual(n1, n2)

    def test_correct_length(self):
        """Output nonce has the requested length."""
        prefix = secrets.token_bytes(8)
        for size in [12, 16, 32, 64]:
            nonce = derive_chunk_nonce(prefix, 0, size)
            self.assertEqual(len(nonce), size)

    def test_invalid_prefix(self):
        """Short prefix raises ValidationError."""
        with self.assertRaises(ValidationError):
            derive_chunk_nonce(b"short", 0, 12)

    def test_negative_index(self):
        """Negative chunk index raises ValidationError."""
        with self.assertRaises(ValidationError):
            derive_chunk_nonce(secrets.token_bytes(8), -1, 12)


class TestBuildChunkAad(unittest.TestCase):
    """Tests for build_chunk_aad()."""

    def test_contains_metadata(self):
        """AAD contains the metadata bytes."""
        metadata = b"dGVzdG1ldGFkYXRh"
        aad = build_chunk_aad(metadata, 0, 10)
        self.assertTrue(aad.startswith(metadata))

    def test_different_indices_produce_different_aad(self):
        """Different chunk indices produce different AAD."""
        metadata = b"dGVzdA=="
        aad0 = build_chunk_aad(metadata, 0, 10)
        aad1 = build_chunk_aad(metadata, 1, 10)
        self.assertNotEqual(aad0, aad1)

    def test_different_counts_produce_different_aad(self):
        """Different chunk counts produce different AAD."""
        metadata = b"dGVzdA=="
        aad_10 = build_chunk_aad(metadata, 0, 10)
        aad_20 = build_chunk_aad(metadata, 0, 20)
        self.assertNotEqual(aad_10, aad_20)


class TestEncryptDecryptChunk(unittest.TestCase):
    """Tests for encrypt_chunk() and decrypt_chunk()."""

    def test_aes_gcm_roundtrip(self):
        """AES-GCM chunk encrypt/decrypt roundtrip."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Hello, streaming world!"
        aad = b"test-aad"

        ct = encrypt_chunk(key, nonce, plaintext, aad, "aes-gcm")
        pt = decrypt_chunk(key, nonce, ct, aad, "aes-gcm")
        self.assertEqual(pt, plaintext)

    def test_chacha20_roundtrip(self):
        """ChaCha20-Poly1305 chunk roundtrip."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"ChaCha20 test data"
        aad = b"chacha-aad"

        ct = encrypt_chunk(key, nonce, plaintext, aad, "chacha20-poly1305")
        pt = decrypt_chunk(key, nonce, ct, aad, "chacha20-poly1305")
        self.assertEqual(pt, plaintext)

    def test_aes_gcm_siv_roundtrip(self):
        """AES-GCM-SIV chunk roundtrip."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"GCM-SIV test"
        aad = b"siv-aad"

        ct = encrypt_chunk(key, nonce, plaintext, aad, "aes-gcm-siv")
        pt = decrypt_chunk(key, nonce, ct, aad, "aes-gcm-siv")
        self.assertEqual(pt, plaintext)

    def test_aes_ocb3_roundtrip(self):
        """AES-OCB3 chunk roundtrip."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"OCB3 test data"
        aad = b"ocb3-aad"

        ct = encrypt_chunk(key, nonce, plaintext, aad, "aes-ocb3")
        pt = decrypt_chunk(key, nonce, ct, aad, "aes-ocb3")
        self.assertEqual(pt, plaintext)

    def test_aes_siv_roundtrip(self):
        """AES-SIV chunk roundtrip."""
        key = secrets.token_bytes(64)  # AES-SIV needs 64-byte key
        nonce = secrets.token_bytes(16)
        plaintext = b"SIV test data"
        aad = b"siv-aad"

        ct = encrypt_chunk(key, nonce, plaintext, aad, "aes-siv")
        pt = decrypt_chunk(key, nonce, ct, aad, "aes-siv")
        self.assertEqual(pt, plaintext)

    def test_xchacha20_roundtrip(self):
        """XChaCha20-Poly1305 chunk roundtrip."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"XChaCha20 test data"
        aad = b"xchacha-aad"

        ct = encrypt_chunk(key, nonce, plaintext, aad, "xchacha20-poly1305")
        pt = decrypt_chunk(key, nonce, ct, aad, "xchacha20-poly1305")
        self.assertEqual(pt, plaintext)

    def test_wrong_key_fails(self):
        """Wrong key causes authentication failure."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"test data"

        ct = encrypt_chunk(key1, nonce, plaintext, None, "aes-gcm")
        with self.assertRaises((AuthenticationError, DecryptionError, Exception)):
            decrypt_chunk(key2, nonce, ct, None, "aes-gcm")

    def test_wrong_aad_fails(self):
        """Mismatched AAD causes authentication failure."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"test data"

        ct = encrypt_chunk(key, nonce, plaintext, b"aad1", "aes-gcm")
        with self.assertRaises((AuthenticationError, DecryptionError, Exception)):
            decrypt_chunk(key, nonce, ct, b"aad2", "aes-gcm")

    def test_unsupported_algorithm(self):
        """Unsupported algorithm raises ValidationError."""
        with self.assertRaises(ValidationError):
            encrypt_chunk(b"k" * 32, b"n" * 12, b"data", None, "unknown-cipher")


# ============================================================
# Test: Threefish streaming chunks
# ============================================================


class TestThreefishChunks(unittest.TestCase):
    """Tests for Threefish chunk encryption."""

    def test_threefish_512_roundtrip(self):
        """Threefish-512 chunk roundtrip."""
        try:
            import threefish_native
        except ImportError:
            pytest.skip("threefish_native not available")

        key = secrets.token_bytes(64)
        nonce = secrets.token_bytes(32)
        plaintext = b"Threefish-512 streaming test data"
        aad = b"tf512-aad"

        ct = encrypt_chunk(key, nonce, plaintext, aad, "threefish-512")
        pt = decrypt_chunk(key, nonce, ct, aad, "threefish-512")
        self.assertEqual(pt, plaintext)

    def test_threefish_1024_roundtrip(self):
        """Threefish-1024 chunk roundtrip."""
        try:
            import threefish_native
        except ImportError:
            pytest.skip("threefish_native not available")

        key = secrets.token_bytes(128)
        nonce = secrets.token_bytes(64)
        plaintext = b"Threefish-1024 streaming test data"
        aad = b"tf1024-aad"

        ct = encrypt_chunk(key, nonce, plaintext, aad, "threefish-1024")
        pt = decrypt_chunk(key, nonce, ct, aad, "threefish-1024")
        self.assertEqual(pt, plaintext)


# ============================================================
# Test: should_use_streaming()
# ============================================================


class TestShouldUseStreaming(unittest.TestCase):
    """Tests for should_use_streaming() decision function."""

    def test_below_threshold_returns_false(self):
        """Files below threshold should not use streaming."""
        self.assertFalse(should_use_streaming(1024, "aes-gcm", threshold=10 * 1024 * 1024))

    def test_above_threshold_returns_true(self):
        """Files above threshold should use streaming for supported algorithms."""
        self.assertTrue(should_use_streaming(20 * 1024 * 1024, "aes-gcm"))

    def test_no_streaming_flag(self):
        """no_streaming=True should always return False."""
        self.assertFalse(should_use_streaming(100 * 1024 * 1024, "aes-gcm", no_streaming=True))

    def test_unsupported_algorithm(self):
        """Unsupported algorithms (fernet, camellia, PQC) return False."""
        for alg in STREAMING_UNSUPPORTED_ALGORITHMS:
            self.assertFalse(
                should_use_streaming(100 * 1024 * 1024, alg),
                f"Expected False for unsupported algorithm {alg}",
            )

    def test_in_memory_bytes_returns_false(self):
        """In-memory bytes input should not use streaming."""
        self.assertFalse(should_use_streaming(100 * 1024 * 1024, "aes-gcm", input_is_bytes=True))

    def test_exact_threshold_returns_true(self):
        """File exactly at threshold should use streaming."""
        self.assertTrue(should_use_streaming(DEFAULT_STREAMING_THRESHOLD, "aes-gcm"))

    def test_custom_threshold(self):
        """Custom threshold is respected."""
        self.assertTrue(should_use_streaming(5000, "aes-gcm", threshold=4000))
        self.assertFalse(should_use_streaming(3000, "aes-gcm", threshold=4000))


# ============================================================
# Test: calculate_hash_streaming()
# ============================================================


class TestCalculateHashStreaming(unittest.TestCase):
    """Tests for streaming SHA-256 hash calculation."""

    def test_matches_standard_hash(self):
        """Streaming hash matches hashlib.sha256 on same data."""
        data = secrets.token_bytes(50000)
        expected = hashlib.sha256(data).hexdigest()

        path = _create_temp_file(data)
        try:
            result = calculate_hash_streaming(path, chunk_size=1024)
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)

    def test_empty_file(self):
        """Hash of empty file matches hashlib.sha256(b'')."""
        expected = hashlib.sha256(b"").hexdigest()
        path = _create_temp_file(b"")
        try:
            result = calculate_hash_streaming(path)
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)


# ============================================================
# Test: StreamingEncryptor / StreamingDecryptor
# ============================================================


class TestStreamingEncryptorDecryptor(unittest.TestCase):
    """Tests for StreamingEncryptor and StreamingDecryptor classes."""

    def _roundtrip(self, algorithm, data, key_size=32, chunk_size=1024):
        """Helper to do a full streaming encrypt/decrypt roundtrip."""
        key = secrets.token_bytes(key_size)
        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")
        output_dec = _create_temp_file(b"")

        try:
            # Encrypt
            enc = StreamingEncryptor(key=key, algorithm=algorithm, chunk_size=chunk_size)
            original_hash = enc.hash_file(input_path)
            chunk_count = enc.get_chunk_count(len(data))

            # Build metadata
            metadata = {
                "format_version": 12,
                "mode": "symmetric",
                "aead_binding": True,
                "streaming": {
                    "enabled": True,
                    "chunk_size": chunk_size,
                    "chunk_count": chunk_count,
                    "nonce_prefix": base64.b64encode(enc.nonce_prefix).decode("ascii"),
                },
                "hashes": {"original_hash": original_hash},
                "encryption": {"cascade": False, "algorithm": algorithm},
            }
            metadata_json = json.dumps(metadata).encode("utf-8")
            metadata_b64 = base64.b64encode(metadata_json)

            enc.encrypt_file(
                input_file=input_path,
                output_file=output_enc,
                metadata_b64=metadata_b64,
                chunk_count=chunk_count,
                quiet=True,
            )

            # Decrypt
            dec = StreamingDecryptor(
                key=key,
                algorithm=algorithm,
                nonce_prefix=enc.nonce_prefix,
                chunk_size=chunk_size,
            )
            result = dec.decrypt_file(
                input_file=output_enc,
                output_file=output_dec,
                metadata_b64=metadata_b64,
                expected_chunk_count=chunk_count,
                original_hash=original_hash,
                quiet=True,
            )

            self.assertTrue(result)

            with open(output_dec, "rb") as f:
                decrypted = f.read()
            self.assertEqual(decrypted, data)

        finally:
            for p in [input_path, output_enc, output_dec]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_aes_gcm_roundtrip(self):
        """AES-GCM streaming roundtrip with multiple chunks."""
        data = secrets.token_bytes(5000)
        self._roundtrip("aes-gcm", data, chunk_size=1024)

    def test_chacha20_roundtrip(self):
        """ChaCha20-Poly1305 streaming roundtrip."""
        data = secrets.token_bytes(5000)
        self._roundtrip("chacha20-poly1305", data, chunk_size=1024)

    def test_aes_gcm_siv_roundtrip(self):
        """AES-GCM-SIV streaming roundtrip."""
        data = secrets.token_bytes(5000)
        self._roundtrip("aes-gcm-siv", data, chunk_size=1024)

    def test_aes_ocb3_roundtrip(self):
        """AES-OCB3 streaming roundtrip."""
        data = secrets.token_bytes(5000)
        self._roundtrip("aes-ocb3", data, chunk_size=1024)

    def test_aes_siv_roundtrip(self):
        """AES-SIV streaming roundtrip (64-byte key)."""
        data = secrets.token_bytes(5000)
        self._roundtrip("aes-siv", data, key_size=64, chunk_size=1024)

    def test_xchacha20_roundtrip(self):
        """XChaCha20-Poly1305 streaming roundtrip."""
        data = secrets.token_bytes(5000)
        self._roundtrip("xchacha20-poly1305", data, chunk_size=1024)

    def test_single_chunk_file(self):
        """File that fits in exactly one chunk."""
        data = secrets.token_bytes(1024)
        self._roundtrip("aes-gcm", data, chunk_size=2048)

    def test_exact_chunk_boundary(self):
        """File size exactly equals chunk_size (one full chunk, no partial)."""
        data = secrets.token_bytes(1024)
        self._roundtrip("aes-gcm", data, chunk_size=1024)

    def test_small_last_chunk(self):
        """File where last chunk is smaller than chunk_size."""
        data = secrets.token_bytes(2500)  # 2 full + 1 partial with 1024 chunks
        self._roundtrip("aes-gcm", data, chunk_size=1024)

    def test_many_chunks(self):
        """Exercise many-chunk paths (50+ chunks)."""
        data = secrets.token_bytes(50 * 1024)
        self._roundtrip("aes-gcm", data, chunk_size=1024)

    def test_in_memory_decrypt(self):
        """StreamingDecryptor returns bytes when output_file is None."""
        key = secrets.token_bytes(32)
        data = secrets.token_bytes(3000)
        chunk_size = 1024

        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")

        try:
            enc = StreamingEncryptor(key=key, algorithm="aes-gcm", chunk_size=chunk_size)
            original_hash = enc.hash_file(input_path)
            chunk_count = enc.get_chunk_count(len(data))

            metadata = {
                "format_version": 12,
                "streaming": {
                    "enabled": True,
                    "chunk_size": chunk_size,
                    "chunk_count": chunk_count,
                    "nonce_prefix": base64.b64encode(enc.nonce_prefix).decode("ascii"),
                },
                "hashes": {"original_hash": original_hash},
                "encryption": {"cascade": False, "algorithm": "aes-gcm"},
            }
            metadata_b64 = base64.b64encode(json.dumps(metadata).encode("utf-8"))

            enc.encrypt_file(input_path, output_enc, metadata_b64, chunk_count, quiet=True)

            dec = StreamingDecryptor(
                key=key,
                algorithm="aes-gcm",
                nonce_prefix=enc.nonce_prefix,
                chunk_size=chunk_size,
            )
            result = dec.decrypt_file(
                input_file=output_enc,
                output_file=None,
                metadata_b64=metadata_b64,
                expected_chunk_count=chunk_count,
                original_hash=original_hash,
                quiet=True,
            )

            self.assertIsInstance(result, bytes)
            self.assertEqual(result, data)
        finally:
            for p in [input_path, output_enc]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_progress_callback(self):
        """Progress callback is invoked for each chunk."""
        key = secrets.token_bytes(32)
        data = secrets.token_bytes(3000)
        chunk_size = 1024

        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")

        try:
            enc = StreamingEncryptor(key=key, algorithm="aes-gcm", chunk_size=chunk_size)
            original_hash = enc.hash_file(input_path)
            chunk_count = enc.get_chunk_count(len(data))

            metadata = {
                "format_version": 12,
                "streaming": {
                    "enabled": True,
                    "chunk_size": chunk_size,
                    "chunk_count": chunk_count,
                    "nonce_prefix": base64.b64encode(enc.nonce_prefix).decode("ascii"),
                },
                "hashes": {"original_hash": original_hash},
                "encryption": {"cascade": False, "algorithm": "aes-gcm"},
            }
            metadata_b64 = base64.b64encode(json.dumps(metadata).encode("utf-8"))

            progress_calls = []

            def cb(idx, total):
                progress_calls.append((idx, total))

            enc.encrypt_file(
                input_path,
                output_enc,
                metadata_b64,
                chunk_count,
                quiet=True,
                progress_callback=cb,
            )

            self.assertEqual(len(progress_calls), chunk_count)
            for i, (idx, total) in enumerate(progress_calls):
                self.assertEqual(idx, i)
                self.assertEqual(total, chunk_count)
        finally:
            for p in [input_path, output_enc]:
                if os.path.exists(p):
                    os.unlink(p)


# ============================================================
# Test: Adversarial / Security tests
# ============================================================


class TestStreamingAdversarial(unittest.TestCase):
    """Adversarial tests: corruption, reordering, truncation."""

    def _encrypt_to_file(self, data, chunk_size=1024):
        """Helper: encrypt data and return (enc_path, key, metadata_b64, enc, chunk_count)."""
        key = secrets.token_bytes(32)
        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")

        enc = StreamingEncryptor(key=key, algorithm="aes-gcm", chunk_size=chunk_size)
        original_hash = enc.hash_file(input_path)
        chunk_count = enc.get_chunk_count(len(data))

        metadata = {
            "format_version": 12,
            "streaming": {
                "enabled": True,
                "chunk_size": chunk_size,
                "chunk_count": chunk_count,
                "nonce_prefix": base64.b64encode(enc.nonce_prefix).decode("ascii"),
            },
            "hashes": {"original_hash": original_hash},
            "encryption": {"cascade": False, "algorithm": "aes-gcm"},
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode("utf-8"))

        enc.encrypt_file(input_path, output_enc, metadata_b64, chunk_count, quiet=True)
        os.unlink(input_path)

        return output_enc, key, metadata_b64, enc, chunk_count, original_hash

    def test_chunk_corruption(self):
        """Tampering with ciphertext of one chunk causes decryption failure."""
        data = secrets.token_bytes(3000)
        enc_path, key, metadata_b64, enc_obj, chunk_count, original_hash = self._encrypt_to_file(
            data
        )

        try:
            # Read and corrupt a byte in the payload
            with open(enc_path, "rb") as f:
                content = bytearray(f.read())

            # Find payload start (after metadata_b64 : OESC <version>)
            colon_pos = content.index(b":")
            # Corrupt a byte in the middle of the first chunk's ciphertext
            corrupt_pos = colon_pos + 1 + 4 + 4 + 4 + 4 + 10  # deep in first chunk data
            if corrupt_pos < len(content) - 36:
                content[corrupt_pos] ^= 0xFF

            with open(enc_path, "wb") as f:
                f.write(content)

            dec = StreamingDecryptor(
                key=key,
                algorithm="aes-gcm",
                nonce_prefix=enc_obj.nonce_prefix,
                chunk_size=1024,
            )

            with self.assertRaises((AuthenticationError, DecryptionError, Exception)):
                dec.decrypt_file(
                    enc_path,
                    None,
                    metadata_b64,
                    chunk_count,
                    original_hash=original_hash,
                    quiet=True,
                )
        finally:
            os.unlink(enc_path)

    def test_trailer_hmac_corruption(self):
        """Corrupting the trailer HMAC causes verification failure."""
        data = secrets.token_bytes(3000)
        enc_path, key, metadata_b64, enc_obj, chunk_count, original_hash = self._encrypt_to_file(
            data
        )

        try:
            with open(enc_path, "rb") as f:
                content = bytearray(f.read())

            # Corrupt the last byte (part of HMAC)
            content[-1] ^= 0xFF

            with open(enc_path, "wb") as f:
                f.write(content)

            dec = StreamingDecryptor(
                key=key,
                algorithm="aes-gcm",
                nonce_prefix=enc_obj.nonce_prefix,
                chunk_size=1024,
            )

            with self.assertRaises(AuthenticationError):
                dec.decrypt_file(
                    enc_path,
                    None,
                    metadata_b64,
                    chunk_count,
                    original_hash=original_hash,
                    quiet=True,
                )
        finally:
            os.unlink(enc_path)

    def test_chunk_truncation(self):
        """Removing the last chunk causes verification failure."""
        data = secrets.token_bytes(3000)
        enc_path, key, metadata_b64, enc_obj, chunk_count, original_hash = self._encrypt_to_file(
            data
        )

        try:
            with open(enc_path, "rb") as f:
                content = f.read()

            # Find payload and remove last chunk by truncating before trailer
            colon_pos = content.index(b":")
            payload = content[colon_pos + 1 :]

            # Read the payload structure to find chunk boundaries
            # We know the trailer is the last 36 bytes
            # Just truncate some data before the trailer to simulate missing chunk
            # Reconstruct with truncated payload (remove ~1024 bytes before trailer)
            truncated = content[: len(content) - 36 - 1040]
            # Re-append a fake trailer
            truncated += struct.pack("<I", chunk_count) + secrets.token_bytes(32)

            with open(enc_path, "wb") as f:
                f.write(truncated)

            dec = StreamingDecryptor(
                key=key,
                algorithm="aes-gcm",
                nonce_prefix=enc_obj.nonce_prefix,
                chunk_size=1024,
            )

            with self.assertRaises((AuthenticationError, DecryptionError)):
                dec.decrypt_file(
                    enc_path,
                    None,
                    metadata_b64,
                    chunk_count,
                    original_hash=original_hash,
                    quiet=True,
                )
        finally:
            os.unlink(enc_path)

    def test_aad_metadata_tampering(self):
        """Modifying metadata post-encryption causes all chunks to fail."""
        data = secrets.token_bytes(3000)
        enc_path, key, metadata_b64, enc_obj, chunk_count, original_hash = self._encrypt_to_file(
            data
        )

        try:
            # Create a different metadata_b64 for decryption
            tampered_metadata = {
                "format_version": 12,
                "streaming": {
                    "enabled": True,
                    "chunk_size": 1024,
                    "chunk_count": chunk_count,
                    "nonce_prefix": base64.b64encode(enc_obj.nonce_prefix).decode("ascii"),
                },
                "hashes": {"original_hash": "tampered_hash_value"},
                "encryption": {"cascade": False, "algorithm": "aes-gcm"},
            }
            tampered_b64 = base64.b64encode(json.dumps(tampered_metadata).encode("utf-8"))

            dec = StreamingDecryptor(
                key=key,
                algorithm="aes-gcm",
                nonce_prefix=enc_obj.nonce_prefix,
                chunk_size=1024,
            )

            with self.assertRaises((AuthenticationError, DecryptionError, Exception)):
                dec.decrypt_file(
                    enc_path,
                    None,
                    tampered_b64,
                    chunk_count,
                    quiet=True,
                )
        finally:
            os.unlink(enc_path)


# ============================================================
# Test: Integration with encrypt_file() / decrypt_file()
# ============================================================


class TestStreamingIntegration(unittest.TestCase):
    """Integration tests using encrypt_file() / decrypt_file() with streaming."""

    def _encrypt_decrypt_roundtrip(
        self, algorithm, data_size=50 * 1024, chunk_size=1024, threshold=1024
    ):
        """Helper for integration roundtrip tests."""
        data = secrets.token_bytes(data_size)
        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")
        output_dec = _create_temp_file(b"")
        password = b"test-password-for-streaming"

        try:
            # Encrypt with streaming
            result = encrypt_file(
                input_file=input_path,
                output_file=output_enc,
                password=password,
                hash_config=_default_hash_config(),
                algorithm=EncryptionAlgorithm(algorithm),
                quiet=True,
                format_version=11,
                chunk_size=chunk_size,
                streaming_threshold=threshold,
            )
            self.assertTrue(result)

            # Verify metadata shows v12 + streaming
            info = extract_file_metadata(output_enc)
            self.assertEqual(info["format_version"], 12)
            self.assertTrue(info["metadata"].get("streaming", {}).get("enabled", False))

            # Decrypt
            result = decrypt_file(
                input_file=output_enc,
                output_file=output_dec,
                password=password,
                quiet=True,
            )
            self.assertTrue(result)

            with open(output_dec, "rb") as f:
                decrypted = f.read()
            self.assertEqual(decrypted, data)

        finally:
            for p in [input_path, output_enc, output_dec]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_aes_gcm_integration(self):
        """AES-GCM streaming integration roundtrip."""
        self._encrypt_decrypt_roundtrip("aes-gcm")

    def test_chacha20_integration(self):
        """ChaCha20-Poly1305 streaming integration roundtrip."""
        self._encrypt_decrypt_roundtrip("chacha20-poly1305")

    def test_xchacha20_integration(self):
        """XChaCha20-Poly1305 streaming integration roundtrip."""
        self._encrypt_decrypt_roundtrip("xchacha20-poly1305")

    def test_aes_gcm_siv_integration(self):
        """AES-GCM-SIV streaming integration roundtrip."""
        self._encrypt_decrypt_roundtrip("aes-gcm-siv")

    @pytest.mark.skip(reason="AES-OCB3 encryption blocked since v1.2.0")
    def test_aes_ocb3_integration(self):
        """AES-OCB3 streaming integration roundtrip."""
        self._encrypt_decrypt_roundtrip("aes-ocb3")

    def test_no_streaming_flag(self):
        """--no-streaming forces one-shot even for large files."""
        data = secrets.token_bytes(20 * 1024)
        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")
        output_dec = _create_temp_file(b"")
        password = b"test-password"

        try:
            result = encrypt_file(
                input_file=input_path,
                output_file=output_enc,
                password=password,
                hash_config=_default_hash_config(),
                algorithm=EncryptionAlgorithm.AES_GCM,
                quiet=True,
                format_version=11,
                no_streaming=True,
                streaming_threshold=1024,
            )
            self.assertTrue(result)

            # Verify it used one-shot (not v12)
            info = extract_file_metadata(output_enc)
            self.assertNotEqual(info["format_version"], 12)

            # Still decrypts correctly
            result = decrypt_file(
                input_file=output_enc,
                output_file=output_dec,
                password=password,
                quiet=True,
            )
            self.assertTrue(result)

            with open(output_dec, "rb") as f:
                self.assertEqual(f.read(), data)
        finally:
            for p in [input_path, output_enc, output_dec]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_below_threshold_uses_oneshot(self):
        """Small files below threshold use one-shot (not v12)."""
        data = secrets.token_bytes(1024)
        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")
        output_dec = _create_temp_file(b"")
        password = b"test-password"

        try:
            result = encrypt_file(
                input_file=input_path,
                output_file=output_enc,
                password=password,
                hash_config=_default_hash_config(),
                algorithm=EncryptionAlgorithm.AES_GCM,
                quiet=True,
                format_version=11,
                streaming_threshold=10 * 1024 * 1024,  # 10 MB
            )
            self.assertTrue(result)

            info = extract_file_metadata(output_enc)
            # Should NOT be v12 since file is tiny
            self.assertNotEqual(info["format_version"], 12)

            # Still decrypts correctly
            result = decrypt_file(
                input_file=output_enc,
                output_file=output_dec,
                password=password,
                quiet=True,
            )
            self.assertTrue(result)
        finally:
            for p in [input_path, output_enc, output_dec]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_fernet_falls_back_to_oneshot(self):
        """Fernet always uses one-shot regardless of file size."""
        data = secrets.token_bytes(20 * 1024)
        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")
        output_dec = _create_temp_file(b"")
        password = b"test-password"

        try:
            result = encrypt_file(
                input_file=input_path,
                output_file=output_enc,
                password=password,
                hash_config=_default_hash_config(),
                algorithm=EncryptionAlgorithm.FERNET,
                quiet=True,
                format_version=11,
                streaming_threshold=1024,
            )
            self.assertTrue(result)

            info = extract_file_metadata(output_enc)
            self.assertNotEqual(info["format_version"], 12)
        finally:
            for p in [input_path, output_enc, output_dec]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_bytes_input_uses_oneshot(self):
        """In-memory bytes input always uses one-shot."""
        data = secrets.token_bytes(20 * 1024)
        password = b"test-password"

        result = encrypt_file(
            input_file=data,
            output_file=None,
            password=password,
            hash_config=_default_hash_config(),
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
            format_version=11,
            streaming_threshold=1024,
        )
        # Returns bytes for in-memory mode
        self.assertIsInstance(result, bytes)


# ============================================================
# Test: Backward compatibility
# ============================================================


class TestBackwardCompatibility(unittest.TestCase):
    """Ensure v10/v11 files still decrypt normally with streaming code present."""

    def test_v11_oneshot_still_works(self):
        """V11 one-shot encrypted file decrypts correctly."""
        data = b"Test data for backward compat v11"
        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")
        output_dec = _create_temp_file(b"")
        password = b"compat-password"

        try:
            result = encrypt_file(
                input_file=input_path,
                output_file=output_enc,
                password=password,
                hash_config=_default_hash_config(),
                algorithm=EncryptionAlgorithm.AES_GCM,
                quiet=True,
                format_version=11,
                no_streaming=True,
            )
            self.assertTrue(result)

            info = extract_file_metadata(output_enc)
            self.assertEqual(info["format_version"], 11)

            result = decrypt_file(
                input_file=output_enc,
                output_file=output_dec,
                password=password,
                quiet=True,
            )
            self.assertTrue(result)

            with open(output_dec, "rb") as f:
                self.assertEqual(f.read(), data)
        finally:
            for p in [input_path, output_enc, output_dec]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_v10_oneshot_still_works(self):
        """V10 one-shot encrypted file decrypts correctly."""
        data = b"Test data for backward compat v10"
        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")
        output_dec = _create_temp_file(b"")
        password = b"compat-password-v10"

        try:
            result = encrypt_file(
                input_file=input_path,
                output_file=output_enc,
                password=password,
                hash_config=_default_hash_config(),
                algorithm=EncryptionAlgorithm.AES_GCM,
                quiet=True,
                format_version=10,
                no_streaming=True,
            )
            self.assertTrue(result)

            info = extract_file_metadata(output_enc)
            self.assertEqual(info["format_version"], 10)

            result = decrypt_file(
                input_file=output_enc,
                output_file=output_dec,
                password=password,
                quiet=True,
            )
            self.assertTrue(result)

            with open(output_dec, "rb") as f:
                self.assertEqual(f.read(), data)
        finally:
            for p in [input_path, output_enc, output_dec]:
                if os.path.exists(p):
                    os.unlink(p)


# ============================================================
# Test: parse_size_string()
# ============================================================


class TestParseSizeString(unittest.TestCase):
    """Tests for parse_size_string() utility."""

    def test_kilobytes(self):
        self.assertEqual(parse_size_string("512K"), 512 * 1024)

    def test_megabytes(self):
        self.assertEqual(parse_size_string("4M"), 4 * 1024 * 1024)

    def test_gigabytes(self):
        self.assertEqual(parse_size_string("1G"), 1024 * 1024 * 1024)

    def test_plain_number(self):
        self.assertEqual(parse_size_string("65536"), 65536)

    def test_lowercase(self):
        self.assertEqual(parse_size_string("1m"), 1024 * 1024)

    def test_invalid_format(self):
        with self.assertRaises(ValueError):
            parse_size_string("abc")

    def test_whitespace_stripped(self):
        self.assertEqual(parse_size_string("  1M  "), 1024 * 1024)


# ============================================================
# Test: Chunk count edge cases
# ============================================================


class TestChunkCount(unittest.TestCase):
    """Tests for StreamingEncryptor.get_chunk_count()."""

    def test_empty_file(self):
        enc = StreamingEncryptor(key=b"k" * 32, algorithm="aes-gcm", chunk_size=1024)
        self.assertEqual(enc.get_chunk_count(0), 0)

    def test_exact_one_chunk(self):
        enc = StreamingEncryptor(key=b"k" * 32, algorithm="aes-gcm", chunk_size=1024)
        self.assertEqual(enc.get_chunk_count(1024), 1)

    def test_partial_last_chunk(self):
        enc = StreamingEncryptor(key=b"k" * 32, algorithm="aes-gcm", chunk_size=1024)
        self.assertEqual(enc.get_chunk_count(1025), 2)

    def test_one_byte(self):
        enc = StreamingEncryptor(key=b"k" * 32, algorithm="aes-gcm", chunk_size=1024)
        self.assertEqual(enc.get_chunk_count(1), 1)

    def test_large_file(self):
        enc = StreamingEncryptor(key=b"k" * 32, algorithm="aes-gcm", chunk_size=1048576)
        # 100 MB file -> 100 chunks of 1MB
        self.assertEqual(enc.get_chunk_count(100 * 1024 * 1024), 100)


class TestStreamingHMACKeyDerivation(unittest.TestCase):
    """Test HKDF-based HMAC key derivation for streaming trailer (H13).

    For format_version >= 12, the streaming HMAC key should be derived
    using HKDF instead of bare SHA-256(key || constant).
    """

    def test_v12_hmac_key_differs_from_legacy(self):
        """Test that v12+ HKDF-derived HMAC key differs from legacy SHA-256."""
        key = secrets.token_bytes(32)
        legacy_hmac_key = hashlib.sha256(key + b"oesc-trailer-hmac").digest()

        enc = StreamingEncryptor(key=key, algorithm="aes-gcm", chunk_size=1024, format_version=12)
        v12_hmac_key = enc._derive_hmac_key()

        self.assertNotEqual(legacy_hmac_key, v12_hmac_key)
        self.assertEqual(len(v12_hmac_key), 32)

    def test_legacy_hmac_key_unchanged(self):
        """Test that legacy (no format_version) HMAC key uses SHA-256."""
        key = secrets.token_bytes(32)
        expected = hashlib.sha256(key + b"oesc-trailer-hmac").digest()

        enc = StreamingEncryptor(key=key, algorithm="aes-gcm", chunk_size=1024)
        legacy_hmac_key = enc._derive_hmac_key()

        self.assertEqual(legacy_hmac_key, expected)

    def test_v11_hmac_key_unchanged(self):
        """Test that format_version=11 uses legacy SHA-256 HMAC key."""
        key = secrets.token_bytes(32)
        expected = hashlib.sha256(key + b"oesc-trailer-hmac").digest()

        enc = StreamingEncryptor(key=key, algorithm="aes-gcm", chunk_size=1024, format_version=11)
        legacy_hmac_key = enc._derive_hmac_key()

        self.assertEqual(legacy_hmac_key, expected)

    def test_v12_hmac_key_deterministic(self):
        """Test that v12+ HKDF HMAC key is deterministic."""
        key = secrets.token_bytes(32)

        enc1 = StreamingEncryptor(key=key, algorithm="aes-gcm", chunk_size=1024, format_version=12)
        enc2 = StreamingEncryptor(key=key, algorithm="aes-gcm", chunk_size=1024, format_version=12)

        self.assertEqual(enc1._derive_hmac_key(), enc2._derive_hmac_key())

    def test_v12_decryptor_hmac_key_matches_encryptor(self):
        """Test that encryptor and decryptor derive the same HMAC key for v12."""
        key = secrets.token_bytes(32)

        enc = StreamingEncryptor(key=key, algorithm="aes-gcm", chunk_size=1024, format_version=12)
        dec = StreamingDecryptor(
            key=key,
            algorithm="aes-gcm",
            nonce_prefix=b"\x00" * 8,
            chunk_size=1024,
            format_version=12,
        )

        self.assertEqual(enc._derive_hmac_key(), dec._derive_hmac_key())

    def test_v12_different_keys_produce_different_hmac_keys(self):
        """Test that different encryption keys produce different HMAC keys."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)

        enc1 = StreamingEncryptor(key=key1, algorithm="aes-gcm", chunk_size=1024, format_version=12)
        enc2 = StreamingEncryptor(key=key2, algorithm="aes-gcm", chunk_size=1024, format_version=12)

        self.assertNotEqual(enc1._derive_hmac_key(), enc2._derive_hmac_key())


class TestStreamingDecryptMemory(unittest.TestCase):
    """Tests that streaming decrypt/metadata reads are memory-bounded."""

    def setUp(self):
        self._tmpfiles = []

    def tearDown(self):
        for p in self._tmpfiles:
            try:
                os.unlink(p)
            except OSError:
                pass

    def _tmp(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        self._tmpfiles.append(path)
        return path

    # ------------------------------------------------------------------
    # 1a. _read_metadata_only returns correct metadata
    # ------------------------------------------------------------------
    def test_read_metadata_only_returns_correct_metadata(self):
        """_read_metadata_only() reads only the b64 metadata before ':'."""
        from openssl_encrypt.modules.crypt_core import _read_metadata_only

        meta = b"SGVsbG8gV29ybGQ="  # base64 for "Hello World"
        payload = os.urandom(1 * 1024 * 1024)  # 1 MB payload
        path = self._tmp(meta + b":" + payload)

        metadata_b64, fallback = _read_metadata_only(path)

        self.assertEqual(metadata_b64, meta)
        self.assertIsNone(fallback, "seekable file should return fallback=None")

    # ------------------------------------------------------------------
    # 1b. _read_metadata_only raises ValueError when no separator
    # ------------------------------------------------------------------
    def test_read_metadata_only_no_separator_raises(self):
        """_read_metadata_only() raises ValueError if no ':' separator found."""
        from openssl_encrypt.modules.crypt_core import _read_metadata_only

        path = self._tmp(b"nodatahere" * 100)

        with self.assertRaises(ValueError):
            _read_metadata_only(path)

    # ------------------------------------------------------------------
    # 1c. streaming decrypt is memory-bounded
    # ------------------------------------------------------------------
    def test_streaming_decrypt_bounded_memory(self):
        """decrypt_file() should not load the full file into memory for v12 streaming."""
        import tracemalloc

        password = "test-password-bounded"
        plaintext = os.urandom(5 * 1024 * 1024)  # 5 MB
        in_path = self._tmp(plaintext)

        fd, enc_path = tempfile.mkstemp()
        os.close(fd)
        self._tmpfiles.append(enc_path)
        fd, dec_path = tempfile.mkstemp()
        os.close(fd)
        self._tmpfiles.append(dec_path)

        # Encrypt with streaming (format_version=11 auto-promotes to 12 with streaming)
        encrypt_file(
            input_file=in_path,
            output_file=enc_path,
            password=password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            format_version=11,
            chunk_size=1024 * 1024,  # 1 MB chunks
            streaming_threshold=1024,  # always stream
            quiet=True,
        )

        enc_size = os.path.getsize(enc_path)

        tracemalloc.start()
        decrypt_file(
            input_file=enc_path,
            output_file=dec_path,
            password=password,
            quiet=True,
        )
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Peak memory should be well below 2x file size.
        # Old (broken) behaviour loaded the full payload plus b64-encode overhead
        # which peaks at ~4-5x enc_size.  Bounded streaming should stay under 2x.
        self.assertLess(
            peak,
            enc_size * 2,
            f"Peak memory {peak / 1024 / 1024:.1f} MB >= 2x enc file size "
            f"({enc_size * 2 / 1024 / 1024:.1f} MB) — full file may have been loaded",
        )

        # Verify correct decryption
        with open(dec_path, "rb") as f:
            result = f.read()
        self.assertEqual(result, plaintext)

    # ------------------------------------------------------------------
    # 1d. extract_file_metadata is memory-bounded for streaming files
    # ------------------------------------------------------------------
    def test_extract_metadata_bounded_for_streaming(self):
        """extract_file_metadata() should not load the full file for v12 streaming."""
        import tracemalloc

        password = "test-meta-bounded"
        plaintext = os.urandom(8 * 1024 * 1024)  # 8 MB — large enough that fixed Python
        # overhead (~2-3 MB) is clearly less than enc_size
        in_path = self._tmp(plaintext)

        fd, enc_path = tempfile.mkstemp()
        os.close(fd)
        self._tmpfiles.append(enc_path)

        encrypt_file(
            input_file=in_path,
            output_file=enc_path,
            password=password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            format_version=11,
            chunk_size=512 * 1024,
            streaming_threshold=1024,
            quiet=True,
        )

        enc_size = os.path.getsize(enc_path)

        tracemalloc.start()
        meta = extract_file_metadata(enc_path)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertEqual(meta["format_version"], 12)
        self.assertLess(
            peak,
            enc_size,
            f"Peak memory {peak / 1024 / 1024:.1f} MB >= enc file size "
            f"{enc_size / 1024 / 1024:.1f} MB — full file was loaded",
        )

    # ------------------------------------------------------------------
    # 1e. Non-streaming files still work correctly (backward compat)
    # ------------------------------------------------------------------
    def test_nonstreaming_decrypt_still_works(self):
        """Non-streaming encrypted files should decrypt correctly after refactor."""
        password = "test-nonstreaming"
        plaintext = os.urandom(1024)  # small — fits in one shot
        in_path = self._tmp(plaintext)

        fd, enc_path = tempfile.mkstemp()
        os.close(fd)
        self._tmpfiles.append(enc_path)
        fd, dec_path = tempfile.mkstemp()
        os.close(fd)
        self._tmpfiles.append(dec_path)

        encrypt_file(
            input_file=in_path,
            output_file=enc_path,
            password=password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            format_version=11,
            no_streaming=True,
            quiet=True,
        )

        meta = extract_file_metadata(enc_path)
        self.assertEqual(meta["format_version"], 11)

        decrypt_file(
            input_file=enc_path,
            output_file=dec_path,
            password=password,
            quiet=True,
        )

        with open(dec_path, "rb") as f:
            result = f.read()
        self.assertEqual(result, plaintext)


class TestCascadeChunkNonceUniqueness(unittest.TestCase):
    """Security regression: cascade + streaming must NOT reuse the per-chunk
    cascade salt across chunks.

    ``CascadeKeyDerivation.derive_layer_keys(master_key, salt)`` derives BOTH
    each layer's key and nonce from ``(master_key, salt)``. If the same
    ``cascade_salt`` is passed for every chunk, every chunk reuses identical
    per-layer (key, nonce) pairs -- catastrophic AEAD nonce reuse. Each chunk
    must therefore be encrypted under a distinct, deterministically derived
    cascade salt. See docs/PLAN_streaming-cascade-nonce_and_envelope.md (#1).
    """

    def test_cascade_per_chunk_salt_is_unique(self):
        """Each chunk must be encrypted under a distinct cascade salt."""
        captured_salts = []

        class _RecordingCascade:
            def encrypt(self, plaintext, master_key, salt, associated_data=None):
                captured_salts.append(bytes(salt))
                return b"C" * (len(plaintext) + 16)

        key = secrets.token_bytes(32)
        cascade_salt = secrets.token_bytes(32)
        chunk_size = 16
        data = b"A" * (chunk_size * 4)  # 4 chunks
        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")

        try:
            enc = StreamingEncryptor(
                key=key,
                algorithm="cascade",
                chunk_size=chunk_size,
                cascade_encryptor=_RecordingCascade(),
                cascade_salt=cascade_salt,
                format_version=12,
            )
            chunk_count = enc.get_chunk_count(len(data))
            metadata_b64 = base64.b64encode(b"{}")

            enc.encrypt_file(
                input_file=input_path,
                output_file=output_enc,
                metadata_b64=metadata_b64,
                chunk_count=chunk_count,
                quiet=True,
            )

            self.assertEqual(len(captured_salts), 4)
            # Security property: the per-chunk salts must be pairwise distinct.
            self.assertEqual(
                len(set(captured_salts)),
                len(captured_salts),
                "cascade salt reused across chunks -> AEAD nonce reuse",
            )
            # And they must be DERIVED, never the raw static base salt.
            self.assertNotIn(cascade_salt, captured_salts)
        finally:
            for p in (input_path, output_enc):
                if os.path.exists(p):
                    os.unlink(p)

    def test_end_to_end_cascade_streaming_records_scheme_2(self):
        """Real cascade+streaming encryption tags the per-chunk scheme and
        round-trips (integration guard for the cascade nonce fix)."""
        password = b"cascade-nonce-scheme-pw"
        data = secrets.token_bytes(8 * 1024)  # multiple chunks at chunk_size=1024
        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")

        try:
            ok = encrypt_file(
                input_file=input_path,
                output_file=output_enc,
                password=password,
                hash_config={"sha256": 1, "pbkdf2_iterations": 0},
                quiet=True,
                chunk_size=1024,
                streaming_threshold=1024,
                algorithm="cascade",
                cascade=True,
                cipher_names=["aes-gcm", "chacha20-poly1305"],
            )
            self.assertTrue(ok)

            with open(output_enc, "rb") as f:
                raw = f.read()
            meta = json.loads(base64.b64decode(raw.split(b":", 1)[0]))
            self.assertTrue(meta["streaming"]["enabled"])
            self.assertGreater(meta["streaming"]["chunk_count"], 1)
            # Fixed scheme (2) must be recorded so decryption derives matching salts.
            self.assertEqual(meta["streaming"]["cascade_nonce_scheme"], 2)

            decrypted = decrypt_file(
                input_file=output_enc, output_file=None, password=password, quiet=True
            )
            self.assertEqual(decrypted, data)
        finally:
            for p in (input_path, output_enc):
                if os.path.exists(p):
                    os.unlink(p)

    def test_legacy_scheme1_file_decrypts_and_warns(self):
        """A cascade+streaming file written with the legacy reused-salt scheme
        (1) must still decrypt (read-compat) AND emit a security warning."""
        from openssl_encrypt.modules.cascade import CascadeConfig, CascadeEncryption
        from openssl_encrypt.modules.streaming import CASCADE_NONCE_SCHEME_LEGACY

        key = secrets.token_bytes(32)
        cascade_salt = secrets.token_bytes(32)
        chunk_size = 1024
        data = secrets.token_bytes(chunk_size * 3 + 17)  # 4 chunks
        cipher_names = ["aes-gcm", "chacha20-poly1305"]

        input_path = _create_temp_file(data)
        output_enc = _create_temp_file(b"")
        output_dec = _create_temp_file(b"")

        try:
            cfg = CascadeConfig(cipher_names=cipher_names, hkdf_hash="sha256")
            casc_enc = CascadeEncryption(cfg, format_version=12, xchacha_nonce_format=2)

            enc = StreamingEncryptor(
                key=key,
                algorithm="cascade",
                chunk_size=chunk_size,
                cascade_encryptor=casc_enc,
                cascade_salt=cascade_salt,
                format_version=12,
                cascade_nonce_scheme=CASCADE_NONCE_SCHEME_LEGACY,  # simulate old file
            )
            chunk_count = enc.get_chunk_count(len(data))
            original_hash = enc.hash_file(input_path)

            # Legacy metadata: deliberately omits the cascade_nonce_scheme flag.
            metadata = {
                "format_version": 12,
                "mode": "symmetric",
                "aead_binding": True,
                "streaming": {
                    "enabled": True,
                    "chunk_size": chunk_size,
                    "chunk_count": chunk_count,
                    "nonce_prefix": base64.b64encode(enc.nonce_prefix).decode("ascii"),
                },
                "hashes": {"original_hash": original_hash},
                "encryption": {"cascade": True, "algorithm": "cascade"},
            }
            metadata_b64 = base64.b64encode(json.dumps(metadata).encode("utf-8"))

            enc.encrypt_file(
                input_file=input_path,
                output_file=output_enc,
                metadata_b64=metadata_b64,
                chunk_count=chunk_count,
                quiet=True,
            )

            casc_dec = CascadeEncryption(cfg, format_version=12, xchacha_nonce_format=2)
            dec = StreamingDecryptor(
                key=key,
                algorithm="cascade",
                nonce_prefix=enc.nonce_prefix,
                chunk_size=chunk_size,
                cascade_decryptor=casc_dec,
                cascade_salt=cascade_salt,
                format_version=12,
                cascade_nonce_scheme=CASCADE_NONCE_SCHEME_LEGACY,
            )

            with self.assertLogs("openssl_encrypt.modules.streaming", level="WARNING") as cm:
                result = dec.decrypt_file(
                    input_file=output_enc,
                    output_file=output_dec,
                    metadata_b64=metadata_b64,
                    expected_chunk_count=chunk_count,
                    original_hash=original_hash,
                    quiet=False,
                )

            self.assertTrue(result)
            with open(output_dec, "rb") as f:
                self.assertEqual(f.read(), data)
            self.assertTrue(
                any(
                    "legacy" in m.lower() or "rekey" in m.lower() or "nonce" in m.lower()
                    for m in cm.output
                ),
                f"expected a legacy-nonce security warning, got: {cm.output}",
            )
        finally:
            for p in (input_path, output_enc, output_dec):
                if os.path.exists(p):
                    os.unlink(p)


class TestFullPipelineStreamingRoundtrip(unittest.TestCase):
    """Full-pipeline streaming coverage (parity with 1.4.x / issue #50).

    The streaming module tests use known keys and bypass the KDF pipeline. This
    class exercises encrypt_file -> decrypt_file through the public API so that a
    regression in the streaming key-derivation ordering (the password key must be
    derived at the format_version that gets stored, v12) is caught. 1.5.x already
    derives correctly; this test guards against future regressions.
    """

    _FAST = {"sha256": 1, "pbkdf2_iterations": 0}

    def _roundtrip(self, algorithm="aes-gcm", cascade=False, cipher_names=None, **extra):
        data = secrets.token_bytes(8 * 1024)  # several chunks at chunk_size=1024
        ip = _create_temp_file(data)
        op = _create_temp_file(b"")
        try:
            kw = dict(
                input_file=ip,
                output_file=op,
                password=b"full-pipeline-streaming-pw",
                hash_config=dict(self._FAST),
                quiet=True,
                chunk_size=1024,
                streaming_threshold=1024,  # force the streaming path
            )
            if cascade:
                kw.update(algorithm="cascade", cascade=True, cipher_names=cipher_names)
            else:
                kw.update(algorithm=algorithm)
            kw.update(extra)
            self.assertTrue(encrypt_file(**kw))

            # Confirm it really streamed (format_version 12 metadata).
            with open(op, "rb") as f:
                meta = json.loads(base64.b64decode(f.read().split(b":", 1)[0]))
            self.assertTrue(meta.get("streaming", {}).get("enabled"))
            self.assertEqual(meta.get("format_version"), 12)

            result = decrypt_file(
                input_file=op,
                output_file=None,
                password=b"full-pipeline-streaming-pw",
                quiet=True,
            )
            self.assertEqual(result, data)
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)

    def test_aes_gcm_streaming_roundtrip(self):
        self._roundtrip(algorithm="aes-gcm")

    def test_chacha_streaming_roundtrip(self):
        self._roundtrip(algorithm="chacha20-poly1305")

    def test_cascade_streaming_roundtrip(self):
        self._roundtrip(cascade=True, cipher_names=["aes-gcm", "chacha20-poly1305"])

    def test_wrong_password_fails(self):
        data = secrets.token_bytes(8 * 1024)
        ip = _create_temp_file(data)
        op = _create_temp_file(b"")
        try:
            self.assertTrue(
                encrypt_file(
                    input_file=ip,
                    output_file=op,
                    password=b"right-pw",
                    hash_config=dict(self._FAST),
                    quiet=True,
                    algorithm="aes-gcm",
                    chunk_size=1024,
                    streaming_threshold=1024,
                )
            )
            with self.assertRaises(Exception):
                decrypt_file(input_file=op, output_file=None, password=b"wrong-pw", quiet=True)
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)


if __name__ == "__main__":
    unittest.main()
