#!/usr/bin/env python3
"""
Unit tests for the verify module — structural integrity checks without password.

Tests valid files, invalid/corrupted files, streaming structure validation,
and output modes (JSON, verbose).
"""

import base64
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from io import StringIO
from unittest import mock

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    encrypt_file,
)
from openssl_encrypt.modules.verify import (
    FileVerifier,
    VerificationResult,
    verify_file_integrity,
)


class TestVerifyValidFiles(unittest.TestCase):
    """Test verification of freshly encrypted valid files."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_content = b"Hello World! Testing verify action."
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _encrypt(self, algorithm=EncryptionAlgorithm.FERNET, **kwargs):
        """Helper to encrypt test file and return encrypted file path."""
        enc_file = os.path.join(self.temp_dir, "encrypted.bin")
        encrypt_file(
            input_file=self.test_file,
            output_file=enc_file,
            password=self.password,
            algorithm=algorithm,
            quiet=True,
            **kwargs,
        )
        return enc_file

    def test_verify_fernet_encrypted_file(self):
        """Freshly encrypted fernet file passes all checks."""
        enc_file = self._encrypt(EncryptionAlgorithm.FERNET)
        all_passed, results = verify_file_integrity(enc_file, json_output=False)
        self.assertTrue(all_passed)
        self.assertTrue(all(r.passed for r in results))

    def test_verify_aes_gcm_encrypted_file(self):
        """Freshly encrypted AES-GCM file passes all checks."""
        enc_file = self._encrypt(EncryptionAlgorithm.AES_GCM)
        all_passed, results = verify_file_integrity(enc_file, json_output=False)
        self.assertTrue(all_passed)

    def test_verify_chacha20_encrypted_file(self):
        """Freshly encrypted ChaCha20-Poly1305 file passes all checks."""
        enc_file = self._encrypt(EncryptionAlgorithm.CHACHA20_POLY1305)
        all_passed, results = verify_file_integrity(enc_file, json_output=False)
        self.assertTrue(all_passed)

    def test_verify_streaming_v12_file(self):
        """Freshly encrypted streaming v12 file passes all checks."""
        # Create larger file to trigger streaming
        large_file = os.path.join(self.temp_dir, "large.bin")
        with open(large_file, "wb") as f:
            f.write(os.urandom(64 * 1024))  # 64 KB

        enc_file = os.path.join(self.temp_dir, "large.enc")
        encrypt_file(
            input_file=large_file,
            output_file=enc_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
            format_version=12,
            no_streaming=False,
            streaming_threshold=1024,  # Force streaming for small file
            chunk_size=16384,
        )

        all_passed, results = verify_file_integrity(enc_file, json_output=False)
        self.assertTrue(all_passed)
        # Verify streaming structure check was run
        streaming_checks = [r for r in results if r.check_name == "streaming_structure"]
        self.assertEqual(len(streaming_checks), 1)
        self.assertTrue(streaming_checks[0].passed)

    def test_verify_returns_results_list(self):
        """verify_file_integrity returns a list of VerificationResult."""
        enc_file = self._encrypt()
        _, results = verify_file_integrity(enc_file, json_output=False)
        self.assertIsInstance(results, list)
        for r in results:
            self.assertIsInstance(r, VerificationResult)
            self.assertIsInstance(r.check_name, str)
            self.assertIsInstance(r.passed, bool)
            self.assertIsInstance(r.message, str)


class TestVerifyInvalidFiles(unittest.TestCase):
    """Test verification of invalid/corrupted files."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_nonexistent_file(self):
        """Nonexistent file fails verification."""
        all_passed, results = verify_file_integrity(
            os.path.join(self.temp_dir, "nonexistent.enc"),
            json_output=False,
        )
        self.assertFalse(all_passed)
        self.assertEqual(results[0].check_name, "file_readable")
        self.assertFalse(results[0].passed)

    def test_empty_file(self):
        """Empty file fails verification."""
        empty = os.path.join(self.temp_dir, "empty.enc")
        with open(empty, "wb") as f:
            pass
        all_passed, results = verify_file_integrity(empty, json_output=False)
        self.assertFalse(all_passed)

    def test_random_bytes_file(self):
        """Random bytes file (no colon) fails verification."""
        random_file = os.path.join(self.temp_dir, "random.enc")
        with open(random_file, "wb") as f:
            f.write(os.urandom(1024))
        all_passed, results = verify_file_integrity(random_file, json_output=False)
        self.assertFalse(all_passed)

    def test_corrupted_base64(self):
        """File with invalid base64 before colon fails."""
        bad_file = os.path.join(self.temp_dir, "bad_b64.enc")
        with open(bad_file, "wb") as f:
            f.write(b"!!!not-valid-base64!!!:encrypted_data")
        all_passed, results = verify_file_integrity(bad_file, json_output=False)
        self.assertFalse(all_passed)

    def test_invalid_json_metadata(self):
        """File with valid base64 but invalid JSON fails."""
        bad_file = os.path.join(self.temp_dir, "bad_json.enc")
        metadata_b64 = base64.b64encode(b"this is not json")
        with open(bad_file, "wb") as f:
            f.write(metadata_b64 + b":encrypted_data")
        all_passed, results = verify_file_integrity(bad_file, json_output=False)
        self.assertFalse(all_passed)

    def test_missing_required_fields(self):
        """File with valid JSON but missing required fields fails."""
        bad_file = os.path.join(self.temp_dir, "bad_schema.enc")
        metadata = {"some_field": "value"}
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode())
        with open(bad_file, "wb") as f:
            f.write(metadata_b64 + b":encrypted_data")
        all_passed, results = verify_file_integrity(bad_file, json_output=False)
        self.assertFalse(all_passed)

    def test_unsupported_format_version(self):
        """File with unsupported format version fails."""
        bad_file = os.path.join(self.temp_dir, "bad_version.enc")
        metadata = {
            "format_version": 999,
            "encryption": {"algorithm": "aes-gcm"},
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode())
        with open(bad_file, "wb") as f:
            f.write(metadata_b64 + b":encrypted_data")
        all_passed, results = verify_file_integrity(bad_file, json_output=False)
        self.assertFalse(all_passed)

    def test_format_version_too_low(self):
        """File with format version below minimum fails."""
        bad_file = os.path.join(self.temp_dir, "old_version.enc")
        metadata = {
            "format_version": 1,
            "encryption": {"algorithm": "aes-gcm"},
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode())
        with open(bad_file, "wb") as f:
            f.write(metadata_b64 + b":encrypted_data")
        all_passed, results = verify_file_integrity(bad_file, json_output=False)
        self.assertFalse(all_passed)

    def test_directory_not_file(self):
        """Directory path fails file_readable check."""
        all_passed, results = verify_file_integrity(self.temp_dir, json_output=False)
        self.assertFalse(all_passed)
        self.assertIn("not a regular file", results[0].message.lower())

    def test_truncated_encrypted_file(self):
        """Truncated file with valid metadata but empty payload fails."""
        bad_file = os.path.join(self.temp_dir, "truncated.enc")
        metadata = {
            "format_version": 10,
            "encryption": {"algorithm": "aes-gcm"},
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode())
        with open(bad_file, "wb") as f:
            f.write(metadata_b64 + b":")
        all_passed, results = verify_file_integrity(bad_file, json_output=False)
        self.assertFalse(all_passed)


class TestVerifyStreamingStructure(unittest.TestCase):
    """Test streaming structure validation for format v12."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_streaming_file(self, payload: bytes) -> str:
        """Create a file with v12 metadata and custom streaming payload."""
        filepath = os.path.join(self.temp_dir, "stream.enc")
        metadata = {
            "format_version": 12,
            "encryption": {"algorithm": "aes-gcm"},
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode())
        with open(filepath, "wb") as f:
            f.write(metadata_b64 + b":" + payload)
        return filepath

    def test_missing_oesc_magic(self):
        """Missing OESC magic bytes fails streaming check."""
        filepath = self._make_streaming_file(b"XXXX" + b"\x00" * 40)
        all_passed, results = verify_file_integrity(filepath, json_output=False)
        self.assertFalse(all_passed)
        streaming = [r for r in results if r.check_name == "streaming_structure"]
        self.assertEqual(len(streaming), 1)
        self.assertFalse(streaming[0].passed)

    def test_wrong_payload_version(self):
        """Wrong payload version fails streaming check."""
        payload = b"OESC" + struct.pack("<I", 99)  # Wrong version
        payload += b"\x00" * 40
        filepath = self._make_streaming_file(payload)
        all_passed, results = verify_file_integrity(filepath, json_output=False)
        self.assertFalse(all_passed)

    def test_valid_single_chunk_structure(self):
        """Valid single-chunk streaming structure passes."""
        ciphertext = os.urandom(32)
        chunk = struct.pack("<I", 0)  # chunk_index = 0
        chunk += struct.pack("<I", len(ciphertext))
        chunk += ciphertext
        trailer = struct.pack("<I", 1)  # chunk_count = 1
        trailer += os.urandom(32)  # HMAC commitment

        payload = b"OESC" + struct.pack("<I", 1) + chunk + trailer
        filepath = self._make_streaming_file(payload)
        all_passed, results = verify_file_integrity(filepath, json_output=False)
        self.assertTrue(all_passed)

    def test_chunk_count_mismatch(self):
        """Trailer chunk count mismatch fails."""
        ciphertext = os.urandom(32)
        chunk = struct.pack("<I", 0) + struct.pack("<I", len(ciphertext)) + ciphertext
        trailer = struct.pack("<I", 5)  # Wrong count (should be 1)
        trailer += os.urandom(32)

        payload = b"OESC" + struct.pack("<I", 1) + chunk + trailer
        filepath = self._make_streaming_file(payload)
        all_passed, results = verify_file_integrity(filepath, json_output=False)
        self.assertFalse(all_passed)

    def test_non_sequential_chunk_index(self):
        """Non-sequential chunk indices fail."""
        ct1 = os.urandom(16)
        ct2 = os.urandom(16)
        chunk1 = struct.pack("<I", 0) + struct.pack("<I", len(ct1)) + ct1
        chunk2 = struct.pack("<I", 5) + struct.pack("<I", len(ct2)) + ct2  # Gap!
        trailer = struct.pack("<I", 2) + os.urandom(32)

        payload = b"OESC" + struct.pack("<I", 1) + chunk1 + chunk2 + trailer
        filepath = self._make_streaming_file(payload)
        all_passed, results = verify_file_integrity(filepath, json_output=False)
        self.assertFalse(all_passed)

    def test_non_streaming_format_skips_check(self):
        """Non-v12 format skips streaming structure check."""
        filepath = os.path.join(self.temp_dir, "v10.enc")
        metadata = {
            "format_version": 10,
            "encryption": {"algorithm": "aes-gcm"},
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode())
        with open(filepath, "wb") as f:
            f.write(metadata_b64 + b":some_data")
        _, results = verify_file_integrity(filepath, json_output=False)
        streaming = [r for r in results if r.check_name == "streaming_structure"]
        self.assertEqual(len(streaming), 1)
        self.assertTrue(streaming[0].passed)  # Skipped = pass


class TestVerifyOutput(unittest.TestCase):
    """Test output formatting modes."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "wb") as f:
            f.write(b"test content")
        self.enc_file = os.path.join(self.temp_dir, "encrypted.bin")
        encrypt_file(
            input_file=self.test_file,
            output_file=self.enc_file,
            password=self.password,
            quiet=True,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_json_output_is_valid_json(self):
        """JSON output mode produces valid JSON."""
        captured = StringIO()
        with mock.patch("sys.stdout", captured):
            verify_file_integrity(self.enc_file, json_output=True)
        output = json.loads(captured.getvalue())
        self.assertIn("valid", output)
        self.assertIn("checks", output)
        self.assertIn("file", output)

    def test_json_output_valid_flag(self):
        """JSON output has correct valid flag for valid file."""
        captured = StringIO()
        with mock.patch("sys.stdout", captured):
            all_passed, _ = verify_file_integrity(self.enc_file, json_output=True)
        output = json.loads(captured.getvalue())
        self.assertTrue(output["valid"])
        self.assertTrue(all_passed)

    def test_json_output_invalid_flag(self):
        """JSON output has correct valid flag for invalid file."""
        captured = StringIO()
        with mock.patch("sys.stdout", captured):
            all_passed, _ = verify_file_integrity(
                os.path.join(self.temp_dir, "nonexistent"),
                json_output=True,
            )
        output = json.loads(captured.getvalue())
        self.assertFalse(output["valid"])
        self.assertFalse(all_passed)

    def test_verbose_output_includes_details(self):
        """Verbose mode includes detail lines (on stderr)."""
        captured = StringIO()
        with mock.patch("sys.stderr", captured):
            verify_file_integrity(self.enc_file, json_output=False, verbose=True)
        output = captured.getvalue()
        # Verbose should show size details, keys, etc.
        self.assertIn("Size:", output)

    def test_json_verbose_includes_details(self):
        """JSON verbose includes details field in checks."""
        captured = StringIO()
        with mock.patch("sys.stdout", captured):
            verify_file_integrity(self.enc_file, json_output=True, verbose=True)
        output = json.loads(captured.getvalue())
        # At least some checks should have details
        has_details = any("details" in c for c in output["checks"])
        self.assertTrue(has_details)

    def test_text_output_shows_pass(self):
        """Text output shows PASS for valid file (on stderr)."""
        captured = StringIO()
        with mock.patch("sys.stderr", captured):
            verify_file_integrity(self.enc_file, json_output=False)
        self.assertIn("PASS", captured.getvalue())

    def test_text_output_shows_fail(self):
        """Text output shows FAIL for invalid file (on stderr)."""
        captured = StringIO()
        with mock.patch("sys.stderr", captured):
            verify_file_integrity(
                os.path.join(self.temp_dir, "nonexistent"),
                json_output=False,
            )
        self.assertIn("FAIL", captured.getvalue())


class TestFileVerifierDirectly(unittest.TestCase):
    """Test FileVerifier class directly."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_legacy_format_version_3(self):
        """Legacy format version 3 passes schema check with minimal fields."""
        filepath = os.path.join(self.temp_dir, "legacy.enc")
        metadata = {
            "format_version": 3,
            "algorithm": "fernet",
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode())
        with open(filepath, "wb") as f:
            f.write(metadata_b64 + b":some_encrypted_data")

        verifier = FileVerifier(filepath)
        all_passed, results = verifier.run_all_checks()
        schema_check = [r for r in results if r.check_name == "metadata_schema"]
        self.assertEqual(len(schema_check), 1)
        self.assertTrue(schema_check[0].passed)

    def test_metadata_not_dict(self):
        """Metadata that is JSON but not a dict fails."""
        filepath = os.path.join(self.temp_dir, "array.enc")
        metadata_b64 = base64.b64encode(json.dumps([1, 2, 3]).encode())
        with open(filepath, "wb") as f:
            f.write(metadata_b64 + b":data")

        verifier = FileVerifier(filepath)
        all_passed, results = verifier.run_all_checks()
        self.assertFalse(all_passed)

    def test_format_version_not_integer(self):
        """Non-integer format_version fails."""
        filepath = os.path.join(self.temp_dir, "str_version.enc")
        metadata = {
            "format_version": "ten",
            "encryption": {"algorithm": "aes-gcm"},
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode())
        with open(filepath, "wb") as f:
            f.write(metadata_b64 + b":data")

        verifier = FileVerifier(filepath)
        all_passed, results = verifier.run_all_checks()
        version_check = [r for r in results if r.check_name == "format_version"]
        self.assertFalse(version_check[0].passed)

    def test_encryption_field_not_dict(self):
        """encryption field that is not a dict fails schema check."""
        filepath = os.path.join(self.temp_dir, "bad_enc.enc")
        metadata = {
            "format_version": 10,
            "encryption": "not_a_dict",
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode())
        with open(filepath, "wb") as f:
            f.write(metadata_b64 + b":data")

        verifier = FileVerifier(filepath)
        all_passed, results = verifier.run_all_checks()
        schema_check = [r for r in results if r.check_name == "metadata_schema"]
        self.assertFalse(schema_check[0].passed)


if __name__ == "__main__":
    unittest.main()
