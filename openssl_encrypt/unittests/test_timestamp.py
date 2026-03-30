#!/usr/bin/env python3
"""
Unit tests for encrypted_at timestamp feature.

Tests that:
- encrypted_at is present in metadata after encryption
- encrypted_at is valid ISO 8601 format
- Old files without encrypted_at still decrypt fine
- Decryption prints age warning for files older than 2 years
"""

import base64
import datetime
import json
import os
import shutil
import tempfile
import unittest
from io import StringIO
from unittest import mock

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
)


class TestEncryptedAtPresence(unittest.TestCase):
    """Test that encrypted_at timestamp is added to metadata during encryption."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_content = b"Hello World! Testing timestamp."
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_encrypted_at_present_in_metadata(self):
        """encrypted_at field must be present in metadata after encryption."""
        encrypted_file = os.path.join(self.temp_dir, "encrypted.bin")

        encrypt_file(
            input_file=self.test_file,
            output_file=encrypted_file,
            password=self.password,
            quiet=True,
        )

        info = extract_file_metadata(encrypted_file)
        metadata = info["metadata"]
        self.assertIn("encrypted_at", metadata)

    def test_encrypted_at_present_fernet(self):
        """encrypted_at is present when using fernet algorithm."""
        encrypted_file = os.path.join(self.temp_dir, "encrypted_fernet.bin")

        encrypt_file(
            input_file=self.test_file,
            output_file=encrypted_file,
            password=self.password,
            quiet=True,
            algorithm=EncryptionAlgorithm.FERNET,
        )

        info = extract_file_metadata(encrypted_file)
        metadata = info["metadata"]
        self.assertIn("encrypted_at", metadata)

    def test_encrypted_at_present_chacha(self):
        """encrypted_at is present when using chacha20-poly1305."""
        encrypted_file = os.path.join(self.temp_dir, "encrypted_chacha.bin")

        encrypt_file(
            input_file=self.test_file,
            output_file=encrypted_file,
            password=self.password,
            quiet=True,
            algorithm=EncryptionAlgorithm.CHACHA20_POLY1305,
        )

        info = extract_file_metadata(encrypted_file)
        metadata = info["metadata"]
        self.assertIn("encrypted_at", metadata)


class TestEncryptedAtFormat(unittest.TestCase):
    """Test that encrypted_at follows ISO 8601 UTC format."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "wb") as f:
            f.write(b"Test content for format validation.")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_encrypted_at_iso8601_format(self):
        """encrypted_at must be valid ISO 8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)."""
        encrypted_file = os.path.join(self.temp_dir, "encrypted.bin")

        encrypt_file(
            input_file=self.test_file,
            output_file=encrypted_file,
            password=self.password,
            quiet=True,
        )

        info = extract_file_metadata(encrypted_file)
        timestamp = info["metadata"]["encrypted_at"]

        # Must end with Z (UTC)
        self.assertTrue(timestamp.endswith("Z"), f"Timestamp must end with 'Z': {timestamp}")

        # Must parse as valid datetime
        parsed = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        self.assertIsInstance(parsed, datetime.datetime)

    def test_encrypted_at_is_recent(self):
        """encrypted_at timestamp should be within last minute (i.e., set at encryption time)."""
        encrypted_file = os.path.join(self.temp_dir, "encrypted.bin")

        before = datetime.datetime.utcnow()
        encrypt_file(
            input_file=self.test_file,
            output_file=encrypted_file,
            password=self.password,
            quiet=True,
        )
        after = datetime.datetime.utcnow()

        info = extract_file_metadata(encrypted_file)
        timestamp = info["metadata"]["encrypted_at"]
        parsed = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")

        # Timestamp should be between before and after
        self.assertGreaterEqual(parsed, before.replace(microsecond=0))
        self.assertLessEqual(parsed, after + datetime.timedelta(seconds=1))


class TestBackwardCompatibility(unittest.TestCase):
    """Test that old files without encrypted_at still decrypt correctly."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_content = b"Backward compat test content."

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_file_without_timestamp_decrypts(self):
        """Files without encrypted_at (created by older versions) must still decrypt."""
        encrypted_file = os.path.join(self.temp_dir, "no_timestamp.bin")

        # Write test file first
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, "wb") as f:
            f.write(self.test_content)

        encrypt_file(
            input_file=test_file,
            output_file=encrypted_file,
            password=self.password,
            quiet=True,
        )

        # Manually strip encrypted_at from metadata to simulate old file
        with open(encrypted_file, "rb") as f:
            content = f.read()

        metadata_b64, encrypted_data = content.split(b":", 1)
        metadata = json.loads(base64.b64decode(metadata_b64))
        metadata.pop("encrypted_at", None)

        # Re-encode without timestamp
        new_metadata_b64 = base64.b64encode(json.dumps(metadata).encode("utf-8"))
        with open(encrypted_file, "wb") as f:
            f.write(new_metadata_b64 + b":" + encrypted_data)

        # Must still decrypt successfully
        decrypted = decrypt_file(
            input_file=encrypted_file,
            output_file=None,
            password=self.password,
            quiet=True,
        )
        self.assertEqual(decrypted, self.test_content)


class TestAgeWarning(unittest.TestCase):
    """Test that decryption prints age warning for old files."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_content = b"Age warning test content."
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_encrypted_file_with_old_timestamp(self, years_ago: int) -> str:
        """Helper: encrypt file, then modify timestamp to be years_ago years old."""
        encrypted_file = os.path.join(self.temp_dir, f"old_{years_ago}y.bin")

        encrypt_file(
            input_file=self.test_file,
            output_file=encrypted_file,
            password=self.password,
            quiet=True,
        )

        # Modify timestamp to be old
        with open(encrypted_file, "rb") as f:
            content = f.read()

        metadata_b64, encrypted_data = content.split(b":", 1)
        metadata = json.loads(base64.b64decode(metadata_b64))

        old_date = datetime.datetime.utcnow() - datetime.timedelta(days=365 * years_ago + 1)
        metadata["encrypted_at"] = old_date.strftime("%Y-%m-%dT%H:%M:%SZ")

        new_metadata_b64 = base64.b64encode(json.dumps(metadata).encode("utf-8"))
        with open(encrypted_file, "wb") as f:
            f.write(new_metadata_b64 + b":" + encrypted_data)

        return encrypted_file

    def test_age_warning_for_old_file(self):
        """Decryption of file >2 years old should print age warning."""
        encrypted_file = self._create_encrypted_file_with_old_timestamp(3)

        output_file = os.path.join(self.temp_dir, "decrypted.txt")

        with mock.patch("sys.stderr", new_callable=StringIO) as mock_stderr:
            decrypt_file(
                input_file=encrypted_file,
                output_file=output_file,
                password=self.password,
                quiet=False,
                no_estimate=True,
            )
            warning_output = mock_stderr.getvalue()

        # Check warning was printed
        self.assertIn("re-encrypt", warning_output.lower())

    def test_no_age_warning_for_recent_file(self):
        """Decryption of recent file should NOT print age warning."""
        encrypted_file = os.path.join(self.temp_dir, "recent.bin")

        encrypt_file(
            input_file=self.test_file,
            output_file=encrypted_file,
            password=self.password,
            quiet=True,
        )

        output_file = os.path.join(self.temp_dir, "decrypted.txt")

        with mock.patch("sys.stderr", new_callable=StringIO) as mock_stderr:
            decrypt_file(
                input_file=encrypted_file,
                output_file=output_file,
                password=self.password,
                quiet=False,
                no_estimate=True,
            )
            warning_output = mock_stderr.getvalue()

        self.assertNotIn("re-encrypt", warning_output.lower())

    def test_no_age_warning_when_quiet(self):
        """No age warning when quiet=True."""
        encrypted_file = self._create_encrypted_file_with_old_timestamp(3)

        output_file = os.path.join(self.temp_dir, "decrypted_quiet.txt")

        with mock.patch("sys.stderr", new_callable=StringIO) as mock_stderr:
            decrypt_file(
                input_file=encrypted_file,
                output_file=output_file,
                password=self.password,
                quiet=True,
            )
            warning_output = mock_stderr.getvalue()

        self.assertNotIn("re-encrypt", warning_output.lower())

    def test_no_age_warning_without_timestamp(self):
        """No age warning when encrypted_at is missing (old files)."""
        encrypted_file = os.path.join(self.temp_dir, "no_ts.bin")

        encrypt_file(
            input_file=self.test_file,
            output_file=encrypted_file,
            password=self.password,
            quiet=True,
        )

        # Strip timestamp
        with open(encrypted_file, "rb") as f:
            content = f.read()

        metadata_b64, encrypted_data = content.split(b":", 1)
        metadata = json.loads(base64.b64decode(metadata_b64))
        metadata.pop("encrypted_at", None)
        new_metadata_b64 = base64.b64encode(json.dumps(metadata).encode("utf-8"))
        with open(encrypted_file, "wb") as f:
            f.write(new_metadata_b64 + b":" + encrypted_data)

        output_file = os.path.join(self.temp_dir, "decrypted_no_ts.txt")

        with mock.patch("sys.stderr", new_callable=StringIO) as mock_stderr:
            decrypt_file(
                input_file=encrypted_file,
                output_file=output_file,
                password=self.password,
                quiet=False,
                no_estimate=True,
            )
            warning_output = mock_stderr.getvalue()

        self.assertNotIn("re-encrypt", warning_output.lower())


if __name__ == "__main__":
    unittest.main()
