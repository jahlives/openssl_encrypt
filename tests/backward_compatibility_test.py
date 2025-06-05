#!/usr/bin/env python3
"""
Backward Compatibility Test for Metadata Formats v3 and v4

This script checks that the recent changes to support metadata format version 5
don't break backward compatibility with versions 3 and 4.
"""

import base64
import json
import os
import shutil
import sys
import tempfile
import unittest
import uuid
from typing import Any, Dict, List, Tuple

# Add the parent directory to the path so we can import the module
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file
from openssl_encrypt.modules.keystore_utils import extract_key_id_from_metadata


class BackwardCompatibilityTest(unittest.TestCase):
    """Test that older metadata formats still work properly after v5 changes"""

    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()

        # Create a test file
        self.test_file = os.path.join(self.test_dir, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("Hello, World! Backward Compatibility Test")

        # Keep track of files to clean up
        self.test_files = [self.test_file]

        # Common passwords for testing
        self.password = b"test_password"

    def tearDown(self):
        """Clean up test environment"""
        # Remove test files
        for file_path in self.test_files:
            if os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except:
                    pass

        # Remove temporary directory
        shutil.rmtree(self.test_dir)

    def test_version3_compatibility(self):
        """Test that version 3 test files can still be processed"""
        test_file_path = "openssl_encrypt/unittests/testfiles/v3/test1_kyber768.txt"

        # Check if the test file exists
        self.assertTrue(os.path.exists(test_file_path), f"Test file not found: {test_file_path}")

        # Read the metadata format version from the file
        with open(test_file_path, "rb") as f:
            data = f.read(8192)
            colon_pos = data.find(b":")
            if colon_pos > 0:
                metadata_b64 = data[:colon_pos]
                try:
                    metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                    metadata = json.loads(metadata_json)
                    format_version = metadata.get("format_version", 1)
                    self.assertEqual(
                        format_version, 3, f"Expected format version 3, got {format_version}"
                    )
                except Exception as e:
                    self.fail(f"Failed to parse metadata: {e}")

        # Try to extract key_id (if it exists in the test file)
        key_id = extract_key_id_from_metadata(test_file_path, verbose=True)
        # No assertion here as the test file might not have a key_id

    def test_version4_compatibility(self):
        """Test that version 4 test files can still be processed"""
        test_file_path = "openssl_encrypt/unittests/testfiles/v4/test1_kyber768.txt"

        # Check if the test file exists
        self.assertTrue(os.path.exists(test_file_path), f"Test file not found: {test_file_path}")

        # Read the metadata format version from the file
        with open(test_file_path, "rb") as f:
            data = f.read(8192)
            colon_pos = data.find(b":")
            if colon_pos > 0:
                metadata_b64 = data[:colon_pos]
                try:
                    metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                    metadata = json.loads(metadata_json)
                    format_version = metadata.get("format_version", 1)
                    self.assertEqual(
                        format_version, 4, f"Expected format version 4, got {format_version}"
                    )
                except Exception as e:
                    self.fail(f"Failed to parse metadata: {e}")

        # Try to extract key_id (if it exists in the test file)
        key_id = extract_key_id_from_metadata(test_file_path, verbose=True)
        # No assertion here as the test file might not have a key_id

    def test_decrypt_v3_format(self):
        """Test that a v3 format file can be decrypted"""
        test_file_path = "openssl_encrypt/unittests/testfiles/v3/test1_aes-gcm.txt"
        decrypted_file = os.path.join(self.test_dir, "decrypted_v3.txt")
        self.test_files.append(decrypted_file)

        # Verify the file exists and is v3 format
        self.assertTrue(os.path.exists(test_file_path))

        # Verify the format version
        with open(test_file_path, "rb") as f:
            data = f.read(8192)
            colon_pos = data.find(b":")
            if colon_pos > 0:
                metadata_b64 = data[:colon_pos]
                try:
                    metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                    metadata = json.loads(metadata_json)
                    format_version = metadata.get("format_version", 1)
                    self.assertEqual(
                        format_version, 3, f"Expected format version 3, got {format_version}"
                    )
                except Exception as e:
                    self.fail(f"Failed to parse metadata: {e}")

        # Decrypt the file
        result = decrypt_file(
            input_file=test_file_path, output_file=decrypted_file, password=self.password
        )

        self.assertTrue(result)
        self.assertTrue(os.path.exists(decrypted_file))

        # Verify the content
        with open(decrypted_file, "r") as f:
            content = f.read()

        with open(self.test_file, "r") as f:
            original_content = f.read()

        self.assertEqual(content, original_content)

    def test_decrypt_v4_format(self):
        """Test that a v4 format file can be decrypted"""
        test_file_path = "openssl_encrypt/unittests/testfiles/v4/test1_aes-gcm.txt"
        decrypted_file = os.path.join(self.test_dir, "decrypted_v4.txt")
        self.test_files.append(decrypted_file)

        # Verify the file exists and is v4 format
        self.assertTrue(os.path.exists(test_file_path))

        # Verify the format version
        with open(test_file_path, "rb") as f:
            data = f.read(8192)
            colon_pos = data.find(b":")
            if colon_pos > 0:
                metadata_b64 = data[:colon_pos]
                try:
                    metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                    metadata = json.loads(metadata_json)
                    format_version = metadata.get("format_version", 1)
                    self.assertEqual(
                        format_version, 4, f"Expected format version 4, got {format_version}"
                    )
                except Exception as e:
                    self.fail(f"Failed to parse metadata: {e}")

        # Decrypt the file
        result = decrypt_file(
            input_file=test_file_path, output_file=decrypted_file, password=self.password
        )

        self.assertTrue(result)
        self.assertTrue(os.path.exists(decrypted_file))


if __name__ == "__main__":
    unittest.main()
