#!/usr/bin/env python3
"""
Tests for verifying Kyber v5 files fail decryption with wrong encryption_data.

These tests verify that trying to decrypt Kyber-encrypted files with the correct password
but wrong encryption_data setting will correctly fail.
"""

import os
import sys
import base64
import json
import pytest
from typing import Optional

# Add the parent directory to the path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the modules to test
from modules.crypt_core import decrypt_file
from modules.crypt_errors import DecryptionError, AuthenticationError, ValidationError


def get_kyber_test_files_v5():
    """Get a list of Kyber test files for v5 format."""
    try:
        files_dir = os.path.join(os.path.dirname(__file__), "testfiles", "v5")
        files = os.listdir(files_dir)
        return [f for f in files if f.startswith("test1_kyber")]
    except:
        return []


def get_metadata(file_path: str) -> dict:
    """
    Extract metadata from encrypted file.
    
    Args:
        file_path: Path to the encrypted file
        
    Returns:
        dict: Metadata from the file
    """
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Split file content by colon to get the metadata part
    metadata_b64 = content.split(':', 1)[0]
    metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
    metadata = json.loads(metadata_json)
    
    return metadata


def get_wrong_encryption_data(file_path: str) -> str:
    """
    Get an encryption_data value that's different from what's in the file.
    
    Args:
        file_path: Path to the encrypted file
        
    Returns:
        str: An encryption_data value that's different from what's in the file
    """
    # Available encryption_data options
    encryption_data_options = [
        "aes-gcm", "aes-gcm-siv", "aes-ocb3", "aes-siv", 
        "chacha20-poly1305", "xchacha20-poly1305"
    ]
    
    # Get current encryption_data from metadata
    metadata = get_metadata(file_path)
    current_encryption_data = metadata.get("encryption", {}).get("encryption_data", "")
    
    # Find a different encryption_data option
    for option in encryption_data_options:
        if option != current_encryption_data:
            return option
            
    # Fallback - should never happen with our test set
    return "aes-gcm"


@pytest.mark.parametrize(
    "filename", 
    get_kyber_test_files_v5(),
    ids=lambda name: f"wrong_encryption_data_{name.replace('test1_', '').replace('.txt', '')}"
)
def test_file_decryption_wrong_encryption_data_v5(filename):
    """
    Test decryption of v5 Kyber files with wrong encryption_data.
    
    This test verifies that trying to decrypt a v5 format Kyber file with the correct password
    but wrong encryption_data setting properly fails and raises an exception rather than succeeding.
    """
    algorithm_name = filename.replace('test1_', '').replace('.txt', '')
    
    # Full path to the test file
    input_file = os.path.join(os.path.dirname(__file__), "testfiles", "v5", filename)
    
    # Get a wrong encryption_data value
    wrong_encryption_data = get_wrong_encryption_data(input_file)
    
    # Provide a mock private key for Kyber tests
    # This matches what the existing tests do
    pqc_private_key = (b'MOCK_PQC_KEY_FOR_' + algorithm_name.encode()) * 10
    
    try:
        # Try to decrypt with correct password but wrong encryption_data
        decrypted_data = decrypt_file(
            input_file=input_file,
            output_file=None,
            password=b"1234",  # Correct password
            encryption_data=wrong_encryption_data,  # Wrong encryption_data
            pqc_private_key=pqc_private_key)
            
        # If we get here, decryption succeeded with wrong encryption_data, which is a failure
        pytest.fail(f"Security issue: Decryption succeeded with wrong encryption_data for {algorithm_name} (v5)")
    except (DecryptionError, AuthenticationError, ValidationError) as e:
        # This is the expected path - decryption should fail with wrong encryption_data
        print(f"\nDecryption correctly failed for {algorithm_name} (v5) with wrong encryption_data: {str(e)}")
        # Test passes because the exception was raised as expected
        pass
    except Exception as e:
        # Unexpected exception type
        pytest.fail(f"Unexpected exception for {algorithm_name} with wrong encryption_data: {str(e)}")


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])