#!/usr/bin/env python3
"""
Simple targeted fix script to address the AES-GCM associated_data issue.
"""

import base64
import json
import os
import secrets
import sys
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def test_aes_gcm_association_data():
    """
    Test that AES-GCM encryption/decryption works with consistent associated_data
    """
    print("Testing AES-GCM with associated_data...")

    # Generate a random key and nonce
    key = secrets.token_bytes(32)  # 32 bytes = 256 bits
    nonce = secrets.token_bytes(12)  # 12 bytes = 96 bits

    # Create some data to encrypt
    plaintext = b"This is a test message"

    # Create header data
    header = {"protection": {"method": "aes-gcm", "params": {"test": "value"}}}
    header_bytes = json.dumps(header).encode("utf-8")

    # Create cipher
    cipher = AESGCM(key)

    # Encrypt with associated_data
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=header_bytes)
    print(f"Encrypted with associated_data={header_bytes!r}")

    # Try to decrypt with the same associated_data
    try:
        decrypted = cipher.decrypt(nonce, ciphertext, associated_data=header_bytes)
        print(f"✓ Successfully decrypted with matching associated_data: {decrypted!r}")
    except Exception as e:
        print(f"✗ Failed to decrypt with matching associated_data: {e}")

    # Try to decrypt with different associated_data
    try:
        header2 = {"protection": {"method": "different", "params": {"test": "value"}}}
        header2_bytes = json.dumps(header2).encode("utf-8")
        decrypted = cipher.decrypt(nonce, ciphertext, associated_data=header2_bytes)
        print(f"✓ Decrypted with non-matching associated_data: {decrypted!r}")
    except Exception as e:
        print(f"✗ Failed to decrypt with non-matching associated_data (expected): {e}")

    # Try to decrypt with None as associated_data
    try:
        decrypted = cipher.decrypt(nonce, ciphertext, associated_data=None)
        print(f"✓ Decrypted with None as associated_data: {decrypted!r}")
    except Exception as e:
        print(f"✗ Failed to decrypt with None as associated_data (expected): {e}")

    print(
        "\nConclusion: For AES-GCM, the associated_data must match exactly between encryption and decryption."
    )
    print("The fix is to ensure both save_keystore and load_keystore use the same value.")


if __name__ == "__main__":
    test_aes_gcm_association_data()
