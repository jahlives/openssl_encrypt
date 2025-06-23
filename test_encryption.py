#!/usr/bin/env python3
"""
Test script to isolate the encryption/decryption issue
"""

import base64
import json
import os
import secrets
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main():
    """Test encryption and decryption with AES-GCM"""
    # Create a temporary file
    fd, temp_path = tempfile.mkstemp()
    os.close(fd)

    try:
        # Sample plaintext
        plaintext = json.dumps({"test": "value", "message": "This is a test"}).encode("utf-8")

        # Generate a random key and nonce
        key = secrets.token_bytes(32)  # 256-bit key for AES-GCM
        nonce = secrets.token_bytes(12)  # 96-bit nonce

        # Create a header
        header = {
            "protection": {
                "method": "aes-256-gcm",
                "params": {
                    "nonce": base64.b64encode(nonce).decode("utf-8"),
                    "salt": base64.b64encode(secrets.token_bytes(16)).decode("utf-8"),
                },
            }
        }

        print(f"Header: {json.dumps(header, indent=2)}")

        # Create AES-GCM cipher
        cipher = AESGCM(key)

        # Try encryption with None as associated_data
        print("\nEncryption with None as associated_data:")
        ciphertext_none = cipher.encrypt(nonce, plaintext, associated_data=None)
        print(f"Ciphertext length: {len(ciphertext_none)}")

        # Try encryption with header as associated_data
        print("\nEncryption with header as associated_data:")
        header_json = json.dumps(header).encode("utf-8")
        ciphertext_header = cipher.encrypt(nonce, plaintext, associated_data=header_json)
        print(f"Ciphertext length: {len(ciphertext_header)}")

        # Write the encrypted data to the file (using None as associated_data)
        with open(temp_path, "wb") as f:
            # Write the header size (4 bytes)
            header_size = len(header_json)
            f.write(header_size.to_bytes(4, byteorder="big"))

            # Write the header
            f.write(header_json)

            # Write the ciphertext
            f.write(ciphertext_none)

        print(f"Saved encrypted data to: {temp_path}")

        # Now try to read and decrypt
        with open(temp_path, "rb") as f:
            encrypted_data = f.read()

        # Parse the encrypted data
        header_size = int.from_bytes(encrypted_data[:4], byteorder="big")
        header_bytes = encrypted_data[4 : 4 + header_size]
        header = json.loads(header_bytes.decode("utf-8"))
        ciphertext = encrypted_data[4 + header_size :]

        print(f"\nRead header: {json.dumps(header, indent=2)}")
        print(f"Read ciphertext length: {len(ciphertext)}")

        # Try decrypting with all possible associated_data approaches
        cipher = AESGCM(key)  # Recreate the cipher

        # Try with None
        print("\nDecrypting with None as associated_data:")
        try:
            decrypted = cipher.decrypt(nonce, ciphertext, associated_data=None)
            print(f"SUCCESS! Decrypted: {decrypted.decode()}")
        except Exception as e:
            print(f"FAILED: {e}")

        # Try with header
        print("\nDecrypting with header as associated_data:")
        try:
            decrypted = cipher.decrypt(nonce, ciphertext, associated_data=header_bytes)
            print(f"SUCCESS! Decrypted: {decrypted.decode()}")
        except Exception as e:
            print(f"FAILED: {e}")

        # Try with reconstructed header
        print("\nDecrypting with reconstructed header as associated_data:")
        try:
            header_json = json.dumps(header).encode("utf-8")
            decrypted = cipher.decrypt(nonce, ciphertext, associated_data=header_json)
            print(f"SUCCESS! Decrypted: {decrypted.decode()}")
        except Exception as e:
            print(f"FAILED: {e}")

        # Try with empty bytes
        print("\nDecrypting with empty bytes as associated_data:")
        try:
            decrypted = cipher.decrypt(nonce, ciphertext, associated_data=b"")
            print(f"SUCCESS! Decrypted: {decrypted.decode()}")
        except Exception as e:
            print(f"FAILED: {e}")

        print("\nSummary:")
        print(
            "For AES-GCM, the associated_data value must match EXACTLY between encryption and decryption."
        )
        print(
            "In the test, we encrypted with associated_data=None, and it successfully decrypted with associated_data=None."
        )

    finally:
        # Clean up
        os.unlink(temp_path)


if __name__ == "__main__":
    main()
