#!/usr/bin/env python3
"""
Minimal fix script that directly implements the associated data fix
"""

import base64
import getpass
import json
import os
import secrets
import sys
import tempfile
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def create_and_verify():
    # Create a temporary file
    fd, temp_path = tempfile.mkstemp()
    os.close(fd)

    try:
        # Sample data to encrypt
        plaintext = json.dumps({"test": "data", "message": "This should work with the fix"}).encode(
            "utf-8"
        )

        # Generate a key and nonce
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

        # Encrypt with AES-GCM using the header as associated data
        print("Encrypting with header as associated data:")
        cipher = AESGCM(key)
        header_bytes = json.dumps(header).encode("utf-8")
        print(f"  Using header: {header}")
        print(f"  Header bytes: {header_bytes}")

        ciphertext = cipher.encrypt(nonce, plaintext, associated_data=header_bytes)
        print(f"  Ciphertext length: {len(ciphertext)}")

        # Write to the file
        with open(temp_path, "wb") as f:
            # Write the header size (4 bytes)
            header_size = len(header_bytes)
            f.write(header_size.to_bytes(4, byteorder="big"))

            # Write the header
            f.write(header_bytes)

            # Write the ciphertext
            f.write(ciphertext)

        print(f"Saved encrypted data to: {temp_path}")

        # Now try to decrypt it
        try:
            print("\nDecrypting the data:")
            with open(temp_path, "rb") as f:
                data = f.read()

            # Parse the encrypted data
            header_size = int.from_bytes(data[:4], byteorder="big")
            print(f"  Header size: {header_size}")

            header_bytes = data[4 : 4 + header_size]
            header = json.loads(header_bytes.decode("utf-8"))
            print(f"  Header: {header}")

            ciphertext = data[4 + header_size :]
            print(f"  Ciphertext length: {len(ciphertext)}")

            # Extract the nonce
            nonce = base64.b64decode(header["protection"]["params"]["nonce"])

            # Try to decrypt with the same approach
            print("\nTrying decryption with header as associated data:")
            try:
                decrypted = cipher.decrypt(nonce, ciphertext, associated_data=header_bytes)
                print(f"  SUCCESS! Decrypted: {decrypted.decode()}")
            except Exception as e:
                print(f"  FAILED with header as associated data: {e}")

            # Try to decrypt with None as associated data
            print("\nTrying decryption with None as associated data:")
            try:
                decrypted = cipher.decrypt(nonce, ciphertext, associated_data=None)
                print(f"  SUCCESS! Decrypted: {decrypted.decode()}")
            except Exception as e:
                print(f"  FAILED with None as associated data: {e}")

            # Try reconstructing the header
            print("\nTrying decryption with reconstructed header:")
            header_json = json.dumps(header).encode("utf-8")
            try:
                decrypted = cipher.decrypt(nonce, ciphertext, associated_data=header_json)
                print(f"  SUCCESS! Decrypted: {decrypted.decode()}")
            except Exception as e:
                print(f"  FAILED with reconstructed header: {e}")

            # Summary
            print("\nSummary:")
            print(
                "The key to this issue is that the associated_data value must match EXACTLY between"
            )
            print("encryption and decryption. In the original code:")
            print("- The save_keystore method uses: associated_data=None")
            print(
                "- The load_keystore method uses: associated_data=json.dumps(header).encode('utf-8')"
            )
            print("- This mismatch causes the decryption to fail with an InvalidTag error")
            print("\nThe FIX is to use the SAME associated data in BOTH places:")
            print("- ALWAYS use: associated_data=json.dumps(header).encode('utf-8')")
            print("- OR ALWAYS use: associated_data=None")
            print("- The important thing is that they match!")

            return True
        except Exception as e:
            print(f"Error: {e}")
            import traceback

            traceback.print_exc()
            return False
    finally:
        # Clean up
        os.unlink(temp_path)


if __name__ == "__main__":
    create_and_verify()
