#!/usr/bin/env python3
"""
Minimal AES-GCM keystore implementation for testing
"""

import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time

from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def create_minimal_keystore(path, password):
    """Create a minimal keystore file using AES-GCM"""
    print("\n=== Creating minimal keystore ===")

    # Generate salt and nonce
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)

    # Derive key with Argon2id
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32)

    # Encode salt as required by argon2-cffi
    salt_b64 = base64.b64encode(salt).decode("utf-8")

    # Hash the password with Argon2id
    hash_result = ph.hash(password + salt_b64)
    derived_key = hashlib.sha256(hash_result.encode("utf-8")).digest()

    # Create keystore data
    keystore_data = {
        "keystore_version": "1.0",
        "creation_date": "2025-05-02T12:00:00.000000",
        "last_modified": "2025-05-02T12:00:00.000000",
        "keys": [],
        "default_key_id": None,
        "protection": {
            "method": "argon2id+aes-256-gcm",
            "params": {
                "salt": salt_b64,
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "argon2_params": {"time_cost": 3, "memory_cost": 65536, "parallelism": 2},
            },
        },
    }

    # Convert to JSON and encrypt
    plaintext = json.dumps(keystore_data).encode("utf-8")

    # Create header for the file
    header = {"protection": keystore_data["protection"]}

    # Options for associated_data
    # 1. Use None (previous approach in code)
    # 2. Use empty bytes (b'')
    # 3. Use serialized header
    # 4. Use a fixed string

    # Let's try each option and write multiple files
    for option in ["none", "empty", "header", "fixed"]:
        cipher = AESGCM(derived_key)
        option_path = f"{path}_{option}"

        if option == "none":
            # Option 1: None
            ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)
            print(f"Option 1: Using None as associated_data")
        elif option == "empty":
            # Option 2: Empty bytes
            ciphertext = cipher.encrypt(nonce, plaintext, associated_data=b"")
            print(f"Option 2: Using empty bytes as associated_data")
        elif option == "header":
            # Option 3: Header JSON
            header_json = json.dumps(header).encode("utf-8")
            ciphertext = cipher.encrypt(nonce, plaintext, associated_data=header_json)
            print(f"Option 3: Using header JSON as associated_data: {header_json!r}")
        else:
            # Option 4: Fixed string
            fixed_data = b"fixed_string"
            ciphertext = cipher.encrypt(nonce, plaintext, associated_data=fixed_data)
            print(f"Option 4: Using fixed string as associated_data: {fixed_data!r}")

        # Write the file
        header_json = json.dumps(header).encode("utf-8")
        header_size = len(header_json)

        with open(option_path, "wb") as f:
            f.write(header_size.to_bytes(4, byteorder="big"))
            f.write(header_json)
            f.write(ciphertext)

        print(f"Wrote file: {option_path}")

    print("=== Minimal keystore creation complete ===\n")
    return [f"{path}_{option}" for option in ["none", "empty", "header", "fixed"]]


def load_minimal_keystore(path, password):
    """Load a minimal keystore file"""
    print(f"\n=== Loading minimal keystore from {path} ===")

    try:
        # Read the file
        with open(path, "rb") as f:
            encrypted_data = f.read()

        # Parse the encrypted data
        header_size = int.from_bytes(encrypted_data[:4], byteorder="big")
        header_bytes = encrypted_data[4 : 4 + header_size]
        header = json.loads(header_bytes.decode("utf-8"))
        ciphertext = encrypted_data[4 + header_size :]

        print(f"File size: {len(encrypted_data)} bytes")
        print(f"Header size: {header_size} bytes")

        # Extract parameters
        protection = header["protection"]
        params = protection["params"]

        # Derive key from password
        ph = PasswordHasher(
            time_cost=params["argon2_params"]["time_cost"],
            memory_cost=params["argon2_params"]["memory_cost"],
            parallelism=params["argon2_params"]["parallelism"],
            hash_len=32,
        )

        # Encode salt as required by argon2-cffi
        salt_b64 = params["salt"]

        # Hash the password with Argon2id
        hash_result = ph.hash(password + salt_b64)
        derived_key = hashlib.sha256(hash_result.encode("utf-8")).digest()

        # Decrypt using all possible associated_data values
        nonce = base64.b64decode(params["nonce"])
        cipher = AESGCM(derived_key)

        success = False

        # Try each option
        for option, associated_data in [
            ("None", None),
            ("Empty bytes", b""),
            ("Header JSON", json.dumps(header).encode("utf-8")),
            ("Fixed string", b"fixed_string"),
        ]:
            try:
                print(f"\nTrying decryption with {option}")
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=associated_data)

                # Verify it's valid JSON
                data = json.loads(plaintext.decode("utf-8"))
                print(f"SUCCESS! Decryption worked with {option}")
                print(f"Keystore data contains {len(data)} keys: {list(data.keys())}")
                success = True
                # Note which option worked for reference
                print(f"IMPORTANT: Option that worked for {os.path.basename(path)}: {option}\n")
                break
            except Exception as e:
                print(f"Failed with {option}: {str(e)}")

        if not success:
            print(f"Could not decrypt {path} with any associated_data option!")

        print(f"=== Loading complete for {path} ===\n")

    except Exception as e:
        print(f"Error loading keystore: {e}")
        import traceback

        traceback.print_exc()


def test_minimal_keystore():
    """Test the minimal keystore implementation"""
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    base_path = os.path.join(temp_dir, "minimal_keystore")

    # Password for testing
    password = "test_password"

    print("\n=== TESTING MINIMAL AES-GCM KEYSTORE ===\n")

    # Create the keystore files
    paths = create_minimal_keystore(base_path, password)

    # Try loading each file
    for path in paths:
        load_minimal_keystore(path, password)

    print("\n=== TESTING COMPLETE ===\n")

    return paths


if __name__ == "__main__":
    test_minimal_keystore()
