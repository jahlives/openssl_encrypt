#!/usr/bin/env python3
"""
Simple test script for the pqc_adapter module.
"""

# Test the pqc_adapter module directly
from openssl_encrypt.modules.pqc_adapter import (
    LIBOQS_AVAILABLE,
    ExtendedPQCipher,
    get_available_pq_algorithms,
)

# Print availability information
print(f"liboqs available: {LIBOQS_AVAILABLE}")

# Get available algorithms
algorithms = get_available_pq_algorithms(quiet=False)
print(f"Available algorithms: {algorithms}")

# Test with ML-KEM-512 (should always work)
print("\nTesting with ML-KEM-512 (native implementation):")
try:
    cipher = ExtendedPQCipher("ML-KEM-512", quiet=False)
    public_key, private_key = cipher.generate_keypair()

    message = b"Hello, post-quantum world!"
    encrypted = cipher.encrypt(message, public_key)
    decrypted = cipher.decrypt(encrypted, private_key)

    print(f"  Original message: {message}")
    print(f"  Decrypted message: {decrypted}")
    print(f"  Success: {message == decrypted}")
except Exception as e:
    print(f"  Error: {e}")

# Test with HQC-128 if available
if LIBOQS_AVAILABLE and "HQC-128" in algorithms:
    print("\nTesting with HQC-128 (liboqs implementation):")
    try:
        cipher = ExtendedPQCipher("HQC-128", quiet=False)
        public_key, private_key = cipher.generate_keypair()

        message = b"Hello, post-quantum world!"
        encrypted = cipher.encrypt(message, public_key)
        decrypted = cipher.decrypt(encrypted, private_key)

        print(f"  Original message: {message}")
        print(f"  Decrypted message: {decrypted}")
        print(f"  Success: {message == decrypted}")
    except Exception as e:
        print(f"  Error: {e}")
