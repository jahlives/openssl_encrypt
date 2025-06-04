#!/usr/bin/env python3
"""
Simple PQC Keystore Demo Script
"""

import os
import sys

from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file
from openssl_encrypt.modules.keystore_cli import KeystoreSecurityLevel, PQCKeystore
from openssl_encrypt.modules.pqc import PQCipher

# Configuration
KEYSTORE_PATH = "demo_keystore.pqc"
KEYSTORE_PASSWORD = "demo123"
INPUT_FILE = "demo_input.txt"
ENCRYPTED_FILE = "demo_encrypted.enc"
DECRYPTED_FILE = "demo_decrypted.txt"
FILE_PASSWORD = "file-password123"

# Create sample input file
with open(INPUT_FILE, "w") as f:
    f.write("This is a secret message protected by PQC keystore!\n")
print(f"Created {INPUT_FILE}")

# Step 1: Create or load keystore
if os.path.exists(KEYSTORE_PATH):
    print(f"Loading existing keystore: {KEYSTORE_PATH}")
    keystore = PQCKeystore(KEYSTORE_PATH)
    keystore.load_keystore(KEYSTORE_PASSWORD)
else:
    print(f"Creating new keystore: {KEYSTORE_PATH}")
    keystore = PQCKeystore(KEYSTORE_PATH)
    keystore.create_keystore(KEYSTORE_PASSWORD, KeystoreSecurityLevel.STANDARD)

# Step 2: Generate PQC keypair
print("Generating Kyber768 keypair...")
cipher = PQCipher("kyber768", quiet=True)
public_key, private_key = cipher.generate_keypair()

# Step 3: Add key to keystore
print("Adding keypair to keystore...")
key_id = keystore.add_key(
    algorithm="kyber768",
    public_key=public_key,
    private_key=private_key,
    description="Demo PQC key",
    tags=["demo"],
    use_master_password=True,
)
keystore.save_keystore()
print(f"Added key with ID: {key_id}")

# Step 4: List keys in keystore
print("\nKeys in keystore:")
keys = keystore.list_keys()
for key in keys:
    print(f"  ID: {key['key_id']}")
    print(f"  Algorithm: {key['algorithm']}")
    print(f"  Description: {key['description']}")
    print(f"  Tags: {', '.join(key['tags'])}")
    print()

# Step 5: Create hash config with key ID for metadata
hash_config = {
    "sha512": 0,
    "sha256": 0,
    "sha3_256": 0,
    "sha3_512": 0,
    "blake2b": 0,
    "shake256": 0,
    "pbkdf2_iterations": 100000,
    "scrypt": {"enabled": False, "n": 128, "r": 8, "p": 1, "rounds": 1},
    "argon2": {
        "enabled": False,
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 4,
        "hash_len": 32,
        "type": 2,
        "rounds": 1,
    },
    "pqc_keystore_key_id": key_id,  # Store key ID in metadata
}

# Step 6: Encrypt file
print(f"Encrypting {INPUT_FILE}...")
success = encrypt_file(
    INPUT_FILE,
    ENCRYPTED_FILE,
    FILE_PASSWORD.encode(),
    hash_config,
    0,  # pbkdf2 iterations
    False,  # quiet
    "kyber768-hybrid",  # algorithm
    True,  # progress
    False,  # verbose
    pqc_keypair=(public_key, private_key),
    pqc_store_private_key=False,  # Don't store private key in metadata
)

if success:
    print(f"Encryption successful! File saved to {ENCRYPTED_FILE}")
else:
    print("Encryption failed!")
    sys.exit(1)

# Step 7: Read the key from keystore for decryption
print("\nRetrieving key from keystore...")
try:
    retrieved_public_key, retrieved_private_key = keystore.get_key(key_id)
    print("Key retrieved successfully!")
except Exception as e:
    print(f"Error retrieving key: {e}")
    sys.exit(1)

# Step 8: Decrypt file
print(f"\nDecrypting {ENCRYPTED_FILE}...")
success = decrypt_file(
    ENCRYPTED_FILE,
    DECRYPTED_FILE,
    FILE_PASSWORD.encode(),
    False,  # quiet
    True,  # progress
    False,  # verbose
    pqc_private_key=retrieved_private_key,
)

if success:
    print(f"Decryption successful! File saved to {DECRYPTED_FILE}")
else:
    print("Decryption failed!")
    sys.exit(1)

# Step 9: Verify content
print("\nVerifying decrypted content:")
with open(INPUT_FILE, "r") as f:
    original_content = f.read()

with open(DECRYPTED_FILE, "r") as f:
    decrypted_content = f.read()

if original_content == decrypted_content:
    print("✅ Original and decrypted content match!")
    print(f"Content: {decrypted_content.strip()}")
else:
    print("❌ Content mismatch!")
    print(f"Original:  {original_content}")
    print(f"Decrypted: {decrypted_content}")

# Cleanup
print("\nDemo completed successfully!")
print("Clean up demo files? (y/n)")
response = input().lower()
if response.startswith("y"):
    for f in [INPUT_FILE, ENCRYPTED_FILE, DECRYPTED_FILE, KEYSTORE_PATH]:
        if os.path.exists(f):
            os.remove(f)
    print("Demo files removed.")
else:
    print("Demo files retained for inspection.")
