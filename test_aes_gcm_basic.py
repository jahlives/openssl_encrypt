#!/usr/bin/env python3
"""
Basic test script for AES-GCM encryption and decryption
"""

import base64
import json
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher

def test_aes_gcm_basic():
    """Test basic AES-GCM encryption and decryption"""
    # Generate a random key
    print("\n=== Testing basic AES-GCM encryption/decryption ===")
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    data = b'This is a test message for AES-GCM encryption'
    
    print(f"Key (base64): {base64.b64encode(key).decode('utf-8')}")
    print(f"Nonce (base64): {base64.b64encode(nonce).decode('utf-8')}")
    print(f"Data: {data!r}")
    
    # Test each associated_data option
    for name, aad in [
        ("None", None),
        ("Empty bytes", b''),
        ("JSON bytes", json.dumps({"test": "data"}).encode('utf-8')),
        ("Fixed string", b'fixed_string')
    ]:
        print(f"\nTesting with associated_data = {name}")
        cipher = AESGCM(key)
        
        # Encrypt
        ciphertext = cipher.encrypt(nonce, data, associated_data=aad)
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        print(f"Ciphertext (base64): {base64.b64encode(ciphertext).decode('utf-8')}")
        
        # Decrypt
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=aad)
            print(f"Decryption SUCCESS: {plaintext!r}")
        except Exception as e:
            print(f"Decryption FAILED: {e}")
        
        # Try decrypting with different associated_data
        for other_name, other_aad in [
            ("None", None),
            ("Empty bytes", b''),
            ("JSON bytes", json.dumps({"test": "data"}).encode('utf-8')),
            ("Fixed string", b'fixed_string')
        ]:
            if other_name != name:
                try:
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=other_aad)
                    print(f"  WARNING: Decrypted with {other_name} even though encrypted with {name}!")
                except Exception:
                    # This is expected - different AAD should fail
                    pass
    
    print("\n=== Basic AES-GCM test complete ===")

def test_aes_gcm_argon2_key():
    """Test AES-GCM with Argon2id key derivation"""
    print("\n=== Testing AES-GCM with Argon2id key derivation ===")
    
    # Password and salt
    password = "test_password"
    salt = secrets.token_bytes(16)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    
    # Derive key with Argon2id
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32
    )
    
    # Hash the password with Argon2id
    print(f"Password: {password}")
    print(f"Salt (base64): {salt_b64}")
    
    # Hash the password
    hash_result = ph.hash(password + salt_b64)
    derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()
    print(f"Hash result: {hash_result}")
    print(f"Derived key (base64): {base64.b64encode(derived_key).decode('utf-8')}")
    
    # Test encryption
    nonce = secrets.token_bytes(12)
    data = b'This is a test message for AES-GCM with Argon2id key derivation'
    
    # Encrypt and decrypt with associated_data=None
    cipher = AESGCM(derived_key)
    ciphertext = cipher.encrypt(nonce, data, associated_data=None)
    print(f"\nEncrypted with associated_data=None")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
        print(f"Successfully decrypted with associated_data=None: {plaintext!r}")
    except Exception as e:
        print(f"Failed to decrypt with associated_data=None: {e}")
    
    # Try a second time with the same key derivation
    print("\nTrying a second key derivation to verify consistency:")
    hash_result2 = ph.hash(password + salt_b64)
    derived_key2 = hashlib.sha256(hash_result2.encode('utf-8')).digest()
    print(f"Second hash result: {hash_result2}")
    print(f"Second derived key (base64): {base64.b64encode(derived_key2).decode('utf-8')}")
    
    if derived_key == derived_key2:
        print("The two derived keys are IDENTICAL - good!")
    else:
        print("WARNING: The two derived keys are DIFFERENT!")
        
        # See if we can decrypt with the second key
        cipher2 = AESGCM(derived_key2)
        try:
            plaintext = cipher2.decrypt(nonce, ciphertext, associated_data=None)
            print(f"Surprisingly, decryption still worked with the second key!")
        except Exception as e:
            print(f"As expected, decryption failed with the second key: {e}")
            
    print("\n=== Argon2id key derivation test complete ===")
    
def test_argon2_hash_consistency():
    """Test Argon2id hash consistency"""
    print("\n=== Testing Argon2id hash consistency ===")
    
    # Password and salt
    password = "test_password"
    salt = secrets.token_bytes(16)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    
    print(f"Password: {password}")
    print(f"Salt (base64): {salt_b64}")
    
    # Create hasher with fixed parameters
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32
    )
    
    # Hash multiple times to check consistency
    hashes = []
    keys = []
    
    for i in range(5):
        # Hash the password
        hash_result = ph.hash(password + salt_b64)
        derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()
        
        hashes.append(hash_result)
        keys.append(derived_key)
        
        print(f"Iteration {i+1}:")
        print(f"  Hash: {hash_result}")
        print(f"  Key (base64): {base64.b64encode(derived_key).decode('utf-8')}")
    
    # Check if all hashes are different (expected with Argon2)
    unique_hashes = set(hashes)
    unique_keys = set(keys)
    
    print(f"\nUnique hashes: {len(unique_hashes)} (out of 5)")
    print(f"Unique keys: {len(unique_keys)} (out of 5)")
    
    # The issue: each time we call ph.hash(), it uses a random salt internally
    # even though we're passing our own salt as part of the password
    print("\nProblem identified: Argon2PasswordHasher.hash() always adds its own random salt!")
    print("This means we get a different key each time, even with the same password and our own salt.")
    
    # Solution: use Argon2 low-level API directly
    from argon2.low_level import hash_secret_raw, Type
    
    print("\nTesting low-level Argon2 API for consistency:")
    
    # Use raw Argon2 function
    raw_keys = []
    for i in range(5):
        raw_result = hash_secret_raw(
            password.encode('utf-8'),
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=2,
            hash_len=32,
            type=Type.ID
        )
        raw_keys.append(raw_result)
        print(f"Iteration {i+1}:")
        print(f"  Raw key (base64): {base64.b64encode(raw_result).decode('utf-8')}")
    
    unique_raw_keys = set([base64.b64encode(k).decode('utf-8') for k in raw_keys])
    print(f"\nUnique raw keys: {len(unique_raw_keys)} (out of 5)")
    
    if len(unique_raw_keys) == 1:
        print("SUCCESS: Low-level Argon2 API produces consistent keys!")
    else:
        print("WARNING: Even low-level Argon2 API produces inconsistent keys!")
        
    print("\n=== Argon2id consistency test complete ===")

if __name__ == "__main__":
    test_aes_gcm_basic()
    test_aes_gcm_argon2_key()
    test_argon2_hash_consistency()