#!/usr/bin/env python3
"""
Simple test script for AES-GCM encryption/decryption with associated data
"""

import os
import secrets
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def test_aes_gcm():
    """Test AES-GCM encryption and decryption with various associated data configurations"""
    print("=== AES-GCM Test ===\n")
    
    # Generate random key and nonce
    key = secrets.token_bytes(32)  # 256-bit key
    nonce = secrets.token_bytes(12)  # 96-bit nonce
    
    # Data to encrypt
    plaintext = b"This is a secret message"
    
    # Associated data variants
    header = {"test": "value"}
    
    # Test 1: Without associated data
    print("Test 1: Without associated data")
    cipher = AESGCM(key)
    ciphertext1 = cipher.encrypt(nonce, plaintext, associated_data=None)
    try:
        decrypted1 = cipher.decrypt(nonce, ciphertext1, associated_data=None)
        print(f"✓ Success! Decrypted: {decrypted1.decode()}")
        
        # Try with wrong associated data
        try:
            cipher.decrypt(nonce, ciphertext1, associated_data=b"wrong")
            print("✗ Error: Should have failed with wrong associated data")
        except Exception as e:
            print(f"✓ Failed correctly with wrong associated data: {type(e).__name__}")
    except Exception as e:
        print(f"✗ Failed: {e}")
    
    # Test 2: With simple associated data
    print("\nTest 2: With simple associated data")
    associated_data = b"simple"
    ciphertext2 = cipher.encrypt(nonce, plaintext, associated_data=associated_data)
    try:
        decrypted2 = cipher.decrypt(nonce, ciphertext2, associated_data=associated_data)
        print(f"✓ Success! Decrypted: {decrypted2.decode()}")
        
        # Try with wrong associated data
        try:
            cipher.decrypt(nonce, ciphertext2, associated_data=None)
            print("✗ Error: Should have failed with wrong associated data")
        except Exception as e:
            print(f"✓ Failed correctly with wrong associated data: {type(e).__name__}")
    except Exception as e:
        print(f"✗ Failed: {e}")
    
    # Test 3: With JSON header
    print("\nTest 3: With JSON header as associated data")
    header_bytes = json.dumps(header).encode('utf-8')
    ciphertext3 = cipher.encrypt(nonce, plaintext, associated_data=header_bytes)
    try:
        decrypted3 = cipher.decrypt(nonce, ciphertext3, associated_data=header_bytes)
        print(f"✓ Success! Decrypted: {decrypted3.decode()}")
        
        # Try with reconstructed header
        header_bytes2 = json.dumps(header).encode('utf-8')
        if header_bytes == header_bytes2:
            print("✓ Headers match as expected")
        else:
            print("✗ Error: Headers don't match")
            
        try:
            decrypted3b = cipher.decrypt(nonce, ciphertext3, associated_data=header_bytes2)
            print(f"✓ Success with reconstructed header! Decrypted: {decrypted3b.decode()}")
        except Exception as e:
            print(f"✗ Failed with reconstructed header: {e}")
        
        # Try with modified header
        header2 = {"test": "different"}
        header_bytes2 = json.dumps(header2).encode('utf-8')
        try:
            cipher.decrypt(nonce, ciphertext3, associated_data=header_bytes2)
            print("✗ Error: Should have failed with modified header")
        except Exception as e:
            print(f"✓ Failed correctly with modified header: {type(e).__name__}")
    except Exception as e:
        print(f"✗ Failed: {e}")
        
    print("\nTests completed!")

if __name__ == "__main__":
    test_aes_gcm()