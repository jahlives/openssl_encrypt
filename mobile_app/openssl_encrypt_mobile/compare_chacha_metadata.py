#!/usr/bin/env python3
"""
Compare ChaCha20 vs XChaCha20 metadata to find differences
"""

import json
import base64

def compare_metadata():
    """Compare ChaCha20 and XChaCha20 metadata"""
    print("🔍 CHACHA20 VS XCHACHA20 METADATA COMPARISON")
    print("=" * 60)
    
    # Read ChaCha20 test file
    chacha20_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_chacha20-poly1305.txt"
    with open(chacha20_file, 'r') as f:
        content = f.read().strip()
    metadata_b64, _ = content.split(':', 1)
    metadata_bytes = base64.b64decode(metadata_b64)
    chacha20_metadata = json.loads(metadata_bytes.decode())
    
    # Read XChaCha20 test file
    xchacha20_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_xchacha20-poly1305.txt"
    with open(xchacha20_file, 'r') as f:
        content = f.read().strip()
    metadata_b64, _ = content.split(':', 1)
    metadata_bytes = base64.b64decode(metadata_b64)
    xchacha20_metadata = json.loads(metadata_bytes.decode())
    
    print("📊 SALT COMPARISON:")
    chacha20_salt = chacha20_metadata.get('derivation_config', {}).get('salt', '')
    xchacha20_salt = xchacha20_metadata.get('derivation_config', {}).get('salt', '')
    
    print(f"ChaCha20 salt:   {chacha20_salt}")
    print(f"XChaCha20 salt:  {xchacha20_salt}")
    print(f"Salts match: {chacha20_salt == xchacha20_salt}")
    print()
    
    print("🔑 ARGON2 CONFIGURATION COMPARISON:")
    chacha20_argon2 = chacha20_metadata.get('derivation_config', {}).get('kdf_config', {}).get('argon2', {})
    xchacha20_argon2 = xchacha20_metadata.get('derivation_config', {}).get('kdf_config', {}).get('argon2', {})
    
    print("ChaCha20 Argon2:")
    for key, value in chacha20_argon2.items():
        print(f"  {key}: {value}")
    
    print("\nXChaCha20 Argon2:")
    for key, value in xchacha20_argon2.items():
        print(f"  {key}: {value}")
    
    print(f"\nArgon2 configs match: {chacha20_argon2 == xchacha20_argon2}")
    
    print("\n📋 FULL METADATA COMPARISON:")
    print("ChaCha20:")
    print(json.dumps(chacha20_metadata, indent=2))
    print("\nXChaCha20:")
    print(json.dumps(xchacha20_metadata, indent=2))
    
    # Check for specific differences
    print("\n🎯 KEY DIFFERENCES:")
    
    # Compare hashes
    chacha20_orig_hash = chacha20_metadata.get('hashes', {}).get('original_hash', '')
    xchacha20_orig_hash = xchacha20_metadata.get('hashes', {}).get('original_hash', '')
    chacha20_enc_hash = chacha20_metadata.get('hashes', {}).get('encrypted_hash', '')
    xchacha20_enc_hash = xchacha20_metadata.get('hashes', {}).get('encrypted_hash', '')
    
    print(f"Original hash match: {chacha20_orig_hash == xchacha20_orig_hash}")
    if chacha20_orig_hash == xchacha20_orig_hash:
        print("  ✅ Same plaintext was encrypted")
    else:
        print("  ❌ Different plaintext")
        print(f"    ChaCha20:  {chacha20_orig_hash}")
        print(f"    XChaCha20: {xchacha20_orig_hash}")
    
    print(f"Encrypted hash match: {chacha20_enc_hash == xchacha20_enc_hash}")
    if chacha20_enc_hash != xchacha20_enc_hash:
        print("  ✅ Different encrypted data (expected)")
        print(f"    ChaCha20:  {chacha20_enc_hash}")
        print(f"    XChaCha20: {xchacha20_enc_hash}")

if __name__ == "__main__":
    compare_metadata()