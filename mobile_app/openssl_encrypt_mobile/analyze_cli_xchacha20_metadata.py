#!/usr/bin/env python3
"""
Analyze CLI XChaCha20 metadata in detail to understand the key derivation parameters
"""

import json
import base64

def analyze_metadata():
    """Analyze the CLI XChaCha20 metadata in detail"""
    print("🔍 DETAILED CLI XCHACHA20 METADATA ANALYSIS")
    print("=" * 60)
    
    # Read CLI XChaCha20 test file
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_xchacha20-poly1305.txt"
    
    with open(test_file, 'r') as f:
        content = f.read().strip()
    
    # Parse CLI format
    metadata_b64, encrypted_data_b64 = content.split(':', 1)
    metadata_bytes = base64.b64decode(metadata_b64)
    metadata_json = metadata_bytes.decode()
    metadata = json.loads(metadata_json)
    
    print("🔧 COMPLETE METADATA STRUCTURE:")
    print(json.dumps(metadata, indent=2))
    print()
    
    print("📊 KEY DERIVATION PARAMETERS:")
    print("=" * 40)
    
    derivation_config = metadata.get('derivation_config', {})
    
    print(f"Salt (b64): {derivation_config.get('salt')}")
    salt_bytes = base64.b64decode(derivation_config.get('salt', ''))
    print(f"Salt (hex): {salt_bytes.hex()}")
    print(f"Salt length: {len(salt_bytes)} bytes")
    print()
    
    hash_config = derivation_config.get('hash_config', {})
    print("Hash Configuration:")
    for algo, config in hash_config.items():
        print(f"  {algo}: {config}")
    print()
    
    kdf_config = derivation_config.get('kdf_config', {})
    print("KDF Configuration:")
    for algo, config in kdf_config.items():
        print(f"  {algo}: {config}")
    print()
    
    print("🎯 ENABLED KDFs:")
    for algo, config in kdf_config.items():
        if isinstance(config, dict):
            enabled = config.get('enabled', True)  # Default to True if not specified
            rounds = config.get('rounds', 0)
            print(f"  {algo}: enabled={enabled}, rounds={rounds}")
            if enabled and rounds > 0:
                print(f"    ✅ ACTIVE: {rounds} rounds")
            elif enabled:
                print(f"    ✅ ACTIVE: default parameters")
            else:
                print(f"    ❌ DISABLED")
        else:
            print(f"  {algo}: {config}")
    
    print("\n🔑 HASH VERIFICATION:")
    hashes = metadata.get('hashes', {})
    print(f"Original hash: {hashes.get('original_hash', 'N/A')}")
    print(f"Encrypted hash: {hashes.get('encrypted_hash', 'N/A')}")

def compare_working_algorithms():
    """Compare with working algorithms to find differences"""
    print("\n🔄 COMPARING WITH WORKING CHACHA20")
    print("=" * 50)
    
    # Load ChaCha20 test file for comparison
    chacha20_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_chacha20-poly1305.txt"
    
    with open(chacha20_file, 'r') as f:
        content = f.read().strip()
    
    # Parse CLI format
    metadata_b64, encrypted_data_b64 = content.split(':', 1)
    metadata_bytes = base64.b64decode(metadata_b64)
    metadata_json = metadata_bytes.decode()
    chacha20_metadata = json.loads(metadata_json)
    
    print("ChaCha20-Poly1305 KDF Config:")
    chacha20_kdf = chacha20_metadata.get('derivation_config', {}).get('kdf_config', {})
    for algo, config in chacha20_kdf.items():
        print(f"  {algo}: {config}")
    
    print("\nXChaCha20-Poly1305 KDF Config:")
    xchacha20_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_xchacha20-poly1305.txt"
    with open(xchacha20_file, 'r') as f:
        content = f.read().strip()
    metadata_b64, _ = content.split(':', 1)
    metadata_bytes = base64.b64decode(metadata_b64)
    metadata = json.loads(metadata_bytes.decode())
    
    xchacha20_kdf = metadata.get('derivation_config', {}).get('kdf_config', {})
    for algo, config in xchacha20_kdf.items():
        print(f"  {algo}: {config}")
    
    print("\n📊 DIFFERENCES:")
    for algo in set(chacha20_kdf.keys()) | set(xchacha20_kdf.keys()):
        chacha_val = chacha20_kdf.get(algo, "N/A")
        xchacha_val = xchacha20_kdf.get(algo, "N/A")
        if chacha_val != xchacha_val:
            print(f"  {algo}: ChaCha20={chacha_val} vs XChaCha20={xchacha_val}")

if __name__ == "__main__":
    analyze_metadata()
    compare_working_algorithms()