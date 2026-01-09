#!/usr/bin/env python3
"""
Hash Processing Debug - Focus on the exact difference between CLI and mobile hash processing
"""

import sys
sys.path.append('.')
sys.path.insert(0, '../openssl_encrypt')

from mobile_crypto_core import MobileCryptoCore
from openssl_encrypt.modules.crypt_core import multi_hash_password as cli_multi_hash_password

def test_single_hash_algorithms():
    """Test each hash algorithm individually to find the differences"""
    print("🔬 Single Hash Algorithm Debug")
    print("=" * 50)
    
    password = b"1234"
    salt = b"test_salt_16byte"[:16]
    
    # Test each hash algorithm individually
    test_cases = [
        {"name": "SHA256 only", "config": {"sha512": 0, "sha256": 1000, "sha3_256": 0, "sha3_512": 0, "blake2b": 0, "shake256": 0, "whirlpool": 0}},
        {"name": "SHA512 only", "config": {"sha512": 1000, "sha256": 0, "sha3_256": 0, "sha3_512": 0, "blake2b": 0, "shake256": 0, "whirlpool": 0}},
        {"name": "SHA3-256 only", "config": {"sha512": 0, "sha256": 0, "sha3_256": 1000, "sha3_512": 0, "blake2b": 0, "shake256": 0, "whirlpool": 0}},
        {"name": "BLAKE2b only", "config": {"sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0, "blake2b": 1000, "shake256": 0, "whirlpool": 0}},
    ]
    
    core = MobileCryptoCore()
    
    for test_case in test_cases:
        print(f"\n📋 {test_case['name']}:")
        config = test_case['config']
        
        # CLI result
        try:
            cli_result = cli_multi_hash_password(password, salt, config, quiet=True)
            cli_hex = cli_result.hex()
            print(f"   CLI:    {cli_hex[:32]}... (len: {len(cli_result)})")
        except Exception as e:
            print(f"   CLI:    ERROR: {e}")
            continue
        
        # Mobile result
        try:
            mobile_result = core.multi_hash_password(password, salt, config)
            mobile_hex = mobile_result.hex()
            print(f"   Mobile: {mobile_hex[:32]}... (len: {len(mobile_result)})")
        except Exception as e:
            print(f"   Mobile: ERROR: {e}")
            continue
        
        # Compare
        if cli_result == mobile_result:
            print(f"   ✅ MATCH!")
        else:
            print(f"   ❌ DIFFERENT")
            print(f"   Difference starts at byte: {find_first_difference(cli_result, mobile_result)}")

def find_first_difference(data1, data2):
    """Find the first byte where two byte arrays differ"""
    min_len = min(len(data1), len(data2))
    for i in range(min_len):
        if data1[i] != data2[i]:
            return i
    if len(data1) != len(data2):
        return min_len
    return -1

def test_hash_order():
    """Test if hash processing order matters"""
    print("\n🔀 Hash Order Debug")
    print("=" * 50)
    
    password = b"1234"
    salt = b"test_salt_16byte"[:16]
    
    # Test different orders
    configs = [
        {"name": "SHA512 first", "config": {"sha512": 100, "sha256": 100, "sha3_256": 0, "sha3_512": 0, "blake2b": 0, "shake256": 0, "whirlpool": 0}},
        {"name": "SHA256 first", "config": {"sha512": 0, "sha256": 100, "sha3_256": 0, "sha3_512": 0, "blake2b": 100, "shake256": 0, "whirlpool": 0}},
    ]
    
    core = MobileCryptoCore()
    
    for config_test in configs:
        print(f"\n📋 {config_test['name']}:")
        config = config_test['config']
        
        # CLI result
        try:
            cli_result = cli_multi_hash_password(password, salt, config, quiet=True)
            print(f"   CLI:    {cli_result.hex()[:32]}...")
        except Exception as e:
            print(f"   CLI:    ERROR: {e}")
            continue
        
        # Mobile result
        try:
            mobile_result = core.multi_hash_password(password, salt, config)
            print(f"   Mobile: {mobile_result.hex()[:32]}...")
        except Exception as e:
            print(f"   Mobile: ERROR: {e}")
            continue
        
        # Compare
        if cli_result == mobile_result:
            print(f"   ✅ MATCH!")
        else:
            print(f"   ❌ DIFFERENT")

if __name__ == "__main__":
    test_single_hash_algorithms()
    test_hash_order()
    
    print(f"\n🎯 Hash Debug Complete")
    print("This will identify which specific hash algorithm or processing order is different.")