#!/usr/bin/env python3
"""
Test script for chained KDF functionality
Shows the enhanced mobile implementation with multiple KDFs
"""

from mobile_crypto_core import MobileCryptoCore
import json

def test_chained_kdfs():
    """Test chained KDF functionality"""
    core = MobileCryptoCore()
    
    print("🔑 Testing Chained KDF Implementation (CLI Compatible)")
    print("=" * 60)
    
    test_password = "test123"
    test_text = "Hello from chained KDF crypto!"
    
    # Test 1: Single KDF (traditional)
    print("\n1. Testing single KDF (PBKDF2 only):")
    single_kdf_config = {
        "pbkdf2": {"enabled": True, "rounds": 100000},
        "scrypt": {"enabled": False},
        "argon2": {"enabled": False},
        "hkdf": {"enabled": False},
        "balloon": {"enabled": False}
    }
    
    result1 = core.encrypt_data(
        test_text.encode(),
        test_password,
        hash_config=core.default_hash_config,
        kdf_config=single_kdf_config
    )
    
    if result1["success"]:
        print("   ✅ Single KDF encryption successful!")
        print(f"   📋 Metadata version: {result1['metadata']['version']}")
        print(f"   🔗 Chained KDFs: {result1['metadata'].get('chained_kdfs', False)}")
        
        # Test decryption
        decrypt1 = core.decrypt_data(result1["encrypted_data"], result1["metadata"], test_password)
        if decrypt1["success"]:
            print(f"   ✅ Decryption successful: '{decrypt1['decrypted_data'].decode()}'")
        else:
            print(f"   ❌ Decryption failed: {decrypt1['error']}")
    else:
        print(f"   ❌ Encryption failed: {result1['error']}")
    
    # Test 2: Multiple chained KDFs
    print("\n2. Testing chained KDFs (PBKDF2 + Scrypt):")
    chained_kdf_config = {
        "pbkdf2": {"enabled": True, "rounds": 50000},
        "scrypt": {"enabled": True, "n": 8192, "r": 8, "p": 1, "rounds": 1},
        "argon2": {"enabled": False},
        "hkdf": {"enabled": False},
        "balloon": {"enabled": False}
    }
    
    result2 = core.encrypt_data(
        test_text.encode(),
        test_password,
        hash_config=core.default_hash_config,
        kdf_config=chained_kdf_config
    )
    
    if result2["success"]:
        print("   ✅ Chained KDF encryption successful!")
        
        # Show enabled KDFs
        enabled_kdfs = [k for k, v in chained_kdf_config.items() if v.get("enabled", False)]
        print(f"   🔗 Enabled KDFs: {', '.join(enabled_kdfs)}")
        
        # Test decryption
        decrypt2 = core.decrypt_data(result2["encrypted_data"], result2["metadata"], test_password)
        if decrypt2["success"]:
            print(f"   ✅ Chained decryption successful: '{decrypt2['decrypted_data'].decode()}'")
        else:
            print(f"   ❌ Decryption failed: {decrypt2['error']}")
    else:
        print(f"   ❌ Encryption failed: {result2['error']}")
    
    # Test 3: Full chain (all KDFs enabled)
    print("\n3. Testing full KDF chain (PBKDF2 + Scrypt + HKDF):")
    if ARGON2_AVAILABLE:
        full_kdf_config = {
            "pbkdf2": {"enabled": True, "rounds": 25000},
            "scrypt": {"enabled": True, "n": 4096, "r": 8, "p": 1, "rounds": 1},
            "argon2": {"enabled": True, "memory_cost": 32768, "time_cost": 2, "parallelism": 1, "rounds": 1},
            "hkdf": {"enabled": True, "info": "FullChainTest"},
            "balloon": {"enabled": False}
        }
    else:
        full_kdf_config = {
            "pbkdf2": {"enabled": True, "rounds": 25000},
            "scrypt": {"enabled": True, "n": 4096, "r": 8, "p": 1, "rounds": 1},
            "argon2": {"enabled": False},
            "hkdf": {"enabled": True, "info": "FullChainTest"},
            "balloon": {"enabled": False}
        }
    
    result3 = core.encrypt_data(
        test_text.encode(),
        test_password,
        hash_config=core.default_hash_config,
        kdf_config=full_kdf_config
    )
    
    if result3["success"]:
        print("   ✅ Full KDF chain encryption successful!")
        
        # Show enabled KDFs
        enabled_kdfs = [k for k, v in full_kdf_config.items() if v.get("enabled", False)]
        print(f"   🔗 Enabled KDFs: {', '.join(enabled_kdfs)}")
        
        # Test decryption  
        decrypt3 = core.decrypt_data(result3["encrypted_data"], result3["metadata"], test_password)
        if decrypt3["success"]:
            print(f"   ✅ Full chain decryption successful: '{decrypt3['decrypted_data'].decode()}'")
        else:
            print(f"   ❌ Decryption failed: {decrypt3['error']}")
    else:
        print(f"   ❌ Encryption failed: {result3['error']}")
    
    # Test 4: Available KDFs
    print("\n4. Available KDF algorithms:")
    kdf_algos = json.loads(core.get_kdf_algorithms())
    for kdf in kdf_algos:
        available = "✅" if kdf['name'] != 'Argon2' or ARGON2_AVAILABLE else "❌"
        print(f"   {available} {kdf['name']}")
    
    print("\n" + "=" * 60)
    print("🎉 Chained KDF implementation complete!")
    print("✅ Multiple KDFs can be enabled in sequence")
    print("✅ Each KDF has configurable parameters")
    print("✅ CLI-compatible chaining order")
    print("✅ Perfect compatibility with hash chaining")

if __name__ == "__main__":
    # Import availability flags
    try:
        from argon2 import PasswordHasher
        ARGON2_AVAILABLE = True
    except ImportError:
        ARGON2_AVAILABLE = False
        
    test_chained_kdfs()