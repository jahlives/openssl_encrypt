#!/usr/bin/env python3
"""
Test Exact CLI Configuration Match
Use the exact parameters from the CLI test file and test mobile decryption
"""

import base64
from cryptography.fernet import Fernet
from mobile_crypto_core import MobileCryptoCore

def test_exact_match():
    """Test mobile with exact CLI parameters"""
    print("🎯 Testing Exact CLI Configuration Match")
    print("=" * 50)
    
    # Exact parameters from CLI test file
    password = "1234"
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    encrypted_data_b64 = "Z0FBQUFBQm9KZHRWcmNyQkpDeUE5dTdScy1rYU9oV01kR3Q0VS12aHQ3dVVkTDdzUEpDSUZYc2tlcWJ5ajNfQk1obXpDS1BYWV85UzVhMWx1cFhxSWlpQkdrbjk3ZlRsekE9PQ=="
    
    print(f"🔑 Test Parameters:")
    print(f"   Password: {password}")
    print(f"   Salt: {salt.hex()}")
    print(f"   Encrypted data length: {len(encrypted_data_b64)}")
    
    core = MobileCryptoCore()
    
    # Hash config (all zeros)
    hash_config = {
        "sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0,
        "blake2b": 0, "shake256": 0, "whirlpool": 0, "blake3": 0
    }
    
    # Exact CLI KDF config
    kdf_config = {
        "pbkdf2": {"enabled": True, "rounds": 10000},  # enabled because rounds > 0
        "scrypt": {"enabled": False, "n": 128, "r": 8, "p": 1, "rounds": 1},
        "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4, "rounds": 10, "hash_len": 32, "type": 2},
        "hkdf": {"enabled": False, "info": "OpenSSL_Encrypt_Mobile"},
        "balloon": {"enabled": False, "time_cost": 3, "space_cost": 65536, "parallelism": 4, "rounds": 2}
    }
    
    print(f"\n📝 Step-by-step processing:")
    
    # Step 1: Hash processing
    print("   Step 1: Hash processing...")
    password_bytes = password.encode()
    hashed = core.multi_hash_password(password_bytes, salt, hash_config)
    print(f"      Result: {hashed.hex()}")
    
    # Step 2: KDF processing
    print("   Step 2: KDF processing...")
    kdf_result = core.multi_kdf_derive(hashed, salt, kdf_config)
    print(f"      Result: {kdf_result.hex()[:32]}...")
    
    # Step 3: Final key
    print("   Step 3: Final key encoding...")
    final_key = base64.urlsafe_b64encode(kdf_result)
    print(f"      Key: {final_key[:32]}...")
    
    # Step 4: Test decryption
    print("   Step 4: Fernet decryption...")
    try:
        f = Fernet(final_key)
        encrypted_data = base64.b64decode(encrypted_data_b64)
        decrypted = f.decrypt(encrypted_data)
        decrypted_text = decrypted.decode('utf-8')
        
        print(f"🎉 SUCCESS: Decryption worked!")
        print(f"      Decrypted: '{decrypted_text}'")
        return True
        
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        
        # Debug: Check Fernet key format
        print(f"\n🔍 Debug information:")
        print(f"   KDF result length: {len(kdf_result)}")
        print(f"   Final key length: {len(final_key)}")
        print(f"   Expected Fernet key length: 44 chars base64")
        
        # Try different key lengths
        if len(kdf_result) > 32:
            print("   Trying truncated key...")
            try:
                truncated_key = base64.urlsafe_b64encode(kdf_result[:32])
                f2 = Fernet(truncated_key)
                decrypted2 = f2.decrypt(encrypted_data)
                print(f"   Truncated key worked: {decrypted2.decode('utf-8')}")
                return True
            except:
                print("   Truncated key also failed")
        
        return False

def test_kdf_order_comparison():
    """Test different KDF orders to see which one works"""
    print(f"\n🔬 KDF Order Comparison Test")
    print("=" * 50)
    
    # Test parameters
    password = "1234"
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    encrypted_data_b64 = "Z0FBQUFBQm9KZHRWcmNyQkpDeUE5dTdScy1rYU9oV01kR3Q0VS12aHQ3dVVkTDdzUEpDSUZYc2tlcWJ5ajNfQk1obXpDS1BYWV85UzVhMWx1cFhxSWlpQkdrbjk3ZlRsekE9PQ=="
    
    password_bytes = password.encode()
    hashed_input = password_bytes + salt  # No hash rounds
    encrypted_data = base64.b64decode(encrypted_data_b64)
    
    print(f"🔑 Testing different KDF orders:")
    print(f"   Input: {hashed_input.hex()}")
    
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from argon2.low_level import hash_secret_raw, Type
    
    # Test 1: PBKDF2 only
    print(f"\n   Test 1: PBKDF2 only")
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=10000,
            backend=default_backend()
        )
        pbkdf2_only = kdf.derive(hashed_input)
        key1 = base64.urlsafe_b64encode(pbkdf2_only)
        
        f1 = Fernet(key1)
        result1 = f1.decrypt(encrypted_data)
        print(f"      ✅ SUCCESS: {result1.decode('utf-8')}")
        return True
        
    except Exception as e:
        print(f"      ❌ Failed: {e}")
    
    # Test 2: Argon2 then PBKDF2 (mobile order)
    print(f"\n   Test 2: Argon2 → PBKDF2 (mobile order)")
    try:
        # Argon2 first
        argon2_result = hash_secret_raw(
            hashed_input,
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        
        # Then PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=10000,
            backend=default_backend()
        )
        final_result = kdf.derive(argon2_result)
        key2 = base64.urlsafe_b64encode(final_result)
        
        f2 = Fernet(key2)
        result2 = f2.decrypt(encrypted_data)
        print(f"      ✅ SUCCESS: {result2.decode('utf-8')}")
        return True
        
    except Exception as e:
        print(f"      ❌ Failed: {e}")
    
    # Test 3: PBKDF2 then Argon2 (reverse order)
    print(f"\n   Test 3: PBKDF2 → Argon2 (reverse order)")
    try:
        # PBKDF2 first
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=10000,
            backend=default_backend()
        )
        pbkdf2_result = kdf.derive(hashed_input)
        
        # Then Argon2
        final_result = hash_secret_raw(
            pbkdf2_result,
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        key3 = base64.urlsafe_b64encode(final_result)
        
        f3 = Fernet(key3)
        result3 = f3.decrypt(encrypted_data)
        print(f"      ✅ SUCCESS: {result3.decode('utf-8')}")
        return True
        
    except Exception as e:
        print(f"      ❌ Failed: {e}")
    
    print(f"   ❌ All KDF order tests failed")
    return False

if __name__ == "__main__":
    print("🎯 Exact CLI Match Test Suite")
    print("=" * 60)
    
    success1 = test_exact_match()
    success2 = test_kdf_order_comparison()
    
    if success1 or success2:
        print(f"\n🎉 SUCCESS: Found working KDF configuration!")
    else:
        print(f"\n❌ FAILED: KDF configuration issues persist")