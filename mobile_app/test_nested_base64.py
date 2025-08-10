#!/usr/bin/env python3
"""
Test for nested base64 encoding in CLI data
"""

import base64

def decode_nested():
    """Check for nested base64 in CLI encrypted data"""
    print("🔍 Nested Base64 Analysis")
    print("=" * 40)
    
    # CLI encrypted data
    encrypted_data_b64 = "Z0FBQUFBQm9KZHRWcmNyQkpDeUE5dTdScy1rYU9oV01kR3Q0VS12aHQ3dVVkTDdzUEpDSUZYc2tlcWJ5ajNfQk1obXpDS1BYWV85UzVhMWx1cFhxSWlpQkdrbjk3ZlRsekE9PQ=="
    
    print(f"🔑 Original: {encrypted_data_b64[:50]}...")
    
    # First decode
    try:
        level1 = base64.b64decode(encrypted_data_b64)
        print(f"✅ Level 1 decode: {len(level1)} bytes")
        print(f"   As text: {level1[:50]}...")
        
        # Check if level1 is also base64
        level1_text = level1.decode('ascii')
        print(f"   As ASCII: {level1_text[:50]}...")
        
        # Second decode
        level2 = base64.b64decode(level1_text)
        print(f"✅ Level 2 decode: {len(level2)} bytes")
        print(f"   First 16 bytes: {level2[:16].hex()}")
        print(f"   Last 16 bytes: {level2[-16:].hex()}")
        
        # Check if this is proper Fernet format
        if len(level2) >= 70 and level2[0] == 0x80:  # Minimum 70 bytes for Fernet
            print(f"🎉 Found proper Fernet data! (length: {len(level2)})")
            return level2
        else:
            print(f"❌ Still not Fernet format (version: 0x{level2[0]:02x}, length: {len(level2)})")
            
    except Exception as e:
        print(f"❌ Nested decode failed: {e}")
        
    return None

def test_with_nested_data():
    """Test decryption with properly decoded data"""
    fernet_data = decode_nested()
    if not fernet_data:
        print("⚠️ No proper Fernet data found")
        return
        
    print(f"\n🧪 Testing with Proper Fernet Data")
    print("=" * 40)
    
    from mobile_crypto_core import MobileCryptoCore
    from cryptography.fernet import Fernet
    import base64
    
    # Test parameters
    password = "1234"
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    
    core = MobileCryptoCore()
    
    # Hash config (all zeros)
    hash_config = {
        "sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0,
        "blake2b": 0, "shake256": 0, "whirlpool": 0, "blake3": 0
    }
    
    # KDF config (PBKDF2 + Argon2)
    kdf_config = {
        "pbkdf2": {"enabled": True, "rounds": 10000},
        "scrypt": {"enabled": False},
        "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4, "rounds": 10, "hash_len": 32, "type": 2},
        "hkdf": {"enabled": False},
        "balloon": {"enabled": False}
    }
    
    print(f"🔑 Deriving key with mobile KDF chain...")
    
    # Derive key
    password_bytes = password.encode()
    hashed = core.multi_hash_password(password_bytes, salt, hash_config)
    kdf_result = core.multi_kdf_derive(hashed, salt, kdf_config)
    key = base64.urlsafe_b64encode(kdf_result)
    
    print(f"   Hash: {hashed.hex()}")
    print(f"   KDF: {kdf_result.hex()[:32]}...")
    print(f"   Key: {key[:32]}...")
    
    # Test Fernet decryption
    try:
        f = Fernet(key)
        decrypted = f.decrypt(fernet_data)
        decrypted_text = decrypted.decode('utf-8')
        
        print(f"🎉 SUCCESS: Decryption worked!")
        print(f"   Result: '{decrypted_text}'")
        return True
        
    except Exception as e:
        print(f"❌ Decryption still failed: {e}")
        
        # Try with different KDF orders
        print(f"\n🔄 Trying different KDF configurations...")
        
        # Test: Only PBKDF2
        kdf_pbkdf2_only = {
            "pbkdf2": {"enabled": True, "rounds": 10000},
            "scrypt": {"enabled": False},
            "argon2": {"enabled": False},
            "hkdf": {"enabled": False},
            "balloon": {"enabled": False}
        }
        
        try:
            kdf_result2 = core.multi_kdf_derive(hashed, salt, kdf_pbkdf2_only)
            key2 = base64.urlsafe_b64encode(kdf_result2)
            f2 = Fernet(key2)
            decrypted2 = f2.decrypt(fernet_data)
            
            print(f"✅ SUCCESS with PBKDF2 only: {decrypted2.decode('utf-8')}")
            return True
            
        except:
            print(f"   PBKDF2 only: failed")
        
        # Test: Only Argon2
        kdf_argon2_only = {
            "pbkdf2": {"enabled": False},
            "scrypt": {"enabled": False},
            "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4, "rounds": 10, "hash_len": 32, "type": 2},
            "hkdf": {"enabled": False},
            "balloon": {"enabled": False}
        }
        
        try:
            kdf_result3 = core.multi_kdf_derive(hashed, salt, kdf_argon2_only)
            key3 = base64.urlsafe_b64encode(kdf_result3)
            f3 = Fernet(key3)
            decrypted3 = f3.decrypt(fernet_data)
            
            print(f"✅ SUCCESS with Argon2 only: {decrypted3.decode('utf-8')}")
            return True
            
        except:
            print(f"   Argon2 only: failed")
        
        return False

if __name__ == "__main__":
    print("🎯 Nested Base64 Analysis")
    print("=" * 50)
    
    success = test_with_nested_data()
    
    if success:
        print(f"\n🎉 SUCCESS: Nested encoding issue resolved!")
    else:
        print(f"\n❌ CONTINUE: Still investigating key derivation differences")