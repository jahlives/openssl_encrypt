#!/usr/bin/env python3
"""
Final KDF Order Test - try all possible orders
"""

import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

def test_all_kdf_orders():
    """Test all possible KDF orders to find the right one"""
    print("🎯 Final KDF Order Test")
    print("=" * 50)
    
    if not ARGON2_AVAILABLE:
        print("❌ Argon2 not available")
        return False
    
    # Test parameters
    password = "1234"
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    hashed_input = password.encode() + salt
    
    # Get proper Fernet data
    encrypted_data_b64 = "Z0FBQUFBQm9KZHRWcmNyQkpDeUE5dTdScy1rYU9oV01kR3Q0VS12aHQ3dVVkTDdzUEpDSUZYc2tlcWJ5ajNfQk1obXpDS1BYWV85UzVhMWx1cFhxSWlpQkdrbjk3ZlRsekE9PQ=="
    level1 = base64.b64decode(encrypted_data_b64)
    fernet_data = base64.b64decode(level1.decode('ascii'))
    
    print(f"🔑 Test parameters:")
    print(f"   Input: {hashed_input.hex()}")
    print(f"   Salt: {salt.hex()}")
    print(f"   Fernet data: {len(fernet_data)} bytes")
    
    # Define KDF functions
    def apply_pbkdf2(input_data, salt, iterations=10000):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(input_data)
    
    def apply_argon2(input_data, salt, rounds=10):
        current = input_data
        for i in range(rounds):
            if i == 0:
                round_salt = salt
            else:
                salt_material = hashlib.sha256(salt + str(i).encode()).digest()
                round_salt = salt_material[:16]
            
            current = hash_secret_raw(
                current,
                round_salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=Type.ID
            )
        return current
    
    # Test different orders
    test_cases = [
        {
            "name": "PBKDF2 only",
            "steps": [("pbkdf2", 10000)]
        },
        {
            "name": "Argon2 only", 
            "steps": [("argon2", 10)]
        },
        {
            "name": "PBKDF2 → Argon2",
            "steps": [("pbkdf2", 10000), ("argon2", 10)]
        },
        {
            "name": "Argon2 → PBKDF2 (mobile order)",
            "steps": [("argon2", 10), ("pbkdf2", 10000)]
        }
    ]
    
    print(f"\n🧪 Testing KDF orders:")
    
    for test_case in test_cases:
        print(f"\n   📋 {test_case['name']}:")
        
        try:
            current_data = hashed_input
            
            for step_name, param in test_case["steps"]:
                if step_name == "pbkdf2":
                    current_data = apply_pbkdf2(current_data, salt, param)
                    print(f"      PBKDF2({param}): {current_data.hex()[:16]}...")
                elif step_name == "argon2":
                    current_data = apply_argon2(current_data, salt, param)
                    print(f"      Argon2({param}): {current_data.hex()[:16]}...")
            
            # Test with Fernet
            fernet_key = base64.urlsafe_b64encode(current_data)
            f = Fernet(fernet_key)
            decrypted = f.decrypt(fernet_data)
            decrypted_text = decrypted.decode('utf-8')
            
            print(f"      🎉 SUCCESS: '{decrypted_text}'")
            print(f"      Final key: {current_data.hex()}")
            return True
            
        except Exception as e:
            print(f"      ❌ Failed: {str(e)[:50]}...")
    
    print(f"\n❌ All KDF orders failed")
    return False

def check_mobile_vs_manual():
    """Compare mobile implementation with manual KDF"""
    print(f"\n🔍 Mobile vs Manual Comparison")
    print("=" * 50)
    
    from mobile_crypto_core import MobileCryptoCore
    
    password = "1234"
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    hashed_input = password.encode() + salt
    
    core = MobileCryptoCore()
    
    # Mobile KDF config
    kdf_config = {
        "pbkdf2": {"enabled": True, "rounds": 10000},
        "scrypt": {"enabled": False},
        "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4, "rounds": 10, "hash_len": 32, "type": 2},
        "hkdf": {"enabled": False},
        "balloon": {"enabled": False}
    }
    
    # Get mobile result
    try:
        mobile_result = core.multi_kdf_derive(hashed_input, salt, kdf_config)
        print(f"📋 Mobile result: {mobile_result.hex()}")
    except Exception as e:
        print(f"❌ Mobile KDF failed: {e}")
        return
    
    # Manual Argon2 → PBKDF2 (mobile order)
    try:
        # Step 1: Argon2
        argon2_result = hash_secret_raw(
            hashed_input,
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        print(f"📋 Manual Argon2: {argon2_result.hex()}")
        
        # Apply Argon2 rounds
        for i in range(1, 10):  # 9 more rounds (total 10)
            salt_material = hashlib.sha256(salt + str(i).encode()).digest()
            round_salt = salt_material[:16]
            argon2_result = hash_secret_raw(
                argon2_result,
                round_salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=Type.ID
            )
        
        print(f"📋 Argon2 final: {argon2_result.hex()}")
        
        # Step 2: PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=10000,
            backend=default_backend()
        )
        pbkdf2_result = kdf.derive(argon2_result)
        print(f"📋 Manual final: {pbkdf2_result.hex()}")
        
        if mobile_result == pbkdf2_result:
            print("✅ Mobile matches manual implementation")
        else:
            print("❌ Mobile differs from manual")
            
    except Exception as e:
        print(f"❌ Manual KDF failed: {e}")

if __name__ == "__main__":
    print("🎯 Final KDF Order Debug Suite")
    print("=" * 60)
    
    success = test_all_kdf_orders()
    check_mobile_vs_manual()
    
    if success:
        print(f"\n🎉 SUCCESS: Found correct KDF order!")
    else:
        print(f"\n❌ CONTINUE: Need to investigate further")