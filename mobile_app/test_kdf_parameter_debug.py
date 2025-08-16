#!/usr/bin/env python3
"""
Debug specific KDF parameters that might differ between CLI and mobile
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

from mobile_crypto_core import MobileCryptoCore

def debug_argon2_parameters():
    """Debug Argon2 parameters specifically"""
    print("🔬 Argon2 Parameter Debug")
    print("=" * 40)
    
    if not ARGON2_AVAILABLE:
        print("❌ Argon2 not available")
        return None
    
    # CLI parameters
    password = "1234"
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    
    # Hash step (no hash rounds)
    hashed_input = password.encode() + salt
    print(f"🔑 Input to Argon2: {hashed_input.hex()}")
    
    # CLI Argon2 parameters
    cli_params = {
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 4,
        "hash_len": 32,
        "type": 2,  # Argon2id
        "rounds": 10
    }
    
    print(f"📋 CLI Argon2 parameters: {cli_params}")
    
    # Test different interpretations
    results = {}
    
    # Test 1: Direct parameters (ignore rounds)
    print(f"\n🧪 Test 1: Direct parameters")
    try:
        result1 = hash_secret_raw(
            hashed_input,
            salt,
            time_cost=cli_params["time_cost"],
            memory_cost=cli_params["memory_cost"],
            parallelism=cli_params["parallelism"],
            hash_len=cli_params["hash_len"],
            type=Type.ID
        )
        results["direct"] = result1
        print(f"   Result: {result1.hex()[:32]}...")
    except Exception as e:
        print(f"   Failed: {e}")
    
    # Test 2: Apply rounds (run Argon2 multiple times)
    print(f"\n🧪 Test 2: Apply rounds ({cli_params['rounds']} iterations)")
    try:
        current_input = hashed_input
        for i in range(cli_params["rounds"]):
            # Generate unique salt for each round
            if i == 0:
                round_salt = salt
            else:
                salt_material = hashlib.sha256(salt + str(i).encode()).digest()
                round_salt = salt_material[:16]
            
            current_input = hash_secret_raw(
                current_input,
                round_salt,
                time_cost=cli_params["time_cost"],
                memory_cost=cli_params["memory_cost"],
                parallelism=cli_params["parallelism"],
                hash_len=cli_params["hash_len"],
                type=Type.ID
            )
            print(f"   Round {i+1}: {current_input.hex()[:16]}...")
            
        results["with_rounds"] = current_input
        print(f"   Final: {current_input.hex()[:32]}...")
    except Exception as e:
        print(f"   Failed: {e}")
    
    # Test 3: Mobile implementation
    print(f"\n🧪 Test 3: Mobile Argon2 implementation")
    core = MobileCryptoCore()
    argon2_config = {
        "pbkdf2": {"enabled": False},
        "scrypt": {"enabled": False},
        "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4, "rounds": 10, "hash_len": 32, "type": 2},
        "hkdf": {"enabled": False},
        "balloon": {"enabled": False}
    }
    
    try:
        mobile_result = core.multi_kdf_derive(hashed_input, salt, argon2_config)
        results["mobile"] = mobile_result
        print(f"   Mobile: {mobile_result.hex()[:32]}...")
    except Exception as e:
        print(f"   Failed: {e}")
    
    return results

def test_with_different_argon2():
    """Test decryption with different Argon2 interpretations"""
    print(f"\n🎯 Testing Different Argon2 Results")
    print("=" * 40)
    
    # Get Argon2 results
    argon2_results = debug_argon2_parameters()
    if not argon2_results:
        print("⚠️ No Argon2 results to test")
        return
    
    # Test parameters
    password = "1234"
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    hashed_input = password.encode() + salt
    
    # Get proper Fernet data (double base64 decoded)
    encrypted_data_b64 = "Z0FBQUFBQm9KZHRWcmNyQkpDeUE5dTdScy1rYU9oV01kR3Q0VS12aHQ3dVVkTDdzUEpDSUZYc2tlcWJ5ajNfQk1obXpDS1BYWV85UzVhMWx1cFhxSWlpQkdrbjk3ZlRsekE9PQ=="
    level1 = base64.b64decode(encrypted_data_b64)
    fernet_data = base64.b64decode(level1.decode('ascii'))
    
    print(f"🔑 Testing different Argon2 → PBKDF2 combinations:")
    
    for name, argon2_result in argon2_results.items():
        print(f"\n   🧪 {name.upper()}: {argon2_result.hex()[:20]}...")
        
        try:
            # Apply PBKDF2 after Argon2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=10000,
                backend=default_backend()
            )
            pbkdf2_result = kdf.derive(argon2_result)
            
            # Create Fernet key
            fernet_key = base64.urlsafe_b64encode(pbkdf2_result)
            
            # Test decryption
            f = Fernet(fernet_key)
            decrypted = f.decrypt(fernet_data)
            decrypted_text = decrypted.decode('utf-8')
            
            print(f"      🎉 SUCCESS: '{decrypted_text}'")
            return True
            
        except Exception as e:
            print(f"      ❌ Failed: {str(e)[:50]}...")
    
    print(f"\n❌ All Argon2 interpretations failed")
    return False

if __name__ == "__main__":
    print("🎯 KDF Parameter Debug Suite")
    print("=" * 60)
    
    success = test_with_different_argon2()
    
    if success:
        print(f"\n🎉 SUCCESS: Found correct Argon2 interpretation!")
    else:
        print(f"\n❌ CONTINUE: Argon2 parameter investigation needed")