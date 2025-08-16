#!/usr/bin/env python3
"""
Analyze the PBKDF2 calls from CLI trace to understand salt generation
"""

import hashlib
import base64
from mobile_crypto_core import MobileCryptoCore

def analyze_cli_pbkdf2_pattern():
    """Analyze how CLI generates PBKDF2 salts"""
    print("🔍 CLI PBKDF2 Salt Pattern Analysis")
    print("=" * 50)
    
    # From trace: first PBKDF2 call result
    first_pbkdf2_result = "8dcc8cf1a9a09dfc9be6159eb118eaca"
    
    # Test parameters
    password = "1234"
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    
    # CLI Argon2 final result (from trace)
    argon2_final = bytes.fromhex("433ead745ee6debdadbce8b468435eea4692373f52b57c32cc34da99ca75c74c")
    
    print(f"🔑 Test parameters:")
    print(f"   Password: {password}")
    print(f"   Salt: {salt.hex()}")
    print(f"   Argon2 final: {argon2_final.hex()}")
    
    # Test different PBKDF2 salt strategies
    salt_strategies = [
        ("original_salt", salt),  # Original 16-byte salt
        ("doubled_salt", salt + salt),  # 32 bytes by doubling
        ("padded_salt", salt + b'\x00' * 16),  # 32 bytes by padding
        ("hashed_salt", hashlib.sha256(salt).digest()),  # 32 bytes by hashing
    ]
    
    print(f"\n📋 Testing PBKDF2 salt strategies:")
    
    for strategy_name, test_salt in salt_strategies:
        print(f"   Strategy: {strategy_name}")
        print(f"      Salt: {test_salt.hex()}")
        print(f"      Length: {len(test_salt)} bytes")
        
        # Test first PBKDF2 call
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=test_salt,
            iterations=1,
            backend=default_backend()
        )
        result = kdf.derive(argon2_final)
        result_hex = result.hex()[:32]
        
        print(f"      First result: {result_hex}")
        print(f"      Expected:     {first_pbkdf2_result}")
        
        if result_hex == first_pbkdf2_result:
            print(f"      ✅ MATCH! Found correct salt strategy")
            return strategy_name, test_salt
        else:
            print(f"      ❌ No match")
    
    print(f"\n❌ No salt strategy matched CLI behavior")
    return None, None

def test_mobile_with_correct_salt(salt_strategy, correct_salt):
    """Test mobile implementation with corrected salt strategy"""
    if not salt_strategy:
        return False
        
    print(f"\n🧪 Testing Mobile with Corrected Salt Strategy: {salt_strategy}")
    print("=" * 60)
    
    # Test parameters
    password = "1234"
    original_salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    
    # Expected CLI key
    expected_cli_key = "dd4bf9c9f4bca63a45f36323f567272a4f509747f90d522f5351c8e7c53951ef"
    
    print(f"   Expected CLI key: {expected_cli_key}")
    
    # Modify mobile implementation temporarily
    core = MobileCryptoCore()
    
    # Simulate CLI process
    password_bytes = password.encode()
    
    # Hash (no rounds - CLI behavior)
    hashed = password_bytes + original_salt
    print(f"   Hash result: {hashed.hex()}")
    
    # Argon2 (10 rounds)
    from argon2.low_level import hash_secret_raw, Type
    
    current = hashed
    for i in range(10):
        if i == 0:
            round_salt = original_salt
        else:
            salt_material = hashlib.sha256(original_salt + str(i).encode()).digest()
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
    
    print(f"   Argon2 final: {current.hex()}")
    
    # PBKDF2 with correct salt strategy (test first few rounds)
    pbkdf2_input = current
    
    # Generate PBKDF2 salt using discovered strategy
    if salt_strategy == "hashed_salt":
        pbkdf2_base_salt = hashlib.sha256(original_salt).digest()
    elif salt_strategy == "doubled_salt":
        pbkdf2_base_salt = original_salt + original_salt
    elif salt_strategy == "padded_salt":
        pbkdf2_base_salt = original_salt + b'\x00' * 16
    else:
        pbkdf2_base_salt = original_salt
    
    print(f"   PBKDF2 base salt: {pbkdf2_base_salt.hex()}")
    
    # Apply PBKDF2 (all 10000 rounds)
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    
    for i in range(10000):
        if i == 0:
            round_salt = pbkdf2_base_salt
        else:
            salt_material = hashlib.sha256(pbkdf2_base_salt + str(i).encode()).digest()
            round_salt = salt_material[:32]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=round_salt,
            iterations=1,
            backend=default_backend()
        )
        pbkdf2_input = kdf.derive(pbkdf2_input)
        
        # Show progress
        if i < 5 or i % 1000 == 0:
            print(f"   PBKDF2 round {i+1}: {pbkdf2_input.hex()[:16]}...")
    
    final_key = pbkdf2_input.hex()
    print(f"   Mobile final key: {final_key}")
    
    if final_key == expected_cli_key:
        print(f"✅ SUCCESS: Mobile key matches CLI!")
        return True
    else:
        print(f"❌ Keys still differ:")
        print(f"   CLI:    {expected_cli_key}")
        print(f"   Mobile: {final_key}")
        return False

if __name__ == "__main__":
    # Find correct salt strategy
    strategy, salt = analyze_cli_pbkdf2_pattern()
    
    # Test mobile with correct strategy
    if strategy:
        success = test_mobile_with_correct_salt(strategy, salt)
        
        if success:
            print(f"\n🎉 SOLUTION FOUND: Use {strategy} for PBKDF2 salt generation")
        else:
            print(f"\n🔍 Need further investigation")
    else:
        print(f"\n❌ Could not determine correct salt strategy")