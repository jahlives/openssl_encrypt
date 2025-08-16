#!/usr/bin/env python3
"""
Phase 2: Step-by-step CLI vs Mobile comparison with exact traces
"""

import base64
import hashlib
from mobile_crypto_core import MobileCryptoCore
from cryptography.fernet import Fernet

def test_corrected_mobile_implementation():
    """Test mobile with the corrected PBKDF2 implementation"""
    print("🧪 Testing Corrected Mobile Implementation")
    print("=" * 50)
    
    # Test parameters from CLI file
    password = "1234"
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    
    print(f"🔑 Parameters:")
    print(f"   Password: {password}")
    print(f"   Salt: {salt.hex()}")
    print(f"   Salt length: {len(salt)} bytes")
    
    # Get encrypted data
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
    
    with open(test_file, 'r') as f:
        content = f.read().strip()
    metadata_b64, encrypted_data_b64 = content.split(':', 1)
    
    level1 = base64.b64decode(encrypted_data_b64)
    fernet_data = base64.b64decode(level1.decode('ascii'))
    
    print(f"   Fernet data: {len(fernet_data)} bytes")
    
    # Test CLI expectations vs mobile reality
    expected_cli_key = "dd4bf9c9f4bca63a45f36323f567272a4f509747f90d522f5351c8e7c53951ef"
    print(f"   Expected CLI key: {expected_cli_key}")
    
    # Test mobile key generation
    core = MobileCryptoCore()
    
    # Configure same as CLI
    hash_config = {"sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0, "blake2b": 0, "shake256": 0, "whirlpool": 0, "blake3": 0}
    kdf_config = {
        "pbkdf2": {"enabled": True, "rounds": 10000},
        "scrypt": {"enabled": False},
        "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4, "rounds": 10, "hash_len": 32, "type": 2},
        "hkdf": {"enabled": False},
        "balloon": {"enabled": False}
    }
    
    # Step-by-step generation
    print(f"\n📝 Step-by-step mobile generation:")
    
    # Hash
    password_bytes = password.encode()
    mobile_hash = core.multi_hash_password(password_bytes, salt, hash_config)
    print(f"   1. Hash: {mobile_hash.hex()}")
    
    # KDF
    mobile_kdf = core.multi_kdf_derive(mobile_hash, salt, kdf_config)
    print(f"   2. KDF:  {mobile_kdf.hex()}")
    
    # Key
    mobile_key_raw = mobile_kdf
    mobile_key = base64.urlsafe_b64encode(mobile_key_raw)
    print(f"   3. Key:  {mobile_key_raw.hex()}")
    
    # Compare with expected
    if mobile_key_raw.hex() == expected_cli_key:
        print(f"✅ SUCCESS: Mobile matches CLI key!")
        
        # Test decryption
        try:
            f = Fernet(mobile_key)
            decrypted = f.decrypt(fernet_data)
            decrypted_text = decrypted.decode('utf-8')
            print(f"🎉 DECRYPTION SUCCESS: '{decrypted_text.strip()}'")
            return True
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            
    else:
        print(f"❌ Keys still differ:")
        print(f"   CLI:    {expected_cli_key}")
        print(f"   Mobile: {mobile_key_raw.hex()}")
        
        # Find where they differ
        cli_bytes = bytes.fromhex(expected_cli_key)
        mobile_bytes = mobile_key_raw
        
        for i in range(min(len(cli_bytes), len(mobile_bytes))):
            if cli_bytes[i] != mobile_bytes[i]:
                print(f"   First diff at byte {i}: CLI={cli_bytes[i]:02x} vs Mobile={mobile_bytes[i]:02x}")
                break
        
        # Test if the differences are small - maybe we can still decrypt
        print(f"\n🔄 Testing mobile key anyway...")
        try:
            f = Fernet(mobile_key)
            decrypted = f.decrypt(fernet_data)
            decrypted_text = decrypted.decode('utf-8')
            print(f"🎉 UNEXPECTED SUCCESS: '{decrypted_text.strip()}'")
            return True
        except Exception as e:
            print(f"❌ Mobile key decrypt failed: {e}")
    
    return False

def manual_cli_recreation():
    """Manually recreate the CLI process step by step"""
    print(f"\n🔧 Manual CLI Recreation")
    print("=" * 50)
    
    # From the CLI trace, I know:
    # 1. 10 Argon2 calls with specific salts
    # 2. 10000 PBKDF2 calls with 1 iteration each and 32-byte salts
    
    password = "1234".encode()
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    
    print(f"🔑 Manual CLI recreation:")
    print(f"   Input: {password}")
    print(f"   Salt: {salt.hex()}")
    
    # Step 1: Hash (no rounds)
    hashed = password + salt
    print(f"   1. Hash: {hashed.hex()}")
    
    # Step 2: Argon2 (10 rounds)
    print(f"   2. Argon2 (10 rounds):")
    
    from argon2.low_level import hash_secret_raw, Type
    
    current = hashed
    for i in range(10):
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
        print(f"      Round {i+1}: {current.hex()[:16]}...")
    
    print(f"   Argon2 final: {current.hex()}")
    
    # Step 3: PBKDF2 (10000 rounds with 1 iteration each)
    print(f"   3. PBKDF2 (10000 rounds, 1 iter each):")
    
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    
    # Based on CLI trace: salt length is 32 bytes for PBKDF2
    pbkdf2_input = current
    
    # Try different salt strategies
    salt_strategies = [
        ("base_salt_16", salt),  # Original 16-byte salt
        ("base_salt_32", salt + salt),  # Double to 32 bytes
        ("hash_salt_32", hashlib.sha256(salt).digest()),  # Hash to 32 bytes
    ]
    
    for strategy_name, base_salt in salt_strategies:
        print(f"      Strategy: {strategy_name}")
        
        test_current = pbkdf2_input
        for i in range(min(5, 10000)):  # Test first 5 rounds
            if i == 0:
                round_salt = base_salt
            else:
                salt_material = hashlib.sha256(base_salt + str(i).encode()).digest()
                round_salt = salt_material[:len(base_salt)]
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=round_salt,
                iterations=1,
                backend=default_backend()
            )
            test_current = kdf.derive(test_current)
        
        print(f"         After 5 rounds: {test_current.hex()[:16]}...")
        
        # Test if this direction looks promising by comparing with CLI's first few PBKDF2 results
        # From trace: first result was 8dcc8cf1a9a09dfc9be6159eb118eaca...
        first_expected = "8dcc8cf1a9a09dfc9be6159eb118eaca"
        
        # Test just the first PBKDF2 call
        first_kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=base_salt,
            iterations=1,
            backend=default_backend()
        )
        first_result = first_kdf.derive(pbkdf2_input)
        print(f"         First result: {first_result.hex()[:32]}")
        
        if first_result.hex().startswith(first_expected[:16]):
            print(f"         ✅ MATCH! This strategy looks correct")
            break
        else:
            print(f"         ❌ No match with expected {first_expected[:16]}...")

if __name__ == "__main__":
    print("🎯 Phase 2: Step-by-Step CLI Recreation")
    print("=" * 60)
    
    # Test corrected mobile implementation
    success = test_corrected_mobile_implementation()
    
    # Manual recreation to understand exact process
    manual_cli_recreation()
    
    if success:
        print(f"\n🎉 SUCCESS: Mobile implementation now matches CLI!")
    else:
        print(f"\n🔍 CONTINUE: Still need to refine mobile implementation")