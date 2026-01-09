#!/usr/bin/env python3
"""
Debug the exact key difference between CLI and mobile
"""

import sys
import base64
import json
sys.path.insert(0, '../openssl_encrypt')

from mobile_crypto_core import MobileCryptoCore
from cryptography.fernet import Fernet

# Try to import CLI functions
try:
    from openssl_encrypt.modules.crypt_core import multi_hash_password as cli_multi_hash_password
    CLI_AVAILABLE = True
except ImportError as e:
    CLI_AVAILABLE = False
    print(f"CLI not available: {e}")

def debug_key_derivation():
    """Debug the exact key derivation difference"""
    print("🔍 Debug Key Derivation Difference")
    print("=" * 50)
    
    # Parse the test file
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
    
    with open(test_file, 'r') as f:
        raw_content = f.read().strip()
    
    metadata_b64, encrypted_data_b64 = raw_content.split(':', 1)
    metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
    metadata = json.loads(metadata_json)
    
    # Extract parameters
    password = "1234"
    derivation_config = metadata["derivation_config"]
    salt = base64.b64decode(derivation_config["salt"])
    
    print(f"🔑 Parameters:")
    print(f"   Password: {password}")
    print(f"   Salt: {salt.hex()}")
    
    # Get CLI hash config
    cli_hash_config = derivation_config.get("hash_config", {})
    hash_config = {}
    for algo, config in cli_hash_config.items():
        if isinstance(config, dict) and "rounds" in config:
            hash_config[algo] = config["rounds"]
        else:
            hash_config[algo] = config if isinstance(config, int) else 0
    
    print(f"   Hash config: {hash_config}")
    
    # Test mobile hash processing
    core = MobileCryptoCore()
    hash_config = core.clean_hash_config(hash_config)
    
    password_bytes = password.encode()
    mobile_hashed = core.multi_hash_password(password_bytes, salt, hash_config)
    print(f"   Mobile hash: {mobile_hashed.hex()}")
    
    # Test CLI hash processing if available
    if CLI_AVAILABLE:
        try:
            cli_hashed = cli_multi_hash_password(password_bytes, salt, hash_config, quiet=True)
            print(f"   CLI hash:    {cli_hashed.hex()}")
            print(f"   Hash match:  {'✅' if mobile_hashed == cli_hashed else '❌'}")
        except Exception as e:
            print(f"   CLI hash failed: {e}")
    
    # Process KDF configuration
    cli_kdf_config = derivation_config.get("kdf_config", {})
    kdf_config = core.default_kdf_config.copy()
    
    # Disable all first
    for kdf in kdf_config:
        kdf_config[kdf]["enabled"] = False
    
    # Enable based on CLI config
    for kdf_name, kdf_params in cli_kdf_config.items():
        if kdf_name in kdf_config:
            if "enabled" in kdf_params:
                enabled = kdf_params["enabled"]
            elif kdf_name == "pbkdf2":
                enabled = kdf_params.get("rounds", 0) > 0
            else:
                enabled = False
            
            kdf_config[kdf_name]["enabled"] = enabled
            
            for param, value in kdf_params.items():
                if param != "enabled":
                    kdf_config[kdf_name][param] = value
    
    print(f"   KDF enabled: {[k for k, v in kdf_config.items() if v.get('enabled')]}")
    
    # Test mobile KDF
    mobile_kdf = core.multi_kdf_derive(mobile_hashed, salt, kdf_config)
    mobile_key = base64.urlsafe_b64encode(mobile_kdf)
    
    print(f"   Mobile KDF: {mobile_kdf.hex()[:32]}...")
    print(f"   Mobile key: {mobile_key[:32]}...")
    
    # Get the actual encrypted data (with nested base64 decoding)
    level1 = base64.b64decode(encrypted_data_b64)
    fernet_data = base64.b64decode(level1.decode('ascii'))
    
    print(f"   Fernet data: {len(fernet_data)} bytes")
    
    # Test decryption
    try:
        f = Fernet(mobile_key)
        decrypted = f.decrypt(fernet_data)
        decrypted_text = decrypted.decode('utf-8')
        print(f"🎉 SUCCESS: '{decrypted_text}'")
        return True
    except Exception as e:
        print(f"❌ Fernet failed: {e}")
        
        # Maybe the issue is in Argon2 type parameter?
        print(f"\n🔄 Trying different Argon2 type interpretations...")
        
        from argon2.low_level import hash_secret_raw, Type
        import hashlib
        
        # Test different Argon2 type values
        for type_name, type_val in [("Type.I", Type.I), ("Type.D", Type.D), ("Type.ID", Type.ID)]:
            print(f"   Testing {type_name}...")
            
            try:
                # Apply Argon2 with different type
                current_input = mobile_hashed
                for i in range(10):  # 10 rounds
                    if i == 0:
                        round_salt = salt
                    else:
                        salt_material = hashlib.sha256(salt + str(i).encode()).digest()
                        round_salt = salt_material[:16]
                    
                    current_input = hash_secret_raw(
                        current_input,
                        round_salt,
                        time_cost=3,
                        memory_cost=65536,
                        parallelism=4,
                        hash_len=32,
                        type=type_val
                    )
                
                # Apply PBKDF2
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.backends import default_backend
                
                pbkdf2_kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=10000,
                    backend=default_backend()
                )
                final_result = pbkdf2_kdf.derive(current_input)
                test_key = base64.urlsafe_b64encode(final_result)
                
                # Test decryption
                test_f = Fernet(test_key)
                test_decrypted = test_f.decrypt(fernet_data)
                test_text = test_decrypted.decode('utf-8')
                
                print(f"      🎉 SUCCESS with {type_name}: '{test_text}'")
                return True
                
            except Exception as type_e:
                print(f"      ❌ Failed with {type_name}: {str(type_e)[:30]}...")
        
        return False

if __name__ == "__main__":
    success = debug_key_derivation()
    
    if success:
        print(f"\n🎉 Found the solution!")
    else:
        print(f"\n❌ Still investigating...")