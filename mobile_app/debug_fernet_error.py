#!/usr/bin/env python3
"""
Debug the specific Fernet decryption error
"""

import base64
import json
from mobile_crypto_core import MobileCryptoCore
from cryptography.fernet import Fernet, InvalidToken

def debug_fernet_error():
    """Debug what's causing the Fernet decryption to fail"""
    print("🔍 Debugging Fernet Decryption Error")
    print("=" * 50)
    
    # Test file
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
    password = "1234"
    
    # Parse file
    with open(test_file, 'r') as f:
        content = f.read().strip()
    
    metadata_b64, encrypted_data_b64 = content.split(':', 1)
    metadata_json = base64.b64decode(metadata_b64).decode()
    metadata = json.loads(metadata_json)
    
    # Generate mobile key
    core = MobileCryptoCore()
    
    derivation_config = metadata["derivation_config"]
    salt = base64.b64decode(derivation_config["salt"])
    
    cli_hash_config = derivation_config.get("hash_config", {})
    hash_config = {}
    for algo, config in cli_hash_config.items():
        if isinstance(config, dict) and "rounds" in config:
            hash_config[algo] = config["rounds"]
        else:
            hash_config[algo] = config if isinstance(config, int) else 0
    hash_config = core.clean_hash_config(hash_config)
    
    cli_kdf_config = derivation_config.get("kdf_config", {})
    kdf_config = core.default_kdf_config.copy()
    for kdf in kdf_config:
        kdf_config[kdf]["enabled"] = False
    
    for kdf_name, kdf_params in cli_kdf_config.items():
        if kdf_name in kdf_config:
            enabled = kdf_params.get("enabled", True)
            kdf_config[kdf_name]["enabled"] = enabled
            
            for param, value in kdf_params.items():
                if param != "enabled":
                    kdf_config[kdf_name][param] = value
    
    mobile_key = core._derive_key(password, salt, hash_config, kdf_config)
    mobile_key_raw = base64.urlsafe_b64decode(mobile_key)
    
    print(f"🔑 Mobile key: {mobile_key}")
    print(f"   Raw bytes: {mobile_key_raw.hex()}")
    print(f"   Length: {len(mobile_key_raw)} bytes")
    
    # Test CLI key extraction for comparison
    print(f"\n🔑 Testing CLI key extraction:")
    
    import sys
    sys.path.insert(0, '../openssl_encrypt')
    
    try:
        from openssl_encrypt.modules.crypt_core import decrypt_file
        from cryptography.fernet import Fernet as OriginalFernet
        
        # Capture CLI key
        cli_key = None
        original_fernet_init = OriginalFernet.__init__
        
        def capture_key(self, key):
            nonlocal cli_key
            cli_key = key
            return original_fernet_init(self, key)
        
        OriginalFernet.__init__ = capture_key
        
        result = decrypt_file(test_file, '/tmp/cli_debug.txt', b"1234", quiet=True)
        
        if cli_key:
            cli_key_raw = base64.urlsafe_b64decode(cli_key)
            print(f"   CLI key: {cli_key}")
            print(f"   Raw bytes: {cli_key_raw.hex()}")
            print(f"   Keys match: {mobile_key_raw == cli_key_raw}")
            
            if mobile_key_raw == cli_key_raw:
                print(f"✅ Keys are identical - problem is elsewhere")
                
                # Test with CLI key on mobile data
                print(f"\n🧪 Testing CLI key on mobile-processed data:")
                
                # Process data like mobile does
                level1_data = base64.b64decode(encrypted_data_b64)
                print(f"   Level 1: {len(level1_data)} bytes, starts with: {level1_data[:20]}")
                
                try:
                    level2_data = base64.b64decode(level1_data.decode('ascii'))
                    print(f"   Level 2: {len(level2_data)} bytes, starts with: {level2_data[:20]}")
                    
                    # Test CLI key with this data
                    f_cli = OriginalFernet(cli_key)
                    try:
                        decrypted_cli = f_cli.decrypt(level2_data)
                        print(f"✅ CLI key works: '{decrypted_cli.decode()}'")
                        
                        # Now test mobile key
                        f_mobile = Fernet(mobile_key)
                        try:
                            decrypted_mobile = f_mobile.decrypt(level2_data)
                            print(f"✅ Mobile key works: '{decrypted_mobile.decode()}'")
                            return True
                        except Exception as mobile_error:
                            print(f"❌ Mobile key fails: {type(mobile_error).__name__}: {mobile_error}")
                            
                    except Exception as cli_error:
                        print(f"❌ CLI key fails: {type(cli_error).__name__}: {cli_error}")
                        
                except Exception as decode_error:
                    print(f"❌ Level 2 decode fails: {decode_error}")
                    print(f"   Level 1 as string: '{level1_data.decode('ascii', errors='replace')}'")
            else:
                print(f"❌ Keys differ - this shouldn't happen!")
        else:
            print(f"❌ Could not capture CLI key")
            
    except Exception as e:
        print(f"❌ CLI key extraction failed: {e}")
        import traceback
        traceback.print_exc()
    
    return False

if __name__ == "__main__":
    debug_fernet_error()