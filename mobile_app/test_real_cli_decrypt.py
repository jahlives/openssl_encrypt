#!/usr/bin/env python3
"""
Test Real CLI File Decryption
"""

import base64
import json
from mobile_crypto_core import MobileCryptoCore

def test_real_cli_file():
    """Test decrypting the actual CLI file"""
    print("🧪 Testing Real CLI File Decryption")
    print("=" * 50)
    
    cli_file = "cli_test_file.txt"
    password = "1234"
    
    try:
        # Read CLI file
        with open(cli_file, 'r') as f:
            raw_content = f.read().strip()
        
        if ':' in raw_content:
            metadata_b64, encrypted_data_b64 = raw_content.split(':', 1)
            
            # Decode metadata
            metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
            metadata = json.loads(metadata_json)
            
            print(f"✅ CLI file parsed successfully")
            print(f"   Metadata keys: {list(metadata.keys())}")
            print(f"   Encrypted data length: {len(encrypted_data_b64)}")
            
            # Test mobile decryption
            core = MobileCryptoCore()
            result = core.decrypt_data(encrypted_data_b64, metadata, password)
            
            if result["success"]:
                print("🎉 SUCCESS: Mobile decrypted CLI file!")
                decrypted = result["decrypted_data"]
                if isinstance(decrypted, bytes):
                    try:
                        decrypted_text = decrypted.decode('utf-8')
                        print(f"   Decrypted text: {decrypted_text}")
                    except:
                        print(f"   Decrypted binary: {decrypted[:50]}...")
                else:
                    print(f"   Decrypted: {decrypted}")
                return True
            else:
                print(f"❌ Mobile decrypt failed: {result['error']}")
                
                # Debug the failure
                print(f"\n🔍 Debug Information:")
                
                # Check derivation config
                if "derivation_config" in metadata:
                    derivation = metadata["derivation_config"]
                    salt = base64.b64decode(derivation["salt"])
                    print(f"   Salt: {salt.hex()}")
                    
                    # Test hash processing
                    hash_config = {}
                    for algo, config in derivation.get("hash_config", {}).items():
                        if isinstance(config, dict) and "rounds" in config:
                            hash_config[algo] = config["rounds"]
                        else:
                            hash_config[algo] = config if isinstance(config, int) else 0
                    
                    hash_config = core.clean_hash_config(hash_config)
                    print(f"   Hash config: {hash_config}")
                    
                    # Test hash step
                    password_bytes = password.encode()
                    hashed = core.multi_hash_password(password_bytes, salt, hash_config)
                    print(f"   Hash result: {hashed.hex()}")
                    
                    # Test KDF config parsing
                    cli_kdf_config = derivation.get("kdf_config", {})
                    kdf_config = core.default_kdf_config.copy()
                    
                    for kdf in kdf_config:
                        kdf_config[kdf]["enabled"] = False
                    
                    for kdf_name, kdf_params in cli_kdf_config.items():
                        if kdf_name in kdf_config:
                            # CLI format: if KDF is present in metadata, it's enabled
                            kdf_config[kdf_name]["enabled"] = True
                            for param, value in kdf_params.items():
                                if param != "enabled":
                                    kdf_config[kdf_name][param] = value
                    
                    print(f"   KDF config: {kdf_config}")
                    
                    # Test key derivation
                    try:
                        key = core._derive_key(password, salt, hash_config, kdf_config)
                        print(f"   Derived key: {key[:32]}...")
                    except Exception as e:
                        print(f"   Key derivation failed: {e}")
                        import traceback
                        traceback.print_exc()
                
                return False
        else:
            print("❌ CLI file format not recognized")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_real_cli_file()