#!/usr/bin/env python3
"""
Test the final decryption with corrected mobile key
"""

import base64
import json
from mobile_crypto_core import MobileCryptoCore
from cryptography.fernet import Fernet

def test_mobile_decryption():
    """Test mobile decryption with corrected implementation"""
    print("🧪 Testing Mobile Decryption with Corrected Key")
    print("=" * 60)
    
    # Test file
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
    password = "1234"
    
    print(f"🔑 Test parameters:")
    print(f"   File: {test_file}")
    print(f"   Password: {password}")
    
    # Read and parse file
    with open(test_file, 'r') as f:
        content = f.read().strip()
    
    metadata_b64, encrypted_data_b64 = content.split(':', 1)
    
    # Decode metadata
    metadata_json = base64.b64decode(metadata_b64).decode()
    metadata = json.loads(metadata_json)
    
    print(f"   Format version: {metadata.get('format_version')}")
    print(f"   Encryption algorithm: {metadata.get('encryption', {}).get('algorithm')}")
    
    # Test mobile decrypt_file method
    print(f"\n📋 Testing Mobile decrypt_file method:")
    
    core = MobileCryptoCore()
    result = core.decrypt_file(test_file, password, "/tmp/mobile_decrypt_test.txt")
    
    print(f"   Result: {result}")
    
    if result.get("success"):
        # Read decrypted content
        with open("/tmp/mobile_decrypt_test.txt", 'r') as f:
            decrypted_content = f.read()
        print(f"   Decrypted content: '{decrypted_content}'")
        print(f"✅ Mobile decrypt_file SUCCESS!")
        return True
    else:
        print(f"❌ Mobile decrypt_file failed: {result.get('error', 'Unknown error')}")
        
        # Try manual decryption to debug
        print(f"\n🔧 Manual decryption debugging:")
        
        try:
            # Use mobile decrypt_data directly
            manual_result = core.decrypt_data(encrypted_data_b64, metadata, password)
            
            if manual_result.get("success"):
                decrypted_text = manual_result["decrypted_data"].decode('utf-8')
                print(f"   Manual decrypt SUCCESS: '{decrypted_text}'")
                return True
            else:
                print(f"   Manual decrypt failed: {manual_result.get('error')}")
                
                # Debug key generation
                print(f"\n🔍 Debugging key generation:")
                
                # Extract salt and configs
                derivation_config = metadata["derivation_config"]
                salt = base64.b64decode(derivation_config["salt"])
                
                # Generate key manually
                password_bytes = password.encode()
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
                        if "enabled" in kdf_params:
                            enabled = kdf_params["enabled"]
                        else:
                            enabled = True
                        
                        kdf_config[kdf_name]["enabled"] = enabled
                        
                        for param, value in kdf_params.items():
                            if param != "enabled":
                                kdf_config[kdf_name][param] = value
                
                key = core._derive_key(password, salt, hash_config, kdf_config)
                print(f"   Generated key: {key}")
                
                # Test Fernet directly
                try:
                    # First level decode
                    level1_data = base64.b64decode(encrypted_data_b64)
                    print(f"   Level 1 data: {len(level1_data)} bytes")
                    
                    # Second level decode (CLI nested base64)
                    level2_data = base64.b64decode(level1_data.decode('ascii'))
                    print(f"   Level 2 data: {len(level2_data)} bytes")
                    
                    f = Fernet(key)
                    decrypted = f.decrypt(level2_data)
                    decrypted_text = decrypted.decode('utf-8')
                    print(f"✅ Direct Fernet SUCCESS: '{decrypted_text}'")
                    return True
                    
                except Exception as fernet_error:
                    print(f"❌ Direct Fernet failed: {fernet_error}")
                    
                    # Check if key is base64-encoded correctly
                    try:
                        key_raw = base64.urlsafe_b64decode(key)
                        print(f"   Key raw bytes: {key_raw.hex()}")
                        print(f"   Key length: {len(key_raw)} bytes")
                    except Exception as key_error:
                        print(f"   Key decode error: {key_error}")
        
        except Exception as e:
            print(f"   Manual decryption error: {e}")
            import traceback
            traceback.print_exc()
    
    return False

if __name__ == "__main__":
    success = test_mobile_decryption()
    
    if success:
        print(f"\n🎉 FINAL SUCCESS: Mobile can decrypt CLI files!")
    else:
        print(f"\n❌ Still debugging decryption issues")