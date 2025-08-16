#!/usr/bin/env python3
"""
Compare CLI vs mobile derived keys
"""

import base64
from mobile_crypto_core import MobileCryptoCore

def compare_keys():
    """Compare the exact keys CLI vs mobile produce"""
    print("🔍 Key Comparison")
    print("=" * 40)
    
    # From CLI tracing
    cli_fernet_key_b64 = b'3Uv5yfS8pjpF82Mj9WcnKk9Ql0f5DVIv'  # First 32 chars from trace
    print(f"CLI Fernet key (partial): {cli_fernet_key_b64}")
    
    # I need to get the full CLI key, let me modify the tracer
    pass

def get_full_cli_key():
    """Get the full CLI-derived key"""
    print("🔍 Getting Full CLI Key")
    print("=" * 40)
    
    import sys
    sys.path.insert(0, '../openssl_encrypt')
    
    try:
        from openssl_encrypt.modules.crypt_core import decrypt_file
        from cryptography.fernet import Fernet
        
        # Patch Fernet to capture the full key
        captured_key = None
        original_fernet_init = Fernet.__init__
        
        def capture_fernet_key(self, key):
            nonlocal captured_key
            captured_key = key
            print(f"📋 Captured CLI key: {key}")
            print(f"   Length: {len(key)}")
            # Decode to see the raw bytes
            try:
                decoded = base64.urlsafe_b64decode(key)
                print(f"   Raw bytes: {decoded.hex()}")
            except Exception as e:
                print(f"   Decode failed: {e}")
            return original_fernet_init(self, key)
        
        Fernet.__init__ = capture_fernet_key
        
        # Run CLI decrypt
        test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
        result = decrypt_file(test_file, '/tmp/cli_key_test.txt', b"1234", quiet=True)
        
        if captured_key:
            print(f"✅ CLI Key captured: {captured_key}")
            
            # Now test mobile key
            print(f"\n📋 Mobile Key Generation:")
            
            # Parse test file metadata
            import json
            with open(test_file, 'r') as f:
                content = f.read().strip()
            
            metadata_b64, _ = content.split(':', 1)
            metadata = json.loads(base64.b64decode(metadata_b64).decode())
            
            # Extract parameters
            derivation_config = metadata["derivation_config"]
            salt = base64.b64decode(derivation_config["salt"])
            
            # Process configs
            core = MobileCryptoCore()
            
            # Hash config
            cli_hash_config = derivation_config.get("hash_config", {})
            hash_config = {}
            for algo, config in cli_hash_config.items():
                if isinstance(config, dict) and "rounds" in config:
                    hash_config[algo] = config["rounds"]
                else:
                    hash_config[algo] = config if isinstance(config, int) else 0
            hash_config = core.clean_hash_config(hash_config)
            
            # KDF config
            cli_kdf_config = derivation_config.get("kdf_config", {})
            kdf_config = core.default_kdf_config.copy()
            
            for kdf in kdf_config:
                kdf_config[kdf]["enabled"] = False
            
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
            
            # Generate mobile key
            password_bytes = "1234".encode()
            mobile_hashed = core.multi_hash_password(password_bytes, salt, hash_config)
            mobile_kdf = core.multi_kdf_derive(mobile_hashed, salt, kdf_config)
            mobile_key = base64.urlsafe_b64encode(mobile_kdf)
            
            print(f"   Mobile key: {mobile_key}")
            print(f"   Mobile raw: {mobile_kdf.hex()}")
            
            # Compare
            if captured_key == mobile_key:
                print(f"✅ Keys match!")
                return True
            else:
                print(f"❌ Keys differ:")
                print(f"   CLI:    {captured_key}")
                print(f"   Mobile: {mobile_key}")
                
                # Compare the raw bytes
                try:
                    cli_raw = base64.urlsafe_b64decode(captured_key)
                    mobile_raw = base64.urlsafe_b64decode(mobile_key)
                    
                    print(f"   CLI raw:    {cli_raw.hex()}")
                    print(f"   Mobile raw: {mobile_raw.hex()}")
                    
                    # Find first difference
                    for i in range(min(len(cli_raw), len(mobile_raw))):
                        if cli_raw[i] != mobile_raw[i]:
                            print(f"   First diff at byte {i}: CLI={cli_raw[i]:02x} vs Mobile={mobile_raw[i]:02x}")
                            break
                            
                except Exception as e:
                    print(f"   Raw comparison failed: {e}")
                
                return False
        else:
            print(f"❌ Failed to capture CLI key")
            return False
            
    except Exception as e:
        print(f"❌ Failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = get_full_cli_key()
    
    if success:
        print(f"\n🎉 Keys match - mobile implementation is correct!")
    else:
        print(f"\n🔍 Key difference found - need to investigate KDF process")