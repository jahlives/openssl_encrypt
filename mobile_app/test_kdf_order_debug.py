#!/usr/bin/env python3
"""
Debug KDF Order and Processing
Check if mobile KDF chain order matches CLI order
"""

import sys
import os
import base64
import json
import tempfile

# Add CLI modules
sys.path.insert(0, '../openssl_encrypt')

from mobile_crypto_core import MobileCryptoCore

try:
    from openssl_encrypt.modules.crypt_core import encrypt_file as cli_encrypt_file, multi_hash_password as cli_multi_hash_password
    CLI_AVAILABLE = True
except ImportError as e:
    CLI_AVAILABLE = False
    print(f"❌ CLI not available: {e}")

def examine_cli_kdf_config():
    """Create a CLI file and examine its exact KDF configuration"""
    if not CLI_AVAILABLE:
        return None
        
    print("🔬 Examining CLI KDF Configuration")
    print("=" * 40)
    
    password = "testpassword123!"
    test_content = "test"
    
    # Create temp files
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
        tmp.write(test_content)
        input_file = tmp.name
    
    output_file = input_file + '.enc'
    
    try:
        # Create CLI file with default settings
        result = cli_encrypt_file(
            input_file=input_file,
            output_file=output_file,
            password=password.encode(),
            algorithm="fernet",
            quiet=True
        )
        
        if result and os.path.exists(output_file):
            # Parse CLI metadata
            with open(output_file, 'r') as f:
                encrypted_content = f.read()
            
            metadata_b64, data_b64 = encrypted_content.split(':', 1)
            metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
            metadata = json.loads(metadata_json)
            
            print(f"✅ CLI file created and parsed")
            
            # Examine the actual KDF config CLI created
            derivation = metadata.get("derivation_config", {})
            cli_kdf_config = derivation.get("kdf_config", {})
            
            print(f"\n📋 CLI KDF Configuration:")
            for kdf_name, kdf_params in cli_kdf_config.items():
                print(f"   {kdf_name}: {kdf_params}")
            
            return {
                "metadata": metadata,
                "kdf_config": cli_kdf_config,
                "password": password,
                "salt": base64.b64decode(derivation["salt"]),
                "encrypted_data": data_b64,
                "test_content": test_content
            }
        else:
            print("❌ CLI encryption failed")
            return None
            
    except Exception as e:
        print(f"❌ CLI examination failed: {e}")
        return None
    finally:
        for f in [input_file, output_file]:
            if os.path.exists(f):
                os.unlink(f)

def test_mobile_kdf_order():
    """Test mobile KDF processing order"""
    cli_info = examine_cli_kdf_config()
    if not cli_info:
        print("⚠️ CLI info not available")
        return
        
    print(f"\n🔬 Testing Mobile KDF Order")
    print("=" * 40)
    
    core = MobileCryptoCore()
    
    # Extract parameters
    password = cli_info["password"]
    salt = cli_info["salt"]
    cli_kdf_config = cli_info["kdf_config"]
    
    print(f"🔑 Test parameters:")
    print(f"   Password: {password}")
    print(f"   Salt: {salt.hex()}")
    
    # Process CLI KDF config through mobile logic
    kdf_config = core.default_kdf_config.copy()
    
    # Disable all first
    for kdf in kdf_config:
        kdf_config[kdf]["enabled"] = False
    
    # Enable based on CLI config
    print(f"\n📝 KDF Processing:")
    for kdf_name, kdf_params in cli_kdf_config.items():
        if kdf_name in kdf_config:
            if "enabled" in kdf_params:
                enabled = kdf_params["enabled"]
            elif kdf_name == "pbkdf2":
                enabled = kdf_params.get("rounds", 0) > 0
            else:
                enabled = False
            
            print(f"   {kdf_name}: enabled={enabled}, params={kdf_params}")
            kdf_config[kdf_name]["enabled"] = enabled
            
            for param, value in kdf_params.items():
                if param != "enabled":
                    kdf_config[kdf_name][param] = value
    
    print(f"\n📋 Final Mobile KDF Config:")
    for kdf_name, kdf_params in kdf_config.items():
        if kdf_params.get("enabled"):
            print(f"   ✅ {kdf_name}: {kdf_params}")
    
    # Test the KDF chain step by step
    print(f"\n🔍 KDF Chain Processing:")
    
    # Start with hashed password (no hash rounds)
    password_bytes = password.encode()
    hashed_input = password_bytes + salt  # CLI behavior for zero hash rounds
    print(f"   Input to KDF: {hashed_input.hex()}")
    
    # Test mobile KDF chain  
    try:
        kdf_result = core.multi_kdf_derive(hashed_input, salt, kdf_config)
        print(f"   Mobile KDF result: {kdf_result.hex()[:32]}...")
        
        # Test final key encoding
        final_key = base64.urlsafe_b64encode(kdf_result)
        print(f"   Mobile final key: {final_key[:32]}...")
        
        # Test decryption with mobile key
        from cryptography.fernet import Fernet
        
        try:
            f = Fernet(final_key)
            encrypted_data = base64.b64decode(cli_info["encrypted_data"])
            decrypted = f.decrypt(encrypted_data)
            decrypted_text = decrypted.decode('utf-8')
            
            print(f"🎉 SUCCESS: Mobile key works with CLI data!")
            print(f"   Decrypted: '{decrypted_text}'")
            print(f"   Expected:  '{cli_info['test_content']}'")
            
            if decrypted_text == cli_info["test_content"]:
                print("✅ Perfect match!")
                return True
            else:
                print("❌ Content mismatch")
                
        except Exception as decrypt_e:
            print(f"❌ Decryption with mobile key failed: {decrypt_e}")
            
    except Exception as e:
        print(f"❌ Mobile KDF chain failed: {e}")
        import traceback
        traceback.print_exc()
    
    return False

def debug_mobile_kdf_order():
    """Debug the mobile KDF processing order"""
    print(f"\n🔬 Mobile KDF Order Analysis")
    print("=" * 40)
    
    # Check mobile KDF order from code
    core = MobileCryptoCore()
    
    print("📋 Mobile KDF Order (from multi_kdf_derive):")
    print("   1. Argon2 (if enabled)")
    print("   2. Balloon (if enabled)")  
    print("   3. Scrypt (if enabled)")
    print("   4. HKDF (if enabled)")
    print("   5. PBKDF2 (if enabled)")
    
    print(f"\n📋 CLI Expected Order:")
    print("   Based on CLI code, the order should be:")
    print("   1. Argon2 → 2. Balloon → 3. Scrypt → 4. HKDF → 5. PBKDF2")
    
    # Test with a simple case
    test_input = b"test_input_data"
    test_salt = b"test_salt_16byte"
    
    # Test individual KDFs to understand the chain
    configs = [
        {"name": "PBKDF2 only", "config": {
            "pbkdf2": {"enabled": True, "rounds": 100000},
            "argon2": {"enabled": False},
            "scrypt": {"enabled": False},
            "hkdf": {"enabled": False},
            "balloon": {"enabled": False}
        }},
        {"name": "Argon2 only", "config": {
            "pbkdf2": {"enabled": False},
            "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 1, "rounds": 1},
            "scrypt": {"enabled": False},
            "hkdf": {"enabled": False},
            "balloon": {"enabled": False}
        }},
        {"name": "Argon2 → PBKDF2", "config": {
            "pbkdf2": {"enabled": True, "rounds": 100000},
            "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 1, "rounds": 1},
            "scrypt": {"enabled": False},
            "hkdf": {"enabled": False},
            "balloon": {"enabled": False}
        }}
    ]
    
    print(f"\n🧪 KDF Chain Tests:")
    for config in configs:
        try:
            result = core.multi_kdf_derive(test_input, test_salt, config["config"])
            print(f"   {config['name']}: {result.hex()[:20]}...")
        except Exception as e:
            print(f"   {config['name']}: FAILED - {e}")

if __name__ == "__main__":
    print("🎯 KDF Order Debug Suite")
    print("=" * 60)
    
    success = test_mobile_kdf_order()
    debug_mobile_kdf_order()
    
    if success:
        print(f"\n🎉 SUCCESS: KDF order compatibility achieved!")
    else:
        print(f"\n❌ CONTINUE: KDF order issues identified for fixing")