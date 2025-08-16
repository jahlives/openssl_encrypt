#!/usr/bin/env python3
"""
CLI Key Comparison Tool
Create a test file with CLI, extract the key derivation info, and compare with mobile
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
    print("✅ CLI modules imported successfully")
except ImportError as e:
    CLI_AVAILABLE = False
    print(f"❌ CLI modules not available: {e}")

def create_cli_test_vector():
    """Create a simple test vector using CLI with known parameters"""
    if not CLI_AVAILABLE:
        print("⚠️ CLI not available")
        return None
        
    print("🔬 Creating CLI Test Vector")
    print("=" * 40)
    
    # Simple test case - minimal parameters
    password = "testpassword123!"  # Use a stronger password to avoid validation issues
    test_content = "Hello World Test Content"
    
    # Create temporary files
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_input:
        tmp_input.write(test_content)
        input_file = tmp_input.name
    
    output_file = input_file + '.enc'
    
    try:
        print(f"🔑 Creating CLI test vector:")
        print(f"   Password: {password}")
        print(f"   Content: {test_content}")
        print(f"   Input: {input_file}")
        print(f"   Output: {output_file}")
        
        # Use CLI encrypt with simple parameters (no extra hash rounds)
        result = cli_encrypt_file(
            input_file=input_file,
            output_file=output_file,
            password=password.encode(),
            algorithm="fernet",
            quiet=True,
            # Use minimal hash configuration 
            hash_config={
                "sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0,
                "blake2b": 0, "shake256": 0, "whirlpool": 0
            }
        )
        
        if result and os.path.exists(output_file):
            print("✅ CLI encryption successful")
            
            # Read the encrypted file
            with open(output_file, 'r') as f:
                encrypted_content = f.read()
            
            if ':' in encrypted_content:
                metadata_b64, data_b64 = encrypted_content.split(':', 1)
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                metadata = json.loads(metadata_json)
                
                print(f"✅ CLI metadata parsed")
                print(f"   Format version: {metadata.get('format_version')}")
                
                # Extract derivation info
                derivation = metadata.get("derivation_config", {})
                salt = base64.b64decode(derivation["salt"]) if "salt" in derivation else None
                
                print(f"   Salt: {salt.hex() if salt else 'None'}")
                
                return {
                    "success": True,
                    "password": password,
                    "salt": salt,
                    "content": test_content,
                    "metadata": metadata,
                    "encrypted_data": data_b64,
                    "encrypted_file": output_file
                }
            else:
                print("❌ Unexpected CLI file format")
                return None
        else:
            print("❌ CLI encryption failed")
            return None
            
    except Exception as e:
        print(f"❌ CLI test vector creation failed: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        # Cleanup temporary files
        for f in [input_file, output_file]:
            if os.path.exists(f):
                os.unlink(f)

def test_mobile_with_cli_vector():
    """Test mobile decryption with CLI-generated test vector"""
    print("\n🔬 Testing Mobile with CLI Vector")
    print("=" * 40)
    
    cli_vector = create_cli_test_vector()
    if not cli_vector or not cli_vector.get("success"):
        print("⚠️ CLI vector not available")
        return False
    
    print(f"🔑 Testing mobile decryption:")
    print(f"   Password: {cli_vector['password']}")
    print(f"   Salt: {cli_vector['salt'].hex()}")
    
    # Test mobile decryption
    core = MobileCryptoCore()
    
    try:
        result = core.decrypt_data(
            cli_vector["encrypted_data"],
            cli_vector["metadata"],
            cli_vector["password"]
        )
        
        if result["success"]:
            decrypted = result["decrypted_data"]
            if isinstance(decrypted, bytes):
                decrypted = decrypted.decode('utf-8')
            
            print(f"🎉 SUCCESS: Mobile decrypted CLI data!")
            print(f"   Expected: {cli_vector['content']}")
            print(f"   Got:      {decrypted}")
            
            if decrypted == cli_vector['content']:
                print("✅ Content matches perfectly!")
                return True
            else:
                print("❌ Content mismatch!")
                return False
        else:
            print(f"❌ Mobile decryption failed: {result.get('error', 'Unknown')}")
            
            # Debug the key derivation step by step
            print(f"\n🔍 Debugging key derivation:")
            
            # Extract CLI metadata
            metadata = cli_vector["metadata"]
            derivation = metadata.get("derivation_config", {})
            salt = cli_vector["salt"]
            password = cli_vector["password"]
            
            # Debug hash processing
            cli_hash_config = derivation.get("hash_config", {})
            hash_config = {}
            for algo, config in cli_hash_config.items():
                if isinstance(config, dict) and "rounds" in config:
                    hash_config[algo] = config["rounds"]
                else:
                    hash_config[algo] = config if isinstance(config, int) else 0
            
            hash_config = core.clean_hash_config(hash_config)
            print(f"   Hash config: {hash_config}")
            
            # Test hash step
            mobile_hash = core.multi_hash_password(password.encode(), salt, hash_config)
            print(f"   Mobile hash: {mobile_hash.hex()}")
            
            # Test CLI hash for comparison
            if CLI_AVAILABLE:
                try:
                    cli_hash = cli_multi_hash_password(password.encode(), salt, hash_config, quiet=True)
                    print(f"   CLI hash:    {cli_hash.hex()}")
                    print(f"   Hash match:  {'✅' if mobile_hash == cli_hash else '❌'}")
                except Exception as e:
                    print(f"   CLI hash failed: {e}")
            
            # Debug KDF processing
            cli_kdf_config = derivation.get("kdf_config", {})
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
            
            print(f"   KDF config: {kdf_config}")
            
            # Test KDF step  
            try:
                mobile_kdf = core.multi_kdf_derive(mobile_hash, salt, kdf_config)
                print(f"   Mobile KDF: {mobile_kdf.hex()[:32]}...")
                
                # Test final key
                mobile_key = core._derive_key(password, salt, hash_config, kdf_config)
                print(f"   Mobile key: {mobile_key[:32]}...")
                
            except Exception as kdf_e:
                print(f"   Mobile KDF failed: {kdf_e}")
            
            return False
            
    except Exception as e:
        print(f"❌ Mobile test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🎯 CLI Key Comparison Suite")
    print("=" * 60)
    
    success = test_mobile_with_cli_vector()
    
    if success:
        print(f"\n🎉 SUCCESS: CLI-Mobile key derivation compatibility achieved!")
    else:
        print(f"\n❌ FAILED: CLI-Mobile key derivation issues remain")