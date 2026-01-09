#!/usr/bin/env python3
"""
Test KDF Compatibility between CLI and Mobile
"""

import sys
import base64
import json
from mobile_crypto_core import MobileCryptoCore

def test_kdf_with_cli_config():
    """Test mobile KDF processing with CLI configuration"""
    print("🧪 Testing Mobile KDF with CLI Configuration")
    print("=" * 50)
    
    # CLI test vector from the file analysis
    cli_metadata = {
        "format_version": 5,
        "derivation_config": {
            "salt": "yTZN13xtVpwLzYCPl7TPWQ==",
            "hash_config": {
                "sha512": {"rounds": 0},
                "sha256": {"rounds": 0},
                "sha3_256": {"rounds": 0},
                "sha3_512": {"rounds": 0},
                "blake2b": {"rounds": 0},
                "shake256": {"rounds": 0},
                "whirlpool": {"rounds": 0}
            },
            "kdf_config": {
                "pbkdf2": {"rounds": 10000},
                "scrypt": {"enabled": False, "n": 128, "r": 8, "p": 1, "rounds": 1},
                "argon2": {"enabled": True, "time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 32, "type": 2, "rounds": 10},
                "balloon": {"enabled": False, "time_cost": 3, "space_cost": 65536, "parallelism": 4, "rounds": 2}
            }
        }
    }
    
    password = "1234"
    salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
    
    core = MobileCryptoCore()
    
    print(f"🔑 Testing Key Derivation:")
    print(f"   Password: {password}")
    print(f"   Salt: {salt.hex()}")
    
    try:
        # Extract configs
        derivation_config = cli_metadata["derivation_config"]
        cli_hash_config = derivation_config.get("hash_config", {})
        hash_config = {}
        for algo, config in cli_hash_config.items():
            if isinstance(config, dict) and "rounds" in config:
                hash_config[algo] = config["rounds"]
            else:
                hash_config[algo] = config if isinstance(config, int) else 0
        
        # Clean the hash config
        hash_config = core.clean_hash_config(hash_config)
        print(f"   Cleaned hash config: {hash_config}")
        
        # Extract KDF config
        cli_kdf_config = derivation_config.get("kdf_config", {})
        kdf_config = core.default_kdf_config.copy()
        
        # Set all to disabled by default
        for kdf in kdf_config:
            kdf_config[kdf]["enabled"] = False
        
        # Enable and configure KDFs found in metadata
        for kdf_name, kdf_params in cli_kdf_config.items():
            if kdf_name in kdf_config:
                # Check if this KDF should be enabled
                if "enabled" in kdf_params:
                    enabled = kdf_params["enabled"]
                else:
                    # CLI format: if KDF is present in metadata, it's enabled
                    enabled = True
                
                print(f"   KDF {kdf_name}: enabled={enabled}, params={kdf_params}")
                
                if enabled:
                    kdf_config[kdf_name]["enabled"] = True
                    # Update with CLI parameters
                    for param, value in kdf_params.items():
                        if param != "enabled":
                            kdf_config[kdf_name][param] = value
        
        print(f"   Final KDF config: {kdf_config}")
        
        # Test mobile key derivation
        derived_key = core._derive_key(password, salt, hash_config, kdf_config)
        print(f"✅ Mobile key derivation successful!")
        print(f"   Derived key: {derived_key[:32]}...")
        
        # Test with real CLI data
        encrypted_data_b64 = "gAAAAABnP5iyPnv9XCfrCYCrXPJjLNgAuYz1jkN7EJ0g8BM7EgSrqnQVOKMgLiGIhWNELEJYq-XdqYKIwwJD8VT9Cy8HdYZr8Rj4WL1aEw54PJkdFoNpJXcdE0FEFl1yZoXUgTnCKVLn4K4i8fDWxE="
        
        # Try mobile decrypt
        decrypt_result = core.decrypt_data(encrypted_data_b64, cli_metadata, password)
        
        if decrypt_result["success"]:
            print("✅ Mobile successfully decrypted CLI data!")
            print(f"   Decrypted: {decrypt_result['decrypted_data'][:50]}...")
            return True
        else:
            print(f"❌ Mobile decrypt failed: {decrypt_result['error']}")
            return False
            
    except Exception as e:
        print(f"❌ Mobile KDF test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_kdf_with_cli_config()