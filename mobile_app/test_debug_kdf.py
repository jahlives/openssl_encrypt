#!/usr/bin/env python3
"""
Test KDF configuration processing
"""

import base64
import json
from mobile_crypto_core import MobileCryptoCore

def test_kdf_processing():
    """Test how mobile processes CLI KDF configuration"""
    print("🧪 Testing KDF Configuration Processing")
    print("=" * 50)
    
    # Real CLI metadata from the file
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
    
    derivation_config = cli_metadata["derivation_config"]
    cli_kdf_config = derivation_config.get("kdf_config", {})
    
    print("🔍 CLI KDF Config Analysis:")
    for kdf_name, kdf_params in cli_kdf_config.items():
        print(f"   {kdf_name}: {kdf_params}")
        if "enabled" in kdf_params:
            print(f"      → enabled: {kdf_params['enabled']}")
        else:
            print(f"      → no 'enabled' field")
    
    # Test mobile processing
    core = MobileCryptoCore()
    kdf_config = core.default_kdf_config.copy()
    
    # Set all to disabled by default
    for kdf in kdf_config:
        kdf_config[kdf]["enabled"] = False
    
    print(f"\n🔧 Mobile Processing:")
    # Enable and configure KDFs found in metadata
    for kdf_name, kdf_params in cli_kdf_config.items():
        if kdf_name in kdf_config:
            # Check if this KDF should be enabled (CLI uses "enabled" field)
            if "enabled" in kdf_params:
                enabled = kdf_params["enabled"]
                reason = f"explicit enabled={enabled}"
            elif kdf_name == "pbkdf2":
                # PBKDF2 is enabled if rounds > 0 (CLI behavior)
                enabled = kdf_params.get("rounds", 0) > 0
                reason = f"pbkdf2 rounds={kdf_params.get('rounds', 0)} > 0"
            else:
                # Other KDFs: only enabled if explicitly marked as enabled
                enabled = False
                reason = "no enabled field, defaulting to False"
            
            print(f"   {kdf_name}: {enabled} ({reason})")
            kdf_config[kdf_name]["enabled"] = enabled
            
            # Update with CLI parameters (skip "enabled" field)
            for param, value in kdf_params.items():
                if param != "enabled":
                    kdf_config[kdf_name][param] = value
    
    print(f"\n📋 Final Mobile KDF Config:")
    for kdf_name, kdf_params in kdf_config.items():
        if kdf_params.get("enabled", False):
            print(f"   ✅ {kdf_name}: {kdf_params}")
        else:
            print(f"   ❌ {kdf_name}: disabled")
    
    # Expected result based on CLI metadata:
    # pbkdf2: enabled (rounds=10000)
    # scrypt: disabled (enabled=False)
    # argon2: enabled (enabled=True)
    # balloon: disabled (enabled=False)
    
    expected_enabled = ["pbkdf2", "argon2"]
    actual_enabled = [kdf for kdf, params in kdf_config.items() if params.get("enabled", False)]
    
    print(f"\n🎯 Validation:")
    print(f"   Expected enabled: {expected_enabled}")
    print(f"   Actual enabled:   {actual_enabled}")
    
    if set(expected_enabled) == set(actual_enabled):
        print("   ✅ KDF configuration matches CLI expectations!")
        return True
    else:
        print("   ❌ KDF configuration mismatch!")
        return False

if __name__ == "__main__":
    test_kdf_processing()