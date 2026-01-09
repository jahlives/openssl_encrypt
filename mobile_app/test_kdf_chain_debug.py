#!/usr/bin/env python3
"""
KDF Chain Debug Tool
Compare CLI vs Mobile KDF processing step-by-step to identify exact differences
"""

import sys
import base64
import json
import hashlib
from typing import Dict, Any

# Add CLI modules
sys.path.insert(0, '../openssl_encrypt')

from mobile_crypto_core import MobileCryptoCore

try:
    from openssl_encrypt.modules.crypt_core import multi_kdf_derive as cli_multi_kdf_derive
    from openssl_encrypt.modules.crypt_core import multi_hash_password as cli_multi_hash_password
    CLI_AVAILABLE = True
    print("✅ CLI modules imported successfully")
except ImportError as e:
    CLI_AVAILABLE = False
    print(f"❌ CLI modules not available: {e}")

def debug_cli_kdf_chain():
    """Debug CLI KDF chain processing"""
    if not CLI_AVAILABLE:
        print("⚠️ CLI not available for comparison")
        return None
        
    print("🔬 CLI KDF Chain Debug")
    print("=" * 40)
    
    # Test parameters from real CLI file
    password = b"1234"
    salt = bytes.fromhex("c9364dd77c6d569c0bcd808f97b4cf59")
    
    # Hash config (all zeros - no hash processing)
    hash_config = {
        "sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0,
        "blake2b": 0, "shake256": 0, "whirlpool": 0
    }
    
    # KDF config from CLI file
    kdf_config = {
        "pbkdf2": {"rounds": 10000},
        "scrypt": {"enabled": False, "n": 128, "r": 8, "p": 1, "rounds": 1},
        "argon2": {"enabled": True, "time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 32, "type": 2, "rounds": 10},
        "balloon": {"enabled": False, "time_cost": 3, "space_cost": 65536, "parallelism": 4, "rounds": 2}
    }
    
    try:
        print(f"🔑 CLI Input:")
        print(f"   Password: {password}")
        print(f"   Salt: {salt.hex()}")
        
        # Step 1: CLI hash processing
        print(f"\n📝 Step 1: CLI Hash Processing")
        cli_hashed = cli_multi_hash_password(password, salt, hash_config, quiet=True)
        print(f"   Result: {cli_hashed.hex()} (len: {len(cli_hashed)}, type: {type(cli_hashed)})")
        
        # Step 2: CLI KDF processing
        print(f"\n📝 Step 2: CLI KDF Processing")
        
        # We need to manually call CLI KDF because the interface might be different
        # Let's try to understand how CLI processes KDFs
        print(f"   KDF Config: {kdf_config}")
        
        # For now, let's see what multi_kdf_derive expects
        try:
            cli_kdf_result = cli_multi_kdf_derive(cli_hashed, salt, kdf_config, quiet=True)
            print(f"   CLI KDF Result: {cli_kdf_result.hex()[:32]}... (len: {len(cli_kdf_result)})")
            return {
                "hash_result": cli_hashed,
                "kdf_result": cli_kdf_result,
                "success": True
            }
        except Exception as kdf_error:
            print(f"   ❌ CLI KDF failed: {kdf_error}")
            
            # Try alternative approach - maybe CLI has different KDF interface
            print(f"   🔄 Trying alternative CLI KDF approach...")
            
            # Let's check what CLI expects for KDF config format
            return {
                "hash_result": cli_hashed,
                "kdf_result": None,
                "kdf_error": str(kdf_error),
                "success": False
            }
            
    except Exception as e:
        print(f"❌ CLI KDF chain failed: {e}")
        import traceback
        traceback.print_exc()
        return {"success": False, "error": str(e)}

def debug_mobile_kdf_chain():
    """Debug Mobile KDF chain processing"""
    print("\n🔬 Mobile KDF Chain Debug")
    print("=" * 40)
    
    # Same parameters as CLI
    password = "1234"
    password_bytes = password.encode()
    salt = bytes.fromhex("c9364dd77c6d569c0bcd808f97b4cf59")
    
    # Hash config (all zeros - no hash processing)
    hash_config = {
        "sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0,
        "blake2b": 0, "shake256": 0, "whirlpool": 0
    }
    
    # Mobile KDF config (processed from CLI format)
    mobile_kdf_config = {
        "pbkdf2": {"enabled": True, "rounds": 10000},
        "scrypt": {"enabled": False, "n": 128, "r": 8, "p": 1, "rounds": 1},
        "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4, "rounds": 10, "hash_len": 32, "type": 2},
        "hkdf": {"enabled": False, "info": "OpenSSL_Encrypt_Mobile"},
        "balloon": {"enabled": False, "time_cost": 3, "space_cost": 65536, "parallelism": 4, "rounds": 2}
    }
    
    core = MobileCryptoCore()
    
    try:
        print(f"🔑 Mobile Input:")
        print(f"   Password: {password_bytes}")
        print(f"   Salt: {salt.hex()}")
        
        # Step 1: Mobile hash processing
        print(f"\n📝 Step 1: Mobile Hash Processing")
        mobile_hashed = core.multi_hash_password(password_bytes, salt, hash_config)
        print(f"   Result: {mobile_hashed.hex()} (len: {len(mobile_hashed)}, type: {type(mobile_hashed)})")
        
        # Step 2: Mobile KDF processing
        print(f"\n📝 Step 2: Mobile KDF Processing")
        print(f"   KDF Config: {mobile_kdf_config}")
        
        mobile_kdf_result = core.multi_kdf_derive(mobile_hashed, salt, mobile_kdf_config)
        print(f"   Mobile KDF Result: {mobile_kdf_result.hex()[:32]}... (len: {len(mobile_kdf_result)})")
        
        # Step 3: Mobile final key (base64 encoding)
        print(f"\n📝 Step 3: Mobile Final Key")
        mobile_final_key = core._derive_key(password, salt, hash_config, mobile_kdf_config)
        print(f"   Mobile Final Key: {mobile_final_key[:32]}... (len: {len(mobile_final_key)})")
        
        return {
            "hash_result": mobile_hashed,
            "kdf_result": mobile_kdf_result,
            "final_key": mobile_final_key,
            "success": True
        }
        
    except Exception as e:
        print(f"❌ Mobile KDF chain failed: {e}")
        import traceback
        traceback.print_exc()
        return {"success": False, "error": str(e)}

def compare_kdf_chains():
    """Compare CLI vs Mobile KDF chain results"""
    print("\n🎯 KDF Chain Comparison")
    print("=" * 50)
    
    cli_result = debug_cli_kdf_chain()
    mobile_result = debug_mobile_kdf_chain()
    
    if not cli_result or not cli_result.get("success"):
        print("⚠️ CLI results not available for comparison")
        return
        
    if not mobile_result or not mobile_result.get("success"):
        print("❌ Mobile KDF chain failed")
        return
    
    # Compare hash results
    print(f"\n📋 Hash Processing Comparison:")
    cli_hash = cli_result["hash_result"]
    mobile_hash = mobile_result["hash_result"]
    
    print(f"   CLI:    {cli_hash.hex()}")
    print(f"   Mobile: {mobile_hash.hex()}")
    
    hash_match = cli_hash == mobile_hash
    print(f"   Match: {'✅' if hash_match else '❌'}")
    
    # Compare KDF results if available
    if cli_result.get("kdf_result") and mobile_result.get("kdf_result"):
        print(f"\n📋 KDF Processing Comparison:")
        cli_kdf = cli_result["kdf_result"]
        mobile_kdf = mobile_result["kdf_result"]
        
        print(f"   CLI KDF:    {cli_kdf.hex()[:32]}...")
        print(f"   Mobile KDF: {mobile_kdf.hex()[:32]}...")
        
        kdf_match = cli_kdf == mobile_kdf
        print(f"   Match: {'✅' if kdf_match else '❌'}")
        
        if not kdf_match:
            print(f"\n🔍 KDF Difference Analysis:")
            print(f"   CLI length:    {len(cli_kdf)}")
            print(f"   Mobile length: {len(mobile_kdf)}")
            
            # Find first difference
            min_len = min(len(cli_kdf), len(mobile_kdf))
            for i in range(min_len):
                if cli_kdf[i] != mobile_kdf[i]:
                    print(f"   First diff at byte {i}: CLI={cli_kdf[i]:02x} vs Mobile={mobile_kdf[i]:02x}")
                    break
    else:
        print(f"\n⚠️ KDF results comparison not possible:")
        if not cli_result.get("kdf_result"):
            print(f"   CLI KDF error: {cli_result.get('kdf_error', 'Unknown')}")

def debug_individual_kdfs():
    """Debug individual KDF implementations"""
    print("\n🔬 Individual KDF Debug")
    print("=" * 40)
    
    # Test input (post-hash)
    input_data = bytes.fromhex("31323334c9364dd77c6d569c0bcd808f97b4cf59")  # "1234" + salt
    salt = bytes.fromhex("c9364dd77c6d569c0bcd808f97b4cf59")
    
    print(f"🔑 KDF Input: {input_data.hex()}")
    print(f"   Salt: {salt.hex()}")
    
    core = MobileCryptoCore()
    
    # Test PBKDF2 only
    print(f"\n📝 PBKDF2 Test:")
    pbkdf2_config = {
        "pbkdf2": {"enabled": True, "rounds": 10000},
        "scrypt": {"enabled": False},
        "argon2": {"enabled": False},
        "hkdf": {"enabled": False},
        "balloon": {"enabled": False}
    }
    
    try:
        pbkdf2_result = core.multi_kdf_derive(input_data, salt, pbkdf2_config)
        print(f"   PBKDF2 result: {pbkdf2_result.hex()[:32]}... (len: {len(pbkdf2_result)})")
    except Exception as e:
        print(f"   PBKDF2 failed: {e}")
    
    # Test Argon2 only  
    print(f"\n📝 Argon2 Test:")
    argon2_config = {
        "pbkdf2": {"enabled": False},
        "scrypt": {"enabled": False},
        "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4, "rounds": 10, "hash_len": 32, "type": 2},
        "hkdf": {"enabled": False},
        "balloon": {"enabled": False}
    }
    
    try:
        argon2_result = core.multi_kdf_derive(input_data, salt, argon2_config)
        print(f"   Argon2 result: {argon2_result.hex()[:32]}... (len: {len(argon2_result)})")
    except Exception as e:
        print(f"   Argon2 failed: {e}")
        
    # Test combined (CLI order: Argon2 → PBKDF2)
    print(f"\n📝 Combined Test (Argon2 → PBKDF2):")
    combined_config = {
        "pbkdf2": {"enabled": True, "rounds": 10000},
        "scrypt": {"enabled": False},
        "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4, "rounds": 10, "hash_len": 32, "type": 2},
        "hkdf": {"enabled": False},
        "balloon": {"enabled": False}
    }
    
    try:
        combined_result = core.multi_kdf_derive(input_data, salt, combined_config)
        print(f"   Combined result: {combined_result.hex()[:32]}... (len: {len(combined_result)})")
    except Exception as e:
        print(f"   Combined failed: {e}")

if __name__ == "__main__":
    print("🎯 KDF Chain Debug Suite")
    print("=" * 60)
    
    # Run comprehensive KDF debugging
    compare_kdf_chains()
    debug_individual_kdfs()
    
    print(f"\n🎉 KDF Chain Debug Complete")
    print("This will help identify the exact KDF processing differences between CLI and mobile.")