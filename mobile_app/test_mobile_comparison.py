#!/usr/bin/env python3
"""
Mobile Comparison Tool
Extracts mobile key derivation intermediate values for comparison with CLI
"""

import sys
import os
import base64
import json
import hashlib

# Import mobile crypto
sys.path.append('.')
from mobile_crypto_core import MobileCryptoCore

def get_mobile_key_derivation_steps(password, salt, hash_config=None, kdf_config=None):
    """Extract mobile key derivation intermediate values"""
    
    try:
        password_str = password if isinstance(password, str) else password.decode()
        password_bytes = password.encode() if isinstance(password, str) else password
        
        print(f"🔍 Mobile Key Derivation Debug:")
        print(f"   Password: {password_str} -> {password_bytes}")
        print(f"   Salt: {salt.hex()}")
        
        core = MobileCryptoCore()
        
        # Default configs if not provided
        if hash_config is None:
            hash_config = {
                "sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0,
                "blake2b": 0, "shake256": 0, "whirlpool": 0
            }
        
        if kdf_config is None:
            kdf_config = {
                "pbkdf2": {"enabled": True, "rounds": 100000},
                "argon2": {"enabled": False},
                "scrypt": {"enabled": False},
                "hkdf": {"enabled": False},
                "balloon": {"enabled": False}
            }
        
        print(f"   Hash config: {hash_config}")
        print(f"   KDF config: {kdf_config}")
        
        # Step 1: Mobile multi-hash password
        print("   Step 1: Mobile hash processing...")
        step1_hashed = core.multi_hash_password(password_bytes, salt, hash_config)
        print(f"   -> Hash result: {step1_hashed[:20]}... (len: {len(step1_hashed)}, type: {type(step1_hashed)})")
        
        # Step 2: Mobile KDF derivation
        print("   Step 2: Mobile KDF processing...")
        step2_kdf_derived = core.multi_kdf_derive(step1_hashed, salt, kdf_config)
        print(f"   -> KDF result: {step2_kdf_derived[:20]}... (len: {len(step2_kdf_derived)}, type: {type(step2_kdf_derived)})")
        
        # Step 3: Mobile final key (via _derive_key)
        print("   Step 3: Mobile final key derivation...")
        step3_final_key = core._derive_key(password_str, salt, hash_config, kdf_config)
        print(f"   -> Final key: {step3_final_key[:32]}... (len: {len(step3_final_key)}, type: {type(step3_final_key)})")
        
        # Step 4: Test mobile encrypt/decrypt to see the full process
        print("   Step 4: Mobile full process test...")
        test_data = b"test content for mobile analysis"
        encrypt_result = core.encrypt_data(test_data, password_str, hash_config, kdf_config)
        
        if encrypt_result["success"]:
            print("   -> Mobile encrypt successful")
            metadata = encrypt_result["metadata"] 
            print(f"   -> Mobile metadata structure: {list(metadata.keys())}")
            
            # Test if mobile can decrypt its own data
            decrypt_result = core.decrypt_data(encrypt_result["encrypted_data"], metadata, password_str)
            if decrypt_result["success"]:
                print("   -> Mobile self-decrypt successful")
                step4_process = "MOBILE_SELF_SUCCESS"
            else:
                print(f"   -> Mobile self-decrypt failed: {decrypt_result.get('error')}")
                step4_process = "MOBILE_SELF_FAILED"
        else:
            print(f"   -> Mobile encrypt failed: {encrypt_result.get('error')}")
            step4_process = "MOBILE_ENCRYPT_FAILED"
        
        return {
            'success': True,
            'input_password': password_str,
            'input_salt': salt.hex(),
            'hash_config': hash_config,
            'kdf_config': kdf_config,
            'step1_after_hash': step1_hashed,
            'step1_hex': step1_hashed.hex() if hasattr(step1_hashed, 'hex') else step1_hashed,
            'step1_type': str(type(step1_hashed)),
            'step2_after_kdf': step2_kdf_derived,
            'step2_hex': step2_kdf_derived.hex() if hasattr(step2_kdf_derived, 'hex') else str(step2_kdf_derived),
            'step2_type': str(type(step2_kdf_derived)),
            'step3_final_key': step3_final_key,
            'step3_str': str(step3_final_key) if step3_final_key else None,
            'step3_type': str(type(step3_final_key)),
            'step4_process_result': step4_process,
            'mobile_metadata': metadata if encrypt_result["success"] else None
        }
        
    except Exception as e:
        print(f"❌ Mobile derivation failed: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

def test_mobile_comparison():
    """Test mobile comparison with simple cases"""
    print("🧪 Testing Mobile Comparison Tool")
    print("=" * 50)
    
    # Test case 1: Simple PBKDF2 only (no hash rounds) - match CLI test
    test_password = "1234"
    test_salt = b"test_salt_16byte"[:16]  # Same as CLI test
    
    hash_config = {
        "sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0,
        "blake2b": 0, "shake256": 0, "whirlpool": 0
    }
    
    kdf_config = {
        "pbkdf2": {"enabled": True, "rounds": 100000},
        "argon2": {"enabled": False},
        "scrypt": {"enabled": False}, 
        "hkdf": {"enabled": False},
        "balloon": {"enabled": False}
    }
    
    print(f"\nTest Case 1: No hash rounds, PBKDF2 only")
    result = get_mobile_key_derivation_steps(test_password, test_salt, hash_config, kdf_config)
    
    if result.get('success'):
        print("✅ Mobile comparison extraction successful")
        print(f"Hash result: {result['step1_hex'][:32]}...")
        print(f"KDF result: {result['step2_hex'][:32]}...")
        print(f"Final key: {result['step3_str'][:32]}...")
    else:
        print(f"❌ Mobile comparison extraction failed: {result.get('error')}")
    
    return result

def compare_with_cli_vectors():
    """Compare mobile results with CLI test vectors if available"""
    print("\n🎯 Comparing Mobile vs CLI Results")
    print("=" * 50)
    
    # Check if CLI test vectors exist
    if not os.path.exists('cli_test_vectors.json'):
        print("❌ CLI test vectors not found. Run test_cli_reference.py first.")
        return False
    
    # Load CLI test vectors
    with open('cli_test_vectors.json', 'r') as f:
        cli_vectors = json.load(f)
    
    print(f"Found {len(cli_vectors)} CLI test vectors")
    
    comparison_results = []
    
    for vector in cli_vectors:
        print(f"\n📋 Testing: {vector['test_name']}")
        
        # Get mobile results with same inputs
        password = vector['input']['password']
        salt = bytes.fromhex(vector['input']['salt'])
        hash_config = vector['input']['hash_config']
        
        kdf_config = {
            "pbkdf2": {"enabled": True, "rounds": 100000},
            "argon2": {"enabled": False},
            "scrypt": {"enabled": False},
            "hkdf": {"enabled": False},
            "balloon": {"enabled": False}
        }
        
        mobile_result = get_mobile_key_derivation_steps(password, salt, hash_config, kdf_config)
        
        if mobile_result.get('success'):
            # Compare results
            cli_hash = vector['cli_output']['hash_result']
            mobile_hash = mobile_result['step1_hex']
            
            hash_match = cli_hash == mobile_hash
            print(f"   Hash match: {'✅' if hash_match else '❌'}")
            
            if not hash_match:
                print(f"   CLI hash:    {cli_hash[:32]}...")
                print(f"   Mobile hash: {mobile_hash[:32]}...")
            
            comparison_results.append({
                'test_name': vector['test_name'],
                'hash_match': hash_match,
                'cli_hash': cli_hash,
                'mobile_hash': mobile_hash
            })
        else:
            print(f"   ❌ Mobile failed: {mobile_result.get('error')}")
            comparison_results.append({
                'test_name': vector['test_name'],
                'hash_match': False,
                'error': mobile_result.get('error')
            })
    
    # Save comparison results
    with open('mobile_cli_comparison.json', 'w') as f:
        json.dump(comparison_results, f, indent=2)
    
    # Summary
    matches = sum(1 for r in comparison_results if r.get('hash_match', False))
    total = len(comparison_results)
    print(f"\n📊 Comparison Summary: {matches}/{total} matches")
    
    if matches == total:
        print("🎉 Perfect match! CLI and mobile hash processing is identical.")
    else:
        print("⚠️ Differences found. This is the source of the compatibility issue.")
    
    return matches == total

if __name__ == "__main__":
    # Test mobile comparison
    result = test_mobile_comparison()
    
    if result.get('success'):
        # Compare with CLI vectors if available
        matches = compare_with_cli_vectors()
        
        if matches:
            print(f"\n🎉 Phase 1.2 Complete: Mobile comparison shows perfect CLI match")
        else:
            print(f"\n🔍 Phase 1.2 Complete: Mobile comparison reveals differences")
            print("This identifies the exact incompatibility source.")
    else:
        print("\n⚠️ Phase 1.2 Incomplete: Mobile comparison failed")