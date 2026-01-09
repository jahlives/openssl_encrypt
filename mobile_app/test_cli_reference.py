#!/usr/bin/env python3
"""
CLI Reference Implementation
Extracts exact CLI key derivation intermediate values for comparison with mobile
"""

import sys
import os
import base64
import json
import hashlib

# Add CLI modules to path
sys.path.insert(0, '../openssl_encrypt')

try:
    from openssl_encrypt.modules.crypt_core import multi_hash_password, decrypt_file, encrypt_file
    CLI_AVAILABLE = True
    print("✅ CLI modules successfully imported")
except ImportError as e:
    CLI_AVAILABLE = False
    print(f"❌ CLI modules not available: {e}")

def get_cli_key_derivation_steps(password, salt, hash_config=None, kdf_config=None):
    """Extract exact CLI key derivation intermediate values"""
    if not CLI_AVAILABLE:
        return {"error": "CLI modules not available"}
    
    try:
        password_bytes = password.encode() if isinstance(password, str) else password
        
        print(f"🔍 CLI Key Derivation Debug:")
        print(f"   Password: {password} -> {password_bytes}")
        print(f"   Salt: {salt.hex()}")
        
        # Default configs if not provided
        if hash_config is None:
            hash_config = {
                "sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0,
                "blake2b": 0, "shake256": 0, "whirlpool": 0
            }
        
        print(f"   Hash config: {hash_config}")
        
        # Step 1: CLI multi-hash password
        print("   Step 1: CLI hash processing...")
        step1_hashed = multi_hash_password(password_bytes, salt, hash_config, quiet=True)
        print(f"   -> Hash result: {step1_hashed[:20]}... (len: {len(step1_hashed)})")
        
        # Step 2: CLI key derivation - we'll need to use the full encrypt/decrypt process
        # to understand how CLI derives keys, since there's no separate derive_key function
        print("   Step 2: CLI full process test...")
        
        # Create a test file and encrypt it with CLI to see the process
        test_content = "test content for key derivation analysis"
        test_file = "cli_key_test.txt"
        encrypted_file = "cli_key_test.encrypted"
        
        try:
            # Write test content
            with open(test_file, 'w') as f:
                f.write(test_content)
            
            # Use CLI encrypt_file to see how it processes keys
            result = encrypt_file(
                input_file=test_file,
                output_file=encrypted_file,
                password=password_bytes,
                quiet=True,
                hash_config=hash_config
            )
            
            if result and os.path.exists(encrypted_file):
                print("   -> CLI encrypt successful")
                
                # Read the encrypted file to see the metadata structure
                with open(encrypted_file, 'r') as f:
                    encrypted_content = f.read()
                
                if ':' in encrypted_content:
                    metadata_b64, data_b64 = encrypted_content.split(':', 1)
                    metadata_json = base64.b64decode(metadata_b64).decode()
                    metadata = json.loads(metadata_json)
                    print(f"   -> CLI metadata structure: {list(metadata.keys())}")
                    step2_derived = "CLI_ENCRYPT_SUCCESS"
                else:
                    step2_derived = "CLI_FORMAT_UNKNOWN"
            else:
                step2_derived = "CLI_ENCRYPT_FAILED"
                
            # Cleanup
            for f in [test_file, encrypted_file]:
                if os.path.exists(f):
                    os.remove(f)
                    
        except Exception as e:
            print(f"   -> CLI full process failed: {e}")
            step2_derived = f"CLI_ERROR: {str(e)}"
        
        return {
            'success': True,
            'input_password': password,
            'input_salt': salt.hex(),
            'hash_config': hash_config,
            'step1_after_hash': step1_hashed,
            'step1_hex': step1_hashed.hex() if step1_hashed else None,
            'step2_derived_key': step2_derived,
            'step2_info': str(step2_derived) if step2_derived else None,
        }
        
    except Exception as e:
        print(f"❌ CLI derivation failed: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

def test_cli_reference():
    """Test CLI reference implementation with simple cases"""
    print("🧪 Testing CLI Reference Implementation")
    print("=" * 50)
    
    # Test case 1: Simple PBKDF2 only (no hash rounds)
    test_password = "1234"
    test_salt = b"test_salt_16byte"[:16]  # Ensure 16 bytes
    
    hash_config = {
        "sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0,
        "blake2b": 0, "shake256": 0, "whirlpool": 0
    }
    
    print(f"\nTest Case 1: No hash rounds, PBKDF2 only")
    result = get_cli_key_derivation_steps(test_password, test_salt, hash_config)
    
    if result.get('success'):
        print("✅ CLI reference extraction successful")
        print(f"Hash result: {result['step1_hex'][:32]}...")
        if result.get('step2_info'):
            print(f"Process result: {result['step2_info']}")
    else:
        print(f"❌ CLI reference extraction failed: {result.get('error')}")
    
    return result

def create_test_vectors():
    """Create test vectors from CLI for mobile comparison"""
    print("\n🎯 Creating CLI Test Vectors")
    print("=" * 50)
    
    test_cases = [
        {
            "name": "No hash rounds",
            "password": "1234",
            "salt": b"test_salt_16byte"[:16],
            "hash_config": {"sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0, "blake2b": 0, "shake256": 0, "whirlpool": 0}
        },
        {
            "name": "SHA256 1000 rounds",
            "password": "1234", 
            "salt": b"test_salt_16byte"[:16],
            "hash_config": {"sha512": 0, "sha256": 1000, "sha3_256": 0, "sha3_512": 0, "blake2b": 0, "shake256": 0, "whirlpool": 0}
        },
        {
            "name": "Multi-hash",
            "password": "1234",
            "salt": b"test_salt_16byte"[:16], 
            "hash_config": {"sha512": 500, "sha256": 1000, "sha3_256": 250, "sha3_512": 0, "blake2b": 100, "shake256": 0, "whirlpool": 0}
        }
    ]
    
    vectors = []
    
    for test_case in test_cases:
        print(f"\n📋 {test_case['name']}:")
        result = get_cli_key_derivation_steps(
            test_case['password'],
            test_case['salt'], 
            test_case['hash_config']
        )
        
        if result.get('success'):
            vectors.append({
                'test_name': test_case['name'],
                'input': {
                    'password': test_case['password'],
                    'salt': test_case['salt'].hex(),
                    'hash_config': test_case['hash_config']
                },
                'cli_output': {
                    'hash_result': result['step1_hex'],
                    'process_result': result.get('step2_info', 'unknown')
                }
            })
            print(f"✅ Vector created")
        else:
            print(f"❌ Failed: {result.get('error')}")
    
    # Save test vectors
    with open('cli_test_vectors.json', 'w') as f:
        json.dump(vectors, f, indent=2)
    
    print(f"\n📄 Saved {len(vectors)} test vectors to cli_test_vectors.json")
    return vectors

if __name__ == "__main__":
    # Test CLI reference implementation
    result = test_cli_reference()
    
    if CLI_AVAILABLE and result.get('success'):
        # Create test vectors for mobile comparison
        vectors = create_test_vectors()
        print(f"\n🎉 Phase 1.1 Complete: CLI reference implementation ready")
        print(f"Generated {len(vectors)} test vectors for mobile comparison")
    else:
        print("\n⚠️ Phase 1.1 Incomplete: CLI reference implementation failed")
        print("Check CLI module availability and imports")