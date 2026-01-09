#!/usr/bin/env python3
"""
Analyze CLI AES-GCM test file structure
"""

import json
import base64

def analyze_aes_gcm_file():
    """Analyze the CLI AES-GCM test file"""
    print("🔍 Analyzing CLI AES-GCM File Structure")
    print("=" * 50)
    
    # Read CLI AES-GCM test file
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_aes-gcm.txt"
    
    with open(test_file, 'r') as f:
        content = f.read().strip()
    
    print(f"📄 Raw file content length: {len(content)} chars")
    print(f"📄 First 100 chars: {content[:100]}...")
    print()
    
    # Parse CLI format (base64_metadata:base64_encrypted_data)
    try:
        metadata_b64, encrypted_data_b64 = content.split(':', 1)
        print(f"📋 Metadata base64 length: {len(metadata_b64)} chars")
        print(f"🔒 Encrypted data base64 length: {len(encrypted_data_b64)} chars")
        print()
        
        # Decode metadata
        metadata_bytes = base64.b64decode(metadata_b64)
        metadata_json = metadata_bytes.decode('utf-8')
        metadata = json.loads(metadata_json)
        
        print("📋 METADATA ANALYSIS:")
        print("-" * 30)
        print(f"Format version: {metadata.get('format_version')}")
        print(f"Algorithm: {metadata.get('encryption', {}).get('algorithm')}")
        print()
        
        # Analyze derivation config
        derivation = metadata.get('derivation_config', {})
        print("🔑 DERIVATION CONFIG:")
        print("-" * 30)
        print(f"Salt (base64): {derivation.get('salt', 'N/A')[:50]}...")
        
        # Hash config
        hash_config = derivation.get('hash_config', {})
        print(f"\n🏷️  Hash config algorithms:")
        for algo, config in hash_config.items():
            if isinstance(config, dict):
                rounds = config.get('rounds', 0)
                print(f"  {algo}: {rounds} rounds")
            else:
                print(f"  {algo}: {config}")
        
        # KDF config  
        kdf_config = derivation.get('kdf_config', {})
        print(f"\n🔧 KDF config:")
        for kdf_name, kdf_params in kdf_config.items():
            if isinstance(kdf_params, dict):
                enabled = kdf_params.get('enabled', 'Not specified')
                print(f"  {kdf_name}:")
                print(f"    enabled: {enabled}")
                for param, value in kdf_params.items():
                    if param != 'enabled':
                        print(f"    {param}: {value}")
            else:
                print(f"  {kdf_name}: {kdf_params}")
        
        # Encryption details
        encryption = metadata.get('encryption', {})
        print(f"\n🔒 ENCRYPTION CONFIG:")
        print("-" * 30)
        for key, value in encryption.items():
            print(f"  {key}: {value}")
        
        # Hashes (integrity)
        hashes = metadata.get('hashes', {})
        print(f"\n#️⃣  INTEGRITY HASHES:")
        print("-" * 30)
        for hash_type, hash_value in hashes.items():
            print(f"  {hash_type}: {hash_value[:40]}...")
        
        print(f"\n📊 SUMMARY:")
        print("-" * 30)
        print(f"✅ Algorithm: {encryption.get('algorithm', 'unknown')}")
        print(f"✅ Format version: {metadata.get('format_version')}")
        print(f"✅ Uses same derivation chain as Fernet (hash+KDF)")
        print(f"✅ Encrypted data length: {len(encrypted_data_b64)} chars")
        print(f"✅ Salt available: {'Yes' if derivation.get('salt') else 'No'}")
        
        # Test decoding encrypted data
        try:
            encrypted_bytes = base64.b64decode(encrypted_data_b64)
            print(f"✅ Encrypted binary length: {len(encrypted_bytes)} bytes")
        except Exception as e:
            print(f"❌ Failed to decode encrypted data: {e}")
        
    except Exception as e:
        print(f"❌ Failed to parse CLI format: {e}")
        return False
    
    return True

if __name__ == "__main__":
    analyze_aes_gcm_file()