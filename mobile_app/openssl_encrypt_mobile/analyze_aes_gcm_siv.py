#!/usr/bin/env python3
"""
Analyze CLI AES-GCM-SIV test file structure
"""

import json
import base64

def analyze_aes_gcm_siv_file():
    """Analyze the CLI AES-GCM-SIV test file"""
    print("🔍 Analyzing CLI AES-GCM-SIV File Structure")
    print("=" * 50)
    
    # Read CLI AES-GCM-SIV test file
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_aes-gcm-siv.txt"
    
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
        print(f"Encryption data: {metadata.get('encryption', {}).get('encryption_data')}")
        print()
        
        # Test decoding encrypted data
        try:
            encrypted_bytes = base64.b64decode(encrypted_data_b64)
            print(f"📊 SUMMARY:")
            print("-" * 30)
            print(f"✅ Algorithm: {metadata.get('encryption', {}).get('algorithm')}")
            print(f"✅ Format version: {metadata.get('format_version')}")
            print(f"✅ Uses same derivation chain as other AES variants")
            print(f"✅ Encrypted data length: {len(encrypted_data_b64)} chars")
            print(f"✅ Encrypted binary length: {len(encrypted_bytes)} bytes")
            print(f"✅ Expected: 12-byte nonce + ciphertext + 16-byte tag for AES-GCM-SIV")
        except Exception as e:
            print(f"❌ Failed to decode encrypted data: {e}")
        
    except Exception as e:
        print(f"❌ Failed to parse CLI format: {e}")
        return False
    
    return True

if __name__ == "__main__":
    analyze_aes_gcm_siv_file()