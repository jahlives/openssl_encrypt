#!/usr/bin/env python3
"""
Test Flutter AES-GCM integration
"""

import json
import base64
import subprocess
import sys

def test_flutter_aes_gcm():
    """Test the flutter_decrypt.py script with AES-GCM"""
    print("🧪 Testing Flutter AES-GCM Integration")
    print("=" * 50)
    
    # Read CLI AES-GCM test file
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_aes-gcm.txt"
    password = "1234"
    
    with open(test_file, 'r') as f:
        content = f.read().strip()
    
    # Parse CLI format
    metadata_b64, encrypted_data_b64 = content.split(':', 1)
    metadata_bytes = base64.b64decode(metadata_b64)
    metadata_json = metadata_bytes.decode()
    metadata = json.loads(metadata_json)
    
    # Create JSON for Flutter script
    encrypted_json = json.dumps({
        'encrypted_data': encrypted_data_b64,
        'metadata': metadata
    })
    
    print(f"🔑 Test parameters:")
    print(f"   Password: {password}")
    print(f"   Algorithm: {metadata.get('encryption', {}).get('algorithm')}")
    print(f"   Format version: {metadata.get('format_version')}")
    print(f"   JSON length: {len(encrypted_json)} chars")
    
    # Test the script
    try:
        result = subprocess.run(
            ['python3', 'flutter_decrypt.py', encrypted_json, password],
            capture_output=True,
            text=True,
            cwd='/home/work/private/git/openssl_encrypt/mobile_app/openssl_encrypt_mobile',
            timeout=10
        )
        
        print(f"\n📋 Script execution:")
        print(f"   Exit code: {result.returncode}")
        print(f"   STDOUT: '{result.stdout.strip()}'")
        if result.stderr:
            print(f"   STDERR: '{result.stderr.strip()}'")
        
        if result.returncode == 0 and not result.stdout.startswith('ERROR:'):
            output = result.stdout.strip()
            if output == "Hello World":
                print(f"✅ SUCCESS: Flutter AES-GCM decryption works perfectly!")
                return True
            else:
                print(f"❌ Unexpected output: '{output}' (expected 'Hello World')")
                return False
        else:
            print(f"❌ Script failed")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

if __name__ == "__main__":
    test_flutter_aes_gcm()