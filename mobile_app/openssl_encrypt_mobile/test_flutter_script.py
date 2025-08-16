#!/usr/bin/env python3
"""
Test the Flutter Python script with CLI file
"""

import json
import base64
import subprocess
import sys

def test_flutter_script():
    """Test the flutter_decrypt.py script"""
    print("🧪 Testing Flutter Python Script")
    print("=" * 50)
    
    # Read CLI test file
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
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
                print(f"✅ SUCCESS: Flutter script works perfectly!")
                return True
            else:
                print(f"❌ Unexpected output: '{output}'")
                return False
        else:
            print(f"❌ Script failed")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

if __name__ == "__main__":
    test_flutter_script()