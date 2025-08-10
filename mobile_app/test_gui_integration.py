#!/usr/bin/env python3
"""
Test the GUI integration with corrected mobile crypto core
"""

import json
import sys
import os

# Add the parent directory to Python path
sys.path.insert(0, '/home/work/private/git/openssl_encrypt/mobile_app')

def test_gui_subprocess():
    """Test the same subprocess call the GUI uses"""
    print("🧪 Testing GUI Subprocess Integration")
    print("=" * 60)
    
    # Read the test file that GUI would process
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
    password = "1234"
    
    with open(test_file, 'r') as f:
        content = f.read().strip()
    
    # Parse as GUI does
    if ':' in content and not content.startswith('{'):
        # CLI format: base64_metadata:base64_encrypted_data  
        parts = content.split(':', 1)
        metadata_b64, encrypted_data_b64 = parts
        
        # Decode metadata
        import base64
        metadata_bytes = base64.b64decode(metadata_b64)
        metadata_json = metadata_bytes.decode()
        metadata = json.loads(metadata_json)
        
        # Create the JSON structure that GUI passes to Python
        encrypted_json = json.dumps({
            'encrypted_data': encrypted_data_b64,
            'metadata': metadata
        })
        
        print(f"📋 Test parameters:")
        print(f"   Password: {password}")
        print(f"   Format version: {metadata.get('format_version')}")
        print(f"   Encrypted data length: {len(encrypted_data_b64)}")
        
        # Test direct import
        print(f"\n🐍 Testing Direct Python Import:")
        try:
            from mobile_crypto_core import MobileCryptoCore
            core = MobileCryptoCore()
            
            result = core.decrypt_text(encrypted_json, password)
            if result.startswith('ERROR:'):
                print(f"   ❌ Direct import failed: {result}")
            else:
                print(f"   ✅ Direct import success: '{result}'")
                
        except Exception as e:
            print(f"   ❌ Direct import exception: {e}")
            import traceback
            traceback.print_exc()
        
        # Test subprocess (like GUI does)
        print(f"\n⚙️ Testing Subprocess (GUI method):")
        
        import subprocess
        
        python_code = f'''
import sys
import json
sys.path.append('/home/work/private/git/openssl_encrypt/mobile_app')

# Try to import and use the mobile crypto core
try:
    from mobile_crypto_core import MobileCryptoCore
    core = MobileCryptoCore()
    
    # Parse input
    encrypted_json = """{encrypted_json}"""
    password = "{password}"
    
    # Decrypt
    result = core.decrypt_text(encrypted_json, password)
    print(result)
    
except Exception as e:
    print(f"ERROR: Python decryption failed: {{str(e)}}")
    import traceback
    traceback.print_exc()
'''
        
        try:
            result = subprocess.run(
                ['python3', '-c', python_code],
                capture_output=True,
                text=True,
                cwd='/home/work/private/git/openssl_encrypt/mobile_app',
                timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout.strip()
                if output.startswith('ERROR:'):
                    print(f"   ❌ Subprocess failed: {output}")
                else:
                    print(f"   ✅ Subprocess success: '{output}'")
            else:
                print(f"   ❌ Subprocess exit code {result.returncode}")
                print(f"   STDOUT: {result.stdout}")
                print(f"   STDERR: {result.stderr}")
                
        except Exception as e:
            print(f"   ❌ Subprocess exception: {e}")
    
    else:
        print(f"❌ Unexpected file format")

if __name__ == "__main__":
    test_gui_subprocess()