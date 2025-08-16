#!/usr/bin/env python3
"""
Manually create a CLI file and test mobile decryption
"""

import sys
import os
import tempfile
sys.path.insert(0, '../openssl_encrypt')

from mobile_crypto_core import MobileCryptoCore

# Try to create a simple CLI test file
try:
    from openssl_encrypt.modules.crypt_core import encrypt_file as cli_encrypt_file
    CLI_AVAILABLE = True
except ImportError:
    CLI_AVAILABLE = False

def create_simple_cli_file():
    """Create a simple CLI file with minimal parameters"""
    if not CLI_AVAILABLE:
        print("❌ CLI not available")
        return None
    
    print("🔧 Creating Simple CLI Test File")
    print("=" * 40)
    
    # Use a strong password to avoid validation issues
    password = "SuperSecurePassword123!"
    test_content = "Hello Mobile Test"
    
    # Create temporary files
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
        tmp.write(test_content)
        input_file = tmp.name
    
    output_file = input_file + '.enc'
    
    try:
        # Use CLI with minimal parameters
        print(f"🔑 Creating CLI file with:")
        print(f"   Content: {test_content}")
        print(f"   Password: {password}")
        
        # Try to encrypt with basic settings
        result = cli_encrypt_file(
            input_file=input_file,
            output_file=output_file,
            password=password.encode(),
            algorithm="fernet",
            quiet=True,
            # Try with minimal hash settings
            hash_config={
                "sha512": 0, "sha256": 0, "sha3_256": 0, "sha3_512": 0,
                "blake2b": 0, "shake256": 0, "whirlpool": 0
            },
            # Try to disable extra KDFs
            kdf_rounds=1  # Minimal KDF rounds
        )
        
        if result and os.path.exists(output_file):
            print("✅ CLI encryption successful")
            
            # Test mobile decryption immediately  
            core = MobileCryptoCore()
            mobile_result = core.decrypt_file(output_file, password, "mobile_test_output.txt")
            
            if mobile_result["success"]:
                print("🎉 SUCCESS: Mobile decrypted CLI file!")
                
                with open("mobile_test_output.txt", 'r') as f:
                    decrypted = f.read()
                print(f"   Original: '{test_content}'")
                print(f"   Decrypted: '{decrypted}'")
                
                if decrypted == test_content:
                    print("✅ Perfect match!")
                    return True
                else:
                    print("❌ Content mismatch")
            else:
                print(f"❌ Mobile decrypt failed: {mobile_result.get('error')}")
                
                # Analyze the file we just created
                import base64
                import json
                
                with open(output_file, 'r') as f:
                    content = f.read()
                
                if ':' in content:
                    metadata_b64, data_b64 = content.split(':', 1)
                    metadata = json.loads(base64.b64decode(metadata_b64).decode())
                    
                    print(f"🔍 CLI file analysis:")
                    print(f"   Format: {metadata.get('format_version')}")
                    derivation = metadata.get("derivation_config", {})
                    kdf_config = derivation.get("kdf_config", {})
                    
                    print(f"   KDFs used:")
                    for kdf, params in kdf_config.items():
                        print(f"      {kdf}: {params}")
                        
        else:
            print("❌ CLI encryption failed")
            
    except Exception as e:
        print(f"❌ CLI test failed: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        # Cleanup
        for f in [input_file, output_file, "mobile_test_output.txt"]:
            if os.path.exists(f):
                try:
                    os.unlink(f)
                except:
                    pass
                    
    return False

def test_with_unit_test_password():
    """Test if the unit test password is actually different"""
    print(f"\n🔍 Testing Unit Test File with Different Approaches")
    print("=" * 50)
    
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
    core = MobileCryptoCore()
    
    # The documentation says unit test files use password "1234"
    # But let me try a few variations
    test_passwords = [
        "1234",
        b"1234", 
        "test",
        "password",
        "Hello World",  # Maybe it's the content?
    ]
    
    for pwd in test_passwords:
        print(f"\n   🔑 Trying password: {repr(pwd)}")
        
        try:
            if isinstance(pwd, bytes):
                pwd_str = pwd.decode()
            else:
                pwd_str = str(pwd)
                
            result = core.decrypt_file(test_file, pwd_str, f"test_output_{pwd_str}.txt")
            
            if result["success"]:
                print(f"      🎉 SUCCESS with password: {repr(pwd)}")
                
                with open(f"test_output_{pwd_str}.txt", 'r') as f:
                    content = f.read()
                print(f"      Content: '{content}'")
                
                # Cleanup
                os.unlink(f"test_output_{pwd_str}.txt")
                return True
            else:
                print(f"      ❌ Failed: {result.get('error', 'Unknown')[:30]}...")
                
        except Exception as e:
            print(f"      ❌ Exception: {str(e)[:30]}...")
    
    return False

if __name__ == "__main__":
    print("🎯 Manual CLI Test Suite")
    print("=" * 50)
    
    # First try creating our own CLI file
    success1 = create_simple_cli_file()
    
    # Then try different passwords on the unit test file
    success2 = test_with_unit_test_password()
    
    if success1 or success2:
        print(f"\n🎉 SUCCESS: Found working configuration!")
    else:
        print(f"\n❌ CONTINUE: Still debugging compatibility")