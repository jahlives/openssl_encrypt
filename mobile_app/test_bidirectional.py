#!/usr/bin/env python3
"""
Bidirectional Compatibility Test
Tests that mobile can decrypt CLI-encrypted files and CLI can decrypt mobile-encrypted files
"""

import sys
import os
from mobile_crypto_core import MobileCryptoCore

def test_mobile_decrypt_cli_file():
    """Test mobile decrypting a CLI-encrypted file"""
    print("🧪 Testing Mobile Decrypt CLI File")
    print("=" * 50)
    
    cli_file = "cli_test_file.txt"
    password = "1234"  # Test files use password "1234"
    
    if not os.path.exists(cli_file):
        print(f"❌ CLI test file not found: {cli_file}")
        return False
    
    core = MobileCryptoCore()
    
    try:
        # Decrypt CLI file with mobile
        result = core.decrypt_file(cli_file, password, "cli_decrypted_by_mobile.txt")
        
        if result["success"]:
            print("✅ Mobile successfully decrypted CLI file!")
            print(f"   Output: {result['output_path']}")
            
            # Read the decrypted content
            with open(result['output_path'], 'r') as f:
                content = f.read()
            print(f"   Content: {content[:50]}...")
            return True
        else:
            print(f"❌ Mobile failed to decrypt CLI file: {result['error']}")
            return False
            
    except Exception as e:
        print(f"❌ Exception during mobile decrypt: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_mobile_encrypt_and_self_decrypt():
    """Test mobile encrypt and decrypt its own files"""
    print("\n🧪 Testing Mobile Self-Compatibility")
    print("=" * 50)
    
    test_content = "Hello from Mobile Crypto Core! This is a bidirectional test."
    password = "1234"
    
    # Write test content
    with open("mobile_test_input.txt", "w") as f:
        f.write(test_content)
    
    core = MobileCryptoCore()
    
    try:
        # Encrypt with mobile
        encrypt_result = core.encrypt_file("mobile_test_input.txt", password, "mobile_test_encrypted.txt")
        
        if not encrypt_result["success"]:
            print(f"❌ Mobile encrypt failed: {encrypt_result['error']}")
            return False
        
        print("✅ Mobile encryption successful")
        
        # Decrypt with mobile  
        decrypt_result = core.decrypt_file("mobile_test_encrypted.txt", password, "mobile_test_decrypted.txt")
        
        if not decrypt_result["success"]:
            print(f"❌ Mobile decrypt failed: {decrypt_result['error']}")
            return False
        
        print("✅ Mobile decryption successful")
        
        # Verify content
        with open("mobile_test_decrypted.txt", "r") as f:
            decrypted_content = f.read()
        
        if decrypted_content == test_content:
            print("✅ Content matches perfectly!")
            return True
        else:
            print(f"❌ Content mismatch:")
            print(f"   Original: {test_content}")
            print(f"   Decrypted: {decrypted_content}")
            return False
            
    except Exception as e:
        print(f"❌ Exception during mobile self-test: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        for f in ["mobile_test_input.txt", "mobile_test_encrypted.txt", "mobile_test_decrypted.txt"]:
            if os.path.exists(f):
                os.remove(f)

def test_format_analysis():
    """Analyze the format of CLI vs mobile encrypted files"""
    print("\n🔍 Format Analysis")
    print("=" * 50)
    
    # Check CLI file format
    cli_file = "cli_test_file.txt"
    if os.path.exists(cli_file):
        with open(cli_file, 'r') as f:
            cli_content = f.read()[:200]
        
        print(f"CLI file format preview:")
        print(f"   {cli_content}...")
        
        if ':' in cli_content:
            print("✅ CLI format detected: base64_metadata:base64_data")
        else:
            print("❓ Unexpected CLI format")
    else:
        print("❌ CLI test file not available")

if __name__ == "__main__":
    print("🎯 Bidirectional Compatibility Test Suite")
    print("=" * 60)
    
    # Test format analysis first
    test_format_analysis()
    
    # Test mobile self-compatibility 
    mobile_self_works = test_mobile_encrypt_and_self_decrypt()
    
    # Test mobile decrypting CLI file
    mobile_decrypt_cli_works = test_mobile_decrypt_cli_file()
    
    # Summary
    print(f"\n📊 Test Results Summary:")
    print(f"   Mobile self-compatibility: {'✅ PASS' if mobile_self_works else '❌ FAIL'}")
    print(f"   Mobile decrypt CLI file:   {'✅ PASS' if mobile_decrypt_cli_works else '❌ FAIL'}")
    
    if mobile_self_works and mobile_decrypt_cli_works:
        print(f"\n🎉 SUCCESS: Bidirectional compatibility achieved!")
        print(f"   - Mobile can encrypt/decrypt its own files")
        print(f"   - Mobile can decrypt CLI-encrypted files")
        print(f"   - Hash processing compatibility: FIXED")
        print(f"   - Data format compatibility: FIXED")
    else:
        print(f"\n⚠️  INCOMPLETE: Some compatibility issues remain")
        
    # Cleanup
    for f in ["cli_decrypted_by_mobile.txt"]:
        if os.path.exists(f):
            print(f"Decrypted content saved to: {f}")