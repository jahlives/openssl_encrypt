#!/usr/bin/env python3
"""
Test AES-OCB3 CLI-Mobile compatibility
"""

import json
import base64
from mobile_crypto_core import MobileCryptoCore

def test_aes_ocb3_cli_decryption():
    """Test decrypting CLI AES-OCB3 file with mobile crypto"""
    print("🧪 Testing AES-OCB3 CLI-Mobile Decryption")
    print("=" * 50)
    
    # Read CLI AES-OCB3 test file
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_aes-ocb3.txt"
    password = "1234"
    
    with open(test_file, 'r') as f:
        content = f.read().strip()
    
    # Parse CLI format
    metadata_b64, encrypted_data_b64 = content.split(':', 1)
    metadata_bytes = base64.b64decode(metadata_b64)
    metadata_json = metadata_bytes.decode()
    metadata = json.loads(metadata_json)
    
    print(f"📄 Test parameters:")
    print(f"   Password: {password}")
    print(f"   Algorithm: {metadata.get('encryption', {}).get('algorithm')}")
    print(f"   Format version: {metadata.get('format_version')}")
    print(f"   Encrypted data length: {len(encrypted_data_b64)} chars")
    print()
    
    # Test mobile decryption
    crypto = MobileCryptoCore()
    result = crypto.decrypt_data(encrypted_data_b64, metadata, password)
    
    print(f"🔓 Mobile decryption result:")
    print(f"   Success: {result.get('success', False)}")
    
    if result.get('success'):
        decrypted = result['decrypted_data'].decode('utf-8', errors='replace')
        print(f"   Decrypted: '{decrypted}'")
        
        # Check if it's the expected "Hello World" (handle potential trailing newline)
        if decrypted.strip() == "Hello World":
            print("✅ SUCCESS: AES-OCB3 CLI-Mobile compatibility works!")
            return True
        else:
            print(f"❌ UNEXPECTED: Expected 'Hello World', got '{decrypted}' (repr: {repr(decrypted)})")
            return False
    else:
        print(f"   Error: {result.get('error', 'Unknown error')}")
        return False

def test_aes_ocb3_mobile_encryption():
    """Test mobile AES-OCB3 encryption"""
    print("\n🧪 Testing Mobile AES-OCB3 Encryption")
    print("=" * 50)
    
    crypto = MobileCryptoCore()
    test_data = "Hello Mobile AES-OCB3!"
    password = "testpass123"
    
    # Test encryption
    result = crypto.encrypt_data(test_data.encode(), password, "aes-ocb3")
    
    print(f"🔒 Mobile encryption result:")
    print(f"   Success: {result.get('success', False)}")
    
    if result.get('success'):
        encrypted_data = result['encrypted_data']
        metadata = result['metadata']
        
        print(f"   Algorithm: {metadata.get('encryption', {}).get('algorithm')}")
        print(f"   Format version: {metadata.get('format_version')}")
        print(f"   Encrypted data length: {len(encrypted_data)} chars")
        
        # Test decryption
        decrypt_result = crypto.decrypt_data(encrypted_data, metadata, password)
        
        if decrypt_result.get('success'):
            decrypted = decrypt_result['decrypted_data'].decode()
            print(f"   Round-trip decrypted: '{decrypted}'")
            
            if decrypted == test_data:
                print("✅ SUCCESS: Mobile AES-OCB3 round-trip works!")
                return True
            else:
                print(f"❌ ROUND-TRIP FAILED: Expected '{test_data}', got '{decrypted}'")
                return False
        else:
            print(f"   Decryption error: {decrypt_result.get('error')}")
            return False
    else:
        print(f"   Error: {result.get('error', 'Unknown error')}")
        return False

def main():
    """Run all AES-OCB3 tests"""
    print("🎯 AES-OCB3 CLI-Mobile Compatibility Testing")
    print("=" * 60)
    
    success_count = 0
    total_tests = 2
    
    # Test 1: CLI AES-OCB3 decryption
    if test_aes_ocb3_cli_decryption():
        success_count += 1
    
    # Test 2: Mobile AES-OCB3 encryption/decryption
    if test_aes_ocb3_mobile_encryption():
        success_count += 1
    
    print(f"\n📊 TEST SUMMARY:")
    print("=" * 30)
    print(f"✅ Passed: {success_count}/{total_tests}")
    print(f"❌ Failed: {total_tests - success_count}/{total_tests}")
    
    if success_count == total_tests:
        print("🎉 ALL TESTS PASSED - AES-OCB3 is working!")
        return True
    else:
        print("💥 SOME TESTS FAILED - Need debugging")
        return False

if __name__ == "__main__":
    main()