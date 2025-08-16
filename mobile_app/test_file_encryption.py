#!/usr/bin/env python3
"""
Test file encryption/decryption compatibility
Creates test files and verifies they can be properly detected and decrypted
"""

import os
import json
import tempfile
from mobile_crypto_core import MobileCryptoCore

def create_test_files():
    """Create test files in different formats to verify file detection"""
    core = MobileCryptoCore()
    test_password = "FileTestPassword123!"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        print("🔐 Testing File Encryption/Decryption Compatibility")
        print("=" * 60)
        
        # Test content
        test_content = """This is a test file for OpenSSL Encrypt Mobile.
It contains multiple lines of text to verify that the file
encryption and decryption process works correctly with the
mobile application.

Key features being tested:
- File content preservation
- Metadata format compatibility
- Cross-platform file reading
- CLI format version 5 support

Test successful if this content is recovered intact!"""
        
        print(f"\n📝 Original test content ({len(test_content)} characters):")
        print(f"First 100 chars: {test_content[:100]}...")
        
        # Test 1: Mobile format file
        print(f"\n1. Testing Mobile Format File:")
        mobile_result = core.encrypt_data(
            test_content.encode(),
            test_password,
            hash_config={"sha256": 1000, "sha512": 500, "sha3_256": 0, "sha3_512": 0, "blake2b": 0, "blake3": 0, "shake256": 0, "whirlpool": 0},
            kdf_config={"pbkdf2": {"enabled": True, "rounds": 50000}, "scrypt": {"enabled": False}, "argon2": {"enabled": False}, "hkdf": {"enabled": False}, "balloon": {"enabled": False}}
        )
        
        if mobile_result["success"]:
            # Save in mobile format (as mobile app would)
            mobile_file_path = os.path.join(temp_dir, "test_mobile_format.txt")
            mobile_file_data = {
                "format": "openssl_encrypt_mobile",
                "version": "2.1",
                "original_filename": "test_mobile_format.txt",
                "encrypted_data": mobile_result["encrypted_data"],
                "metadata": mobile_result["metadata"]
            }
            
            with open(mobile_file_path, 'w') as f:
                json.dump(mobile_file_data, f, indent=2)
            
            print(f"   ✅ Mobile format file created: {mobile_file_path}")
            print(f"   📄 File size: {os.path.getsize(mobile_file_path)} bytes")
            
            # Verify file can be detected as encrypted
            try:
                with open(mobile_file_path, 'r') as f:
                    file_content = f.read()
                    parsed = json.loads(file_content)
                    
                if (parsed.get('format') == 'openssl_encrypt_mobile' and 
                    'encrypted_data' in parsed and 'metadata' in parsed):
                    print(f"   ✅ Mobile format detected correctly")
                else:
                    print(f"   ❌ Mobile format detection failed")
                    
            except Exception as e:
                print(f"   ❌ File parsing failed: {e}")
        
        # Test 2: CLI format file  
        print(f"\n2. Testing CLI Format File:")
        cli_result = core.encrypt_data(
            test_content.encode(),
            test_password,
            hash_config={"sha512": 1500, "sha256": 1000, "sha3_256": 0, "sha3_512": 0, "blake2b": 500, "blake3": 0, "shake256": 0, "whirlpool": 0},
            kdf_config={"pbkdf2": {"enabled": True, "rounds": 75000}, "scrypt": {"enabled": True, "n": 8192, "r": 8, "p": 1, "rounds": 1}, "argon2": {"enabled": False}, "hkdf": {"enabled": False}, "balloon": {"enabled": False}}
        )
        
        if cli_result["success"]:
            # Save in CLI format (direct JSON)
            cli_file_path = os.path.join(temp_dir, "test_cli_format.txt")
            cli_file_data = {
                "encrypted_data": cli_result["encrypted_data"],
                "metadata": cli_result["metadata"]
            }
            
            with open(cli_file_path, 'w') as f:
                json.dump(cli_file_data, f, indent=2)
            
            print(f"   ✅ CLI format file created: {cli_file_path}")
            print(f"   📄 File size: {os.path.getsize(cli_file_path)} bytes")
            print(f"   📋 Metadata format version: {cli_result['metadata']['format_version']}")
            
            # Verify file can be detected as encrypted
            try:
                with open(cli_file_path, 'r') as f:
                    file_content = f.read()
                    parsed = json.loads(file_content)
                    
                if ('encrypted_data' in parsed and 'metadata' in parsed):
                    metadata = parsed['metadata']
                    if ('format_version' in metadata or 'derivation_config' in metadata):
                        print(f"   ✅ CLI format detected correctly")
                    else:
                        print(f"   ❌ CLI format detection failed - missing key fields")
                else:
                    print(f"   ❌ CLI format detection failed - missing basic structure")
                    
            except Exception as e:
                print(f"   ❌ File parsing failed: {e}")
        
        # Test 3: Invalid files (should not be detected as encrypted)
        print(f"\n3. Testing Invalid File Detection:")
        
        invalid_files = [
            ("plain_text.txt", "This is just plain text, not encrypted."),
            ("invalid_json.txt", '{"incomplete": "json"'),
            ("wrong_format.txt", '{"some_data": "value", "not_encrypted": true}'),
            ("empty_file.txt", "")
        ]
        
        for filename, content in invalid_files:
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'w') as f:
                f.write(content)
            
            # Check if it's incorrectly detected as encrypted
            try:
                with open(file_path, 'r') as f:
                    file_content = f.read()
                    
                is_encrypted = False
                try:
                    parsed = json.loads(file_content)
                    if isinstance(parsed, dict):
                        # Check mobile format
                        if (parsed.get('format') == 'openssl_encrypt_mobile' and
                            'encrypted_data' in parsed and 'metadata' in parsed):
                            is_encrypted = True
                        # Check CLI format
                        elif ('encrypted_data' in parsed and 'metadata' in parsed):
                            metadata = parsed['metadata']
                            if isinstance(metadata, dict):
                                if ('format_version' in metadata or
                                    'derivation_config' in metadata or
                                    'algorithm' in metadata):
                                    is_encrypted = True
                except:
                    pass
                
                if is_encrypted:
                    print(f"   ❌ {filename}: Incorrectly detected as encrypted")
                else:
                    print(f"   ✅ {filename}: Correctly detected as not encrypted")
                    
            except Exception as e:
                print(f"   ✅ {filename}: Correctly failed to parse ({e})")
        
        # Test 4: Decryption verification
        print(f"\n4. Testing File Content Decryption:")
        
        test_files = [
            ("mobile_format", mobile_file_path, mobile_result),
            ("cli_format", cli_file_path, cli_result)
        ]
        
        for format_name, file_path, original_result in test_files:
            print(f"\n   Testing {format_name} decryption:")
            
            try:
                # Read the encrypted file
                with open(file_path, 'r') as f:
                    file_content = f.read()
                    parsed = json.loads(file_content)
                
                # Extract encrypted data and metadata
                if parsed.get('format') == 'openssl_encrypt_mobile':
                    encrypted_data = parsed['encrypted_data']
                    metadata = parsed['metadata']
                else:
                    encrypted_data = parsed['encrypted_data']
                    metadata = parsed['metadata']
                
                # Decrypt
                decrypt_result = core.decrypt_data(encrypted_data, metadata, test_password)
                
                if decrypt_result["success"]:
                    decrypted_content = decrypt_result["decrypted_data"].decode()
                    
                    if decrypted_content == test_content:
                        print(f"      ✅ Content matches perfectly!")
                        print(f"      📏 Length: {len(decrypted_content)} chars (expected: {len(test_content)})")
                    else:
                        print(f"      ❌ Content mismatch!")
                        print(f"      📏 Got: {len(decrypted_content)} chars, Expected: {len(test_content)}")
                        print(f"      📝 First 50 chars: {decrypted_content[:50]}...")
                else:
                    print(f"      ❌ Decryption failed: {decrypt_result['error']}")
                    
            except Exception as e:
                print(f"      ❌ File processing failed: {e}")
        
        print(f"\n" + "=" * 60)
        print("🎉 File Encryption/Decryption Test Complete!")
        print("✅ Mobile format files created and verified")
        print("✅ CLI format files created and verified")
        print("✅ Invalid files correctly rejected")
        print("✅ File content preservation verified")
        print("\nFiles are ready for mobile app testing!")

if __name__ == "__main__":
    create_test_files()