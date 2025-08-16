#!/usr/bin/env python3
"""
Compare how CLI vs Mobile processes the encrypted data
"""

import base64
import json
import sys
sys.path.insert(0, '../openssl_encrypt')

def trace_cli_data_processing():
    """Trace how CLI processes the encrypted data"""
    print("🔍 Tracing CLI Data Processing")
    print("=" * 50)
    
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
    
    # Read raw file content
    with open(test_file, 'r') as f:
        raw_content = f.read().strip()
    
    print(f"📄 Raw file content:")
    print(f"   Length: {len(raw_content)}")
    print(f"   First 100 chars: {raw_content[:100]}...")
    
    # Split on first colon
    if ':' in raw_content:
        metadata_part, encrypted_part = raw_content.split(':', 1)
        print(f"\n📋 File structure:")
        print(f"   Metadata part length: {len(metadata_part)}")
        print(f"   Encrypted part length: {len(encrypted_part)}")
        print(f"   Encrypted part first 50: {encrypted_part[:50]}...")
        
        # Decode metadata
        try:
            metadata_decoded = base64.b64decode(metadata_part)
            metadata = json.loads(metadata_decoded.decode())
            print(f"   Metadata format_version: {metadata.get('format_version')}")
        except Exception as e:
            print(f"   Metadata decode error: {e}")
            return
            
        # Now trace CLI processing by patching Fernet.decrypt
        print(f"\n🔧 Tracing CLI decrypt process:")
        
        try:
            from cryptography.fernet import Fernet
            original_decrypt = Fernet.decrypt
            
            cli_decrypt_data = []
            
            def trace_decrypt(self, data):
                cli_decrypt_data.append(data)
                print(f"   CLI Fernet.decrypt called with:")
                print(f"      Data type: {type(data)}")
                print(f"      Data length: {len(data)}")
                print(f"      Data first 20 bytes: {data[:20]}")
                print(f"      Data hex: {data.hex()[:40]}...")
                result = original_decrypt(self, data)
                print(f"      Result: '{result.decode()}'")
                return result
            
            Fernet.decrypt = trace_decrypt
            
            # Run CLI decrypt
            from openssl_encrypt.modules.crypt_core import decrypt_file
            result = decrypt_file(test_file, '/tmp/cli_trace.txt', b"1234", quiet=True)
            print(f"   CLI result: {result}")
            
            if cli_decrypt_data:
                print(f"\n📊 CLI used this data for Fernet:")
                cli_data = cli_decrypt_data[0]
                
                # Now compare with mobile processing
                print(f"\n📱 Mobile data processing:")
                mobile_level1 = base64.b64decode(encrypted_part)
                print(f"   Mobile Level 1: {len(mobile_level1)} bytes")
                print(f"      First 20 bytes: {mobile_level1[:20]}")
                print(f"      Hex: {mobile_level1.hex()[:40]}...")
                
                try:
                    mobile_level2 = base64.b64decode(mobile_level1.decode('ascii'))
                    print(f"   Mobile Level 2: {len(mobile_level2)} bytes")
                    print(f"      First 20 bytes: {mobile_level2[:20]}")
                    print(f"      Hex: {mobile_level2.hex()[:40]}...")
                    
                    # Compare
                    if cli_data == mobile_level2:
                        print(f"✅ CLI and Mobile process data identically!")
                        print(f"   But decryption still fails - key issue?")
                        
                        # Test if mobile key actually works
                        from mobile_crypto_core import MobileCryptoCore
                        core = MobileCryptoCore()
                        
                        # Get mobile-generated key
                        derivation_config = metadata["derivation_config"]
                        salt = base64.b64decode(derivation_config["salt"])
                        mobile_key = core._derive_key("1234", salt, {}, {
                            "pbkdf2": {"enabled": False},
                            "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4, "rounds": 10, "hash_len": 32, "type": 2},
                            "scrypt": {"enabled": False},
                            "hkdf": {"enabled": False},
                            "balloon": {"enabled": False}
                        })
                        
                        print(f"\n🧪 Testing mobile-generated key directly:")
                        f_test = Fernet(mobile_key)
                        try:
                            test_decrypt = f_test.decrypt(mobile_level2)
                            print(f"✅ Mobile key works: '{test_decrypt.decode()}'")
                            return True
                        except Exception as test_error:
                            print(f"❌ Mobile key test fails: {test_error}")
                            
                            # Compare mobile vs CLI key bytes
                            mobile_raw = base64.urlsafe_b64decode(mobile_key)
                            cli_raw = None
                            
                            # Get CLI key
                            original_init = Fernet.__init__
                            def capture_init(self, key):
                                nonlocal cli_raw
                                if isinstance(key, bytes):
                                    cli_raw = base64.urlsafe_b64decode(key)
                                else:
                                    cli_raw = base64.urlsafe_b64decode(key.encode())
                                return original_init(self, key)
                            
                            Fernet.__init__ = capture_init
                            decrypt_file(test_file, '/tmp/cli_key_capture.txt', b"1234", quiet=True)
                            
                            if cli_raw:
                                print(f"   CLI key raw:    {cli_raw.hex()}")
                                print(f"   Mobile key raw: {mobile_raw.hex()}")
                                if cli_raw == mobile_raw:
                                    print(f"   Keys identical - data processing issue")
                                else:
                                    print(f"   Keys differ - KDF issue remains")
                    else:
                        print(f"❌ CLI and Mobile process data differently!")
                        print(f"   CLI data length: {len(cli_data)}")
                        print(f"   Mobile data length: {len(mobile_level2)}")
                        
                        # Find differences
                        min_len = min(len(cli_data), len(mobile_level2))
                        for i in range(min_len):
                            if cli_data[i] != mobile_level2[i]:
                                print(f"   First diff at byte {i}: CLI={cli_data[i]:02x} vs Mobile={mobile_level2[i]:02x}")
                                break
                        
                except Exception as level2_error:
                    print(f"   Mobile Level 2 error: {level2_error}")
                    
        except Exception as e:
            print(f"❌ CLI tracing failed: {e}")
            import traceback
            traceback.print_exc()
    else:
        print(f"❌ File format not recognized")

if __name__ == "__main__":
    trace_cli_data_processing()