#!/usr/bin/env python3
"""
Test with your specific CLI test file
"""

from mobile_crypto_core import MobileCryptoCore

def test_your_file():
    """Test with the specific file you provided"""
    print("🧪 Testing Your CLI Test File")
    print("=" * 50)
    
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
    password = "1234"
    
    print(f"🔑 File: {test_file}")
    print(f"🔑 Password: {password}")
    
    core = MobileCryptoCore()
    
    try:
        result = core.decrypt_file(test_file, password, "your_file_decrypted.txt")
        
        if result["success"]:
            print("🎉 SUCCESS: Mobile decrypted your CLI file!")
            
            # Read the decrypted content
            try:
                with open("your_file_decrypted.txt", 'r') as f:
                    content = f.read()
                print(f"📄 Decrypted content: '{content}'")
            except:
                with open("your_file_decrypted.txt", 'rb') as f:
                    content = f.read()
                print(f"📄 Decrypted binary: {content[:100]}...")
                
            return True
        else:
            print(f"❌ Mobile decrypt failed: {result.get('error', 'Unknown error')}")
            
            # Debug the file format
            print(f"\n🔍 Analyzing your file...")
            
            import base64
            import json
            
            with open(test_file, 'r') as f:
                raw_content = f.read().strip()
            
            print(f"   File size: {len(raw_content)} chars")
            print(f"   First 100 chars: {raw_content[:100]}")
            
            if ':' in raw_content:
                metadata_b64, data_b64 = raw_content.split(':', 1)
                print(f"   Metadata length: {len(metadata_b64)}")
                print(f"   Data length: {len(data_b64)}")
                
                # Parse metadata
                try:
                    metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                    metadata = json.loads(metadata_json)
                    
                    print(f"   ✅ Metadata parsed")
                    print(f"   Format version: {metadata.get('format_version')}")
                    
                    if "derivation_config" in metadata:
                        derivation = metadata["derivation_config"]
                        print(f"   Salt: {derivation.get('salt', 'missing')}")
                        
                        # Show KDF config
                        kdf_config = derivation.get("kdf_config", {})
                        print(f"   KDF algorithms:")
                        for kdf, params in kdf_config.items():
                            print(f"      {kdf}: {params}")
                            
                except Exception as e:
                    print(f"   ❌ Metadata parse failed: {e}")
            else:
                print("   ❌ No ':' separator found")
            
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_your_file()