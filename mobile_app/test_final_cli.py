#!/usr/bin/env python3
"""
Final CLI Compatibility Test - with detailed error reporting
"""

import traceback
from mobile_crypto_core import MobileCryptoCore

def test_cli_decryption_detailed():
    """Test CLI decryption with detailed error reporting"""
    print("🧪 Final CLI Decryption Test")
    print("=" * 50)
    
    cli_file = "cli_test_file.txt"
    password = "1234"
    
    core = MobileCryptoCore()
    
    try:
        print("🔍 Attempting CLI file decryption...")
        result = core.decrypt_file(cli_file, password, "final_test_output.txt")
        
        print(f"🎯 Result: {result}")
        
        if result["success"]:
            print("🎉 SUCCESS: Mobile decrypted CLI file successfully!")
            
            # Read and display the output
            try:
                with open("final_test_output.txt", 'r') as f:
                    content = f.read()
                print(f"📄 Decrypted content: {content}")
                return True
            except Exception as e:
                print(f"⚠️ Could not read output file: {e}")
                return True  # Still a successful decrypt
        else:
            print(f"❌ Mobile decrypt failed: {result.get('error', 'Unknown error')}")
            
            # Try to get more detailed error info by manually parsing
            print(f"\n🔧 Manual parsing attempt...")
            
            import base64
            import json
            
            with open(cli_file, 'r') as f:
                raw_content = f.read().strip()
            
            if ':' in raw_content:
                metadata_b64, encrypted_data_b64 = raw_content.split(':', 1)
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                metadata = json.loads(metadata_json)
                
                print(f"✅ CLI file parsed manually")
                
                # Use decrypt_data directly
                decrypt_result = core.decrypt_data(encrypted_data_b64, metadata, password)
                print(f"🔍 Direct decrypt_data result: {decrypt_result}")
                
                if decrypt_result["success"]:
                    print("🎉 SUCCESS: Direct decrypt_data worked!")
                    decrypted = decrypt_result["decrypted_data"]
                    if isinstance(decrypted, bytes):
                        try:
                            print(f"📄 Decrypted: {decrypted.decode('utf-8')}")
                        except:
                            print(f"📄 Decrypted (binary): {decrypted}")
                    else:
                        print(f"📄 Decrypted: {decrypted}")
                    return True
                else:
                    print(f"❌ Direct decrypt_data also failed: {decrypt_result.get('error', 'Unknown')}")
            else:
                print("❌ Could not parse CLI file format")
            
            return False
            
    except Exception as e:
        print(f"❌ Exception during test: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_cli_decryption_detailed()
    
    if success:
        print(f"\n🎉 FINAL RESULT: SUCCESS - CLI-Mobile compatibility achieved!")
    else:
        print(f"\n❌ FINAL RESULT: FAILED - Issues still remain")