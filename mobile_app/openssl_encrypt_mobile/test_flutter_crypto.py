#!/usr/bin/env python3
"""
Test crypto from Flutter directory
"""

import json
import sys
import os

def test_flutter_crypto():
    """Test the corrected crypto from Flutter directory"""
    print("🧪 Testing Flutter Crypto Directory")
    print("=" * 50)
    
    # Test direct import
    try:
        from mobile_crypto_core import MobileCryptoCore
        core = MobileCryptoCore()
        
        # Test with CLI file
        test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
        password = "1234"
        
        result = core.decrypt_file(test_file, password, "/tmp/flutter_test.txt")
        
        if result.get("success"):
            with open("/tmp/flutter_test.txt", 'r') as f:
                content = f.read()
            print(f"✅ Flutter crypto SUCCESS: '{content.strip()}'")
            print(f"   All CLI-compatible fixes are working!")
            return True
        else:
            print(f"❌ Flutter crypto FAILED: {result.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Flutter crypto EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_flutter_crypto()