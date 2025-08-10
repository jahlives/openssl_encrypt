#!/usr/bin/env python3
"""
REAL bidirectional compatibility test
Tests actual CLI vs mobile file encryption/decryption
"""

import os
import sys
import subprocess
from mobile_crypto_core import MobileCryptoCore

def test_real_compatibility():
    """Test real CLI <-> Mobile compatibility"""
    
    print("🔬 REAL Bidirectional Compatibility Test")
    print("=" * 50)
    
    test_password = "1234"
    test_content = "Hello bidirectional test!"
    
    # Create test input file
    with open("test_input.txt", "w") as f:
        f.write(test_content)
    
    print("\n1. Testing CLI → Mobile:")
    print("   Creating file with actual CLI...")
    
    # Test 1: CLI encrypts, Mobile decrypts
    cli_cmd = [
        "python3", "-m", "openssl_encrypt.modules.crypt_cli", "encrypt",
        "--input", "test_input.txt", 
        "--output", "cli_encrypted.txt",
        "--password", test_password,
        "--force-password",
        "--algorithm", "fernet",
        "--quiet"
    ]
    
    cli_result = subprocess.run(cli_cmd, cwd="..", capture_output=True, text=True)
    
    if cli_result.returncode == 0:
        print("   ✅ CLI encryption successful")
        
        # Now test mobile decryption
        core = MobileCryptoCore()
        mobile_result = core.decrypt_file("cli_encrypted.txt", test_password)
        
        if mobile_result["success"]:
            with open(mobile_result["output_path"], "r") as f:
                decrypted_content = f.read()
            
            if decrypted_content.strip() == test_content:
                print("   ✅ Mobile decryption of CLI file: SUCCESS")
                cli_to_mobile = True
            else:
                print(f"   ❌ Content mismatch. Expected: '{test_content}', Got: '{decrypted_content.strip()}'")
                cli_to_mobile = False
        else:
            print("   ❌ Mobile decryption of CLI file: FAILED")
            print(f"   Error: {mobile_result.get('error', 'Unknown error')}")
            cli_to_mobile = False
    else:
        print("   ❌ CLI encryption failed")
        print(f"   Error: {cli_result.stderr}")
        cli_to_mobile = False
    
    print("\n2. Testing Mobile → CLI:")
    print("   Creating file with mobile...")
    
    # Test 2: Mobile encrypts, CLI decrypts
    core = MobileCryptoCore()
    mobile_encrypt_result = core.encrypt_file("test_input.txt", test_password, "mobile_encrypted.txt")
    
    if mobile_encrypt_result["success"]:
        print("   ✅ Mobile encryption successful")
        
        # Now test CLI decryption
        cli_decrypt_cmd = [
            "python3", "-m", "openssl_encrypt.modules.crypt_cli", "decrypt",
            "--input", "mobile_encrypted.txt",
            "--output", "cli_decrypted.txt", 
            "--password", test_password,
            "--force-password",
            "--quiet"
        ]
        
        cli_decrypt_result = subprocess.run(cli_decrypt_cmd, cwd="..", capture_output=True, text=True)
        
        if cli_decrypt_result.returncode == 0:
            with open("cli_decrypted.txt", "r") as f:
                decrypted_content = f.read()
            
            if decrypted_content.strip() == test_content:
                print("   ✅ CLI decryption of mobile file: SUCCESS") 
                mobile_to_cli = True
            else:
                print(f"   ❌ Content mismatch. Expected: '{test_content}', Got: '{decrypted_content.strip()}'")
                mobile_to_cli = False
        else:
            print("   ❌ CLI decryption of mobile file: FAILED")
            print(f"   Error: {cli_decrypt_result.stderr}")
            mobile_to_cli = False
    else:
        print("   ❌ Mobile encryption failed")
        print(f"   Error: {mobile_encrypt_result.get('error', 'Unknown error')}")
        mobile_to_cli = False
    
    # Summary
    print("\n" + "=" * 50)
    print("🎯 REAL BIDIRECTIONAL TEST RESULTS")
    print("=" * 50)
    print(f"CLI → Mobile: {'✅ PASSED' if cli_to_mobile else '❌ FAILED'}")
    print(f"Mobile → CLI: {'✅ PASSED' if mobile_to_cli else '❌ FAILED'}")
    
    if cli_to_mobile and mobile_to_cli:
        print("\n🎉 PERFECT BIDIRECTIONAL COMPATIBILITY!")
    else:
        print("\n⚠️  BIDIRECTIONAL COMPATIBILITY BROKEN!")
        if not cli_to_mobile:
            print("❌ Mobile cannot decrypt CLI files")
        if not mobile_to_cli:
            print("❌ CLI cannot decrypt mobile files")
    
    # Cleanup
    for f in ["test_input.txt", "cli_encrypted.txt", "mobile_encrypted.txt", "cli_decrypted.txt"]:
        if os.path.exists(f):
            os.remove(f)
    
    return cli_to_mobile and mobile_to_cli

if __name__ == "__main__":
    success = test_real_compatibility()
    sys.exit(0 if success else 1)