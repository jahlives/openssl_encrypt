#!/usr/bin/env python3
"""
Script to verify the PQCKeystore fix by testing creation and loading of a keystore
"""

import os
import sys
import tempfile
import shutil
import argparse
import json
import traceback

# Add the project to path
sys.path.insert(0, os.path.abspath('.'))
from openssl_encrypt.modules.pqc_keystore import (
    PQCKeystore, KeystoreSecurityLevel, KeystoreProtectionMethod
)

def test_keystore_fix():
    """Test that the keystore fix allows creation and loading of a keystore"""
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "test_keystore.pqc")
    
    # Master password for tests
    master_password = "test_master_password"
    
    print("\n=== Testing PQCKeystore fix ===")
    
    try:
        # Create a keystore
        print("\nStep 1: Creating keystore")
        keystore = PQCKeystore(keystore_path)
        result = keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
        print(f"Keystore created successfully: {result}")
        
        # Try to load it in a new instance
        print("\nStep 2: Loading keystore")
        keystore2 = PQCKeystore(keystore_path)
        result = keystore2.load_keystore(master_password)
        print(f"Keystore loaded successfully: {result}")
        
        # If we got this far, the fix worked
        print("\n✅ SUCCESS! The PQCKeystore fix is working correctly.")
        print("The keystore can now be created and loaded successfully.")
        
        # Clean up
        shutil.rmtree(temp_dir)
        
        return True
    except Exception as e:
        print(f"\n❌ ERROR: The fix didn't work: {str(e)}")
        traceback.print_exc()
        return False

def test_with_key():
    """Test creating a keystore with a key and then loading it"""
    # Check if PQC is available
    try:
        from openssl_encrypt.modules.pqc import PQCipher, check_pqc_support, LIBOQS_AVAILABLE
        if not LIBOQS_AVAILABLE:
            print("PQC is not available - skipping key test")
            return True
    except ImportError:
        print("PQC module not available - skipping key test")
        return True
    
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "test_keystore_with_key.pqc")
    
    # Master password for tests
    master_password = "test_master_password"
    
    print("\n=== Testing PQCKeystore with key addition ===")
    
    try:
        # Create a keystore
        print("\nStep 1: Creating keystore")
        keystore = PQCKeystore(keystore_path)
        result = keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
        print(f"Keystore created successfully: {result}")
        
        # Generate a key pair
        print("\nStep 2: Adding a key")
        try:
            cipher = PQCipher("Kyber768", quiet=True)
            public_key, private_key = cipher.generate_keypair()
            
            key_id = keystore.add_key(
                algorithm="Kyber768",
                public_key=public_key,
                private_key=private_key,
                use_master_password=True,
                description="Test key"
            )
            print(f"Key added with ID: {key_id}")
            
            # Save the keystore
            keystore.save_keystore()
            print("Keystore saved with key")
            
        except Exception as e:
            print(f"Error adding key: {e}")
            traceback.print_exc()
            return False
        
        # Try to load it in a new instance
        print("\nStep 3: Loading keystore with key")
        keystore2 = PQCKeystore(keystore_path)
        result = keystore2.load_keystore(master_password)
        print(f"Keystore loaded successfully: {result}")
        
        # Try to get the key
        try:
            public_key, private_key = keystore2.get_key(key_id)
            print(f"Key retrieved successfully with ID: {key_id}")
        except Exception as e:
            print(f"Error retrieving key: {e}")
            traceback.print_exc()
            return False
        
        # If we got this far, the fix worked
        print("\n✅ SUCCESS! The PQCKeystore fix works with key operations.")
        print("The keystore can now be created, have keys added, and be loaded successfully.")
        
        # Clean up
        shutil.rmtree(temp_dir)
        
        return True
    except Exception as e:
        print(f"\n❌ ERROR: The key test didn't work: {str(e)}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify the PQCKeystore loading fix")
    parser.add_argument("--with-key", action="store_true", help="Also test key addition and retrieval")
    
    args = parser.parse_args()
    
    # Always run the basic test
    success = test_keystore_fix()
    
    # Optionally run the key test
    if args.with_key and success:
        success = test_with_key()
    
    if success:
        print("\nAll tests passed! The fix was successful.")
        sys.exit(0)
    else:
        print("\nTests failed! The fix wasn't successful.")
        sys.exit(1)