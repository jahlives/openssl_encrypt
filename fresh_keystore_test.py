#!/usr/bin/env python3
"""
Test the PQC keystore creation and loading with the fix for the associated_data issue
"""

import os
import sys
import tempfile
import shutil
import getpass

# Add the parent directory to the path
sys.path.insert(0, os.path.abspath("."))

from openssl_encrypt.modules.pqc_keystore import PQCKeystore, KeystoreSecurityLevel

def run_keystore_test():
    """Create a new keystore with the standard security level, and then load it again"""
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    try:
        # Create a keystore file path
        keystore_path = os.path.join(temp_dir, "test.keystore")
        
        # Master password for testing
        master_password = "test123456"
        
        print(f"Creating keystore at: {keystore_path}")
        
        # Create a new keystore
        keystore = PQCKeystore(keystore_path)
        try:
            # Create the keystore with standard security level
            result = keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
            print(f"Keystore created: {result}")
            
            # Now try to load it
            print("\nAttempting to load the keystore...")
            keystore2 = PQCKeystore(keystore_path)
            load_result = keystore2.load_keystore(master_password)
            print(f"Keystore loaded: {load_result}")
            print("SUCCESS! The keystore was created and loaded successfully.")
            
            return True
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    finally:
        # Clean up
        shutil.rmtree(temp_dir)

def run_paranoid_keystore_test():
    """Create a new keystore with the paranoid security level, and then load it again"""
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    try:
        # Create a keystore file path
        keystore_path = os.path.join(temp_dir, "test_paranoid.keystore")
        
        # Master password for testing
        master_password = "test123456"
        
        print(f"\nCreating paranoid keystore at: {keystore_path}")
        
        # Create a new keystore
        keystore = PQCKeystore(keystore_path)
        try:
            # Create the keystore with paranoid security level
            result = keystore.create_keystore(master_password, KeystoreSecurityLevel.PARANOID)
            print(f"Paranoid keystore created: {result}")
            
            # Now try to load it
            print("\nAttempting to load the paranoid keystore...")
            keystore2 = PQCKeystore(keystore_path)
            load_result = keystore2.load_keystore(master_password)
            print(f"Paranoid keystore loaded: {load_result}")
            print("SUCCESS! The paranoid keystore was created and loaded successfully.")
            
            return True
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    finally:
        # Clean up
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    print("===== Testing PQC Keystore Creation and Loading =====")
    standard_result = run_keystore_test()
    paranoid_result = run_paranoid_keystore_test()
    
    if standard_result and paranoid_result:
        print("\n✅ All tests PASSED! The keystore fix is working.")
        sys.exit(0)
    else:
        print("\n❌ Tests FAILED. The keystore fix is not working properly.")
        sys.exit(1)