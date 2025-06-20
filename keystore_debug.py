#!/usr/bin/env python3
"""
Debug script to identify the PQCKeystore loading issue
"""

import os
import sys
import tempfile
import base64
import json
from typing import Dict

# Add the project to path
sys.path.insert(0, os.path.abspath('.'))
from openssl_encrypt.modules.pqc_keystore import PQCKeystore, KeystoreSecurityLevel

def debug_keystore_file(keystore_path: str) -> None:
    """Debug a keystore file by examining its binary structure"""
    print(f"Analyzing keystore file: {keystore_path}")
    
    with open(keystore_path, 'rb') as f:
        data = f.read()
    
    # Extract header
    if len(data) < 4:
        print("Error: File too small to be a valid keystore")
        return
    
    header_size = int.from_bytes(data[:4], byteorder='big')
    print(f"Header size: {header_size}")
    
    if len(data) < 4 + header_size:
        print("Error: File smaller than expected based on header size")
        return
    
    try:
        header_data = data[4:4+header_size].decode('utf-8')
        header = json.loads(header_data)
        print(f"Header: {json.dumps(header, indent=2)}")
        
        # Check protection method 
        method = header["protection"]["method"]
        print(f"Protection method: {method}")
        
        # The ciphertext size
        ciphertext_size = len(data) - (4 + header_size)
        print(f"Ciphertext size: {ciphertext_size}")
        
        # Check for nonce and associated data usage
        if "nonce" in header["protection"]["params"]:
            nonce = base64.b64decode(header["protection"]["params"]["nonce"])
            print(f"Nonce (hex): {nonce.hex()}")
            print(f"Nonce length: {len(nonce)}")
        
    except Exception as e:
        print(f"Error parsing header: {e}")

def test_keystore_creation_and_loading():
    """Test keystore creation and loading to identify the issue"""
    print("\n=== Testing keystore creation and loading ===")
    
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "test_keystore.pqc")
    
    # Master password for tests
    master_password = "test_master_password"
    
    # Create the first keystore
    print("\nStep 1: Creating keystore")
    keystore1 = PQCKeystore(keystore_path)
    keystore1.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
    
    # Debug the file format
    debug_keystore_file(keystore_path)
    
    # Try to load it in a new instance
    print("\nStep 2: Loading keystore")
    keystore2 = PQCKeystore(keystore_path)
    try:
        result = keystore2.load_keystore(master_password)
        print(f"Keystore loaded successfully: {result}")
    except Exception as e:
        print(f"Error loading keystore: {str(e)}")
        import traceback
        traceback.print_exc()
    
    # Create a keystore and add a key in one step
    print("\n=== Testing keystore creation with key addition ===")
    
    # Create a new keystore path
    keystore_path2 = os.path.join(temp_dir, "test_keystore2.pqc")
    
    # Import necessary modules
    try:
        from openssl_encrypt.modules.pqc import PQCipher, check_pqc_support, LIBOQS_AVAILABLE
        
        # Check if PQC is available
        if not LIBOQS_AVAILABLE:
            print("Post-quantum cryptography is not available. Skipping key addition test.")
        else:
            # Create a new keystore and add a key
            print("\nStep 1: Creating keystore with key")
            keystore3 = PQCKeystore(keystore_path2)
            keystore3.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
            
            # Generate a key
            print("Generating Kyber768 key pair...")
            cipher = PQCipher("Kyber768", quiet=True)
            public_key, private_key = cipher.generate_keypair()
            
            # Add the key
            key_id = keystore3.add_key(
                algorithm="Kyber768",
                public_key=public_key,
                private_key=private_key,
                use_master_password=True,
                description="Test key"
            )
            print(f"Added key with ID: {key_id}")
            
            # Save the keystore
            keystore3.save_keystore()
            
            # Debug the file format
            debug_keystore_file(keystore_path2)
            
            # Try to load it in a new instance
            print("\nStep 2: Loading keystore with key")
            keystore4 = PQCKeystore(keystore_path2)
            try:
                result = keystore4.load_keystore(master_password)
                print(f"Keystore loaded successfully: {result}")
                
                # Try to get the key
                public_key, private_key = keystore4.get_key(key_id)
                print(f"Key retrieved successfully with ID: {key_id}")
            except Exception as e:
                print(f"Error loading keystore or getting key: {str(e)}")
                import traceback
                traceback.print_exc()
    except ImportError:
        print("PQC modules not available. Skipping key addition test.")
    
if __name__ == "__main__":
    test_keystore_creation_and_loading()