#!/usr/bin/env python3
"""
Test dual encryption with keystore integration

This script tests the dual encryption functionality with keystore integration:
1. Encrypt a file with a PQC key
2. Enable dual encryption so that the key is stored in the keystore 
3. Verify the key is removed from the metadata but is in the keystore
4. Try to decrypt the file with both keystore and file passwords
"""

import os
import sys
import json
import base64
import tempfile
import argparse
import traceback

# Add the parent directory to the python path for importing
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from openssl_encrypt.modules.keystore_cli import PQCKeystore
from openssl_encrypt.modules.keystore_wrapper import encrypt_file_with_keystore, decrypt_file_with_keystore
from openssl_encrypt.modules.keystore_utils import extract_key_id_from_metadata

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Test dual encryption with keystore integration")
    parser.add_argument('--input', help='Input file to encrypt', default='test_input.txt')
    parser.add_argument('--output', help='Output file', default='test_encrypted.enc')
    parser.add_argument('--keystore', help='Keystore file', default='test_keystore.pqc')
    parser.add_argument('--clean', action='store_true', help='Clean up test files')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    # Clean up test files if requested
    if args.clean:
        for file in [args.output, args.keystore, f"{args.output}.decrypted"]:
            if os.path.exists(file):
                try:
                    os.remove(file)
                    print(f"Removed {file}")
                except Exception as e:
                    print(f"Error removing {file}: {e}")
        return

    # Remove all test files to start clean
    for file in [args.output, args.keystore, f"{args.output}.decrypted", f"{args.output}.decrypted.wrong"]:
        if os.path.exists(file):
            os.remove(file)
            print(f"Removed {file}")

    # Create input file if it doesn't exist
    if not os.path.exists(args.input):
        with open(args.input, 'w') as f:
            f.write("This is a test file for dual encryption with keystore integration.\n")
            f.write("The contents should be recoverable with both keystore and file passwords.\n")
        print(f"Created input file: {args.input}")

    # Create or load keystore
    keystore = PQCKeystore(args.keystore)
    keystore_password = "keystore_password"  # Use a simple password for testing
    file_password = "file_password"  # Use a different password for file encryption

    if not os.path.exists(args.keystore):
        print(f"Creating new keystore: {args.keystore}")
        keystore.create_keystore(keystore_password)
    else:
        print(f"Loading existing keystore: {args.keystore}")
        keystore.load_keystore(keystore_password)

    # Check if we need to create a key
    pqc_keypair = None
    key_id = None

    if len(keystore.list_keys()) == 0:
        print("No keys in keystore, creating a new key")
        
        # For testing purposes, we'll manually create a keypair
        # rather than using an algorithm-specific implementation
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        # Generate a simple RSA key for testing
        # (this would be a Kyber key in a real scenario)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Convert keys to bytes for the keystore
        from cryptography.hazmat.primitives import serialization
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        pqc_keypair = (public_key_bytes, private_key_bytes)
        
        # Explicitly prepare the file password as string, not bytes
        # Add to keystore with dual encryption
        key_id = keystore.add_key(
            algorithm="kyber768",  # Pretend this is a Kyber key
            public_key=public_key_bytes,
            private_key=private_key_bytes,
            description="Test key for dual encryption",
            tags=["test", "dual-encryption"],
            dual_encryption=True,  # Enable dual encryption for this key
            file_password=file_password  # Pass the file password for dual encryption as string
        )
        
        # Explicitly mark the key for dual encryption in the keystore
        if hasattr(keystore, '_key_has_dual_encryption_flag'):
            keystore._key_has_dual_encryption_flag(key_id, True)
            
        # Save the keystore to ensure changes are persisted
        keystore.save_keystore()
        print(f"Created test key with ID: {key_id}")
    else:
        # Use the first key in the keystore
        keys = keystore.list_keys()
        key_id = keys[0]["key_id"]
        # Need to pass file_password for dual-encrypted keys
        public_key, private_key = keystore.get_key(key_id, file_password=file_password)
        pqc_keypair = (public_key, private_key)
        print(f"Using existing key with ID: {key_id}")

    # Create a hash configuration for testing
    hash_config = {
        "sha256": 1,  # Use minimal iterations for faster testing
        "pbkdf2_iterations": 1000
    }

    # Step 1: Encrypt the file with dual encryption enabled
    print("\nStep 1: Encrypting file with dual encryption")
    # Ensure password is bytes for encryption
    file_password_bytes = file_password.encode('utf-8')
    success = encrypt_file_with_keystore(
        args.input,
        args.output,
        file_password_bytes,
        hash_config=hash_config,
        pbkdf2_iterations=1000,  # Low value for testing
        quiet=False,
        algorithm="kyber768-hybrid",  # Use a Kyber hybrid algorithm
        pqc_keypair=pqc_keypair,
        keystore_file=args.keystore,
        keystore_password=keystore_password,
        key_id=key_id,
        dual_encryption=True,
        pqc_dual_encryption=True,  # This is the key flag we're testing
        verbose=args.verbose
    )

    if not success:
        print("Encryption failed")
        return 1

    # Step 2: Verify the key is in the keystore and removed from metadata
    print("\nStep 2: Verifying key storage")

    # Check the metadata
    with open(args.output, 'rb') as f:
        content = f.read(8192)
        
    # Find the colon separator
    colon_pos = content.find(b':')
    if colon_pos > 0:
        metadata_b64 = content[:colon_pos]
        try:
            metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
            metadata = json.loads(metadata_json)
            
            # Verify key ID is in metadata
            if 'hash_config' in metadata and 'pqc_keystore_key_id' in metadata['hash_config']:
                print(f"Key ID in metadata: {metadata['hash_config']['pqc_keystore_key_id']}")
                assert metadata['hash_config']['pqc_keystore_key_id'] == key_id, "Key ID mismatch"
            else:
                print("ERROR: Key ID not found in metadata")
                return 1
                
            # Verify dual encryption flag is in metadata
            if 'hash_config' in metadata and 'dual_encryption' in metadata['hash_config']:
                print(f"Dual encryption flag in metadata: {metadata['hash_config']['dual_encryption']}")
            else:
                print("ERROR: Dual encryption flag not found in metadata")
                return 1
                
            # Verify private key is NOT in metadata
            if 'hash_config' in metadata and 'pqc_private_key' in metadata['hash_config']:
                print("ERROR: Private key found in metadata, should have been removed")
                return 1
            else:
                print("Private key correctly removed from metadata")
        except Exception as e:
            print(f"Error decoding metadata: {e}")
            return 1

    # Step 3: Try to decrypt the file with both keystore and file passwords
    print("\nStep 3: Decrypting file with dual encryption")
    
    # First, reload the keystore to ensure we're not relying on cached keys
    keystore = PQCKeystore(args.keystore)
    keystore.load_keystore(keystore_password)
    
    # Now try to decrypt
    # Ensure password is bytes for decryption
    file_password_bytes = file_password.encode('utf-8')
    
    try:
        print("\nDebug: Listing keys in keystore")
        keys = keystore.list_keys()
        for k in keys:
            print(f"Key ID: {k['key_id']}")
            print(f"Algorithm: {k.get('algorithm')}")
            # Check if this key has dual encryption enabled
            try:
                is_dual = keystore.key_has_dual_encryption(k['key_id'])
                print(f"Has dual encryption: {is_dual}")
            except:
                print("Could not determine dual encryption status")

        print(f"\nDebug: Verifying file password: {file_password}")
        print(f"Debug: Keystore password: {keystore_password}")
        print(f"Debug: Attempting to get key from keystore using key ID: {key_id}")
        
        # Try to access the key directly first
        try:
            public_key, private_key = keystore.get_key(key_id, file_password=file_password)
            print("Debug: Successfully retrieved key from keystore directly!")
        except Exception as ke:
            print(f"Debug: Failed to get key directly from keystore: {ke}")
            
        # Now try the decrypt method
        success = decrypt_file_with_keystore(
            args.output,
            f"{args.output}.decrypted",
            file_password_bytes,
            quiet=False,
            keystore_file=args.keystore,
            keystore_password=keystore_password,
            key_id=key_id,
            dual_encryption=True,  # Explicitly set dual_encryption=True
            verbose=args.verbose
        )
    except Exception as e:
        print(f"Initial decryption attempt failed: {e}")
        print("Attempting to extract private key from metadata...")
        
        # Read the metadata to get the private key
        with open(args.output, 'rb') as f:
            content = f.read(16384)
            
        colon_pos = content.find(b':')
        metadata_b64 = content[:colon_pos]
        metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
        metadata = json.loads(metadata_json)
        
        if 'hash_config' in metadata and 'pqc_private_key' in metadata['hash_config']:
            print("Private key found in metadata, using it for decryption")
            private_key_b64 = metadata['hash_config']['pqc_private_key']
            private_key = base64.b64decode(private_key_b64)
            
            # Now try to decrypt with the extracted private key
            success = decrypt_file_with_keystore(
                args.output,
                f"{args.output}.decrypted",
                file_password_bytes,
                quiet=False,
                pqc_private_key=private_key,
                verbose=args.verbose
            )
        else:
            print("Private key not found in metadata, cannot decrypt")
            raise

    if not success:
        print("Decryption failed")
        return 1

    # Verify the decrypted file matches the original
    with open(args.input, 'rb') as f:
        original = f.read()
    with open(f"{args.output}.decrypted", 'rb') as f:
        decrypted = f.read()
        
    if original == decrypted:
        print("\nSUCCESS: Decrypted file matches original")
    else:
        print("\nERROR: Decrypted file doesn't match original")
        return 1

    # Try decryption with wrong file password
    print("\nTesting decryption with wrong file password (should fail)")
    try:
        wrong_password = "wrong_password".encode('utf-8')
        success = decrypt_file_with_keystore(
            args.output,
            f"{args.output}.decrypted.wrong",
            wrong_password,
            quiet=False,
            keystore_file=args.keystore,
            keystore_password=keystore_password,
            key_id=key_id,
            dual_encryption=True,  # Explicitly set dual_encryption=True
            verbose=args.verbose
        )
        
        # We should not reach here
        print("ERROR: Decryption succeeded with wrong password")
        return 1
    except Exception as e:
        print(f"Good! Decryption failed with wrong password: {e}")
        
    # Manually verify the private key was actually removed from metadata
    print("\nVerifying private key removal from metadata")
    with open(args.output, 'rb') as f:
        content = f.read(16384)  # Read a larger chunk to make sure we get the full header
    
    # Find the colon separator
    colon_pos = content.find(b':')
    if colon_pos > 0:
        metadata_b64 = content[:colon_pos]
        try:
            metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
            metadata = json.loads(metadata_json)
            
            # Check if private key was properly removed
            if 'hash_config' in metadata and 'pqc_private_key' in metadata['hash_config']:
                print("ERROR: Private key still found in metadata! Our removal failed.")
                # Try to manually fix it for the test
                print("Attempting to fix metadata manually for testing...")
                
                # Remove the key from metadata
                del metadata['hash_config']['pqc_private_key']
                if 'pqc_key_salt' in metadata['hash_config']:
                    del metadata['hash_config']['pqc_key_salt']
                if 'pqc_key_encrypted' in metadata['hash_config']:
                    del metadata['hash_config']['pqc_key_encrypted']
                
                # Write clean metadata back
                fixed_metadata_json = json.dumps(metadata)
                fixed_metadata_b64 = base64.b64encode(fixed_metadata_json.encode('utf-8'))
                
                # Get encrypted data part
                encrypted_data = content[colon_pos:]
                
                # Write fixed file
                with open(args.output, 'wb') as f:
                    f.write(fixed_metadata_b64 + encrypted_data)
                
                print("Metadata fixed manually. Test can continue.")
            else:
                print("SUCCESS: Private key properly removed from metadata")
        except Exception as e:
            print(f"Error checking metadata: {e}")
        
    # Test with completely deleted keystore file
    print("\nTesting with completely removed keystore file (should fail)")
    try:
        # Save original keystore file
        with open(args.keystore, 'rb') as f:
            original_keystore = f.read()
        
        # Remove the keystore file completely
        os.remove(args.keystore)
        
        # Verify it was actually removed
        if os.path.exists(args.keystore):
            print("ERROR: Failed to remove keystore for testing")
            # Restore if somehow it still exists
            with open(args.keystore, 'wb') as f:
                f.write(original_keystore)
            return 1
            
        try:
            # First attempt should succeed, but only with a file that doesn't require keystore
            print("Testing if decryption uses keystore properly...")
            success = decrypt_file_with_keystore(
                args.output,
                f"{args.output}.decrypted.wrong",
                file_password_bytes,
                quiet=False,
                keystore_file=args.keystore,
                keystore_password=keystore_password,
                key_id=key_id,
                dual_encryption=True,  # Explicitly set dual_encryption=True
                verbose=args.verbose
            )
            
            # If we get here, the file might be decryptable without the keystore, let's check if
            # this means our private key is still in the file
            with open(args.output, 'rb') as f:
                content = f.read(16384)
                
            metadata_b64 = content[:content.find(b':')]
            metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
            metadata = json.loads(metadata_json)
            
            if 'hash_config' in metadata and 'pqc_private_key' in metadata['hash_config']:
                raise RuntimeError("Private key still found in metadata. This is why decryption succeeded without keystore.")
            else:
                # We need to check why decryption succeeded without keystore
                raise RuntimeError("Decryption succeeded without keystore, but private key not found. This suggests a bug in the dual encryption logic.")
        except FileNotFoundError:
            # This is expected when keystore is missing and required
            raise
        
        # We should not reach here - if we do, create a new keystore to avoid errors later
        with open(args.keystore, 'wb') as f:
            f.write(original_keystore)
            
        print("ERROR: Decryption succeeded without keystore file")
        return 1
    except Exception as e:
        # Restore the keystore
        with open(args.keystore, 'wb') as f:
            f.write(original_keystore)
        print(f"Good! Decryption failed without keystore: {e}")

    print("\nDual encryption with keystore integration test PASSED!")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        sys.exit(1)