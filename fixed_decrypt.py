#!/usr/bin/env python3
"""
Fixed script for decrypting files with long metadata
"""

import os
import sys
import json
import base64
import getpass
import argparse
from typing import Optional

def extract_key_id_from_metadata(encrypted_file, verbose=True):
    """Extract key ID from encrypted file metadata with robust colon detection"""
    if verbose:
        print(f"Extracting key ID from metadata: {encrypted_file}")
    
    try:
        # Read more data to ensure we capture the full metadata
        with open(encrypted_file, 'rb') as f:
            data = f.read(4096)  # Increased from 3000 to 4096 to handle longer metadata
        
        if verbose:
            print(f"Read {len(data)} bytes from file")
        
        # Find the colon separator - search the entire buffer
        colon_pos = data.find(b':')
        if colon_pos > 0:
            if verbose:
                print(f"Found colon separator at position {colon_pos}")
            
            metadata_b64 = data[:colon_pos]
            if verbose:
                print(f"Extracted base64 metadata ({len(metadata_b64)} bytes)")
            
            try:
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                if verbose:
                    print(f"Successfully decoded metadata JSON ({len(metadata_json)} chars)")
                
                # Try JSON parsing first
                try:
                    metadata = json.loads(metadata_json)
                    if verbose:
                        print(f"Successfully parsed metadata as JSON")
                    
                    if 'hash_config' in metadata and 'pqc_keystore_key_id' in metadata['hash_config']:
                        key_id = metadata['hash_config']['pqc_keystore_key_id']
                        if verbose:
                            print(f"Found key ID in hash_config: {key_id}")
                        return key_id
                except json.JSONDecodeError as e:
                    if verbose:
                        print(f"JSON parsing failed: {e}")
                
                # Fallback to regex for UUID pattern
                import re
                uuid_pattern = r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'
                matches = re.findall(uuid_pattern, metadata_json)
                
                if matches:
                    if verbose:
                        print(f"Found UUID matches: {matches}")
                    
                    # Try to find the one associated with the key ID
                    key_id_pos = metadata_json.find("pqc_keystore_key_id")
                    if key_id_pos >= 0:
                        for match in matches:
                            if metadata_json.find(match, key_id_pos) >= 0:
                                if verbose:
                                    print(f"Found key ID using position search: {match}")
                                return match
                    
                    # If no specific match found, return the first one
                    if verbose:
                        print(f"Using first UUID as key ID: {matches[0]}")
                    return matches[0]
            except Exception as e:
                if verbose:
                    print(f"Error processing metadata: {e}")
        else:
            if verbose:
                print("No colon separator found in file")
    except Exception as e:
        if verbose:
            print(f"Error reading file: {e}")
    
    return None

def decrypt_file_with_keystore(input_file, output_file, file_password, keystore_file, keystore_password, key_id=None, verbose=False):
    """Decrypt a file using a key from the keystore"""
    try:
        # Import necessary modules
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from openssl_encrypt.modules.keystore_cli import PQCKeystore
        from openssl_encrypt.modules.crypt_core import decrypt_file
        
        # Extract key ID if not provided
        if not key_id:
            key_id = extract_key_id_from_metadata(input_file, verbose)
            
        if not key_id:
            print(f"Error: Could not extract key ID from file metadata")
            return False
        
        if verbose:
            print(f"Using key ID: {key_id}")
        
        # Load keystore and get key
        keystore = PQCKeystore(keystore_file)
        keystore.load_keystore(keystore_password)
        
        # Get key from keystore
        try:
            _, private_key = keystore.get_key(key_id)
            if verbose:
                print(f"Successfully retrieved key from keystore")
        except Exception as e:
            print(f"Error retrieving key from keystore: {e}")
            return False
        
        # Decrypt the file
        success = decrypt_file(
            input_file,
            output_file,
            file_password,
            quiet=not verbose,
            verbose=verbose,
            pqc_private_key=private_key
        )
        
        if success:
            if verbose:
                print(f"Successfully decrypted file: {output_file}")
            return True
        else:
            if verbose:
                print(f"Decryption failed")
            return False
    
    except Exception as e:
        print(f"Error during decryption: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    parser = argparse.ArgumentParser(description="Decrypt files with PQC keystore")
    parser.add_argument("input_file", help="Encrypted input file")
    parser.add_argument("--output", "-o", help="Output file (default: input_file.dec)")
    parser.add_argument("--keystore", required=True, help="Keystore file")
    parser.add_argument("--password", help="File password")
    parser.add_argument("--keystore-password", help="Keystore password")
    parser.add_argument("--key-id", help="Specific key ID to use")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Set output file if not specified
    output_file = args.output or f"{args.input_file}.dec"
    
    # Get passwords if not provided
    file_password = args.password
    if not file_password:
        file_password = getpass.getpass("Enter file password: ")
    
    keystore_password = args.keystore_password
    if not keystore_password:
        keystore_password = getpass.getpass("Enter keystore password: ")
    
    # Convert string passwords to bytes if needed
    if isinstance(file_password, str):
        file_password = file_password.encode()
    
    # Decrypt the file
    success = decrypt_file_with_keystore(
        args.input_file, 
        output_file, 
        file_password, 
        args.keystore, 
        keystore_password, 
        args.key_id,
        args.verbose
    )
    
    if success:
        print(f"✅ Successfully decrypted file: {output_file}")
        
        # Display file content
        try:
            with open(output_file, 'r') as f:
                content = f.read()
            print(f"\nDecrypted content:\n{content}")
        except Exception:
            print("Note: Unable to display binary content")
    else:
        print(f"❌ Failed to decrypt file")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())