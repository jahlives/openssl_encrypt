#!/usr/bin/env python3
"""
Direct fix for keystore password prompting
"""

import os
import sys
import getpass
import json
import base64
import uuid

def extract_key_id_from_metadata(encrypted_file, verbose=False):
    """
    Extract the key ID from an encrypted file's metadata
    """
    try:
        with open(encrypted_file, 'rb') as f:
            data = f.read(3000)  # Read enough for the header
        
        colon_pos = data.find(b':')
        if colon_pos > 0:
            metadata_b64 = data[:colon_pos]
            try:
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                
                # First try direct JSON parsing
                try:
                    metadata = json.loads(metadata_json)
                    if 'hash_config' in metadata and 'pqc_keystore_key_id' in metadata['hash_config']:
                        key_id = metadata['hash_config']['pqc_keystore_key_id']
                        if verbose:
                            print(f"Found key ID in metadata JSON: {key_id}")
                        return key_id
                except json.JSONDecodeError:
                    if verbose:
                        print("JSON parsing failed, trying regex")
                
                # Fall back to regex for UUID pattern
                import re
                uuid_pattern = r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'
                matches = re.findall(uuid_pattern, metadata_json)
                
                if matches:
                    # In case of multiple matches, prefer one that's after "pqc_keystore_key_id"
                    for i in range(len(metadata_json) - 20):
                        if metadata_json[i:i+20].find("pqc_keystore_key_id") >= 0:
                            # Found the key, now see which UUID is closest after this position
                            for match in matches:
                                if metadata_json[i:].find(match) >= 0:
                                    if verbose:
                                        print(f"Found key ID using regex: {match}")
                                    return match
                    
                    # If we couldn't find one after the key name, just return the first match
                    if verbose:
                        print(f"Found potential key ID: {matches[0]}")
                    return matches[0]
            except Exception as e:
                if verbose:
                    print(f"Error decoding metadata: {e}")
    except Exception as e:
        if verbose:
            print(f"Error reading file: {e}")
    
    return None

def main():
    # Validate command-line arguments
    if len(sys.argv) < 3:
        print("Usage: python keystore_password_fix.py <encrypted_file> <keystore_file>")
        return 1
    
    encrypted_file = sys.argv[1]
    keystore_file = sys.argv[2]
    
    if not os.path.exists(encrypted_file):
        print(f"Error: Encrypted file {encrypted_file} does not exist")
        return 1
    
    if not os.path.exists(keystore_file):
        print(f"Error: Keystore file {keystore_file} does not exist")
        return 1
    
    # Extract key ID from metadata
    key_id = extract_key_id_from_metadata(encrypted_file, verbose=True)
    
    if not key_id:
        print("Error: Could not extract key ID from metadata")
        return 1
    
    # Prompt for passwords
    file_password = getpass.getpass("Enter file password: ")
    keystore_password = getpass.getpass("Enter keystore password: ")
    
    # Run the decrypt command with all required parameters
    import subprocess
    
    output_file = encrypted_file + ".dec"
    
    cmd = [
        "python", "-m", "openssl_encrypt.crypt", "decrypt",
        "-i", encrypted_file,
        "-o", output_file,
        "--keystore", keystore_file,
        "--keystore-password", keystore_password,
        "--key-id", key_id,
        "--password", file_password
    ]
    
    print("Running decryption command with explicit parameters...")
    
    result = subprocess.run(cmd)
    
    if result.returncode == 0:
        print(f"✅ Decryption successful! Output file: {output_file}")
        
        # Display the decrypted content
        with open(output_file, 'r') as f:
            content = f.read()
        
        print("\nDecrypted content:")
        print("="*40)
        print(content)
        print("="*40)
    else:
        print(f"❌ Decryption failed with return code {result.returncode}")
    
    return result.returncode

if __name__ == "__main__":
    sys.exit(main())