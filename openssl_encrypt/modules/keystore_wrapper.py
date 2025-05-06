#!/usr/bin/env python3
"""
Wrapper module for PQC keystore integration with crypt_core.py

This module provides enhanced versions of encrypt_file and decrypt_file
that ensure key IDs are properly stored in metadata for keystore integration.
"""

import base64
import json
import os
from typing import Dict, Any, Optional, Tuple, Union

from .crypt_core import encrypt_file as original_encrypt_file
from .crypt_core import decrypt_file as original_decrypt_file
from .keystore_utils import extract_key_id_from_metadata, get_pqc_key_for_decryption

def encrypt_file_with_keystore(
    input_file: str,
    output_file: str,
    password: Union[str, bytes],
    hash_config: Optional[Dict[str, Any]] = None,
    pbkdf2_iterations: int = 100000,
    quiet: bool = False,
    algorithm: str = "aes-gcm",
    pqc_keypair: Optional[Tuple[bytes, bytes]] = None,
    keystore_file: Optional[str] = None,
    keystore_password: Optional[str] = None,
    key_id: Optional[str] = None,
    dual_encryption: bool = False,
    **kwargs
) -> bool:
    """
    Enhanced version of encrypt_file that ensures key ID is properly stored in metadata
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        password: Password for encryption
        hash_config: Hash configuration
        pbkdf2_iterations: Number of PBKDF2 iterations
        quiet: Whether to suppress output
        algorithm: Encryption algorithm
        pqc_keypair: PQC key pair (public_key, private_key)
        keystore_file: Path to keystore file
        keystore_password: Password for keystore
        key_id: ID of the key to use from keystore
        dual_encryption: Whether to use dual encryption (requires both keystore and file passwords)
        **kwargs: Additional arguments for encrypt_file
        
    Returns:
        bool: Success or failure
    """
    # Create a copy of hash_config or initialize it with required fields
    if hash_config is None:
        hash_config = {
            "sha256": 0,
            "sha512": 0,
            "sha3_256": 0,
            "sha3_512": 0,
            "blake2b": 0,
            "shake256": 0,
            "whirlpool": 0,
            "scrypt": {"enabled": False},
            "argon2": {"enabled": False},
            "pbkdf2_iterations": pbkdf2_iterations
        }
    elif "pbkdf2_iterations" not in hash_config:
        hash_config["pbkdf2_iterations"] = pbkdf2_iterations
    
    hash_config_copy = hash_config.copy()
    
    # If we're using a keystore key, ensure the key ID is in hash_config
    if key_id is not None:
        if not quiet:
            print(f"Storing key ID in metadata: {key_id}")
        hash_config_copy["pqc_keystore_key_id"] = key_id
        
        # If dual encryption is enabled, set the flag in the metadata
        if dual_encryption:
            if not quiet:
                print("Setting dual encryption flag in metadata")
            hash_config_copy["dual_encryption"] = True
    
    # Call the original encrypt_file
    result = original_encrypt_file(
        input_file,
        output_file,
        password,
        hash_config=hash_config_copy,
        pbkdf2_iterations=pbkdf2_iterations,
        quiet=quiet,
        algorithm=algorithm,
        pqc_keypair=pqc_keypair,
        **kwargs
    )
    
    if not result:
        return False
    
    # Verify that the key ID and dual encryption flag are in the metadata
    if key_id is not None:
        # Open the encrypted file and check metadata
        with open(output_file, 'rb') as f:
            content = f.read(8192)  # Read enough for the header - increased for large keys
            
        # Find the colon separator
        colon_pos = content.find(b':')
        if colon_pos > 0:
            metadata_b64 = content[:colon_pos]
            try:
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                
                try:
                    metadata = json.loads(metadata_json)
                    need_update = False
                    
                    # Check if key ID is in metadata
                    if ('hash_config' in metadata and 
                        ('pqc_keystore_key_id' not in metadata['hash_config'] or 
                         metadata['hash_config']['pqc_keystore_key_id'] != key_id)):
                        
                        if not quiet:
                            print("Key ID not found in metadata, adding it manually")
                        
                        # Key ID is missing from metadata, add it
                        if 'hash_config' not in metadata:
                            metadata['hash_config'] = {}
                        
                        metadata['hash_config']['pqc_keystore_key_id'] = key_id
                        need_update = True
                    
                    # Check if dual_encryption flag is missing
                    if dual_encryption and ('hash_config' in metadata and 
                                          'dual_encryption' not in metadata['hash_config']):
                        if not quiet:
                            print("Dual encryption flag missing from metadata, adding it")
                        
                        if 'hash_config' not in metadata:
                            metadata['hash_config'] = {}
                        
                        metadata['hash_config']['dual_encryption'] = True
                        need_update = True
                    
                    # If we need to update the metadata, rewrite the file
                    if need_update:
                        # Convert back to JSON and base64
                        new_metadata_json = json.dumps(metadata)
                        new_metadata_b64 = base64.b64encode(new_metadata_json.encode('utf-8'))
                        
                        # Rewrite the file with updated metadata
                        with open(output_file, 'rb') as f:
                            full_content = f.read()
                            
                        with open(output_file, 'wb') as f:
                            f.write(new_metadata_b64)
                            f.write(full_content[colon_pos:])
                        
                        if not quiet:
                            if dual_encryption:
                                print("Updated metadata with key ID and dual encryption flag")
                            else:
                                print("Updated metadata with key ID")
                except json.JSONDecodeError:
                    if not quiet:
                        print("Warning: Could not parse metadata as JSON")
            except Exception as e:
                if not quiet:
                    print(f"Warning: Error checking metadata: {e}")
    
    # Verify with our extract function
    extracted_key_id = extract_key_id_from_metadata(output_file, False)
    if key_id is not None and extracted_key_id != key_id and not quiet:
        print(f"Warning: Key ID in metadata ({extracted_key_id}) " +
              f"doesn't match original key ID ({key_id})")
    
    return True

def decrypt_file_with_keystore(
    input_file: str,
    output_file: str,
    password: Union[str, bytes],
    quiet: bool = False,
    pqc_private_key: Optional[bytes] = None,
    keystore_file: Optional[str] = None,
    keystore_password: Optional[str] = None,
    key_id: Optional[str] = None,
    dual_encryption: bool = False,
    **kwargs
) -> bool:
    """
    Enhanced version of decrypt_file that automatically extracts key ID from metadata
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        password: Password for decryption
        quiet: Whether to suppress output
        pqc_private_key: PQC private key
        keystore_file: Path to keystore file
        keystore_password: Password for keystore
        key_id: ID of the key to use from keystore
        dual_encryption: Whether this file uses dual encryption
        **kwargs: Additional arguments for decrypt_file
        
    Returns:
        bool: Success or failure
    """
    # Check for dual encryption in metadata if not explicitly specified
    if not dual_encryption:
        # Check if this file uses dual encryption
        try:
            with open(input_file, 'rb') as f:
                content = f.read(8192)  # Read enough for the header
                
            # Find the colon separator
            colon_pos = content.find(b':')
            if colon_pos > 0:
                metadata_b64 = content[:colon_pos]
                try:
                    metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                    metadata = json.loads(metadata_json)
                    
                    # Check for dual encryption flag
                    if 'hash_config' in metadata and 'dual_encryption' in metadata['hash_config']:
                        dual_encryption = metadata['hash_config']['dual_encryption']
                        if dual_encryption and not quiet:
                            print("File uses dual encryption - requires both keystore and file passwords")
                except Exception:
                    pass  # Ignore parsing errors
        except Exception:
            pass  # Ignore file reading errors
    
    # If key_id is not provided, try to extract it from metadata
    if key_id is None and keystore_file is not None:
        extracted_key_id = extract_key_id_from_metadata(input_file, not quiet)
        
        if extracted_key_id:
            if not quiet:
                print(f"Using key ID from metadata: {extracted_key_id}")
            key_id = extracted_key_id
    
    # If we have a keystore and key ID, get the private key
    if key_id is not None and keystore_file is not None:
        from .keystore_cli import PQCKeystore
        import getpass
        
        try:
            keystore = PQCKeystore(keystore_file)
            
            # If no keystore password provided, prompt for it
            if keystore_password is None:
                keystore_password = getpass.getpass("Enter keystore password: ")
            
            keystore.load_keystore(keystore_password)
            
            # Determine if we need to pass the file password for dual encryption
            file_password = None
            if dual_encryption:
                # For dual-encrypted keys, we need to pass the file password
                if isinstance(password, bytes):
                    # Convert bytes to string if needed
                    try:
                        file_password = password.decode('utf-8')
                    except UnicodeDecodeError:
                        # If we can't decode as UTF-8, use as bytes
                        file_password = password
                else:
                    file_password = password
                
                if not quiet:
                    print(f"Using file password for dual-encrypted key")
                    
                # Verify the file password format
                if not file_password:
                    raise ValueError("File password is required for dual-encrypted files")
            
            # Get the key with or without file password for dual encryption
            try:
                _, private_key = keystore.get_key(key_id, None, file_password)
            except Exception as e:
                error_msg = str(e).lower()
                # Check for various password/decryption error messages
                if dual_encryption and ("incorrect file password" in error_msg or 
                                       "invalid" in error_msg or 
                                       "failed to handle dual encryption" in error_msg or
                                       "could not decrypt" in error_msg):
                    # This is an expected error for incorrect file passwords with dual encryption
                    if not quiet:
                        print(f"Dual encryption verification failed: {e}")
                    raise ValueError(f"Invalid file password for dual-encrypted key: {e}")
                else:
                    # Pass through other errors
                    raise
            
            if not quiet:
                print(f"Retrieved private key for key ID {key_id} from keystore")
                if dual_encryption:
                    print("Key successfully decrypted with both keystore and file passwords")
            
            pqc_private_key = private_key
        except Exception as e:
            if not quiet:
                print(f"Error retrieving key from keystore: {e}")
    
    # Call the original decrypt_file with improved error handling
    try:
        result = original_decrypt_file(
            input_file,
            output_file,
            password,
            quiet=quiet,
            pqc_private_key=pqc_private_key,
            **kwargs
        )
        return result
    except Exception as e:
        error_msg = str(e).lower()
        # Check if this might be a password error from dual encryption
        if dual_encryption and ("invalid input" in error_msg or 
                               "invalid parameter" in error_msg or
                               "decryption failed" in error_msg):
            if not quiet:
                print(f"Decryption failed - possible invalid file password: {e}")
            raise ValueError(f"Invalid file password for dual-encrypted key: {e}")
        else:
            # Re-raise the original error
            raise