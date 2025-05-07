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
    pqc_dual_encryption: bool = False,  # For backward compatibility, prefer using dual_encryption
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
        pqc_dual_encryption: Whether to use dual encryption for PQC keys (requires both keystore and file passwords)
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
            
            # Add a password verification hash for later validation
            import hashlib
            # Generate a random salt for verification
            pw_verify_salt = os.urandom(16)
            # Create a hash of the password with the salt
            if isinstance(password, bytes):
                pw_verify_bytes = password
            else:
                pw_verify_bytes = password.encode('utf-8')
            pw_hash = hashlib.pbkdf2_hmac('sha256', pw_verify_bytes, pw_verify_salt, 10000)
            # Store in metadata (encoded as base64)
            hash_config_copy["pqc_dual_encrypt_verify_salt"] = base64.b64encode(pw_verify_salt).decode('utf-8')
            hash_config_copy["pqc_dual_encrypt_verify"] = base64.b64encode(pw_hash).decode('utf-8')
            if not quiet:
                print("Adding password verification hash to metadata")
    
    # Unify the dual encryption flags for consistency
    use_dual_encryption = dual_encryption or pqc_dual_encryption
    
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
        pqc_dual_encrypt_key=use_dual_encryption,  # Pass unified flag
        **kwargs
    )
    
    if not result:
        return False
        
    # If dual encryption is enabled for PQC keys, store the key in keystore and remove from metadata
    if use_dual_encryption and key_id is not None and keystore_file is not None:
        if not quiet:
            print("Storing PQC key in keystore and removing from metadata")
        
        try:
            # Read the metadata from the output file
            with open(output_file, 'rb') as f:
                content = f.read(8192)  # Read enough for the header
                
            # Find the colon separator
            colon_pos = content.find(b':')
            if colon_pos > 0:
                metadata_b64 = content[:colon_pos]
                encrypted_data = content[colon_pos:]
                
                try:
                    metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                    metadata = json.loads(metadata_json)
                    
                    # Check if the private key is in the metadata
                    if 'hash_config' in metadata and 'pqc_private_key' in metadata['hash_config']:
                        # Import the store_pqc_key_in_keystore function locally to avoid circular imports
                        from .keystore_utils import store_pqc_key_in_keystore
                        
                        # Store the key in the keystore
                        store_pqc_key_in_keystore(
                            metadata['hash_config'],
                            keystore_file,
                            keystore_password,
                            key_id=key_id,
                            quiet=quiet
                        )
                        
                        # Create a clean copy of the metadata to avoid any reference issues
                        import copy
                        clean_metadata = copy.deepcopy(metadata)
                        
                        # Remove the private key from the metadata using a completely new metadata object
                        # This approach avoids potential reference issues with nested structures
                        keys_to_remove = [
                            'pqc_private_key',
                            'pqc_key_salt',
                            'pqc_key_encrypted',
                            'pqc_private_key_embedded'  # Also remove this flag
                        ]
                        
                        # Create a completely new metadata object with only the fields we want to keep
                        clean_metadata = {
                            'format_version': metadata.get('format_version', 3),
                            'salt': metadata.get('salt', ''),
                            'hash_config': {},
                            'pbkdf2_iterations': metadata.get('pbkdf2_iterations', 100000),
                            'original_hash': metadata.get('original_hash', ''),
                            'encrypted_hash': metadata.get('encrypted_hash', ''),
                            'algorithm': metadata.get('algorithm', '')
                        }
                        
                        # Copy only the hash_config fields we want to keep
                        for k, v in metadata.get('hash_config', {}).items():
                            if k not in keys_to_remove:
                                clean_metadata['hash_config'][k] = v
                        
                        # Ensure the important flags are preserved
                        if 'hash_config' in metadata:
                            # Ensure dual encryption flags are consistent
                            if 'pqc_dual_encrypt_key' in metadata['hash_config'] or dual_encryption:
                                clean_metadata['hash_config']['dual_encryption'] = True
                            
                            # Ensure key ID is preserved
                            if 'pqc_keystore_key_id' in metadata['hash_config']:
                                clean_metadata['hash_config']['pqc_keystore_key_id'] = metadata['hash_config']['pqc_keystore_key_id']
                            
                            # Copy the public key
                            if 'pqc_public_key' in metadata['hash_config']:
                                clean_metadata['hash_config']['pqc_public_key'] = metadata['hash_config']['pqc_public_key']
                        
                        # Write the updated metadata back to the file
                        new_metadata_json = json.dumps(clean_metadata)
                        new_metadata_b64 = base64.b64encode(new_metadata_json.encode('utf-8'))
                        
                        with open(output_file, 'wb') as f:
                            f.write(new_metadata_b64)
                            f.write(encrypted_data)
                        
                        # Verify the keys were actually removed
                        with open(output_file, 'rb') as f:
                            verify_content = f.read(8192)
                            
                        verify_metadata_b64 = verify_content[:verify_content.find(b':')]
                        verify_metadata_json = base64.b64decode(verify_metadata_b64).decode('utf-8')
                        verify_metadata = json.loads(verify_metadata_json)
                        
                        if 'hash_config' in verify_metadata and any(key in verify_metadata['hash_config'] for key in keys_to_remove):
                            if not quiet:
                                print("WARNING: Some sensitive keys still in metadata. Trying one more approach...")
                            
                            # If some keys are still in metadata, build an even more minimal metadata
                            minimal_metadata = {
                                'format_version': metadata.get('format_version', 3),
                                'salt': metadata.get('salt', ''),
                                'hash_config': {
                                    'dual_encryption': True,
                                    'pqc_keystore_key_id': key_id
                                },
                                'pbkdf2_iterations': metadata.get('pbkdf2_iterations', 100000),
                                'original_hash': metadata.get('original_hash', ''),
                                'encrypted_hash': metadata.get('encrypted_hash', ''),
                                'algorithm': metadata.get('algorithm', '')
                            }
                            
                            # Add password verification fields if they exist
                            if 'pqc_dual_encrypt_verify' in metadata.get('hash_config', {}) and 'pqc_dual_encrypt_verify_salt' in metadata.get('hash_config', {}):
                                minimal_metadata['hash_config']['pqc_dual_encrypt_verify'] = metadata['hash_config']['pqc_dual_encrypt_verify']
                                minimal_metadata['hash_config']['pqc_dual_encrypt_verify_salt'] = metadata['hash_config']['pqc_dual_encrypt_verify_salt']
                            
                            # Add public key if it exists
                            if 'pqc_public_key' in metadata.get('hash_config', {}):
                                minimal_metadata['hash_config']['pqc_public_key'] = metadata['hash_config']['pqc_public_key']
                            
                            # Write the minimal metadata
                            minimal_metadata_json = json.dumps(minimal_metadata)
                            minimal_metadata_b64 = base64.b64encode(minimal_metadata_json.encode('utf-8'))
                            
                            with open(output_file, 'wb') as f:
                                f.write(minimal_metadata_b64)
                                f.write(encrypted_data)
                            
                            # One more verification
                            with open(output_file, 'rb') as f:
                                final_content = f.read(8192)
                            
                            final_metadata_b64 = final_content[:final_content.find(b':')]
                            final_metadata_json = base64.b64decode(final_metadata_b64).decode('utf-8')
                            final_metadata = json.loads(final_metadata_json)
                            
                            if 'hash_config' in final_metadata and any(key in final_metadata['hash_config'] for key in keys_to_remove):
                                if not quiet:
                                    print("WARNING: Unable to completely remove private key from metadata!")
                            
                        if not quiet:
                            print("Successfully stored PQC key in keystore and removed from metadata")
                except Exception as e:
                    if not quiet:
                        print(f"Warning: Error processing metadata: {e}")
        except Exception as e:
            if not quiet:
                print(f"Warning: Error storing PQC key in keystore: {e}")
                print("Continuing with the private key stored in metadata for safety")
    
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
    
    # If dual encryption is enabled, verify the file password using the hash in metadata
    if dual_encryption:
        try:
            # Read the metadata again (or use what we already read)
            if not 'metadata' in locals() or metadata is None:
                with open(input_file, 'rb') as f:
                    content = f.read(8192)  # Read enough for the header
                
                # Find the colon separator
                colon_pos = content.find(b':')
                if colon_pos > 0:
                    metadata_b64 = content[:colon_pos]
                    metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                    metadata = json.loads(metadata_json)
            
            # First check if we have a valid password
            if password is None:
                if not quiet:
                    print("ERROR: No password provided for dual-encrypted file")
                raise ValueError("File password is required for dual-encrypted files")
                
            # Convert string password to bytes if needed
            pw_verify_bytes = password
            if isinstance(password, str):
                pw_verify_bytes = password.encode('utf-8')
            
            # Validate password length
            if len(pw_verify_bytes) < 8:  # Require at least 8 characters
                if not quiet:
                    print("ERROR: File password is too short for dual-encryption (minimum 8 characters)")
                raise ValueError("File password is too short for dual-encryption")
            
            # Check for password verification fields
            if ('hash_config' in metadata and 
                'pqc_dual_encrypt_verify' in metadata['hash_config'] and
                'pqc_dual_encrypt_verify_salt' in metadata['hash_config']):
                
                # Get stored values
                verify_hash = base64.b64decode(metadata['hash_config']['pqc_dual_encrypt_verify'])
                verify_salt = base64.b64decode(metadata['hash_config']['pqc_dual_encrypt_verify_salt'])
                
                # Calculate hash with current password
                import hashlib
                current_pw_hash = hashlib.pbkdf2_hmac('sha256', pw_verify_bytes, verify_salt, 10000)
                
                # Verify hash matches - use constant-time comparison to prevent timing attacks
                import hmac
                if not hmac.compare_digest(current_pw_hash, verify_hash):
                    if not quiet:
                        print("Password verification failed - incorrect file password")
                    raise ValueError("Invalid file password for dual-encrypted file")
                elif not quiet:
                    print("File password verification successful")
            else:
                # No verification fields in metadata - unusual for dual encryption
                if not quiet:
                    print("WARNING: Dual encryption flag set but no password verification data found in metadata")
                    print("Password verification skipped - proceeding with provided password")
                    
        except ValueError as ve:
            # Re-raise these as they're expected for validation failures
            raise ve
        except Exception as e:
            if not quiet:
                print(f"Warning: Error in password verification: {e}")
    
    # If key_id is not provided, try to extract it from metadata
    if key_id is None and keystore_file is not None:
        extracted_key_id = extract_key_id_from_metadata(input_file, not quiet)
        
        if extracted_key_id:
            if not quiet:
                print(f"Using key ID from metadata: {extracted_key_id}")
            key_id = extracted_key_id
        elif not quiet:
            # Key ID wasn't found in metadata
            if key_id:
                print(f"No key ID found in metadata, using specified key ID: {key_id}")
            else:
                # Try to load keystore and check if there's only one key
                try:
                    from .keystore_cli import PQCKeystore
                    keystore = PQCKeystore(keystore_file)
                    
                    # If no keystore password provided, prompt for it
                    if keystore_password is None:
                        keystore_password = getpass.getpass("Enter keystore password: ")
                    
                    keystore.load_keystore(keystore_password)
                    keys = keystore.list_keys()
                    
                    if len(keys) == 1:
                        key_id = keys[0]["key_id"]
                        print(f"No key ID found in metadata, but only one key in keystore. Using key ID: {key_id}")
                    elif len(keys) > 1:
                        print(f"No key ID found in metadata. Multiple keys in keystore ({len(keys)}). Please specify using --key-id parameter.")
                        # Can optionally list available keys here
                        if not quiet:
                            print("Available keys:")
                            for k in keys:
                                print(f"  - {k['key_id']} ({k.get('algorithm', 'unknown')})")
                    else:
                        print("No key ID found in metadata and no keys in keystore. Please specify using --key-id parameter.")
                except Exception as e:
                    print(f"No key ID found in metadata. Please specify using --key-id parameter. (Error loading keystore: {e})")
    
    # If we have a keystore and key ID, get the private key
    if key_id is not None and keystore_file is not None:
        from .keystore_cli import PQCKeystore, KeyNotFoundError
        import getpass
        
        # Check if keystore file exists
        if not os.path.exists(keystore_file):
            if not quiet:
                print(f"Error: Keystore file not found at {keystore_file}")
            if dual_encryption:
                raise ValueError(f"Keystore not found at {keystore_file}")
        else:
            try:
                keystore = PQCKeystore(keystore_file)
                
                # If no keystore password provided, prompt for it
                if keystore_password is None:
                    keystore_password = getpass.getpass("Enter keystore password: ")
                
                keystore.load_keystore(keystore_password)
                
                # Debug - print keys in keystore
                if kwargs.get('verbose', False):
                    try:
                        keys = keystore.list_keys()
                        if not quiet:
                            print(f"Keys in keystore: {len(keys)}")
                            for k in keys:
                                print(f"  - {k['key_id']} ({k.get('algorithm', 'unknown')})")
                                
                        # Check if key ID exists
                        if key_id not in [k["key_id"] for k in keys]:
                            if not quiet:
                                print(f"Key ID {key_id} not found in keystore")
                    except Exception as le:
                        if not quiet and kwargs.get('verbose', False):
                            print(f"Error listing keys: {le}")
                
                # Determine if we need to pass the file password for dual encryption
                file_password_for_key = None
                if dual_encryption:
                    # For dual-encrypted keys, we need to pass the file password
                    if isinstance(password, bytes):
                        # Convert bytes to string if needed
                        try:
                            file_password_for_key = password.decode('utf-8')
                        except UnicodeDecodeError:
                            # If we can't decode as UTF-8, use as bytes
                            file_password_for_key = password
                    else:
                        file_password_for_key = password
                    
                    if not quiet:
                        print(f"Using file password for dual-encrypted key")
                        
                    # Verify the file password format
                    if not file_password_for_key:
                        raise ValueError("File password is required for dual-encrypted files")
                
                # Get the key with file password for dual encryption
                try:
                    _, private_key = keystore.get_key(key_id, None, file_password_for_key)
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
                # Re-raise for dual-encrypted files that require keystore access
                if dual_encryption:
                    raise ValueError("Failed to retrieve key from keystore for dual-encrypted file")
    
    # First check if we need a keystore but couldn't get the key
    if dual_encryption and key_id is not None and key_id != "EMBEDDED_PRIVATE_KEY" and pqc_private_key is None:
        if not keystore_file or not os.path.exists(keystore_file):
            if not quiet:
                print("ERROR: This file requires a keystore for decryption but no valid keystore was provided.")
            raise ValueError(f"Keystore not found at {keystore_file}")
        if not quiet:
            print("ERROR: Unable to retrieve key from keystore. Make sure both keystore and file passwords are correct.")
        raise ValueError("Failed to retrieve key from keystore for dual-encrypted file")
        
    # Check if we have the pqc_private_key before proceeding
    if dual_encryption and key_id is not None and key_id != "EMBEDDED_PRIVATE_KEY" and pqc_private_key is None:
        if not quiet:
            print("ERROR: This file is dual-encrypted but no private key was found.")
        raise ValueError("Unable to retrieve private key for dual-encrypted file")
    
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
        
        # If this was a dual-encrypted file and we succeeded without keystore access,
        # this suggests the private key is still in the metadata - raise an error
        if dual_encryption and keystore_file is not None and not os.path.exists(keystore_file) and result:
            if not quiet:
                print("WARNING: Decryption succeeded without keystore. This suggests the private key is still in the metadata.")
            raise ValueError("Decryption succeeded without keystore, but private key not found. This suggests a bug in the dual encryption logic.")
            
        return result
    except Exception as e:
        error_msg = str(e).lower()
        # Check if this might be a password error from dual encryption
        if dual_encryption and (
            "invalid input" in error_msg or 
            "invalid parameter" in error_msg or
            "decryption failed" in error_msg or
            "invalid file password" in error_msg or
            "mac" in error_msg or
            "verification" in error_msg
        ):
            if not quiet:
                print(f"Decryption failed - possible invalid file password: {e}")
            raise ValueError(f"Invalid file password for dual-encrypted file: {e}")
        else:
            # Re-raise the original error
            raise