#!/usr/bin/env python3
"""
Utility functions for PQC keystore operations
"""

import os
import json
import base64
import getpass
import logging
from typing import Dict, Any, Tuple, Optional

# Set up module-level logger
logger = logging.getLogger(__name__)

def extract_key_id_from_metadata(encrypted_file: str, verbose: bool = False) -> Optional[str]:
    """
    Extract PQC keystore key ID from encrypted file metadata
    
    Args:
        encrypted_file: Path to the encrypted file
        verbose: Whether to print verbose output
        
    Returns:
        Optional[str]: The key ID if found, None otherwise
    """
    try:
        with open(encrypted_file, 'rb') as f:
            data = f.read(8192)  # Read enough for the header - increased to 8KB for large PQC keys
        
        # Find the colon separator
        colon_pos = data.find(b':')
        if colon_pos > 0:
            metadata_b64 = data[:colon_pos]
            try:
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                
                # First try direct JSON parsing
                try:
                    metadata = json.loads(metadata_json)
                    format_version = metadata.get('format_version', 1)
                    
                    # Handle format_version 5
                    if format_version == 5:
                        # Format version 5 follows the same structure as v4, look in derivation_config.kdf_config
                        if ('derivation_config' in metadata and 
                            'kdf_config' in metadata['derivation_config'] and 
                            'pqc_keystore_key_id' in metadata['derivation_config']['kdf_config']):
                            key_id = metadata['derivation_config']['kdf_config']['pqc_keystore_key_id']
                            if verbose:
                                logger.info(f"Found key ID in format version 5 metadata derivation_config: {key_id}")
                            return key_id
                        # Also check for dual_encryption flag in kdf_config
                        elif ('derivation_config' in metadata and 
                              'kdf_config' in metadata['derivation_config'] and 
                              'dual_encryption' in metadata['derivation_config']['kdf_config'] and
                              metadata['derivation_config']['kdf_config']['dual_encryption']):
                            if verbose:
                                logger.info("Found dual_encryption flag in format version 5 metadata")
                        # Check in the root level hash_config for backward compatibility
                        elif 'hash_config' in metadata and 'pqc_keystore_key_id' in metadata['hash_config']:
                            key_id = metadata['hash_config']['pqc_keystore_key_id']
                            if verbose:
                                logger.info(f"Found key ID in format version 5 legacy location: {key_id}")
                            return key_id
                    # Handle format_version 4
                    elif format_version == 4:
                        # First check in derivation_config.kdf_config
                        if ('derivation_config' in metadata and 
                            'kdf_config' in metadata['derivation_config'] and 
                            'pqc_keystore_key_id' in metadata['derivation_config']['kdf_config']):
                            key_id = metadata['derivation_config']['kdf_config']['pqc_keystore_key_id']
                            if verbose:
                                logger.info(f"Found key ID in format version 4 metadata derivation_config: {key_id}")
                            return key_id
                        # Also check for dual_encryption flag in kdf_config
                        elif ('derivation_config' in metadata and 
                              'kdf_config' in metadata['derivation_config'] and 
                              'dual_encryption' in metadata['derivation_config']['kdf_config'] and
                              metadata['derivation_config']['kdf_config']['dual_encryption']):
                            if verbose:
                                logger.info("Found dual_encryption flag in format version 4 metadata")
                        # Check in the root level hash_config for backward compatibility
                        elif 'hash_config' in metadata and 'pqc_keystore_key_id' in metadata['hash_config']:
                            key_id = metadata['hash_config']['pqc_keystore_key_id']
                            if verbose:
                                logger.info(f"Found key ID in format version 4 legacy location: {key_id}")
                            return key_id
                    # Handle format_version 1-3
                    elif 'hash_config' in metadata and 'pqc_keystore_key_id' in metadata['hash_config']:
                        key_id = metadata['hash_config']['pqc_keystore_key_id']
                        if verbose:
                            logger.info(f"Found key ID in metadata JSON: {key_id}")
                        return key_id
                except json.JSONDecodeError:
                    if verbose:
                        logger.info("JSON parsing failed, trying regex")
                
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
                                        logger.info(f"Found key ID using regex: {match}")
                                    return match
                    
                    # If we couldn't find one after the key name, just return the first match
                    if verbose:
                        logger.info(f"Found potential key ID: {matches[0]}")
                    return matches[0]
            except Exception as e:
                if verbose:
                    logger.info(f"Error decoding metadata: {e}")
        
        # Fall back to legacy OSENC format
        header_start = data.find(b'OSENC')
        if header_start >= 0:
            header_end = data.find(b'HEND')
            if header_end > header_start:
                header_json = data[header_start+5:header_end].decode('utf-8')
                try:
                    header_config = json.loads(header_json)
                    
                    # Extract key ID from hash_config
                    if 'hash_config' in header_config:
                        key_id = header_config['hash_config'].get('pqc_keystore_key_id')
                        if key_id and verbose:
                            print(f"Found key ID in metadata: {key_id}")
                        return key_id
                except Exception as e:
                    if verbose:
                        logger.info(f"Error parsing legacy header JSON: {e}")
    except Exception as e:
        if verbose:
            logger.info(f"Error extracting key ID from metadata: {e}")
    
    # Check for embedded private key
    try:
        with open(encrypted_file, 'rb') as f:
            header_data = f.read(8192)  # Read enough for header with embedded key - increased to 8KB for large PQC keys
            
        # Try to detect if there's an embedded private key
        try:
            parts = header_data.split(b':', 1)
            if len(parts) > 1:
                metadata_b64 = parts[0]
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                
                try:
                    header_config = json.loads(metadata_json)
                    format_version = header_config.get('format_version', 1)
                    
                    # Handle format_version 4
                    if format_version == 4:
                        # Check if there's a PQC public key in the metadata
                        if ('encryption' in header_config and 'pqc_public_key' in header_config['encryption']):
                            # This file has an embedded public key, which means it might have an embedded private key
                            if verbose:
                                logger.info("Found embedded PQC public key in format v4 metadata")
                            
                            # Check for embedded private key
                            if 'pqc_private_key' in header_config['encryption']:
                                # Check for embedded private key marker
                                private_key_marker = header_config['encryption'].get('pqc_private_key_embedded')
                                if private_key_marker:
                                    if verbose:
                                        logger.info("File has embedded private key")
                                    return "EMBEDDED_PRIVATE_KEY"
                    # Handle format_version 1-3
                    elif 'hash_config' in header_config and 'pqc_public_key' in header_config['hash_config']:
                        # This file has an embedded public key, which means it might have an embedded private key
                        if verbose:
                            logger.info("Found embedded PQC public key in metadata")
                        
                        # Check for embedded private key marker
                        private_key_marker = header_config['hash_config'].get('pqc_private_key_embedded')
                        if private_key_marker:
                            if verbose:
                                logger.info("File has embedded private key")
                            return "EMBEDDED_PRIVATE_KEY"
                except json.JSONDecodeError:
                    # If we can't parse as JSON but there's a match for private key
                    if metadata_json.find("pqc_private_key_embedded") >= 0:
                        if verbose:
                            logger.info("Found embedded private key indicator")
                        return "EMBEDDED_PRIVATE_KEY"
        except Exception as e:
            if verbose:
                logger.info(f"Error checking for embedded private key: {e}")
                
    except Exception as e:
        if verbose:
            logger.info(f"Error checking for embedded key: {e}")
    
    return None

def get_keystore_password(args) -> str:
    """
    Get keystore password from command-line arguments or prompt
    
    Args:
        args: Command-line arguments
        
    Returns:
        str: Keystore password
    """
    # Check if a password is provided in the arguments
    if hasattr(args, 'keystore_password') and args.keystore_password:
        return args.keystore_password
        
    # Check if a password file is provided
    if hasattr(args, 'keystore_password_file') and args.keystore_password_file:
        try:
            with open(args.keystore_password_file, 'r') as f:
                return f.read().strip()
        except Exception as e:
            if not getattr(args, 'quiet', False):
                print(f"Warning: Failed to read keystore password from file: {e}")
    
    # For decryption operations, we should always prompt for a separate keystore password
    # rather than reusing the file password, as they could be different
    
    # Prompt user for password (always prompt for keystore operations to ensure we get the right password)
    return getpass.getpass("Enter keystore password: ")

def get_pqc_key_for_decryption(args, hash_config=None, metadata=None):
    """
    Get PQC key for decryption, checking keystore if available
    
    Args:
        args: Command-line arguments
        hash_config: Hash configuration with possible key ID
        metadata: Full metadata if available (for format version 4 support)
        
    Returns:
        tuple: (pqc_keypair, pqc_private_key, key_id)
    """
    # Initialize variables
    pqc_keypair = None
    pqc_private_key = None
    key_id = None
    format_version = 3  # Default to format version 3
    
    # Determine format version if metadata is provided
    if metadata:
        format_version = metadata.get('format_version', 3)
    
    # Check if we have a key ID in the hash_config or metadata
    if format_version == 5 and metadata:
        # Check for key ID in format version 5 structure (same as v4)
        if ('derivation_config' in metadata and 
            'kdf_config' in metadata['derivation_config'] and 
            'pqc_keystore_key_id' in metadata['derivation_config']['kdf_config']):
            key_id = metadata['derivation_config']['kdf_config']['pqc_keystore_key_id']
            if not getattr(args, 'quiet', False):
                print(f"Found key ID in metadata derivation_config (v5): {key_id}")
    elif format_version == 4 and metadata:
        # Check for key ID in format version 4 structure
        if ('derivation_config' in metadata and 
            'kdf_config' in metadata['derivation_config'] and 
            'pqc_keystore_key_id' in metadata['derivation_config']['kdf_config']):
            key_id = metadata['derivation_config']['kdf_config']['pqc_keystore_key_id']
            if not getattr(args, 'quiet', False):
                print(f"Found key ID in metadata derivation_config: {key_id}")
    elif hash_config and 'pqc_keystore_key_id' in hash_config:
        # Legacy format (1-3)
        key_id = hash_config['pqc_keystore_key_id']
        if not getattr(args, 'quiet', False):
            print(f"Found key ID in hash_config: {key_id}")
    
    # If no key ID found yet, try extracting from file
    if not key_id and hasattr(args, 'input') and args.input:
        # Use the improved extract_key_id_from_metadata function
        # which now includes regex-based extraction for robustness
        key_id = extract_key_id_from_metadata(args.input, getattr(args, 'verbose', False))
        if key_id and not getattr(args, 'quiet', False):
            print(f"Found key ID in file metadata: {key_id}")
    
    # Check for embedded private key
    if key_id == "EMBEDDED_PRIVATE_KEY":
        if hasattr(args, 'input') and args.input:
            try:
                # Read the file to extract the embedded private key
                with open(args.input, 'rb') as f:
                    file_data = f.read(8192)  # Read enough to get the embedded key
                
                parts = file_data.split(b':', 1)
                if len(parts) > 1:
                    metadata_b64 = parts[0]
                    metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                    header_config = json.loads(metadata_json)
                    
                    # Get format version from metadata
                    format_version = header_config.get('format_version', 3)
                    
                    if format_version == 4:
                        # Extract from format version 4 structure
                        if 'encryption' in header_config and 'pqc_private_key' in header_config['encryption']:
                            embedded_private_key = header_config['encryption']['pqc_private_key']
                            if embedded_private_key:
                                if not getattr(args, 'quiet', False):
                                    print("Successfully retrieved embedded private key from format v4 metadata")
                                
                                # Decode the private key
                                private_key = base64.b64decode(embedded_private_key)
                                
                                # Extract public key as well
                                if 'pqc_public_key' in header_config['encryption']:
                                    public_key = base64.b64decode(header_config['encryption']['pqc_public_key'])
                                    
                                    # Return the key pair
                                    pqc_keypair = (public_key, private_key)
                                    pqc_private_key = private_key
                                    return pqc_keypair, pqc_private_key, "EMBEDDED_PRIVATE_KEY"
                    else:
                        # Legacy format (v1-3)
                        if 'hash_config' in header_config:
                            embedded_private_key = header_config['hash_config'].get('pqc_private_key')
                            if embedded_private_key:
                                if not getattr(args, 'quiet', False):
                                    print("Successfully retrieved embedded private key from metadata")
                                
                                # Decode the private key
                                private_key = base64.b64decode(embedded_private_key)
                                
                                # Extract public key as well
                                if 'pqc_public_key' in header_config['hash_config']:
                                    public_key = base64.b64decode(header_config['hash_config']['pqc_public_key'])
                                    
                                    # Return the key pair
                                    pqc_keypair = (public_key, private_key)
                                    pqc_private_key = private_key
                                    return pqc_keypair, pqc_private_key, "EMBEDDED_PRIVATE_KEY"
            except Exception as e:
                if getattr(args, 'verbose', False):
                    logger.info(f"Failed to extract embedded private key: {e}")
    
    # Check for dual encryption flag in metadata
    dual_encryption = False
    
    if format_version == 5 and metadata:
        # Check for dual encryption flag in format version 5 structure (same as v4)
        if ('derivation_config' in metadata and 
            'kdf_config' in metadata['derivation_config'] and 
            'dual_encryption' in metadata['derivation_config']['kdf_config']):
            dual_encryption = metadata['derivation_config']['kdf_config']['dual_encryption']
            if not getattr(args, 'quiet', False) and dual_encryption:
                print("Dual encryption is enabled for this file (format v5)")
    elif format_version == 4 and metadata:
        # Check for dual encryption flag in format version 4 structure
        if ('derivation_config' in metadata and 
            'kdf_config' in metadata['derivation_config'] and 
            'dual_encryption' in metadata['derivation_config']['kdf_config']):
            dual_encryption = metadata['derivation_config']['kdf_config']['dual_encryption']
            if not getattr(args, 'quiet', False) and dual_encryption:
                print("Dual encryption is enabled for this file (format v4)")
    elif hash_config and 'dual_encryption' in hash_config:
        # Legacy format (v1-3)
        dual_encryption = hash_config['dual_encryption']
        if not getattr(args, 'quiet', False) and dual_encryption:
            print("Dual encryption is enabled for this file")
    
    # If we have a keystore and key ID, try to retrieve the key
    if key_id and key_id != "EMBEDDED_PRIVATE_KEY" and hasattr(args, 'keystore') and args.keystore:
        try:
            # Get keystore password
            keystore_password = get_keystore_password(args)
            
            # Import now to avoid circular imports
            from .keystore_cli import get_key_from_keystore
            
            # Get the file password for dual encryption if needed
            file_password = None
            if dual_encryption and hasattr(args, 'password'):
                # For dual encryption, we need both the keystore password and the file password
                file_password = args.password
                if not getattr(args, 'quiet', False):
                    print(f"Using file password for dual-encrypted key")
            
            # Get key from keystore
            public_key, private_key = get_key_from_keystore(
                args.keystore,
                key_id,
                keystore_password,
                None,  # key_password
                getattr(args, 'quiet', False),
                file_password
            )
            
            pqc_keypair = (public_key, private_key)
            pqc_private_key = private_key
            
            if not getattr(args, 'quiet', False):
                print(f"Successfully retrieved key from keystore using ID from metadata")
                if dual_encryption:
                    print("Key was dual-encrypted with both keystore and file passwords")
                
            return pqc_keypair, pqc_private_key, key_id
        except Exception as e:
            if getattr(args, 'verbose', False):
                logger.info(f"Failed to get key from keystore: {e}")
    
    # Fall back to pqc_keyfile if specified
    if hasattr(args, 'pqc_keyfile') and args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
        try:
            # Load key pair from file
            import json
            import base64
            
            with open(args.pqc_keyfile, 'r') as f:
                key_data = json.load(f)
            
            if 'public_key' in key_data and 'private_key' in key_data:
                # Check if the private key is encrypted
                if key_data.get('key_encrypted', False) and 'key_salt' in key_data:
                    # Get password for decryption
                    keyfile_password = getpass.getpass("Enter password to decrypt the private key in keyfile: ").encode()
                    
                    # Import what we need to decrypt
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    import hashlib
                    
                    # Key derivation using the same method as when encrypting
                    key_salt = base64.b64decode(key_data['key_salt'])
                    key_derivation = hashlib.pbkdf2_hmac('sha256', keyfile_password, key_salt, 100000)
                    encryption_key = hashlib.sha256(key_derivation).digest()
                    
                    try:
                        encrypted_private_key = base64.b64decode(key_data['private_key'])
                        
                        # Format: nonce (12 bytes) + encrypted_key
                        nonce = encrypted_private_key[:12]
                        encrypted_key_data = encrypted_private_key[12:]
                        
                        # Decrypt the private key with the password-derived key
                        cipher = AESGCM(encryption_key)
                        private_key = cipher.decrypt(nonce, encrypted_key_data, None)
                        
                        # Decode public key
                        public_key = base64.b64decode(key_data['public_key'])
                        
                        pqc_keypair = (public_key, private_key)
                        pqc_private_key = private_key
                        
                        if not getattr(args, 'quiet', False):
                            print(f"Successfully decrypted and loaded key from PQC keyfile: {args.pqc_keyfile}")
                            
                        return pqc_keypair, pqc_private_key, None
                    except Exception as e:
                        if getattr(args, 'verbose', False):
                            logger.info(f"Failed to decrypt key from file: {e}")
                else:
                    # Unencrypted private key
                    public_key = base64.b64decode(key_data['public_key'])
                    private_key = base64.b64decode(key_data['private_key'])
                    
                    pqc_keypair = (public_key, private_key)
                    pqc_private_key = private_key
                    
                    if not getattr(args, 'quiet', False):
                        print(f"Using key from PQC keyfile: {args.pqc_keyfile}")
                        
                    return pqc_keypair, pqc_private_key, None
        except Exception as e:
            if getattr(args, 'verbose', False):
                logger.info(f"Failed to load key from file: {e}")
    
    return None, None, None

def store_pqc_key_in_keystore(metadata, keystore_path, keystore_password, key_id=None, quiet=False):
    """
    Extract already-encrypted private key from metadata and store it in the keystore
    
    Args:
        metadata: The file metadata containing the encrypted key
        keystore_path: Path to the keystore file
        keystore_password: Password for the keystore
        key_id: Optional existing key ID to update (or create new if None)
        quiet: Whether to suppress output
        
    Returns:
        str: The key ID used to store the key
    """
    # Check format version to determine where to look for fields
    format_version = metadata.get('format_version', 1)
    
    # Check for dual encryption flag based on format version
    dual_encrypt_enabled = False
    encrypted_private_key = None
    public_key = None
    algorithm = None
    
    if format_version == 5:
        # Format version 5 structure (same structure as v4 for key storage)
        if 'derivation_config' in metadata and 'kdf_config' in metadata['derivation_config']:
            dual_encrypt_enabled = metadata['derivation_config']['kdf_config'].get('dual_encryption', False)
        
        if 'encryption' in metadata:
            # Check for private key in encryption section
            if 'pqc_private_key' in metadata['encryption']:
                encrypted_private_key = base64.b64decode(metadata['encryption']['pqc_private_key'])
            
            # Get public key from encryption section
            if 'pqc_public_key' in metadata['encryption']:
                public_key = base64.b64decode(metadata['encryption']['pqc_public_key'])
            
            # Get algorithm from encryption section
            algorithm = metadata['encryption'].get('algorithm', 'kyber768-hybrid')
    elif format_version == 4:
        # Format version 4 structure
        if 'derivation_config' in metadata and 'kdf_config' in metadata['derivation_config']:
            dual_encrypt_enabled = metadata['derivation_config']['kdf_config'].get('dual_encryption', False)
        
        if 'encryption' in metadata:
            # Check for private key in encryption section
            if 'pqc_private_key' in metadata['encryption']:
                encrypted_private_key = base64.b64decode(metadata['encryption']['pqc_private_key'])
            
            # Get public key from encryption section
            if 'pqc_public_key' in metadata['encryption']:
                public_key = base64.b64decode(metadata['encryption']['pqc_public_key'])
            
            # Get algorithm from encryption section
            algorithm = metadata['encryption'].get('algorithm', 'kyber768-hybrid')
    else:
        # Legacy format (1-3)
        dual_encrypt_enabled = metadata.get('pqc_dual_encrypt_key', False) or metadata.get('dual_encryption', False)
        
        if 'pqc_private_key' in metadata:
            encrypted_private_key = base64.b64decode(metadata['pqc_private_key'])
            
        if 'pqc_public_key' in metadata:
            public_key = base64.b64decode(metadata['pqc_public_key'])
            
        algorithm = metadata.get('algorithm', 'kyber768-hybrid')
    
    # Check if we have the necessary data to proceed
    if encrypted_private_key is None or not dual_encrypt_enabled:
        if not quiet:
            print(f"No PQC private key in metadata or dual encryption not enabled (format v{format_version})")
        return None
    
    # Import necessary dependencies here to prevent circular imports
    from .keystore_cli import PQCKeystore
    from .secure_memory import secure_memzero
    
    try:
        # Create or load keystore
        keystore = PQCKeystore(keystore_path)
        if not os.path.exists(keystore_path):
            if not quiet:
                print(f"Creating new keystore: {keystore_path}")
            keystore.create_keystore(keystore_password)
        else:
            keystore.load_keystore(keystore_password)
        
        # If algorithm is not found in metadata, use a default
        if algorithm is None:
            algorithm = 'kyber768-hybrid'
            
        # Clean algorithm name if it has -hybrid suffix
        if algorithm.endswith('-hybrid'):
            algorithm = algorithm[:-7]  # Remove -hybrid suffix
        
        # If we have a key ID and the key exists, update it
        import datetime
        description = f"Updated from file on {datetime.datetime.now().strftime('%Y-%m-%d')}"
        tags = ["from-file", "dual-encrypted", f"format-v{format_version}"]
        
        if key_id and key_id in [k['key_id'] for k in keystore.list_keys()]:
            # Check if update_key method exists in PQCKeystore
            if hasattr(keystore, 'update_key'):
                if not quiet:
                    print(f"Updating existing key in keystore: {key_id}")
                # Update the key using the update_key method
                keystore.update_key(
                    key_id=key_id,
                    private_key=encrypted_private_key,
                    description=description,
                    tags=tags
                )
            else:
                # If update_key doesn't exist, try to remove and recreate the key
                if not quiet:
                    print(f"Replacing existing key in keystore: {key_id}")
                keystore.remove_key(key_id)
                keystore.add_key(
                    algorithm=algorithm,
                    public_key=public_key,
                    private_key=encrypted_private_key,
                    description=description,
                    tags=tags,
                    use_master_password=True
                )
                
                # Mark the key as specially encrypted (for recordkeeping)
                # This won't change how it's encrypted, but will indicate it's from a dual-encrypted file
                if hasattr(keystore, '_key_has_dual_encryption_flag'):
                    keystore._key_has_dual_encryption_flag(key_id, True)
        else:
            # Add as a new key
            if not quiet:
                print("Adding new key to keystore")
            key_id = keystore.add_key(
                algorithm=algorithm,
                public_key=public_key,
                private_key=encrypted_private_key,
                description=description,
                tags=tags,
                use_master_password=True
            )
            
            # Mark the key as specially encrypted (for recordkeeping)
            # This won't change how it's encrypted, but will indicate it's from a dual-encrypted file
            if hasattr(keystore, '_key_has_dual_encryption_flag'):
                keystore._key_has_dual_encryption_flag(key_id, True)
            
            # Update metadata with the key ID based on format version
            if format_version == 5:
                if 'derivation_config' in metadata and 'kdf_config' in metadata['derivation_config']:
                    metadata['derivation_config']['kdf_config']['pqc_keystore_key_id'] = key_id
            elif format_version == 4:
                if 'derivation_config' in metadata and 'kdf_config' in metadata['derivation_config']:
                    metadata['derivation_config']['kdf_config']['pqc_keystore_key_id'] = key_id
            else:
                # Legacy format update
                metadata['pqc_keystore_key_id'] = key_id
        
        if not quiet:
            print(f"Successfully stored PQC key in keystore with ID: {key_id}")
        
        return key_id
        
    except Exception as e:
        if not quiet:
            print(f"Error storing PQC key in keystore: {e}")
        return None
    finally:
        # Clean up sensitive data
        try:
            # Clear encrypted_private_key if it exists
            if encrypted_private_key is not None:
                try:
                    # Use secure_memzero for byte arrays
                    secure_memzero(encrypted_private_key)
                except:
                    # Fallback if secure_memzero fails
                    encrypted_private_key = b'\x00' * len(encrypted_private_key)
                encrypted_private_key = None
        except:
            # Last resort cleanup - just remove the reference
            encrypted_private_key = None
        
def auto_generate_pqc_key(args, hash_config, format_version=3):
    """
    Auto-generate PQC key and add to keystore if needed
    
    Args:
        args: Command-line arguments
        hash_config: Hash configuration to update with key ID
        format_version: The format version being used (default: 3)
        
    Returns:
        tuple: (pqc_keypair, pqc_private_key)
    """
    if not hasattr(args, 'algorithm') or not args.algorithm.startswith('kyber'):
        return None, None
        
    # Check for dual encryption flag
    dual_encryption = False
    if hasattr(args, 'dual_encrypt_key') and args.dual_encrypt_key:
        dual_encryption = True
        # Make sure the file password is available for dual encryption
        if not hasattr(args, 'password') or not args.password:
            if not getattr(args, 'quiet', False):
                print("Warning: Dual encryption requested but no file password provided. Disabling dual encryption.")
            dual_encryption = False
        else:
            # Set the dual encryption flag in the appropriate location based on format version
            if format_version == 4:
                # Format version 4 structure
                if not isinstance(hash_config, dict):
                    hash_config = {}
                    
                # Ensure the hash_config includes the proper structure
                hash_config['dual_encryption'] = True  # For backward compatibility
                
                # Add to the proper location in derivation_config.kdf_config
                if 'derivation_config' not in hash_config:
                    hash_config['derivation_config'] = {}
                if 'kdf_config' not in hash_config['derivation_config']:
                    hash_config['derivation_config']['kdf_config'] = {}
                    
                hash_config['derivation_config']['kdf_config']['dual_encryption'] = True
            else:
                # Legacy format (v1-3)
                hash_config["dual_encryption"] = True
                
            if not getattr(args, 'quiet', False):
                print("Enabling dual encryption for key - file will require both keystore and file passwords")
        
    # Check if we have a keystore
    if hasattr(args, 'keystore') and args.keystore:
        try:
            # Get keystore password
            keystore_password = get_keystore_password(args)
            
            # Import now to avoid circular imports
            from .pqc import PQCipher, check_pqc_support
            from .keystore_cli import PQCKeystore, KeystoreSecurityLevel
            
            # Get algorithm mapping
            pqc_algorithms = check_pqc_support(quiet=getattr(args, 'quiet', False))[2]
            
            # Create the underlying algorithm name without -hybrid
            pqc_algorithm = args.algorithm.replace('-hybrid', '')
            
            # Create or load keystore
            keystore = PQCKeystore(args.keystore)
            if not os.path.exists(args.keystore):
                if not getattr(args, 'quiet', False):
                    print(f"Creating new keystore: {args.keystore}")
                keystore.create_keystore(keystore_password, KeystoreSecurityLevel.STANDARD)
            else:
                keystore.load_keystore(keystore_password)
            
            # Check for existing keys - also match dual_encryption status
            keys = keystore.list_keys()
            matching_keys = [k for k in keys 
                            if k["algorithm"].lower().replace("-", "") == pqc_algorithm.lower().replace("-", "")
                            and k.get("dual_encryption", False) == dual_encryption]
            
            if matching_keys:
                # Use existing key
                key_id = matching_keys[0]["key_id"]
                if dual_encryption and hasattr(args, 'password'):
                    public_key, private_key = keystore.get_key(key_id, None, args.password)
                else:
                    public_key, private_key = keystore.get_key(key_id)
                
                if not getattr(args, 'quiet', False):
                    print(f"Using existing {matching_keys[0]['algorithm']} key from keystore")
                    if dual_encryption:
                        print("This key uses dual encryption (keystore password + file password)")
            else:
                # Generate new key
                if not getattr(args, 'quiet', False):
                    print(f"Generating new {pqc_algorithm} key for keystore")
                    if dual_encryption:
                        print("Using dual encryption for this key")
                
                # Get base algorithm name (without -hybrid)
                base_algo = args.algorithm.replace('-hybrid', '')
                
                # Generate keypair
                cipher = PQCipher(base_algo, quiet=getattr(args, 'quiet', False))
                public_key, private_key = cipher.generate_keypair()
                
                # Get file password if we're using dual encryption
                file_password = None
                if dual_encryption and hasattr(args, 'password'):
                    file_password = args.password
                
                # Add to keystore
                key_id = keystore.add_key(
                    algorithm=pqc_algorithm,
                    public_key=public_key,
                    private_key=private_key,
                    use_master_password=True,
                    description=f"Auto-generated {pqc_algorithm} key{' with dual encryption' if dual_encryption else ''}",
                    dual_encryption=dual_encryption,
                    file_password=file_password
                )
                
                # Save keystore
                keystore.save_keystore()
                
                if not getattr(args, 'quiet', False):
                    print(f"Added new key to keystore with ID: {key_id}")
            
            # Store key ID in metadata based on format version
            if format_version == 5:
                # Format version 5 structure (same hierarchical structure as v4)
                if not isinstance(hash_config, dict):
                    hash_config = {}
                
                # Store key ID in both locations for maximum compatibility
                # In legacy location for backward compatibility
                hash_config["pqc_keystore_key_id"] = key_id
                
                # In the correct V5 hierarchical structure (same as V4)
                if 'derivation_config' not in hash_config:
                    hash_config['derivation_config'] = {}
                if 'kdf_config' not in hash_config['derivation_config']:
                    hash_config['derivation_config']['kdf_config'] = {}
                    
                hash_config['derivation_config']['kdf_config']['pqc_keystore_key_id'] = key_id
            elif format_version == 4:
                # Format version 4 structure
                if not isinstance(hash_config, dict):
                    hash_config = {}
                
                # Store key ID in both locations for maximum compatibility
                # In legacy location for backward compatibility
                hash_config["pqc_keystore_key_id"] = key_id
                
                # In the correct V4 hierarchical structure
                if 'derivation_config' not in hash_config:
                    hash_config['derivation_config'] = {}
                if 'kdf_config' not in hash_config['derivation_config']:
                    hash_config['derivation_config']['kdf_config'] = {}
                    
                hash_config['derivation_config']['kdf_config']['pqc_keystore_key_id'] = key_id
            else:
                # Legacy format (v1-3)
                hash_config["pqc_keystore_key_id"] = key_id
            
            # If we're using dual encryption, store that in metadata
            if dual_encryption:
                if format_version == 5:
                    # Store in both locations for maximum compatibility
                    # Legacy location for backward compatibility
                    hash_config["dual_encryption"] = True
                    
                    # Format version 5 structure (same as v4)
                    if 'derivation_config' not in hash_config:
                        hash_config['derivation_config'] = {}
                    if 'kdf_config' not in hash_config['derivation_config']:
                        hash_config['derivation_config']['kdf_config'] = {}
                        
                    hash_config['derivation_config']['kdf_config']['dual_encryption'] = True
                elif format_version == 4:
                    # Store in both locations for maximum compatibility
                    # Legacy location for backward compatibility
                    hash_config["dual_encryption"] = True
                    
                    # Format version 4 structure
                    if 'derivation_config' not in hash_config:
                        hash_config['derivation_config'] = {}
                    if 'kdf_config' not in hash_config['derivation_config']:
                        hash_config['derivation_config']['kdf_config'] = {}
                        
                    hash_config['derivation_config']['kdf_config']['dual_encryption'] = True
                else:
                    # Legacy format
                    hash_config["dual_encryption"] = True
            
            # If requested, also store the private key in metadata for self-decryption
            if hasattr(args, 'pqc_store_key') and args.pqc_store_key:
                encoded_private_key = base64.b64encode(private_key).decode('utf-8')
                if format_version == 5:
                    # Store in format version 5 structure (same as v4)
                    if 'encryption' not in hash_config:
                        hash_config['encryption'] = {}
                        
                    hash_config['encryption']['pqc_private_key'] = encoded_private_key
                    hash_config['encryption']['pqc_private_key_embedded'] = True
                elif format_version == 4:
                    # Store in format version 4 structure
                    if 'encryption' not in hash_config:
                        hash_config['encryption'] = {}
                        
                    hash_config['encryption']['pqc_private_key'] = encoded_private_key
                    hash_config['encryption']['pqc_private_key_embedded'] = True
                else:
                    # Legacy format
                    hash_config["pqc_private_key"] = encoded_private_key
                    hash_config["pqc_private_key_embedded"] = True
                    
                if not getattr(args, 'quiet', False):
                    print("Storing private key in metadata for self-decryption")
            
            # Important: clear the keystore cache for security
            keystore.clear_cache()
            
            return (public_key, private_key), private_key
        except Exception as e:
            if getattr(args, 'verbose', False):
                logger.info(f"Error with keystore: {e}, falling back to ephemeral key")
    
    # Fall back to ephemeral key
    if not getattr(args, 'quiet', False):
        print(f"Using ephemeral key for {args.algorithm}")
    
    from .pqc import PQCipher
    
    # Get base algorithm name
    base_algo = args.algorithm.replace('-hybrid', '')
    
    # Generate keypair
    cipher = PQCipher(base_algo, quiet=getattr(args, 'quiet', False))
    public_key, private_key = cipher.generate_keypair()
    
    # If requested, store the private key in metadata for self-decryption
    if hasattr(args, 'pqc_store_key') and args.pqc_store_key:
        encoded_private_key = base64.b64encode(private_key).decode('utf-8')
        encoded_public_key = base64.b64encode(public_key).decode('utf-8')
        
        if format_version == 4:
            # Store in format version 4 structure
            if 'encryption' not in hash_config:
                hash_config['encryption'] = {}
                
            hash_config['encryption']['pqc_private_key'] = encoded_private_key
            hash_config['encryption']['pqc_private_key_embedded'] = True
            hash_config['encryption']['pqc_public_key'] = encoded_public_key
        else:
            # Legacy format
            hash_config["pqc_private_key"] = encoded_private_key
            hash_config["pqc_private_key_embedded"] = True
            hash_config["pqc_public_key"] = encoded_public_key
            
        if not getattr(args, 'quiet', False):
            print("Storing private key in metadata for self-decryption")
    else:
        # Store just the public key for verification
        encoded_public_key = base64.b64encode(public_key).decode('utf-8')
        
        if format_version == 5:
            # Store in format version 5 structure (same as v4)
            if 'encryption' not in hash_config:
                hash_config['encryption'] = {}
                
            hash_config['encryption']['pqc_public_key'] = encoded_public_key
        elif format_version == 4:
            # Store in format version 4 structure
            if 'encryption' not in hash_config:
                hash_config['encryption'] = {}
                
            hash_config['encryption']['pqc_public_key'] = encoded_public_key
        else:
            # Legacy format
            hash_config["pqc_public_key"] = encoded_public_key
    
    return (public_key, private_key), private_key