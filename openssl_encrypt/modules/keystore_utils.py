#!/usr/bin/env python3
"""
Utility functions for PQC keystore operations
"""

import os
import json
import base64
import getpass
from typing import Dict, Any, Tuple, Optional

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
            header_data = f.read(1024)  # Read enough for header
            
        # Try base64 JSON format (newer format)
        try:
            parts = header_data.split(b':', 1)
            if len(parts) > 1:
                metadata_b64 = parts[0]
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                header_config = json.loads(metadata_json)
                
                # Extract key ID from hash_config
                if 'hash_config' in header_config:
                    key_id = header_config['hash_config'].get('pqc_keystore_key_id')
                    if key_id and verbose:
                        print(f"Found key ID in metadata: {key_id}")
                    return key_id
        except Exception as e:
            if verbose:
                print(f"Failed to parse base64 JSON metadata: {e}")
                
        # Fall back to legacy OSENC format
        header_start = header_data.find(b'OSENC')
        if header_start >= 0:
            header_end = header_data.find(b'HEND')
            if header_end > header_start:
                header_json = header_data[header_start+5:header_end].decode('utf-8')
                header_config = json.loads(header_json)
                
                # Extract key ID from hash_config
                if 'hash_config' in header_config:
                    key_id = header_config['hash_config'].get('pqc_keystore_key_id')
                    if key_id and verbose:
                        print(f"Found key ID in metadata: {key_id}")
                    return key_id
    except Exception as e:
        if verbose:
            print(f"Error extracting key ID from metadata: {e}")
    
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
    
    # Fall back to main password if available
    if hasattr(args, 'password') and args.password:
        return args.password
        
    # Prompt user for password
    return getpass.getpass("Enter keystore password: ")

def get_pqc_key_for_decryption(args, hash_config=None):
    """
    Get PQC key for decryption, checking keystore if available
    
    Args:
        args: Command-line arguments
        hash_config: Hash configuration with possible key ID
        
    Returns:
        tuple: (pqc_keypair, pqc_private_key, key_id)
    """
    # Initialize variables
    pqc_keypair = None
    pqc_private_key = None
    key_id = None
    
    # Check if we have a key ID in the hash_config
    if hash_config and 'pqc_keystore_key_id' in hash_config:
        key_id = hash_config['pqc_keystore_key_id']
        if not getattr(args, 'quiet', False):
            print(f"Found key ID in hash_config: {key_id}")
    
    # If no key ID in hash_config, try extracting from file
    if not key_id and hasattr(args, 'input') and args.input:
        key_id = extract_key_id_from_metadata(args.input, getattr(args, 'verbose', False))
        if key_id and not getattr(args, 'quiet', False):
            print(f"Found key ID in file metadata: {key_id}")
    
    # If we have a keystore and key ID, try to retrieve the key
    if key_id and hasattr(args, 'keystore') and args.keystore:
        try:
            # Get keystore password
            keystore_password = get_keystore_password(args)
            
            # Import now to avoid circular imports
            from .keystore_cli import get_key_from_keystore
            
            # Get key from keystore
            public_key, private_key = get_key_from_keystore(
                args.keystore,
                key_id,
                keystore_password,
                None,
                getattr(args, 'quiet', False)
            )
            
            pqc_keypair = (public_key, private_key)
            pqc_private_key = private_key
            
            if not getattr(args, 'quiet', False):
                print(f"Successfully retrieved key from keystore using ID from metadata")
                
            return pqc_keypair, pqc_private_key, key_id
        except Exception as e:
            if getattr(args, 'verbose', False):
                print(f"Failed to get key from keystore: {e}")
    
    # Fall back to pqc_keyfile if specified
    if hasattr(args, 'pqc_keyfile') and args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
        try:
            # Load key pair from file
            import json
            import base64
            
            with open(args.pqc_keyfile, 'r') as f:
                key_data = json.load(f)
            
            if 'public_key' in key_data and 'private_key' in key_data:
                public_key = base64.b64decode(key_data['public_key'])
                private_key = base64.b64decode(key_data['private_key'])
                
                pqc_keypair = (public_key, private_key)
                pqc_private_key = private_key
                
                if not getattr(args, 'quiet', False):
                    print(f"Using key from PQC keyfile: {args.pqc_keyfile}")
                    
                return pqc_keypair, pqc_private_key, None
        except Exception as e:
            if getattr(args, 'verbose', False):
                print(f"Failed to load key from file: {e}")
    
    return None, None, None

def auto_generate_pqc_key(args, hash_config):
    """
    Auto-generate PQC key and add to keystore if needed
    
    Args:
        args: Command-line arguments
        hash_config: Hash configuration to update with key ID
        
    Returns:
        tuple: (pqc_keypair, pqc_private_key)
    """
    if not hasattr(args, 'algorithm') or not args.algorithm.startswith('kyber'):
        return None, None
        
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
            
            # Check for existing keys
            keys = keystore.list_keys()
            matching_keys = [k for k in keys if k["algorithm"].lower().replace("-", "") == 
                            pqc_algorithm.lower().replace("-", "")]
            
            if matching_keys:
                # Use existing key
                key_id = matching_keys[0]["key_id"]
                public_key, private_key = keystore.get_key(key_id)
                
                if not getattr(args, 'quiet', False):
                    print(f"Using existing {matching_keys[0]['algorithm']} key from keystore")
            else:
                # Generate new key
                if not getattr(args, 'quiet', False):
                    print(f"Generating new {pqc_algorithm} key for keystore")
                
                # Get base algorithm name (without -hybrid)
                base_algo = args.algorithm.replace('-hybrid', '')
                
                # Generate keypair
                cipher = PQCipher(base_algo, quiet=getattr(args, 'quiet', False))
                public_key, private_key = cipher.generate_keypair()
                
                # Add to keystore
                key_id = keystore.add_key(
                    algorithm=pqc_algorithm,
                    public_key=public_key,
                    private_key=private_key,
                    use_master_password=True,
                    description=f"Auto-generated {pqc_algorithm} key"
                )
                
                # Save keystore
                keystore.save_keystore()
                
                if not getattr(args, 'quiet', False):
                    print(f"Added new key to keystore with ID: {key_id}")
            
            # Store key ID in metadata
            hash_config["pqc_keystore_key_id"] = key_id
            
            # Important: clear the keystore cache for security
            keystore.clear_cache()
            
            return (public_key, private_key), private_key
        except Exception as e:
            if getattr(args, 'verbose', False):
                print(f"Error with keystore: {e}, falling back to ephemeral key")
    
    # Fall back to ephemeral key
    if not getattr(args, 'quiet', False):
        print(f"Using ephemeral key for {args.algorithm}")
    
    from .pqc import PQCipher
    
    # Get base algorithm name
    base_algo = args.algorithm.replace('-hybrid', '')
    
    # Generate keypair
    cipher = PQCipher(base_algo, quiet=getattr(args, 'quiet', False))
    public_key, private_key = cipher.generate_keypair()
    
    return (public_key, private_key), private_key