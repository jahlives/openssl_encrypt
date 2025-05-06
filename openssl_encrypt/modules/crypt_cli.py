#!/usr/bin/env python3
"""
Command-line interface for encryption/decryption operations
"""

import os
import sys
import json
import base64
import getpass
import argparse
from typing import Dict, Any, List, Tuple, Optional, Union

from .crypt_core import encrypt_file, decrypt_file
from .crypt_errors import KeyDerivationError, DecryptionError, KeyNotFoundError
from .secure_memory import secure_memzero, SecureBytes
# Define secure delete availability flag
SECURE_DELETE_AVAILABLE = hasattr(os, 'sysconf')
from .keystore_cli import KeystorePasswordError

# Define algorithm mapping
def get_algorithm_value(algorithm_name):
    """Get the appropriate algorithm value based on the name"""
    algorithm_map = {
        "aes-256-cbc": "aes-256-cbc",
        "aes-256-ctr": "aes-256-ctr",
        "aes-256-cfb": "aes-256-cfb",
        "aes-256-ofb": "aes-256-ofb",
        "aes-256-gcm": "aes-256-gcm",
        "aes-gcm": "aes-256-gcm",
        "aes-128-gcm": "aes-128-gcm",
        "aes-gcm-siv": "aes-128-gcm-siv",
        "aes-128-gcm-siv": "aes-128-gcm-siv",
        "aes-256-gcm-siv": "aes-256-gcm-siv",
        "aes-ocb": "aes-256-ocb3",
        "aes-256-ocb": "aes-256-ocb3",
        "aes-128-ocb": "aes-128-ocb3",
        "aes-ocb3": "aes-256-ocb3",
        "aes-256-ocb3": "aes-256-ocb3",
        "aes-128-ocb3": "aes-128-ocb3",
        "aes-siv": "aes-256-siv",
        "aes-256-siv": "aes-256-siv",
        "aes-128-siv": "aes-128-siv",
        "chacha20": "chacha20",
        "chacha20-poly1305": "chacha20-poly1305",
        "xchacha20": "xchacha20",
        "xchacha20-poly1305": "xchacha20-poly1305",
        "fernet": "fernet",
        "kyber512": "kyber512",
        "kyber768": "kyber768",
        "kyber1024": "kyber1024",
        "kyber512-hybrid": "kyber512-hybrid",
        "kyber768-hybrid": "kyber768-hybrid",
        "kyber1024-hybrid": "kyber1024-hybrid"
    }
    
    return algorithm_map.get(algorithm_name.lower())

try:
    from . import keystore_wrapper
    from . import keystore_utils
    KEYSTORE_AVAILABLE = True
except ImportError:
    KEYSTORE_AVAILABLE = False

def get_parser():
    """Create and return the argument parser"""
    parser = argparse.ArgumentParser(description='OpenSSL-based encryption utility')
    
    # Common arguments
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress informational output')
    parser.add_argument('--version', action='store_true', help='Print version information')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('-i', '--input', required=True, help='Input file to encrypt')
    encrypt_parser.add_argument('-o', '--output', help='Output file (defaults to input + .enc)')
    encrypt_parser.add_argument('-f', '--force', action='store_true', help='Force overwrite of output file')
    encrypt_parser.add_argument('-a', '--algorithm', default='aes-gcm', help='Encryption algorithm to use')
    encrypt_parser.add_argument('-p', '--password', help='Password for encryption (will prompt if not provided)')
    encrypt_parser.add_argument('--password-file', help='File containing password')
    encrypt_parser.add_argument('--force-password', action='store_true', help='Use provided password even if it appears weak')
    encrypt_parser.add_argument('--secure-delete', action='store_true', help='Securely delete original file after encryption')
    encrypt_parser.add_argument('--hash-rounds', type=int, default=100000, help='Number of PBKDF2 hash iterations')
    encrypt_parser.add_argument('--scrypt', action='store_true', help='Use scrypt for key derivation')
    encrypt_parser.add_argument('--scrypt-n', type=int, default=16384, help='Scrypt N parameter')
    encrypt_parser.add_argument('--scrypt-r', type=int, default=8, help='Scrypt r parameter')
    encrypt_parser.add_argument('--scrypt-p', type=int, default=1, help='Scrypt p parameter')
    encrypt_parser.add_argument('--argon2', action='store_true', help='Use argon2 for key derivation')
    encrypt_parser.add_argument('--argon2-time', type=int, default=3, help='Argon2 time cost parameter')
    encrypt_parser.add_argument('--argon2-memory', type=int, default=65536, help='Argon2 memory cost parameter')
    encrypt_parser.add_argument('--argon2-parallelism', type=int, default=4, help='Argon2 parallelism parameter')
    encrypt_parser.add_argument('--argon2-type', choices=['d', 'i', 'id'], default='id', help='Argon2 variant to use')
    encrypt_parser.add_argument('--use-balloon', action='store_true', help='Use balloon hashing')
    encrypt_parser.add_argument('--balloon-rounds', type=int, default=3, help='Number of balloon hash rounds')
    encrypt_parser.add_argument('--balloon-space', type=int, default=1024, help='Balloon space cost parameter')
    encrypt_parser.add_argument('--sha256-rounds', type=int, default=0, help='Number of SHA-256 hash iterations')
    encrypt_parser.add_argument('--sha512-rounds', type=int, default=0, help='Number of SHA-512 hash iterations')
    encrypt_parser.add_argument('--sha3-256-rounds', type=int, default=0, help='Number of SHA3-256 hash iterations')
    encrypt_parser.add_argument('--sha3-512-rounds', type=int, default=0, help='Number of SHA3-512 hash iterations')
    encrypt_parser.add_argument('--blake2b-rounds', type=int, default=0, help='Number of BLAKE2b hash iterations')
    encrypt_parser.add_argument('--whirlpool-rounds', type=int, default=0, help='Number of Whirlpool hash iterations')
    encrypt_parser.add_argument('--shake256-rounds', type=int, default=0, help='Number of SHAKE256 hash iterations')
    
    # Add keystore support if available
    if KEYSTORE_AVAILABLE:
        keystore_group = encrypt_parser.add_argument_group('keystore options')
        keystore_group.add_argument('--keystore', help='Path to keystore file')
        keystore_group.add_argument('--keystore-password', help='Password for keystore')
        keystore_group.add_argument('--keystore-password-file', help='File containing keystore password')
        keystore_group.add_argument('--key-id', help='ID of the key to use from keystore')
        keystore_group.add_argument('--use-keystore-key', action='store_true', 
                                    help='Use a key from the keystore for encryption/decryption')
        keystore_group.add_argument('--dual-encrypt-key', action='store_true',
                                    help='Encrypt with both keystore and file passwords (defense in depth)')
        keystore_group.add_argument('--create-keystore', action='store_true', 
                                    help='Create keystore if it does not exist')
        keystore_group.add_argument('--pqc-keyfile', help='Path to PQC key file')
        keystore_group.add_argument('--pqc-store-key', action='store_true', 
                                    help='Store PQC private key in metadata (for self-decryption)')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('-i', '--input', required=True, help='Input file to decrypt')
    decrypt_parser.add_argument('-o', '--output', help='Output file (defaults to removing .enc)')
    decrypt_parser.add_argument('-f', '--force', action='store_true', help='Force overwrite of output file')
    decrypt_parser.add_argument('-p', '--password', help='Password for decryption (will prompt if not provided)')
    decrypt_parser.add_argument('--password-file', help='File containing password')
    decrypt_parser.add_argument('--force-password', action='store_true', help='Skip password strength checks')
    decrypt_parser.add_argument('--secure-delete', action='store_true', help='Securely delete encrypted file after decryption')
    
    # Add keystore support if available
    if KEYSTORE_AVAILABLE:
        keystore_group = decrypt_parser.add_argument_group('keystore options')
        keystore_group.add_argument('--keystore', help='Path to keystore file')
        keystore_group.add_argument('--keystore-password', help='Password for keystore')
        keystore_group.add_argument('--keystore-password-file', help='File containing keystore password')
        keystore_group.add_argument('--key-id', help='ID of the key to use from keystore')
        keystore_group.add_argument('--pqc-keyfile', help='Path to PQC key file')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show information about an encrypted file')
    info_parser.add_argument('-i', '--input', required=True, help='Encrypted file to analyze')
    
    return parser

def get_keystore_password(args):
    """Get the keystore password from arguments or prompt"""
    if args.keystore_password:
        return args.keystore_password
    
    if args.keystore_password_file:
        try:
            with open(args.keystore_password_file, 'r') as f:
                return f.read().strip()
        except Exception as e:
            if not args.quiet:
                print(f"Error reading keystore password file: {e}")
    
    # Otherwise prompt the user
    return getpass.getpass("Enter keystore password: ")

def get_file_password(args):
    """Get the file password from arguments or prompt"""
    if args.password:
        return args.password
    
    if args.password_file:
        try:
            with open(args.password_file, 'r') as f:
                password = f.read().strip()
                return password
        except Exception as e:
            if not args.quiet:
                print(f"Error reading password file: {e}")
    
    # Otherwise prompt the user
    pw1 = getpass.getpass("Enter password: ")
    
    if args.command == 'encrypt':
        # For encryption, ask for confirmation
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Passwords do not match")
            secure_memzero(pw1)
            secure_memzero(pw2)
            return None
        
    return pw1

def encrypt_command(args):
    """Handle the encrypt command"""
    # Validate args
    if not os.path.exists(args.input):
        print(f"Input file not found: {args.input}")
        return 1
    
    # Set default output if not provided
    if not args.output:
        args.output = args.input + '.enc'
    
    # Check if output already exists
    if os.path.exists(args.output) and not args.force:
        print(f"Output file already exists: {args.output}")
        print("Use -f/--force to overwrite")
        return 1
    
    # Get password
    args.password = get_file_password(args)
    if args.password is None:
        return 1
    
    # Create hash configuration
    hash_config = {
        "sha256": args.sha256_rounds,
        "sha512": args.sha512_rounds,
        "sha3_256": args.sha3_256_rounds,
        "sha3_512": args.sha3_512_rounds,
        "blake2b": args.blake2b_rounds,
        "shake256": args.shake256_rounds,
        "whirlpool": args.whirlpool_rounds,
        "scrypt": {
            "enabled": args.scrypt,
            "n": args.scrypt_n,
            "r": args.scrypt_r,
            "p": args.scrypt_p
        },
        "argon2": {
            "enabled": args.argon2,
            "time_cost": args.argon2_time,
            "memory_cost": args.argon2_memory,
            "parallelism": args.argon2_parallelism,
            "type": args.argon2_type
        },
        "balloon": {
            "enabled": getattr(args, 'use_balloon', False),
            "space_cost": getattr(args, 'balloon_space', 1024),
            "time_cost": getattr(args, 'balloon_rounds', 3)
        },
        "pbkdf2_iterations": args.hash_rounds
    }
    
    # Get algorithm value
    algorithm = get_algorithm_value(args.algorithm)
    
    # Check algorithm validity
    if algorithm is None:
        print(f"Invalid algorithm: {args.algorithm}")
        return 1
    
    # Check for keystore options
    if KEYSTORE_AVAILABLE and args.keystore:
        # We'll use keystore functionality
        if args.key_id or args.use_keystore_key:
            # Using an existing key from the keystore
            from .keystore_cli import PQCKeystore, get_key_from_keystore
            
            try:
                # Get keystore password
                keystore_password = get_keystore_password(args)
                
                if args.key_id:
                    # Use a specific key ID
                    try:
                        keystore = PQCKeystore(args.keystore)
                        keystore.load_keystore(keystore_password)
                        
                        # Get the key
                        public_key, private_key = keystore.get_key(args.key_id)
                        
                        if not args.quiet:
                            print(f"Using key {args.key_id} from keystore")
                            
                        pqc_keypair = (public_key, private_key)
                        
                        # Add key ID to hash_config for later retrieval
                        hash_config["pqc_keystore_key_id"] = args.key_id
                        
                        # Add dual encryption flag if requested
                        if getattr(args, 'dual_encrypt_key', False):
                            hash_config["dual_encryption"] = True
                            if not args.quiet:
                                print("Setting dual encryption flag in metadata")
                    except Exception as e:
                        if not args.quiet:
                            print(f"Error getting key {args.key_id}: {e}")
                        raise
                else:
                    # Auto-generate or select an appropriate key
                    try:
                        # First check if we're using dual encryption
                        if getattr(args, 'dual_encrypt_key', False):
                            hash_config["dual_encryption"] = True
                            if not args.quiet:
                                print("Setting dual encryption flag in metadata")
                            
                            # IMPORTANT: We need to force the dual_encryption flag in the keystore_wrapper too
                            # Define kwargs dictionary if not used elsewhere
                            kwargs = {"dual_encryption": True}
                            
                        # Use keystore_utils to auto-generate a key
                        pqc_keypair, _ = keystore_utils.auto_generate_pqc_key(args, hash_config)
                        if not pqc_keypair:
                            print("Failed to generate or select an appropriate PQC key")
                            return 1
                    except Exception as e:
                        if not args.quiet:
                            print(f"Error generating PQC key: {e}")
                        raise
            except Exception as e:
                if not args.quiet:
                    print(f"Keystore error: {e}")
                return 1
                
            # Now encrypt using keystore wrapper
            try:
                # Determine the key ID if it's in the hash_config
                key_id = hash_config.get("pqc_keystore_key_id")
                
                # Pass kwargs or handle it in arguments
                kwargs_for_encryption = {
                    "hash_config": hash_config,
                    "pbkdf2_iterations": args.hash_rounds,
                    "quiet": args.quiet,
                    "algorithm": args.algorithm,
                    "pqc_keypair": pqc_keypair,
                    "keystore_file": args.keystore,
                    "keystore_password": get_keystore_password(args) if 'get_keystore_password' in dir() else None,
                    "key_id": key_id,
                    "dual_encryption": getattr(args, 'dual_encrypt_key', False)
                }
                
                # Add pqc_store_private_key if the argument exists
                if hasattr(args, 'pqc_store_key'):
                    kwargs_for_encryption["pqc_store_private_key"] = args.pqc_store_key
                
                result = keystore_wrapper.encrypt_file_with_keystore(
                    args.input,
                    args.output,
                    args.password,
                    **kwargs_for_encryption
                )
                
                if not result:
                    print("Encryption failed")
                    return 1
                    
                if not args.quiet:
                    print(f"\nFile encrypted successfully: {args.output}")
                    
            except Exception as e:
                print(f"Encryption error: {e}")
                return 1
        elif args.pqc_keyfile:
            # Using an external key file
            pass
    else:
        # Standard encryption without keystore
        try:
            # Check if algorithm is PQC
            if args.algorithm.startswith(('kyber', 'pqc-')):
                print("PQC algorithms require keystore support")
                print("Please specify --keystore and --use-keystore-key")
                return 1
                
            # Standard encryption
            result = encrypt_file(
                args.input,
                args.output,
                args.password,
                hash_config=hash_config,
                pbkdf2_iterations=args.hash_rounds,
                quiet=args.quiet,
                algorithm=args.algorithm
            )
            
            if not result:
                print("Encryption failed")
                return 1
                
            if not args.quiet:
                print(f"\nFile encrypted successfully: {args.output}")
                
        except KeyDerivationError as e:
            print(f"Key derivation error: {e}")
            return 1
        except Exception as e:
            print(f"Encryption error: {e}")
            return 1
    
    # Handle secure deletion of original file if requested
    if args.secure_delete:
        if SECURE_DELETE_AVAILABLE:
            from .crypt_utils import secure_delete_file
            
            if not args.quiet:
                print(f"Securely deleting original file: {args.input}")
                
            secure_delete_file(args.input, 3, args.quiet)
        else:
            print("Secure deletion not available - skipping")
            
    return 0

def decrypt_command(args):
    """Handle the decrypt command"""
    # Validate args
    if not os.path.exists(args.input):
        print(f"Input file not found: {args.input}")
        return 1
    
    # Set default output if not provided
    if not args.output:
        if args.input.endswith('.enc'):
            args.output = args.input[:-4]
        else:
            args.output = args.input + '.dec'
    
    # Check if output already exists
    if os.path.exists(args.output) and not args.force:
        print(f"Output file already exists: {args.output}")
        print("Use -f/--force to overwrite")
        return 1
    
    # Get password
    args.password = get_file_password(args)
    if args.password is None:
        return 1
    
    # Check for keystore options
    if KEYSTORE_AVAILABLE and (args.keystore or args.pqc_keyfile):
        # Check if we need to extract key ID from metadata
        key_id = args.key_id
        
        if not key_id and args.keystore:
            # Try to extract key ID from metadata
            key_id = keystore_utils.extract_key_id_from_metadata(args.input, not args.quiet)
            
            if key_id:
                if not args.quiet:
                    print(f"Using key ID from metadata: {key_id}")
            else:
                print("No key ID found in metadata")
                print("Please specify --key-id")
                return 1
        
        # Using a keystore key
        if key_id and args.keystore:
            # Using a specific key ID from keystore
            try:
                from .keystore_cli import PQCKeystore, get_key_from_keystore
                
                # Get keystore password
                keystore_password = get_keystore_password(args)
                
                keystore = PQCKeystore(args.keystore)
                keystore.load_keystore(keystore_password)
                
                # Check if this is a dual-encrypted key
                dual_encryption = False
                
                try:
                    with open(args.input, 'rb') as f:
                        data = f.read(8192)  # Read enough for the header
                    
                    # Find the colon separator
                    colon_pos = data.find(b':')
                    if colon_pos > 0:
                        metadata_b64 = data[:colon_pos]
                        metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                        metadata = json.loads(metadata_json)
                        
                        # Check for dual encryption flag
                        if 'hash_config' in metadata and 'dual_encryption' in metadata['hash_config']:
                            dual_encryption = metadata['hash_config']['dual_encryption']
                            if dual_encryption and not args.quiet:
                                print("File uses dual encryption - requires both keystore and file passwords")
                except Exception as e:
                    if args.verbose:
                        print(f"Error checking metadata for dual encryption: {e}")
                
                # For dual encryption, we need to pass the file password
                file_password = None
                if dual_encryption and hasattr(args, 'password') and args.password:
                    # Convert password to string if needed
                    file_password = args.password
                    if isinstance(file_password, bytes):
                        try:
                            file_password = file_password.decode('utf-8')
                        except UnicodeDecodeError:
                            # If we can't decode, just use as is
                            pass
                            
                    try:
                        # Get key with both passwords
                        if not args.quiet:
                            print(f"Using file password for dual-encrypted key")
                        try:
                            _, private_key = keystore.get_key(key_id, None, file_password)
                        except KeystorePasswordError as e:
                            if not args.quiet:
                                print(f"Keystore password error: {e}")
                            
                            # For dual-encrypted keys, this is likely a file password error
                            if dual_encryption:
                                print("Decryption failed: Incorrect file password for dual-encrypted key")
                                return False
                            else:
                                raise
                        except Exception as e:
                            if not args.quiet:
                                print(f"Error getting key: {e}")
                            raise
                            
                        pqc_private_key = private_key
                        
                        if not args.quiet:
                            print(f"Successfully retrieved key {key_id} from keystore for decryption")
                            
                    except Exception as e:
                        if args.verbose:
                            print(f"Error getting key with file password: {e}")
                        raise
                else:
                    # Get key without file password
                    try:
                        _, private_key = keystore.get_key(key_id)
                        pqc_private_key = private_key
                        
                        if not args.quiet:
                            print(f"Successfully retrieved key {key_id} from keystore for decryption")
                            
                    except Exception as e:
                        if not args.quiet:
                            print(f"Error getting key: {e}")
                        raise
                
                if not args.quiet:
                    print(f"Using keystore wrapper for decryption with key ID: {key_id}")
                
                # Decrypt using keystore wrapper
                result = keystore_wrapper.decrypt_file_with_keystore(
                    args.input,
                    args.output,
                    args.password,
                    quiet=args.quiet,
                    pqc_private_key=pqc_private_key,
                    keystore_file=args.keystore,
                    keystore_password=keystore_password,
                    key_id=key_id,
                    dual_encryption=dual_encryption
                )
                
                if not result:
                    print("Decryption failed")
                    return 1
                    
                if not args.quiet:
                    print(f"\nFile decrypted successfully: {args.output}")
                    
            except Exception as e:
                print(f"Decryption error: {e}")
                return 1
        elif args.pqc_keyfile:
            # Using an external key file for decryption
            pass
    else:
        # Standard decryption without keystore
        try:
            result = decrypt_file(
                args.input,
                args.output,
                args.password,
                quiet=args.quiet
            )
            
            if not result:
                print("Decryption failed")
                return 1
                
            if not args.quiet:
                print(f"\nFile decrypted successfully: {args.output}")
                
        except DecryptionError as e:
            print(f"Decryption error: {e}")
            return 1
        except Exception as e:
            print(f"Error: {e}")
            return 1
    
    # Handle secure deletion of encrypted file if requested
    if args.secure_delete:
        if SECURE_DELETE_AVAILABLE:
            from .crypt_utils import secure_delete_file
            
            if not args.quiet:
                print(f"Securely deleting encrypted file: {args.input}")
                
            secure_delete_file(args.input, 3, args.quiet)
        else:
            print("Secure deletion not available - skipping")
            
    return 0

def info_command(args):
    """Handle the info command"""
    # Validate args
    if not os.path.exists(args.input):
        print(f"Input file not found: {args.input}")
        return 1
    
    # Get information about the file
    try:
        # Extract metadata from the file
        with open(args.input, 'rb') as f:
            data = f.read(8192)  # Read enough for the header
        
        # Find the colon separator
        colon_pos = data.find(b':')
        if colon_pos <= 0:
            print(f"File does not appear to be encrypted: {args.input}")
            return 1
            
        # Extract and decode metadata
        metadata_b64 = data[:colon_pos]
        try:
            metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
            metadata = json.loads(metadata_json)
        except Exception:
            print(f"File does not contain valid metadata: {args.input}")
            return 1
            
        print(f"Encrypted file: {args.input}")
        
        # Print basic file info
        print(f"Size: {os.path.getsize(args.input)} bytes")
        if 'hash_config' in metadata:
            hash_config = metadata['hash_config']
            
            # Print algorithm info
            if 'algorithm' in hash_config:
                print(f"Algorithm: {hash_config['algorithm']}")
            
            # Print hash info
            print("\nHash configuration:")
            for hash_name in ['sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake2b', 'shake256', 'whirlpool']:
                if hash_name in hash_config and hash_config[hash_name] > 0:
                    print(f"  {hash_name}: {hash_config[hash_name]} iterations")
            
            # Print KDF info
            if 'pbkdf2_iterations' in hash_config:
                print(f"  PBKDF2: {hash_config['pbkdf2_iterations']} iterations")
            
            if 'scrypt' in hash_config and hash_config['scrypt'].get('enabled', False):
                print("  Scrypt: enabled")
                
            if 'argon2' in hash_config and hash_config['argon2'].get('enabled', False):
                print("  Argon2: enabled")
                
            # Check if PQC keystore key was used
            if 'pqc_keystore_key_id' in hash_config:
                print(f"\nPQC keystore key ID: {hash_config['pqc_keystore_key_id']}")
                
                # Check for dual encryption flag
                if 'dual_encryption' in hash_config and hash_config['dual_encryption']:
                    print("Dual encryption: enabled (requires both keystore and file passwords)")
                
            # Check if PQC key is embedded
            if 'pqc_private_key_embedded' in hash_config and hash_config['pqc_private_key_embedded']:
                print("\nPQC private key: embedded in file metadata")
        
    except Exception as e:
        print(f"Error analyzing file: {e}")
        return 1
        
    return 0

def main():
    """Main entrypoint"""
    parser = get_parser()
    args = parser.parse_args()
    
    if args.version:
        from . import version
        print(f"OpenSSL Encrypt version {version.VERSION}")
        return 0
    
    # If no command provided, print help
    if not args.command:
        parser.print_help()
        return 1
    
    # Handle each command
    if args.command == 'encrypt':
        return encrypt_command(args)
    elif args.command == 'decrypt':
        return decrypt_command(args)
    elif args.command == 'info':
        return info_command(args)
    else:
        print(f"Unknown command: {args.command}")
        return 1

if __name__ == "__main__":
    sys.exit(main())