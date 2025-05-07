#!/usr/bin/env python3
"""
Secure File Encryption Tool - Command Line Interface

This module provides the command-line interface for the encryption tool,
handling user input, parsing arguments, and calling the appropriate
functionality from the core and utils modules.
"""

import os
import sys
import argparse
import getpass
import uuid
import atexit
import signal
import tempfile
import time
import base64
import hashlib
import secrets
from enum import Enum
from typing import Dict, Any, Optional
import json
import yaml

# Import from local modules
from .crypt_core import (
    encrypt_file,
    decrypt_file,
    check_argon2_support,
    get_file_permissions,
    WHIRLPOOL_AVAILABLE,
    ARGON2_AVAILABLE,
    ARGON2_TYPE_INT_MAP,
    EncryptionAlgorithm,
    PQC_AVAILABLE,
    string_entropy)
from .crypt_utils import (
    secure_shred_file, expand_glob_patterns, generate_strong_password,
    display_password_with_timeout, show_security_recommendations,
    request_confirmation
)
from .password_policy import (
    PasswordPolicy, validate_password, validate_password_or_raise,
    get_password_strength
)
from . import crypt_errors
# Import keystore-related modules
from .keystore_wrapper import encrypt_file_with_keystore, decrypt_file_with_keystore
from .keystore_utils import extract_key_id_from_metadata, get_keystore_password, get_pqc_key_for_decryption, auto_generate_pqc_key


def debug_hash_config(args, hash_config, message="Hash configuration"):
    """Debug output for hash configuration"""
    print(f"\n{message}:")
    print(
        f"SHA3-512: args={args.sha3_512_rounds}, hash_config={hash_config.get('sha3_512', 'Not set')}")
    print(
        f"SHA3-256: args={args.sha3_256_rounds}, hash_config={hash_config.get('sha3_256', 'Not set')}")
    print(
        f"SHA-512: args={args.sha512_rounds}, hash_config={hash_config.get('sha512', 'Not set')}")
    print(
        f"SHA-256: args={args.sha256_rounds}, hash_config={hash_config.get('sha256', 'Not set')}")
    print(
        f"BLAKE2b: args={args.blake2b_rounds}, hash_config={hash_config.get('blake2b', 'Not set')}")
    print(
        f"SHAKE-256: args={args.shake256_rounds}, hash_config={hash_config.get('shake256', 'Not set')}")
    print(
        f"PBKDF2: args={args.pbkdf2_iterations}, hash_config={hash_config.get('pbkdf2_iterations', 'Not set')}")
    print(
        f"Scrypt: args.n={args.scrypt_n}, hash_config.n={hash_config.get('scrypt', {}).get('n', 'Not set')}")
    print(
        f"Argon2: args.enable_argon2={args.enable_argon2}, hash_config.enabled={hash_config.get('argon2', {}).get('enabled', 'Not set')}")


class SecurityTemplate(Enum):
    STANDARD = "standard"
    PARANOID = "paranoid"
    QUICK = "quick"


def show_version_info():
    """Display version information including git commit hash, Python version and dependencies."""
    import sys
    import platform
    from importlib.metadata import version as pkg_version
    import os

    # Import version information from version.py
    try:
        from openssl_encrypt.version import __version__, __git_commit__
        version_module_path = sys.modules['openssl_encrypt.version'].__file__
    except ImportError:
        __version__ = "unknown"
        __git_commit__ = "unknown"
        version_module_path = None

    # Get Python version
    python_version = sys.version.split()[0]
    python_implementation = platform.python_implementation()

    # Get system information
    system = platform.system()
    release = platform.release()

    # Get dependency versions
    dependencies = {
        "cryptography": "unknown",
        "argon2-cffi": "unknown",
        "PyYAML": "unknown"
    }

    # Try to get actual versions of dependencies
    for dep in dependencies:
        try:
            dependencies[dep] = pkg_version(dep)
        except Exception:
            pass

    # Format the output
    version_info = [
        f"openssl_encrypt: v{__version__} (commit: {__git_commit__})",
        f"Python: {python_implementation} {python_version}",
        f"System: {system} {release}",
        "\nDependencies:",
    ]

    for dep, ver in dependencies.items():
        version_info.append(f"  {dep}: {ver}")

    return "\n".join(version_info)


def load_template_file(template_name: str) -> Optional[Dict[str, Any]]:
    """
    Load a template file from the ./template directory.
    Supports JSON and YAML formats.

    Args:
        template_name: Name of the template file (without extension)

    Returns:
        Template configuration dict or None if template not found
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Move up one level from the modules directory to the project root
    project_root = os.path.dirname(script_dir)

    # Templates are in project root
    template_dir = os.path.join(project_root, "templates")

    # Try different extensions
    for ext in [".json", ".yaml", ".yml"]:
        template_path = os.path.join(template_dir, template_name + ext)
        if os.path.exists(template_path):
            try:
                with open(template_path, 'r') as f:
                    if ext == ".json":
                        return json.load(f)
                    else:
                        return yaml.safe_load(f)
            except Exception as e:
                print(f"Error loading template {template_path}: {e}")
                sys.exit(1)

    print(f"Template {template_name} not found in {template_dir}")
    sys.exit(1)


def get_template_config(template: str or SecurityTemplate) -> Dict[str, Any]:
    """
    Returns predefined hash configurations matching your metadata structure.
    """
    templates = {
        SecurityTemplate.QUICK: {
            "hash_config": {
                "sha512": 0,
                "sha256": 1000,
                "sha3_256": 0,
                "sha3_512": 10000,
                "blake2b": 0,
                "shake256": 0,
                "whirlpool": 0,
                "scrypt": {
                    "enabled": False,
                    "n": 128,
                    "r": 8,
                    "p": 1,
                    "rounds": 1000
                },
                "argon2": {
                    "enabled": False,
                    "time_cost": 2,
                    "memory_cost": 65536,  # 64MB
                    "parallelism": 4,
                    "hash_len": 32,
                    "type": 2,
                    "rounds": 10
                },
                "pbkdf2_iterations": 10000,
                "type": "id",
                "algorithm": "fernet"
            }
        },
        SecurityTemplate.STANDARD: {
            "hash_config": {
                "sha512": 0,
                "sha256": 0,
                "sha3_256": 0,
                "sha3_512": 600000,
                "blake2b": 200000,
                "shake256": 200000,
                "whirlpool": 0,
                "scrypt": {
                    "enabled": True,
                    "n": 128,
                    "r": 8,
                    "p": 1,
                    "rounds": 10
                },
                "argon2": {
                    "enabled": True,
                    "time_cost": 3,
                    "memory_cost": 65536,
                    "parallelism": 4,
                    "hash_len": 32,
                    "type": 2,
                    "rounds": 100
                },
                "pbkdf2_iterations": 0,
                "type": "id",
                "algorithm": "aes-gcm-siv"
            }
        },
        SecurityTemplate.PARANOID: {
            "hash_config": {
                "sha512": 10000,
                "sha256": 10000,
                "sha3_256": 10000,
                "sha3_512": 800000,
                "blake2b": 800000,
                "shake256": 400000,
                "scrypt": {
                    "enabled": True,
                    "n": 256,
                    "r": 16,
                    "p": 2,
                    "rounds": 100
                },
                "argon2": {
                    "enabled": True,
                    "time_cost": 4,
                    "memory_cost": 131072,  # 128MB
                    "parallelism": 8,
                    "hash_len": 64,
                    "type": 2,
                    "rounds": 200
                },
                "balloon": {
                    "enabled": True,
                    "time_cost": 3,
                    "space_cost": 65536,
                    "parallelism": 4,
                    "hash_len": 64,
                    "rounds": 5
                },
                "pbkdf2_iterations": 0,
                "type": "id",
                "algorithm": "xchacha20-poly1305"
            }
        }
    }

    # If template is a SecurityTemplate enum, use built-in template
    if isinstance(template, SecurityTemplate):
        return templates[template]

    # Otherwise, load template from file
    if isinstance(template, str):
        try:
            custom_template = load_template_file(template)
            if custom_template:
                # Validate template structure
                if "hash_config" in custom_template:
                    return custom_template
                else:
                    print(f"Invalid template format: missing 'hash_config' key")
                    sys.exit(1)
        except Exception as e:
            print(f"Error loading template file: {e}")
            sys.exit(1)


def main():
    """
    Main function that handles the command-line interface.
    """
    # Global variable to track temporary files that need cleanup
    temp_files_to_cleanup = []

    def cleanup_temp_files():
        """Clean up any temporary files that were created but not deleted"""
        for temp_file in temp_files_to_cleanup:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    if not args.quiet:
                        print(f"Cleaned up temporary file: {temp_file}")
            except Exception:
                pass

    # Register cleanup function to run on normal exit
    atexit.register(cleanup_temp_files)

    # Register signal handlers for common termination signals
    def signal_handler(signum, frame):
        cleanup_temp_files()
        # Re-raise the signal to allow the default handler to run
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    # Register handlers for common termination signals
    for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
        try:
            signal.signal(sig, signal_handler)
        except AttributeError:
            # Some signals might not be available on all platforms
            pass

    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Encrypt or decrypt a file with a password')

    # show or hide progess
    parser.add_argument(
        '--progress',
        action='store_true',
        help='Show progress bar'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show hash/kdf details'
    )

    # Add template argument
    parser.add_argument(
        '-t',
        '--template',
        help='Specify a template name (built-in or from ./template directory)')

    # Template selection group
    template_group = parser.add_mutually_exclusive_group()
    template_group.add_argument(
        '--quick',
        action='store_true',
        help='Use quick but secure configuration'
    )
    template_group.add_argument(
        '--standard',
        action='store_true',
        help='Use standard security configuration (default)'
    )
    template_group.add_argument(
        '--paranoid',
        action='store_true',
        help='Use maximum security configuration'
    )

    # Define core actions
    parser.add_argument(
        'action',
        choices=[
            'encrypt',
            'decrypt',
            'shred',
            'generate-password',
            'security-info',
            'check-argon2',
            'check-pqc',
            'version',
            'show-version-file'],
        help='Action to perform: encrypt/decrypt files, shred data, generate passwords, '
             'show security recommendations, check Argon2 support, check post-quantum cryptography support or display version file contents')

    parser.add_argument(
        '--algorithm',
        type=str,
        choices=[
            algo.value for algo in EncryptionAlgorithm],
        default=EncryptionAlgorithm.FERNET.value,
        help='Encryption algorithm to use: \n'
             '  fernet (default, AES-128-CBC with authentication), \n'
             '  aes-gcm (AES-256 in GCM mode, high security, widely trusted), \n'
             '  aes-gcm-siv (AES-256 in GCM-SIV mode, resistant to nonce reuse), \n'
             '  aes-ocb3 (AES-256 in OCB3 mode, faster than GCM), \n'
             '  aes-siv (AES in SIV mode, synthetic IV), \n'
             '  chacha20-poly1305 (modern AEAD cipher with 12-byte nonce), \n'
             '  xchacha20-poly1305 (ChaCha20-Poly1305 with 24-byte nonce, safer for high-volume encryption), \n'
             '  camellia (Camellia in CBC mode), \n'
             '  kyber512-hybrid (post-quantum key exchange with AES-256-GCM, NIST level 1), \n'
             '  kyber768-hybrid (post-quantum key exchange with AES-256-GCM, NIST level 3), \n'
             '  kyber1024-hybrid (post-quantum key exchange with AES-256-GCM, NIST level 5)')
    # Define common options
    parser.add_argument(
        '--password', '-p',
        help='Password (will prompt if not provided)'
    )
    parser.add_argument(
        '--random',
        type=int,
        metavar='LENGTH',
        help='Generate a random password of specified length for encryption'
    )
    parser.add_argument(
        '--input',
        '-i',
        help='Input file or directory (supports glob patterns for shred action)')
    parser.add_argument(
        '--output', '-o',
        help='Output file (optional for decrypt)'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress all output except decrypted content and exit code'
    )
    parser.add_argument(
        '--overwrite', '-f',
        action='store_true',
        help='Overwrite the input file with the output'
    )
    parser.add_argument(
        '--shred', '-s',
        action='store_true',
        help='Securely delete the original file after encryption/decryption'
    )
    parser.add_argument(
        '--shred-passes',
        type=int,
        default=3,
        help='Number of passes for secure deletion (default: 3)'
    )
    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        help='Process directories recursively when shredding'
    )

    # # Add memory security option
    # parser.add_argument(
    #     '--disable-secure-memory',
    #     action='store_true',
    #     help='Disable secure memory handling (not recommended)'
    # )

    # Group hash configuration arguments for better organization
    hash_group = parser.add_argument_group(
        'Hash Options', 'Configure hashing algorithms for key derivation')

    # SHA family arguments - updated to match the template naming
    hash_group.add_argument(
        '--sha512-rounds',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help='Number of SHA-512 iterations (default: 1,000,000 if flag provided without value)'
    )
    hash_group.add_argument(
        '--sha256-rounds',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help='Number of SHA-256 iterations (default: 1,000,000 if flag provided without value)'
    )
    hash_group.add_argument(
        '--sha3-256-rounds',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help='Number of SHA3-256 iterations (default: 1,000,000 if flag provided without value)'
    )
    hash_group.add_argument(
        '--sha3-512-rounds',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help='Number of SHA3-512 iterations (default: 1,000,000 if flag provided without value)'
    )
    hash_group.add_argument(
        '--blake2b-rounds',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help='Number of BLAKE2b iterations (default: 1,000,000 if flag provided without value)'
    )
    hash_group.add_argument(
        '--shake256-rounds',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help='Number of SHAKE-256 iterations (default: 1,000,000 if flag provided without value)'
    )
    hash_group.add_argument(
        '--whirlpool-rounds',
        type=int,
        default=0,
        help='Number of Whirlpool iterations (default: 0, not used)'
    )

    # PBKDF2 option - renamed for consistency
    hash_group.add_argument(
        '--pbkdf2-iterations',
        type=int,
        default=0,
        help='Number of PBKDF2 iterations (default: 100000)'
    )

    # Scrypt parameters group - updated to match the template naming
    scrypt_group = parser.add_argument_group(
        'Scrypt Options', 'Configure Scrypt memory-hard function parameters')
    scrypt_group.add_argument(
        '--enable-scrypt',
        action='store_true',
        help='Use Scrypt password hashing (requires scrypt package)',
        default=False
    )
    scrypt_group.add_argument(
        '--scrypt-rounds',
        type=int,
        default=1,
        help='Use scrypt rounds for interating (default: 1)'
    )
    scrypt_group.add_argument(
        '--scrypt-n',
        type=int,
        default=128,
        help='Scrypt CPU/memory cost factor N (default: 0, not used. Use power of 2 like 16384)'
    )
    scrypt_group.add_argument(
        '--scrypt-r',
        type=int,
        default=8,
        help='Scrypt block size parameter r (default: 8)'
    )
    scrypt_group.add_argument(
        '--scrypt-p',
        type=int,
        default=1,
        help='Scrypt parallelization parameter p (default: 1)'
    )

    # Add legacy option for backward compatibility
    scrypt_group.add_argument(
        '--scrypt-cost',
        type=int,
        default=0,
        help=argparse.SUPPRESS  # Hidden legacy option
    )

    # Add Keystore options
    keystore_group = parser.add_argument_group('Keystore Options', 'Configure keystore integration for key management')
    keystore_group.add_argument(
        '--keystore',
        help='Path to the keystore file'
    )
    keystore_group.add_argument(
        '--keystore-password',
        help='Password for the keystore (will prompt if not provided)'
    )
    keystore_group.add_argument(
        '--keystore-password-file',
        help='File containing the keystore password'
    )
    keystore_group.add_argument(
        '--key-id',
        help='ID of the key to use from keystore'
    )
    keystore_group.add_argument(
        '--dual-encrypt-key',
        action='store_true',
        help='Use dual encryption for the key (requires both keystore and file passwords)'
    )
    keystore_group.add_argument(
        '--auto-generate-key',
        action='store_true',
        help='Explicitly request to generate and store a PQC key in the keystore (happens automatically for PQC algorithms)'
    )
    keystore_group.add_argument(
        '--auto-create-keystore',
        action='store_true',
        help='Automatically create keystore if it does not exist'
    )
    
    # Add Post-Quantum Cryptography options
    pqc_group = parser.add_argument_group('Post-Quantum Cryptography Options')
    pqc_group.add_argument(
        '--pqc-keyfile',
        help='Path to store or load post-quantum key pair'
    )
    pqc_group.add_argument(
        '--pqc-store-key',
        action='store_true',
        help='Store the post-quantum private key in the encrypted file (less secure but enables self-decryption)'
    )
    pqc_group.add_argument(
        '--pqc-gen-key',
        action='store_true',
        help='Generate a new post-quantum key pair and store in the path specified by --pqc-keyfile'
    )

    # Argon2 parameters group - updated for consistency
    argon2_group = parser.add_argument_group(
        'Argon2 Options', 'Configure Argon2 memory-hard function parameters')
    argon2_group.add_argument(
        '--enable-argon2',
        action='store_true',
        help='Use Argon2 password hashing (requires argon2-cffi package)',
        default=False
    )
    argon2_group.add_argument(
        '--argon2-rounds',
        type=int,
        default=1,
        help='Argon2 time cost parameter (default: 1)'
    )
    argon2_group.add_argument(
        '--argon2-time',
        type=int,
        default=3,
        help='Argon2 time cost parameter (default: 3)'
    )
    argon2_group.add_argument(
        '--argon2-memory',
        type=int,
        default=65536,
        help='Argon2 memory cost in KB (default: 65536 - 64MB)'
    )
    argon2_group.add_argument(
        '--argon2-parallelism',
        type=int,
        default=4,
        help='Argon2 parallelism factor (default: 4)'
    )
    argon2_group.add_argument(
        '--argon2-hash-len',
        type=int,
        default=32,
        help='Argon2 hash length in bytes (default: 32)'
    )
    argon2_group.add_argument(
        '--argon2-type',
        choices=['id', 'i', 'd'],
        default='id',
        help='Argon2 variant to use: id (recommended), i, or d'
    )
    argon2_group.add_argument(
        '--argon2-preset',
        choices=['low', 'medium', 'high', 'paranoid'],
        help='Use predefined Argon2 parameters (overrides other Argon2 settings)'
    )

    # Add legacy option for backward compatibility
    argon2_group.add_argument(
        '--use-argon2',
        action='store_true',
        help=argparse.SUPPRESS  # Hidden legacy option
    )

    balloon_group = parser.add_argument_group('Balloon Hashing options')
    balloon_group.add_argument(
        '--enable-balloon',
        action='store_true',
        help='Enable Balloon Hashing KDF'  # Hidden legacy option''
    )
    balloon_group.add_argument(
        '--balloon-time-cost',
        type=int,
        default=3,
        help='Time cost parameter for Balloon hashing - controls computational complexity. Higher values increase security but also processing time.'
    )
    balloon_group.add_argument(
        '--balloon-space-cost',
        type=int,
        default=65536,
        help='Space cost parameter for Balloon hashing in bytes - controls memory usage. Higher values increase security but require more memory.'
    )
    balloon_group.add_argument(
        '--balloon-parallelism',
        type=int,
        default=4,
        help='Parallelism parameter for Balloon hashing - controls number of parallel threads. Higher values can improve performance on multi-core systems.'
    )
    balloon_group.add_argument(
        '--balloon-rounds',
        type=int,
        default=2,
        help='Number of rounds for Balloon hashing. More rounds increase security but also processing time.'
    )
    balloon_group.add_argument(
        '--balloon-hash-len',
        type=int,
        default=32,
        help='Length of the final hash output in bytes for Balloon hashing.'
    )
    balloon_group.add_argument(
        '--use-balloon',
        action='store_true',
        help=argparse.SUPPRESS  # Hidden legacy option'
    )

    # Legacy options for backward compatibility
    hash_group.add_argument(
        '--sha512',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help=argparse.SUPPRESS)
    hash_group.add_argument(
        '--sha256',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help=argparse.SUPPRESS)
    hash_group.add_argument(
        '--sha3-256',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help=argparse.SUPPRESS)
    hash_group.add_argument(
        '--sha3-512',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help=argparse.SUPPRESS)
    hash_group.add_argument(
        '--blake2b',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help=argparse.SUPPRESS)
    hash_group.add_argument(
        '--shake256',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help=argparse.SUPPRESS)
    hash_group.add_argument(
        '--pbkdf2',
        type=int,
        default=100000,
        help=argparse.SUPPRESS)

    # Password generation options
    password_group = parser.add_argument_group('Password Generation Options')
    password_group.add_argument(
        '--length',
        type=int,
        default=16,
        help='Length of generated password (default: 16)'
    )
    password_group.add_argument(
        '--use-digits',
        action='store_true',
        help='Include digits in generated password'
    )
    password_group.add_argument(
        '--use-lowercase',
        action='store_true',
        help='Include lowercase letters in generated password'
    )
    password_group.add_argument(
        '--use-uppercase',
        action='store_true',
        help='Include uppercase letters in generated password'
    )
    password_group.add_argument(
        '--use-special',
        action='store_true',
        help='Include special characters in generated password'
    )

    # Password policy options
    policy_group = parser.add_argument_group('Password Policy Options',
                                             'Configure password strength validation')
    policy_group.add_argument(
        '--password-policy',
        choices=['minimal', 'basic', 'standard', 'paranoid', 'none'],
        default='standard',
        help='Password policy level to enforce (default: standard)'
    )
    policy_group.add_argument(
        '--min-password-length',
        type=int,
        help='Minimum password length (overrides policy level)'
    )
    policy_group.add_argument(
        '--min-password-entropy',
        type=float,
        help='Minimum password entropy in bits (overrides policy level)'
    )
    policy_group.add_argument(
        '--disable-common-password-check',
        action='store_true',
        help='Disable checking against common password lists'
    )
    policy_group.add_argument(
        '--force-password',
        action='store_true',
        help='Force acceptance of weak passwords (use with caution)'
    )
    policy_group.add_argument(
        '--custom-password-list',
        help='Path to custom common password list file'
    )

    args = parser.parse_args()

    # Handle legacy options and map to new names
    # SHA family mappings
    if not args.sha512_rounds and args.sha512:
        args.sha512_rounds = args.sha512
    if not args.sha256_rounds and args.sha256:
        args.sha256_rounds = args.sha256
    if not args.sha3_256_rounds and args.sha3_256:
        args.sha3_256_rounds = args.sha3_256
    if not args.sha3_512_rounds and args.sha3_512:
        args.sha3_512_rounds = args.sha3_512
    if not args.blake2b_rounds and args.blake2b:
        args.blake2b_rounds = args.blake2b
    if not args.shake256_rounds and args.shake256:
        args.shake256_rounds = args.shake256

    # PBKDF2 mapping
    if args.pbkdf2 != 100000:  # Only override if not the default
        args.pbkdf2_iterations = args.pbkdf2

    # Argon2 mapping
    if args.use_argon2:
        args.enable_argon2 = True

    if args.enable_balloon:
        args.use_balloon = True

    if args.action == 'version':
        print(show_version_info())
        return 0

    if args.action == 'show-version-file':
        try:
            from openssl_encrypt.version import print_version_info, get_version_info

            # Call print_version_info function to show detailed version information
            print_version_info()

            # Additionally, show the full version info dictionary
            version_info = get_version_info()
            print("\nComplete Version Information:")
            print("----------------------------")
            for key, value in version_info.items():
                if key == "history":
                    # Skip history as it was already printed by print_version_info
                    continue
                print(f"{key}: {value}")

            return 0
        except ImportError:
            print("Version module not found. Run 'pip install -e .' to generate the version file.")
            return 1

    # Handle scrypt_cost conversion to scrypt_n
    if args.scrypt_cost > 0 and args.scrypt_n == 0:
        args.scrypt_n = 2 ** args.scrypt_cost

    # Check for utility and information actions first
    if args.action == 'security-info':
        show_security_recommendations()
        sys.exit(0)

    elif args.action == 'check-argon2':
        argon2_available, version, supported_types = check_argon2_support()
        print("\nARGON2 SUPPORT CHECK")
        print("====================")
        if argon2_available:
            print(f"✓ Argon2 is AVAILABLE (version {version})")
            print(
                f"✓ Supported variants: {
                ', '.join(
                    'Argon2' +
                    t for t in supported_types)}")

            # Try a test hash to verify functionality
            try:
                import argon2
                test_hash = argon2.low_level.hash_secret_raw(
                    b"test_password",
                    b"testsalt12345678",
                    time_cost=1,
                    memory_cost=8,
                    parallelism=1,
                    hash_len=16,
                    type=argon2.low_level.Type.ID
                )
                if len(test_hash) == 16:
                    print("✓ Argon2 functionality test: PASSED")
                else:
                    print("✗ Argon2 functionality test: FAILED (unexpected hash length)")
            except Exception as e:
                print(f"✗ Argon2 functionality test: FAILED with error: {e}")
        else:
            print("✗ Argon2 is NOT AVAILABLE")
            print("\nTo enable Argon2 support, install the argon2-cffi package:")
            print("    pip install argon2-cffi")
        sys.exit(0)

    elif args.action == 'check-pqc':
        from .pqc import check_pqc_support, PQCAlgorithm

        pqc_available, version, supported_algorithms = check_pqc_support(quiet=args.quiet)
        if not args.quiet:
            print("\nPOST-QUANTUM CRYPTOGRAPHY SUPPORT CHECK")
            print("======================================")
        if pqc_available:
            if not args.quiet:
                print(f"✓ Post-quantum cryptography is AVAILABLE (liboqs version {version})")
                print("✓ Supported algorithms:")

                # Organize algorithms by type
                kems = [algo for algo in supported_algorithms if 'Kyber' in algo]
                sigs = [algo for algo in supported_algorithms if 'Kyber' not in algo]

                if kems:
                    print("\n  Key Encapsulation Mechanisms (KEMs):")
                    for algo in kems:
                        print(f"    - {algo}")

                if sigs:
                    print("\n  Digital Signature Algorithms:")
                    for algo in sigs:
                        print(f"    - {algo}")

            # Try a test encryption to verify functionality
            try:
                from .pqc import PQCipher
                test_cipher = PQCipher(PQCAlgorithm.KYBER768, quiet=args.quiet)
                public_key, private_key = test_cipher.generate_keypair()
                test_data = b"Test post-quantum encryption"
                encrypted = test_cipher.encrypt(test_data, public_key)
                decrypted = test_cipher.decrypt(encrypted, private_key)

                if decrypted == test_data:
                    print("\n✓ Post-quantum encryption functionality test: PASSED")
                else:
                    print("\n✗ Post-quantum encryption functionality test: FAILED (decryption mismatch)")
            except Exception as e:
                print(f"\n✗ Post-quantum encryption functionality test: FAILED with error: {e}")
        else:
            print("✗ Post-quantum cryptography is NOT AVAILABLE")
            print("\nTo enable post-quantum cryptography support, install the liboqs-python package:")
            print("    pip install liboqs-python")

        print("\nUsage examples:")
        print("  Encrypt with Kyber-768 (NIST Level 3):")
        print("    python -m openssl_encrypt.crypt encrypt -i file.txt --algorithm kyber768-hybrid")
        print("\n  Generate and save a key pair:")
        print(
            "    python -m openssl_encrypt.crypt encrypt -i file.txt --algorithm kyber768-hybrid --pqc-gen-key --pqc-keyfile key.pqc")
        print("\n  Decrypt using a saved key pair:")
        print("    python -m openssl_encrypt.crypt decrypt -i file.txt.enc -o file.txt --pqc-keyfile key.pqc")

        sys.exit(0)

    elif args.action == 'generate-password':
        # If no character sets are explicitly selected, use all by default
        if not (
                args.use_lowercase or args.use_uppercase or args.use_digits or args.use_special):
            args.use_lowercase = True
            args.use_uppercase = True
            args.use_digits = True
            args.use_special = True

        # Apply password policy if specified
        if args.password_policy != 'none' and not args.force_password:
            # Create policy to get minimum required length
            policy_params = {}
            if args.min_password_length is not None:
                policy_params['min_length'] = args.min_password_length

            policy = PasswordPolicy(
                policy_level=args.password_policy,
                **policy_params
            )

            # Ensure length meets policy requirements
            if args.length < policy.min_length:
                print(
                    f"\nIncreasing password length from {args.length} to {policy.min_length} to meet policy requirements")
                args.length = policy.min_length

        # Generate password
        password = generate_strong_password(
            args.length,
            args.use_lowercase,
            args.use_uppercase,
            args.use_digits,
            args.use_special
        )

        # Check password strength
        entropy, strength = get_password_strength(password)
        print(f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)")

        # Validate against policy
        if args.password_policy != 'none':
            policy_params = {}
            if args.min_password_entropy is not None:
                policy_params['min_entropy'] = args.min_password_entropy

            if args.disable_common_password_check:
                policy_params['check_common_passwords'] = False

            if args.custom_password_list:
                policy_params['common_passwords_path'] = args.custom_password_list

            # Create policy
            policy = PasswordPolicy(
                policy_level=args.password_policy,
                **policy_params
            )

            # Check if generated password meets policy (it should, but verify)
            valid, _ = policy.validate_password(password, quiet=True)
            if not valid:
                # This is rare but could happen with specific combinations of constraints
                print("Warning: Generated password does not meet policy requirements.")
                print("Consider adjusting character requirements or using a longer length.")

        # Display the password
        display_password_with_timeout(password)
        # Exit after generating password
        sys.exit(0)

    # For other actions, input file is required
    if args.input is None:
        parser.error("the following arguments are required: --input/-i")

    # Get password (only for encrypt/decrypt actions)
    if args.action in ['encrypt', 'decrypt']:
        password = None
        generated_password = None

        try:
            from .secure_memory import secure_string, secure_input, SecureBytes

            # Initialize a secure string to hold the password
            with secure_string() as password_secure:
                # Handle random password generation for encryption
                if args.action == 'encrypt' and args.random and not args.password:
                    # Determine character sets based on args or defaults
                    use_lowercase = args.use_lowercase if args.use_lowercase is not None else True
                    use_uppercase = args.use_uppercase if args.use_uppercase is not None else True
                    use_digits = args.use_digits if args.use_digits is not None else True
                    use_special = args.use_special if args.use_special is not None else True

                    # Ensure length meets policy requirements
                    if args.password_policy != 'none' and not args.force_password:
                        # Create policy to get minimum required length
                        policy_params = {}
                        if args.min_password_length is not None:
                            policy_params['min_length'] = args.min_password_length

                        policy = PasswordPolicy(
                            policy_level=args.password_policy,
                            **policy_params
                        )

                        # Ensure random password length meets policy requirements
                        if args.random < policy.min_length:
                            if not args.quiet:
                                print(
                                    f"\nIncreasing random password length from {args.random} to {policy.min_length} to meet policy requirements")
                            args.random = policy.min_length

                    # Generate password with requested settings
                    generated_password = generate_strong_password(
                        args.random,
                        use_lowercase=use_lowercase,
                        use_uppercase=use_uppercase,
                        use_digits=use_digits,
                        use_special=use_special,
                        use_secure_mem=True
                    )

                    # Validate the generated password against policy
                    if args.password_policy != 'none':
                        policy_params = {}
                        if args.min_password_entropy is not None:
                            policy_params['min_entropy'] = args.min_password_entropy

                        if args.disable_common_password_check:
                            policy_params['check_common_passwords'] = False

                        if args.custom_password_list:
                            policy_params['common_passwords_path'] = args.custom_password_list

                        # Create policy
                        policy = PasswordPolicy(
                            policy_level=args.password_policy,
                            **policy_params
                        )

                        # Check if generated password meets policy (it should, but verify)
                        valid, msgs = policy.validate_password(generated_password, quiet=args.quiet)

                        # Print strength information
                        if not args.quiet:
                            for msg in msgs:
                                if "Password strength:" in msg:
                                    print(f"\n{msg}")

                    password_secure.extend(generated_password.encode())
                    if not args.quiet:
                        print("\nGenerated a random password for encryption.")

                # If password provided as argument
                elif args.password:
                    # Skip validation in test mode
                    in_test_mode = os.environ.get('PYTEST_CURRENT_TEST') is not None

                    # Validate password strength if policy is enabled, not in force mode, and not in test mode
                    if args.password_policy != 'none' and not args.force_password and not in_test_mode:
                        try:
                            # Create policy with user-specified parameters
                            policy_params = {}

                            # Override policy settings with custom parameters if provided
                            if args.min_password_length is not None:
                                policy_params['min_length'] = args.min_password_length

                            if args.min_password_entropy is not None:
                                policy_params['min_entropy'] = args.min_password_entropy

                            if args.disable_common_password_check:
                                policy_params['check_common_passwords'] = False

                            if args.custom_password_list:
                                policy_params['common_passwords_path'] = args.custom_password_list

                            # Create policy
                            policy = PasswordPolicy(
                                policy_level=args.password_policy,
                                **policy_params
                            )

                            # Validate the password (will raise ValidationError if invalid)
                            policy.validate_password_or_raise(args.password, quiet=args.quiet)

                        except crypt_errors.ValidationError as e:
                            # Always display password strength information before validation failure
                            if not args.quiet:
                                # Calculate and display password strength
                                entropy, strength = get_password_strength(args.password)
                                print(f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)")
                                print(f"Password validation failed: {str(e)}")
                                print("Use --force-password to bypass validation (not recommended)")
                            sys.exit(1)

                    password_secure.extend(args.password.encode())

                # If no password provided yet, prompt the user
                else:
                    # For encryption, require password confirmation to
                    # prevent typos
                    if args.action == 'encrypt' and not args.quiet:
                        match = False
                        while not match:
                            pwd1 = getpass.getpass(
                                'Enter password: ').encode()
                            pwd2 = getpass.getpass(
                                'Confirm password: ').encode()

                            if pwd1 == pwd2:
                                # Validate password if policy is enabled, not forced, and not in test mode
                                valid_password = True
                                in_test_mode = os.environ.get('PYTEST_CURRENT_TEST') is not None

                                if args.password_policy != 'none' and not args.force_password and not in_test_mode:
                                    try:
                                        # Create policy with user-specified parameters
                                        policy_params = {}

                                        # Override policy settings with custom parameters if provided
                                        if args.min_password_length is not None:
                                            policy_params['min_length'] = args.min_password_length

                                        if args.min_password_entropy is not None:
                                            policy_params['min_entropy'] = args.min_password_entropy

                                        if args.disable_common_password_check:
                                            policy_params['check_common_passwords'] = False

                                        if args.custom_password_list:
                                            policy_params['common_passwords_path'] = args.custom_password_list

                                        # Create policy and validate password
                                        policy = PasswordPolicy(
                                            policy_level=args.password_policy,
                                            **policy_params
                                        )
                                        policy.validate_password_or_raise(pwd1.decode('utf-8', errors='ignore'))

                                    except crypt_errors.ValidationError as e:
                                        # Calculate and display password strength
                                        entropy, strength = get_password_strength(pwd1.decode('utf-8', errors='ignore'))
                                        print(f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)")
                                        print(f"Password validation failed: {str(e)}")
                                        print("Use --force-password to bypass validation (not recommended)")
                                        valid_password = False

                                if valid_password:
                                    password_secure.extend(pwd1)
                                    match = True

                                # Securely clear the temporary buffers
                                pwd1 = b'\x00' * len(pwd1)
                                pwd2 = b'\x00' * len(pwd2)
                            else:
                                # Securely clear the temporary buffers
                                pwd1 = b'\x00' * len(pwd1)
                                pwd2 = b'\x00' * len(pwd2)
                                print(
                                    "Passwords do not match. Please try again.")
                    # For decryption or quiet mode, just ask once
                    else:
                        # Always prompt for a password, even in quiet mode
                        # We need to show the prompt but we can hide any extra text
                        pwd = getpass.getpass('Enter password: ')

                        # In quiet mode, move up one line and clear it after getting the password
                        if args.quiet:
                            sys.stdout.write('\033[A\033[K')
                            sys.stdout.flush()

                        password_secure.extend(pwd.encode('utf-8'))
                        # Securely clear the temporary buffer
                        pwd = b'\x00' * len(pwd)

                # Convert to bytes for the rest of the code
                password = bytes(password_secure)

        except ImportError:
            # Fall back to standard method if secure_memory is not
            # available
            if not args.quiet:
                print("Warning: secure_memory module not available")
            sys.exit(1)

    # Check for Whirlpool availability if needed and not in quiet mode
    if args.whirlpool_rounds > 0 and not WHIRLPOOL_AVAILABLE and not args.quiet:
        print("Warning: pywhirlpool module not found. SHA-512 will be used instead.")

    # Check for Argon2 availability if needed
    if (args.enable_argon2 or args.argon2_preset) and not ARGON2_AVAILABLE:
        if not args.quiet:
            print("Warning: argon2-cffi module not found. Argon2 will be disabled.")
            print("Install with: pip install argon2-cffi")
        args.enable_argon2 = False
        args.argon2_preset = None

    # Check for post-quantum cryptography availability if needed
    if args.algorithm in ['kyber512-hybrid', 'kyber768-hybrid', 'kyber1024-hybrid']:
        try:
            # Attempt direct import to ensure module is truly available
            import oqs
            pqc_available = True
        except ImportError:
            pqc_available = False

        if not pqc_available:
            if not args.quiet:
                print("Warning: liboqs-python module not found. Post-quantum cryptography will not be available.")
                print("Install with: pip install liboqs-python")
                print("Falling back to aes-gcm algorithm.")
            args.algorithm = 'aes-gcm'

    # Validate random password parameter
    if args.random is not None:
        if args.action != 'encrypt':
            parser.error("--random can only be used with the encrypt action")
        if args.password:
            parser.error("--password and --random cannot be used together")
        if args.random < 12:
            if not args.quiet:
                print(
                    f"Warning: Random password length increased to 12 (minimum secure length)")
            args.random = 12

    # Set default iterations if SHA algorithms are requested but no iterations
    # provided
    MIN_SHA_ITERATIONS = 1000000

    # If user specified to use SHA-256, SHA-512, or SHA3 but didn't provide
    # iterations
    if args.sha256_rounds == 1:  # When flag is provided without value
        args.sha256_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(
                f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-256")

    if args.sha512_rounds == 1:  # When flag is provided without value
        args.sha512_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(
                f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-512")

    if args.sha3_256_rounds == 1:  # When flag is provided without value
        args.sha3_256_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(
                f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-256")

    if args.sha3_512_rounds == 1:  # When flag is provided without value
        args.sha3_512_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(
                f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-512")

    if args.blake2b_rounds == 1:  # When flag is provided without value
        args.blake2b_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(
                f"Using default of {MIN_SHA_ITERATIONS} iterations for BLAKE2b")

    if args.shake256_rounds == 1:  # When flag is provided without value
        args.shake256_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(
                f"Using default of {MIN_SHA_ITERATIONS} iterations for SHAKE-256")

    # Handle Argon2 presets if specified
    if args.argon2_preset and ARGON2_AVAILABLE:
        args.enable_argon2 = True

        # Define the presets with increasingly stronger parameters
        argon2_presets = {
            'low': {
                'time_cost': 2,
                'memory_cost': 32768,  # 32 MB
                'parallelism': 2,
                'hash_len': 32,
                'type': 'id'
            },
            'medium': {
                'time_cost': 3,
                'memory_cost': 65536,  # 64 MB
                'parallelism': 4,
                'hash_len': 32,
                'type': 'id'
            },
            'high': {
                'time_cost': 4,
                'memory_cost': 131072,  # 128 MB
                'parallelism': 6,
                'hash_len': 32,
                'type': 'id'
            },
            'paranoid': {
                'time_cost': 6,
                'memory_cost': 262144,  # 256 MB
                'parallelism': 8,
                'hash_len': 64,
                'type': 'id'
            }
        }

        # Apply the selected preset
        preset = argon2_presets[args.argon2_preset]
        args.argon2_time = preset['time_cost']
        args.argon2_memory = preset['memory_cost']
        args.argon2_parallelism = preset['parallelism']
        args.argon2_hash_len = preset['hash_len']
        args.argon2_type = preset['type']

        if not args.quiet:
            print(
                f"Using Argon2 preset '{
                args.argon2_preset}' with parameters:")
            print(f"  - Time cost: {args.argon2_time}")
            print(f"  - Memory: {args.argon2_memory} KB")
            print(f"  - Parallelism: {args.argon2_parallelism}")
            print(f"  - Hash length: {args.argon2_hash_len} bytes")
            print(f"  - Type: Argon2{args.argon2_type}")

    # Create the hash configuration dictionary
    if args.paranoid or args.quick or args.standard:
        if args.paranoid:
            hash_config = get_template_config(SecurityTemplate.PARANOID)
            hash_config['hash_config']['algorithm'] = 'xchacha20-poly1305'
        elif args.quick:
            hash_config = get_template_config(SecurityTemplate.QUICK)
            hash_config['hash_config']['algorithm'] = 'aes-ocb3'
        elif args.standard:
            hash_config = get_template_config(SecurityTemplate.STANDARD)
            hash_config['hash_config']['algorithm'] = 'aes-gcm-siv'
        setattr(args, 'algorithm', hash_config['hash_config']['algorithm'])
        hash_config = hash_config['hash_config']
    elif args.template:
        hash_config = get_template_config(args.template)
        if hash_config['hash_config']['algorithm']:
            setattr(args, 'algorithm', hash_config['hash_config']['algorithm'])
        else:
            hash_config['hash_config']['algorithm'] = 'fernet'
            setattr(args, 'algorithm', 'fernet')
        hash_config = hash_config['hash_config']
    else:
        hash_config = {
            'sha512': args.sha512_rounds,
            'sha256': args.sha256_rounds,
            'sha3_256': args.sha3_256_rounds,
            'sha3_512': args.sha3_512_rounds,
            'blake2b': args.blake2b_rounds,
            'shake256': args.shake256_rounds,
            'whirlpool': args.whirlpool_rounds,
            'scrypt': {
                'enabled': args.enable_scrypt,
                'n': args.scrypt_n,
                'r': args.scrypt_r,
                'p': args.scrypt_p,
                'rounds': args.scrypt_rounds
            },
            'argon2': {
                'enabled': args.enable_argon2,
                'time_cost': args.argon2_time,
                'memory_cost': args.argon2_memory,
                'parallelism': args.argon2_parallelism,
                'hash_len': args.argon2_hash_len,
                # Store integer value for JSON serialization
                'type': ARGON2_TYPE_INT_MAP[args.argon2_type],
                'rounds': args.argon2_rounds
            },
            'balloon': {
                'enabled': args.enable_balloon,
                'time_cost': args.balloon_time_cost,
                'space_cost': args.balloon_space_cost,
                'parallelism': args.balloon_parallelism,
                'rounds': args.balloon_rounds

            },
            'pbkdf2_iterations': args.pbkdf2_iterations
        }

    # Uncomment this line to debug the hash configuration
    # debug_hash_config(args, hash_config, "Hash configuration after setup")

    exit_code = 0
    try:
        if args.action == 'encrypt':
            # Handle output file path
            if args.overwrite:
                output_file = args.input
                # Create a temporary file for the encryption to enable atomic
                # replacement
                temp_dir = os.path.dirname(os.path.abspath(args.input))
                temp_suffix = f".{uuid.uuid4().hex[:12]}.tmp"
                temp_output = os.path.join(temp_dir, f".{os.path.basename(args.input)}{temp_suffix}")

                # Add to cleanup list in case process is interrupted
                temp_files_to_cleanup.append(temp_output)

                try:
                    # Get original file permissions before doing anything
                    original_permissions = get_file_permissions(args.input)
                    # Handle PQC key operations
                    pqc_keypair = None
                    if args.algorithm in ['kyber512-hybrid', 'kyber768-hybrid', 'kyber1024-hybrid']:
                        # Check if we should generate and save a new key pair
                        if args.pqc_gen_key and args.pqc_keyfile:
                            from .pqc import PQCipher, PQCAlgorithm, check_pqc_support

                            # Map algorithm name to PQCAlgorithm with fallbacks
                            pqc_algorithms = check_pqc_support(quiet=args.quiet)[2]

                            # Determine which variants are available
                            kyber512_options = [alg for alg in pqc_algorithms if
                                                alg.lower().replace('-', '').replace('_', '') in ["kyber512",
                                                                                                  "mlkem512"]]
                            kyber768_options = [alg for alg in pqc_algorithms if
                                                alg.lower().replace('-', '').replace('_', '') in ["kyber768",
                                                                                                  "mlkem768"]]
                            kyber1024_options = [alg for alg in pqc_algorithms if
                                                 alg.lower().replace('-', '').replace('_', '') in ["kyber1024",
                                                                                                   "mlkem1024"]]

                            # Choose first available or fall back to default name
                            kyber512_algo = kyber512_options[0] if kyber512_options else "Kyber512"
                            kyber768_algo = kyber768_options[0] if kyber768_options else "Kyber768"
                            kyber1024_algo = kyber1024_options[0] if kyber1024_options else "Kyber1024"

                            if not args.quiet:
                                print(
                                    f"Using algorithm mappings: kyber512-hybrid → {kyber512_algo}, kyber768-hybrid → {kyber768_algo}, kyber1024-hybrid → {kyber1024_algo}")

                            # Create direct string mapping instead of using enum
                            algo_map = {
                                'kyber512-hybrid': kyber512_algo,
                                'kyber768-hybrid': kyber768_algo,
                                'kyber1024-hybrid': kyber1024_algo
                            }

                            # Generate key pair
                            cipher = PQCipher(algo_map[args.algorithm], quiet=args.quiet)
                            public_key, private_key = cipher.generate_keypair()

                            # Save key pair to file
                            import json
                            import base64

                            key_data = {
                                'algorithm': args.algorithm,
                                'public_key': base64.b64encode(public_key).decode('utf-8'),
                                'private_key': base64.b64encode(private_key).decode('utf-8')
                            }

                            with open(args.pqc_keyfile, 'w') as f:
                                json.dump(key_data, f)

                            if not args.quiet:
                                print(f"Post-quantum key pair saved to {args.pqc_keyfile}")

                            pqc_keypair = (public_key, private_key)

                        # Check if we should load an existing key pair
                        elif args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
                            import json
                            import base64

                            with open(args.pqc_keyfile, 'r') as f:
                                key_data = json.load(f)

                            if 'public_key' in key_data and 'private_key' in key_data:
                                public_key = base64.b64decode(key_data['public_key'])
                                private_key = base64.b64decode(key_data['private_key'])
                                pqc_keypair = (public_key, private_key)

                                if not args.quiet:
                                    print(f"Loaded post-quantum key pair from {args.pqc_keyfile}")

                    # For PQC algorithms, we may need to generate a keypair if not specified
                    if args.algorithm in ['kyber512-hybrid', 'kyber768-hybrid', 'kyber1024-hybrid'] and not pqc_keypair:
                        # No keypair provided, generate an ephemeral one
                        from .pqc import PQCipher, check_pqc_support

                        # Map algorithm name to available algorithms
                        pqc_algorithms = check_pqc_support(quiet=args.quiet)[2]
                        kyber512_options = [alg for alg in pqc_algorithms if
                                            alg.lower().replace('-', '').replace('_', '') in ["kyber512", "mlkem512"]]
                        kyber768_options = [alg for alg in pqc_algorithms if
                                            alg.lower().replace('-', '').replace('_', '') in ["kyber768", "mlkem768"]]
                        kyber1024_options = [alg for alg in pqc_algorithms if
                                             alg.lower().replace('-', '').replace('_', '') in ["kyber1024",
                                                                                               "mlkem1024"]]

                        # Choose first available algorithm
                        algo_map = {
                            'kyber512-hybrid': kyber512_options[0] if kyber512_options else "Kyber512",
                            'kyber768-hybrid': kyber768_options[0] if kyber768_options else "Kyber768",
                            'kyber1024-hybrid': kyber1024_options[0] if kyber1024_options else "Kyber1024"
                        }

                        if not args.quiet:
                            print(f"Generating ephemeral post-quantum key pair for {args.algorithm}")
                            if args.pqc_store_key:
                                print("Private key will be stored in the encrypted file for self-decryption")
                            else:
                                print(
                                    "WARNING: Private key will NOT be stored - you must use a key file for decryption")

                        cipher = PQCipher(algo_map[args.algorithm], quiet=args.quiet)
                        public_key, private_key = cipher.generate_keypair()
                        pqc_keypair = (public_key, private_key)

                    # Check if we should use keystore integration
                    if hasattr(args, 'keystore') and args.keystore:
                        # First, check if the keystore exists
                        if not os.path.exists(args.keystore):
                            # Keystore doesn't exist
                            create_new = False
                            if getattr(args, 'auto_create_keystore', False):
                                # Auto-create keystore is enabled
                                if not args.quiet:
                                    print(f"Keystore not found at {args.keystore}, creating a new one")
                                create_new = True
                            else:
                                # Prompt the user if they want to create a new keystore or abort
                                if not args.quiet:
                                    print(f"Keystore not found at {args.keystore}")
                                    print("Use --auto-create-keystore option to automatically create keystore")
                                    create_prompt = input("Would you like to create a new keystore? (y/n): ").lower().strip()
                                    create_new = create_prompt.startswith('y')
                            
                            if create_new:
                                # Create a new keystore
                                from .keystore_cli import PQCKeystore, KeystoreSecurityLevel
                                
                                # Get keystore password
                                keystore_password = None
                                if hasattr(args, 'keystore_password') and args.keystore_password:
                                    keystore_password = args.keystore_password
                                elif hasattr(args, 'keystore_password_file') and args.keystore_password_file:
                                    try:
                                        with open(args.keystore_password_file, 'r') as f:
                                            keystore_password = f.read().strip()
                                    except Exception as e:
                                        if not args.quiet:
                                            print(f"Warning: Failed to read keystore password from file: {e}")
                                            keystore_password = getpass.getpass("Enter keystore password: ")
                                else:
                                    keystore_password = getpass.getpass("Enter new keystore password: ")
                                    confirm = getpass.getpass("Confirm new keystore password: ")
                                    if keystore_password != confirm:
                                        if not args.quiet:
                                            print("Passwords do not match")
                                        raise ValueError("Keystore passwords do not match")
                                
                                # Create the keystore
                                keystore = PQCKeystore(args.keystore)
                                keystore.create_keystore(keystore_password, KeystoreSecurityLevel.STANDARD)
                                if not args.quiet:
                                    print(f"Created new keystore at {args.keystore}")
                            else:
                                # Abort
                                if not args.quiet:
                                    print(f"Encryption aborted: Keystore not found at {args.keystore}")
                                return 1
                        
                        # Get keystore password if needed
                        keystore_password = None
                        if hasattr(args, 'keystore_password') and args.keystore_password:
                            keystore_password = args.keystore_password
                        elif hasattr(args, 'keystore_password_file') and args.keystore_password_file:
                            try:
                                with open(args.keystore_password_file, 'r') as f:
                                    keystore_password = f.read().strip()
                            except Exception as e:
                                if not args.quiet:
                                    print(f"Warning: Failed to read keystore password from file: {e}")
                                    keystore_password = getpass.getpass("Enter keystore password: ")
                        else:
                            keystore_password = getpass.getpass("Enter keystore password: ")
                        
                        # Check if we should auto-generate a key
                        key_id = getattr(args, 'key_id', None)
                        # Always auto-generate a key if we're using a keystore with PQC algorithm
                        # and no key_id is provided, or explicitly requested with --auto-generate-key
                        if (key_id is None and args.algorithm.startswith('kyber')) or getattr(args, 'auto_generate_key', False):
                            # Set the auto_generate_key flag for the auto_generate_pqc_key function
                            if not hasattr(args, 'auto_generate_key') or not args.auto_generate_key:
                                if not args.quiet:
                                    print("Auto-generating key for keystore")
                                setattr(args, 'auto_generate_key', True)
                            # Auto-generate key
                            # This will update hash_config with key_id
                            auto_generate_pqc_key(args, hash_config)
                        
                        # Encrypt using keystore integration
                        success = encrypt_file_with_keystore(
                            args.input,
                            temp_output,
                            password,
                            hash_config=hash_config,
                            pbkdf2_iterations=args.pbkdf2_iterations,
                            quiet=args.quiet,
                            algorithm=args.algorithm,
                            pqc_keypair=pqc_keypair if 'pqc_keypair' in locals() else None,
                            keystore_file=args.keystore,
                            keystore_password=keystore_password,
                            key_id=key_id,
                            dual_encryption=getattr(args, 'dual_encrypt_key', False),
                            progress=args.progress,
                            verbose=args.verbose,
                            pqc_store_private_key=args.pqc_store_key,
                            pqc_dual_encryption=getattr(args, 'pqc_dual_encrypt_key', False)
                        )
                    else:
                        # Use standard encryption
                        success = encrypt_file(
                            args.input,
                            temp_output,
                            password,
                            hash_config,
                            args.pbkdf2_iterations,
                            args.quiet,
                            algorithm=args.algorithm,
                            progress=args.progress,
                            verbose=args.verbose,
                            pqc_keypair=pqc_keypair if 'pqc_keypair' in locals() else None,
                            pqc_store_private_key=args.pqc_store_key
                        )

                    if success:
                        # Apply the original permissions to the temp file
                        os.chmod(temp_output, original_permissions)

                        # Replace the original file with the encrypted file
                        # (atomic operation)
                        os.replace(temp_output, output_file)

                        # Successful replacement means we don't need to clean
                        # up the temp file
                        temp_files_to_cleanup.remove(temp_output)
                    else:
                        # Clean up the temp file if it exists
                        if os.path.exists(temp_output):
                            os.remove(temp_output)
                            temp_files_to_cleanup.remove(temp_output)
                except Exception as e:
                    # Clean up the temp file in case of any error
                    if os.path.exists(temp_output):
                        os.remove(temp_output)
                        if temp_output in temp_files_to_cleanup:
                            temp_files_to_cleanup.remove(temp_output)
                    raise e
            elif not args.output:
                # Default output file name if not specified
                output_file = args.input + '.encrypted'
            else:
                output_file = args.output

            # Handle PQC key operations (for non-overwriting case)
            pqc_keypair = None
            if args.algorithm in ['kyber512-hybrid', 'kyber768-hybrid', 'kyber1024-hybrid']:
                # Check if we should generate and save a new key pair
                if args.pqc_gen_key and args.pqc_keyfile:
                    from .pqc import PQCipher, PQCAlgorithm, check_pqc_support

                    # Map algorithm name to PQCAlgorithm with fallbacks
                    pqc_algorithms = check_pqc_support(quiet=args.quiet)[2]

                    # Determine which variants are available
                    kyber512_options = [alg for alg in pqc_algorithms if
                                        alg.lower().replace('-', '').replace('_', '') in ["kyber512", "mlkem512"]]
                    kyber768_options = [alg for alg in pqc_algorithms if
                                        alg.lower().replace('-', '').replace('_', '') in ["kyber768", "mlkem768"]]
                    kyber1024_options = [alg for alg in pqc_algorithms if
                                         alg.lower().replace('-', '').replace('_', '') in ["kyber1024", "mlkem1024"]]

                    # Choose first available or fall back to default name
                    kyber512_algo = kyber512_options[0] if kyber512_options else "Kyber512"
                    kyber768_algo = kyber768_options[0] if kyber768_options else "Kyber768"
                    kyber1024_algo = kyber1024_options[0] if kyber1024_options else "Kyber1024"

                    if not args.quiet:
                        print(
                            f"Using algorithm mappings: kyber512-hybrid → {kyber512_algo}, kyber768-hybrid → {kyber768_algo}, kyber1024-hybrid → {kyber1024_algo}")

                    # Create direct string mapping
                    algo_map = {
                        'kyber512-hybrid': kyber512_algo,
                        'kyber768-hybrid': kyber768_algo,
                        'kyber1024-hybrid': kyber1024_algo
                    }

                    # Generate key pair
                    cipher = PQCipher(algo_map[args.algorithm], quiet=args.quiet)
                    public_key, private_key = cipher.generate_keypair()

                    # Save key pair to file
                    import json
                    import base64

                    # Get password for encrypting the private key in the keyfile
                    keyfile_password = None
                    if 'password' in locals() and password:
                        # Use the same password as for the file encryption
                        keyfile_password = password
                    else:
                        # Get a separate password for the keyfile
                        keyfile_password = getpass.getpass(
                            "Enter password to encrypt the private key in keyfile: ").encode()

                    # Encrypt the private key with the password
                    # We generate a key derived from the password
                    key_salt = secrets.token_bytes(16)
                    key_derivation = hashlib.pbkdf2_hmac('sha256', keyfile_password, key_salt, 100000)
                    encryption_key = hashlib.sha256(key_derivation).digest()

                    # Use AES-GCM to encrypt the private key
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    cipher = AESGCM(encryption_key)
                    nonce = secrets.token_bytes(12)  # 12 bytes for AES-GCM
                    encrypted_private_key = nonce + cipher.encrypt(nonce, private_key, None)

                    key_data = {
                        'algorithm': args.algorithm,
                        'public_key': base64.b64encode(public_key).decode('utf-8'),
                        'private_key': base64.b64encode(encrypted_private_key).decode('utf-8'),
                        'key_salt': base64.b64encode(key_salt).decode('utf-8'),
                        'key_encrypted': True  # Mark that the key is encrypted
                    }

                    with open(args.pqc_keyfile, 'w') as f:
                        json.dump(key_data, f)

                    if not args.quiet:
                        print(f"Post-quantum key pair saved to {args.pqc_keyfile}")

                    pqc_keypair = (public_key, private_key)

                # Check if we should load an existing key pair
                elif args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
                    import json
                    import base64

                    with open(args.pqc_keyfile, 'r') as f:
                        key_data = json.load(f)

                    if 'public_key' in key_data and 'private_key' in key_data:
                        public_key = base64.b64decode(key_data['public_key'])
                        encrypted_private_key = base64.b64decode(key_data['private_key'])

                        # Check if key is encrypted (will be for keys created after our fix)
                        if key_data.get('key_encrypted', False):
                            if not args.quiet:
                                print("Found encrypted private key in keyfile")

                            # Get password to decrypt the private key
                            keyfile_password = None
                            if 'password' in locals() and password:
                                # Try the same password as for the file
                                keyfile_password = password
                            else:
                                # Ask for the keyfile password
                                keyfile_password = getpass.getpass(
                                    "Enter password to decrypt the private key in keyfile: ").encode()

                            # Import what we need to decrypt
                            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                            # Key derivation using the same method as when encrypting
                            key_salt = base64.b64decode(key_data['key_salt'])
                            key_derivation = hashlib.pbkdf2_hmac('sha256', keyfile_password, key_salt, 100000)
                            encryption_key = hashlib.sha256(key_derivation).digest()

                            try:
                                # Format: nonce (12 bytes) + encrypted_key
                                nonce = encrypted_private_key[:12]
                                encrypted_key_data = encrypted_private_key[12:]

                                # Decrypt the private key with the password-derived key
                                cipher = AESGCM(encryption_key)
                                private_key = cipher.decrypt(nonce, encrypted_key_data, None)

                                if not args.quiet:
                                    print("Successfully decrypted private key from keyfile")
                            except Exception as e:
                                print(f"Error decrypting private key: {e}. Wrong password?")
                                print("Will proceed with only the public key.")
                                private_key = None
                        else:
                            # Legacy support for non-encrypted keys (created before our fix)
                            private_key = encrypted_private_key
                            if not args.quiet:
                                print("WARNING: Using legacy unencrypted private key from keyfile")

                        pqc_keypair = (public_key, private_key) if private_key else (public_key, None)

                        if not args.quiet:
                            print(f"Loaded post-quantum key pair from {args.pqc_keyfile}")
                else:
                    # No keyfile specified - generate an ephemeral keypair for this encryption
                    from .pqc import PQCipher, check_pqc_support
                    import random

                    # Map algorithm name to available algorithms
                    pqc_algorithms = check_pqc_support(quiet=args.quiet)[2]
                    kyber512_options = [alg for alg in pqc_algorithms if
                                        alg.lower().replace('-', '').replace('_', '') in ["kyber512", "mlkem512"]]
                    kyber768_options = [alg for alg in pqc_algorithms if
                                        alg.lower().replace('-', '').replace('_', '') in ["kyber768", "mlkem768"]]
                    kyber1024_options = [alg for alg in pqc_algorithms if
                                         alg.lower().replace('-', '').replace('_', '') in ["kyber1024", "mlkem1024"]]

                    # Choose first available algorithm
                    algo_map = {
                        'kyber512-hybrid': kyber512_options[0] if kyber512_options else "Kyber512",
                        'kyber768-hybrid': kyber768_options[0] if kyber768_options else "Kyber768",
                        'kyber1024-hybrid': kyber1024_options[0] if kyber1024_options else "Kyber1024"
                    }

                    # Generate a new ephemeral keypair
                    if not args.quiet:
                        print(f"Generating ephemeral post-quantum key pair for {args.algorithm}")
                        if args.pqc_store_key:
                            print("Private key will be stored in the encrypted file for self-decryption")
                        else:
                            print("WARNING: Private key will NOT be stored - you must use a key file for decryption")

                    cipher = PQCipher(algo_map[args.algorithm], quiet=args.quiet)
                    public_key, private_key = cipher.generate_keypair()
                    pqc_keypair = (public_key, private_key)

            # Direct encryption to output file (when not overwriting)
            if not args.overwrite:
                # Check if we should use keystore integration
                if hasattr(args, 'keystore') and args.keystore:
                    # First, check if the keystore exists
                    if not os.path.exists(args.keystore):
                        # Keystore doesn't exist
                        create_new = False
                        if getattr(args, 'auto_create_keystore', False):
                            # Auto-create keystore is enabled
                            if not args.quiet:
                                print(f"Keystore not found at {args.keystore}, creating a new one")
                            create_new = True
                        else:
                            # Prompt the user if they want to create a new keystore or abort
                            if not args.quiet:
                                print(f"Keystore not found at {args.keystore}")
                                print("Use --auto-create-keystore option to automatically create keystore")
                                create_prompt = input("Would you like to create a new keystore? (y/n): ").lower().strip()
                                create_new = create_prompt.startswith('y')
                        
                        if create_new:
                            # Create a new keystore
                            from .keystore_cli import PQCKeystore, KeystoreSecurityLevel
                            
                            # Get keystore password
                            keystore_password = None
                            if hasattr(args, 'keystore_password') and args.keystore_password:
                                keystore_password = args.keystore_password
                            elif hasattr(args, 'keystore_password_file') and args.keystore_password_file:
                                try:
                                    with open(args.keystore_password_file, 'r') as f:
                                        keystore_password = f.read().strip()
                                except Exception as e:
                                    if not args.quiet:
                                        print(f"Warning: Failed to read keystore password from file: {e}")
                                        keystore_password = getpass.getpass("Enter keystore password: ")
                            else:
                                keystore_password = getpass.getpass("Enter new keystore password: ")
                                confirm = getpass.getpass("Confirm new keystore password: ")
                                if keystore_password != confirm:
                                    if not args.quiet:
                                        print("Passwords do not match")
                                    raise ValueError("Keystore passwords do not match")
                            
                            # Create the keystore
                            keystore = PQCKeystore(args.keystore)
                            keystore.create_keystore(keystore_password, KeystoreSecurityLevel.STANDARD)
                            if not args.quiet:
                                print(f"Created new keystore at {args.keystore}")
                        else:
                            # Abort
                            if not args.quiet:
                                print(f"Encryption aborted: Keystore not found at {args.keystore}")
                            return 1
                    
                    # Get keystore password if needed
                    keystore_password = None
                    if hasattr(args, 'keystore_password') and args.keystore_password:
                        keystore_password = args.keystore_password
                    elif hasattr(args, 'keystore_password_file') and args.keystore_password_file:
                        try:
                            with open(args.keystore_password_file, 'r') as f:
                                keystore_password = f.read().strip()
                        except Exception as e:
                            if not args.quiet:
                                print(f"Warning: Failed to read keystore password from file: {e}")
                                keystore_password = getpass.getpass("Enter keystore password: ")
                    else:
                        keystore_password = getpass.getpass("Enter keystore password: ")
                    
                    # Check if we should auto-generate a key
                    key_id = getattr(args, 'key_id', None)
                    # Always auto-generate a key if we're using a keystore with PQC algorithm
                    # and no key_id is provided, or explicitly requested with --auto-generate-key
                    if (key_id is None and args.algorithm.startswith('kyber')) or getattr(args, 'auto_generate_key', False):
                        # Set the auto_generate_key flag for the auto_generate_pqc_key function
                        if not hasattr(args, 'auto_generate_key') or not args.auto_generate_key:
                            if not args.quiet:
                                print("Auto-generating key for keystore")
                            setattr(args, 'auto_generate_key', True)
                        # Auto-generate key
                        # This will update hash_config with key_id
                        auto_generate_pqc_key(args, hash_config)
                    
                    # Encrypt using keystore integration
                    success = encrypt_file_with_keystore(
                        args.input,
                        output_file,
                        password,
                        hash_config=hash_config,
                        pbkdf2_iterations=args.pbkdf2_iterations,
                        quiet=args.quiet,
                        algorithm=args.algorithm,
                        pqc_keypair=pqc_keypair if 'pqc_keypair' in locals() else None,
                        keystore_file=args.keystore,
                        keystore_password=keystore_password,
                        key_id=key_id,
                        dual_encryption=getattr(args, 'dual_encrypt_key', False),
                        progress=args.progress,
                        verbose=args.verbose,
                        pqc_store_private_key=args.pqc_store_key
                    )
                else:
                    # Use standard encryption
                    success = encrypt_file(
                        args.input,
                        output_file,
                        password,
                        hash_config,
                        args.pbkdf2_iterations,
                        args.quiet,
                        algorithm=args.algorithm,
                        progress=args.progress,
                        verbose=args.verbose,
                        pqc_keypair=pqc_keypair if 'pqc_keypair' in locals() else None,
                        pqc_store_private_key=args.pqc_store_key
                    )

            if success:
                if not args.quiet:
                    print(f"\nFile encrypted successfully: {output_file}")

                    # If we used a generated password, display it with a
                    # warning
                    if generated_password:
                        # Store the original signal handler
                        original_sigint = signal.getsignal(signal.SIGINT)

                        # Flag to track if Ctrl+C was pressed
                        interrupted = False

                        # Custom signal handler for SIGINT
                        def sigint_handler(signum, frame):
                            nonlocal interrupted
                            interrupted = True
                            # Restore original handler immediately
                            signal.signal(signal.SIGINT, original_sigint)

                        try:
                            # Set our custom handler
                            signal.signal(signal.SIGINT, sigint_handler)

                            print("\n" + "!" * 80)
                            print(
                                "IMPORTANT: SAVE THIS PASSWORD NOW".center(80))
                            print("!" * 80)
                            print(
                                f"\nGenerated Password: {generated_password}")
                            print(
                                "\nWARNING: This is the ONLY time this password will be displayed.")
                            print(
                                "         If you lose it, your data CANNOT be recovered.")
                            print(
                                "         Please write it down or save it in a password manager now.")
                            print("\nThis message will disappear in 10 seconds...")

                            # Wait for 10 seconds or until keyboard interrupt
                            for remaining in range(10, 0, -1):
                                if interrupted:
                                    break
                                # Overwrite the line with updated countdown
                                print(f"\rTime remaining: {remaining} seconds...", end="", flush=True)
                                # Sleep in small increments to check for
                                # interruption more frequently
                                for _ in range(10):
                                    if interrupted:
                                        break
                                    time.sleep(0.1)

                        finally:
                            # Restore original signal handler no matter what
                            signal.signal(signal.SIGINT, original_sigint)

                            # Give an indication that we're clearing the screen
                            if interrupted:
                                print("\n\nClearing password from screen (interrupted by user)...")
                            else:
                                print("\n\nClearing password from screen...")

                            # Use system command to clear the screen
                            if sys.platform == 'win32':
                                os.system('cls')  # Windows
                            else:
                                os.system('clear')  # Unix/Linux/MacOS

                            print("Password has been cleared from screen.")
                            print("For additional security, consider clearing your terminal history.")

                # If shredding was requested and encryption was successful
                if args.shred and not args.overwrite:
                    if not args.quiet:
                        print("Shredding the original file as requested...")
                    secure_shred_file(
                        args.input, args.shred_passes, args.quiet)

        elif args.action == 'decrypt':
            if args.overwrite:
                output_file = args.input
                # Create a temporary file for the decryption
                temp_dir = os.path.dirname(os.path.abspath(args.input))
                temp_suffix = f".{uuid.uuid4().hex[:12]}.tmp"
                temp_output = os.path.join(temp_dir, f".{os.path.basename(args.input)}{temp_suffix}")

                # Add to cleanup list
                temp_files_to_cleanup.append(temp_output)

                try:
                    # Get original file permissions before doing anything
                    original_permissions = get_file_permissions(args.input)

                    # Handle PQC key operations for decryption
                    pqc_private_key = None
                    if args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
                        import json
                        import base64

                        try:
                            with open(args.pqc_keyfile, 'r') as f:
                                key_data = json.load(f)

                            if 'private_key' in key_data:
                                encrypted_private_key = base64.b64decode(key_data['private_key'])

                                # Check if key is encrypted (will be for keys created after our fix)
                                if key_data.get('key_encrypted', False):
                                    if not args.quiet:
                                        print("Found encrypted private key in keyfile")

                                    # Get password to decrypt the private key
                                    keyfile_password = None
                                    if 'password' in locals() and password:
                                        # Try the same password as for the file
                                        keyfile_password = password
                                    else:
                                        # Ask for the keyfile password
                                        keyfile_password = getpass.getpass(
                                            "Enter password to decrypt the private key in keyfile: ").encode()

                                    # Import what we need to decrypt
                                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                                    # Key derivation using the same method as when encrypting
                                    key_salt = base64.b64decode(key_data['key_salt'])
                                    key_derivation = hashlib.pbkdf2_hmac('sha256', keyfile_password, key_salt, 100000)
                                    encryption_key = hashlib.sha256(key_derivation).digest()

                                    try:
                                        # Format: nonce (12 bytes) + encrypted_key
                                        nonce = encrypted_private_key[:12]
                                        encrypted_key_data = encrypted_private_key[12:]

                                        # Decrypt the private key with the password-derived key
                                        cipher = AESGCM(encryption_key)
                                        pqc_private_key = cipher.decrypt(nonce, encrypted_key_data, None)

                                        if not args.quiet:
                                            print("Successfully decrypted private key from keyfile")
                                    except Exception as e:
                                        print(f"Error decrypting private key: {e}. Wrong password?")
                                        print("Decryption may fail without a valid private key.")
                                        pqc_private_key = None
                                else:
                                    # Legacy support for non-encrypted keys (created before our fix)
                                    pqc_private_key = encrypted_private_key
                                    if not args.quiet:
                                        print("WARNING: Using legacy unencrypted private key from keyfile")

                                if not args.quiet and pqc_private_key:
                                    print(f"Loaded post-quantum private key from {args.pqc_keyfile}")
                        except Exception as e:
                            if not args.quiet:
                                print(f"Warning: Failed to load PQC key file: {e}")

                    # Check if we should use keystore integration
                    if hasattr(args, 'keystore') and args.keystore:
                        # Get keystore password if needed
                        keystore_password = None
                        if hasattr(args, 'keystore_password') and args.keystore_password:
                            keystore_password = args.keystore_password
                        elif hasattr(args, 'keystore_password_file') and args.keystore_password_file:
                            try:
                                with open(args.keystore_password_file, 'r') as f:
                                    keystore_password = f.read().strip()
                            except Exception as e:
                                if not args.quiet:
                                    print(f"Warning: Failed to read keystore password from file: {e}")
                                    keystore_password = getpass.getpass("Enter keystore password: ")
                        else:
                            keystore_password = getpass.getpass("Enter keystore password: ")
                        
                        # Determine key ID if not provided
                        key_id = getattr(args, 'key_id', None)
                        
                        # Double-check: If no key ID provided or extracted from metadata,
                        # print a warning and suggest user to provide key ID manually
                        if key_id is None and not args.quiet:
                            print("\nWarning: No key ID found in metadata and --key-id not provided.")
                            print("If decryption fails, please specify the key ID with --key-id parameter.")
                        
                        # Decrypt using keystore integration
                        success = decrypt_file_with_keystore(
                            args.input,
                            temp_output,
                            password,
                            quiet=args.quiet,
                            pqc_private_key=pqc_private_key,
                            keystore_file=args.keystore,
                            keystore_password=keystore_password,
                            key_id=key_id,
                            dual_encryption=getattr(args, 'dual_encrypt_key', False),
                            progress=args.progress,
                            verbose=args.verbose
                        )
                    else:
                        # Use standard decryption
                        success = decrypt_file(
                            args.input,
                            temp_output,
                            password,
                            args.quiet,
                            progress=args.progress,
                            verbose=args.verbose,
                            pqc_private_key=pqc_private_key
                        )
                    if success:
                        # Apply the original permissions to the temp file
                        os.chmod(temp_output, original_permissions)

                        # Replace the original file with the decrypted file
                        os.replace(temp_output, output_file)

                        # Successful replacement means we don't need to clean
                        # up the temp file
                        temp_files_to_cleanup.remove(temp_output)
                    else:
                        # Clean up the temp file if it exists
                        if os.path.exists(temp_output):
                            os.remove(temp_output)
                            temp_files_to_cleanup.remove(temp_output)
                except Exception as e:
                    # Clean up the temp file in case of any error
                    if os.path.exists(temp_output):
                        os.remove(temp_output)
                        if temp_output in temp_files_to_cleanup:
                            temp_files_to_cleanup.remove(temp_output)
                    raise e
            elif args.output:
                # Handle PQC key operations for decryption
                pqc_private_key = None
                if args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
                    import json
                    import base64

                    try:
                        with open(args.pqc_keyfile, 'r') as f:
                            key_data = json.load(f)

                        if 'private_key' in key_data:
                            encrypted_private_key = base64.b64decode(key_data['private_key'])

                            # Check if key is encrypted (will be for keys created after our fix)
                            if key_data.get('key_encrypted', False):
                                if not args.quiet:
                                    print("Found encrypted private key in keyfile")

                                # Get password to decrypt the private key
                                keyfile_password = None
                                if 'password' in locals() and password:
                                    # Try the same password as for the file
                                    keyfile_password = password
                                else:
                                    # Ask for the keyfile password
                                    keyfile_password = getpass.getpass(
                                        "Enter password to decrypt the private key in keyfile: ").encode()

                                # Import what we need to decrypt
                                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                                # Key derivation using the same method as when encrypting
                                key_salt = base64.b64decode(key_data['key_salt'])
                                key_derivation = hashlib.pbkdf2_hmac('sha256', keyfile_password, key_salt, 100000)
                                encryption_key = hashlib.sha256(key_derivation).digest()

                                try:
                                    # Format: nonce (12 bytes) + encrypted_key
                                    nonce = encrypted_private_key[:12]
                                    encrypted_key_data = encrypted_private_key[12:]

                                    # Decrypt the private key with the password-derived key
                                    cipher = AESGCM(encryption_key)
                                    pqc_private_key = cipher.decrypt(nonce, encrypted_key_data, None)

                                    if not args.quiet:
                                        print("Successfully decrypted private key from keyfile")
                                except Exception as e:
                                    print(f"Error decrypting private key: {e}. Wrong password?")
                                    print("Decryption may fail without a valid private key.")
                                    pqc_private_key = None
                            else:
                                # Legacy support for non-encrypted keys (created before our fix)
                                pqc_private_key = encrypted_private_key
                                if not args.quiet:
                                    print("WARNING: Using legacy unencrypted private key from keyfile")

                            if not args.quiet and pqc_private_key:
                                print(f"Loaded post-quantum private key from {args.pqc_keyfile}")
                    except Exception as e:
                        if not args.quiet:
                            print(f"Warning: Failed to load PQC key file: {e}")

                # Check if we should use keystore integration
                if hasattr(args, 'keystore') and args.keystore:
                    # Get keystore password if needed
                    keystore_password = None
                    if hasattr(args, 'keystore_password') and args.keystore_password:
                        keystore_password = args.keystore_password
                    elif hasattr(args, 'keystore_password_file') and args.keystore_password_file:
                        try:
                            with open(args.keystore_password_file, 'r') as f:
                                keystore_password = f.read().strip()
                        except Exception as e:
                            if not args.quiet:
                                print(f"Warning: Failed to read keystore password from file: {e}")
                                keystore_password = getpass.getpass("Enter keystore password: ")
                    else:
                        keystore_password = getpass.getpass("Enter keystore password: ")
                    
                    # Determine key ID if not provided
                    key_id = getattr(args, 'key_id', None)
                    
                    # The keystore_wrapper.py will now handle cases with no key ID,
                    # including trying the only key in the keystore
                    
                    # Decrypt using keystore integration
                    success = decrypt_file_with_keystore(
                        args.input,
                        args.output,
                        password,
                        quiet=args.quiet,
                        pqc_private_key=pqc_private_key,
                        keystore_file=args.keystore,
                        keystore_password=keystore_password,
                        key_id=key_id,
                        dual_encryption=getattr(args, 'dual_encrypt_key', False),
                        progress=args.progress,
                        verbose=args.verbose
                    )
                else:
                    # Use standard decryption
                    success = decrypt_file(
                        args.input,
                        args.output,
                        password,
                        args.quiet,
                        progress=args.progress,
                        verbose=args.verbose,
                        pqc_private_key=pqc_private_key
                    )
                if success and not args.quiet:
                    print(f"\nFile decrypted successfully: {args.output}")

                # If shredding was requested and decryption was successful
                if args.shred and success:
                    if not args.quiet:
                        print("Shredding the encrypted file as requested...")
                    secure_shred_file(
                        args.input, args.shred_passes, args.quiet)
            else:
                # Handle PQC key operations for decryption to screen
                pqc_private_key = None
                if args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
                    import json
                    import base64

                    try:
                        with open(args.pqc_keyfile, 'r') as f:
                            key_data = json.load(f)

                        if 'private_key' in key_data:
                            encrypted_private_key = base64.b64decode(key_data['private_key'])

                            # Check if key is encrypted (will be for keys created after our fix)
                            if key_data.get('key_encrypted', False):
                                if not args.quiet:
                                    print("Found encrypted private key in keyfile")

                                # Get password to decrypt the private key
                                keyfile_password = None
                                if 'password' in locals() and password:
                                    # Try the same password as for the file
                                    keyfile_password = password
                                else:
                                    # Ask for the keyfile password
                                    keyfile_password = getpass.getpass(
                                        "Enter password to decrypt the private key in keyfile: ").encode()

                                # Import what we need to decrypt
                                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                                # Key derivation using the same method as when encrypting
                                key_salt = base64.b64decode(key_data['key_salt'])
                                key_derivation = hashlib.pbkdf2_hmac('sha256', keyfile_password, key_salt, 100000)
                                encryption_key = hashlib.sha256(key_derivation).digest()

                                try:
                                    # Format: nonce (12 bytes) + encrypted_key
                                    nonce = encrypted_private_key[:12]
                                    encrypted_key_data = encrypted_private_key[12:]

                                    # Decrypt the private key with the password-derived key
                                    cipher = AESGCM(encryption_key)
                                    pqc_private_key = cipher.decrypt(nonce, encrypted_key_data, None)

                                    if not args.quiet:
                                        print("Successfully decrypted private key from keyfile")
                                except Exception as e:
                                    print(f"Error decrypting private key: {e}. Wrong password?")
                                    print("Decryption may fail without a valid private key.")
                                    pqc_private_key = None
                            else:
                                # Legacy support for non-encrypted keys (created before our fix)
                                pqc_private_key = encrypted_private_key
                                if not args.quiet:
                                    print("WARNING: Using legacy unencrypted private key from keyfile")

                            if not args.quiet and pqc_private_key:
                                print(f"Loaded post-quantum private key from {args.pqc_keyfile}")
                    except Exception as e:
                        if not args.quiet:
                            print(f"Warning: Failed to load PQC key file: {e}")

                # Decrypt to screen if no output file specified (useful for
                # text files)
                
                # Check if we should use keystore integration
                if hasattr(args, 'keystore') and args.keystore:
                    # Get keystore password if needed
                    keystore_password = None
                    if hasattr(args, 'keystore_password') and args.keystore_password:
                        keystore_password = args.keystore_password
                    elif hasattr(args, 'keystore_password_file') and args.keystore_password_file:
                        try:
                            with open(args.keystore_password_file, 'r') as f:
                                keystore_password = f.read().strip()
                        except Exception as e:
                            if not args.quiet:
                                print(f"Warning: Failed to read keystore password from file: {e}")
                                keystore_password = getpass.getpass("Enter keystore password: ")
                    else:
                        keystore_password = getpass.getpass("Enter keystore password: ")
                    
                    # Determine key ID if not provided
                    key_id = getattr(args, 'key_id', None)
                    
                    # The keystore_wrapper.py will now handle cases with no key ID,
                    # including trying the only key in the keystore
                    
                    # Decrypt using keystore integration
                    decrypted = decrypt_file_with_keystore(
                        args.input,
                        None,
                        password,
                        quiet=args.quiet,
                        pqc_private_key=pqc_private_key,
                        keystore_file=args.keystore,
                        keystore_password=keystore_password,
                        key_id=key_id,
                        dual_encryption=getattr(args, 'dual_encrypt_key', False),
                        progress=args.progress,
                        verbose=args.verbose
                    )
                else:
                    # Use standard decryption
                    decrypted = decrypt_file(
                        args.input,
                        None,
                        password,
                        args.quiet,
                        progress=args.progress,
                        verbose=args.verbose,
                        pqc_private_key=pqc_private_key
                    )
                try:
                    # Try to decode as text
                    if not args.quiet:
                        print("\nDecrypted content:")
                    print(decrypted.decode().rstrip())
                except UnicodeDecodeError:
                    if not args.quiet:
                        print(
                            "\nDecrypted successfully, but content is binary and cannot be displayed.")

        elif args.action == 'shred':
            # Direct shredding of files or directories without
            # encryption/decryption

            # Expand any glob patterns in the input path
            matched_paths = expand_glob_patterns(args.input)

            if not matched_paths:
                if not args.quiet:
                    print(f"No files or directories match the pattern: {args.input}")
                exit_code = 1
            else:
                # If there are multiple files/dirs to shred, inform the user
                if len(matched_paths) > 1 and not args.quiet:
                    print(f"Found {len(matched_paths)} files/directories matching the pattern.")

                overall_success = True

                # Process each matched path
                for path in matched_paths:
                    # Special handling for directories without recursive flag
                    if os.path.isdir(path) and not args.recursive:
                        # Directory detected but recursive flag not provided
                        if args.quiet:
                            # In quiet mode, fail immediately without
                            # confirmation
                            if not args.quiet:
                                print(f"Error: {path} is a directory. "
                                      f"Use --recursive to shred directories.")
                            overall_success = False
                            continue
                        else:
                            # Ask for confirmation since this is potentially
                            # dangerous
                            confirm_message = (
                                f"WARNING: {path} is a directory but --recursive flag is not specified. "
                                f"Only empty directories will be removed. Continue?"
                            )
                            if request_confirmation(confirm_message):
                                success = secure_shred_file(
                                    path, args.shred_passes, args.quiet)
                                if not success:
                                    overall_success = False
                            else:
                                print(f"Skipping directory: {path}")
                                continue
                    else:
                        # File or directory with recursive flag
                        if not args.quiet:
                            print(f"Securely shredding {'directory' if os.path.isdir(path) else 'file'}: {path}")

                        success = secure_shred_file(
                            path, args.shred_passes, args.quiet)
                        if not success:
                            overall_success = False

                # Set exit code to failure if any operation failed
                if not overall_success:
                    exit_code = 1

    except Exception as e:
        if not args.quiet:
            print(f"\nError: {e}")
        exit_code = 1

    # Exit with appropriate code
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
