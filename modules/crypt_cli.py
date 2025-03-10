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

# Import from local modules
from modules.crypt_core import (
    encrypt_file, decrypt_file, check_argon2_support,
    get_file_permissions, WHIRLPOOL_AVAILABLE, ARGON2_AVAILABLE, ARGON2_TYPE_MAP
)
from modules.crypt_utils import (
    secure_shred_file, expand_glob_patterns, generate_strong_password,
    display_password_with_timeout, show_security_recommendations,
    request_confirmation
)

# Global variable for secure memory handling
GLOBAL_USE_SECURE_MEM = True  # Default value, will be updated based on args

def use_secure_memory(args):
    """
    Determine if secure memory handling should be used.

    Args:
        args: Command-line arguments namespace

    Returns:
        bool: True if secure memory should be used, False otherwise
    """
    return not hasattr(args, 'disable_secure_memory') or not args.disable_secure_memory


def main():
    """
    Main function that handles the command-line interface.
    """
    # Global variable to track temporary files that need cleanup
    temp_files_to_cleanup = []

    global GLOBAL_USE_SECURE_MEM

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

    # Define core actions
    parser.add_argument(
        'action',
        choices=['encrypt', 'decrypt', 'shred', 'generate-password', 'security-info', 'check-argon2'],
        help='Action to perform: encrypt/decrypt files, shred data, generate passwords, '
             'show security recommendations, or check Argon2 support'
    )

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
        '--input', '-i',
        help='Input file or directory (supports glob patterns for shred action)'
    )
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
        '--overwrite',
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

    # Add memory security option
    parser.add_argument(
        '--disable-secure-memory',
        action='store_true',
        help='Disable secure memory handling (not recommended)'
    )

    # Group hash configuration arguments for better organization
    hash_group = parser.add_argument_group('Hash Options', 'Configure hashing algorithms for key derivation')
    
    # SHA family arguments
    hash_group.add_argument(
        '--sha512',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help='Number of SHA-512 iterations (default: 1,000,000 if flag provided without value)'
    )
    hash_group.add_argument(
        '--sha256',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help='Number of SHA-256 iterations (default: 1,000,000 if flag provided without value)'
    )
    hash_group.add_argument(
        '--sha3-256',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help='Number of SHA3-256 iterations (default: 1,000,000 if flag provided without value)'
    )
    hash_group.add_argument(
        '--sha3-512',
        type=int,
        nargs='?',
        const=1,
        default=0,
        help='Number of SHA3-512 iterations (default: 1,000,000 if flag provided without value)'
    )
    hash_group.add_argument(
        '--whirlpool',
        type=int,
        default=0,
        help='Number of Whirlpool iterations (default: 0, not used)'
    )
    
    # Scrypt parameters group
    scrypt_group = parser.add_argument_group('Scrypt Options', 'Configure Scrypt memory-hard function parameters')
    scrypt_group.add_argument(
        '--scrypt-cost',
        type=int,
        default=0,
        help='Scrypt cost factor N as power of 2 (default: 0, not used)'
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
    
    # Argon2 parameters group
    argon2_group = parser.add_argument_group('Argon2 Options', 'Configure Argon2 memory-hard function parameters')
    argon2_group.add_argument(
        '--use-argon2',
        action='store_true',
        help='Use Argon2 password hashing (requires argon2-cffi package)'
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
    
    # PBKDF2 option
    hash_group.add_argument(
        '--pbkdf2',
        type=int,
        default=100000,
        help='Number of PBKDF2 iterations (default: 100000)'
    )

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

    args = parser.parse_args()

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
            print(f"✓ Supported variants: {', '.join('Argon2'+t for t in supported_types)}")
            
            # Try a test hash to verify functionality
            try:
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
        
    elif args.action == 'generate-password':
        # If no character sets are explicitly selected, use all by default
        if not (args.use_lowercase or args.use_uppercase or args.use_digits or args.use_special):
            args.use_lowercase = True
            args.use_uppercase = True
            args.use_digits = True
            args.use_special = True

        # Generate and display the password
        password = generate_strong_password(
            args.length,
            args.use_lowercase,
            args.use_uppercase,
            args.use_digits,
            args.use_special,
            GLOBAL_USE_SECURE_MEM
        )

        display_password_with_timeout(password)
        # Exit after generating password
        sys.exit(0)

    # For other actions, input file is required
    if args.input is None:
        parser.error("the following arguments are required: --input/-i")

    # Update the global variable based on args
    GLOBAL_USE_SECURE_MEM = use_secure_memory(args)

    # Check for Whirlpool availability if needed and not in quiet mode
    if args.whirlpool > 0 and not WHIRLPOOL_AVAILABLE and not args.quiet:
        print("Warning: pywhirlpool module not found. SHA-512 will be used instead.")
        
    # Check for Argon2 availability if needed
    if (args.use_argon2 or args.argon2_preset) and not ARGON2_AVAILABLE:
        if not args.quiet:
            print("Warning: argon2-cffi module not found. Argon2 will be disabled.")
            print("Install with: pip install argon2-cffi")
        args.use_argon2 = False
        args.argon2_preset = None

    # Validate random password parameter
    if args.random is not None:
        if args.action != 'encrypt':
            parser.error("--random can only be used with the encrypt action")
        if args.password:
            parser.error("--password and --random cannot be used together")
        if args.random < 12:
            if not args.quiet:
                print(f"Warning: Random password length increased to 12 (minimum secure length)")
            args.random = 12

    # Get password (only for encrypt/decrypt actions)
    password = None
    generated_password = None

    if args.action in ['encrypt', 'decrypt']:
        password = None
        generated_password = None
        use_secure_mem = GLOBAL_USE_SECURE_MEM

        if use_secure_mem:
            try:
                from secure_memory import secure_string, secure_input, SecureBytes

                # Initialize a secure string to hold the password
                with secure_string() as password_secure:
                    # Handle random password generation for encryption
                    use_secure_mem = GLOBAL_USE_SECURE_MEM
                    if args.action == 'encrypt' and args.random and not args.password:
                        generated_password = generate_strong_password(
                            args.random,
                            use_lowercase=True,
                            use_uppercase=True,
                            use_digits=True,
                            use_special=True,
                            use_secure_mem=True  # Use True instead of use_secure_mem
                        )
                        password_secure.extend(generated_password.encode())
                        if not args.quiet:
                            print("\nGenerated a random password for encryption.")

                    # If password provided as argument
                    elif args.password:
                        password_secure.extend(args.password.encode())

                    # If no password provided yet, prompt the user
                    else:
                        # For encryption, require password confirmation to prevent typos
                        if args.action == 'encrypt' and not args.quiet:
                            match = False
                            while not match:
                                pwd1 = getpass.getpass('Enter password: ').encode()
                                pwd2 = getpass.getpass('Confirm password: ').encode()

                                if pwd1 == pwd2:
                                    password_secure.extend(pwd1)
                                    # Securely clear the temporary buffers
                                    pwd1 = b'\x00' * len(pwd1)
                                    pwd2 = b'\x00' * len(pwd2)
                                    match = True
                                else:
                                    # Securely clear the temporary buffers
                                    pwd1 = b'\x00' * len(pwd1)
                                    pwd2 = b'\x00' * len(pwd2)
                                    print("Passwords do not match. Please try again.")
                        # For decryption or quiet mode, just ask once
                        else:
                            # When in quiet mode, don't add the "Enter password: " prompt text
                            prompt = '' if args.quiet else 'Enter password: '
                            pwd = getpass.getpass(prompt).encode()
                            password_secure.extend(pwd)
                            # Securely clear the temporary buffer
                            pwd = b'\x00' * len(pwd)

                    # Convert to bytes for the rest of the code
                    password = bytes(password_secure)

            except ImportError:
                # Fall back to standard method if secure_memory is not available
                if not args.quiet:
                    print("Warning: secure_memory module not available, falling back to standard password handling")
                use_secure_mem = False

        # Standard password handling if secure_memory is not available or disabled
        if not use_secure_mem:
            # Original password handling code
            password = args.password

            # Handle random password generation for encryption
            if args.action == 'encrypt' and args.random and not password:
                generated_password = generate_strong_password(
                    args.random,
                    use_lowercase=True,
                    use_uppercase=True,
                    use_digits=True,
                    use_special=True,
                    use_secure_mem=GLOBAL_USE_SECURE_MEM
                )
                password = generated_password
                if not args.quiet:
                    print("\nGenerated a random password for encryption.")

            # If no password provided yet, prompt the user
            if not password:
                # For encryption, require password confirmation to prevent typos
                if args.action == 'encrypt' and not args.quiet:
                    while True:
                        password1 = getpass.getpass('Enter password: ')
                        password2 = getpass.getpass('Confirm password: ')

                        if password1 == password2:
                            password = password1
                            break
                        else:
                            print("Passwords do not match. Please try again.")
                # For decryption or quiet mode, just ask once
                else:
                    # When in quiet mode, don't add the "Enter password: " prompt text
                    if args.quiet:
                        password = getpass.getpass('')
                    else:
                        password = getpass.getpass('Enter password: ')

            # Convert to bytes
            password = password.encode()

    # Set default iterations if SHA algorithms are requested but no iterations provided
    MIN_SHA_ITERATIONS = 1000000

    # If user specified to use SHA-256, SHA-512, or SHA3 but didn't provide iterations
    if args.sha256 == 1:  # When flag is provided without value
        args.sha256 = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-256")

    if args.sha512 == 1:  # When flag is provided without value
        args.sha512 = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-512")

    if args.sha3_256 == 1:  # When flag is provided without value
        args.sha3_256 = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-256")

    if args.sha3_512 == 1:  # When flag is provided without value
        args.sha3_512 = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-512")
            
    # Handle Argon2 presets if specified
    if args.argon2_preset and ARGON2_AVAILABLE:
        args.use_argon2 = True
        
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
            print(f"Using Argon2 preset '{args.argon2_preset}' with parameters:")
            print(f"  - Time cost: {args.argon2_time}")
            print(f"  - Memory: {args.argon2_memory} KB")
            print(f"  - Parallelism: {args.argon2_parallelism}")
            print(f"  - Hash length: {args.argon2_hash_len} bytes")
            print(f"  - Type: Argon2{args.argon2_type}")

    # Create hash configuration dictionary (only include algorithms with iterations > 0)
    scrypt_n = 2 ** args.scrypt_cost if args.scrypt_cost > 0 else 0
    
    # Create the hash configuration dictionary
    hash_config = {
        'sha512': args.sha512,
        'sha256': args.sha256,
        'sha3_256': args.sha3_256,
        'sha3_512': args.sha3_512,
        'whirlpool': args.whirlpool,
        'scrypt': {
            'n': scrypt_n,
            'r': args.scrypt_r,
            'p': args.scrypt_p
        },
        'argon2': {
            'enabled': args.use_argon2,
            'time_cost': args.argon2_time,
            'memory_cost': args.argon2_memory,
            'parallelism': args.argon2_parallelism,
            'hash_len': args.argon2_hash_len,
            'type': ARGON2_TYPE_MAP[args.argon2_type]
        }
    }

    exit_code = 0
    try:
        if args.action == 'encrypt':
            # Handle output file path
            if args.overwrite:
                output_file = args.input
                # Create a temporary file for the encryption to enable atomic replacement
                temp_dir = os.path.dirname(os.path.abspath(args.input))
                temp_suffix = f".{uuid.uuid4().hex[:12]}.tmp"
                temp_output = os.path.join(temp_dir, f".{os.path.basename(args.input)}{temp_suffix}")

                # Add to cleanup list in case process is interrupted
                temp_files_to_cleanup.append(temp_output)
            elif not args.output:
                # Default output file name if not specified
                output_file = args.input + '.encrypted'
            else:
                output_file = args.output

            # Display hash configuration details
            if not args.quiet:
                print("\nEncrypting with the following hash configuration:")
                any_hash_used = False

                for algorithm, params in hash_config.items():
                    if algorithm == 'scrypt' and params.get('n', 0) > 0:
                        any_hash_used = True
                        print(f"- Scrypt: n={params['n']} (cost factor 2^{args.scrypt_cost}), "
                              f"r={params['r']}, p={params['p']}")
                    elif algorithm == 'argon2' and params.get('enabled', False):
                        any_hash_used = True
                        print(f"- Argon2{params['type'].split('.')[-1]}: time_cost={params['time_cost']}, "
                              f"memory_cost={params['memory_cost']}KB, "
                              f"parallelism={params['parallelism']}, "
                              f"hash_len={params['hash_len']}")
                    elif algorithm not in ['scrypt', 'argon2'] and params > 0:
                        any_hash_used = True
                        print(f"- {algorithm}: {params} iterations")

                if not any_hash_used:
                    print("- No additional hashing algorithms used")

                print(f"- PBKDF2: {args.pbkdf2} iterations")

                if use_secure_mem:
                    print("- Secure memory handling: Enabled")
                else:
                    print("- Secure memory handling: Disabled")

            # If overwriting, encrypt to a temporary file first for safety
            if args.overwrite:
                try:
                    # Get original file permissions before doing anything
                    original_permissions = get_file_permissions(args.input)

                    # Encrypt to temporary file
                    success = encrypt_file(
                        args.input, temp_output, password, hash_config, args.pbkdf2, args.quiet, GLOBAL_USE_SECURE_MEM
                    )

                    if success:
                        # Apply the original permissions to the temp file
                        os.chmod(temp_output, original_permissions)

                        # Replace the original file with the encrypted file (atomic operation)
                        os.replace(temp_output, output_file)

                        # Successful replacement means we don't need to clean up the temp file
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
            else:
                # Direct encryption to output file
                success = encrypt_file(
                    args.input, output_file, password, hash_config, args.pbkdf2, args.quiet, GLOBAL_USE_SECURE_MEM
                )

            if success:
                if not args.quiet:
                    print(f"\nFile encrypted successfully: {output_file}")

                    # If we used a generated password, display it with a warning
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
                            print("IMPORTANT: SAVE THIS PASSWORD NOW".center(80))
                            print("!" * 80)
                            print(f"\nGenerated Password: {generated_password}")
                            print("\nWARNING: This is the ONLY time this password will be displayed.")
                            print("         If you lose it, your data CANNOT be recovered.")
                            print("         Please write it down or save it in a password manager now.")
                            print("\nThis message will disappear in 10 seconds...")

                            # Wait for 10 seconds or until keyboard interrupt
                            for remaining in range(10, 0, -1):
                                if interrupted:
                                    break
                                # Overwrite the line with updated countdown
                                print(f"\rTime remaining: {remaining} seconds...", end="", flush=True)
                                # Sleep in small increments to check for interruption more frequently
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
                    secure_shred_file(args.input, args.shred_passes, args.quiet)

        elif args.action == 'decrypt':
            # Handle output file path for decryption
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

                    # Decrypt to temporary file first
                    success = decrypt_file(args.input, temp_output, password, args.quiet, GLOBAL_USE_SECURE_MEM)
                    if success:
                        # Apply the original permissions to the temp file
                        os.chmod(temp_output, original_permissions)

                        # Replace the original file with the decrypted file
                        os.replace(temp_output, output_file)

                        # Successful replacement means we don't need to clean up the temp file
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
                success = decrypt_file(args.input, args.output, password, args.quiet, GLOBAL_USE_SECURE_MEM)
                if success and not args.quiet:
                    print(f"\nFile decrypted successfully: {args.output}")

                # If shredding was requested and decryption was successful
                if args.shred and success:
                    if not args.quiet:
                        print("Shredding the encrypted file as requested...")
                    secure_shred_file(args.input, args.shred_passes, args.quiet)
            else:
                # Decrypt to screen if no output file specified (useful for text files)
                decrypted = decrypt_file(args.input, None, password, args.quiet, GLOBAL_USE_SECURE_MEM)
                try:
                    # Try to decode as text
                    if not args.quiet:
                        print("\nDecrypted content:")
                    print(decrypted.decode())
                except UnicodeDecodeError:
                    if not args.quiet:
                        print("\nDecrypted successfully, but content is binary and cannot be displayed.")

        elif args.action == 'shred':
            # Direct shredding of files or directories without encryption/decryption

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
                            # In quiet mode, fail immediately without confirmation
                            if not args.quiet:
                                print(f"Error: {path} is a directory. "
                                      f"Use --recursive to shred directories.")
                            overall_success = False
                            continue
                        else:
                            # Ask for confirmation since this is potentially dangerous
                            confirm_message = (
                                f"WARNING: {path} is a directory but --recursive flag is not specified. "
                                f"Only empty directories will be removed. Continue?"
                            )
                            if request_confirmation(confirm_message):
                                success = secure_shred_file(path, args.shred_passes, args.quiet)
                                if not success:
                                    overall_success = False
                            else:
                                print(f"Skipping directory: {path}")
                                continue
                    else:
                        # File or directory with recursive flag
                        if not args.quiet:
                            print(f"Securely shredding "
                                  f"{'directory' if os.path.isdir(path) else 'file'}: {path}")

                        success = secure_shred_file(path, args.shred_passes, args.quiet)
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
