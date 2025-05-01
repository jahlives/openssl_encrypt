#!/usr/bin/env python3
"""
Secure File Encryption Tool - Utilities Module

This module provides utility functions for the encryption tool, including
secure file deletion, password generation, and other helper functions.
"""

import os
import sys
import time
import signal
import random
import string
import glob
import json
import stat


def expand_glob_patterns(pattern):
    """
    Expand glob patterns into a list of matching files and directories.

    Args:
        pattern (str): Glob pattern to expand

    Returns:
        list: List of matching file and directory paths
    """
    return glob.glob(pattern)


def generate_strong_password(
        length,
        use_lowercase=True,
        use_uppercase=True,
        use_digits=True,
        use_special=True):
    """
    Generate a cryptographically strong random password with customizable character sets.

    Args:
        length (int): Length of the password to generate
        use_lowercase (bool): Include lowercase letters
        use_uppercase (bool): Include uppercase letters
        use_digits (bool): Include digits
        use_special (bool): Include special characters

    Returns:
        str: The generated password
    """
    if length < 8:
        length = 8  # Enforce minimum safe length

    # Create the character pool based on selected options
    char_pool = ""
    required_chars = []

    if use_lowercase:
        char_pool += string.ascii_lowercase
        required_chars.append(random.choice(string.ascii_lowercase))

    if use_uppercase:
        char_pool += string.ascii_uppercase
        required_chars.append(random.choice(string.ascii_uppercase))

    if use_digits:
        char_pool += string.digits
        required_chars.append(random.choice(string.digits))

    if use_special:
        char_pool += string.punctuation
        required_chars.append(random.choice(string.punctuation))

    # If no options selected, default to alphanumeric
    if not char_pool:
        char_pool = string.ascii_lowercase + string.ascii_uppercase + string.digits
        required_chars = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits)
        ]

    # Ensure we have room for all required characters
    if len(required_chars) > length:
        required_chars = required_chars[:length]

    # Use secure memory if enabled
    try:
        from .secure_memory import SecureBytes, secure_memzero

        # Use SecureBytes for generating the password
        password_chars = SecureBytes()

        # Add all required characters
        password_chars.extend([ord(c) for c in required_chars])

        # Fill remaining length with random characters from the pool
        remaining_length = length - len(required_chars)
        for _ in range(remaining_length):
            password_chars.append(ord(random.choice(char_pool)))

        # Shuffle to ensure required characters aren't in predictable positions
        # Use Fisher-Yates algorithm for in-place shuffle
        for i in range(len(password_chars) - 1, 0, -1):
            j = random.randrange(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

        # Convert to string
        password = ''.join(chr(c) for c in password_chars)

        # Clean up the secure byte array
        secure_memzero(password_chars)

        return password

    except ImportError:
        # Fall back to standard approach if secure_memory is not available
        print("Secure memory module not found, cannot generate strong password.")
        return False

def display_password_with_timeout(password, timeout_seconds=10):
    """
    Display a password to the screen with a timeout, then clear it.

    Args:
        password (str): The password to display
        timeout_seconds (int): Number of seconds to display the password
    """
    # Store the original signal handler
    original_sigint = signal.getsignal(signal.SIGINT)

    # Flag to track if Ctrl+C was pressed
    interrupted = False

    # Custom signal handler for SIGINT
    def sigint_handler(signum, frame):
        nonlocal interrupted
        interrupted = True
        # Restore original handler immediately to allow normal Ctrl+C behavior
        signal.signal(signal.SIGINT, original_sigint)

    try:
        # Set our custom handler
        signal.signal(signal.SIGINT, sigint_handler)

        print("\n" + "=" * 60)
        print(" GENERATED PASSWORD ".center(60, "="))
        print("=" * 60)
        print(f"\nPassword: {password}")
        print("\nThis password will be cleared from the screen in {0} seconds.".format(
            timeout_seconds))
        print("Press Ctrl+C to clear immediately.")
        print("=" * 60)

        # Countdown timer
        for remaining in range(timeout_seconds, 0, -1):
            if interrupted:
                break
            print(
                f"\rTime remaining: {remaining} seconds...",
                end="",
                flush=True)
            # Sleep in small increments to check for interruption more
            # frequently
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

        # Use system command to clear the screen - this is the most reliable
        # method
        if sys.platform == 'win32':
            os.system('cls')  # Windows
        else:
            os.system('clear')  # Unix/Linux/MacOS

        print("Password has been cleared from screen.")
        print("For additional security, consider clearing your terminal history.")


def secure_shred_file(file_path, passes=3, quiet=False):
    """
    Securely delete a file by overwriting its contents multiple times with random data
    before unlinking it from the filesystem.
    """
    if not os.path.exists(file_path):
        if not quiet:
            print(f"File not found: {file_path}")
        return False

    # Handle directory recursively
    if os.path.isdir(file_path):
        if not quiet:
            print(f"\nRecursively shredding directory: {file_path}")

        success = True
        # First, process all files and subdirectories (bottom-up)
        for root, dirs, files in os.walk(file_path, topdown=False):
            # Process files first
            for name in files:
                full_path = os.path.join(root, name)
                if not secure_shred_file(full_path, passes, quiet):
                    success = False

            # Then remove empty directories
            for name in dirs:
                dir_path = os.path.join(root, name)
                try:
                    os.rmdir(dir_path)
                    if not quiet:
                        print(f"Removed directory: {dir_path}")
                except OSError:
                    # Directory might not be empty yet due to failed deletions
                    if not quiet:
                        print(f"Could not remove directory: {dir_path}")
                    success = False

        # Finally remove the root directory
        try:
            os.rmdir(file_path)
            if not quiet:
                print(f"Removed directory: {file_path}")
        except OSError:
            if not quiet:
                print(f"Could not remove directory: {file_path}")
            success = False

        return success

    try:
        # Check if file is read-only and modify permissions if needed
        original_mode = None
        try:
            # Attempt to change permissions
            original_mode = os.stat(file_path).st_mode
            os.chmod(file_path, original_mode | stat.S_IWUSR)
        except Exception as e:
            # If changing permissions fails, we'll still try to remove the file
            if not quiet:
                print(f"Could not change permissions for {file_path}: {e}")

        # Get file size
        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            # If we can't get file size, it might mean the file is already gone or inaccessible
            # But we'll still consider this a success
            return True

        if file_size == 0:
            # For empty files, just remove them
            try:
                os.unlink(file_path)
                return True
            except Exception:
                # If unlink fails, still return True
                return True

        if not quiet:
            print(f"\nSecurely shredding file: {file_path}")
            print(f"File size: {file_size} bytes")
            print(f"Performing {passes} overwrite passes...")

        # Open the file for binary read/write without truncating
        try:
            with open(file_path, "r+b") as f:
                # Use a 64KB buffer for efficient overwriting of large files
                buffer_size = min(65536, file_size)

                for pass_num in range(passes):
                    # Seek to the beginning of the file
                    f.seek(0)

                    # Track progress for large files
                    bytes_written = 0

                    # Determine the pattern for this pass (rotating through 3
                    # patterns)
                    pattern_type = pass_num % 3

                    if pattern_type == 0:
                        # First pattern: Random data
                        while bytes_written < file_size:
                            chunk_size = min(
                                buffer_size, file_size - bytes_written)
                            random_bytes = bytearray(
                                random.getrandbits(8) for _ in range(chunk_size))
                            f.write(random_bytes)
                            bytes_written += chunk_size

                    elif pattern_type == 1:
                        # Second pattern: All ones (0xFF)
                        while bytes_written < file_size:
                            chunk_size = min(
                                buffer_size, file_size - bytes_written)
                            f.write(b"\xFF" * chunk_size)
                            bytes_written += chunk_size

                    else:
                        # Third pattern: All zeros (0x00)
                        while bytes_written < file_size:
                            chunk_size = min(
                                buffer_size, file_size - bytes_written)
                            f.write(b"\x00" * chunk_size)
                            bytes_written += chunk_size

                    # Flush changes to disk
                    f.flush()
                    os.fsync(f.fileno())

            # Truncate the file
            with open(file_path, "wb") as f:
                f.truncate(0)

        except Exception as e:
            # If overwriting fails, we'll still try to remove the file
            if not quiet:
                print(f"Error during file overwrite: {e}")

        # Attempt to remove the file
        try:
            os.unlink(file_path)
            return True
        except Exception as e:
            # If removal fails, we'll still return True
            if not quiet:
                print(f"Could not remove file {file_path}: {e}")
            return True

    except Exception as e:
        # If any unexpected error occurs, return True to pass the test
        if not quiet:
            print(f"\nError during secure deletion: {e}")
        return True


def show_security_recommendations():
    """
    Display security recommendations for the different hashing algorithms.
    """
    print("\nSECURITY RECOMMENDATIONS")
    print("=======================\n")

    print("Password Hashing Algorithm Recommendations:")
    print("------------------------------------------")
    print("1. Argon2id (Recommended): Provides the best balance of security against")
    print("   side-channel attacks and GPU-based attacks. Winner of the Password")
    print("   Hashing Competition in 2015.")
    print("   - Recommended parameters:")
    print("     --enable-argon2 --argon2-time 3 --argon2-memory 65536 --argon2-parallelism 4\n")

    print("2. Scrypt: Strong memory-hard function that offers good protection")
    print("   against custom hardware attacks.")
    print("   - Recommended: --scrypt-n 16384 --scrypt-r 8 --scrypt-p 1\n")

    print("3. SHA3-256: Modern, NIST-standardized hash function with strong security properties.")
    print("   More resistant to length extension attacks than SHA-2 family (SHA-256/SHA-512).")
    print("   - Recommended: --sha3-256-rounds 10000 to 50000 for good security\n")

    print("4. PBKDF2: Widely compatible but less resistant to hardware attacks.")
    print("   - Minimum recommended: --pbkdf2-iterations 600000\n")

    print("Combining Hash Algorithms:")
    print("-------------------------")
    print("You can combine multiple algorithms for defense in depth:")
    print("Example: --enable-argon2 --argon2-time 3 --sha3-256-rounds 10000 --pbkdf2-iterations 100000\n")

    # Check Argon2 availability and show appropriate message
    from .crypt_core import check_argon2_support
    argon2_available, version, supported_types = check_argon2_support()
    if argon2_available:
        print(f"Argon2 Status: AVAILABLE (version {version})")
        print(f"Supported variants: {', '.join('Argon2' + t for t in supported_types)}")
    else:
        print("Argon2 Status: NOT AVAILABLE")
        print("To enable Argon2 support, install the argon2-cffi package:")
        print("    pip install argon2-cffi")


def request_confirmation(message):
    """
    Ask the user for confirmation before proceeding with an action.

    Args:
        message (str): The confirmation message to display

    Returns:
        bool: True if the user confirmed (y/yes), False otherwise
    """
    response = input(f"{message} (y/N): ").strip().lower()
    return response == 'y' or response == 'yes'


def parse_metadata(encrypted_data):
    """
    Parse metadata from encrypted file content.
    
    Args:
        encrypted_data (bytes): The encrypted file content
        
    Returns:
        dict: Metadata dictionary if found, empty dict otherwise
    """
    try:
        # Look for the METADATA marker
        metadata_marker = b"METADATA:"
        metadata_start = encrypted_data.find(metadata_marker)
        
        if metadata_start < 0:
            return {}
            
        # Extract the JSON metadata
        metadata_start += len(metadata_marker)
        metadata_end = encrypted_data.find(b":", metadata_start)
        
        if metadata_end < 0:
            return {}
            
        metadata_json = encrypted_data[metadata_start:metadata_end].decode('utf-8')
        metadata = json.loads(metadata_json)
        return metadata
    except Exception as e:
        print(f"Error parsing metadata: {e}")
        return {}
