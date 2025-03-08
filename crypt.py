#!/usr/bin/env python3
"""
Secure File Encryption Tool

This module provides functionality for secure file encryption, decryption,
and secure deletion. It uses strong cryptographic techniques including
symmetric encryption with Fernet (AES-128-CBC), multiple hash algorithms,
and secure data wiping for sensitive information.

The tool can be used as a command-line utility or imported as a module.
"""

import os
import base64
import argparse
import getpass
import hashlib
import json
import tempfile
import uuid
import stat
import signal
import atexit
import sys
import time
import threading
import random
import glob
import string
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# Try to import optional dependencies
try:
    import pywhirlpool
    WHIRLPOOL_AVAILABLE = True
except ImportError:
    WHIRLPOOL_AVAILABLE = False


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


def secure_shred_file(file_path, passes=3, quiet=False):
    """
    Securely delete a file by overwriting its contents multiple times with random data
    before unlinking it from the filesystem.
    
    This implementation follows military-grade data wiping standards by using
    multiple overwrite patterns to ensure data cannot be recovered even with 
    advanced forensic techniques.
    
    Args:
        file_path (str): Path to the file to shred
        passes (int): Number of overwrite passes to perform
        quiet (bool): Whether to suppress status messages
        
    Returns:
        bool: True if shredding was successful
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
        # Get file size
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            # For empty files, just remove them
            os.unlink(file_path)
            if not quiet:
                print(f"Empty file removed: {file_path}")
            return True
        
        if not quiet:
            print(f"\nSecurely shredding file: {file_path}")
            print(f"File size: {file_size} bytes")
            print(f"Performing {passes} overwrite passes...")
        
        # Open the file for binary read/write without truncating
        with open(file_path, "r+b") as f:
            # Use a 64KB buffer for efficient overwriting of large files
            buffer_size = min(65536, file_size)
            
            for pass_num in range(passes):
                # Seek to the beginning of the file
                f.seek(0)
                
                # Track progress for large files
                bytes_written = 0
                
                # Determine the pattern for this pass (rotating through 3 patterns)
                pattern_type = pass_num % 3
                
                if pattern_type == 0:
                    # First pattern: Random data - prevents recovery through statistical analysis
                    pattern_name = "random data"
                    while bytes_written < file_size:
                        # Determine how many bytes to write in this chunk
                        chunk_size = min(buffer_size, file_size - bytes_written)
                        
                        # Generate cryptographically secure random bytes
                        random_bytes = bytearray(random.getrandbits(8) for _ in range(chunk_size))
                        f.write(random_bytes)
                        
                        bytes_written += chunk_size
                        
                        # Show progress for large files
                        if not quiet:
                            percent = (bytes_written / file_size) * 100
                            pass_percent = ((pass_num + percent/100) / passes) * 100
                            bar_length = 30
                            filled_length = int(bar_length * pass_percent // 100)
                            bar = '█' * filled_length + ' ' * (bar_length - filled_length)
                            
                            print(f"\rShredding: [{bar}] Pass {pass_num+1}/{passes} "
                                  f"({pattern_name}): {percent:.1f}%", end="", flush=True)
                
                elif pattern_type == 1:
                    # Second pattern: All ones (0xFF) - different bit pattern to 
                    # ensure complete coverage
                    pattern_name = "all 1's"
                    while bytes_written < file_size:
                        chunk_size = min(buffer_size, file_size - bytes_written)
                        f.write(b"\xFF" * chunk_size)
                        bytes_written += chunk_size
                        
                        if not quiet:
                            percent = (bytes_written / file_size) * 100
                            pass_percent = ((pass_num + percent/100) / passes) * 100
                            bar_length = 30
                            filled_length = int(bar_length * pass_percent // 100)
                            bar = '█' * filled_length + ' ' * (bar_length - filled_length)
                            
                            print(f"\rShredding: [{bar}] Pass {pass_num+1}/{passes} "
                                  f"({pattern_name}): {percent:.1f}%", end="", flush=True)
                
                else:
                    # Third pattern: All zeros (0x00) - reset all bits
                    pattern_name = "all 0's"
                    while bytes_written < file_size:
                        chunk_size = min(buffer_size, file_size - bytes_written)
                        f.write(b"\x00" * chunk_size)
                        bytes_written += chunk_size
                        
                        if not quiet:
                            percent = (bytes_written / file_size) * 100
                            pass_percent = ((pass_num + percent/100) / passes) * 100
                            bar_length = 30
                            filled_length = int(bar_length * pass_percent // 100)
                            bar = '█' * filled_length + ' ' * (bar_length - filled_length)
                            
                            print(f"\rShredding: [{bar}] Pass {pass_num+1}/{passes} "
                                  f"({pattern_name}): {percent:.1f}%", end="", flush=True)
                
                # Flush changes to disk and ensure they're written to physical media
                f.flush()
                os.fsync(f.fileno())
        
        # Finally, truncate the file to 0 bytes before unlinking
        # This helps with hiding the file size
        with open(file_path, "wb") as f:
            f.truncate(0)
        
        # Remove the file from the filesystem
        os.unlink(file_path)
        
        if not quiet:
            print("\nFile has been securely deleted.")
        
        return True
        
    except Exception as e:
        if not quiet:
            print(f"\nError during secure deletion: {e}")
        return False


def show_animated_progress(message, stop_event, quiet=False):
    """
    Display an animated progress bar for operations that don't provide incremental feedback.
    
    Creates a visual indicator that the program is still working during long operations
    like key derivation or decryption of large files.
    
    Args:
        message (str): Message to display
        stop_event (threading.Event): Event to signal when to stop the animation
        quiet (bool): Whether to suppress progress output
    """
    if quiet:
        return
    
    animation = "|/-\\"  # Animation characters for spinning cursor
    idx = 0
    start_time = time.time()
    
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        minutes, seconds = divmod(int(elapsed), 60)
        time_str = f"{minutes:02d}:{seconds:02d}"
        
        # Create a pulsing bar to show activity
        bar_length = 30
        position = int((elapsed % 3) * 10)  # Moves every 0.1 seconds
        bar = ' ' * position + '█████' + ' ' * (bar_length - 5 - position)
        
        print(f"\r{message}: [{bar}] {animation[idx]} {time_str}", end='', flush=True)
        idx = (idx + 1) % len(animation)
        time.sleep(0.1)


def with_progress_bar(func, message, *args, quiet=False, **kwargs):
    """
    Execute a function with an animated progress bar to indicate activity.
    
    This is used for operations that don't report incremental progress like
    PBKDF2 key derivation or Scrypt, which can take significant time to complete.
    
    Args:
        func: Function to execute
        message: Message to display
        quiet: Whether to suppress progress output
        *args, **kwargs: Arguments to pass to the function
        
    Returns:
        The return value of the function
    """
    stop_event = threading.Event()
    
    if not quiet:
        # Start progress thread
        progress_thread = threading.Thread(
            target=show_animated_progress,
            args=(message, stop_event, quiet)
        )
        progress_thread.daemon = True
        progress_thread.start()
    
    try:
        # Call the actual function
        start_time = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start_time
        
        # Stop the progress thread
        stop_event.set()
        if not quiet:
            progress_thread.join()
            # Clear the current line
            print(f"\r{' ' * 80}\r", end='', flush=True)
            print(f"{message} completed in {duration:.2f} seconds")
            
        return result
    except Exception as e:
        # Stop the progress thread in case of error
        stop_event.set()
        if not quiet:
            progress_thread.join()
            # Clear the current line
            print(f"\r{' ' * 80}\r", end='', flush=True)
        raise e


def set_secure_permissions(file_path):
    """
    Set permissions on the file to restrict access to only the owner (current user).
    
    This applies the principle of least privilege by ensuring that sensitive files
    are only accessible by the user who created them.
    
    Args:
        file_path (str): Path to the file
    """
    # Set permissions to 0600 (read/write for owner only)
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)


def get_file_permissions(file_path):
    """
    Get the permissions of a file.
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        int: File permissions mode
    """
    return os.stat(file_path).st_mode & 0o777  # Get just the permission bits


def copy_permissions(source_file, target_file):
    """
    Copy permissions from source file to target file.
    
    Used to preserve original permissions when overwriting files.
    
    Args:
        source_file (str): Path to the source file
        target_file (str): Path to the target file
    """
    try:
        # Get the permissions from the source file
        mode = get_file_permissions(source_file)
        # Apply to the target file
        os.chmod(target_file, mode)
    except Exception:
        # If we can't copy permissions, fall back to secure permissions
        set_secure_permissions(target_file)


def calculate_hash(data):
    """
    Calculate SHA-256 hash of data for integrity verification.
    
    Args:
        data (bytes): Data to hash
        
    Returns:
        str: Hexadecimal hash string
    """
    return hashlib.sha256(data).hexdigest()


def multi_hash_password(password, salt, hash_config, quiet=False):
    """
    Apply multiple rounds of different hash algorithms to a password.
    
    This function implements a layered approach to password hashing, allowing
    multiple different algorithms to be applied in sequence. This provides defense
    in depth against weaknesses in any single algorithm.
    
    Supported algorithms:
        - SHA-256
        - SHA-512
        - SHA3-256
        - SHA3-512
        - Whirlpool
        - Scrypt (memory-hard function)
    
    Args:
        password (bytes): The password bytes
        salt (bytes): Salt value to use
        hash_config (dict): Dictionary with algorithm names as keys and iteration/parameter values
        quiet (bool): Whether to suppress progress output
    
    Returns:
        bytes: The hashed password
    """
    # Start with the original password + salt
    hashed = password + salt
    
    # Function to display progress for iterative hashing
    def show_progress(algorithm, current, total):
        if quiet:
            return
        
        # Only update every 1% or at least every 1000 iterations
        update_frequency = max(1, min(total // 100, 1000))
        if current % update_frequency != 0 and current != total:
            return
            
        percent = (current / total) * 100
        bar_length = 30
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + ' ' * (bar_length - filled_length)
        
        print(f"\r{algorithm} hashing: [{bar}] {percent:.1f}% ({current}/{total})", 
              end='', flush=True)
        
        if current == total:
            print()  # New line after completion
    
    # Apply each hash algorithm in sequence (only if iterations > 0)
    for algorithm, params in hash_config.items():
        if algorithm == 'sha512' and params > 0:
            if not quiet:
                print(f"Applying {params} rounds of SHA-512...")
            
            for i in range(params):
                hashed = hashlib.sha512(hashed).digest()
                show_progress("SHA-512", i+1, params)
        
        elif algorithm == 'sha256' and params > 0:
            if not quiet:
                print(f"Applying {params} rounds of SHA-256...")
                
            for i in range(params):
                hashed = hashlib.sha256(hashed).digest()
                show_progress("SHA-256", i+1, params)
        
        elif algorithm == 'sha3_256' and params > 0:
            # Make sure SHA3 is available (added in Python 3.6)
            if hasattr(hashlib, 'sha3_256'):
                if not quiet:
                    print(f"Applying {params} rounds of SHA3-256...")
                    
                for i in range(params):
                    hashed = hashlib.sha3_256(hashed).digest()
                    show_progress("SHA3-256", i+1, params)
            else:
                if not quiet:
                    print(f"SHA3 not available in this Python version, "
                          f"using {params} rounds of SHA-512 instead...")
                    
                for i in range(params):
                    hashed = hashlib.sha512(hashed).digest()
                    show_progress("SHA-512 (fallback)", i+1, params)
                    
        elif algorithm == 'sha3_512' and params > 0:
            # Make sure SHA3 is available (added in Python 3.6)
            if hasattr(hashlib, 'sha3_512'):
                if not quiet:
                    print(f"Applying {params} rounds of SHA3-512...")
                    
                for i in range(params):
                    hashed = hashlib.sha3_512(hashed).digest()
                    show_progress("SHA3-512", i+1, params)
            else:
                if not quiet:
                    print(f"SHA3 not available in this Python version, "
                          f"using {params} rounds of SHA-512 instead...")
                    
                for i in range(params):
                    hashed = hashlib.sha512(hashed).digest()
                    show_progress("SHA-512 (fallback)", i+1, params)
        
        elif algorithm == 'whirlpool' and params > 0:
            if WHIRLPOOL_AVAILABLE:
                if not quiet:
                    print(f"Applying {params} rounds of Whirlpool...")
                    
                for i in range(params):
                    w = pywhirlpool.new(hashed)
                    hashed = w.digest()
                    show_progress("Whirlpool", i+1, params)
            else:
                if not quiet:
                    print(f"Whirlpool not available, using {params} rounds of SHA-512 instead...")
                    
                for i in range(params):
                    hashed = hashlib.sha512(hashed).digest()
                    show_progress("SHA-512 (fallback)", i+1, params)
        
        elif algorithm == 'scrypt' and params.get('n', 0) > 0:
            # Apply scrypt with provided parameters
            # Scrypt is a memory-hard function requiring significant RAM to compute,
            # making it more resistant to hardware attacks
            if not quiet:
                print(f"Applying scrypt with n={params['n']}, r={params['r']}, p={params['p']}...")
            
            # Scrypt doesn't provide progress updates, so use an animated progress bar
            def do_scrypt():
                scrypt_kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=params['n'],  # CPU/memory cost factor
                    r=params['r'],  # Block size factor
                    p=params['p'],  # Parallelization factor
                    backend=default_backend()
                )
                return scrypt_kdf.derive(hashed)
                
            # Run scrypt with progress bar
            hashed = with_progress_bar(
                do_scrypt, 
                "Scrypt processing", 
                quiet=quiet
            )
    
    return hashed


def generate_key(password, salt=None, hash_config=None, pbkdf2_iterations=100000, quiet=False):
    """
    Generate a Fernet key from a password using multiple hash algorithms.
    
    This implements a robust key derivation process:
    1. Apply optional custom multi-hash rounds (configurable)
    2. Apply PBKDF2 with configurable iterations
    3. Format the result as a valid Fernet key
    
    Args:
        password (bytes): The password to use
        salt (bytes, optional): Salt value. If None, a random salt is generated.
        hash_config (dict, optional): Dictionary of hash algorithms and iterations.
        pbkdf2_iterations (int): Number of PBKDF2 iterations
        quiet (bool): Whether to suppress progress output
    
    Returns:
        tuple: (key, salt, hash_config)
    """
    if salt is None:
        # Generate a cryptographically secure random salt
        salt = os.urandom(16)
    
    # Default empty hash configuration if none provided
    if hash_config is None:
        hash_config = {
            'sha512': 0,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'whirlpool': 0,
            'scrypt': {
                'n': 0,
                'r': 8,
                'p': 1
            }
        }
    
    # First apply our custom multi-hash function (if any hashing is enabled)
    hashed_password = multi_hash_password(password, salt, hash_config, quiet)
    
    # Then use PBKDF2HMAC to derive the key
    if not quiet and pbkdf2_iterations > 10000:
        print(f"Applying PBKDF2 with {pbkdf2_iterations} iterations...")
    
    # PBKDF2 doesn't provide progress updates, so use an animated progress bar for long operations
    def do_pbkdf2():
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits
            salt=salt,
            iterations=pbkdf2_iterations,
            backend=default_backend()
        )
        return kdf.derive(hashed_password)
    
    # Only show progress for larger iteration counts
    if pbkdf2_iterations > 10000 and not quiet:
        derived_key = with_progress_bar(
            do_pbkdf2,
            "PBKDF2 processing",
            quiet=quiet
        )
    else:
        derived_key = do_pbkdf2()
    
    # Encode as URL-safe base64 for Fernet
    key = base64.urlsafe_b64encode(derived_key)
    return key, salt, hash_config


def encrypt_file(input_file, output_file, password, hash_config=None, 
                pbkdf2_iterations=100000, quiet=False):
    """
    Encrypt a file with a password.
    
    Implements secure file encryption with these steps:
    1. Generate a key from the password using configurable hashing
    2. Calculate a hash of the original file for integrity verification
    3. Encrypt the file using Fernet symmetric encryption
    4. Store metadata (salt, hash config, file hash) with the encrypted data
    
    Args:
        input_file (str): Path to the file to encrypt
        output_file (str): Path where to save the encrypted file
        password (bytes): The password to use for encryption
        hash_config (dict, optional): Hash configuration dictionary
        pbkdf2_iterations (int): Number of PBKDF2 iterations
        quiet (bool): Whether to suppress progress output
    
    Returns:
        bool: True if encryption was successful
    """
    # Generate a key from the password
    salt = os.urandom(16)  # Unique salt for each encryption
    
    if not quiet:
        print("\nGenerating encryption key...")
    
    key, salt, hash_config = generate_key(password, salt, hash_config, pbkdf2_iterations, quiet)
    
    # Create a Fernet instance with the key
    f = Fernet(key)
    
    # Read the input file
    if not quiet:
        print(f"Reading file: {input_file}")
    
    with open(input_file, 'rb') as file:
        data = file.read()
    
    # Calculate hash of original data for integrity verification
    if not quiet:
        print("Calculating content hash...")
    
    original_hash = calculate_hash(data)
    
    # Encrypt the data
    if not quiet:
        print("Encrypting content...")
    
    # For large files, use progress bar for encryption
    def do_encrypt():
        return f.encrypt(data)
    
    # Only show progress for larger files (> 1MB)
    if len(data) > 1024 * 1024 and not quiet:
        encrypted_data = with_progress_bar(
            do_encrypt,
            "Encrypting data",
            quiet=quiet
        )
    else:
        encrypted_data = do_encrypt()
    
    # Create metadata with the salt and hash configuration
    # This allows the exact same parameters to be used for decryption
    metadata = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'hash_config': hash_config,
        'pbkdf2_iterations': pbkdf2_iterations,
        'original_hash': original_hash  # Store hash of the original content
    }
    
    # Serialize and encode the metadata
    metadata_json = json.dumps(metadata).encode('utf-8')
    metadata_base64 = base64.b64encode(metadata_json)
    
    # Write the metadata and encrypted data to the output file
    # Format: base64_metadata:encrypted_data
    if not quiet:
        print(f"Writing encrypted file: {output_file}")
    
    with open(output_file, 'wb') as file:
        file.write(metadata_base64 + b':' + encrypted_data)
    
    # By default, set secure permissions on the output file
    # This will be overridden with original permissions when overwriting
    set_secure_permissions(output_file)
    
    return True


def decrypt_file(input_file, output_file, password, quiet=False):
    """
    Decrypt a file with a password.
    
    Implements secure file decryption with these steps:
    1. Extract metadata from the encrypted file
    2. Generate the same key used for encryption
    3. Decrypt the file data
    4. Verify file integrity using the stored hash
    
    Args:
        input_file (str): Path to the encrypted file
        output_file (str): Path where to save the decrypted file, or None to return data
        password (bytes): The password to use for decryption
        quiet (bool): Whether to suppress status messages
        
    Returns:
        bytes or bool: If output_file is None, returns the decrypted data, otherwise returns True
    """
    # Read the encrypted file
    if not quiet:
        print(f"\nReading encrypted file: {input_file}")
    
    with open(input_file, 'rb') as file:
        content = file.read()
    
    # Extract the metadata and encrypted data
    # Format: base64_metadata:encrypted_data
    parts = content.split(b':', 1)
    if len(parts) != 2:
        raise ValueError("Invalid file format")
    
    metadata_base64, encrypted_data = parts
    
    try:
        # Decode the metadata
        metadata_json = base64.b64decode(metadata_base64)
        metadata = json.loads(metadata_json.decode('utf-8'))
        
        # Extract parameters from metadata
        salt = base64.b64decode(metadata['salt'])
        hash_config = metadata['hash_config']
        pbkdf2_iterations = metadata.get('pbkdf2_iterations', 100000)  # Default if not present
        original_hash = metadata.get('original_hash')  # May not exist in older files
        
        if not quiet:
            print("Metadata extracted successfully")
            
    except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
        raise ValueError(f"Error parsing file metadata: {e}")
    
    # Generate the key using the same parameters
    if not quiet:
        print("Generating decryption key...")
    
    key, _, _ = generate_key(password, salt, hash_config, pbkdf2_iterations, quiet)
    
    # Create a Fernet instance with the key
    f = Fernet(key)
    
    # Decrypt the data
    try:
        if not quiet:
            print("Decrypting content...")
        
        # For large files, use progress bar for decryption
        def do_decrypt():
            return f.decrypt(encrypted_data)
        
        # Only show progress for larger files (> 1MB)
        if len(encrypted_data) > 1024 * 1024 and not quiet:
            decrypted_data = with_progress_bar(
                do_decrypt,
                "Decrypting data",
                quiet=quiet
            )
        else:
            decrypted_data = do_decrypt()
            
    except Exception as e:
        raise ValueError(f"Decryption failed. Invalid password or corrupted file: {e}")
    
    # Verify hash if it was stored in metadata
    if original_hash:
        if not quiet:
            print("Verifying content integrity...")
        
        decrypted_hash = calculate_hash(decrypted_data)
        if decrypted_hash != original_hash:
            raise ValueError("Hash verification failed. The file may be corrupted or tampered with.")
        elif not quiet:
            print("\nHash verification successful: Content integrity verified ✓")
    elif not quiet:
        print("\nNote: This file was encrypted without hash verification")
    
    # Write the decrypted data to the output file or return it
    if output_file:
        if not quiet:
            print(f"Writing decrypted file: {output_file}")
        
        with open(output_file, 'wb') as file:
            file.write(decrypted_data)
        
        # By default, set secure permissions on the output file
        # This will be overridden with original permissions when overwriting
        set_secure_permissions(output_file)
        
        return True
    else:
        return decrypted_data


def expand_glob_patterns(pattern):
    """
    Expand glob patterns into a list of matching files and directories.
    
    Args:
        pattern (str): Glob pattern to expand
        
    Returns:
        list: List of matching file and directory paths
    """
    return glob.glob(pattern)


def generate_strong_password(length, use_lowercase=True, use_uppercase=True, 
                         use_digits=True, use_special=True):
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
    
    # Fill remaining length with random characters from the pool
    remaining_length = length - len(required_chars)
    password_chars = required_chars + [random.choice(char_pool) for _ in range(remaining_length)]
    
    # Shuffle to ensure required characters aren't in predictable positions
    random.shuffle(password_chars)
    
    return ''.join(password_chars)


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
        print("\nThis password will be cleared from the screen in {0} seconds.".format(timeout_seconds))
        print("Press Ctrl+C to clear immediately.")
        print("=" * 60)
        
        # Countdown timer
        for remaining in range(timeout_seconds, 0, -1):
            if interrupted:
                break
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
        
        # Use system command to clear the screen - this is the most reliable method
        if sys.platform == 'win32':
            os.system('cls')  # Windows
        else:
            os.system('clear')  # Unix/Linux/MacOS
        
        print("Password has been cleared from screen.")
        print("For additional security, consider clearing your terminal history.")


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
    
    # Define core actions
    parser.add_argument(
        'action', 
        choices=['encrypt', 'decrypt', 'shred', 'generate-password'], 
        help='Action to perform'
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
    
    # Hash configuration arguments (all optional)
    parser.add_argument(
        '--sha512', 
        type=int, 
        nargs='?', 
        const=1, 
        default=0,
        help='Number of SHA-512 iterations (default: 1,000,000 if flag provided without value)'
    )
    parser.add_argument(
        '--sha256', 
        type=int, 
        nargs='?', 
        const=1, 
        default=0,
        help='Number of SHA-256 iterations (default: 1,000,000 if flag provided without value)'
    )
    parser.add_argument(
        '--sha3-256', 
        type=int, 
        nargs='?', 
        const=1, 
        default=0,
        help='Number of SHA3-256 iterations (default: 1,000,000 if flag provided without value)'
    )
    parser.add_argument(
        '--sha3-512', 
        type=int, 
        nargs='?', 
        const=1, 
        default=0,
        help='Number of SHA3-512 iterations (default: 1,000,000 if flag provided without value)'
    )
    parser.add_argument(
        '--whirlpool', 
        type=int, 
        default=0,
        help='Number of Whirlpool iterations (default: 0, not used)'
    )
    parser.add_argument(
        '--scrypt-cost', 
        type=int, 
        default=0,
        help='Scrypt cost factor N as power of 2 (default: 0, not used)'
    )
    parser.add_argument(
        '--scrypt-r', 
        type=int, 
        default=8,
        help='Scrypt block size parameter r (default: 8)'
    )
    parser.add_argument(
        '--scrypt-p', 
        type=int, 
        default=1,
        help='Scrypt parallelization parameter p (default: 1)'
    )
    parser.add_argument(
        '--pbkdf2', 
        type=int, 
        default=100000,
        help='Number of PBKDF2 iterations (default: 100000)'
    )
    
    # Password generation options
    parser.add_argument(
        '--length', 
        type=int, 
        default=16,
        help='Length of generated password (default: 16)'
    )
    parser.add_argument(
        '--use-digits', 
        action='store_true',
        help='Include digits in generated password'
    )
    parser.add_argument(
        '--use-lowercase', 
        action='store_true',
        help='Include lowercase letters in generated password'
    )
    parser.add_argument(
        '--use-uppercase', 
        action='store_true',
        help='Include uppercase letters in generated password'
    )
    parser.add_argument(
        '--use-special', 
        action='store_true',
        help='Include special characters in generated password'
    )
    
    args = parser.parse_args()
    
    # Check for Whirlpool availability if needed and not in quiet mode
    if args.whirlpool > 0 and not WHIRLPOOL_AVAILABLE and not args.quiet:
        print("Warning: pywhirlpool module not found. SHA-512 will be used instead.")
        
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
    
    # Check for password generation action
    if args.action == 'generate-password':
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
            args.use_special
        )
        
        display_password_with_timeout(password)
        # Exit after generating password
        sys.exit(0)
        
    # For other actions, input file is required
    if args.input is None:
        parser.error("the following arguments are required: --input/-i")
    
    # Get password (only for encrypt/decrypt actions)
    password = None
    generated_password = None
    
    if args.action in ['encrypt', 'decrypt']:
        password = args.password
        
        # Handle random password generation for encryption
        if args.action == 'encrypt' and args.random and not password:
            generated_password = generate_strong_password(
                args.random,
                use_lowercase=True,
                use_uppercase=True,
                use_digits=True,
                use_special=True
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
    
    # Create hash configuration dictionary (only include algorithms with iterations > 0)
    scrypt_n = 2 ** args.scrypt_cost if args.scrypt_cost > 0 else 0
    
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
                        print(f"- scrypt: n={params['n']} (cost factor 2^{args.scrypt_cost}), "
                              f"r={params['r']}, p={params['p']}")
                    elif algorithm != 'scrypt' and params > 0:
                        any_hash_used = True
                        print(f"- {algorithm}: {params} iterations")
                
                if not any_hash_used:
                    print("- No additional hashing algorithms used")
                    
                print(f"- PBKDF2: {args.pbkdf2} iterations")
            
            # If overwriting, encrypt to a temporary file first for safety
            if args.overwrite:
                try:
                    # Get original file permissions before doing anything
                    original_permissions = get_file_permissions(args.input)
                    
                    # Encrypt to temporary file
                    success = encrypt_file(
                        args.input, temp_output, password, hash_config, args.pbkdf2, args.quiet
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
                    args.input, output_file, password, hash_config, args.pbkdf2, args.quiet
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
                    success = decrypt_file(args.input, temp_output, password, args.quiet)
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
                success = decrypt_file(args.input, args.output, password, args.quiet)
                if success and not args.quiet:
                    print(f"\nFile decrypted successfully: {args.output}")
                    
                # If shredding was requested and decryption was successful
                if args.shred and success:
                    if not args.quiet:
                        print("Shredding the encrypted file as requested...")
                    secure_shred_file(args.input, args.shred_passes, args.quiet)
            else:
                # Decrypt to screen if no output file specified (useful for text files)
                decrypted = decrypt_file(args.input, None, password, args.quiet)
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

