#!/usr/bin/env python3
"""
Secure File Encryption Tool - Core Module

This module provides the core functionality for secure file encryption, decryption,
and secure deletion. It contains the cryptographic operations and key derivation
functions that power the encryption tool.
"""

import os
import base64
import hashlib
import json
import stat
import time
import threading
import random
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

# Try to import argon2 library
try:
    import argon2
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
    
    # Map Argon2 type string to the actual type constant
    ARGON2_TYPE_MAP = {
        'id': Type.ID,    # Argon2id (recommended)
        'i': Type.I,      # Argon2i
        'd': Type.D       # Argon2d
    }
    
    # Map for integer representation (JSON serializable)
    ARGON2_TYPE_INT_MAP = {
        'id': 2,  # Type.ID.value
        'i': 1,   # Type.I.value
        'd': 0    # Type.D.value
    }
    
    # Reverse mapping from int to Type
    ARGON2_INT_TO_TYPE_MAP = {
        2: Type.ID,
        1: Type.I,
        0: Type.D
    }
except ImportError:
    ARGON2_AVAILABLE = False
    ARGON2_TYPE_MAP = {'id': None, 'i': None, 'd': None}
    ARGON2_TYPE_INT_MAP = {'id': 2, 'i': 1, 'd': 0}  # Default integer values
    ARGON2_INT_TO_TYPE_MAP = {}

def check_argon2_support():
    """
    Check if Argon2 is available and which variants are supported.
    
    Returns:
        tuple: (is_available, version, supported_types)
    """
    if not ARGON2_AVAILABLE:
        return False, None, []
    
    try:
        # Get version
        version = argon2.__version__
        
        # Check which variants are supported
        supported_types = []
        if hasattr(argon2.low_level, 'Type'):
            if hasattr(argon2.low_level.Type, 'ID'):
                supported_types.append('id')
            if hasattr(argon2.low_level.Type, 'I'):
                supported_types.append('i')
            if hasattr(argon2.low_level.Type, 'D'):
                supported_types.append('d')
                
        return True, version, supported_types
    except Exception:
        return False, None, []

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

def multi_hash_password(password, salt, hash_config, quiet=False, use_secure_mem=True):
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
        - Argon2 (memory-hard function, winner of PHC)

    Args:
        password (bytes): The password bytes
        salt (bytes): Salt value to use
        hash_config (dict): Dictionary with algorithm names as keys and iteration/parameter values
        quiet (bool): Whether to suppress progress output
        use_secure_mem (bool): Whether to use secure memory handling

    Returns:
        bytes: The hashed password
    """

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

    if use_secure_mem:
        try:
            from secure_memory import secure_buffer, secure_memcpy, secure_memzero

            # Use secure memory approach
            with secure_buffer(len(password) + len(salt), zero=False) as hashed:
                # Initialize the secure buffer with password + salt
                secure_memcpy(hashed, password + salt)

                # Apply each hash algorithm in sequence (only if iterations > 0)
                for algorithm, params in hash_config.items():
                    if algorithm == 'sha512' and params > 0:
                        if not quiet:
                            print(f"Applying {params} rounds of SHA-512...")

                        with secure_buffer(64, zero=False) as hash_buffer:  # SHA-512 produces 64 bytes
                            for i in range(params):
                                # Create a copy of current hash result
                                result = hashlib.sha512(hashed).digest()
                                # Securely copy to our hash buffer
                                secure_memcpy(hash_buffer, result)
                                # Update the main hash buffer
                                secure_memcpy(hashed, hash_buffer)
                                show_progress("SHA-512", i + 1, params)
                    
                    elif algorithm == 'sha256' and params > 0:
                        if not quiet:
                            print(f"Applying {params} rounds of SHA-256...")

                        with secure_buffer(32, zero=False) as hash_buffer:  # SHA-256 produces 32 bytes
                            for i in range(params):
                                result = hashlib.sha256(hashed).digest()
                                secure_memcpy(hash_buffer, result)
                                secure_memcpy(hashed, hash_buffer)
                                show_progress("SHA-256", i + 1, params)
                    
                    elif algorithm == 'sha3_256' and params > 0:
                        if not quiet:
                            print(f"Applying {params} rounds of SHA3-256...")

                        with secure_buffer(32, zero=False) as hash_buffer:  # SHA3-256 produces 32 bytes
                            for i in range(params):
                                result = hashlib.sha3_256(hashed).digest()
                                secure_memcpy(hash_buffer, result)
                                secure_memcpy(hashed, hash_buffer)
                                show_progress("SHA3-256", i + 1, params)
                    
                    elif algorithm == 'sha3_512' and params > 0:
                        if not quiet:
                            print(f"Applying {params} rounds of SHA3-512...")

                        with secure_buffer(64, zero=False) as hash_buffer:  # SHA3-512 produces 64 bytes
                            for i in range(params):
                                result = hashlib.sha3_512(hashed).digest()
                                secure_memcpy(hash_buffer, result)
                                secure_memcpy(hashed, hash_buffer)
                                show_progress("SHA3-512", i + 1, params)
                    
                    elif algorithm == 'whirlpool' and params > 0:
                        if not quiet:
                            print(f"Applying {params} rounds of Whirlpool...")

                        if WHIRLPOOL_AVAILABLE:
                            with secure_buffer(64, zero=False) as hash_buffer:  # Whirlpool produces 64 bytes
                                for i in range(params):
                                    result = pywhirlpool.whirlpool(bytes(hashed)).digest()
                                    secure_memcpy(hash_buffer, result)
                                    secure_memcpy(hashed, hash_buffer)
                                    show_progress("Whirlpool", i + 1, params)
                        else:
                            # Fall back to SHA-512 if Whirlpool is not available
                            if not quiet:
                                print("Warning: Whirlpool not available, using SHA-512 instead")

                            with secure_buffer(64, zero=False) as hash_buffer:
                                for i in range(params):
                                    result = hashlib.sha512(hashed).digest()
                                    secure_memcpy(hash_buffer, result)
                                    secure_memcpy(hashed, hash_buffer)
                                    show_progress("SHA-512 (fallback)", i + 1, params)

                    elif algorithm == 'scrypt' and params.get('n', 0) > 0:
                        # Apply scrypt with provided parameters
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
                            result = scrypt_kdf.derive(bytes(hashed))

                            # Create a temporary secure buffer for the result
                            with secure_buffer(32, zero=False) as scrypt_result:
                                secure_memcpy(scrypt_result, result)
                                # Resize the output buffer if needed
                                if len(hashed) < 32:
                                    # Not ideal to create a new buffer, but necessary if original is too small
                                    new_hashed = bytearray(32)
                                    secure_memcpy(new_hashed, scrypt_result)
                                    return new_hashed
                                else:
                                    # Copy result to the output buffer
                                    secure_memcpy(hashed, scrypt_result, 32)
                                    return hashed

                        # Run scrypt with progress bar
                        hashed = with_progress_bar(
                            do_scrypt,
                            "Scrypt processing",
                            quiet=quiet
                        )
                    
                    elif algorithm == 'argon2' and params.get('enabled', False) and ARGON2_AVAILABLE:
                        # Apply Argon2 with provided parameters
                        if not quiet:
                            print(f"Applying Argon2 with time_cost={params['time_cost']}, "
                                  f"memory_cost={params['memory_cost']}, parallelism={params['parallelism']}, "
                                  f"hash_len={params['hash_len']}...")
                        
                        # Argon2 doesn't provide progress updates, so use an animated progress bar
                        def do_argon2():
                            # Use low_level API for more control
                            # Convert type integer back to enum if needed
                            argon2_type = params['type']
                            if ARGON2_AVAILABLE and isinstance(argon2_type, int) and argon2_type in ARGON2_INT_TO_TYPE_MAP:
                                argon2_type = ARGON2_INT_TO_TYPE_MAP[argon2_type]
                                
                            result = argon2.low_level.hash_secret_raw(
                                secret=bytes(hashed),
                                salt=salt,
                                time_cost=params['time_cost'],
                                memory_cost=params['memory_cost'],
                                parallelism=params['parallelism'],
                                hash_len=params['hash_len'],
                                type=argon2_type
                            )
                            
                            # Create a temporary secure buffer for the result
                            with secure_buffer(params['hash_len'], zero=False) as argon2_result:
                                secure_memcpy(argon2_result, result)
                                # Resize the output buffer if needed
                                if len(hashed) < params['hash_len']:
                                    # Not ideal to create a new buffer, but necessary if original is too small
                                    new_hashed = bytearray(params['hash_len'])
                                    secure_memcpy(new_hashed, argon2_result)
                                    return new_hashed
                                else:
                                    # Copy result to the output buffer
                                    secure_memcpy(hashed, argon2_result, params['hash_len'])
                                    return hashed
                        
                        # Run Argon2 with progress bar
                        hashed = with_progress_bar(
                            do_argon2,
                            "Argon2 processing",
                            quiet=quiet
                        )

                # Create a new bytes object with the final result
                # We need to convert to bytes for compatibility with the rest of the code
                result = bytes(hashed)

            return result

        except ImportError:
            # Fall back to standard method if secure_memory is not available
            if not quiet:
                print("Warning: secure_memory module not available, falling back to standard method")
            use_secure_mem = False

    # Standard method without secure memory
    if not use_secure_mem:
        # Start with the original password + salt
        hashed = password + salt

        # Apply each hash algorithm in sequence (only if iterations > 0)
        for algorithm, params in hash_config.items():
            if algorithm == 'sha512' and params > 0:
                if not quiet:
                    print(f"Applying {params} rounds of SHA-512...")

                for i in range(params):
                    hashed = hashlib.sha512(hashed).digest()
                    show_progress("SHA-512", i + 1, params)
            
            elif algorithm == 'sha256' and params > 0:
                if not quiet:
                    print(f"Applying {params} rounds of SHA-256...")

                for i in range(params):
                    hashed = hashlib.sha256(hashed).digest()
                    show_progress("SHA-256", i + 1, params)
            
            elif algorithm == 'sha3_256' and params > 0:
                if not quiet:
                    print(f"Applying {params} rounds of SHA3-256...")

                for i in range(params):
                    hashed = hashlib.sha3_256(hashed).digest()
                    show_progress("SHA3-256", i + 1, params)
            
            elif algorithm == 'sha3_512' and params > 0:
                if not quiet:
                    print(f"Applying {params} rounds of SHA3-512...")

                for i in range(params):
                    hashed = hashlib.sha3_512(hashed).digest()
                    show_progress("SHA3-512", i + 1, params)
            
            elif algorithm == 'whirlpool' and params > 0:
                if not quiet:
                    print(f"Applying {params} rounds of Whirlpool...")

                if WHIRLPOOL_AVAILABLE:
                    for i in range(params):
                        hashed = pywhirlpool.whirlpool(hashed).digest()
                        show_progress("Whirlpool", i + 1, params)
                else:
                    # Fall back to SHA-512 if Whirlpool is not available
                    if not quiet:
                        print("Warning: Whirlpool not available, using SHA-512 instead")
                    
                    for i in range(params):
                        hashed = hashlib.sha512(hashed).digest()
                        show_progress("SHA-512 (fallback)", i + 1, params)

            elif algorithm == 'scrypt' and params.get('n', 0) > 0:
                # Apply scrypt with provided parameters
                if not quiet:
                    print(f"Applying scrypt with n={params['n']}, r={params['r']}, p={params['p']}...")

                # Scrypt doesn't provide progress updates, so use an animated progress bar
                def do_scrypt():
                    scrypt_kdf = Scrypt(
                        salt=salt,
                        length=32,
                        n=params['n'],
                        r=params['r'],
                        p=params['p'],
                        backend=default_backend()
                    )
                    return scrypt_kdf.derive(hashed)

                # Run scrypt with progress bar
                hashed = with_progress_bar(
                    do_scrypt,
                    "Scrypt processing",
                    quiet=quiet
                )
            
            elif algorithm == 'argon2' and params.get('enabled', False) and ARGON2_AVAILABLE:
                # Apply Argon2 with provided parameters
                if not quiet:
                    print(f"Applying Argon2 with time_cost={params['time_cost']}, "
                          f"memory_cost={params['memory_cost']}, parallelism={params['parallelism']}, "
                          f"hash_len={params['hash_len']}...")
                
                # Argon2 doesn't provide progress updates, so use an animated progress bar
                def do_argon2():
                    # Use low_level API for more control
                    # Convert type integer back to enum if needed
                    argon2_type = params['type']
                    if ARGON2_AVAILABLE and isinstance(argon2_type, int) and argon2_type in ARGON2_INT_TO_TYPE_MAP:
                        argon2_type = ARGON2_INT_TO_TYPE_MAP[argon2_type]
                        
                    return argon2.low_level.hash_secret_raw(
                        secret=hashed,
                        salt=salt,
                        time_cost=params['time_cost'],
                        memory_cost=params['memory_cost'],
                        parallelism=params['parallelism'],
                        hash_len=params['hash_len'],
                        type=argon2_type
                    )
                
                # Run Argon2 with progress bar
                hashed = with_progress_bar(
                    do_argon2,
                    "Argon2 processing",
                    quiet=quiet
                )

        return hashed

def generate_key(password, salt=None, hash_config=None, pbkdf2_iterations=100000, quiet=False, use_secure_mem=True):
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
        use_secure_mem (bool): Whether to use secure memory handling

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
            },
            'argon2': {
                'enabled': False,
                'time_cost': 3,
                'memory_cost': 65536,  # 64 MB
                'parallelism': 4,
                'hash_len': 32,
                'type': 'Type.ID'  # Argon2id variant
            }
        }

    # First apply our custom multi-hash function (if any hashing is enabled)
    hashed_password = multi_hash_password(password, salt, hash_config, quiet, use_secure_mem)

    # Then use PBKDF2HMAC to derive the key
    if not quiet and pbkdf2_iterations > 10000:
        print(f"Applying PBKDF2 with {pbkdf2_iterations} iterations...")

    # PBKDF2 doesn't provide progress updates, so use an animated progress bar for long operations
    def do_pbkdf2():
        # Initialize use_secure_mem for the nested function scope
        nonlocal use_secure_mem
        
        if use_secure_mem:
            
            try:
                from modules.secure_memory import secure_buffer, secure_memcpy

                with secure_buffer(len(hashed_password), zero=False) as secure_hashed_pwd:
                    secure_memcpy(secure_hashed_pwd, hashed_password)

                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,  # 32 bytes = 256 bits
                        salt=salt,
                        iterations=pbkdf2_iterations,
                        backend=default_backend()
                    )

                    # Use a secure buffer for the derived key
                    with secure_buffer(32, zero=False) as derived_key_buffer:
                        derived_key_bytes = kdf.derive(secure_hashed_pwd)
                        secure_memcpy(derived_key_buffer, derived_key_bytes)

                        # Encode as URL-safe base64 for Fernet
                        key = base64.urlsafe_b64encode(bytes(derived_key_buffer))
                        return key
            except ImportError:
                # Fall back to standard method if secure_memory is not available
                if not quiet:
                    print("Warning: secure_memory module not available, falling back to standard method")
                use_secure_mem = False

        # Standard method
        if not use_secure_mem:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=pbkdf2_iterations,
                backend=default_backend()
            )
            derived_key = kdf.derive(hashed_password)
            key = base64.urlsafe_b64encode(derived_key)
            return key

    # Only show progress for larger iteration counts
    if pbkdf2_iterations > 10000 and not quiet:
        derived_key = with_progress_bar(
            do_pbkdf2,
            "PBKDF2 processing",
            quiet=quiet
        )
    else:
        derived_key = do_pbkdf2()

    return derived_key, salt, hash_config

def encrypt_file(input_file, output_file, password, hash_config=None,
                 pbkdf2_iterations=100000, quiet=False, use_secure_mem=True):
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
        use_secure_mem (bool): Whether to use secure memory handling

    Returns:
        bool: True if encryption was successful
    """
    # Generate a key from the password
    salt = os.urandom(16)  # Unique salt for each encryption

    if not quiet:
        print("\nGenerating encryption key...")

    key, salt, hash_config = generate_key(
        password, salt, hash_config, pbkdf2_iterations, quiet, use_secure_mem
    )

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
        # Must declare nonlocal before any usage of the variable
        nonlocal use_secure_mem
        
        # Function body continues here
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

    # Clean up sensitive data if using secure memory
    if use_secure_mem:
        try:
            from modules.secure_memory import secure_memzero
            secure_memzero(key)
        except ImportError:
            # Just set to None if secure_memzero is not available
            key = None
    else:
        # Best effort cleanup in standard mode
        key = None

    return True

def decrypt_file(input_file, output_file, password, quiet=False, use_secure_mem=True):
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
        use_secure_mem (bool): Whether to use secure memory handling

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

    key, _, _ = generate_key(password, salt, hash_config, pbkdf2_iterations, quiet, use_secure_mem)

    # Create a Fernet instance with the key
    f = Fernet(key)

    # Decrypt the data
    try:
        if not quiet:
            print("Decrypting content...")

        # For large files, use progress bar for decryption
        def do_decrypt():  
            # Must declare nonlocal before any usage of the variable
            nonlocal use_secure_mem
            
            # Function body continues here
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

        # Use secure memory if enabled
        if use_secure_mem:
            try:
                from modules.secure_memory import secure_buffer, secure_memcpy, secure_memzero

                with secure_buffer(len(decrypted_data), zero=False) as secure_decrypted:
                    secure_memcpy(secure_decrypted, decrypted_data)

                    # Verify hash if it was stored in metadata
                    if original_hash:
                        if not quiet:
                            print("Verifying content integrity...")

                        decrypted_hash = calculate_hash(secure_decrypted)
                        if decrypted_hash != original_hash:
                            secure_memzero(key)
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
                            file.write(bytes(secure_decrypted))

                        # By default, set secure permissions on the output file
                        # This will be overridden with original permissions when overwriting
                        set_secure_permissions(output_file)

                        # Clean up sensitive data
                        secure_memzero(key)

                        return True
                    else:
                        # Need to return a copy of the decrypted data
                        result = bytes(secure_decrypted)

                        # Clean up sensitive data
                        secure_memzero(key)

                        return result

            except ImportError:
                # Fall back to standard method if secure_memory is not available
                if not quiet:
                    print("Warning: secure_memory module not available, falling back to standard method")
                use_secure_mem = False

        # Standard method if secure memory is disabled or not available
        if not use_secure_mem:
            # Verify hash if it was stored in metadata
            if original_hash:
                if not quiet:
                    print("Verifying content integrity...")

                decrypted_hash = calculate_hash(decrypted_data)
                if decrypted_hash != original_hash:
                    key = None  # Best effort cleanup
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

                # Best effort cleanup
                key = None

                return True
            else:
                # Best effort cleanup
                key = None
                return decrypted_data

    except Exception as e:
        # Clean up sensitive data on error
        if use_secure_mem:
            try:
                from modules.secure_memory import secure_memzero
                secure_memzero(key)
            except ImportError:
                key = None
        else:
            key = None
        raise ValueError(f"Decryption failed. Invalid password or corrupted file: {e}")

