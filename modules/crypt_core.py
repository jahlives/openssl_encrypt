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
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


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
        'id': Type.ID,  # Argon2id (recommended)
        'i': Type.I,  # Argon2i
        'd': Type.D  # Argon2d
    }

    # Map for integer representation (JSON serializable)
    ARGON2_TYPE_INT_MAP = {
        'id': 2,  # Type.ID.value
        'i': 1,  # Type.I.value
        'd': 0  # Type.D.value
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

class EncryptionAlgorithm(Enum):
    FERNET = "fernet"
    AES_GCM = "aes-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


def encrypt_with_algorithm(data, key, algorithm=EncryptionAlgorithm.FERNET):
    """
    Encrypt data using the specified algorithm.

    Args:
        data (bytes): Data to encrypt
        key (bytes): Encryption key
        algorithm (EncryptionAlgorithm): Encryption algorithm to use

    Returns:
        bytes: Encrypted data with metadata
    """
    if algorithm == EncryptionAlgorithm.FERNET:
        f = Fernet(key)
        encrypted = f.encrypt(data)
        metadata = {
            'encryption_algorithm': algorithm.value,
            'salt': None,  # Fernet handles its own salt
            'encrypted_hash': calculate_hash(encrypted)
        }
    else:
        # Generate a random salt/nonce
        salt = os.urandom(16)  # 16 bytes for AES-GCM, we'll use first 12 for ChaCha20-Poly1305

        if algorithm == EncryptionAlgorithm.AES_GCM:
            cipher = AESGCM(key)
            encrypted = cipher.encrypt(salt[:12], data, None)
        else:  # ChaCha20-Poly1305
            cipher = ChaCha20Poly1305(key)
            encrypted = cipher.encrypt(salt[:12], data, None)

        metadata = {
            'encryption_algorithm': algorithm.value,
            'salt': base64.b64encode(salt).decode('utf-8'),
            'encrypted_hash': calculate_hash(encrypted)
        }

    # Encode metadata and combine with encrypted data
    metadata_bytes = base64.b64encode(json.dumps(metadata).encode())
    return metadata_bytes + b':' + base64.b64encode(encrypted)


def decrypt_with_algorithm(encrypted_data, key):
    """
    Decrypt data using the appropriate algorithm.

    Args:
        encrypted_data (bytes): Encrypted data
        key (bytes): Decryption key

    Returns:
        bytes: Decrypted data
    """
    try:
        # Split metadata and encrypted data
        metadata_b64, encrypted_b64 = encrypted_data.split(b':', 1)
        metadata = json.loads(base64.b64decode(metadata_b64))
        encrypted = base64.b64decode(encrypted_b64)

        # Verify encrypted data hash
        if calculate_hash(encrypted) != metadata['encrypted_hash']:
            raise ValueError("Encrypted data hash mismatch")

        algorithm = metadata['encryption_algorithm']

        if algorithm == EncryptionAlgorithm.FERNET.value:
            f = Fernet(key)
            return f.decrypt(encrypted)

        elif algorithm == EncryptionAlgorithm.AES_GCM.value:
            cipher = AESGCM(key)
            salt = base64.b64decode(metadata['salt'])
            return cipher.decrypt(salt[:12], encrypted, None)

        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305.value:
            cipher = ChaCha20Poly1305(key)
            salt = base64.b64decode(metadata['salt'])
            return cipher.decrypt(salt[:12], encrypted, None)

        else:
            raise ValueError(f"Unsupported encryption algorithm: {algorithm}")

    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")


def check_argon2_support():
    """
    Check if Argon2 is available and which variants are supported.

    Returns:
        tuple: (is_available, version, supported_types)
    """
    if not ARGON2_AVAILABLE:
        return False, None, []

    try:
        # Get version using importlib.metadata instead of direct attribute access
        try:
            import importlib.metadata
            version = importlib.metadata.version('argon2-cffi')
        except (ImportError, importlib.metadata.PackageNotFoundError):
            # Fall back to old method for older Python versions or if metadata not found
            import argon2
            version = getattr(argon2, '__version__', 'unknown')

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
            progress_thread.join(timeout=1.0)  # Set a timeout to prevent hanging
            # Clear the current line
            print(f"\r{' ' * 80}\r", end='', flush=True)
            print(f"{message} completed in {duration:.2f} seconds")

        return result
    except Exception as e:
        # Stop the progress thread in case of error
        stop_event.set()
        if not quiet:
            progress_thread.join(timeout=1.0)  # Set a timeout to prevent hanging
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
    # If hash_config is provided but doesn't specify type, use 'id' (Argon2id) as default
    if hash_config and 'type' in hash_config:
        # Strip 'argon2' prefix if present
        hash_config['type'] = hash_config['type'].replace('argon2', '')
    elif hash_config:
        hash_config['type'] = 'id'  # Default to Argon2id

    # Function to display progress for iterative hashing
    def show_progress(algorithm, current, total):
        if quiet:
            return

        # Update more frequently for better visual feedback
        update_frequency = max(1, min(total // 100, 100))  # Update at least every 100 iterations
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
            from modules.secure_memory import secure_buffer, secure_memcpy, secure_memzero

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
                            if ARGON2_AVAILABLE and isinstance(argon2_type,
                                                               int) and argon2_type in ARGON2_INT_TO_TYPE_MAP:
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


def generate_key(password, salt, hash_config, pbkdf2_iterations=100000, quiet=False, use_secure_mem=True,
                 algorithm=EncryptionAlgorithm.FERNET.value):
    """
    Generate an encryption key from a password using PBKDF2 or Argon2.

    Args:
        password (bytes): The password to derive the key from
        salt (bytes): Random salt for key derivation
        hash_config (dict): Configuration for hash algorithms including Argon2
        pbkdf2_iterations (int): Number of iterations for PBKDF2
        quiet (bool): Whether to suppress progress output
        use_secure_mem (bool): Whether to use secure memory
        algorithm (str): The encryption algorithm to be used

    Returns:
        tuple: (key, salt, hash_config)
    """
    # Determine required key length based on algorithm
    if algorithm == EncryptionAlgorithm.FERNET.value:
        key_length = 32  # Fernet requires 32 bytes that will be base64 encoded
    elif algorithm == EncryptionAlgorithm.AES_GCM.value:
        key_length = 32  # AES-256-GCM requires 32 bytes
    elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305.value:
        key_length = 32  # ChaCha20-Poly1305 requires 32 bytes
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Apply hash iterations if any are configured (SHA-256, SHA-512, SHA3-256, etc.)
    has_hash_iterations = hash_config and any(
        hash_config.get(algo, 0) > 0 for algo in
        ['sha256', 'sha512', 'sha3_256', 'sha3_512', 'whirlpool']
    ) or (hash_config and hash_config.get('scrypt', {}).get('n', 0) > 0)

    if has_hash_iterations:
        if not quiet:
            print("Applying hash iterations...")
        # Apply multiple hash algorithms in sequence
        hashed_password = multi_hash_password(password, salt, hash_config, quiet, use_secure_mem)
    else:
        # If no hash iterations are specified, use the original password
        hashed_password = password

    # Check if Argon2 is available on the system
    argon2_available = ARGON2_AVAILABLE

    # Determine if we should use Argon2
    # Only don't use Argon2 if it's explicitly disabled (enabled=False) in hash_config
    use_argon2 = argon2_available

    # If hash_config has argon2 section with enabled explicitly set to False, honor that
    if hash_config and 'argon2' in hash_config and 'enabled' in hash_config['argon2']:
        use_argon2 = hash_config['argon2']['enabled']

    if use_argon2:
        # Use Argon2 for key derivation
        if not quiet:
            print("Using Argon2 for key derivation...")

        # Get parameters from the argon2 section of hash_config, or use defaults
        argon2_config = hash_config.get('argon2', {}) if hash_config else {}
        time_cost = argon2_config.get('time_cost', 3)
        memory_cost = argon2_config.get('memory_cost', 65536)
        parallelism = argon2_config.get('parallelism', 4)
        hash_len = key_length
        type_int = argon2_config.get('type', 2)  # Default to ID (2)

        # Convert type integer to Argon2 type enum
        if type_int in ARGON2_INT_TO_TYPE_MAP:
            argon2_type = ARGON2_INT_TO_TYPE_MAP[type_int]
        else:
            # Default to Argon2id if type is not valid
            argon2_type = Type.ID

        try:
            key = argon2.low_level.hash_secret_raw(
                secret=hashed_password,  # Use the potentially hashed password
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=hash_len,
                type=argon2_type
            )

            # Update hash_config to reflect that Argon2 was used
            if hash_config is None:
                hash_config = {}
            if 'argon2' not in hash_config:
                hash_config['argon2'] = {}
            hash_config['argon2']['enabled'] = True
            hash_config['argon2']['time_cost'] = time_cost
            hash_config['argon2']['memory_cost'] = memory_cost
            hash_config['argon2']['parallelism'] = parallelism
            hash_config['argon2']['hash_len'] = hash_len
            hash_config['argon2']['type'] = type_int

        except Exception as e:
            if not quiet:
                print(f"Argon2 key derivation failed: {str(e)}. Falling back to PBKDF2.")
            # Fall back to PBKDF2 if Argon2 fails
            use_argon2 = False

    # Use PBKDF2 if Argon2 is not available or fails
    if not use_argon2:
        if not quiet:
            print(f"Using PBKDF2 with {pbkdf2_iterations} iterations...")

        # For Fernet, we need to base64 encode the key later
        if algorithm == EncryptionAlgorithm.FERNET.value:
            key = base64.urlsafe_b64encode(
                PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=key_length,
                    salt=salt,
                    iterations=pbkdf2_iterations,
                    backend=default_backend()
                ).derive(hashed_password)  # Use the potentially hashed password
            )
        else:
            # For other algorithms, return raw bytes
            key = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                iterations=pbkdf2_iterations,
                backend=default_backend()
            ).derive(hashed_password)  # Use the potentially hashed password

    return key, salt, hash_config



def encrypt_file(input_file, output_file, password, hash_config=None,
                 pbkdf2_iterations=100000, quiet=False, use_secure_mem=True,
                 algorithm=EncryptionAlgorithm.FERNET):
    """
    Encrypt a file with a password using the specified algorithm.

    Args:
        input_file (str): Path to the file to encrypt
        output_file (str): Path where to save the encrypted file
        password (bytes): The password to use for encryption
        hash_config (dict, optional): Hash configuration dictionary
        pbkdf2_iterations (int): Number of PBKDF2 iterations
        quiet (bool): Whether to suppress progress output
        use_secure_mem (bool): Whether to use secure memory handling
        algorithm (EncryptionAlgorithm): Encryption algorithm to use (default: Fernet)

    Returns:
        bool: True if encryption was successful
    """
    if isinstance(algorithm, str):
        algorithm = EncryptionAlgorithm(algorithm)

    # Generate a key from the password
    salt = os.urandom(16)  # Unique salt for each encryption

    if not quiet:
        print("\nGenerating encryption key...")
    algorithm_value = algorithm.value if isinstance(algorithm, EncryptionAlgorithm) else algorithm
    key, salt, hash_config = generate_key(
        password, salt, hash_config, pbkdf2_iterations, quiet, use_secure_mem, algorithm_value
    )

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
        print("Encrypting content with " + algorithm_value)

    # For large files, use progress bar for encryption
    def do_encrypt():
        if algorithm == EncryptionAlgorithm.FERNET:
            f = Fernet(key)
            return f.encrypt(data)
        else:
            # Generate a random nonce
            nonce = os.urandom(16)  # 16 bytes for AES-GCM and ChaCha20-Poly1305

            if algorithm == EncryptionAlgorithm.AES_GCM:
                cipher = AESGCM(key)
                return nonce + cipher.encrypt(nonce[:12], data, None)
            else:  # ChaCha20-Poly1305
                cipher = ChaCha20Poly1305(key)
                return nonce + cipher.encrypt(nonce[:12], data, None)

    # Only show progress for larger files (> 1MB)
    if len(data) > 1024 * 1024 and not quiet:
        encrypted_data = with_progress_bar(
            do_encrypt,
            "Encrypting data",
            quiet=quiet
        )
    else:
        encrypted_data = do_encrypt()

    # Calculate hash of encrypted data
    if not quiet:
        print("Calculating encrypted content hash...")

    encrypted_hash = calculate_hash(encrypted_data)

    # Create metadata with all necessary information
    metadata = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'hash_config': hash_config,
        'pbkdf2_iterations': pbkdf2_iterations,
        'original_hash': original_hash,
        'encrypted_hash': encrypted_hash,
        'algorithm': algorithm.value  # Add the encryption algorithm used
    }

    # Serialize and encode the metadata
    metadata_json = json.dumps(metadata).encode('utf-8')
    metadata_base64 = base64.b64encode(metadata_json)

    # Base64 encode the encrypted data
    encrypted_data = base64.b64encode(encrypted_data)

    # Write the metadata and encrypted data to the output file
    if not quiet:
        print(f"Writing encrypted file: {output_file}")

    with open(output_file, 'wb') as file:
        file.write(metadata_base64 + b':' + encrypted_data)

    # Set secure permissions on the output file
    set_secure_permissions(output_file)

    # Clean up
    key = None

    return True



def decrypt_file(input_file, output_file, password, quiet=False, use_secure_mem=True):
    """
    Decrypt a file with a password.

    Args:
        input_file (str): Path to the encrypted file
        output_file (str, optional): Path where to save the decrypted file. If None, returns decrypted data
        password (bytes): The password to use for decryption
        quiet (bool): Whether to suppress progress output
        use_secure_mem (bool): Whether to use secure memory handling

    Returns:
        Union[bool, bytes]: True if decryption was successful and output_file is specified,
                           or the decrypted data if output_file is None
    """
    # Read the encrypted file
    if not quiet:
        print(f"\nReading encrypted file: {input_file}")

    with open(input_file, 'rb') as file:
        file_content = file.read()

    # Split metadata and encrypted data
    try:
        metadata_b64, encrypted_data = file_content.split(b':', 1)
        metadata = json.loads(base64.b64decode(metadata_b64))
        encrypted_data = base64.b64decode(encrypted_data)
    except Exception as e:
        raise ValueError(f"Invalid file format: {str(e)}")

    # Extract necessary information from metadata
    salt = base64.b64decode(metadata['salt'])
    hash_config = metadata.get('hash_config')
    pbkdf2_iterations = metadata.get('pbkdf2_iterations', 100000)
    original_hash = metadata.get('original_hash')
    encrypted_hash = metadata.get('encrypted_hash')
    algorithm = metadata.get('algorithm',
                             EncryptionAlgorithm.FERNET.value)  # Default to Fernet for backward compatibility

    # Verify the hash of encrypted data
    if encrypted_hash:
        if not quiet:
            print("Verifying encrypted content integrity...")
        if calculate_hash(encrypted_data) != encrypted_hash:
            raise ValueError("Encrypted data has been tampered with")

    # Generate the key from the password and salt
    if not quiet:
        print("Generating decryption key...")

    key, _, _ = generate_key(
        password, salt, hash_config, pbkdf2_iterations, quiet, use_secure_mem, algorithm
    )

    # Decrypt the data
    if not quiet:
        print("Decrypting content with " + algorithm)

    def do_decrypt():
        if algorithm == EncryptionAlgorithm.FERNET.value:
            f = Fernet(key)
            return f.decrypt(encrypted_data)
        else:
            # First 16 bytes are the nonce
            nonce = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            if algorithm == EncryptionAlgorithm.AES_GCM.value:
                cipher = AESGCM(key)
                return cipher.decrypt(nonce[:12], ciphertext, None)
            elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305.value:
                cipher = ChaCha20Poly1305(key)
                return cipher.decrypt(nonce[:12], ciphertext, None)
            else:
                raise ValueError(f"Unsupported encryption algorithm: {algorithm}")

    # Only show progress for larger files (> 1MB)
    if len(encrypted_data) > 1024 * 1024 and not quiet:
        decrypted_data = with_progress_bar(
            do_decrypt,
            "Decrypting data",
            quiet=quiet
        )
    else:
        decrypted_data = do_decrypt()

    # Verify the hash of decrypted data
    if original_hash:
        if not quiet:
            print("Verifying decrypted content integrity...")
        if calculate_hash(decrypted_data) != original_hash:
            raise ValueError("Decryption failed: data integrity check failed")

    # If no output file is specified, return the decrypted data
    if output_file is None:
        return decrypted_data

    # Write the decrypted data to file
    if not quiet:
        print(f"Writing decrypted file: {output_file}")

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

    # Set secure permissions on the output file
    set_secure_permissions(output_file)

    # Clean up
    key = None

    return True


