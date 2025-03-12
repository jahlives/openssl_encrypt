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

DEBUG_MODE = True  # Set to True to enable detailed debugging
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


def decrypt_with_algorithm_debug(encrypted_data, key):
    """Debug version with extensive logging"""
    # Add the missing imports
    import base64

    print("\n=== DEBUG: decrypt_with_algorithm called ===")
    print(f"Encrypted data length: {len(encrypted_data)} bytes")
    print(f"Key length: {len(key)} bytes")

    # Show the first few bytes of encrypted data to help identify format
    preview = encrypted_data[:50]
    print(f"Data preview: {preview}")

    # Check if data contains a colon (algorithm separator)
    has_colon = b':' in encrypted_data
    print(f"Contains ':' separator: {has_colon}")

    # Attempt algorithm detection
    if has_colon:
        parts = encrypted_data.split(b':', 2)
        print(f"Split result: {len(parts)} parts")

        if len(parts) >= 2:
            try:
                algorithm = parts[0].decode('ascii')
                print(f"Detected algorithm: {algorithm}")

                if algorithm == 'fernet':
                    print("Attempting Fernet decryption...")
                    from cryptography.fernet import Fernet
                    f = Fernet(key)
                    result = f.decrypt(parts[1])
                    print(f"Fernet decryption successful! Result length: {len(result)} bytes")
                    return result

                elif algorithm == 'aes-gcm':
                    print("Attempting AES-GCM decryption...")
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                    if len(parts) != 3:
                        print(f"ERROR: Invalid AES-GCM format, expected 3 parts, got {len(parts)}")
                        raise ValueError("Invalid AES-GCM data format")

                    nonce = parts[1]
                    ciphertext = parts[2]
                    print(f"Nonce length: {len(nonce)} bytes")
                    print(f"Ciphertext length: {len(ciphertext)} bytes")

                    # Adjust key if needed
                    original_key_len = len(key)
                    if len(key) != 32:
                        key = key[:32] if len(key) > 32 else key.ljust(32, b'\0')
                        print(f"Adjusted key length from {original_key_len} to {len(key)} bytes")

                    # Create the cipher and decrypt
                    aesgcm = AESGCM(key)
                    result = aesgcm.decrypt(nonce, ciphertext, None)
                    print(f"AES-GCM decryption successful! Result length: {len(result)} bytes")
                    return result

                elif algorithm == 'chacha20-poly1305':
                    print("Attempting ChaCha20-Poly1305 decryption...")
                    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

                    if len(parts) != 3:
                        print(f"ERROR: Invalid ChaCha20-Poly1305 format, expected 3 parts, got {len(parts)}")
                        raise ValueError("Invalid ChaCha20-Poly1305 data format")

                    nonce = parts[1]
                    ciphertext = parts[2]
                    print(f"Nonce length: {len(nonce)} bytes")
                    print(f"Ciphertext length: {len(ciphertext)} bytes")

                    # Adjust key if needed
                    original_key_len = len(key)
                    if len(key) != 32:
                        key = key[:32] if len(key) > 32 else key.ljust(32, b'\0')
                        print(f"Adjusted key length from {original_key_len} to {len(key)} bytes")

                    # Create the cipher and decrypt
                    chacha = ChaCha20Poly1305(key)
                    result = chacha.decrypt(nonce, ciphertext, None)
                    print(f"ChaCha20-Poly1305 decryption successful! Result length: {len(result)} bytes")
                    return result

                else:
                    print(f"ERROR: Unknown algorithm '{algorithm}'")

            except Exception as e:
                print(f"ERROR in algorithm-specific decryption: {str(e)}")
                print("Falling back to legacy Fernet decryption...")

    # Legacy format or fallback
    print("Attempting legacy Fernet decryption...")
    try:
        from cryptography.fernet import Fernet
        f = Fernet(key)
        result = f.decrypt(encrypted_data)
        print(f"Legacy Fernet decryption successful! Result length: {len(result)} bytes")
        return result
    except Exception as e:
        print(f"ERROR in legacy Fernet decryption: {str(e)}")
        raise ValueError(f"All decryption methods failed: {e}")


def decrypt_file_debug(input_file, output_file, password, quiet=False, use_secure_mem=True):
    """Debug version with extensive logging"""
    import json
    import base64
    print("\n======= DEBUG: decrypt_file_debug called =======")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print(f"Password length: {len(password)} bytes")
    print(f"Secure memory: {use_secure_mem}")

    try:
        # Read the encrypted file
        print(f"Reading encrypted file: {input_file}")

        try:
            with open(input_file, 'rb') as file:
                content = file.read()
            print(f"Successfully read {len(content)} bytes from file")
        except Exception as read_err:
            print(f"ERROR reading file: {str(read_err)}")
            raise

        # Check for metadata format
        has_metadata = b':' in content
        print(f"File contains metadata separator: {has_metadata}")

        if not has_metadata:
            print("File doesn't contain standard metadata format. Attempting legacy decryption.")
            # Try direct decryption without metadata
            try:
                import hashlib
                import base64

                print("Generating key for legacy decryption...")
                key = base64.urlsafe_b64encode(hashlib.sha256(password).digest())
                print(f"Generated key length: {len(key)} bytes")

                decrypted_data = decrypt_with_algorithm_debug(content, key)

                # Write or return the decrypted data
                if output_file:
                    print(f"Writing decrypted data to: {output_file}")
                    with open(output_file, 'wb') as f:
                        f.write(decrypted_data)
                    print(f"Successfully wrote {len(decrypted_data)} bytes")
                    return True
                else:
                    print("No output file specified, returning decrypted data")
                    return decrypted_data

            except Exception as legacy_err:
                print(f"ERROR in legacy decryption: {str(legacy_err)}")
                raise

        # Extract the metadata and encrypted data
        parts = content.split(b':', 1)
        if len(parts) != 2:
            print(f"ERROR: Expected 2 parts after splitting, but got {len(parts)}")
            raise ValueError("Invalid file format")

        metadata_base64, encrypted_data = parts
        print(f"Metadata length: {len(metadata_base64)} bytes")
        print(f"Encrypted data length: {len(encrypted_data)} bytes")

        # Decode the metadata
        try:
            print("Decoding metadata...")
            metadata_json = base64.b64decode(metadata_base64)
            metadata = json.loads(metadata_json.decode('utf-8'))

            # Extract parameters
            print("Extracting parameters from metadata...")
            salt = base64.b64decode(metadata['salt'])
            hash_config = metadata.get('hash_config', {})
            pbkdf2_iterations = metadata.get('pbkdf2_iterations', 100000)
            original_hash = metadata.get('original_hash')
            encryption_algorithm = metadata.get('encryption_algorithm', 'fernet')

            print(f"Salt length: {len(salt)} bytes")
            print(f"PBKDF2 iterations: {pbkdf2_iterations}")
            print(f"Encryption algorithm: {encryption_algorithm}")
            print(f"Original hash present: {original_hash is not None}")

            # Print hash config summary
            print("Hash configuration:")
            for algo, value in hash_config.items():
                if isinstance(value, dict):
                    print(f"  {algo}: {json.dumps(value)}")
                else:
                    print(f"  {algo}: {value}")

        except Exception as metadata_err:
            print(f"ERROR parsing metadata: {str(metadata_err)}")
            raise ValueError(f"Error parsing file metadata: {metadata_err}")

        # Generate the key
        print("\nGenerating decryption key...")
        try:
            key, _, _ = generate_key(password, salt, hash_config, pbkdf2_iterations, quiet, use_secure_mem)
            print(f"Key generation successful, key length: {len(key)} bytes")
        except Exception as key_err:
            print(f"ERROR generating key: {str(key_err)}")
            raise

        # Decrypt the data
        print("\nDecrypting data...")
        try:
            decrypted_data = decrypt_with_algorithm_debug(encrypted_data, key)
            print(f"Decryption successful! Data length: {len(decrypted_data)} bytes")
        except Exception as decrypt_err:
            print(f"ERROR during decryption: {str(decrypt_err)}")
            raise

        # Verify hash if available
        if original_hash:
            print("\nVerifying content integrity...")
            decrypted_hash = calculate_hash(decrypted_data)

            print(f"Original hash: {original_hash}")
            print(f"Computed hash: {decrypted_hash}")

            if decrypted_hash != original_hash:
                print("ERROR: Hash verification failed!")
                raise ValueError("Content integrity check failed - hash mismatch")
            else:
                print("Hash verification successful!")

        # Write output or return the data
        if output_file:
            print(f"\nWriting decrypted data to: {output_file}")
            with open(output_file, 'wb') as file:
                file.write(decrypted_data)
            print(f"Successfully wrote {len(decrypted_data)} bytes")

            try:
                print("Setting secure permissions on output file")
                set_secure_permissions(output_file)
            except Exception as perm_err:
                print(f"WARNING: Could not set permissions: {str(perm_err)}")

            return True
        else:
            print("\nNo output file specified, returning decrypted data")
            print(f"First 100 bytes preview: {decrypted_data[:100]}")
            return decrypted_data

    except Exception as e:
        error_message = f"Decryption failed: {str(e)}"
        print(f"\nCRITICAL ERROR: {error_message}")

        # Print full exception traceback for debugging
        import traceback
        print("\nTraceback:")
        traceback.print_exc()

        raise ValueError(error_message)


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
                    print("RAW")
                    print(len(hashed))

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


def generate_key(password, salt=None, hash_config=None, pbkdf2_iterations=0, quiet=False, use_secure_mem=True):
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
    print(len(hashed_password))

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
            #key = base64.urlsafe_b64encode(derived_key)
            key = hashed_password
            return key

    # Only show progress for larger iteration counts
    if pbkdf2_iterations > 10000 and not quiet:
        derived_key = with_progress_bar(
            do_pbkdf2,
            "PBKDF2 processing",
            quiet=quiet
        )
    else:
        if pbkdf2_iterations > 0:
            derived_key = do_pbkdf2()
            return derived_key, salt, hash_config
        print(len(base64.b64decode(hashed_password)))
        derived_key = hashed_password

    return derived_key, salt, hash_config


def encrypt_with_algorithm(data, key, algorithm='fernet'):
    """
    Encrypt data using the specified algorithm.

    Args:
        data (bytes): Data to encrypt
        key (bytes): Key derived from password (must be appropriate length for algorithm)
        algorithm (str): Algorithm to use ('fernet', 'aes-gcm', or 'chacha20-poly1305')

    Returns:
        bytes: Encrypted data including necessary metadata
    """
    if algorithm == 'fernet':
        # Use original Fernet implementation
        from cryptography.fernet import Fernet
        f = Fernet(key)
        return b'fernet:' + f.encrypt(data)

    elif algorithm == 'aes-gcm':
        # AES-GCM implementation
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        # For AES-GCM, we need a 256-bit key (32 bytes)
        print(len(base64.b64decode(key)))
        if len(key) != 32:
            # Use the first 32 bytes or pad if needed
            key = key[:32] if len(key) > 32 else key.ljust(32, b'\0')

        # Generate a random 96-bit (12-byte) nonce/IV
        nonce = os.urandom(12)

        # Create the cipher and encrypt
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)  # No associated data

        # Return format: algorithm:nonce:ciphertext
        return b'aes-gcm:' + nonce + b':' + ciphertext

    elif algorithm == 'chacha20-poly1305':
        # ChaCha20-Poly1305 implementation
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        # For ChaCha20-Poly1305, we need a 256-bit key (32 bytes)
        if len(key) != 32:
            # Use the first 32 bytes or pad if needed
            key = key[:32] if len(key) > 32 else key.ljust(32, b'\0')

        # Generate a random 96-bit (12-byte) nonce
        nonce = os.urandom(12)

        # Create the cipher and encrypt
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, data, None)  # No associated data

        # Return format: algorithm:nonce:ciphertext
        return b'chacha20-poly1305:' + nonce + b':' + ciphertext

    else:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm}")


def decrypt_with_algorithm(encrypted_data, key):
    """
    Decrypt data using the appropriate algorithm.
    This version focuses on maximum compatibility with older formats.

    Args:
        encrypted_data (bytes): Encrypted data
        key (bytes): Key derived from password

    Returns:
        bytes: Decrypted data
    """
    # First, try the simplest approach: straight Fernet decryption
    # This handles legacy files that don't have any algorithm prefix
    try:
        from cryptography.fernet import Fernet
        f = Fernet(key)
        return f.decrypt(encrypted_data)
    except Exception as e:
        # If simple Fernet fails, try parsing for algorithm info
        pass

    # Now try with algorithm prefix parsing
    if b':' in encrypted_data:
        parts = encrypted_data.split(b':', 2)
        try:
            if len(parts) >= 2:
                algorithm = parts[1].decode('ascii')
                print(len(parts))
                print(f"algo " + algorithm)
                if algorithm == 'fernet':
                    from cryptography.fernet import Fernet
                    f = Fernet(key)
                    return f.decrypt(parts[2])

                elif algorithm == 'aes-gcm' and len(parts) == 3:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    metadata = json.loads(base64.b64decode(parts[0]))
                    nonce, ciphertext = metadata['salt'], parts[2]
                    try:
                        print("Hello World")
                        print(f"salt " + metadata['salt'])
                        print(b"key " + key)
                        print(b"encrypted " + parts[2])
                        print(f"nonce " + nonce)
                    except Exception as e:
                        print(e)

                    # Ensure key is the right size (32 bytes)
                    #if len(key) != 32:
                    #    print("Keylength")
                    #    key = key[:32] if len(key) > 32 else key.ljust(32, b'\0')
                    print(b"key " + key)
                    print(len(key))
                    try:
                        aesgcm = AESGCM(key)
                        return aesgcm.decrypt(nonce, ciphertext, None)
                    except Exception as e:
                        print(e)

                elif algorithm == 'chacha20-poly1305' and len(parts) == 3:
                    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
                    nonce, ciphertext = parts[1], parts[2]

                    # Ensure key is the right size (32 bytes)
                    if len(key) != 32:
                        key = key[:32] if len(key) > 32 else key.ljust(32, b'\0')

                    chacha = ChaCha20Poly1305(key)
                    return chacha.decrypt(nonce, ciphertext, None)
        except Exception as e:
            # If algorithm-specific decryption fails, continue to next approach
            pass

    # Final fallback: try forced approaches with specific algorithms
    # Try AES-GCM as last resort
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        # Ensure key is the right size (32 bytes)
        key_32 = key[:32] if len(key) > 32 else key.ljust(32, b'\0')

        # Assume the first 12 bytes might be a nonce
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(key_32)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        pass

    # Try ChaCha20-Poly1305 as last resort
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        # Ensure key is the right size (32 bytes)
        key_32 = key[:32] if len(key) > 32 else key.ljust(32, b'\0')

        # Assume the first 12 bytes might be a nonce
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        chacha = ChaCha20Poly1305(key_32)
        return chacha.decrypt(nonce, ciphertext, None)
    except Exception:
        pass

    # If all else fails, raise an error
    raise ValueError("Failed to decrypt with any algorithm")


def encrypt_file(input_file, output_file, password, hash_config=None,
                 pbkdf2_iterations=100000, quiet=False, use_secure_mem=True,
                 encryption_algorithm='fernet'):
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
        encryption_algorithm (str): Algorithm to use ('fernet', 'aes-gcm', or 'chacha20-poly1305')

    Returns:
        bool: True if encryption was successful
    """
    # Generate a key from the password
    salt = os.urandom(16)  # Unique salt for each encryption

    if not quiet:
        print(f"\nGenerating encryption key using {encryption_algorithm}...")

    key, salt, hash_config = generate_key(
        password, salt, hash_config, pbkdf2_iterations, quiet, use_secure_mem
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

    # Encrypt the data with selected algorithm
    if not quiet:
        print(f"Encrypting content with {encryption_algorithm}...")

    # For large files, use progress bar for encryption
    def do_encrypt():
        return encrypt_with_algorithm(data, key, encryption_algorithm)

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

    # Create metadata with the salt, hash configuration, and both hashes
    metadata = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'hash_config': hash_config,
        'pbkdf2_iterations': pbkdf2_iterations,
        'original_hash': original_hash,
        'encrypted_hash': encrypted_hash,  # Add hash of encrypted data
        'encryption_algorithm': encryption_algorithm  # Add the algorithm used
    }

    # Serialize and encode the metadata
    metadata_json = json.dumps(metadata).encode('utf-8')
    metadata_base64 = base64.b64encode(metadata_json)

    # Write the metadata and encrypted data to the output file
    if not quiet:
        print(f"Writing encrypted file: {output_file}")

    with open(output_file, 'wb') as file:
        file.write(metadata_base64 + b':' + str.encode(encryption_algorithm) + b":" + base64.b64encode(encrypted_data))

    # Set secure permissions on the output file
    set_secure_permissions(output_file)

    # Clean up
    key = None

    return True


def decrypt_file(input_file, output_file, password, quiet=False, use_secure_mem=True):
    """
    Decrypt a file with a password, automatically detecting the encryption algorithm.

    Args:
        input_file (str): Path to the encrypted file
        output_file (str): Path where to save the decrypted file, or None to return data
        password (bytes): The password to use for decryption
        quiet (bool): Whether to suppress status messages
        use_secure_mem (bool): Whether to use secure memory handling

    Returns:
        bytes or bool: If output_file is None, returns the decrypted data, otherwise returns True
    """
    try:
        # Read the encrypted file
        if not quiet:
            print(f"\nReading encrypted file: {input_file}")

        with open(input_file, 'rb') as file:
            content = file.read()

        # Extract the metadata and encrypted data
        parts = content.split(b':', 2)
        if len(parts) != 3:
            if not quiet:
                print("Warning: File doesn't contain standard metadata format. Attempting legacy decryption.")
            # Try direct decryption for legacy files
            try:
                key = base64.urlsafe_b64encode(hashlib.sha256(password).digest())
                decrypted_data = decrypt_with_algorithm(content, key)

                # Write or return the decrypted data
                if output_file:
                    with open(output_file, 'wb') as f:
                        f.write(decrypted_data)
                    if not quiet:
                        print(f"File decrypted successfully: {output_file}")
                    return True
                else:
                    return decrypted_data
            except Exception as e:
                raise ValueError(f"Legacy decryption failed: {e}")

        metadata_base64, algorithm, data = parts

        # Decode the metadata
        try:
            metadata_json = base64.b64decode(metadata_base64)
            metadata = json.loads(metadata_json.decode('utf-8'))
            print(metadata)
            # Extract parameters from metadata
            salt = base64.b64decode(metadata['salt'])
            hash_config = metadata['hash_config']
            pbkdf2_iterations = metadata.get('pbkdf2_iterations', 100000)
            original_hash = metadata.get('original_hash')
            encrypted_hash = metadata.get('encrypted_hash')

            # Get the encryption algorithm if present, default to fernet
            encryption_algorithm = metadata.get('encryption_algorithm', 'fernet')

            if not quiet:
                print(f"Metadata extracted successfully (algorithm: {encryption_algorithm})")

        except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
            raise ValueError(f"Error parsing file metadata: {e}")

        # Generate the key using the same parameters
        if not quiet:
            print("Generating decryption key...")

        try:
            key, _, _ = generate_key(password, salt, hash_config, pbkdf2_iterations, quiet, use_secure_mem)
        except Exception as key_gen_err:
            raise ValueError(f"Key generation failed: {key_gen_err}")

        # Decrypt the data using the appropriate algorithm
        try:
            if not quiet:
                print(f"Decrypting content using {encryption_algorithm}...")
            #print (parts[0] + b":" + parts[1] +b":" + base64.b64encode(parts[2]))
            encrypted_data = parts[0] + b":" + parts[1] +b":" + parts[2]
            decrypted_data = decrypt_with_algorithm(encrypted_data, key)

        except Exception as decrypt_err:
            # Explicitly mention password failure
            raise ValueError(f"Decryption failed: {decrypt_err}. Invalid password or corrupted file.")

        # Verify hash if it was stored in metadata
        if original_hash:
            if not quiet:
                print("Verifying decrypted content integrity...")

            decrypted_hash = calculate_hash(decrypted_data)
            if decrypted_hash != original_hash:
                raise ValueError("Decryption failed. Content integrity check failed - hash mismatch.")
            elif not quiet:
                print("\n✓ Decrypted content integrity verified successfully")

        # Write the decrypted data to the output file or return it
        if output_file:
            if not quiet:
                print(f"Writing decrypted file: {output_file}")

            with open(output_file, 'wb') as file:
                file.write(decrypted_data)

            # By default, set secure permissions on the output file
            set_secure_permissions(output_file)

            return True
        else:
            return decrypted_data

    except Exception as e:
        # Ensure the error includes a clear reference to password or decryption failure
        error_message = f"Decryption failed: {str(e)}"

        if not quiet:
            print(f"\nERROR: {error_message}")

        raise ValueError(error_message)
