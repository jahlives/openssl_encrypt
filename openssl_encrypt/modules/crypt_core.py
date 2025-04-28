#!/usr/bin/env python3
"""
Secure File Encryption Tool - Core Module

This module provides the core functionality for secure file encryption, decryption,
and secure deletion. It contains the cryptographic operations and key derivation
functions that power the encryption tool.
"""

import base64
import hashlib
import json
import math
import os
import random
import secrets
import stat
import sys
import threading
import time
from enum import Enum
from functools import wraps

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESSIV
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    SCRYPT_AVAILABLE = True
except ImportError:
    SCRYPT_AVAILABLE = False

from .secure_memory import (
    SecureBytes,
    secure_memzero
)

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

try:
    from .balloon import balloon_m
    BALLOON_AVAILABLE = True
except ImportError:
    BALLOON_AVAILABLE = False


class EncryptionAlgorithm(Enum):
    FERNET = "fernet"
    AES_GCM = "aes-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    AES_SIV = "aes-siv"
    CAMELLIA = "camellia"


class KeyStretch:
    key_stretch = False
    hash_stretch = False
    kind_action = 'encrypt'


class CamelliaCipher:
    def __init__(self, key):
        self.key = SecureBytes(key)

    def encrypt(self, nonce, data, associated_data=None):
        cipher = Cipher(algorithms.Camellia(bytes(self.key)), modes.CBC(nonce))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.Camellia.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        result = encryptor.update(padded_data) + encryptor.finalize()
        secure_memzero(padded_data)  # Clear the padded data from memory
        return result

    def decrypt(self, nonce, data, associated_data=None):
        cipher = Cipher(algorithms.Camellia(bytes(self.key)), modes.CBC(nonce))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.Camellia.block_size).unpadder()
        result = unpadder.update(padded_data) + unpadder.finalize()
        secure_memzero(padded_data)  # Clear the padded data from memory
        return result


def string_entropy(password: str) -> float:
    """
    Calculate password entropy in bits.
    Higher entropy = more random = stronger password.
    """
    # Count character frequencies
    password = str(password)
    char_amount = 0
    char_sets = [False, False, False, False]
    char_nums = [26, 26, 10, 32]
    for i in password:
        if i.islower():
            char_sets[0] = True
        if i.isupper():
            char_sets[1] = True
        if i.isdigit():
            char_sets[2] = True
        if not i.isalnum() and i.isascii():
            char_sets[3] = True

    for x in range(4):
        if char_sets[x]:
            char_amount += char_nums[x]
    return math.log2(char_amount) * len(set(password))


def add_timing_jitter(func):
    """
    Adds random timing jitter to function execution to help prevent timing attacks.

    Args:
        func: The function to wrap with timing jitter
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Add random delay between 1 and 10 milliseconds
        jitter = random.uniform(0.001, 0.01)
        time.sleep(jitter)

        result = func(*args, **kwargs)

        # Add another random delay after execution
        jitter = random.uniform(0.001, 0.01)
        time.sleep(jitter)

        return result

    return wrapper


def check_argon2_support():
    """
    Check if Argon2 is available and which variants are supported.

    Returns:
        tuple: (is_available, version, supported_types)
    """
    if not ARGON2_AVAILABLE:
        return False, None, []

    try:
        # Get version using importlib.metadata instead of direct attribute
        # access
        try:
            import importlib.metadata
            version = importlib.metadata.version('argon2-cffi')
        except (ImportError, importlib.metadata.PackageNotFoundError):
            # Fall back to old method for older Python versions or if metadata
            # not found
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
            # Set a timeout to prevent hanging
            progress_thread.join(timeout=1.0)
            # Clear the current line
            print(f"\r{' ' * 80}\r", end='', flush=True)
            print(f"{message} completed in {duration:.2f} seconds")

        return result
    except Exception as e:
        # Stop the progress thread in case of error
        stop_event.set()
        if not quiet:
            # Set a timeout to prevent hanging
            progress_thread.join(timeout=1.0)
            # Clear the current line
            print(f"\r{' ' * 80}\r", end='', flush=True)
        raise e


@add_timing_jitter
def multi_hash_password(
        password,
        salt,
        hash_config,
        quiet=False,
        progress=False):
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
        progress (bool): Whether to use progress bar for progress output

    Returns:
        bytes: The hashed password
    """
    # If hash_config is provided but doesn't specify type, use 'id' (Argon2id)
    # as default
    if hash_config and 'type' in hash_config:
        # Strip 'argon2' prefix if present
        hash_config['type'] = hash_config['type'].replace('argon2', '')
    elif hash_config:
        hash_config['type'] = 'id'  # Default to Argon2id

    # Function to display progress for iterative hashing
    def show_progress(algorithm, current, total):
        if quiet:
            return
        if not progress:
            return

        # Update more frequently for better visual feedback
        # Update at least every 100 iterations
        update_frequency = max(1, min(total // 100, 100))
        if current % update_frequency != 0 and current != total:
            return

        percent = (current / total) * 100
        bar_length = 30
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + ' ' * (bar_length - filled_length)

        print(f"\r{algorithm} hashing: [{bar}] {percent:.1f}% ({current}/{total})",end='',flush=True)

        if current == total:
            print()  # New line after completion

    stretch_hash = False
    try:
        from .secure_memory import secure_buffer, secure_memcpy, secure_memzero
        # Use secure memory approach
        with secure_buffer(len(password) + len(salt), zero=False) as hashed:
            # Initialize the secure buffer with password + salt
            secure_memcpy(hashed, password + salt)

            # Apply each hash algorithm in sequence (only if iterations >
            # 0)
            for algorithm, params in hash_config.items():
                if algorithm == 'sha512' and params > 0:
                    if not quiet and not progress:
                        print(f"Applying {params} rounds of SHA-512", end= " ")
                    elif not quiet:
                        print(f"Applying {params} rounds of SHA-512")

                    # SHA-512 produces 64 bytes
                    with secure_buffer(64, zero=False) as hash_buffer:
                        for i in range(params):
                            result = hashlib.sha512(hashed).digest()
                            secure_memcpy(hash_buffer, result)
                            secure_memcpy(hashed, hash_buffer)
                            show_progress("SHA-512", i + 1, params)
                            KeyStretch.hash_stretch = True
                        if not quiet and not progress:
                            print("✅")

                elif algorithm == 'sha256' and params > 0:
                    if not quiet and not progress:
                        print(f"Applying {params} rounds of SHA-256", end=" ")
                    elif not quiet:
                        print(f"Applying {params} rounds of SHA-256")

                    # SHA-256 produces 32 bytes
                    with secure_buffer(32, zero=False) as hash_buffer:
                        for i in range(params):
                            result = hashlib.sha256(hashed).digest()
                            secure_memcpy(hash_buffer, result)
                            secure_memcpy(hashed, hash_buffer)
                            show_progress("SHA-256", i + 1, params)
                            KeyStretch.hash_stretch = True
                        if not quiet and not progress:
                            print("✅")

                elif algorithm == 'sha3_256' and params > 0:
                    if not quiet and not progress:
                        print(f"Applying {params} rounds of SHA3-256", end=" ")
                    elif not quiet:
                        print(f"Applying {params} rounds of SHA3-256")
                    # SHA3-256 produces 32 bytes
                    with secure_buffer(32, zero=False) as hash_buffer:
                        for i in range(params):
                            result = hashlib.sha3_256(hashed).digest()
                            secure_memcpy(hash_buffer, result)
                            secure_memcpy(hashed, hash_buffer)
                            show_progress("SHA3-256", i + 1, params)
                            KeyStretch.hash_stretch = True
                        if not quiet and not progress:
                            print("✅")

                elif algorithm == 'sha3_512' and params > 0:
                    if not quiet and not progress:
                        print(f"Applying {params} rounds of SHA3-512", end=" ")
                    elif not quiet:
                        print(f"Applying {params} rounds of SHA3-512")
                    # SHA3-512 produces 64 bytes
                    with secure_buffer(64, zero=False) as hash_buffer:
                        for i in range(params):
                            result = hashlib.sha3_512(hashed).digest()
                            secure_memcpy(hash_buffer, result)
                            secure_memcpy(hashed, hash_buffer)
                            show_progress("SHA3-512", i + 1, params)
                            KeyStretch.hash_stretch = True
                        if not quiet and not progress:
                            print("✅")

                elif algorithm == 'whirlpool' and params > 0:
                    if not quiet and WHIRLPOOL_AVAILABLE and not progress:
                        print(f"Applying {params} rounds of Whirlpool", end=" ")
                    elif not quiet and not WHIRLPOOL_AVAILABLE:
                        print(f"Applying {params} rounds of Whirlpool")

                    if WHIRLPOOL_AVAILABLE:
                        # Whirlpool produces 64 bytes
                        with secure_buffer(64, zero=False) as hash_buffer:
                            for i in range(params):
                                result = pywhirlpool.whirlpool(
                                    bytes(hashed)).digest()
                                secure_memcpy(hash_buffer, result)
                                secure_memcpy(hashed, hash_buffer)
                                show_progress("Whirlpool", i + 1, params)
                                KeyStretch.hash_stretch = True
                            if not quiet and not progress:
                                print("✅")
                    else:
                        # Fall back to SHA-512 if Whirlpool is not
                        # available
                        if not quiet and not progress:
                            print(
                                "Warning: Whirlpool not available, using SHA-512 instead", end=" ")
                        elif not quiet:
                            print(
                                "Warning: Whirlpool not available, using SHA-512 instead"
                            )
                        with secure_buffer(64, zero=False) as hash_buffer:
                            for i in range(params):
                                result = hashlib.sha512(hashed).digest()
                                secure_memcpy(hash_buffer, result)
                                secure_memcpy(hashed, hash_buffer)
                                show_progress(
                                    "SHA-512 (fallback)", i + 1, params)
                                KeyStretch.hash_stretch = True
                            if not quiet and not progress:
                                print("✅")
            result = SecureBytes.copy_from(hashed)
        return result
    except ImportError:
        # Fall back to standard method if secure_memory is not available
        if not quiet:
            print("Warning: secure_memory module not available")
        sys.exit(1)
    finally:
        if 'hashed' in locals():
            secure_memzero(hashed)


@add_timing_jitter
def generate_key(
        password,
        salt,
        hash_config,
        pbkdf2_iterations=100000,
        quiet=False,
        algorithm=EncryptionAlgorithm.FERNET.value,
        progress=False):
    """
    Generate an encryption key from a password using PBKDF2 or Argon2.

    Args:
        password (bytes): The password to derive the key from
        salt (bytes): Random salt for key derivation
        hash_config (dict): Configuration for hash algorithms including Argon2
        pbkdf2_iterations (int): Number of iterations for PBKDF2
        quiet (bool): Whether to suppress progress output
        progress (bool): Whether to use progress bar for progress output
        algorithm (str): The encryption algorithm to be used

    Returns:
        tuple: (key, salt, hash_config)
    """

    def show_progress(algorithm, current, total):
        if quiet:
            return
        if not progress:
            return

        # Update more frequently for better visual feedback
        # Update at least every 100 iterations
        update_frequency = max(1, min(total // 100, 100))
        if current % update_frequency != 0 and current != total:
            return

        percent = (current / total) * 100
        bar_length = 30
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + ' ' * (bar_length - filled_length)

        print(f"\r{algorithm} hashing: [{bar}] {percent:.1f}% ({current}/{total})", end='', flush=True)

        if current == total:
            print()  # New line after completion

    # Determine required key length based on algorithm
    if algorithm == EncryptionAlgorithm.FERNET.value:
        key_length = 32  # Fernet requires 32 bytes that will be base64 encoded
    elif algorithm == EncryptionAlgorithm.AES_GCM.value:
        key_length = 32  # AES-256-GCM requires 32 bytes
    elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305.value:
        key_length = 32  # ChaCha20-Poly1305 requires 32 bytes
    elif algorithm == EncryptionAlgorithm.AES_SIV.value:
        key_length = 64
    elif algorithm == EncryptionAlgorithm.CAMELLIA.value:
        key_length = 32
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Apply hash iterations if any are configured (SHA-256, SHA-512, SHA3-256,
    # etc.)
    has_hash_iterations = hash_config and any(
        hash_config.get(algo, 0) > 0 for algo in
        ['sha256', 'sha512', 'sha3_256', 'sha3_512', 'whirlpool']
    ) or (hash_config and hash_config.get('scrypt', {}).get('n', 0) > 0)

    if has_hash_iterations:
        if not quiet and not progress:
            print("Applying hash iterations", end=" ")
        elif not quiet:
            print("Applying hash iterations")
        # Apply multiple hash algorithms in sequence
        password = multi_hash_password(
            password, salt, hash_config, quiet, progress=progress)
    # Check if Argon2 is available on the system
    argon2_available = ARGON2_AVAILABLE

    # Determine if we should use Argon2
    # Only don't use Argon2 if it's explicitly disabled (enabled=False) in
    # hash_config
    use_argon2 = hash_config.get('argon2', {}).get('enabled', False)
    use_scrypt = hash_config.get('scrypt', {}).get('enabled', False)
    use_pbkdf2 = hash_config.get('pbkdf2', {}).get('pbkdf2-iterations', 0)
    use_balloon = hash_config.get('balloon', {}).get('enabled', False)

    # If hash_config has argon2 section with enabled explicitly set to False, honor that
    # if hash_config and 'argon2' in hash_config and 'enabled' in hash_config['argon2']:
    #    use_argon2 = hash_config['argon2']['enabled']
    if use_argon2 and ARGON2_AVAILABLE:
        derived_salt = salt
        # Use Argon2 for key derivation
        if not quiet and not progress:
            print("Using Argon2 for key derivation", end=" ")
        elif not quiet:
            print("Using Argon2 for key derivation")

        # Get parameters from the argon2 section of hash_config, or use
        # defaults
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

        if hasattr(password, 'to_bytes'):
            password = bytes(password)
        else:
            password = bytes(password)

        try:
            for i in range(hash_config.get('argon2', {}).get('rounds', 1)):
                derived_salt = derived_salt + str(i).encode()
                password = argon2.low_level.hash_secret_raw(
                    secret=password,  # Use the potentially hashed password
                    salt=derived_salt,
                    time_cost=time_cost,
                    memory_cost=memory_cost,
                    parallelism=parallelism,
                    hash_len=hash_len,
                    type=argon2_type
                )
                KeyStretch.key_stretch = True
                derived_salt = password[:16]
                show_progress(
                    "Argon2",
                    i + 1,
                    hash_config.get(
                        'argon2',
                        {}).get(
                        'rounds',
                        1))
            secure_memzero(derived_salt)
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
            if not quiet and not progress:
                print("✅")
        except Exception as e:
            if not quiet:
                print(f"Argon2 key derivation failed: {str(e)}. Falling back to PBKDF2.")
            # Fall back to PBKDF2 if Argon2 fails
            use_argon2 = False

    if use_balloon and BALLOON_AVAILABLE:
        derived_salt = salt
        if not quiet and not progress:
            print("Using Balloon-Hashing for key derivation", end=" ")
        elif not quiet:
            print("Using Balloon-Hashing for key derivation")
        balloon_config = hash_config.get('balloon', {}) if hash_config else {}
        time_cost = balloon_config.get('time_cost', 3)
        space_cost = balloon_config.get(
            'space_cost', 65536)  # renamed from memory_cost
        parallelism = balloon_config.get('parallelism', 4)
        hash_len = key_length

        try:
            for i in range(hash_config.get('balloon', {}).get('rounds', 1)):
                derived_salt = derived_salt + str(i).encode()
                password = balloon_m(
                    password=password,  # Use the potentially hashed password
                    salt=str(derived_salt),
                    time_cost=time_cost,
                    space_cost=space_cost,  # renamed from memory_cost
                    parallel_cost=parallelism
                )
                KeyStretch.key_stretch = True
                derived_salt = password[:16]
                show_progress(
                    "Balloon",
                    i + 1,
                    hash_config.get(
                        'balloon',
                        {}).get(
                        'rounds',
                        1))

            secure_memzero(derived_salt)

            # Update hash_config
            if hash_config is None:
                hash_config = {}
            if 'balloon' not in hash_config:
                hash_config['balloon'] = {}
            hash_config['balloon'].update({
                'enabled': True,
                'time_cost': time_cost,
                'space_cost': space_cost,  # renamed from memory_cost
                'parallelism': parallelism,
                'hash_len': hash_len
            })
            if not quiet and not progress:
                print("✅")
        except Exception as e:
            if not quiet:
                print(f"Balloon key derivation failed: {str(e)}. Falling back to PBKDF2.")
            use_balloon = False  # Consider falling back to PBKDF2

    if use_scrypt and SCRYPT_AVAILABLE:

        derived_salt = salt
        if not quiet and not progress:
            print("Using Scrypt for key derivation", end=" ")
        elif not quiet:
            print("Using Scrypt for key derivation")
        try:
            for i in range(hash_config.get('scrypt', {}).get('rounds', 1)):
                derived_salt = derived_salt + str(i).encode()
                scrypt_kdf = Scrypt(
                    salt=derived_salt,
                    length=32,
                    n=hash_config['scrypt']['n'],  # CPU/memory cost factor
                    r=hash_config['scrypt']['r'],  # Block size factor
                    p=hash_config['scrypt']['p'],  # Parallelization factor
                    backend=default_backend()
                )
                KeyStretch.key_stretch = True
                password = scrypt_kdf.derive(password)
                derived_salt = password[:16]
                show_progress(
                    "Scrypt",
                    i + 1,
                    hash_config.get(
                        'scrypt',
                        {}).get(
                        'rounds',
                        1))
 #           hashed_password = derived_key
            if not quiet and not progress:
                print("✅")
        except Exception as e:
            if not quiet:
                print(f"Scrypt key derivation failed: {str(e)}. Falling back to PBKDF2.")
            use_scrypt = False  # Consider falling back to PBKDF2

    if os.environ.get('PYTEST_CURRENT_TEST') is not None and hash_config['pbkdf2_iterations'] is None:
        use_pbkdf2 = 100000
    elif hash_config['pbkdf2_iterations'] > 0:
        use_pbkdf2 = hash_config['pbkdf2_iterations']
    if use_pbkdf2 and use_pbkdf2 > 0:
        derived_salt = salt
        for i in range(use_pbkdf2):
            derived_salt = derived_salt + str(i).encode('utf-8')
            password = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=derived_salt,
                iterations=1,
                backend=default_backend()
            ).derive(password)  # Use the potentially hashed password
            derived_salt = password[:16]
            KeyStretch.key_stretch = True
            show_progress("PBKDF2", i + 1, use_pbkdf2)
    if not KeyStretch.hash_stretch and not KeyStretch.key_stretch and KeyStretch.kind_action == 'encrypt' and os.environ.get(
            'PYTEST_CURRENT_TEST') is None:
        if len(password) < 32:
            print(
                'ERROR: encryption without at least one hash and/or kdf is NOT recommended')
            print('ERROR: this would be a high security risk as "normal" passwords do not have enough entropy by far')
            print(
                'ERROR: this could only work if you provide a password with at least 32 characters and entropy of 80 bits or higher')
            print(
                f"ERROR: your current password only has {format(len(password))} characters ({len(set(password))} unique characters) and {string_entropy(password):.1f} bits of entropy")
            print(
                f"ERROR: if you insist on using too-weak password then set the environment variable PYTEST_CURRENT_TEST to a non-empty value")
            secure_memzero(password)
            sys.exit(1)
        elif string_entropy(password) < 80:
            print(
                'ERROR: encryption without at least one hash and/or kdf is NOT recommended')
            print('ERROR: this would be a high security risk as "normal" passwords do not have enough entropy by far')
            print(
                'ERROR: this could only work if you provide a password with at least 32 characters and 80 bits entropy')
            print(
                f"ERROR: your current password has {format(len(password))} characters ({len(set(password))} unique characters) and {string_entropy(password):.1f} bits of entropy")
            print(f"ERROR: if you insist on using too-weak password then set the environment variable PYTEST_CURRENT_TEST to a non-empty value")
            secure_memzero(password)
            sys.exit(1)
        else:
            print(
                'WARNING: You are about to use the password directly without any key strengthening.')
            print(
                'WARNING: This is only secure if your password has sufficient entropy (randomness).')
            print(
                f"WARNING: Your password is {str(len(password))} long ({len(set(password))} unique characters) and has {string_entropy(password):.1f} bits entropy.")
            print(
                'WARNING: you should still consider to stop here and use hash/kdf chaining')
            confirmation = input(
                'Are you sure you want to proceed? (y/n): ').strip().lower()
            if confirmation != 'y' and confirmation != 'yes':
                print('Operation cancelled by user.')
                secure_memzero(password)
                sys.exit(1)
            print('Proceeding with direct password usage...')
            #hashed_password = password
    if not KeyStretch.key_stretch and not KeyStretch.hash_stretch:
        if algorithm in [EncryptionAlgorithm.AES_GCM.value, EncryptionAlgorithm.CAMELLIA.value, EncryptionAlgorithm.CHACHA20_POLY1305.value]:
            password = hashlib.sha256(password).digest()
        elif algorithm == EncryptionAlgorithm.AES_SIV.value:
            password = hashlib.sha512(password).digest()
        else:
            password = base64.b64encode(hashlib.sha256(password).digest())
    elif algorithm == EncryptionAlgorithm.FERNET.value:
        password = base64.urlsafe_b64encode(password)
    try:
        return password, salt, hash_config
    finally:
        if KeyStretch.hash_stretch or KeyStretch.hash_stretch:
            secure_memzero(derived_salt)
        secure_memzero(password)
        secure_memzero(salt)


def encrypt_file(input_file, output_file, password, hash_config=None,
                 pbkdf2_iterations=100000, quiet=False,
                 algorithm=EncryptionAlgorithm.FERNET, progress=False, verbose=False):
    """
    Encrypt a file with a password using the specified algorithm.

    Args:
        input_file (str): Path to the file to encrypt
        output_file (str): Path where to save the encrypted file
        password (bytes): The password to use for encryption
        hash_config (dict, optional): Hash configuration dictionary
        pbkdf2_iterations (int): Number of PBKDF2 iterations
        quiet (bool): Whether to suppress progress output
        progress (bool): Whether to show progress bar
        verbose (bool): Whether to show verbose output
        algorithm (EncryptionAlgorithm): Encryption algorithm to use (default: Fernet)

    Returns:
        bool: True if encryption was successful
    """
    if isinstance(algorithm, str):
        algorithm = EncryptionAlgorithm(algorithm)
    # Generate a key from the password
    salt = secrets.token_bytes(16)  # Unique salt for each encryption
    if not quiet:
        print("\nGenerating encryption key...")
    algorithm_value = algorithm.value if isinstance(
        algorithm, EncryptionAlgorithm) else algorithm
    print_hash_config(
        hash_config,
        encryption_algo=algorithm_value,
        salt=salt,
        quiet=quiet,
        verbose=verbose
    )

    key, salt, hash_config = generate_key(
        password, salt, hash_config, pbkdf2_iterations, quiet, algorithm_value, progress=progress)
    # Read the input file
    if not quiet:
        print(f"Reading file: {input_file}")

    with open(input_file, 'rb') as file:
        data = file.read()

    # Calculate hash of original data for integrity verification
    if not quiet:
        print("Calculating content hash", end=" ")

    original_hash = calculate_hash(data)
    if not quiet:
        print("✅")

    # Encrypt the data
    if not quiet:
        print("Encrypting content with " + algorithm_value, end=" ")

    # For large files, use progress bar for encryption
    def do_encrypt():
        if algorithm == EncryptionAlgorithm.FERNET:
            f = Fernet(key)
            return f.encrypt(data)
        else:
            # Generate a random nonce
            # 16 bytes for AES-GCM and ChaCha20-Poly1305
            nonce = secrets.token_bytes(16)
            if algorithm == EncryptionAlgorithm.AES_GCM:
                cipher = AESGCM(key)
                return nonce + cipher.encrypt(nonce[:12], data, None)
            elif algorithm == EncryptionAlgorithm.AES_SIV:
                cipher = AESSIV(key)
                return nonce[:12] + cipher.encrypt(data, None)
            elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:  # ChaCha20-Poly1305
                cipher = ChaCha20Poly1305(key)
                return nonce + cipher.encrypt(nonce[:12], data, None)
            elif algorithm == EncryptionAlgorithm.CAMELLIA:
                cipher = CamelliaCipher(key)
                return nonce + cipher.encrypt(nonce, data, None)
            else:
                print(f"Unknown algorithm " + algorithm.value + f"supplied")
                return False

    # Only show progress for larger files (> 1MB)
    if len(data) > 1024 * 1024 and not quiet:
        encrypted_data = with_progress_bar(
            do_encrypt,
            "Encrypting data",
            quiet=quiet
        )
    else:
        encrypted_data = do_encrypt()
    if not quiet:
        print("✅")
    # Calculate hash of encrypted data
    if not quiet:
        print("Calculating encrypted content hash", end=" ")

    encrypted_hash = calculate_hash(encrypted_data)
    if not quiet:
        print("✅")

    # Create metadata with all necessary information
    metadata = {
        'format_version': 2,
        'salt': base64.b64encode(salt).decode('utf-8'),
        'hash_config': hash_config,
        'pbkdf2_iterations': pbkdf2_iterations,
        'original_hash': original_hash,
        'encrypted_hash': encrypted_hash,
        'algorithm': algorithm.value  # Add the encryption algorithm
    }
    # If scrypt is used, add rounds to hash_config
    # Serialize and encode the metadata
    metadata_json = json.dumps(metadata).encode('utf-8')
    metadata_base64 = base64.b64encode(metadata_json)

    # Base64 encode the encrypted data
    encrypted_data = base64.b64encode(encrypted_data)

    # Write the metadata and encrypted data to the output file
    if not quiet:
        print(f"Writing encrypted file: {output_file}", end=" ")

    with open(output_file, 'wb') as file:
        file.write(metadata_base64 + b':' + encrypted_data)

    # Set secure permissions on the output file
    set_secure_permissions(output_file)
    if not quiet:
        print("✅")

    # Clean up
    key = None
    try:
        return True
    finally:
        secure_memzero(key)
        secure_memzero(data)
        secure_memzero(encrypted_data)
        secure_memzero(encrypted_hash)

def decrypt_file(
        input_file,
        output_file,
        password,
        quiet=False,
        progress=False,
        verbose=False):
    """
    Decrypt a file with a password.

    Args:
        input_file (str): Path to the encrypted file
        output_file (str, optional): Path where to save the decrypted file. If None, returns decrypted data
        password (bytes): The password to use for decryption
        quiet (bool): Whether to suppress progress output
        progress (bool): Whether to show progress bar
        verbose (bool): Whether to show verbose output
    Returns:
        Union[bool, bytes]: True if decryption was successful and output_file is specified,
                           or the decrypted data if output_file is None
    """
    KeyStretch.kind_action = 'decrypt'
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
    format_version = metadata.get('format_version', 1)
    salt = base64.b64decode(metadata['salt'])
    hash_config = metadata.get('hash_config')
    if format_version == 1:
        pbkdf2_iterations = metadata.get('pbkdf2_iterations', 100000)
    elif format_version == 2:
        pbkdf2_iterations = 0
    else:
        raise ValueError(f"Unsupported file format version: {format_version}")
    original_hash = metadata['original_hash']
    encrypted_hash = metadata['encrypted_hash']
    algorithm = metadata['algorithm']
    original_hash = metadata.get('original_hash')
    encrypted_hash = metadata.get('encrypted_hash')
    # Default to Fernet for backward compatibility
    algorithm = metadata.get('algorithm', EncryptionAlgorithm.FERNET.value)

    print_hash_config(
        hash_config,
        encryption_algo=metadata.get('algorithm', 'fernet'),
        salt=metadata.get('salt'),
        quiet=quiet,
        verbose=verbose
    )

    # Verify the hash of encrypted data
    if encrypted_hash:
        if not quiet:
            print("Verifying encrypted content integrity", end=" ")
        if calculate_hash(encrypted_data) != encrypted_hash:
            print("❌")  # Red X symbol
            raise ValueError("Encrypted data has been tampered with")
        elif not quiet:
            print("✅")  # Green check symbol

    # Generate the key from the password and salt
    if not quiet:
        print("Generating decryption key ✅")  # Green check symbol)

    key, _, _ = generate_key(password, salt, hash_config,
                             pbkdf2_iterations, quiet, algorithm, progress=progress)
    # Decrypt the data
    if not quiet:
        print("Decrypting content with " + algorithm, end=" ")

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
            elif algorithm == EncryptionAlgorithm.AES_SIV.value:
                cipher = AESSIV(key)
                return cipher.decrypt(encrypted_data[12:], None)
            elif algorithm == EncryptionAlgorithm.CAMELLIA.value:
                cipher = CamelliaCipher(key)
                return cipher.decrypt(nonce, ciphertext, None)
            else:
                raise ValueError(
                    f"Unsupported encryption algorithm: {algorithm}")

    # Only show progress for larger files (> 1MB)
    if len(encrypted_data) > 1024 * 1024 and not quiet:
        decrypted_data = with_progress_bar(
            do_decrypt,
            "Decrypting data",
            quiet=quiet
        )
    else:
        decrypted_data = do_decrypt()

    if not quiet:
        print("✅")  # Green check symbol
    # Verify the hash of decrypted data
    if original_hash:
        if not quiet:
            print("Verifying decrypted content integrity", end=" ")
        if calculate_hash(decrypted_data) != original_hash:
            print("❌")  # Red X symbol
            raise ValueError("Decryption failed: data integrity check failed")
        elif not quiet:
            print("✅")  # Green check symbol

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
    try:
        return True
    finally:
        secure_memzero(key)
        secure_memzero(decrypted_data)
        secure_memzero(file_content)

def get_organized_hash_config(hash_config, encryption_algo=None, salt=None):
    organized_config = {
        'encryption': {
            'algorithm': encryption_algo,
            'salt': salt
        },
        'kdfs': {},
        'hashes': {}
    }

    # Define which algorithms are KDFs and which are hashes
    kdf_algorithms = ['scrypt', 'argon2', 'balloon', 'pbkdf2_iterations']
    hash_algorithms = ['sha3_512', 'sha3_256', 'sha512', 'sha256', 'whirlpool']

    # Organize the config
    for algo, params in hash_config.items():
        if algo in kdf_algorithms:
            if isinstance(params, dict):
                if params.get('enabled', False):
                    organized_config['kdfs'][algo] = params
            elif algo == 'pbkdf2_iterations' and params > 0:
                organized_config['kdfs'][algo] = params
        elif algo in hash_algorithms and params > 0:
            organized_config['hashes'][algo] = params

    return organized_config

def print_hash_config(
        hash_config,
        encryption_algo=None,
        salt=None,
        quiet=False,
        verbose=False):
    if quiet:
        return
    print("Secure memory handling: Enabled")
    organized = get_organized_hash_config(hash_config, encryption_algo, salt)

    if KeyStretch.kind_action == 'decrypt' and verbose:
        print("\nDecrypting with the following configuration:")
    elif verbose:
        print("\nEncrypting with the following configuration:")

    if verbose:
        # Print Hashes
        print("  Hash Functions:")
        if not organized['hashes']:
            print("    - No additional hashing algorithms used")
        else:
            for algo, iterations in organized['hashes'].items():
                print(f"    - {algo.upper()}: {iterations} iterations")
        # Print KDFs
        print("  Key Derivation Functions:")
        if not organized['kdfs']:
            print("    - No KDFs used")
        else:
            for algo, params in organized['kdfs'].items():
                if algo == 'scrypt':
                    print(
                        f"    - Scrypt: n={params['n']}, r={params['r']}, p={params['p']}")
                elif algo == 'argon2':
                    print(f"    - Argon2: time_cost={params['time_cost']}, "
                          f"memory_cost={params['memory_cost']}KB, "
                          f"parallelism={params['parallelism']}, "
                          f"hash_len={params['hash_len']}")
                elif algo == 'balloon':
                    print(f"    - Balloon: time_cost={params['time_cost']}, "
                          f"space_cost={params['space_cost']}, "
                          f"parallelism={params['parallelism']}, "
                          f"rounds={params['rounds']}")
                elif algo == 'pbkdf2_iterations':
                    print(f"    - PBKDF2: {params} iterations")
        print("  Encryption:")
        print(f"    - Algorithm: {encryption_algo or 'Not specified'}")
        salt_str = base64.b64encode(salt).decode(
            'utf-8') if isinstance(salt, bytes) else salt
        print(f"    - Salt: {salt_str or 'Not specified'}")
        print('')
