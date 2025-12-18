#!/usr/bin/env python3
"""
Mobile-optimized cryptographic core for OpenSSL Encrypt
Implements chained hash/KDF processing compatible with CLI desktop version
"""

import logging

# Suppress warnings at the very beginning, before any imports
import os
import sys
import warnings

warnings.filterwarnings("ignore")
logging.disable(logging.WARNING)
# Redirect stderr to suppress hashlib errors during import
if hasattr(sys.stderr, "write"):
    original_stderr = sys.stderr
    sys.stderr = open(os.devnull, "w")
    try:
        import hashlib
    finally:
        sys.stderr.close()
        sys.stderr = original_stderr
else:
    import hashlib

import base64
import json
from typing import Any, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    AESGCMSIV,
    AESOCB3,
    AESSIV,
    ChaCha20Poly1305,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Try to import optional KDFs
try:
    from argon2 import PasswordHasher
    from argon2.low_level import Type, hash_secret_raw

    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

try:
    from openssl_encrypt.modules.balloon import balloon_m

    BALLOON_AVAILABLE = True
except ImportError:
    BALLOON_AVAILABLE = False

try:
    import blake3

    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False

try:
    import whirlpool

    WHIRLPOOL_AVAILABLE = True
except ImportError:
    try:
        import pywhirlpool as whirlpool

        WHIRLPOOL_AVAILABLE = True
    except ImportError:
        WHIRLPOOL_AVAILABLE = False

try:
    import nacl.secret
    import nacl.utils

    XCHACHA20_AVAILABLE = True
except ImportError:
    XCHACHA20_AVAILABLE = False


# CLI-Compatible XChaCha20Poly1305 class (imported from CLI crypt_core.py)
class XChaCha20Poly1305:
    """CLI-compatible XChaCha20Poly1305 implementation"""

    def __init__(self, key):
        # Validate key before use
        if key is None:
            raise ValueError("Key cannot be None")

        # Validate key length (should be 32 bytes for ChaCha20-Poly1305)
        try:
            key_length = len(key)
            if key_length != 32:
                raise ValueError(
                    f"Invalid key length: {key_length}. XChaCha20Poly1305 requires a 32-byte key"
                )

            self.key = key
            self.cipher = ChaCha20Poly1305(key)
        except Exception as e:
            # Convert any other errors to validation errors
            raise ValueError("Invalid key material") from e

    def _process_nonce(self, nonce):
        """
        Process and validate nonce to ensure proper length and format.
        The cryptography library's ChaCha20Poly1305 expects 12-byte nonces,
        while XChaCha20Poly1305 is designed for 24-byte nonces.

        We use the HChaCha20 construction to derive a ChaCha20 key and nonce
        from the XChaCha20 nonce, following the XChaCha20 specification.

        Args:
            nonce (bytes): Input nonce

        Returns:
            bytes: Properly formatted 12-byte nonce for use with the ChaCha20Poly1305 library

        Raises:
            ValueError: If nonce validation fails
        """
        # Validate nonce
        if nonce is None:
            raise ValueError("Nonce cannot be None")

        # Ensure nonce is bytes
        if not isinstance(nonce, (bytes, bytearray, memoryview)):
            raise ValueError(f"Nonce must be bytes-like object, got {type(nonce).__name__}")

        # Check if nonce is empty
        if len(nonce) == 0:
            raise ValueError("Nonce cannot be empty")

        # Process based on length
        if len(nonce) == 24:
            # For XChaCha20Poly1305, use a proper derivation algorithm
            # The 24-byte nonce is split into a 16-byte nonce and an 8-byte block counter
            # First, use the HChaCha20 function to mix the key with the first 16 bytes
            # Since we don't have direct access to HChaCha20, we'll use HKDF
            # to derive a secure 12-byte nonce from the original 24-byte nonce

            # Use the first 16 bytes of the nonce as the HKDF salt (mimicking HChaCha20 input)
            # and the remaining 8 bytes as the info parameter to ensure uniqueness
            hkdf = HKDF(
                algorithm=hashes.SHA256(),  # Use SHA256 which is universally available
                length=12,  # We need 12 bytes for ChaCha20Poly1305
                salt=nonce[:16],
                info=nonce[16:],
                backend=default_backend(),
            )

            # Use the original key as input key material
            truncated_nonce = hkdf.derive(self.key)
        elif len(nonce) == 12:
            # Already correct size for ChaCha20Poly1305
            truncated_nonce = nonce
        else:
            # For any other size, use a strong deterministic process to create a 12-byte nonce
            # Use HKDF with SHA256 for better security than simple truncation

            # Use the nonce as the info parameter to ensure uniqueness
            hkdf = HKDF(
                algorithm=hashes.SHA256(),  # Use SHA256 which is universally available
                length=12,  # We need 12 bytes for ChaCha20Poly1305
                salt=None,
                info=nonce,
                backend=default_backend(),
            )

            # Use the original key as input key material
            truncated_nonce = hkdf.derive(self.key)

        # Final validation of the processed nonce
        if len(truncated_nonce) != 12:
            raise ValueError(f"Failed to generate 12-byte nonce, got {len(truncated_nonce)} bytes")

        return truncated_nonce

    def encrypt(self, nonce, data, associated_data=None):
        """
        Encrypt data using XChaCha20Poly1305.

        Args:
            nonce (bytes): Nonce for encryption (ideally 24 bytes for XChaCha20Poly1305)
            data (bytes): Data to encrypt
            associated_data (bytes, optional): Associated data for AEAD

        Returns:
            bytes: Encrypted data
        """
        # Validate inputs
        if data is None:
            raise ValueError("Data cannot be None")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValueError(f"Data must be bytes-like object, got {type(data).__name__}")

        truncated_nonce = self._process_nonce(nonce)

        # Process associated data
        if associated_data is not None and not isinstance(
            associated_data, (bytes, bytearray, memoryview)
        ):
            raise ValueError(
                f"Associated data must be bytes-like object, got {type(associated_data).__name__}"
            )

        # Encrypt using the underlying cipher
        return self.cipher.encrypt(truncated_nonce, data, associated_data)

    def decrypt(self, nonce, data, associated_data=None):
        """
        Decrypt data using XChaCha20Poly1305.

        Args:
            nonce (bytes): Nonce used for encryption (ideally 24 bytes for XChaCha20Poly1305)
            data (bytes): Data to decrypt
            associated_data (bytes, optional): Associated data for AEAD

        Returns:
            bytes: Decrypted data
        """
        # Validate inputs
        if data is None:
            raise ValueError("Data cannot be None")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValueError(f"Data must be bytes-like object, got {type(data).__name__}")

        truncated_nonce = self._process_nonce(nonce)

        # Process associated data
        if associated_data is not None and not isinstance(
            associated_data, (bytes, bytearray, memoryview)
        ):
            raise ValueError(
                f"Associated data must be bytes-like object, got {type(associated_data).__name__}"
            )

        # Minimum ciphertext size check (AEAD tag is at least 16 bytes)
        if len(data) < 16:
            raise ValueError("Ciphertext too short - missing authentication tag")

        # Decrypt using the underlying cipher
        return self.cipher.decrypt(truncated_nonce, data, associated_data)


class MobileCryptoCore:
    """Mobile-optimized cryptographic operations"""

    def __init__(self):
        self.supported_algorithms = [
            "fernet",  # AES-128-CBC + HMAC, proven security
            "aes-gcm",  # AES-256-GCM, AEAD encryption
            "aes-gcm-siv",  # AES-256-GCM-SIV, AEAD encryption with nonce misuse resistance
            "aes-ocb3",  # AES-256-OCB3, AEAD encryption with parallelizability
            "aes-siv",  # AES-256-SIV, nonce-misuse resistant AEAD
            "chacha20-poly1305",  # ChaCha20-Poly1305, AEAD encryption
            "xchacha20-poly1305",  # XChaCha20-Poly1305, AEAD encryption (requires PyNaCl)
        ]

        # Hash algorithms matching CLI order: SHA-512, SHA-256, SHA3-256, SHA3-512, BLAKE2b, BLAKE3, SHAKE-256, Whirlpool
        self.hash_algorithms = {
            "sha512": hashes.SHA512,
            "sha256": hashes.SHA256,
            "sha3_256": hashes.SHA3_256,
            "sha3_512": hashes.SHA3_512,
            "blake2b": lambda: hashes.BLAKE2b(64),  # 64 bytes = 512 bits
            "blake3": "blake3",  # Special handling
            "shake256": "shake256",  # Special handling
            "whirlpool": "whirlpool",  # Special handling
        }

        # Default hash chain configuration matching CLI
        self.default_hash_config = {
            "sha512": 1000,
            "sha256": 1000,
            "sha3_256": 1000,
            "sha3_512": 1000,
            "blake2b": 1000,
            "blake3": 1000,
            "shake256": 1000,
            "whirlpool": 1000,
        }

        # KDF algorithms with CLI-compatible chaining support
        self.kdf_algorithms = {
            "pbkdf2": {"name": "PBKDF2"},
            "scrypt": {"name": "Scrypt"},
            "argon2": {"name": "Argon2"},
            "hkdf": {"name": "HKDF"},
            "balloon": {"name": "Balloon"},
        }

        # Default KDF chain configuration (CLI order)
        self.default_kdf_config = {
            "pbkdf2": {"enabled": True, "rounds": 100000},
            "scrypt": {"enabled": False, "n": 16384, "r": 8, "p": 1, "rounds": 1},
            "argon2": {
                "enabled": False,
                "memory_cost": 65536,
                "time_cost": 3,
                "parallelism": 1,
                "rounds": 1,
            },
            "hkdf": {"enabled": False, "info": "OpenSSL_Encrypt_Mobile"},
            "balloon": {"enabled": False, "space_cost": 8, "time_cost": 1},
        }

        # CLI-compatible default parameters (used when mobile doesn't specify)
        self.cli_kdf_defaults = {
            "pbkdf2": {"rounds": 100000},
            "scrypt": {"n": 16384, "r": 8, "p": 1, "rounds": 1},
            "argon2": {"memory_cost": 65536, "time_cost": 3, "parallelism": 1, "rounds": 1},
            "hkdf": {"info": "OpenSSL_Encrypt_Mobile"},
            "balloon": {"space_cost": 8, "time_cost": 1},
        }

    def clean_hash_config(self, hash_config: Dict[str, any]) -> Dict[str, int]:
        """Clean hash config to remove non-integer fields (CLI compatibility)"""
        if hash_config is None:
            return self.default_hash_config.copy()

        VALID_HASH_ALGORITHMS = [
            "sha512",
            "sha256",
            "sha3_256",
            "sha3_512",
            "blake2b",
            "blake3",
            "shake256",
            "whirlpool",
        ]

        clean_config = {}
        for key, value in hash_config.items():
            if key in VALID_HASH_ALGORITHMS and isinstance(value, int):
                clean_config[key] = value
            # Skip invalid fields like 'type': 'id'

        # Fill in missing algorithms with 0
        for algo in VALID_HASH_ALGORITHMS:
            if algo not in clean_config:
                clean_config[algo] = 0

        return clean_config

    def multi_hash_password(
        self, password: bytes, salt: bytes, hash_config: Dict[str, int] = None
    ) -> bytes:
        """
        Apply multiple rounds of different hash algorithms to a password.
        Implements the exact same chaining order as the CLI desktop version.

        Hash order: SHA-512, SHA-256, SHA3-256, SHA3-512, BLAKE2b, BLAKE3, SHAKE-256, Whirlpool
        """
        # Clean hash config to handle CLI data contamination
        clean_config = self.clean_hash_config(hash_config)

        # CLI COMPATIBILITY: Always start with password + salt (like CLI does)
        # This matches CLI multi_hash_password behavior exactly
        hashed = password + salt

        # Apply each hash algorithm in CLI order (only if iterations > 0)
        for algorithm, params in clean_config.items():
            if params <= 0:
                continue

            if algorithm == "sha512":
                for i in range(params):
                    hashed = hashlib.sha512(hashed).digest()[:20]  # CLI truncates to 20 bytes

            elif algorithm == "sha256":
                for i in range(params):
                    hashed = hashlib.sha256(hashed).digest()[:20]  # CLI truncates to 20 bytes

            elif algorithm == "sha3_256":
                for i in range(params):
                    hashed = hashlib.sha3_256(hashed).digest()[:20]  # CLI truncates to 20 bytes

            elif algorithm == "sha3_512":
                for i in range(params):
                    hashed = hashlib.sha3_512(hashed).digest()[:20]  # CLI truncates to 20 bytes

            elif algorithm == "blake2b":
                for i in range(params):
                    # Use salt for key to enhance security (CLI behavior)
                    key_material = hashlib.sha256(salt + str(i).encode()).digest()
                    digest = hashlib.blake2b(hashed, key=key_material[:32], digest_size=64).digest()
                    hashed = digest[:20]  # CLI truncates to 20 bytes

            elif algorithm == "blake3" and BLAKE3_AVAILABLE:
                for i in range(params):
                    key_material = hashlib.sha256(salt + str(i).encode()).digest()
                    hasher = blake3.blake3(key=key_material[:32])
                    hasher.update(hashed)
                    digest = hasher.digest(64)  # Get 64 bytes for consistency
                    hashed = digest[:20]  # CLI truncates to 20 bytes
            elif algorithm == "blake3" and not BLAKE3_AVAILABLE:
                # Fallback to BLAKE2b (CLI behavior)
                for i in range(params):
                    key_material = hashlib.sha256(salt + str(i).encode()).digest()
                    digest = hashlib.blake2b(hashed, key=key_material[:32], digest_size=64).digest()
                    hashed = digest[:20]  # CLI truncates to 20 bytes

            elif algorithm == "shake256":
                for i in range(params):
                    # Each round combines the current hash with a round-specific salt (CLI behavior)
                    round_material = hashlib.sha256(salt + str(i).encode()).digest()
                    shake = hashlib.shake_256()
                    shake.update(hashed + round_material)
                    digest = shake.digest(64)  # Get 64 bytes
                    hashed = digest[:20]  # CLI truncates to 20 bytes

            elif algorithm == "whirlpool" and WHIRLPOOL_AVAILABLE:
                for i in range(params):
                    try:
                        if hasattr(whirlpool, "new"):
                            digest = whirlpool.new(hashed).digest()
                        elif hasattr(whirlpool, "whirlpool"):
                            digest = whirlpool.whirlpool(hashed).digest()
                        else:
                            raise ImportError("No whirlpool method available")
                        hashed = digest[:20]  # CLI truncates to 20 bytes
                    except Exception:
                        # Fall back to SHA-512 (CLI behavior)
                        hashed = hashlib.sha512(hashed).digest()[:20]  # CLI truncates to 20 bytes
            elif algorithm == "whirlpool" and not WHIRLPOOL_AVAILABLE:
                # Fall back to SHA-512 (CLI behavior)
                for i in range(params):
                    hashed = hashlib.sha512(hashed).digest()[:20]  # CLI truncates to 20 bytes

        return hashed

    def multi_kdf_derive_with_algorithm(
        self, password: bytes, salt: bytes, kdf_config: Dict[str, Any] = None, algorithm: str = None
    ) -> bytes:
        """
        Apply multiple KDFs in sequence (CLI compatible) with algorithm-specific key lengths
        CLI KDF order: Argon2 → Balloon → Scrypt → HKDF → PBKDF2
        """
        if kdf_config is None:
            kdf_config = self.default_kdf_config.copy()

        derived_password = password
        base_salt = salt

        # Determine key length based on algorithm (matching CLI)
        key_length = 32  # Default for most algorithms
        if algorithm == "aes-siv":
            key_length = 64  # AES-SIV needs 64 bytes (double key)

        # Apply KDFs in CLI order: Argon2 → Balloon → Scrypt → HKDF → PBKDF2

        # 1. Argon2 (if enabled)
        if (
            "argon2" in kdf_config
            and kdf_config["argon2"].get("enabled", False)
            and ARGON2_AVAILABLE
        ):
            argon2_params = kdf_config["argon2"]
            memory_cost = argon2_params.get("memory_cost", 65536)
            time_cost = argon2_params.get("time_cost", 3)
            parallelism = argon2_params.get("parallelism", 1)
            rounds = argon2_params.get("rounds", 1)
            # Use CLI-provided type parameter, but override hash_len for algorithm-specific length
            argon2_type = argon2_params.get("type", 2)  # Default to Type.ID (2)

            for i in range(rounds):
                if i == 0:
                    round_salt = base_salt
                else:
                    salt_material = hashlib.sha256(base_salt + str(i).encode()).digest()
                    round_salt = salt_material[:16]

                hash_result = hash_secret_raw(
                    derived_password,
                    round_salt,
                    time_cost=time_cost,
                    memory_cost=memory_cost,
                    parallelism=parallelism,
                    hash_len=key_length,  # Use algorithm-specific length
                    type=Type(argon2_type),
                )
                derived_password = hash_result

        # 2. Balloon (if enabled)
        if (
            "balloon" in kdf_config
            and kdf_config["balloon"].get("enabled", False)
            and BALLOON_AVAILABLE
        ):
            balloon_params = kdf_config["balloon"]
            space_cost = balloon_params.get("space_cost", 8)
            time_cost = balloon_params.get("time_cost", 1)
            # Handle CLI parameter naming differences
            parallel_cost = balloon_params.get(
                "parallelism", balloon_params.get("parallel_cost", 1)
            )

            # Use Balloon KDF with CLI-compatible parameter format
            balloon_result = balloon_m(
                password=derived_password,  # Pass bytes directly (CLI compatible)
                salt=str(base_salt),  # Convert bytes to string repr (CLI compatible)
                space_cost=space_cost,
                time_cost=time_cost,
                parallel_cost=parallel_cost,  # Use CLI parameter
                delta=3,  # Default delta value
            )

            # Ensure we get exactly the right number of bytes for key derivation chain
            if len(balloon_result) >= key_length:
                derived_password = balloon_result[:key_length]
            else:
                # If balloon returns less than needed, pad with PBKDF2
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=key_length - len(balloon_result),
                    salt=base_salt,
                    iterations=1000,
                    backend=default_backend(),
                )
                padding = kdf.derive(derived_password)
                derived_password = balloon_result + padding[: key_length - len(balloon_result)]

        # 3. Scrypt (if enabled)
        if "scrypt" in kdf_config and kdf_config["scrypt"].get("enabled", False):
            scrypt_params = kdf_config["scrypt"]
            n = scrypt_params.get("n", 16384)
            r = scrypt_params.get("r", 8)
            p = scrypt_params.get("p", 1)
            rounds = scrypt_params.get("rounds", 1)

            for i in range(rounds):
                # Generate unique salt for each round (CLI behavior)
                if i == 0:
                    round_salt = base_salt
                else:
                    salt_material = hashlib.sha256(base_salt + str(i).encode()).digest()
                    round_salt = salt_material[:16]

                kdf = Scrypt(
                    salt=round_salt,
                    length=key_length,  # Use algorithm-specific length
                    n=n,
                    r=r,
                    p=p,
                    backend=default_backend(),
                )
                derived_password = kdf.derive(derived_password)

        # 4. HKDF (if enabled)
        if "hkdf" in kdf_config and kdf_config["hkdf"].get("enabled", False):
            hkdf_params = kdf_config["hkdf"]
            info = hkdf_params.get("info", "OpenSSL_Encrypt_Mobile")
            if isinstance(info, str):
                info = info.encode()
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=key_length,  # Use algorithm-specific length
                salt=base_salt,
                info=info,
                backend=default_backend(),
            )
            derived_password = kdf.derive(derived_password)

        # 5. PBKDF2 (always check if configured with rounds > 0)
        if "pbkdf2" in kdf_config and kdf_config["pbkdf2"].get("rounds", 0) > 0:
            pbkdf2_params = kdf_config["pbkdf2"]
            rounds = pbkdf2_params.get("rounds", 100000)

            # CRITICAL CLI COMPATIBILITY: CLI applies PBKDF2 as separate calls with 1 iteration each
            # Salt pattern: SHA256(base_salt + str(round_index)) where round_index is 0-based
            for i in range(rounds):
                # Generate salt using CLI pattern: SHA256(base_salt + str(i))
                salt_material = hashlib.sha256(base_salt + str(i).encode()).digest()
                round_salt = salt_material  # Use full 32 bytes

                # Apply PBKDF2 with 1 iteration per round using algorithm-specific key length
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=key_length,  # Use algorithm-specific length (32 for XChaCha20, 64 for AES-SIV)
                    salt=round_salt,
                    iterations=1,  # CLI uses 1 iteration per call
                    backend=default_backend(),
                )
                derived_password = kdf.derive(derived_password)

        return derived_password

    def multi_kdf_derive(
        self, password: bytes, salt: bytes, kdf_config: Dict[str, Any] = None
    ) -> bytes:
        """
        Apply multiple KDFs in sequence (CLI compatible)
        CLI KDF order: Argon2 → Balloon → Scrypt → HKDF → PBKDF2
        """
        if kdf_config is None:
            kdf_config = self.default_kdf_config.copy()

        derived_password = password
        base_salt = salt

        # Apply KDFs in CLI order: Argon2 → Balloon → Scrypt → HKDF → PBKDF2

        # 1. Argon2 (if enabled)
        if (
            "argon2" in kdf_config
            and kdf_config["argon2"].get("enabled", False)
            and ARGON2_AVAILABLE
        ):
            argon2_params = kdf_config["argon2"]
            memory_cost = argon2_params.get("memory_cost", 65536)
            time_cost = argon2_params.get("time_cost", 3)
            parallelism = argon2_params.get("parallelism", 1)
            rounds = argon2_params.get("rounds", 1)
            # Use CLI-provided hash_len and type parameters
            hash_len = argon2_params.get("hash_len", 32)
            argon2_type = argon2_params.get("type", 2)  # Default to Type.ID (2)

            for i in range(rounds):
                if i == 0:
                    round_salt = base_salt
                else:
                    salt_material = hashlib.sha256(base_salt + str(i).encode()).digest()
                    round_salt = salt_material[:16]

                hash_result = hash_secret_raw(
                    derived_password,
                    round_salt,
                    time_cost=time_cost,
                    memory_cost=memory_cost,
                    parallelism=parallelism,
                    hash_len=hash_len,
                    type=Type(argon2_type),
                )
                derived_password = hash_result

        # 2. Balloon (if enabled)
        if (
            "balloon" in kdf_config
            and kdf_config["balloon"].get("enabled", False)
            and BALLOON_AVAILABLE
        ):
            balloon_params = kdf_config["balloon"]
            space_cost = balloon_params.get("space_cost", 8)
            time_cost = balloon_params.get("time_cost", 1)
            # Handle CLI parameter naming differences
            parallel_cost = balloon_params.get(
                "parallelism", balloon_params.get("parallel_cost", 1)
            )

            # Use Balloon KDF with CLI-compatible parameter format
            # CLI passes password as bytes (handled by hash_func internally)
            # and salt as string (converted from bytes via str())

            # Use balloon_m with CLI-compatible parameters
            balloon_result = balloon_m(
                password=derived_password,  # Pass bytes directly (CLI compatible)
                salt=str(base_salt),  # Convert bytes to string repr (CLI compatible)
                space_cost=space_cost,
                time_cost=time_cost,
                parallel_cost=parallel_cost,  # Use CLI parameter
                delta=3,  # Default delta value
            )

            # Ensure we get exactly 32 bytes for key derivation chain
            if len(balloon_result) >= 32:
                derived_password = balloon_result[:32]
            else:
                # If balloon returns less than 32 bytes, pad with PBKDF2
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32 - len(balloon_result),
                    salt=base_salt,
                    iterations=1000,
                    backend=default_backend(),
                )
                padding = kdf.derive(derived_password)
                derived_password = balloon_result + padding[: 32 - len(balloon_result)]

        # 3. Scrypt (if enabled)
        if "scrypt" in kdf_config and kdf_config["scrypt"].get("enabled", False):
            scrypt_params = kdf_config["scrypt"]
            n = scrypt_params.get("n", 16384)
            r = scrypt_params.get("r", 8)
            p = scrypt_params.get("p", 1)
            rounds = scrypt_params.get("rounds", 1)

            for i in range(rounds):
                # Generate unique salt for each round (CLI behavior)
                if i == 0:
                    round_salt = base_salt
                else:
                    salt_material = hashlib.sha256(base_salt + str(i).encode()).digest()
                    round_salt = salt_material[:16]

                kdf = Scrypt(salt=round_salt, length=32, n=n, r=r, p=p, backend=default_backend())
                derived_password = kdf.derive(derived_password)

        # 4. HKDF (if enabled)
        if "hkdf" in kdf_config and kdf_config["hkdf"].get("enabled", False):
            hkdf_params = kdf_config["hkdf"]
            info = hkdf_params.get("info", "OpenSSL_Encrypt_Mobile")
            if isinstance(info, str):
                info = info.encode()
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=base_salt,
                info=info,
                backend=default_backend(),
            )
            derived_password = kdf.derive(derived_password)

        # 5. PBKDF2 (always check if configured with rounds > 0)
        if "pbkdf2" in kdf_config and kdf_config["pbkdf2"].get("rounds", 0) > 0:
            pbkdf2_params = kdf_config["pbkdf2"]
            rounds = pbkdf2_params.get("rounds", 100000)

            # CRITICAL CLI COMPATIBILITY: CLI applies PBKDF2 as separate calls with 1 iteration each
            # Salt pattern: SHA256(base_salt + str(round_index)) where round_index is 0-based
            for i in range(rounds):
                # Generate salt using CLI pattern: SHA256(base_salt + str(i))
                salt_material = hashlib.sha256(base_salt + str(i).encode()).digest()
                round_salt = salt_material  # Use full 32 bytes

                # CRITICAL FIX: CLI uses key_length based on algorithm (32 for XChaCha20/AES)
                # Mobile was using fixed 32, but needs to match CLI's algorithm-specific key_length
                key_length = 32  # XChaCha20, AES, ChaCha20 all need 32 bytes
                if hasattr(self, "_current_algorithm"):
                    if self._current_algorithm == "aes-siv":
                        key_length = 64  # AES-SIV needs 64 bytes (double key)

                # Apply PBKDF2 with 1 iteration per round
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=key_length,  # Use algorithm-appropriate length
                    salt=round_salt,
                    iterations=1,  # CLI uses 1 iteration per call
                    backend=default_backend(),
                )
                derived_password = kdf.derive(derived_password)

        return derived_password

    def _derive_key_with_algorithm(
        self,
        password: str,
        salt: bytes,
        hash_config: Dict[str, int] = None,
        kdf_config: Dict[str, Any] = None,
        algorithm: str = None,
    ) -> bytes:
        """
        Derive encryption key using chained hashes and chained KDFs (CLI-compatible) with algorithm-specific key lengths
        1. Apply multi-hash password chaining
        2. Apply multi-KDF chaining to the hashed result
        """
        password_bytes = password.encode()

        # Step 1: Apply hash chaining (CLI order)
        hashed_password = self.multi_hash_password(password_bytes, salt, hash_config)

        # Step 2: Apply chained KDFs to the hashed password with algorithm-specific lengths
        derived_key = self.multi_kdf_derive_with_algorithm(
            hashed_password, salt, kdf_config, algorithm
        )

        # For Fernet, return base64 encoded. For others, return raw bytes
        if algorithm == "fernet":
            return base64.urlsafe_b64encode(derived_key)
        else:
            return derived_key

    def _derive_key(
        self,
        password: str,
        salt: bytes,
        hash_config: Dict[str, int] = None,
        kdf_config: Dict[str, Any] = None,
    ) -> bytes:
        """
        Derive encryption key using chained hashes and chained KDFs (CLI-compatible)
        1. Apply multi-hash password chaining
        2. Apply multi-KDF chaining to the hashed result
        """
        password_bytes = password.encode()

        # Step 1: Apply hash chaining (CLI order)
        hashed_password = self.multi_hash_password(password_bytes, salt, hash_config)

        # Step 2: Apply chained KDFs to the hashed password
        derived_key = self.multi_kdf_derive(hashed_password, salt, kdf_config)

        return base64.urlsafe_b64encode(derived_key)

    def encrypt_data(
        self,
        data: bytes,
        password: str,
        algorithm: str = "fernet",
        hash_config: Dict[str, int] = None,
        kdf_config: Dict[str, Any] = None,
        progress_callback=None,
    ) -> Dict[str, Any]:
        """
        Encrypt data using specified algorithm with chained hash/KDF (CLI-compatible)
        Returns dict with encrypted data and metadata

        Supported algorithms:
        - fernet: AES-128-CBC + HMAC (default)
        - aes-gcm: AES-256-GCM (AEAD)
        """
        try:
            # Validate algorithm
            if algorithm not in self.supported_algorithms:
                return {"success": False, "error": f"Unsupported algorithm: {algorithm}"}

            # Generate random salt
            salt = os.urandom(16)

            if progress_callback:
                progress_callback(10)  # Salt generated

            # Use default configs if not provided and clean them
            if hash_config is None:
                hash_config = self.default_hash_config.copy()
            else:
                hash_config = self.clean_hash_config(hash_config)
            if kdf_config is None:
                kdf_config = self.default_kdf_config.copy()

            # Ensure CLI-compatible parameters for enabled KDFs
            for kdf_name, kdf_params in kdf_config.items():
                if kdf_params.get("enabled", False) and kdf_name in self.cli_kdf_defaults:
                    # Fill in missing CLI parameters with defaults
                    for param, default_val in self.cli_kdf_defaults[kdf_name].items():
                        if param not in kdf_params:
                            kdf_params[param] = default_val

            if progress_callback:
                progress_callback(20)  # Configuration prepared

            # Derive key with chained hash/KDF
            if algorithm == "fernet":
                # Fernet needs 32 bytes for URL-safe base64 encoded key
                key = self._derive_key(password, salt, hash_config, kdf_config)
            elif algorithm == "aes-gcm":
                # AES-256-GCM needs 32 bytes raw key
                raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                final_key = self.multi_kdf_derive(raw_key, salt, kdf_config)
                key = final_key[:32]  # Ensure exactly 32 bytes for AES-256
            elif algorithm == "aes-gcm-siv":
                # AES-256-GCM-SIV needs 32 bytes raw key
                raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                final_key = self.multi_kdf_derive(raw_key, salt, kdf_config)
                key = final_key[:32]  # Ensure exactly 32 bytes for AES-256
            elif algorithm == "aes-ocb3":
                # AES-256-OCB3 needs 32 bytes raw key
                raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                final_key = self.multi_kdf_derive(raw_key, salt, kdf_config)
                key = final_key[:32]  # Ensure exactly 32 bytes for AES-256
            elif algorithm == "aes-siv":
                # AES-SIV needs 64 bytes raw key (double key for CLI compatibility)
                raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                # CRITICAL: Pass algorithm for proper key length in PBKDF2
                final_key = self.multi_kdf_derive_with_algorithm(
                    raw_key, salt, kdf_config, algorithm
                )
                key = final_key[:64] if len(final_key) >= 64 else final_key
            elif algorithm == "chacha20-poly1305":
                # ChaCha20-Poly1305 needs 32 bytes raw key
                raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                final_key = self.multi_kdf_derive(raw_key, salt, kdf_config)
                key = final_key[:32]  # Ensure exactly 32 bytes for ChaCha20
            elif algorithm == "xchacha20-poly1305":
                # XChaCha20-Poly1305 needs 32 bytes raw key
                raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                # CRITICAL: Pass algorithm for proper key length in PBKDF2
                final_key = self.multi_kdf_derive_with_algorithm(
                    raw_key, salt, kdf_config, algorithm
                )
                key = final_key[:32] if len(final_key) >= 32 else final_key

            if progress_callback:
                progress_callback(50)  # Key derivation complete

            # Encrypt data based on algorithm
            if algorithm == "fernet":
                f = Fernet(key)
                encrypted_data = f.encrypt(data)

            elif algorithm == "aes-gcm":
                # AES-256-GCM encryption
                nonce = os.urandom(12)  # 96-bit nonce for GCM
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(data) + encryptor.finalize()

                # Combine nonce + ciphertext + auth_tag (CLI format)
                encrypted_data = nonce + ciphertext + encryptor.tag

            elif algorithm == "aes-gcm-siv":
                # AES-256-GCM-SIV encryption (nonce-misuse resistant AEAD)
                nonce = os.urandom(12)  # 96-bit nonce for GCM-SIV
                gcmsiv = AESGCMSIV(key)
                encrypted_bytes = gcmsiv.encrypt(nonce, data, None)

                # AESGCMSIV.encrypt() returns ciphertext + tag combined
                # CLI format: nonce + ciphertext + tag
                encrypted_data = nonce + encrypted_bytes

            elif algorithm == "aes-ocb3":
                # AES-256-OCB3 encryption (parallelizable AEAD)
                nonce = os.urandom(12)  # 96-bit nonce for OCB3
                ocb3 = AESOCB3(key)
                encrypted_bytes = ocb3.encrypt(nonce, data, None)

                # AESOCB3.encrypt() returns ciphertext + tag combined
                # CLI format: nonce + ciphertext + tag
                encrypted_data = nonce + encrypted_bytes

            elif algorithm == "aes-siv":
                # AES-256-SIV encryption (CLI-compatible)
                # CLI stores 16-byte nonce + SIV ciphertext (even though nonce isn't used)

                # Generate 16-byte nonce (CLI format, not used for encryption)
                nonce = os.urandom(16)

                siv = AESSIV(key)
                encrypted_bytes = siv.encrypt(data, None)

                # CLI format: 16-byte nonce + ciphertext + tag (even though nonce isn't used for SIV)
                encrypted_data = nonce + encrypted_bytes

            elif algorithm == "chacha20-poly1305":
                # ChaCha20-Poly1305 encryption (AEAD)
                nonce = os.urandom(12)  # 96-bit nonce for ChaCha20-Poly1305
                chacha = ChaCha20Poly1305(key)
                encrypted_bytes = chacha.encrypt(nonce, data, None)

                # ChaCha20Poly1305.encrypt() returns nonce + ciphertext + tag combined
                # But we need CLI format: nonce + ciphertext + tag
                # encrypted_bytes is already ciphertext + 16-byte tag
                encrypted_data = nonce + encrypted_bytes

            elif algorithm == "xchacha20-poly1305":
                # XChaCha20-Poly1305 encryption (CLI-compatible)
                # CLI generates 24-byte nonce but only encrypts with first 12 bytes

                # Generate 24-byte nonce (CLI standard for storage)
                full_nonce = os.urandom(24)

                # CRITICAL CLI COMPATIBILITY: CLI only uses first 12 bytes for encryption
                # but stores the full 24 bytes in file
                nonce_for_encryption = full_nonce[:12]  # Use first 12 bytes like CLI

                # Use CLI-compatible XChaCha20Poly1305 class
                cipher = XChaCha20Poly1305(key)
                encrypted_bytes = cipher.encrypt(nonce_for_encryption, data, None)

                # CLI format: 24-byte nonce + ciphertext + tag (store full nonce)
                encrypted_data = full_nonce + encrypted_bytes

            if progress_callback:
                progress_callback(80)  # Encryption complete

            # Create CLI-compatible metadata (format version 5)
            metadata = {
                "format_version": 5,
                "derivation_config": {
                    "salt": base64.b64encode(salt).decode(),
                    "hash_config": {},
                    "kdf_config": {},
                },
                "encryption": {
                    "algorithm": algorithm,
                    "encryption_data": algorithm,  # CLI compatibility
                },
                "mobile_version": "2.1",
                "original_size": len(data),
            }

            # Add hash config in CLI format (nested with rounds)
            for algo, rounds in hash_config.items():
                if rounds > 0:
                    metadata["derivation_config"]["hash_config"][algo] = {"rounds": rounds}

            # Add KDF config in CLI format
            for kdf_name, kdf_params in kdf_config.items():
                if kdf_params.get("enabled", False):
                    # Copy all parameters except 'enabled' flag
                    cli_params = {k: v for k, v in kdf_params.items() if k != "enabled"}
                    metadata["derivation_config"]["kdf_config"][kdf_name] = cli_params

            if progress_callback:
                progress_callback(100)  # Complete

            return {
                "success": True,
                "encrypted_data": base64.b64encode(encrypted_data).decode(),
                "metadata": metadata,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def decrypt_data(
        self, encrypted_data_b64: str, metadata: Dict[str, Any], password: str
    ) -> Dict[str, Any]:
        """
        Decrypt data using stored metadata with original hash/KDF chain parameters
        Supports CLI format v5, mobile formats, and legacy formats
        """
        try:
            # Decode encrypted data (CLI format v5 uses single base64 decode only)
            try:
                # CLI format v5: single base64 decode gives Fernet data directly
                encrypted_data = base64.b64decode(encrypted_data_b64.encode())

                # Note: CLI format v5 does NOT use nested base64 encoding
                # The first decode gives us the Fernet data directly

            except Exception as decode_error:
                return {
                    "success": False,
                    "error": f"Failed to decode encrypted data: {str(decode_error)}",
                }

            # Handle CLI format version 4 and 5 (real CLI format)
            if metadata.get("format_version") in [4, 5] and "derivation_config" in metadata:
                # CLI format version 5
                derivation_config = metadata["derivation_config"]

                # Get salt
                salt = base64.b64decode(derivation_config["salt"].encode())

                # Extract hash config from CLI format
                cli_hash_config = derivation_config.get("hash_config", {})
                hash_config = {}
                for algo, config in cli_hash_config.items():
                    if isinstance(config, dict) and "rounds" in config:
                        hash_config[algo] = config["rounds"]
                    else:
                        hash_config[algo] = config if isinstance(config, int) else 0

                # Clean the hash config to handle CLI data contamination
                hash_config = self.clean_hash_config(hash_config)

                # Extract KDF config from CLI format
                cli_kdf_config = derivation_config.get("kdf_config", {})
                kdf_config = self.default_kdf_config.copy()

                # Set all to disabled by default
                for kdf in kdf_config:
                    kdf_config[kdf]["enabled"] = False

                # Enable and configure KDFs found in metadata
                for kdf_name, kdf_params in cli_kdf_config.items():
                    if kdf_name in kdf_config:
                        # Check if this KDF should be enabled (CLI uses "enabled" field)
                        if "enabled" in kdf_params:
                            enabled = kdf_params["enabled"]
                        else:
                            # Legacy CLI format: if KDF is present, it's enabled
                            enabled = True

                        kdf_config[kdf_name]["enabled"] = enabled

                        # Update with CLI parameters (skip "enabled" field)
                        for param, value in kdf_params.items():
                            if param != "enabled":
                                kdf_config[kdf_name][param] = value

                # Get algorithm from metadata
                algorithm = metadata.get("encryption", {}).get("algorithm", "fernet")

                # Derive appropriate key based on algorithm
                if algorithm == "fernet":
                    key = self._derive_key(password, salt, hash_config, kdf_config)
                elif algorithm == "aes-gcm":
                    # AES-GCM uses raw key, not base64 encoded
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    key = self.multi_kdf_derive(raw_key, salt, kdf_config)[
                        :32
                    ]  # 32 bytes for AES-256
                elif algorithm == "aes-gcm-siv":
                    # AES-GCM-SIV uses raw key, not base64 encoded
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    key = self.multi_kdf_derive(raw_key, salt, kdf_config)[
                        :32
                    ]  # 32 bytes for AES-256
                elif algorithm == "aes-ocb3":
                    # AES-OCB3 uses raw key, not base64 encoded
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    key = self.multi_kdf_derive(raw_key, salt, kdf_config)[
                        :32
                    ]  # 32 bytes for AES-256
                elif algorithm == "aes-siv":
                    # AES-SIV needs 64 bytes raw key (CLI compatibility)
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    # Use algorithm-specific KDF to get 64-byte key
                    final_key = self.multi_kdf_derive_with_algorithm(
                        raw_key, salt, kdf_config, algorithm
                    )
                    key = final_key[:64] if len(final_key) >= 64 else final_key
                elif algorithm == "chacha20-poly1305":
                    # ChaCha20-Poly1305 uses raw key, not base64 encoded
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    key = self.multi_kdf_derive(raw_key, salt, kdf_config)[
                        :32
                    ]  # 32 bytes for ChaCha20
                elif algorithm == "xchacha20-poly1305":
                    # XChaCha20-Poly1305 needs 32 bytes raw key (CLI compatibility)
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    # Use algorithm-specific KDF to get 32-byte key
                    final_key = self.multi_kdf_derive_with_algorithm(
                        raw_key, salt, kdf_config, algorithm
                    )
                    key = final_key[:32] if len(final_key) >= 32 else final_key
                else:
                    # Check if we need algorithm-specific key derivation
                    if algorithm in ["xchacha20-poly1305", "aes-siv"]:
                        key = self._derive_key_with_algorithm(
                            password, salt, hash_config, kdf_config, algorithm
                        )
                    else:
                        key = self._derive_key(
                            password, salt, hash_config, kdf_config
                        )  # Default fallback

            # Handle CLI format version 3 (legacy CLI format)
            elif metadata.get("format_version") == 3 and "algorithm" in metadata:
                # CLI format version 3
                salt = base64.b64decode(metadata["salt"].encode())
                algorithm = metadata["algorithm"]

                # Extract hash config from v3 format (similar to v4/v5)
                v3_hash_config = metadata.get("hash_config", {})
                hash_config = {}

                # Handle v3 hash config format
                for algo in [
                    "sha512",
                    "sha256",
                    "sha3_256",
                    "sha3_512",
                    "blake2b",
                    "shake256",
                    "whirlpool",
                ]:
                    if algo in v3_hash_config:
                        hash_config[algo] = v3_hash_config[algo]
                    else:
                        hash_config[algo] = 0

                # Clean the hash config
                hash_config = self.clean_hash_config(hash_config)

                # Extract KDF config from v3 format
                kdf_config = self.default_kdf_config.copy()

                # Set all to disabled by default
                for kdf in kdf_config:
                    kdf_config[kdf]["enabled"] = False

                # Enable and configure KDFs from v3 hash_config
                if "scrypt" in v3_hash_config and isinstance(v3_hash_config["scrypt"], dict):
                    scrypt_params = v3_hash_config["scrypt"]
                    if scrypt_params.get("enabled", False):
                        kdf_config["scrypt"]["enabled"] = True
                        for param, value in scrypt_params.items():
                            if param != "enabled" and param in kdf_config["scrypt"]:
                                kdf_config["scrypt"][param] = value

                if "argon2" in v3_hash_config and isinstance(v3_hash_config["argon2"], dict):
                    argon2_params = v3_hash_config["argon2"]
                    if argon2_params.get("enabled", False):
                        kdf_config["argon2"]["enabled"] = True
                        # Copy all Argon2 parameters, including hash_len which might not be in default config
                        for param, value in argon2_params.items():
                            if param != "enabled":
                                kdf_config["argon2"][param] = value

                if "balloon" in v3_hash_config and isinstance(v3_hash_config["balloon"], dict):
                    balloon_params = v3_hash_config["balloon"]
                    if balloon_params.get("enabled", False):
                        kdf_config["balloon"]["enabled"] = True
                        for param, value in balloon_params.items():
                            if param != "enabled" and param in kdf_config["balloon"]:
                                kdf_config["balloon"][param] = value

                # Handle PBKDF2 from v3 format
                pbkdf2_iterations = metadata.get("pbkdf2_iterations", 0)
                if pbkdf2_iterations > 0:
                    kdf_config["pbkdf2"]["enabled"] = True
                    kdf_config["pbkdf2"]["rounds"] = pbkdf2_iterations

                # Derive appropriate key based on algorithm (like v4/v5 handling)
                if algorithm == "fernet":
                    key = self._derive_key(password, salt, hash_config, kdf_config)
                elif algorithm == "aes-gcm":
                    # AES-GCM uses raw key, not base64 encoded
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    key = self.multi_kdf_derive(raw_key, salt, kdf_config)[
                        :32
                    ]  # 32 bytes for AES-256
                elif algorithm == "aes-gcm-siv":
                    # AES-GCM-SIV uses raw key, not base64 encoded
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    key = self.multi_kdf_derive(raw_key, salt, kdf_config)[
                        :32
                    ]  # 32 bytes for AES-256
                elif algorithm == "aes-ocb3":
                    # AES-OCB3 uses raw key, not base64 encoded
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    key = self.multi_kdf_derive(raw_key, salt, kdf_config)[
                        :32
                    ]  # 32 bytes for AES-256
                elif algorithm == "aes-siv":
                    # AES-SIV needs 64 bytes raw key (CLI compatibility)
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    # Use algorithm-specific KDF to get 64-byte key
                    final_key = self.multi_kdf_derive_with_algorithm(
                        raw_key, salt, kdf_config, algorithm
                    )
                    key = final_key[:64] if len(final_key) >= 64 else final_key
                elif algorithm == "chacha20-poly1305":
                    # ChaCha20-Poly1305 uses raw key, not base64 encoded
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    key = self.multi_kdf_derive(raw_key, salt, kdf_config)[
                        :32
                    ]  # 32 bytes for ChaCha20
                elif algorithm == "xchacha20-poly1305":
                    # XChaCha20-Poly1305 needs 32 bytes raw key (CLI compatibility)
                    raw_key = self.multi_hash_password(password.encode(), salt, hash_config)
                    # Use algorithm-specific KDF to get 32-byte key
                    final_key = self.multi_kdf_derive_with_algorithm(
                        raw_key, salt, kdf_config, algorithm
                    )
                    key = final_key[:32] if len(final_key) >= 32 else final_key
                else:
                    # Check if we need algorithm-specific key derivation
                    if algorithm in ["xchacha20-poly1305", "aes-siv"]:
                        key = self._derive_key_with_algorithm(
                            password, salt, hash_config, kdf_config, algorithm
                        )
                    else:
                        key = self._derive_key(
                            password, salt, hash_config, kdf_config
                        )  # Default fallback

            # Handle mobile format with derivation_config (mobile v2.x)
            elif "derivation_config" in metadata and "salt" in metadata["derivation_config"]:
                # Mobile format with derivation_config
                salt = base64.b64decode(metadata["derivation_config"]["salt"].encode())

                # Use the same logic as CLI format
                derivation_config = metadata["derivation_config"]
                cli_hash_config = derivation_config.get("hash_config", {})
                hash_config = {}
                for algo, config in cli_hash_config.items():
                    if isinstance(config, dict) and "rounds" in config:
                        hash_config[algo] = config["rounds"]
                    else:
                        hash_config[algo] = config if isinstance(config, int) else 0

                for algo in self.default_hash_config:
                    if algo not in hash_config:
                        hash_config[algo] = 0

                cli_kdf_config = derivation_config.get("kdf_config", {})
                kdf_config = self.default_kdf_config.copy()

                for kdf in kdf_config:
                    kdf_config[kdf]["enabled"] = False

                for kdf_name, kdf_params in cli_kdf_config.items():
                    if kdf_name in kdf_config:
                        # Check if this KDF should be enabled (CLI uses "enabled" field)
                        if "enabled" in kdf_params:
                            enabled = kdf_params["enabled"]
                        else:
                            # Legacy CLI format: if KDF is present, it's enabled
                            enabled = True

                        kdf_config[kdf_name]["enabled"] = enabled

                        # Update with CLI parameters (skip "enabled" field)
                        for param, value in kdf_params.items():
                            if param != "enabled":
                                kdf_config[kdf_name][param] = value

                # Get algorithm for algorithm-specific key derivation
                algorithm = metadata.get("encryption", {}).get("algorithm", "fernet")

                # Use algorithm-specific key derivation for CLI compatibility
                if algorithm in ["xchacha20-poly1305", "aes-siv"]:
                    key = self._derive_key_with_algorithm(
                        password, salt, hash_config, kdf_config, algorithm
                    )
                else:
                    key = self._derive_key(password, salt, hash_config, kdf_config)

            # Handle old mobile format (direct salt)
            elif "salt" in metadata:
                salt = base64.b64decode(metadata["salt"].encode())

            elif "hash_config" in metadata and "kdf_config" in metadata:
                # Old mobile format (v2.0/2.1)
                hash_config = metadata.get("hash_config", self.default_hash_config)
                kdf_config = metadata.get("kdf_config", self.default_kdf_config)

                # Get algorithm for algorithm-specific key derivation
                algorithm = metadata.get("encryption", {}).get("algorithm", "fernet")
                if algorithm in ["xchacha20-poly1305", "aes-siv"]:
                    key = self._derive_key_with_algorithm(
                        password, salt, hash_config, kdf_config, algorithm
                    )
                else:
                    key = self._derive_key(password, salt, hash_config, kdf_config)

            else:
                # Legacy format compatibility (v1.x)
                hash_algo = metadata.get("hash_algorithm", "sha256")
                kdf_algo = metadata.get("kdf_algorithm", "pbkdf2")

                # Use single hash and single KDF for legacy compatibility
                single_hash_config = {algo: 0 for algo in self.default_hash_config}
                single_hash_config[hash_algo] = 1

                legacy_kdf_config = self.default_kdf_config.copy()
                for kdf in legacy_kdf_config:
                    legacy_kdf_config[kdf]["enabled"] = False
                legacy_kdf_config[kdf_algo]["enabled"] = True
                if kdf_algo == "pbkdf2":
                    legacy_kdf_config[kdf_algo]["rounds"] = metadata.get("iterations", 100000)

                # Get algorithm for algorithm-specific key derivation
                algorithm = metadata.get("encryption", {}).get("algorithm", "fernet")
                if algorithm in ["xchacha20-poly1305", "aes-siv"]:
                    key = self._derive_key_with_algorithm(
                        password, salt, single_hash_config, legacy_kdf_config, algorithm
                    )
                else:
                    key = self._derive_key(password, salt, single_hash_config, legacy_kdf_config)

            # Decrypt based on algorithm
            try:
                # Determine algorithm from metadata (handle different format versions)
                if metadata.get("format_version") == 3:
                    # v3 format: algorithm is directly in metadata
                    algorithm = metadata.get("algorithm", "fernet")
                else:
                    # v4/v5 format: algorithm is in encryption section
                    algorithm = metadata.get("encryption", {}).get("algorithm", "fernet")

                if algorithm == "fernet":
                    f = Fernet(key)
                    decrypted_data = f.decrypt(encrypted_data)

                elif algorithm == "aes-gcm":
                    # AES-256-GCM decryption
                    if len(encrypted_data) < 28:  # 12 (nonce) + 16 (min ciphertext + tag)
                        raise ValueError("Encrypted data too short for AES-GCM")

                    # Extract components (CLI format: nonce + ciphertext + auth_tag)
                    nonce = encrypted_data[:12]  # 96-bit nonce
                    ciphertext_and_tag = encrypted_data[12:]  # ciphertext + 16-byte tag

                    if len(ciphertext_and_tag) < 16:
                        raise ValueError("Invalid AES-GCM data: missing auth tag")

                    ciphertext = ciphertext_and_tag[:-16]  # All but last 16 bytes
                    auth_tag = ciphertext_and_tag[-16:]  # Last 16 bytes

                    # Use pre-derived key (already computed above for AES-GCM)
                    cipher = Cipher(
                        algorithms.AES(key), modes.GCM(nonce, auth_tag), backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

                elif algorithm == "aes-gcm-siv":
                    # AES-256-GCM-SIV decryption
                    if len(encrypted_data) < 28:  # 12 (nonce) + 16 (min ciphertext + tag)
                        raise ValueError("Encrypted data too short for AES-GCM-SIV")

                    # Extract components (CLI format: nonce + ciphertext + auth_tag)
                    nonce = encrypted_data[:12]  # 96-bit nonce
                    ciphertext_and_tag = encrypted_data[12:]  # ciphertext + 16-byte tag

                    # Use pre-derived key (already computed above for AES-GCM-SIV)
                    gcmsiv = AESGCMSIV(key)
                    decrypted_data = gcmsiv.decrypt(nonce, ciphertext_and_tag, None)

                elif algorithm == "aes-ocb3":
                    # AES-256-OCB3 decryption
                    if len(encrypted_data) < 28:  # 12 (nonce) + 16 (min ciphertext + tag)
                        raise ValueError("Encrypted data too short for AES-OCB3")

                    # Extract components (CLI format: nonce + ciphertext + auth_tag)
                    nonce = encrypted_data[:12]  # 96-bit nonce
                    ciphertext_and_tag = encrypted_data[12:]  # ciphertext + 16-byte tag

                    # Use pre-derived key (already computed above for AES-OCB3)
                    ocb3 = AESOCB3(key)
                    decrypted_data = ocb3.decrypt(nonce, ciphertext_and_tag, None)

                elif algorithm == "aes-siv":
                    # AES-256-SIV decryption (CLI-compatible)
                    # CLI format: 16-byte nonce + ciphertext + tag (nonce not used)
                    if len(encrypted_data) < 32:  # 16 (nonce) + 16 (min ciphertext + tag)
                        raise ValueError("Encrypted data too short for AES-SIV")

                    # Extract nonce and ciphertext+tag (CLI format)
                    stored_nonce = encrypted_data[:16]  # 16-byte nonce (not used)
                    siv_data = encrypted_data[16:]  # ciphertext + tag

                    # Use pre-derived key (already computed above for AES-SIV)
                    siv = AESSIV(key)
                    decrypted_data = siv.decrypt(siv_data, None)

                elif algorithm == "chacha20-poly1305":
                    # ChaCha20-Poly1305 decryption
                    if len(encrypted_data) < 28:  # 12 (nonce) + 16 (min ciphertext + tag)
                        raise ValueError("Encrypted data too short for ChaCha20-Poly1305")

                    # Extract components (CLI format: nonce + ciphertext + auth_tag)
                    nonce = encrypted_data[:12]  # 96-bit nonce
                    ciphertext_and_tag = encrypted_data[12:]  # ciphertext + 16-byte tag

                    # Use pre-derived key (already computed above for ChaCha20-Poly1305)
                    chacha = ChaCha20Poly1305(key)
                    decrypted_data = chacha.decrypt(nonce, ciphertext_and_tag, None)

                elif algorithm == "xchacha20-poly1305":
                    # XChaCha20-Poly1305 decryption (CLI-compatible)
                    # CLI stores 24-byte nonce but only encrypts with first 12 bytes

                    if len(encrypted_data) < 40:  # 24 (nonce) + 16 (min ciphertext + tag)
                        raise ValueError("Encrypted data too short for XChaCha20-Poly1305")

                    # Extract nonce and ciphertext+tag (CLI format)
                    stored_nonce = encrypted_data[:24]  # 24-byte nonce from file
                    ciphertext_and_tag = encrypted_data[24:]  # ciphertext + tag

                    # CRITICAL CLI COMPATIBILITY: CLI only uses first 12 bytes for encryption
                    # but stores 24 bytes. XChaCha20Poly1305 class should receive first 12 bytes
                    nonce_for_decryption = stored_nonce[:12]  # Use first 12 bytes like CLI

                    # Use CLI-compatible XChaCha20Poly1305 class
                    cipher = XChaCha20Poly1305(key)
                    decrypted_data = cipher.decrypt(nonce_for_decryption, ciphertext_and_tag, None)

                else:
                    return {"success": False, "error": f"Unsupported algorithm: {algorithm}"}

            except Exception as decrypt_error:
                # Get algorithm using same logic as above (handle different format versions)
                if metadata.get("format_version") == 3:
                    # v3 format: algorithm is directly in metadata
                    algorithm = metadata.get("algorithm", "fernet")
                else:
                    # v4/v5 format: algorithm is in encryption section
                    algorithm = metadata.get("encryption", {}).get("algorithm", "fernet")

                return {
                    "success": False,
                    "error": f"{algorithm.upper()} decryption failed: {str(decrypt_error)}",
                }

            return {"success": True, "decrypted_data": decrypted_data}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def encrypt_text(self, text: str, password: str, algorithm: str = "fernet") -> str:
        """Simple text encryption for testing"""
        result = self.encrypt_data(text.encode(), password, algorithm)
        if result["success"]:
            return json.dumps(
                {"encrypted_data": result["encrypted_data"], "metadata": result["metadata"]}
            )
        else:
            return json.dumps({"error": result["error"]})

    def decrypt_text(self, encrypted_json: str, password: str) -> str:
        """Simple text decryption for testing"""
        try:
            data = json.loads(encrypted_json)
            result = self.decrypt_data(data["encrypted_data"], data["metadata"], password)
            if result["success"]:
                return result["decrypted_data"].decode()
            else:
                return f"ERROR: {result['error']}"
        except Exception as e:
            return f"ERROR: {str(e)}"

    def get_supported_algorithms(self) -> str:
        """Get list of supported algorithms as JSON"""
        return json.dumps(self.supported_algorithms)

    def get_hash_algorithms(self) -> str:
        """Get list of supported hash algorithms as JSON (CLI order)"""
        # Return in CLI processing order
        cli_order = [
            "sha512",
            "sha256",
            "sha3_256",
            "sha3_512",
            "blake2b",
            "blake3",
            "shake256",
            "whirlpool",
        ]
        available = [algo for algo in cli_order if algo in self.hash_algorithms]
        return json.dumps(available)

    def get_chained_hash_config(self) -> str:
        """Get default chained hash configuration as JSON"""
        return json.dumps(self.default_hash_config)

    def set_hash_rounds(self, algorithm: str, rounds: int) -> bool:
        """Set custom rounds for a specific hash algorithm"""
        if algorithm in self.hash_algorithms and rounds >= 0:
            self.default_hash_config[algorithm] = rounds
            return True
        return False

    def get_kdf_algorithms(self) -> str:
        """Get list of supported KDF algorithms as JSON"""
        available_kdfs = []
        for kdf_name, kdf_info in self.kdf_algorithms.items():
            if kdf_name == "argon2" and not ARGON2_AVAILABLE:
                continue
            available_kdfs.append({"id": kdf_name, "name": kdf_info["name"], "available": True})
        return json.dumps(available_kdfs)

    def get_security_levels(self) -> str:
        """Get list of security levels as JSON"""
        return json.dumps(
            [
                {
                    "id": "fast",
                    "name": "Fast",
                    "description": "Lower iterations, faster processing",
                },
                {
                    "id": "standard",
                    "name": "Standard",
                    "description": "Balanced security and performance (recommended)",
                },
                {
                    "id": "secure",
                    "name": "Secure",
                    "description": "Higher iterations, maximum security",
                },
            ]
        )

    def get_crypto_config(self) -> str:
        """Get complete crypto configuration as JSON"""
        return json.dumps(
            {
                "encryption_algorithms": self.supported_algorithms,
                "hash_algorithms": list(self.hash_algorithms.keys()),
                "kdf_algorithms": [
                    kdf for kdf in self.kdf_algorithms.keys() if kdf != "argon2" or ARGON2_AVAILABLE
                ],
                "security_levels": ["fast", "standard", "secure"],
                "features": {
                    "argon2_available": ARGON2_AVAILABLE,
                    "balloon_available": BALLOON_AVAILABLE,
                    "blake3_available": BLAKE3_AVAILABLE,
                    "whirlpool_available": WHIRLPOOL_AVAILABLE,
                    "version": "mobile-2.0",
                    "cli_compatible": True,
                    "chained_hashing": True,
                },
            }
        )

    def encrypt_file(
        self, file_path: str, password: str, output_path: str = None, progress_callback=None
    ) -> Dict[str, Any]:
        """
        Encrypt a file using mobile-optimized approach
        """
        try:
            if not os.path.exists(file_path):
                return {"success": False, "error": "Input file not found"}

            # Read file data
            if progress_callback:
                progress_callback(10)

            with open(file_path, "rb") as f:
                file_data = f.read()

            if progress_callback:
                progress_callback(20)

            # Encrypt data
            result = self.encrypt_data(file_data, password, progress_callback)

            if not result["success"]:
                return result

            # Prepare output file
            if not output_path:
                output_path = file_path + ".enc"

            # Write CLI-compatible file format (base64_metadata:base64_encrypted_data)
            metadata_json = json.dumps(result["metadata"])
            metadata_b64 = base64.b64encode(metadata_json.encode()).decode()
            encrypted_data_b64 = result["encrypted_data"]

            cli_format = f"{metadata_b64}:{encrypted_data_b64}"

            # Write encrypted file in CLI format
            with open(output_path, "w") as f:
                f.write(cli_format)

            return {
                "success": True,
                "output_path": output_path,
                "original_size": len(file_data),
                "encrypted_size": os.path.getsize(output_path),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def decrypt_file(
        self,
        encrypted_file_path: str,
        password: str,
        output_path: str = None,
        progress_callback=None,
    ) -> Dict[str, Any]:
        """
        Decrypt a file encrypted with mobile crypto core or CLI format
        """
        try:
            if not os.path.exists(encrypted_file_path):
                return {"success": False, "error": "Encrypted file not found"}

            if progress_callback:
                progress_callback(10)

            # Read encrypted file content
            with open(encrypted_file_path, "r") as f:
                raw_content = f.read().strip()

            if progress_callback:
                progress_callback(20)

            # Determine file format (CLI or mobile JSON)
            if ":" in raw_content and not raw_content.startswith("{"):
                # CLI format: base64_metadata:base64_encrypted_data
                try:
                    metadata_b64, encrypted_data_b64 = raw_content.split(":", 1)
                    metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                    metadata = json.loads(metadata_json)
                    encrypted_data = encrypted_data_b64
                    original_filename = "decrypted_file.txt"

                    print(
                        f"📋 Detected CLI format version {metadata.get('format_version', 'unknown')}"
                    )

                except Exception as e:
                    return {"success": False, "error": f"Failed to parse CLI format: {str(e)}"}

            else:
                # Mobile JSON format
                try:
                    file_content = json.loads(raw_content)

                    # Validate mobile format
                    if file_content.get("format") != "openssl_encrypt_mobile":
                        return {"success": False, "error": "Invalid encrypted file format"}

                    encrypted_data = file_content["encrypted_data"]
                    metadata = file_content["metadata"]
                    original_filename = file_content.get("original_filename", "decrypted_file")

                except Exception as e:
                    return {
                        "success": False,
                        "error": f"Failed to parse mobile JSON format: {str(e)}",
                    }

            # Decrypt data using unified decrypt_data method
            result = self.decrypt_data(encrypted_data, metadata, password)

            if not result["success"]:
                return result

            # Prepare output file
            if not output_path:
                base_dir = os.path.dirname(encrypted_file_path)
                output_path = os.path.join(base_dir, original_filename)

            # Write decrypted file
            with open(output_path, "wb") as f:
                f.write(result["decrypted_data"])

            if progress_callback:
                progress_callback(100)

            return {
                "success": True,
                "output_path": output_path,
                "original_filename": original_filename,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}


# For FFI: Create global instance and C-compatible functions
crypto_core = MobileCryptoCore()


def mobile_encrypt_text(text: str, password: str) -> str:
    """C-compatible function for text encryption"""
    return crypto_core.encrypt_text(text, password)


def mobile_decrypt_text(encrypted_json: str, password: str) -> str:
    """C-compatible function for text decryption"""
    return crypto_core.decrypt_text(encrypted_json, password)


def mobile_get_algorithms() -> str:
    """C-compatible function to get supported algorithms"""
    return crypto_core.get_supported_algorithms()


if __name__ == "__main__":
    # Test the mobile crypto core
    core = MobileCryptoCore()

    # Test text encryption/decryption
    test_text = "Hello from OpenSSL Encrypt Mobile!"
    test_password = "test123"

    print("Testing mobile crypto core...")

    # Encrypt
    encrypted = core.encrypt_text(test_text, test_password)
    print(f"Encrypted: {encrypted[:100]}...")

    # Decrypt
    decrypted = core.decrypt_text(encrypted, test_password)
    print(f"Decrypted: {decrypted}")

    # Test success
    print(f"Test {'PASSED' if decrypted == test_text else 'FAILED'}")

    # Show algorithms
    print(f"Supported algorithms: {core.get_supported_algorithms()}")
