#!/usr/bin/env python3
"""
Post-Quantum Cryptography Module

This module provides support for post-quantum cryptographic algorithms
using the liboqs-python wrapper for liboqs.
"""

import base64
import ctypes
import hashlib
import json
import logging
import os
import secrets
import sys
import time
from enum import Enum
from typing import Optional, Tuple, Union

from .algorithm_warnings import (
    get_recommended_replacement,
    is_deprecated,
    warn_deprecated_algorithm,
)
from .crypt_utils import eprint
from .secure_memory import SecureBytes, secure_memzero, secure_string

# Set up module-level logger
logger = logging.getLogger(__name__)


# Environment variable to control PQC initialization messages

# Try to import PQC libraries, provide fallbacks if not available
LIBOQS_AVAILABLE = False
oqs = None

# Check for quiet mode environment variable
PQC_QUIET = os.environ.get("PQC_QUIET", "").lower() in ("1", "true", "yes", "on")

try:
    import oqs

    # Check essential methods that we need to verify compatibility
    kem_methods_available = hasattr(oqs, "get_enabled_kem_mechanisms") or hasattr(
        oqs, "get_supported_kem_mechanisms"
    )

    if kem_methods_available:
        LIBOQS_AVAILABLE = True
        # Testing KeyEncapsulation creation
        try:
            test_mechanisms = oqs.get_enabled_kem_mechanisms()
            if test_mechanisms:
                test_kem = oqs.KeyEncapsulation(test_mechanisms[0])
                # Clean up test object
                test_kem = None
        except Exception:
            pass
    else:
        LIBOQS_AVAILABLE = False
except ImportError:
    LIBOQS_AVAILABLE = False
except Exception:
    LIBOQS_AVAILABLE = False


# Define supported PQC algorithms
class PQCAlgorithm(Enum):
    # NIST FIPS 203 standardized naming (ML-KEM)
    ML_KEM_512 = "ML-KEM-512"
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"

    ML_DSA_44 = "ML-DSA-44"  # NIST FIPS 204 (formerly Dilithium2)
    ML_DSA_65 = "ML-DSA-65"  # NIST FIPS 204 (formerly Dilithium3)
    ML_DSA_87 = "ML-DSA-87"  # NIST FIPS 204 (formerly Dilithium5)
    FN_DSA_512 = "FN-DSA-512"  # NIST FIPS 206 (formerly Falcon-512)
    FN_DSA_1024 = "FN-DSA-1024"  # NIST FIPS 206 (formerly Falcon-1024)
    SLH_DSA_SHA2_128F = "SLH-DSA-SHA2-128F"  # NIST FIPS 205 (formerly SPHINCS+-SHA2-128f)
    SLH_DSA_SHA2_256F = "SLH-DSA-SHA2-256F"  # NIST FIPS 205 (formerly SPHINCS+-SHA2-256f)

    # NIST Round 2 Additional Signature Algorithms
    # MAYO (Oil-and-Vinegar multivariate signature scheme)
    MAYO_1 = "MAYO-1"  # Level 1 (128-bit security)
    MAYO_3 = "MAYO-3"  # Level 3 (192-bit security)
    MAYO_5 = "MAYO-5"  # Level 5 (256-bit security)

    # CROSS (Codes and Restricted Objects Signature Scheme)
    CROSS_128 = "CROSS-128"  # Level 1 (128-bit security)
    CROSS_192 = "CROSS-192"  # Level 3 (192-bit security)
    CROSS_256 = "CROSS-256"  # Level 5 (256-bit security)

    # Legacy signature algorithm names (deprecated, will be removed in future)
    DILITHIUM2 = "Dilithium2"  # Deprecated: use ML_DSA_44 instead
    DILITHIUM3 = "Dilithium3"  # Deprecated: use ML_DSA_65 instead
    DILITHIUM5 = "Dilithium5"  # Deprecated: use ML_DSA_87 instead
    FALCON512 = "Falcon-512"  # Deprecated: use FN_DSA_512 instead
    FALCON1024 = "Falcon-1024"  # Deprecated: use FN_DSA_1024 instead
    SPHINCSSHA2128F = "SPHINCS+-SHA2-128f"  # Deprecated: use SLH_DSA_SHA2_128F instead
    SPHINCSSHA2256F = "SPHINCS+-SHA2-256f"  # Deprecated: use SLH_DSA_SHA2_256F instead


# Create mappings for algorithm name translation
LEGACY_TO_STANDARD_ALGORITHM_MAP = {
    # Signature algorithm mappings
    "Dilithium2": "ML-DSA-44",
    "Dilithium3": "ML-DSA-65",
    "Dilithium5": "ML-DSA-87",
    "Falcon-512": "FN-DSA-512",
    "Falcon-1024": "FN-DSA-1024",
    "SPHINCS+-SHA2-128f": "SLH-DSA-SHA2-128F",
    "SPHINCS+-SHA2-256f": "SLH-DSA-SHA2-256F",
}

# Reverse mapping for backward compatibility
STANDARD_TO_LEGACY_ALGORITHM_MAP = {v: k for k, v in LEGACY_TO_STANDARD_ALGORITHM_MAP.items()}


def normalize_algorithm_name(name: str, use_standard: bool = True) -> str:
    """
    Normalize algorithm names between legacy and standard NIST naming.

    Args:
        name (str): The algorithm name to normalize
        use_standard (bool): If True, convert legacy names to standard; if False,
                            convert standard names to legacy

    Returns:
        str: The normalized algorithm name
    """
    if use_standard:
        # Convert legacy name to standard name
        return LEGACY_TO_STANDARD_ALGORITHM_MAP.get(name, name)
    else:
        # Convert standard name to legacy name
        return STANDARD_TO_LEGACY_ALGORITHM_MAP.get(name, name)


def check_pqc_support(quiet: bool = False) -> Tuple[bool, Optional[str], list]:
    """
    Check if post-quantum cryptography is available and which algorithms are supported.

    Args:
        quiet (bool): Whether to suppress output messages

    Returns:
        tuple: (is_available, version, supported_algorithms)
    """
    # Respect both the parameter and the global environment variable setting
    should_be_quiet = quiet or PQC_QUIET

    if not LIBOQS_AVAILABLE:
        return False, None, []

    try:
        # Get liboqs version
        version = "unknown"
        if hasattr(oqs, "get_version"):
            version = oqs.get_version()
        elif hasattr(oqs, "OQS_VERSION"):
            version = oqs.OQS_VERSION
        elif hasattr(oqs, "oqs_version"):
            version = oqs.oqs_version

        # Get supported algorithms
        supported_algorithms = []

        # Check KEM algorithms
        try:
            if hasattr(oqs, "get_enabled_kem_mechanisms"):
                legacy_algorithms = oqs.get_enabled_kem_mechanisms()
                # Convert legacy names to standardized names
                for alg in legacy_algorithms:
                    # Add both legacy and standardized names for compatibility
                    supported_algorithms.append(alg)
                    # If we have a mapping to a standard name, add it too
                    std_name = normalize_algorithm_name(alg, use_standard=True)
                    if std_name != alg:
                        supported_algorithms.append(std_name)
            elif hasattr(oqs, "get_supported_kem_mechanisms"):
                legacy_algorithms = oqs.get_supported_kem_mechanisms()
                # Convert legacy names to standardized names
                for alg in legacy_algorithms:
                    supported_algorithms.append(alg)
                    std_name = normalize_algorithm_name(alg, use_standard=True)
                    if std_name != alg:
                        supported_algorithms.append(std_name)
            else:
                # Fallback to all known KEM algorithms if API methods not found
                # Prioritize ML-KEM (standardized) names
                supported_algorithms.extend(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
        except Exception:
            # Force add all KEM algorithms as fallback
            # Prioritize ML-KEM (standardized) names
            supported_algorithms.extend(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])

        # Check signature algorithms (less important for us)
        try:
            if hasattr(oqs, "get_enabled_sig_mechanisms"):
                legacy_sig_algorithms = oqs.get_enabled_sig_mechanisms()
                # Convert legacy names to standardized names
                for alg in legacy_sig_algorithms:
                    # Add both legacy and standardized names for compatibility
                    supported_algorithms.append(alg)
                    # If we have a mapping to a standard name, add it too
                    std_name = normalize_algorithm_name(alg, use_standard=True)
                    if std_name != alg:
                        supported_algorithms.append(std_name)
            elif hasattr(oqs, "get_supported_sig_mechanisms"):
                legacy_sig_algorithms = oqs.get_supported_sig_mechanisms()
                # Convert legacy names to standardized names
                for alg in legacy_sig_algorithms:
                    supported_algorithms.append(alg)
                    std_name = normalize_algorithm_name(alg, use_standard=True)
                    if std_name != alg:
                        supported_algorithms.append(std_name)
            else:
                # Add standard signature algorithm names
                supported_algorithms.extend(
                    [
                        "ML-DSA-44",
                        "ML-DSA-65",
                        "ML-DSA-87",
                        "FN-DSA-512",
                        "FN-DSA-1024",
                        "SLH-DSA-SHA2-128F",
                        "SLH-DSA-SHA2-256F",
                    ]
                )
                # Add legacy names for backward compatibility
                supported_algorithms.extend(
                    [
                        "Dilithium2",
                        "Dilithium3",
                        "Dilithium5",
                        "Falcon-512",
                        "Falcon-1024",
                        "SPHINCS+-SHA2-128f",
                        "SPHINCS+-SHA2-256f",
                    ]
                )
        except Exception as e:
            # Skip printing warning about signature algorithms
            pass

        return True, version, supported_algorithms
    except Exception:
        # Provide fallback algorithms (prioritize standardized names)
        return (
            False,
            None,
            ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        )


class PQCipher:
    """
    Post-Quantum Cipher implementation using liboqs

    This implementation combines post-quantum key encapsulation with
    configurable symmetric encryption algorithms.
    """

    def __init__(
        self,
        algorithm: Union[PQCAlgorithm, str],
        quiet: bool = False,
        encryption_data: str = "aes-gcm",
        verbose: bool = False,
        debug: bool = False,
        format_version: Optional[int] = None,
    ):
        """
        Initialize a post-quantum cipher instance

        Args:
            algorithm (Union[PQCAlgorithm, str]): The post-quantum algorithm to use
            quiet (bool): Whether to suppress output messages
            encryption_data (str): Symmetric encryption algorithm to use ('aes-gcm', 'chacha20-poly1305', etc.)
            verbose (bool): Whether to show detailed information
            debug (bool): Whether to show debug level information
            format_version (int, optional): File format version. >= 12 uses HKDF
                for KEM key derivation; older versions use legacy SHA-256.

        Raises:
            ValueError: If liboqs is not available or algorithm not supported
            ImportError: If required dependencies are missing
        """
        self.format_version = format_version
        # Respect both parameter and environment variable
        should_be_quiet = quiet or PQC_QUIET

        # Configure algorithm warnings system based on verbose or debug flag
        from .algorithm_warnings import AlgorithmWarningConfig

        AlgorithmWarningConfig.configure(verbose_mode=verbose or debug)

        if not LIBOQS_AVAILABLE:
            raise ImportError(
                "liboqs-python is required for post-quantum cryptography. "
                "Install with: pip install liboqs-python"
            )

        # Check if algorithm is deprecated and issue warning
        if isinstance(algorithm, str) and is_deprecated(algorithm):
            replacement = get_recommended_replacement(algorithm)
            warn_deprecated_algorithm(algorithm, "PQCipher initialization")
            if not should_be_quiet and replacement and verbose:
                eprint(f"Warning: The algorithm '{algorithm}' is deprecated.")
                eprint(f"Consider using '{replacement}' instead for better security.")

            # Try to normalize to standardized name if available
            standardized_name = normalize_algorithm_name(algorithm, use_standard=True)
            if standardized_name != algorithm:
                if not should_be_quiet and verbose:
                    eprint(
                        f"Using standardized algorithm name '{standardized_name}' instead of '{algorithm}'"
                    )
                algorithm = standardized_name

        # Check if encryption_data is deprecated
        if is_deprecated(encryption_data):
            data_replacement = get_recommended_replacement(encryption_data)
            warn_deprecated_algorithm(encryption_data, "PQC data encryption")
            # Only show direct warning messages if verbose or not an INFO level warning
            if not should_be_quiet and data_replacement and verbose:
                eprint(f"Warning: The data encryption algorithm '{encryption_data}' is deprecated.")
                eprint(f"Consider using '{data_replacement}' instead for better security.")

        # Store the encryption_data parameter
        self.encryption_data = encryption_data

        # Import required symmetric encryption algorithms
        try:
            from cryptography.hazmat.primitives.ciphers.aead import (
                AESGCM,
                AESGCMSIV,
                AESSIV,
                ChaCha20Poly1305,
            )

            self.AESGCM = AESGCM
            self.ChaCha20Poly1305 = ChaCha20Poly1305
            self.AESSIV = AESSIV
            self.AESGCMSIV = AESGCMSIV
        except ImportError:
            raise ImportError("The 'cryptography' library is required")

        # Check available algorithms
        supported = check_pqc_support(quiet=should_be_quiet)[2]

        # Store quiet mode and debug mode for use in other methods
        self.quiet = should_be_quiet
        self.debug = debug

        # Map the requested algorithm to an available one
        if isinstance(algorithm, str):
            # Convert string to actual algorithm name
            requested_algo = algorithm

            # Try to normalize to standard name first
            standard_name = normalize_algorithm_name(requested_algo, use_standard=True)

            # If we have a standardized name different from the original, use it preferentially
            if standard_name != requested_algo and standard_name in supported:
                self.algorithm_name = standard_name
                # Log a deprecation warning if we're using a legacy name
                if not should_be_quiet:
                    eprint(
                        f"Warning: Algorithm name '{requested_algo}' is deprecated. "
                        f"Using standardized name '{standard_name}' instead."
                    )
            # Otherwise, check if the original name is supported
            elif requested_algo in supported:
                self.algorithm_name = requested_algo
            else:
                # As a fallback, look for variants (with/without hyphens, case insensitive)
                requested_base = requested_algo.lower().replace("-", "").replace("_", "")

                # For each supported algorithm, see if it's a variant of the requested one
                matched = False
                for supported_algo in supported:
                    supported_base = supported_algo.lower().replace("-", "").replace("_", "")

                    # Check if the algorithm names match after normalization
                    if supported_base == requested_base:
                        self.algorithm_name = supported_algo
                        matched = True
                        break

                    if ("kyber" in requested_base or "mlkem" in requested_base) and (
                        "kyber" in supported_base or "mlkem" in supported_base
                    ):
                        # Extract the security level (number)
                        req_level = "".join(c for c in requested_base if c.isdigit())
                        sup_level = "".join(c for c in supported_base if c.isdigit())

                        if req_level and sup_level and req_level == sup_level:
                            self.algorithm_name = supported_algo
                            matched = True
                            break

                if not matched:
                    # SECURITY (H3): never silently downgrade to a different
                    # (potentially weaker) algorithm - fail loudly. 1.5 already
                    # raises here; the security property matches the 1.4 fix.
                    raise ValueError(
                        f"Unsupported PQC algorithm: '{algorithm}'. "
                        f"Available algorithms: {', '.join(sorted(supported))}"
                    )

        elif isinstance(algorithm, PQCAlgorithm):
            # Enum value
            if algorithm.value in supported:
                self.algorithm_name = algorithm.value
            else:
                # Legacy enum values (e.g. Kyber768) must still resolve to their
                # standardized equivalent (ML-KEM-768) at the SAME security level.
                standard_name = normalize_algorithm_name(algorithm.value, use_standard=True)
                if standard_name in supported:
                    self.algorithm_name = standard_name
                else:
                    # SECURITY (H3): fail loudly rather than "hope for the best"
                    # with an unsupported enum value (1.5 already raises here).
                    raise ValueError(
                        f"Unsupported PQC algorithm: '{algorithm.value}'. "
                        f"Available algorithms: {', '.join(sorted(supported))}"
                    )

        # Report the actual algorithm being used
        if not self.quiet and verbose:
            eprint(f"Using algorithm: {self.algorithm_name}")

        # All Kyber/ML-KEM/HQC algorithms are KEM algorithms
        self.is_kem = any(x in self.algorithm_name.lower() for x in ["ml-kem", "kyber", "hqc"])

    def _derive_symmetric_key(self, shared_secret: bytes, key_length: int = 32) -> bytes:
        """Derive a symmetric key from a KEM shared secret.

        For format_version >= 12: uses HKDF-SHA256 with algorithm name as info,
        providing proper domain separation and extract-then-expand semantics.

        For legacy formats (< 12 or None): uses bare SHA-256 for backward
        compatibility with existing encrypted files.

        Args:
            shared_secret: Raw shared secret from KEM encapsulation/decapsulation.
            key_length: Desired key length in bytes (default 32 for AES-256).

        Returns:
            Derived symmetric key bytes.
        """
        if self.format_version is not None and self.format_version >= 12:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            return HKDF(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=None,
                info=b"openssl_encrypt-kem-key-" + self.algorithm_name.encode(),
            ).derive(shared_secret)
        else:
            return hashlib.sha256(shared_secret).digest()

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a post-quantum keypair

        Returns:
            Tuple[bytes, bytes]: (public_key, private_key)
        """
        if not self.is_kem:
            raise ValueError("This method is only supported for KEM algorithms")

        try:
            with oqs.KeyEncapsulation(self.algorithm_name) as kem:
                try:
                    public_key = kem.generate_keypair()
                    private_key = kem.export_secret_key()
                except AttributeError:
                    # Some versions use different method names
                    if hasattr(kem, "keypair"):
                        public_key = kem.keypair()
                    else:
                        # Try alternate API
                        kem.generate_keypair()
                        public_key = kem.export_public_key()

                    private_key = kem.export_secret_key()

            return public_key, private_key
        except Exception as e:
            if not self.quiet:
                eprint(f"Error generating keypair: {e}")
                # For debugging, show what methods are available
                with oqs.KeyEncapsulation(self.algorithm_name) as kem:
                    eprint(f"Available methods: {dir(kem)}")
            raise

    def encapsulate_only(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Perform KEM encapsulation only (without data encryption).

        This is used for password wrapping in asymmetric mode where we need
        the shared secret to wrap a password, but don't directly encrypt data.

        Args:
            public_key (bytes): Recipient's public key

        Returns:
            Tuple[bytes, bytes]: (shared_secret, encapsulated_key)

        Note:
            Caller is responsible for secure memory handling of shared_secret.
            Use SecureBytes and call secure_memzero() after use.
        """
        if not self.is_kem:
            raise ValueError("This method is only supported for KEM algorithms")

        shared_secret = None

        try:
            with oqs.KeyEncapsulation(self.algorithm_name) as kem:
                # Encapsulate to get shared secret
                encapsulated_key, shared_secret = kem.encap_secret(public_key)

                if self.debug:
                    logger.debug(
                        f"KEM encapsulation: encapsulated_key={len(encapsulated_key)} bytes, "
                        f"shared_secret={len(shared_secret)} bytes"
                    )

                # Return (shared_secret, encapsulated_key) - caller must handle secure cleanup
                return shared_secret, encapsulated_key

        except Exception as e:
            if not self.quiet:
                eprint(f"Error in KEM encapsulation: {e}")
            # Clean up on error
            if shared_secret is not None:
                secure_memzero(shared_secret)
            raise ValueError(f"KEM encapsulation failed: {e}")

    def decapsulate_only(self, encapsulated_key: bytes, private_key: bytes) -> bytes:
        """
        Perform KEM decapsulation only (without data decryption).

        This is used for password unwrapping in asymmetric mode where we need
        to recover the shared secret from the encapsulated key.

        Args:
            encapsulated_key (bytes): Encapsulated key from sender
            private_key (bytes): Recipient's private key

        Returns:
            bytes: Shared secret

        Note:
            Caller is responsible for secure memory handling.
            Use SecureBytes and call secure_memzero() after use.
        """
        if not self.is_kem:
            raise ValueError("This method is only supported for KEM algorithms")

        shared_secret = None

        try:
            # Create KeyEncapsulation with private key
            with oqs.KeyEncapsulation(self.algorithm_name, private_key) as kem:
                # Decapsulate to recover shared secret (only takes encapsulated_key)
                shared_secret = kem.decap_secret(encapsulated_key)

                if self.debug:
                    logger.debug(f"KEM decapsulation: shared_secret={len(shared_secret)} bytes")

                # Return shared secret - caller must handle secure cleanup
                return shared_secret

        except Exception as e:
            if not self.quiet:
                eprint(f"Error in KEM decapsulation: {e}")
            # Clean up on error
            if shared_secret is not None:
                secure_memzero(shared_secret)
            raise ValueError(f"KEM decapsulation failed: {e}")

    def encrypt(self, data: bytes, public_key: bytes, aad: bytes = None) -> bytes:
        """
        Encrypt data using a hybrid post-quantum + symmetric approach

        Args:
            data (bytes): The data to encrypt
            public_key (bytes): The recipient's public key
            aad (bytes, optional): Additional authenticated data for AEAD binding

        Returns:
            bytes: The encrypted data format: encapsulated_key + nonce + ciphertext
        """
        if not self.is_kem:
            raise ValueError("This method is only supported for KEM algorithms")

        if self.debug:
            logger.debug(f"ENCRYPT:PQC_KEM Algorithm: {self.algorithm_name}")
            logger.debug(f"ENCRYPT:PQC_KEM Public key length: {len(public_key)} bytes")
            logger.debug(f"ENCRYPT:PQC_KEM Input data length: {len(data)} bytes")
            logger.debug(f"ENCRYPT:PQC_KEM Symmetric encryption: {self.encryption_data}")

        # SECURITY (CRIT-1): Test environment detection has been removed.
        # All encryptions now use real PQC KEM regardless of environment.
        shared_secret = None
        symmetric_key = None

        try:
            # Use PQC KEM to establish a shared secret
            with oqs.KeyEncapsulation(self.algorithm_name) as kem:
                # Encapsulate a shared secret with the public key
                encapsulated_key, shared_secret = kem.encap_secret(public_key)

                # Derive symmetric key from shared secret
                symmetric_key = self._derive_symmetric_key(shared_secret)

                # Generate random nonce (12 bytes for most AEAD ciphers)
                nonce = secrets.token_bytes(12)

                # Select cipher based on encryption_data setting
                if self.encryption_data == "aes-gcm":
                    cipher = self.AESGCM(symmetric_key)
                elif self.encryption_data == "chacha20-poly1305":
                    cipher = self.ChaCha20Poly1305(symmetric_key)
                elif self.encryption_data == "xchacha20-poly1305":
                    try:
                        from openssl_encrypt.modules.crypt_core import XChaCha20Poly1305

                        cipher = XChaCha20Poly1305(symmetric_key)
                    except ImportError:
                        cipher = self.ChaCha20Poly1305(symmetric_key)
                elif self.encryption_data == "aes-gcm-siv":
                    cipher = self.AESGCMSIV(symmetric_key)
                elif self.encryption_data == "aes-siv":
                    cipher = self.AESSIV(symmetric_key)
                elif self.encryption_data in ("threefish-512", "threefish-1024"):
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

                    import threefish_native

                    key_len = 64 if self.encryption_data == "threefish-512" else 128
                    expanded_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=key_len,
                        salt=None,
                        info=self.encryption_data.encode() + b"-pqc-key-expansion",
                    ).derive(symmetric_key)
                    # Threefish-512 needs 32-byte nonce, Threefish-1024 needs 64-byte nonce
                    nonce_len = 32 if self.encryption_data == "threefish-512" else 64
                    tf_nonce = secrets.token_bytes(nonce_len)
                    if self.encryption_data == "threefish-512":
                        ciphertext = threefish_native.encrypt_512(expanded_key, tf_nonce, data, aad)
                    else:
                        ciphertext = threefish_native.encrypt_1024(
                            expanded_key, tf_nonce, data, aad
                        )
                    result = encapsulated_key + tf_nonce + ciphertext
                    return result
                else:
                    cipher = self.AESGCM(symmetric_key)

                # AES-SIV has a different API: encrypt(data, [associated_data])
                if self.encryption_data == "aes-siv":
                    aad_list = [nonce]
                    if aad:
                        aad_list.append(aad)
                    ciphertext = cipher.encrypt(data, aad_list)
                else:
                    ciphertext = cipher.encrypt(nonce, data, aad)

                # Format: encapsulated_key + nonce + ciphertext
                result = encapsulated_key + nonce + ciphertext

                return result

        except Exception as e:
            if not self.quiet:
                eprint(f"Error in post-quantum encryption: {e}")
            raise ValueError(f"PQC encryption failed: {e}")
        finally:
            # Clean up sensitive data
            if shared_secret is not None:
                secure_memzero(shared_secret)
            if symmetric_key is not None:
                secure_memzero(symmetric_key)

    def decrypt(
        self,
        encrypted_data: bytes,
        private_key: bytes,
        file_contents: bytes = None,
        aad: bytes = None,
    ) -> bytes:
        """
        Decrypt data that was encrypted with the corresponding public key

        Args:
            encrypted_data (bytes): The encrypted data
            private_key (bytes): The recipient's private key
            file_contents (bytes, optional): The full original encrypted file contents
                                           for recovery if direct decryption fails
            aad (bytes, optional): Additional authenticated data (must match encryption AAD)

        Returns:
            bytes: The decrypted data

        Raises:
            ValueError: If decryption fails
        """
        logger.debug(
            f"DECRYPT:PQC_KEM decrypt() called with encrypted_data length: {len(encrypted_data)}"
        )
        logger.debug(f"DECRYPT:PQC_KEM encrypted_data starts with: {encrypted_data[:50]}")

        if not self.is_kem:
            raise ValueError("This method is only supported for KEM algorithms")

        if self.debug:
            logger.debug(f"DECRYPT:PQC_KEM Algorithm: {self.algorithm_name}")
            logger.debug(f"DECRYPT:PQC_KEM Private key length: {len(private_key)} bytes")
            logger.debug(f"DECRYPT:PQC_KEM Encrypted data length: {len(encrypted_data)} bytes")
            logger.debug(f"DECRYPT:PQC_KEM Symmetric encryption: {self.encryption_data}")

        # Initialize variables for later cleanup
        shared_secret = None
        symmetric_key = None

        try:
            # Import the KeyEncapsulation object
            with oqs.KeyEncapsulation(self.algorithm_name, private_key) as kem:
                # Determine size of encapsulated key
                # Some liboqs-python versions return 0 from struct properties;
                # fall back to kem.details dict which always works.
                kem_ciphertext_size = kem.length_ciphertext
                shared_secret_len = kem.length_shared_secret
                if kem_ciphertext_size == 0 and hasattr(kem, "details"):
                    kem_ciphertext_size = kem.details.get("length_ciphertext", 0)
                if shared_secret_len == 0 and hasattr(kem, "details"):
                    shared_secret_len = kem.details.get("length_shared_secret", 32)

                if self.debug:
                    logger.debug(f"DECRYPT:PQC_KEM encrypted_data length: {len(encrypted_data)}")
                    logger.debug(f"DECRYPT:PQC_KEM kem_ciphertext_size: {kem_ciphertext_size}")
                    logger.debug(
                        f"DECRYPT:PQC_KEM encrypted_data starts with: {encrypted_data[:50]}"
                    )

                # Split the encrypted data into encapsulated key and remaining data
                encapsulated_key = encrypted_data[:kem_ciphertext_size]
                remaining_data = encrypted_data[kem_ciphertext_size:]

                # Standard format: remaining_data = nonce + ciphertext
                if len(remaining_data) < 12:
                    raise ValueError(
                        "Encrypted data too short: missing nonce. " "The file may be corrupted."
                    )

                nonce = remaining_data[:12]
                ciphertext = remaining_data[12:]

                # No need for debug output on nonce

                # Standard KEM decapsulation (production path)
                try:
                    shared_secret = kem.decap_secret(encapsulated_key)
                except Exception as e1:
                    if self.debug:
                        logger.debug(f"decap_secret failed: {e1}")

                    # Try decaps_cb if available as alternative API
                    if hasattr(kem, "decaps_cb") and callable(kem.decaps_cb):
                        try:
                            shared_secret_buffer = bytearray(shared_secret_len)
                            result = kem.decaps_cb(
                                shared_secret_buffer, encapsulated_key, private_key
                            )
                            if result == 0:  # Success
                                shared_secret = bytes(shared_secret_buffer)
                        except Exception as e2:
                            if self.debug:
                                logger.debug(f"decaps_cb failed: {e2}")

                # SECURITY (CRIT-3): Do NOT fall back to simulation mode
                # when real decapsulation fails. Raise an error instead.
                if shared_secret is None:
                    raise ValueError(
                        "KEM decapsulation failed. Unable to recover shared secret. "
                        "The file may be corrupted or the wrong private key was provided."
                    )

                # No need to log shared secret details

                # Convert to bytes if still bytearray
                if isinstance(shared_secret, bytearray):
                    shared_secret = bytes(shared_secret)

                # Derive the symmetric key using secure memory operations
                with SecureBytes(shared_secret) as secure_shared_secret:
                    symmetric_key = SecureBytes(
                        self._derive_symmetric_key(bytes(secure_shared_secret))
                    )

                # Get the encryption_data from the metadata if available
                metadata_encryption_data = None
                if file_contents:
                    try:
                        # Try to extract encryption_data from metadata
                        import base64
                        import json

                        # Common metadata extraction pattern for our file format
                        # (peel a hidden/whitened file to legacy-equivalent bytes first)
                        from .hidden_header import to_legacy_bytes

                        parts = to_legacy_bytes(file_contents).split(b":", 1)
                        if len(parts) > 1 and len(parts[0]) > 0:
                            try:
                                metadata_json = base64.b64decode(parts[0]).decode("utf-8")
                                metadata = json.loads(metadata_json)
                                if isinstance(metadata, dict):
                                    # Check v5 format first (nested encryption section)
                                    if "encryption" in metadata and isinstance(
                                        metadata["encryption"], dict
                                    ):
                                        metadata_encryption_data = metadata["encryption"].get(
                                            "encryption_data"
                                        )
                                    # Then check for top-level field (older formats)
                                    elif "encryption_data" in metadata:
                                        metadata_encryption_data = metadata["encryption_data"]
                            except Exception as e:
                                if not self.quiet:
                                    eprint(f"Error extracting encryption_data from metadata: {e}")
                    except Exception as e:
                        # Ignore extraction errors
                        pass

                # Validate encryption_data against metadata if available
                if metadata_encryption_data and self.encryption_data != metadata_encryption_data:
                    if not self.quiet:
                        eprint(
                            f"Error: Encryption data mismatch - provided '{self.encryption_data}' but metadata has '{metadata_encryption_data}'"
                        )
                    raise ValueError(
                        f"Encryption data algorithm mismatch: provided '{self.encryption_data}' but metadata has '{metadata_encryption_data}'"
                    )

                # Select the appropriate cipher based on encryption_data
                if self.encryption_data == "aes-gcm":
                    cipher = self.AESGCM(symmetric_key)
                elif self.encryption_data == "chacha20-poly1305":
                    cipher = self.ChaCha20Poly1305(symmetric_key)
                elif self.encryption_data == "xchacha20-poly1305":
                    # Use the custom XChaCha20Poly1305 implementation from crypt_core
                    try:
                        from openssl_encrypt.modules.crypt_core import XChaCha20Poly1305

                        cipher = XChaCha20Poly1305(symmetric_key)
                    except ImportError as e:
                        if not self.quiet:
                            eprint(
                                f"XChaCha20Poly1305 not available ({e}), falling back to ChaCha20Poly1305"
                            )
                        cipher = self.ChaCha20Poly1305(symmetric_key)
                    except Exception as e:
                        if not self.quiet:
                            eprint(
                                f"XChaCha20Poly1305 creation failed ({e}), falling back to ChaCha20Poly1305"
                            )
                        cipher = self.ChaCha20Poly1305(symmetric_key)
                elif self.encryption_data == "aes-gcm-siv":
                    cipher = self.AESGCMSIV(symmetric_key)
                elif self.encryption_data == "aes-siv":
                    cipher = self.AESSIV(symmetric_key)
                elif self.encryption_data in ("threefish-512", "threefish-1024"):
                    # Threefish uses threefish_native module directly, not AEAD cipher classes
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

                    import threefish_native

                    # Expand 32-byte shared secret to required key length via HKDF
                    key_len = 64 if self.encryption_data == "threefish-512" else 128
                    expanded_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=key_len,
                        salt=None,
                        info=self.encryption_data.encode() + b"-pqc-key-expansion",
                    ).derive(symmetric_key)

                    # Threefish-512 uses 32-byte nonce, Threefish-1024 uses 64-byte nonce
                    nonce_len = 32 if self.encryption_data == "threefish-512" else 64
                    nonce = remaining_data[:nonce_len]
                    ciphertext = remaining_data[nonce_len:]
                    if self.encryption_data == "threefish-512":
                        plaintext = threefish_native.decrypt_512(
                            expanded_key, nonce, ciphertext, aad
                        )
                    else:
                        plaintext = threefish_native.decrypt_1024(
                            expanded_key, nonce, ciphertext, aad
                        )
                    return plaintext
                else:
                    # Default to AES-GCM for unknown algorithms
                    if not self.quiet:
                        eprint(
                            f"Unknown encryption algorithm {self.encryption_data}, falling back to aes-gcm"
                        )
                    cipher = self.AESGCM(symmetric_key)
                # SECURITY (CRIT-1): Empty ciphertext recovery and negative
                # test pattern detection have been removed from production code.
                if len(ciphertext) == 0:
                    raise ValueError(
                        "Decryption failed: empty ciphertext. "
                        "The file may be corrupted or was encrypted with legacy test mode."
                    )

                # Decrypt using the selected AEAD cipher
                try:
                    with SecureBytes() as secure_plaintext:
                        # AES-SIV has a different API: decrypt(data, [associated_data])
                        if self.encryption_data == "aes-siv":
                            aad_list = [nonce]
                            if aad:
                                aad_list.append(aad)
                            decrypted = cipher.decrypt(ciphertext, aad_list)
                        else:
                            decrypted = cipher.decrypt(nonce, ciphertext, aad)
                        secure_plaintext.extend(decrypted)
                        # Zero out the intermediate decrypted data
                        if isinstance(decrypted, bytearray):
                            secure_memzero(decrypted)
                        if self.debug:
                            logger.debug(f"Decryption successful, length: {len(secure_plaintext)}")
                        return bytes(secure_plaintext)

                except Exception as e:
                    # SECURITY (CRIT-2): No fallback to unauthenticated ciphers.
                    logger.warning(
                        "AEAD decryption failed. No fallback to unauthenticated "
                        "ciphers is permitted."
                    )
                    raise ValueError("Decryption failed: authentication error")
        except Exception as e:
            if not self.quiet:
                eprint(f"Error in post-quantum decryption: {e}")
            if "kem" in locals():
                if not self.quiet:
                    eprint(f"Available methods on KEM object: {dir(kem)}")
            raise
        finally:
            # Clean up sensitive data
            if shared_secret:
                secure_memzero(shared_secret)
            if symmetric_key:
                secure_memzero(symmetric_key)
