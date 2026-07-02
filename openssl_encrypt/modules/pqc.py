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


def public_key_part(private_key: bytes) -> bytes:
    """
    Extract a deterministic public-key-like value from a private key.

    .. deprecated::
        This function is only retained for backward-compatible decryption of
        files encrypted with the legacy simulation mode. It MUST NOT be used
        for new encryptions (CRIT-3).

    Args:
        private_key: The private key bytes

    Returns:
        bytes: A deterministic identifier derived from the private key
    """
    # Use secure memory for operations with private key data
    with SecureBytes(private_key) as secure_private_key:
        if len(secure_private_key) <= 16:
            return bytes(secure_private_key)
        else:
            return bytes(secure_private_key[:16])


# Environment variable to control PQC initialization messages

# Try to import PQC libraries, provide fallbacks if not available
LIBOQS_AVAILABLE = False
oqs = None

# Check for quiet mode environment variable
PQC_QUIET = os.environ.get("PQC_QUIET", "").lower() in ("1", "true", "yes", "on")


def _env_allow_legacy_testdata() -> bool:
    """Whether reading the insecure legacy TESTDATA formats is opted in via env.

    Resolved at decrypt time so the environment can enable legacy migration
    without any code change; defaults to disabled (secure). See issue #54.
    """
    return os.environ.get("OPENSSL_ENCRYPT_ALLOW_LEGACY_TESTDATA", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


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

    # Legacy Kyber naming scheme (deprecated, will be removed in future)
    # For backward compatibility only
    KYBER512 = "Kyber512"  # Deprecated: use ML_KEM_512 instead
    KYBER768 = "Kyber768"  # Deprecated: use ML_KEM_768 instead
    KYBER1024 = "Kyber1024"  # Deprecated: use ML_KEM_1024 instead

    # Legacy format with hyphens (deprecated, will be removed in future)
    KYBER512_LEGACY = "Kyber-512"  # Deprecated: use ML_KEM_512 instead
    KYBER768_LEGACY = "Kyber-768"  # Deprecated: use ML_KEM_768 instead
    KYBER1024_LEGACY = "Kyber-1024"  # Deprecated: use ML_KEM_1024 instead

    # Signature algorithms (NIST FIPS 204/205/206 standardized naming)
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
    # Kyber/ML-KEM mappings
    "Kyber512": "ML-KEM-512",
    "Kyber768": "ML-KEM-768",
    "Kyber1024": "ML-KEM-1024",
    "Kyber-512": "ML-KEM-512",
    "Kyber-768": "ML-KEM-768",
    "Kyber-1024": "ML-KEM-1024",
    "kyber512-hybrid": "ml-kem-512-hybrid",
    "kyber768-hybrid": "ml-kem-768-hybrid",
    "kyber1024-hybrid": "ml-kem-1024-hybrid",
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
                # Add legacy names for backward compatibility
                supported_algorithms.extend(["Kyber512", "Kyber768", "Kyber1024"])
        except Exception:
            # Force add all KEM algorithms as fallback
            # Prioritize ML-KEM (standardized) names
            supported_algorithms.extend(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
            # Add legacy names for backward compatibility
            supported_algorithms.extend(["Kyber512", "Kyber768", "Kyber1024"])

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
            [
                "ML-KEM-512",
                "ML-KEM-768",
                "ML-KEM-1024",
                "Kyber512",
                "Kyber768",
                "Kyber1024",
            ],
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
        allow_legacy_testdata: bool = False,
    ):
        """
        Initialize a post-quantum cipher instance

        Args:
            algorithm (Union[PQCAlgorithm, str]): The post-quantum algorithm to use
            quiet (bool): Whether to suppress output messages
            encryption_data (str): Symmetric encryption algorithm to use ('aes-gcm', 'chacha20-poly1305', etc.)
            verbose (bool): Whether to show detailed information
            debug (bool): Whether to show debug level information

        Raises:
            ValueError: If liboqs is not available or algorithm not supported
            ImportError: If required dependencies are missing
        """
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
            # Only show direct warning messages if verbose or not an INFO warning about Kyber vs ML-KEM
            kyber_or_mlkem_warning = "kyber" in algorithm.lower() or "ml-kem" in algorithm.lower()
            if not should_be_quiet and replacement and (verbose or not kyber_or_mlkem_warning):
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
                AESOCB3,
                AESSIV,
                ChaCha20Poly1305,
            )

            self.AESGCM = AESGCM
            self.ChaCha20Poly1305 = ChaCha20Poly1305
            self.AESSIV = AESSIV
            self.AESGCMSIV = AESGCMSIV
            self.AESOCB3 = AESOCB3
        except ImportError:
            raise ImportError("The 'cryptography' library is required")

        # Check available algorithms
        supported = check_pqc_support(quiet=should_be_quiet)[2]

        # Store quiet mode and debug mode for use in other methods
        self.quiet = should_be_quiet
        self.debug = debug

        # SECURITY: the legacy TESTDATA / PQC_TEST_DATA "simulation" formats
        # bypass real encryption and are only readable when explicitly opted in
        # (this argument or OPENSSL_ENCRYPT_ALLOW_LEGACY_TESTDATA env var). Normal
        # decryption must never take that passthrough path, otherwise a crafted
        # file forges arbitrary plaintext with no key (issue #54). The env var is
        # resolved at decrypt time via _env_allow_legacy_testdata().
        self.allow_legacy_testdata = bool(allow_legacy_testdata)

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

                    # Also match on name and number (e.g., Kyber512 matches ML-KEM-512)
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
                    # (potentially weaker) algorithm. A request we cannot resolve
                    # exactly must fail loudly so the caller can correct it, rather
                    # than be served an arbitrary "first available" KEM.
                    kem_supported = sorted(
                        {
                            alg
                            for alg in supported
                            if any(x in alg.lower() for x in ["kyber", "ml-kem", "hqc"])
                        }
                    )
                    raise ValueError(
                        f"Unsupported or unavailable post-quantum algorithm: "
                        f"'{requested_algo}'. Refusing to silently downgrade to a "
                        f"different algorithm. Available KEM algorithms: "
                        f"{', '.join(kem_supported) or '(none)'}"
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
                    # Look for variants (normalized, case/hyphen-insensitive)
                    for supported_algo in supported:
                        if algorithm.value.lower().replace(
                            "-", ""
                        ) == supported_algo.lower().replace("-", ""):
                            self.algorithm_name = supported_algo
                            break
                    else:
                        # SECURITY (H3): do not "hope for the best" with an
                        # unsupported enum value — fail loudly rather than risk a
                        # silent downgrade or an opaque downstream failure.
                        raise ValueError(
                            f"Unsupported or unavailable post-quantum algorithm: "
                            f"'{algorithm.value}'. Refusing to silently downgrade. "
                            f"Available algorithms: {', '.join(sorted(set(supported))) or '(none)'}"
                        )

        # Report the actual algorithm being used
        if not self.quiet and verbose:
            eprint(f"Using algorithm: {self.algorithm_name}")

        # All Kyber/ML-KEM/HQC algorithms are KEM algorithms
        self.is_kem = any(x in self.algorithm_name.lower() for x in ["kyber", "ml-kem", "hqc"])

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
                symmetric_key = hashlib.sha256(shared_secret).digest()

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
                elif self.encryption_data == "aes-ocb3":
                    cipher = self.AESOCB3(symmetric_key)
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

                # SECURITY (CRIT-1 / issue #54): the legacy TESTDATA and
                # PQC_TEST_DATA formats bypass real encryption and authentication.
                # They are only honoured when the caller has explicitly opted in
                # via allow_legacy_testdata (constructor arg or env var); otherwise
                # a crafted file starting with these magic bytes would "decrypt"
                # to attacker-chosen plaintext with no key. When not opted in, the
                # data falls through to real KEM decapsulation, which authenticates.
                _legacy_testdata_header = b"PQC_TEST_DATA:"
                _legacy_testdata_marker = b"TESTDATA"
                _allow_legacy = (
                    getattr(self, "allow_legacy_testdata", False) or _env_allow_legacy_testdata()
                )

                if _allow_legacy and encrypted_data.startswith(_legacy_testdata_header):
                    logger.warning(
                        "DEPRECATION WARNING: Decrypting legacy PQC_TEST_DATA format. "
                        "This format bypasses real encryption and will be removed in a future version. "
                        "Re-encrypt this file with real PQC keys."
                    )
                    plaintext = encrypted_data[len(_legacy_testdata_header) :]
                    return plaintext

                elif _allow_legacy and encrypted_data.startswith(_legacy_testdata_marker):
                    logger.warning(
                        "DEPRECATION WARNING: Decrypting legacy TESTDATA format. "
                        "This format bypasses real encryption and will be removed in a future version. "
                        "Re-encrypt this file with real PQC keys."
                    )
                    data_len_bytes = encrypted_data[8:12]
                    data_len = int.from_bytes(data_len_bytes, byteorder="big")
                    if 0 <= data_len <= len(encrypted_data) - 12:
                        return encrypted_data[12 : 12 + data_len]
                    else:
                        return encrypted_data[12:]

                # Split the encrypted data into KEM ciphertext + symmetric payload
                encapsulated_key = encrypted_data[:kem_ciphertext_size]
                remaining_data = encrypted_data[kem_ciphertext_size:]

                if self.debug:
                    logger.debug(
                        f"DECRYPT:PQC_KEM Encapsulated key starts with: {encapsulated_key[:20]}"
                    )

                # Legacy TESTDATA embedded in encapsulated_key slot (opt-in only)
                if _allow_legacy and encapsulated_key.startswith(_legacy_testdata_marker):
                    logger.warning(
                        "DEPRECATION WARNING: Decrypting legacy TESTDATA format "
                        "(embedded in KEM ciphertext slot). "
                        "Re-encrypt this file with real PQC keys."
                    )
                    data_len_bytes = encapsulated_key[8:12]
                    if data_len_bytes == b"\xff\xff\xff\xff":
                        # Data stored after test nonce in remaining_data
                        test_nonce_pos = remaining_data.find(b"TESTNONCE123")
                        if test_nonce_pos != -1:
                            test_data_start = test_nonce_pos + 12
                            if test_data_start < len(remaining_data):
                                payload = remaining_data[test_data_start:]
                                if payload.startswith(_legacy_testdata_header):
                                    return payload[len(_legacy_testdata_header) :]
                    else:
                        data_len = int.from_bytes(data_len_bytes, byteorder="big")
                        if 0 <= data_len <= len(encapsulated_key) - 12:
                            return encapsulated_key[12 : 12 + data_len]

                # Standard format: remaining_data = nonce + ciphertext
                if len(remaining_data) < 12:
                    raise ValueError(
                        "Encrypted data too short: missing nonce. " "The file may be corrupted."
                    )

                nonce = remaining_data[:12]
                ciphertext = remaining_data[12:]

                # No need for debug output on nonce

                # Check if this is a simulated ciphertext (legacy format).
                # SECURITY (CRIT-3 / issue #65): simulation mode derives a weak
                # deterministic shared secret from largely public data. Like the
                # TESTDATA formats it is only honoured under the explicit
                # allow_legacy_testdata opt-in; otherwise a crafted SIMULATED_PQC
                # prefix would force an attacker-selectable downgrade on the normal
                # decrypt path. When not opted in, the header is treated as an
                # ordinary (bogus) KEM ciphertext and fails authentication.
                sim_header = b"SIMULATED_PQC_v1"
                simulation_detected = False

                if (
                    _allow_legacy
                    and len(encapsulated_key) >= len(sim_header)
                    and encapsulated_key[: len(sim_header)] == sim_header
                ):
                    simulation_detected = True

                # Initialize the shared secret with None to detect success
                shared_secret = None

                # SECURITY (CRIT-3): Simulation mode is only allowed for
                # backward-compatible DECRYPTION of legacy files.
                # New encryptions never use simulation mode.
                if simulation_detected:
                    # Legacy simulation mode detected - warn prominently
                    logger.warning(
                        "SECURITY WARNING: This file was encrypted with weak "
                        "simulation mode (deterministic shared secret). "
                        "Re-encrypt this file with real PQC keys for proper security."
                    )
                    if not self.quiet:
                        eprint(
                            "SECURITY WARNING: Decrypting legacy simulation-mode file. "
                            "This mode uses a weak deterministic secret. "
                            "Re-encrypt with real PQC keys."
                        )
                    # Use the legacy deterministic approach for decryption only
                    with SecureBytes() as secure_input:
                        secure_input.extend(encapsulated_key)
                        secure_input.extend(public_key_part(private_key))
                        shared_secret = SecureBytes(
                            hashlib.sha256(secure_input).digest()[:shared_secret_len]
                        )
                else:
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
                    symmetric_key = SecureBytes(hashlib.sha256(secure_shared_secret).digest())

                # Get the encryption_data from the metadata if available
                metadata_encryption_data = None
                if file_contents:
                    try:
                        # Try to extract encryption_data from metadata
                        import base64
                        import json

                        # Common metadata extraction pattern for our file format
                        parts = file_contents.split(b":", 1)
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
                elif self.encryption_data == "aes-ocb3":
                    cipher = self.AESOCB3(symmetric_key)
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
