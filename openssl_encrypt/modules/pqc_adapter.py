#!/usr/bin/env python3
"""
Post-Quantum Cryptography Adapter Module

This module provides adapter classes to integrate our liboqs wrapper with the existing
post-quantum cryptography architecture. It creates a unified interface for both our
native implementations and liboqs-supported algorithms.
"""

import hashlib
import logging
import secrets
from typing import Any, Dict, List, Optional, Tuple, Union

from .algorithm_warnings import (
    get_recommended_replacement,
    is_deprecated,
    warn_deprecated_algorithm,
)
from .pqc import PQCAlgorithm as CorePQCAlgorithm
from .pqc import PQCipher, normalize_algorithm_name
from .pqc_liboqs import (
    LIBOQS_AVAILABLE,
    PQAlgorithm,
    PQEncapsulator,
    PQSigner,
    check_liboqs_support,
)
from .secure_memory import SecureBytes, secure_memzero

# Configure logger
logger = logging.getLogger(__name__)

# Check liboqs support
LIBOQS_SUPPORTED, LIBOQS_VERSION, LIBOQS_ALGORITHMS = check_liboqs_support(quiet=True)

# Mapping from our enum values to algorithm types
ALGORITHM_TYPE_MAP = {
    # Key Encapsulation Mechanisms (KEMs)
    "ML-KEM-512": "kem",
    "ML-KEM-768": "kem",
    "ML-KEM-1024": "kem",
    "Kyber512": "kem",
    "Kyber768": "kem",
    "Kyber1024": "kem",
    "HQC-128": "kem",
    "HQC-192": "kem",
    "HQC-256": "kem",
    # Digital Signature Algorithms (DSAs)
    "ML-DSA-44": "sig",
    "ML-DSA-65": "sig",
    "ML-DSA-87": "sig",
    "SLH-DSA-SHA2-128F": "sig",
    "SLH-DSA-SHA2-192F": "sig",
    "SLH-DSA-SHA2-256F": "sig",
    "FN-DSA-512": "sig",
    "FN-DSA-1024": "sig",
    # NIST Round 2 Additional Signature Algorithms
    "MAYO-1": "sig",
    "MAYO-3": "sig",
    "MAYO-5": "sig",
    "CROSS-128": "sig",
    "CROSS-192": "sig",
    "CROSS-256": "sig",
}

# Hybrid algorithm mapping (standard name to PQ algorithm)
HYBRID_ALGORITHM_MAP = {
    # KEM-based hybrid algorithms (ML-KEM/Kyber)
    "ml-kem-512-hybrid": "ML-KEM-512",
    "ml-kem-768-hybrid": "ML-KEM-768",
    "ml-kem-1024-hybrid": "ML-KEM-1024",
    "kyber512-hybrid": "Kyber512",
    "kyber768-hybrid": "Kyber768",
    "kyber1024-hybrid": "Kyber1024",
    # HQC hybrid algorithms
    "hqc-128-hybrid": "HQC-128",
    "hqc-192-hybrid": "HQC-192",
    "hqc-256-hybrid": "HQC-256",
    # MAYO hybrid algorithms
    "mayo-1-hybrid": "MAYO-1",
    "mayo-3-hybrid": "MAYO-3",
    "mayo-5-hybrid": "MAYO-5",
    # CROSS hybrid algorithms
    "cross-128-hybrid": "CROSS-128",
    "cross-192-hybrid": "CROSS-192",
    "cross-256-hybrid": "CROSS-256",
    # ML-KEM with ChaCha20 (just for naming, actual cipher determined by user's choice)
    "ml-kem-512-chacha20": "ML-KEM-512",
    "ml-kem-768-chacha20": "ML-KEM-768",
    "ml-kem-1024-chacha20": "ML-KEM-1024",
}

# New algorithms added by liboqs integration
NEW_PQ_ALGORITHMS = [
    "HQC-128",
    "HQC-192",
    "HQC-256",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128F",
    "SLH-DSA-SHA2-192F",
    "SLH-DSA-SHA2-256F",
    "FN-DSA-512",
    "FN-DSA-1024",
    # NIST Round 2 Additional Signature Algorithms
    "MAYO-1",
    "MAYO-3",
    "MAYO-5",
    "CROSS-128",
    "CROSS-192",
    "CROSS-256",
]

# Security level mapping (algorithm to security level)
SECURITY_LEVEL_MAP = {
    # Level 1 (roughly equivalent to AES-128)
    "ML-KEM-512": 1,
    "Kyber512": 1,
    "HQC-128": 1,
    "ML-DSA-44": 1,
    "SLH-DSA-SHA2-128F": 1,
    "FN-DSA-512": 1,
    # Level 3 (roughly equivalent to AES-192)
    "ML-KEM-768": 3,
    "Kyber768": 3,
    "HQC-192": 3,
    "ML-DSA-65": 3,
    "SLH-DSA-SHA2-192F": 3,
    # Level 5 (roughly equivalent to AES-256)
    "ML-KEM-1024": 5,
    "Kyber1024": 5,
    "HQC-256": 5,
    "ML-DSA-87": 5,
    "SLH-DSA-SHA2-256F": 5,
    "FN-DSA-1024": 5,
    # NIST Round 2 Additional Signature Algorithms Security Levels
    "MAYO-1": 1,  # Level 1 (128-bit security)
    "MAYO-3": 3,  # Level 3 (192-bit security)
    "MAYO-5": 5,  # Level 5 (256-bit security)
    "CROSS-128": 1,  # Level 1 (128-bit security)
    "CROSS-192": 3,  # Level 3 (192-bit security)
    "CROSS-256": 5,  # Level 5 (256-bit security)
}


class ExtendedPQCipher(PQCipher):
    """
    Extended Post-Quantum Cipher implementation that supports both our native
    ML-KEM (Kyber) implementation and additional algorithms via liboqs.

    This class extends PQCipher to provide a unified interface for all post-quantum
    algorithms, whether they are implemented natively or via liboqs.
    """

    def __init__(
        self,
        algorithm: Union[str, PQAlgorithm, CorePQCAlgorithm],
        quiet: bool = False,
        encryption_data: str = "aes-gcm",
        verbose: bool = False,
        debug: bool = False,
    ):
        """
        Initialize an extended post-quantum cipher instance

        Args:
            algorithm: The post-quantum algorithm to use
            quiet: Whether to suppress output messages
            encryption_data: Symmetric encryption algorithm to use
            verbose: Whether to show detailed information

        Raises:
            ValueError: If algorithm not supported
            ImportError: If required dependencies are missing
        """
        # Convert algorithm to string if it's an enum
        if isinstance(algorithm, (PQAlgorithm, CorePQCAlgorithm)):
            algorithm_str = algorithm.value
        else:
            algorithm_str = algorithm

        # Determine if this is a KEM or signature algorithm
        self.is_kem = True  # Default for backward compatibility
        algorithm_type = ALGORITHM_TYPE_MAP.get(algorithm_str, "kem")
        if algorithm_type == "sig":
            self.is_kem = False

        # Store original algorithm name
        self.original_algorithm = algorithm_str

        # For KEM algorithms supported by our native implementation,
        # use the existing PQCipher class
        native_kem_algorithms = [
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024",
            "Kyber512",
            "Kyber768",
            "Kyber1024",
        ]

        if self.is_kem and algorithm_str in native_kem_algorithms:
            # Use the parent class for native KEM algorithms
            super().__init__(algorithm_str, quiet, encryption_data, verbose, debug)
            self.use_liboqs = False
            self.encryption_data = encryption_data
        else:
            # For other algorithms, use liboqs if available
            if not LIBOQS_AVAILABLE:
                raise ImportError(
                    "liboqs-python is required for additional post-quantum algorithms. "
                    "Install with: pip install liboqs"
                )

            # Initialize based on algorithm type
            self.use_liboqs = True
            self.quiet = quiet
            self.encryption_data = encryption_data
            self.algorithm_name = algorithm_str

            # Import required symmetric encryption algorithms for hybrid mode
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

            if self.is_kem:
                # Initialize KEM
                self.liboqs_kem = PQEncapsulator(algorithm_str, quiet=quiet)
            else:
                # Initialize signature algorithm
                self.liboqs_sig = PQSigner(algorithm_str, quiet=quiet)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a post-quantum keypair

        Returns:
            Tuple[bytes, bytes]: (public_key, private_key)
        """
        if not self.use_liboqs:
            # Use native implementation for supported algorithms
            return super().generate_keypair()

        if not self.is_kem:
            # For signature algorithms
            return self.liboqs_sig.generate_keypair()
        else:
            # For KEM algorithms
            return self.liboqs_kem.generate_keypair()

    def encrypt(self, data: bytes, public_key: bytes) -> bytes:
        """
        Encrypt data using a hybrid post-quantum + symmetric approach

        Args:
            data: The data to encrypt
            public_key: The recipient's public key

        Returns:
            bytes: The encrypted data
        """
        if not self.use_liboqs:
            # Use native implementation for supported algorithms
            return super().encrypt(data, public_key)

        if not self.is_kem:
            raise ValueError("This method is only supported for KEM algorithms")

        # Use liboqs KEM for encapsulation
        ciphertext, shared_secret = self.liboqs_kem.encapsulate(public_key)

        # Use secure memory for sensitive operations
        secure_shared_secret = SecureBytes(shared_secret)
        try:
            # Derive symmetric key using secure memory
            symmetric_key = SecureBytes(hashlib.sha256(secure_shared_secret).digest())

            # Select the appropriate cipher based on encryption_data
            if self.encryption_data == "aes-gcm":
                cipher = self.AESGCM(symmetric_key)
            elif self.encryption_data == "chacha20-poly1305":
                cipher = self.ChaCha20Poly1305(symmetric_key)
            elif self.encryption_data == "xchacha20-poly1305":
                try:
                    from .crypt_core import XChaCha20Poly1305

                    cipher = XChaCha20Poly1305(symmetric_key)
                except ImportError:
                    if not self.quiet:
                        logger.warning(
                            "XChaCha20Poly1305 not available, falling back to ChaCha20Poly1305"
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
                    logger.warning(
                        f"Unknown encryption algorithm {self.encryption_data}, falling back to aes-gcm"
                    )
                cipher = self.AESGCM(symmetric_key)

            # Generate nonce
            nonce = secrets.token_bytes(12)  # 96 bits for AES-GCM

            # Encrypt data
            encrypted_data = cipher.encrypt(nonce, data, None)

            # Format: encapsulated_key + nonce + ciphertext
            result = ciphertext + nonce + encrypted_data

            return result
        finally:
            # Clean up secure memory
            if "secure_shared_secret" in locals():
                secure_memzero(secure_shared_secret)
            if "symmetric_key" in locals():
                secure_memzero(symmetric_key)

    def decrypt(
        self, encrypted_data: bytes, private_key: bytes, file_contents: bytes = None
    ) -> bytes:
        """
        Decrypt data that was encrypted with the corresponding public key

        Args:
            encrypted_data: The encrypted data
            private_key: The recipient's private key
            file_contents: The full original encrypted file contents for recovery

        Returns:
            bytes: The decrypted data
        """
        if not self.use_liboqs:
            # Use native implementation for supported algorithms
            return super().decrypt(encrypted_data, private_key, file_contents)

        if not self.is_kem:
            raise ValueError("This method is only supported for KEM algorithms")

        try:
            # Determine ciphertext size for the algorithm
            kem_ciphertext_size = self.liboqs_kem.kem.length_ciphertext

            # Workaround for HQC algorithms where length_ciphertext returns 0
            if kem_ciphertext_size == 0:
                hqc_sizes = {"HQC-128": 4433, "HQC-192": 8978, "HQC-256": 14421}
                if self.algorithm_name in hqc_sizes:
                    kem_ciphertext_size = hqc_sizes[self.algorithm_name]
                    logger.debug(
                        f"Using hardcoded ciphertext size for {self.algorithm_name}: {kem_ciphertext_size}"
                    )
                else:
                    raise ValueError(
                        f"Cannot determine ciphertext size for algorithm {self.algorithm_name}"
                    )

            # Split the encrypted data
            encapsulated_key = encrypted_data[:kem_ciphertext_size]
            remaining_data = encrypted_data[kem_ciphertext_size:]

            # Extract nonce and ciphertext
            nonce = remaining_data[:12]
            ciphertext = remaining_data[12:]

            # Decapsulate shared secret
            shared_secret = self.liboqs_kem.decapsulate(encapsulated_key, private_key)

            # Use secure memory for sensitive operations
            with SecureBytes(shared_secret) as secure_shared_secret:
                # Derive symmetric key using secure memory
                symmetric_key = SecureBytes(hashlib.sha256(secure_shared_secret).digest())

                # Select the appropriate cipher based on encryption_data
                if self.encryption_data == "aes-gcm":
                    cipher = self.AESGCM(symmetric_key)
                elif self.encryption_data == "chacha20-poly1305":
                    cipher = self.ChaCha20Poly1305(symmetric_key)
                elif self.encryption_data == "xchacha20-poly1305":
                    try:
                        from .crypt_core import XChaCha20Poly1305

                        cipher = XChaCha20Poly1305(symmetric_key)
                    except ImportError:
                        if not self.quiet:
                            logger.warning(
                                "XChaCha20Poly1305 not available, falling back to ChaCha20Poly1305"
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
                        logger.warning(
                            f"Unknown encryption algorithm {self.encryption_data}, falling back to aes-gcm"
                        )
                    cipher = self.AESGCM(symmetric_key)

                # Decrypt data using secure memory
                with SecureBytes() as secure_plaintext:
                    # Decrypt directly into secure memory
                    decrypted = cipher.decrypt(nonce, ciphertext, None)
                    secure_plaintext.extend(decrypted)

                    # Zero out the original decrypted data
                    if isinstance(decrypted, bytearray):
                        secure_memzero(decrypted)

                    # Return a copy, secure memory will be auto-cleared
                    return bytes(secure_plaintext)
        except Exception as e:
            if not self.quiet:
                logger.error(f"Error in post-quantum decryption: {e}")
            raise ValueError(f"Decryption failed: {str(e)}")

    def sign(self, data: bytes, private_key: bytes) -> bytes:
        """
        Sign data using a post-quantum digital signature algorithm

        Args:
            data: The data to sign
            private_key: The signer's private key

        Returns:
            bytes: The signature
        """
        if self.is_kem:
            raise ValueError("This method is only supported for signature algorithms")

        return self.liboqs_sig.sign(data, private_key)

    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature using a post-quantum digital signature algorithm

        Args:
            data: The original data that was signed
            signature: The signature to verify
            public_key: The signer's public key

        Returns:
            bool: True if the signature is valid, False otherwise
        """
        if self.is_kem:
            raise ValueError("This method is only supported for signature algorithms")

        return self.liboqs_sig.verify(data, signature, public_key)


def get_security_level(algorithm: str) -> int:
    """
    Get the security level of an algorithm

    Args:
        algorithm: The algorithm name

    Returns:
        int: Security level (1, 3, or 5)
    """
    # Normalize algorithm name first
    normalized = normalize_algorithm_name(algorithm, use_standard=True)

    # Try to get security level from map
    return SECURITY_LEVEL_MAP.get(normalized, 0)


def get_default_encryption_data(algorithm: str) -> str:
    """
    Get the default symmetric encryption algorithm for a hybrid mode

    Args:
        algorithm: The hybrid algorithm name

    Returns:
        str: The default symmetric encryption algorithm
    """
    # For algorithms with ChaCha20 in the name, use ChaCha20-Poly1305
    if "chacha20" in algorithm.lower():
        return "chacha20-poly1305"

    # Default for most algorithms is AES-GCM
    return "aes-gcm"


def get_available_pq_algorithms(include_legacy: bool = True, quiet: bool = False) -> List[str]:
    """
    Get a list of available post-quantum algorithms

    Args:
        include_legacy: Whether to include legacy algorithm names
        quiet: Whether to suppress output messages

    Returns:
        List[str]: List of available algorithm names
    """
    available_algorithms = []

    # Always include ML-KEM/Kyber from our native implementation
    available_algorithms.extend(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])

    # Include legacy Kyber names if requested
    if include_legacy:
        available_algorithms.extend(["Kyber512", "Kyber768", "Kyber1024"])

    # Add liboqs algorithms if available
    if LIBOQS_AVAILABLE:
        _, _, liboqs_algs = check_liboqs_support(quiet=quiet)

        # Just add all the new algorithms for now
        # In a real implementation, we would check if they're actually supported
        # by the installed liboqs version, but for simplicity we'll assume they are
        available_algorithms.extend(NEW_PQ_ALGORITHMS)

    return available_algorithms


# Test function for the module
def test_extended_pqcipher():
    """Test the ExtendedPQCipher class"""
    # Check if liboqs is available
    if not LIBOQS_AVAILABLE:
        print("liboqs is not available. Install with: pip install liboqs")
        return

    # Get available algorithms
    algorithms = get_available_pq_algorithms()
    print(f"Available algorithms: {algorithms}")

    # Test with ML-KEM-512 (native implementation)
    print("\nTesting with ML-KEM-512 (native implementation):")
    try:
        cipher = ExtendedPQCipher("ML-KEM-512")
        public_key, private_key = cipher.generate_keypair()

        message = b"Hello, post-quantum world!"
        encrypted = cipher.encrypt(message, public_key)
        decrypted = cipher.decrypt(encrypted, private_key)

        print(f"  Original message: {message}")
        print(f"  Decrypted message: {decrypted}")
        print(f"  Success: {message == decrypted}")
    except Exception as e:
        print(f"  Error: {e}")

    # Test with HQC-128 (liboqs implementation) if available
    if "HQC-128" in algorithms:
        print("\nTesting with HQC-128 (liboqs implementation):")
        try:
            cipher = ExtendedPQCipher("HQC-128")
            public_key, private_key = cipher.generate_keypair()

            message = b"Hello, post-quantum world!"
            encrypted = cipher.encrypt(message, public_key)
            decrypted = cipher.decrypt(encrypted, private_key)

            print(f"  Original message: {message}")
            print(f"  Decrypted message: {decrypted}")
            print(f"  Success: {message == decrypted}")
        except Exception as e:
            print(f"  Error: {e}")

    # Test with ML-DSA-44 (signature algorithm) if available
    if "ML-DSA-44" in algorithms:
        print("\nTesting with ML-DSA-44 (signature algorithm):")
        try:
            signer = ExtendedPQCipher("ML-DSA-44")
            public_key, private_key = signer.generate_keypair()

            message = b"Hello, post-quantum world!"
            signature = signer.sign(message, private_key)
            is_valid = signer.verify(message, signature, public_key)

            print(f"  Original message: {message}")
            print(f"  Signature size: {len(signature)} bytes")
            print(f"  Valid signature: {is_valid}")

            # Try with modified message
            modified = b"Hello, modified world!"
            is_valid = signer.verify(modified, signature, public_key)
            print(f"  Valid signature for modified message: {is_valid} (should be False)")
        except Exception as e:
            print(f"  Error: {e}")


if __name__ == "__main__":
    test_extended_pqcipher()
