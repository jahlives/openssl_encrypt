#!/usr/bin/env python3
"""
Post-Quantum Signature Module

This module provides signature operations using ML-DSA (formerly Dilithium)
for asymmetric cryptography. Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.

Security Features:
- Constant-time signature verification
- Secure memory handling for private keys
- DoS protection through fast verification
"""

import hashlib
import logging
import time
from typing import Tuple

from .secure_memory import SecureBytes

# Set up module-level logger
logger = logging.getLogger(__name__)

# Try to import liboqs
LIBOQS_AVAILABLE = False
oqs = None

try:
    import oqs

    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False


class SignatureError(Exception):
    """Base exception for signature operations"""

    pass


class SignatureVerificationError(SignatureError):
    """Raised when signature verification fails"""

    pass


class SignatureAlgorithm:
    """Supported signature algorithms"""

    ML_DSA_44 = "ML-DSA-44"  # NIST Level 1 (~2KB signatures)
    ML_DSA_65 = "ML-DSA-65"  # NIST Level 3 (~3KB signatures) - DEFAULT
    ML_DSA_87 = "ML-DSA-87"  # NIST Level 5 (~4KB signatures)

    # Legacy names for backward compatibility
    DILITHIUM2 = "Dilithium2"  # Maps to ML-DSA-44
    DILITHIUM3 = "Dilithium3"  # Maps to ML-DSA-65
    DILITHIUM5 = "Dilithium5"  # Maps to ML-DSA-87


# Algorithm name mappings (legacy → standard)
LEGACY_TO_STANDARD_SIG = {
    "Dilithium2": "ML-DSA-44",
    "Dilithium3": "ML-DSA-65",
    "Dilithium5": "ML-DSA-87",
}

# liboqs algorithm names
LIBOQS_SIG_NAMES = {
    "ML-DSA-44": "Dilithium2",
    "ML-DSA-65": "Dilithium3",
    "ML-DSA-87": "Dilithium5",
}


class PQCSigner:
    """
    Post-Quantum Signature Operations using ML-DSA.

    Provides sign and verify operations with secure memory handling.

    Example:
        signer = PQCSigner("ML-DSA-65")
        public_key, private_key = signer.generate_keypair()

        # Sign message
        with SecureBytes(private_key) as secure_key:
            signature = signer.sign(message, bytes(secure_key))

        # Verify signature
        is_valid = signer.verify(message, signature, public_key)
    """

    def __init__(self, algorithm: str = "ML-DSA-65", quiet: bool = False):
        """
        Initialize PQC signer.

        Args:
            algorithm: Signature algorithm (ML-DSA-44, ML-DSA-65, ML-DSA-87)
            quiet: Suppress informational messages

        Raises:
            ValueError: If algorithm not supported
            RuntimeError: If liboqs not available
        """
        self.quiet = quiet

        # Normalize algorithm name
        if algorithm in LEGACY_TO_STANDARD_SIG:
            self.algorithm = LEGACY_TO_STANDARD_SIG[algorithm]
            if not quiet:
                logger.info(f"Using standard name {self.algorithm} for legacy {algorithm}")
        else:
            self.algorithm = algorithm

        # Validate algorithm
        if self.algorithm not in [
            SignatureAlgorithm.ML_DSA_44,
            SignatureAlgorithm.ML_DSA_65,
            SignatureAlgorithm.ML_DSA_87,
        ]:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        # Check liboqs availability
        if not LIBOQS_AVAILABLE:
            raise RuntimeError(
                "liboqs-python not available. Install with: pip install liboqs-python"
            )

        # Get liboqs algorithm name
        self.liboqs_name = LIBOQS_SIG_NAMES.get(self.algorithm)
        if not self.liboqs_name:
            raise ValueError(f"No liboqs mapping for {self.algorithm}")

        if not quiet:
            logger.debug(f"Initialized PQCSigner with {self.algorithm}")

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new signature keypair.

        Returns:
            Tuple of (public_key, private_key) as bytes

        Note:
            Private key should be immediately wrapped in SecureBytes
            for secure memory handling.
        """
        try:
            signer = oqs.Signature(self.liboqs_name)

            # Generate keypair
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()

            if not self.quiet:
                logger.debug(
                    f"Generated {self.algorithm} keypair: "
                    f"pub={len(public_key)} bytes, priv={len(private_key)} bytes"
                )

            return public_key, private_key

        except Exception as e:
            logger.error(f"Failed to generate keypair: {e}")
            raise SignatureError(f"Keypair generation failed: {e}")

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """
        Sign a message using ML-DSA.

        Args:
            message: Message to sign
            private_key: Private signing key

        Returns:
            Signature bytes

        Raises:
            SignatureError: If signing fails

        Security:
            - Private key should be in SecureBytes container
            - Private key is not copied, used directly
            - Consider using context managers for automatic cleanup
        """
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes")
        if not isinstance(private_key, bytes):
            raise TypeError("Private key must be bytes")

        try:
            signer = oqs.Signature(self.liboqs_name, private_key)
            signature = signer.sign(message)

            if not self.quiet:
                logger.debug(f"Created signature: {len(signature)} bytes")

            return signature

        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise SignatureError(f"Failed to sign message: {e}")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature using ML-DSA.

        Args:
            message: Original message
            signature: Signature to verify
            public_key: Public key for verification

        Returns:
            True if signature is valid, False otherwise

        Security:
            - Uses constant-time comparison internally (via liboqs)
            - Fast operation (~1-5ms) suitable for DoS protection
            - Does not raise exception on invalid signature
        """
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes")
        if not isinstance(signature, bytes):
            raise TypeError("Signature must be bytes")
        if not isinstance(public_key, bytes):
            raise TypeError("Public key must be bytes")

        try:
            verifier = oqs.Signature(self.liboqs_name, secret_key=None)
            is_valid = verifier.verify(message, signature, public_key)

            if not self.quiet:
                logger.debug(f"Signature verification: {'VALID' if is_valid else 'INVALID'}")

            return is_valid

        except Exception as e:
            # Verification failures are not exceptional - return False
            logger.debug(f"Verification failed: {e}")
            return False

    def get_signature_size(self) -> int:
        """
        Get the signature size for this algorithm.

        Returns:
            Signature size in bytes
        """
        try:
            signer = oqs.Signature(self.liboqs_name)
            return signer.details["length_signature"]
        except Exception:
            # Approximate sizes if details not available
            sizes = {
                "ML-DSA-44": 2420,
                "ML-DSA-65": 3309,
                "ML-DSA-87": 4627,
            }
            return sizes.get(self.algorithm, 3309)

    def get_public_key_size(self) -> int:
        """
        Get the public key size for this algorithm.

        Returns:
            Public key size in bytes
        """
        try:
            signer = oqs.Signature(self.liboqs_name)
            return signer.details["length_public_key"]
        except Exception:
            # Approximate sizes if details not available
            sizes = {
                "ML-DSA-44": 1312,
                "ML-DSA-65": 1952,
                "ML-DSA-87": 2592,
            }
            return sizes.get(self.algorithm, 1952)

    def get_private_key_size(self) -> int:
        """
        Get the private key size for this algorithm.

        Returns:
            Private key size in bytes
        """
        try:
            signer = oqs.Signature(self.liboqs_name)
            return signer.details["length_secret_key"]
        except Exception:
            # Approximate sizes if details not available
            sizes = {
                "ML-DSA-44": 2560,
                "ML-DSA-65": 4032,
                "ML-DSA-87": 4896,
            }
            return sizes.get(self.algorithm, 4032)


def calculate_fingerprint(public_key: bytes, algorithm: str = "SHA256") -> str:
    """
    Calculate fingerprint of a public key.

    Args:
        public_key: Public key bytes
        algorithm: Hash algorithm (SHA256, SHA512, BLAKE2b)

    Returns:
        Fingerprint as hex string with colons (like SSH fingerprints)
        Example: "3a:4b:5c:6d:7e:8f:..."
    """
    if algorithm == "SHA256":
        h = hashlib.sha256(public_key).digest()
    elif algorithm == "SHA512":
        h = hashlib.sha512(public_key).digest()
    elif algorithm == "BLAKE2b":
        h = hashlib.blake2b(public_key, digest_size=32).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    # Format with colons like SSH fingerprints
    hex_str = h.hex()
    return ":".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))


def verify_signature_with_timing(
    message: bytes, signature: bytes, public_key: bytes, algorithm: str = "ML-DSA-65"
) -> Tuple[bool, float]:
    """
    Verify signature and measure timing (for DoS protection verification).

    Args:
        message: Original message
        signature: Signature to verify
        public_key: Public key
        algorithm: Signature algorithm

    Returns:
        Tuple of (is_valid, verification_time_seconds)
    """
    signer = PQCSigner(algorithm, quiet=True)

    start_time = time.perf_counter()
    is_valid = signer.verify(message, signature, public_key)
    end_time = time.perf_counter()

    verification_time = end_time - start_time

    return is_valid, verification_time


# Convenience functions for common operations


def sign_with_ml_dsa_65(message: bytes, private_key: bytes) -> bytes:
    """
    Sign message with ML-DSA-65 (recommended default).

    Args:
        message: Message to sign
        private_key: Private key (should be in SecureBytes)

    Returns:
        Signature bytes
    """
    signer = PQCSigner("ML-DSA-65", quiet=True)
    return signer.sign(message, private_key)


def verify_with_ml_dsa_65(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify signature with ML-DSA-65 (recommended default).

    Args:
        message: Original message
        signature: Signature to verify
        public_key: Public key

    Returns:
        True if valid, False otherwise
    """
    signer = PQCSigner("ML-DSA-65", quiet=True)
    return signer.verify(message, signature, public_key)


if __name__ == "__main__":
    # Simple test
    print("Testing PQC Signer...")

    signer = PQCSigner("ML-DSA-65")

    # Generate keypair
    public_key, private_key = signer.generate_keypair()
    print(f"Public key: {len(public_key)} bytes")
    print(f"Private key: {len(private_key)} bytes")

    # Sign message
    message = b"Hello, Post-Quantum World!"
    with SecureBytes(private_key) as secure_key:
        signature = signer.sign(message, bytes(secure_key))
    print(f"Signature: {len(signature)} bytes")

    # Verify signature
    is_valid = signer.verify(message, signature, public_key)
    print(f"Verification: {'VALID' if is_valid else 'INVALID'}")

    # Test with wrong message
    is_valid = signer.verify(b"Wrong message", signature, public_key)
    print(f"Wrong message verification: {'VALID' if is_valid else 'INVALID'}")

    # Calculate fingerprint
    fingerprint = calculate_fingerprint(public_key)
    print(f"Fingerprint: {fingerprint[:60]}...")
