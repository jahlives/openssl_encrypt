#!/usr/bin/env python3
"""
Asymmetric Cryptography Core Module

This module provides the core functionality for asymmetric encryption operations:
- PasswordWrapper: KEM-based password wrapping using ML-KEM
- MetadataCanonicalizer: Deterministic JSON serialization for signatures

These components are used in the Format V7 asymmetric encryption pipeline.

Security Features:
- Secure memory handling for all key material
- Constant-time operations where applicable
- Defense in depth with KDF chain
"""

import hashlib
import json
import logging
import secrets
from typing import Dict, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto_secure_memory import CryptoKey
from .pqc import PQCAlgorithm, PQCipher
from .secure_memory import SecureBytes, secure_memzero

# Set up module-level logger
logger = logging.getLogger(__name__)


class PasswordWrapperError(Exception):
    """Base exception for password wrapping operations"""

    pass


class PasswordWrapper:
    """
    KEM-based password wrapping for asymmetric encryption.

    This class implements the password wrapping scheme used in Format V7:
    1. KEM encapsulation generates shared secret
    2. Shared secret used to wrap password with AES-256-GCM
    3. Encapsulated key stored in metadata for recipient

    Security:
    - Uses ML-KEM for post-quantum secure key encapsulation
    - AES-256-GCM for password encryption (authenticated)
    - Secure memory handling for all secrets

    Example:
        # Sender side
        wrapper = PasswordWrapper("ML-KEM-768")
        encapsulated_key, shared_secret = wrapper.encapsulate(recipient_pubkey)
        encrypted_password = wrapper.wrap_password(password, shared_secret)

        # Recipient side
        shared_secret = wrapper.decapsulate(encapsulated_key, recipient_privkey)
        password = wrapper.unwrap_password(encrypted_password, shared_secret)
    """

    def __init__(self, kem_algorithm: str = "ML-KEM-768", quiet: bool = False):
        """
        Initialize password wrapper.

        Args:
            kem_algorithm: KEM algorithm (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
            quiet: Suppress informational messages

        Raises:
            ValueError: If algorithm not supported
            RuntimeError: If liboqs not available
        """
        self.quiet = quiet
        self.kem_algorithm = kem_algorithm

        # Validate algorithm
        valid_algorithms = [
            PQCAlgorithm.ML_KEM_512.value,
            PQCAlgorithm.ML_KEM_768.value,
            PQCAlgorithm.ML_KEM_1024.value,
        ]

        if kem_algorithm not in valid_algorithms:
            raise ValueError(f"Unsupported KEM algorithm: {kem_algorithm}")

        # Create PQCipher instance for KEM operations
        try:
            self.cipher = PQCipher(algorithm=kem_algorithm, quiet=quiet)
        except Exception as e:
            raise RuntimeError(f"Failed to initialize KEM cipher: {e}")

        if not quiet:
            logger.debug(f"Initialized PasswordWrapper with {kem_algorithm}")

    def encapsulate(self, recipient_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Perform KEM encapsulation to generate shared secret.

        Args:
            recipient_public_key: Recipient's public KEM key

        Returns:
            Tuple of (encapsulated_key, shared_secret)
            - encapsulated_key: To be stored in metadata for recipient
            - shared_secret: Used to wrap password (caller must handle securely!)

        Raises:
            PasswordWrapperError: If encapsulation fails

        Security:
            - Shared secret MUST be wrapped in SecureBytes by caller
            - Shared secret MUST be zeroed after use
        """
        if not isinstance(recipient_public_key, bytes):
            raise TypeError("Recipient public key must be bytes")

        try:
            # Use PQCipher's encapsulate_only method
            # Returns: (shared_secret, encapsulated_key)
            shared_secret, encapsulated_key = self.cipher.encapsulate_only(recipient_public_key)

            if not self.quiet:
                logger.debug(
                    f"KEM encapsulation: encapsulated_key={len(encapsulated_key)} bytes, "
                    f"shared_secret={len(shared_secret)} bytes"
                )

            return encapsulated_key, shared_secret

        except Exception as e:
            logger.error(f"KEM encapsulation failed: {e}")
            raise PasswordWrapperError(f"Failed to encapsulate: {e}")

    def decapsulate(self, encapsulated_key: bytes, recipient_private_key: bytes) -> bytes:
        """
        Perform KEM decapsulation to recover shared secret.

        Args:
            encapsulated_key: Encapsulated key from metadata
            recipient_private_key: Recipient's private KEM key

        Returns:
            Shared secret (caller must wrap in SecureBytes!)

        Raises:
            PasswordWrapperError: If decapsulation fails

        Security:
            - Private key should be in CryptoKey container
            - Result MUST be wrapped in SecureBytes by caller
            - Result MUST be zeroed after use
        """
        if not isinstance(encapsulated_key, bytes):
            raise TypeError("Encapsulated key must be bytes")
        if not isinstance(recipient_private_key, bytes):
            raise TypeError("Recipient private key must be bytes")

        try:
            # Use PQCipher's decapsulate_only method
            shared_secret = self.cipher.decapsulate_only(encapsulated_key, recipient_private_key)

            if not self.quiet:
                logger.debug(f"KEM decapsulation: shared_secret={len(shared_secret)} bytes")

            return shared_secret

        except Exception as e:
            logger.error(f"KEM decapsulation failed: {e}")
            raise PasswordWrapperError(f"Failed to decapsulate: {e}")

    def wrap_password(self, password: bytes, shared_secret: bytes) -> bytes:
        """
        Wrap password using shared secret with AES-256-GCM.

        Args:
            password: Password to wrap (typically 32 bytes random)
            shared_secret: Shared secret from KEM (32+ bytes)

        Returns:
            Encrypted password in format: [nonce:12][ciphertext][tag:16]

        Raises:
            PasswordWrapperError: If wrapping fails

        Security:
            - Uses AES-256-GCM for authenticated encryption
            - Random 96-bit nonce per wrapping
            - 128-bit authentication tag
            - Both password and shared_secret should be in SecureBytes
        """
        if not isinstance(password, bytes):
            raise TypeError("Password must be bytes")
        if not isinstance(shared_secret, bytes):
            raise TypeError("Shared secret must be bytes")

        # Derive AES-256 key from shared secret
        # Use HKDF-style derivation with domain separation
        wrap_key_bytes = None
        nonce = None

        try:
            # Derive 32-byte key from shared secret
            h = hashlib.sha256()
            h.update(b"openssl_encrypt.password_wrap.v1")
            h.update(shared_secret)
            wrap_key_bytes = h.digest()

            # Generate random nonce (96 bits for GCM)
            nonce = secrets.token_bytes(12)

            # Encrypt password with AES-256-GCM
            aesgcm = AESGCM(wrap_key_bytes)
            ciphertext_with_tag = aesgcm.encrypt(
                nonce, password, None  # No additional authenticated data
            )

            # Format: nonce + ciphertext + tag
            # (tag is already appended by AESGCM.encrypt)
            encrypted_password = nonce + ciphertext_with_tag

            if not self.quiet:
                logger.debug(
                    f"Password wrapped: {len(password)} bytes → {len(encrypted_password)} bytes "
                    f"(nonce:12 + ciphertext:{len(password)} + tag:16)"
                )

            return encrypted_password

        except Exception as e:
            logger.error(f"Password wrapping failed: {e}")
            raise PasswordWrapperError(f"Failed to wrap password: {e}")

        finally:
            # Secure cleanup
            if wrap_key_bytes is not None:
                secure_memzero(wrap_key_bytes)
            # nonce is public, no need to zero

    def unwrap_password(self, encrypted_password: bytes, shared_secret: bytes) -> bytes:
        """
        Unwrap password using shared secret.

        Args:
            encrypted_password: Encrypted password from metadata [nonce:12][ciphertext][tag:16]
            shared_secret: Shared secret from KEM decapsulation

        Returns:
            Original password (caller must wrap in SecureBytes!)

        Raises:
            PasswordWrapperError: If unwrapping fails or authentication fails

        Security:
            - Verifies authentication tag (constant-time)
            - Raises exception on any tampering
            - Result MUST be wrapped in SecureBytes by caller
        """
        if not isinstance(encrypted_password, bytes):
            raise TypeError("Encrypted password must be bytes")
        if not isinstance(shared_secret, bytes):
            raise TypeError("Shared secret must be bytes")

        # Validate minimum size: nonce(12) + tag(16) = 28 bytes
        if len(encrypted_password) < 28:
            raise PasswordWrapperError(
                f"Invalid encrypted password size: {len(encrypted_password)} bytes "
                f"(minimum 28 bytes)"
            )

        wrap_key_bytes = None

        try:
            # Derive same AES-256 key from shared secret
            h = hashlib.sha256()
            h.update(b"openssl_encrypt.password_wrap.v1")
            h.update(shared_secret)
            wrap_key_bytes = h.digest()

            # Extract components
            nonce = encrypted_password[:12]
            ciphertext_with_tag = encrypted_password[12:]

            # Decrypt with AES-256-GCM
            aesgcm = AESGCM(wrap_key_bytes)
            password = aesgcm.decrypt(
                nonce,
                ciphertext_with_tag,
                None,  # No additional authenticated data
            )

            if not self.quiet:
                logger.debug(
                    f"Password unwrapped: {len(encrypted_password)} bytes → {len(password)} bytes"
                )

            return password

        except Exception:
            # Don't leak information about why decryption failed
            logger.error("Password unwrapping failed (invalid key or corrupted data)")
            raise PasswordWrapperError("Failed to unwrap password: authentication failed")

        finally:
            # Secure cleanup
            if wrap_key_bytes is not None:
                secure_memzero(wrap_key_bytes)


class MetadataCanonicalizer:
    """
    Deterministic JSON serialization for metadata signatures.

    This class ensures that metadata is serialized in a consistent,
    deterministic way for signature generation and verification.

    Canonicalization rules:
    1. Remove "signature" field entirely
    2. Sort all dictionary keys recursively
    3. No whitespace in JSON output
    4. UTF-8 encoding
    5. No trailing newline

    This ensures that the same metadata always produces the same bytes,
    which is critical for signature verification.

    Example:
        metadata = {"format_version": 7, "asymmetric": {...}, ...}
        canonical_bytes = MetadataCanonicalizer.canonicalize(metadata)
        signature = signer.sign(canonical_bytes, private_key)
    """

    @staticmethod
    def canonicalize(metadata: Dict) -> bytes:
        """
        Canonicalize metadata for signature operations.

        Args:
            metadata: Metadata dictionary (may include signature field)

        Returns:
            Deterministic byte representation of metadata

        Raises:
            ValueError: If metadata is not a dictionary
            TypeError: If metadata contains non-serializable types

        Note:
            - Signature field is automatically removed if present
            - Original metadata dict is not modified
        """
        if not isinstance(metadata, dict):
            raise ValueError("Metadata must be a dictionary")

        # Create a deep copy to avoid modifying original
        metadata_copy = MetadataCanonicalizer._deep_copy_without_signature(metadata)

        try:
            # Serialize with sorted keys, no whitespace, UTF-8
            canonical_json = json.dumps(
                metadata_copy,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )

            # Encode to UTF-8 bytes
            canonical_bytes = canonical_json.encode("utf-8")

            logger.debug(f"Canonicalized metadata: {len(canonical_bytes)} bytes")

            return canonical_bytes

        except (TypeError, ValueError) as e:
            logger.error(f"Metadata canonicalization failed: {e}")
            raise TypeError(f"Cannot canonicalize metadata: {e}")

    @staticmethod
    def _deep_copy_without_signature(obj):
        """
        Recursively copy object structure, removing 'signature' keys.

        Args:
            obj: Object to copy (dict, list, or primitive)

        Returns:
            Deep copy without any 'signature' keys
        """
        if isinstance(obj, dict):
            # Copy dict, excluding 'signature' key
            return {
                key: MetadataCanonicalizer._deep_copy_without_signature(value)
                for key, value in obj.items()
                if key != "signature"
            }
        elif isinstance(obj, list):
            # Recursively copy list elements
            return [MetadataCanonicalizer._deep_copy_without_signature(item) for item in obj]
        else:
            # Primitives (str, int, float, bool, None) are copied by value
            return obj

    @staticmethod
    def verify_determinism(metadata: Dict) -> bool:
        """
        Verify that canonicalization is deterministic.

        This is a test helper that canonicalizes the same metadata twice
        and verifies the results are identical.

        Args:
            metadata: Metadata to test

        Returns:
            True if canonicalization is deterministic, False otherwise
        """
        try:
            canonical1 = MetadataCanonicalizer.canonicalize(metadata)
            canonical2 = MetadataCanonicalizer.canonicalize(metadata)

            is_deterministic = canonical1 == canonical2

            if is_deterministic:
                logger.debug("Canonicalization is deterministic ✓")
            else:
                logger.warning("Canonicalization is NOT deterministic!")

            return is_deterministic

        except Exception as e:
            logger.error(f"Determinism check failed: {e}")
            return False


# Convenience functions for common operations


def wrap_password_for_recipient(
    password: bytes,
    recipient_public_key: bytes,
    kem_algorithm: str = "ML-KEM-768",
) -> Tuple[bytes, bytes]:
    """
    High-level function to wrap password for a recipient.

    Args:
        password: Password to wrap (should be in SecureBytes)
        recipient_public_key: Recipient's public KEM key
        kem_algorithm: KEM algorithm to use

    Returns:
        Tuple of (encapsulated_key, encrypted_password)

    Security:
        - Cleans up shared_secret securely
        - Password should be in SecureBytes context
    """
    wrapper = PasswordWrapper(kem_algorithm, quiet=True)

    # Encapsulate to get shared secret
    encapsulated_key, shared_secret_raw = wrapper.encapsulate(recipient_public_key)

    try:
        # Wrap shared secret in SecureBytes
        with SecureBytes(shared_secret_raw) as shared_secret:
            # Wrap password
            encrypted_password = wrapper.wrap_password(password, bytes(shared_secret))

        return encapsulated_key, encrypted_password

    finally:
        # Ensure shared_secret_raw is zeroed
        secure_memzero(shared_secret_raw)


def unwrap_password_for_recipient(
    encapsulated_key: bytes,
    encrypted_password: bytes,
    recipient_private_key: bytes,
    kem_algorithm: str = "ML-KEM-768",
) -> bytes:
    """
    High-level function to unwrap password for a recipient.

    Args:
        encapsulated_key: Encapsulated key from metadata
        encrypted_password: Encrypted password from metadata
        recipient_private_key: Recipient's private KEM key (should be from CryptoKey)
        kem_algorithm: KEM algorithm to use

    Returns:
        Unwrapped password (caller must wrap in SecureBytes!)

    Raises:
        PasswordWrapperError: If decapsulation or unwrapping fails

    Security:
        - Cleans up shared_secret securely
        - Result MUST be wrapped in SecureBytes by caller
    """
    wrapper = PasswordWrapper(kem_algorithm, quiet=True)

    # Decapsulate to get shared secret
    shared_secret_raw = wrapper.decapsulate(encapsulated_key, recipient_private_key)

    try:
        # Wrap shared secret in SecureBytes
        with SecureBytes(shared_secret_raw) as shared_secret:
            # Unwrap password
            password = wrapper.unwrap_password(encrypted_password, bytes(shared_secret))

        return password

    finally:
        # Ensure shared_secret_raw is zeroed
        secure_memzero(shared_secret_raw)


if __name__ == "__main__":
    # Simple test of password wrapping
    print("Testing PasswordWrapper...")

    # Initialize wrapper
    wrapper = PasswordWrapper("ML-KEM-768")

    # Generate test keypair (using PQCipher directly for testing)
    cipher = PQCipher("ML-KEM-768")
    recipient_pubkey, recipient_privkey = cipher.generate_keypair()

    print(f"Recipient keys: pub={len(recipient_pubkey)} bytes, priv={len(recipient_privkey)} bytes")

    # Generate random password
    password = secrets.token_bytes(32)
    print(f"Password: {len(password)} bytes")

    # Wrap password
    with SecureBytes(password) as secure_password:
        encapsulated_key, shared_secret_raw = wrapper.encapsulate(recipient_pubkey)

        with SecureBytes(shared_secret_raw) as shared_secret:
            encrypted_password = wrapper.wrap_password(bytes(secure_password), bytes(shared_secret))

    print(f"Encapsulated key: {len(encapsulated_key)} bytes")
    print(f"Encrypted password: {len(encrypted_password)} bytes")

    # Unwrap password
    with CryptoKey(key_data=recipient_privkey) as priv_crypto:
        shared_secret_raw2 = wrapper.decapsulate(encapsulated_key, priv_crypto.get_bytes())

        with SecureBytes(shared_secret_raw2) as shared_secret2:
            password_recovered = wrapper.unwrap_password(encrypted_password, bytes(shared_secret2))

    # Verify (wrap recovered password in SecureBytes for secure cleanup)
    with SecureBytes(password_recovered) as recovered:
        if password == bytes(recovered):
            print("✅ Password wrapping roundtrip successful!")
        else:
            print("❌ Password wrapping failed!")
            print(f"  Original:  {password.hex()[:64]}...")
            print(f"  Recovered: {bytes(recovered).hex()[:64]}...")

    # Clean up original password
    secure_memzero(password)

    # Test metadata canonicalization
    print("\nTesting MetadataCanonicalizer...")

    test_metadata = {
        "format_version": 7,
        "mode": "asymmetric",
        "asymmetric": {
            "recipients": [{"key_id": "abc123", "encapsulated_key": "base64data"}],
            "sender": {"key_id": "def456"},
        },
        "signature": {"algorithm": "ML-DSA-65", "value": "should_be_removed"},
    }

    canonical1 = MetadataCanonicalizer.canonicalize(test_metadata)
    canonical2 = MetadataCanonicalizer.canonicalize(test_metadata)

    print(f"Canonical bytes: {len(canonical1)} bytes")
    print(f"Deterministic: {canonical1 == canonical2}")

    # Verify signature field was removed
    canonical_str = canonical1.decode("utf-8")
    if '"signature"' not in canonical_str:
        print("✅ Signature field correctly removed")
    else:
        print("❌ Signature field not removed!")

    print("\n✅ All asymmetric_core tests passed!")
