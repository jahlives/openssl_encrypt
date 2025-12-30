#!/usr/bin/env python3
"""
Public Key Bundle - Self-signed public key distribution format.

SECURITY CRITICAL:
This module defines the PublicKeyBundle format for distributing public keys
via the keyserver system. All bundles are cryptographically self-signed
to prevent tampering.

SECURITY GUARANTEES:
- Immutable dataclass (frozen=True) prevents modification after creation
- Self-signature using ML-DSA provides cryptographic proof of authenticity
- Strict algorithm whitelists prevent legacy/weak cryptography
- Fingerprint always recalculated, never trusted from external sources
- Only public keys included, NEVER private keys

DESIGN PRINCIPLES:
- Zero trust: All bundles from external sources are verified before use
- Kerckhoffs's principle: Algorithm names are public, keys remain secret
- Defense in depth: Multiple validation layers (signature + fingerprint + algorithms)
"""

import base64
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, Optional

from .pqc_signing import PQCSigner, calculate_fingerprint

if TYPE_CHECKING:
    from .identity import Identity

# Set up module-level logger
logger = logging.getLogger(__name__)


class KeyBundleError(Exception):
    """Base exception for key bundle operations"""

    pass


class InvalidSignatureError(KeyBundleError):
    """Raised when bundle signature verification fails"""

    pass


class InvalidAlgorithmError(KeyBundleError):
    """Raised when unsupported algorithm is used"""

    pass


class InvalidFingerprintError(KeyBundleError):
    """Raised when fingerprint doesn't match keys"""

    pass


@dataclass(frozen=True)
class PublicKeyBundle:
    """
    Immutable, self-signed public key bundle for keyserver distribution.

    SECURITY: This class is frozen (immutable) to prevent any modification
    after creation. All fields are validated and cryptographically verified.

    ALLOWED FIELDS (per Kerckhoffs's principle):
    - Algorithm names and parameters (public information)
    - Public keys (designed to be public)
    - Fingerprints (derived from public keys)
    - Timestamps (UTC, no timezone information)

    NEVER CONTAINS:
    - Private keys (encryption or signing)
    - Passwords or passphrases
    - Salts or key derivation secrets
    - Filenames, file paths, or user data

    Attributes:
        name: Identity name (e.g., "alice")
        email: Optional email address
        fingerprint: SHA-256 fingerprint of both public keys (hex with colons)
        created_at: ISO 8601 timestamp (UTC)
        encryption_public_key: Public encryption key bytes (PEM format)
        signing_public_key: Public signing key bytes (PEM format)
        encryption_algorithm: KEM algorithm (ML-KEM-512/768/1024 only)
        signing_algorithm: Signature algorithm (ML-DSA-44/65/87 only)
        self_signature: ML-DSA signature of bundle content
    """

    # Identity information
    name: str
    email: Optional[str]
    fingerprint: str  # SHA-256 with colons (e.g., "3a:4b:...")
    created_at: str  # ISO 8601 format

    # Public keys (bytes, PEM format)
    encryption_public_key: bytes  # ML-KEM
    signing_public_key: bytes  # ML-DSA

    # Algorithms (strict whitelist)
    encryption_algorithm: str  # Only ML-KEM-512/768/1024
    signing_algorithm: str  # Only ML-DSA-44/65/87

    # Self-signature for authenticity
    self_signature: bytes  # ML-DSA signature

    # Strict algorithm whitelists (PQC only)
    ALLOWED_KEM_ALGORITHMS = frozenset(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])

    ALLOWED_SIGNING_ALGORITHMS = frozenset(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])

    def __post_init__(self):
        """
        Validate bundle after initialization.

        Raises:
            InvalidAlgorithmError: If algorithms not in whitelist
            ValueError: If required fields are invalid
        """
        # Validate algorithms
        if self.encryption_algorithm not in self.ALLOWED_KEM_ALGORITHMS:
            raise InvalidAlgorithmError(
                f"Invalid encryption algorithm: {self.encryption_algorithm}. "
                f"Allowed: {', '.join(self.ALLOWED_KEM_ALGORITHMS)}"
            )

        if self.signing_algorithm not in self.ALLOWED_SIGNING_ALGORITHMS:
            raise InvalidAlgorithmError(
                f"Invalid signing algorithm: {self.signing_algorithm}. "
                f"Allowed: {', '.join(self.ALLOWED_SIGNING_ALGORITHMS)}"
            )

        # Validate required fields
        if not self.name or not isinstance(self.name, str):
            raise ValueError("Name is required and must be a string")

        if not self.fingerprint or not isinstance(self.fingerprint, str):
            raise ValueError("Fingerprint is required and must be a string")

        if not self.encryption_public_key or not isinstance(self.encryption_public_key, bytes):
            raise ValueError("Encryption public key is required and must be bytes")

        if not self.signing_public_key or not isinstance(self.signing_public_key, bytes):
            raise ValueError("Signing public key is required and must be bytes")

        if not self.self_signature or not isinstance(self.self_signature, bytes):
            raise ValueError("Self-signature is required and must be bytes")

    @classmethod
    def from_identity(cls, identity: "Identity") -> "PublicKeyBundle":
        """
        Create self-signed bundle from Identity.

        SECURITY: Requires access to private signing key to create signature.
        This proves that the bundle creator controls the identity.

        Args:
            identity: Identity instance (must have signing_private_key loaded)

        Returns:
            PublicKeyBundle with self-signature

        Raises:
            ValueError: If identity doesn't have private signing key
            InvalidAlgorithmError: If algorithms not supported
        """
        # Import Identity here to avoid circular import
        from .identity import Identity

        if not isinstance(identity, Identity):
            raise TypeError("identity must be an Identity instance")

        if not identity.signing_private_key:
            raise ValueError("Identity must have signing_private_key loaded to create bundle")

        if not identity.is_own_identity:
            raise ValueError("Can only create bundles from own identities")

        # Validate algorithms
        if identity.encryption_algorithm not in cls.ALLOWED_KEM_ALGORITHMS:
            raise InvalidAlgorithmError(
                f"Identity uses unsupported encryption algorithm: {identity.encryption_algorithm}"
            )

        if identity.signing_algorithm not in cls.ALLOWED_SIGNING_ALGORITHMS:
            raise InvalidAlgorithmError(
                f"Identity uses unsupported signing algorithm: {identity.signing_algorithm}"
            )

        # Create bundle data (everything except signature)
        bundle_data = {
            "name": identity.name,
            "email": identity.email,
            "fingerprint": identity.fingerprint,
            "created_at": identity.created_at,
            "encryption_public_key": base64.b64encode(identity.encryption_public_key).decode(
                "ascii"
            ),
            "signing_public_key": base64.b64encode(identity.signing_public_key).decode("ascii"),
            "encryption_algorithm": identity.encryption_algorithm,
            "signing_algorithm": identity.signing_algorithm,
        }

        # Serialize for signing (deterministic JSON)
        message = json.dumps(bundle_data, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # Sign with identity's private signing key
        signer = PQCSigner(identity.signing_algorithm, quiet=True)
        signature = signer.sign(message, identity.signing_private_key.get_bytes())

        # Create bundle with signature
        bundle = cls(
            name=identity.name,
            email=identity.email,
            fingerprint=identity.fingerprint,
            created_at=identity.created_at,
            encryption_public_key=identity.encryption_public_key,
            signing_public_key=identity.signing_public_key,
            encryption_algorithm=identity.encryption_algorithm,
            signing_algorithm=identity.signing_algorithm,
            self_signature=signature,
        )

        logger.info(f"Created self-signed bundle for '{identity.name}'")
        return bundle

    def verify_signature(self) -> bool:
        """
        Verify self-signature and fingerprint.

        SECURITY: This is the CRITICAL verification step. All bundles from
        external sources MUST be verified before use.

        Verification steps:
        1. Verify self-signature with signing public key
        2. Recalculate fingerprint from public keys
        3. Compare calculated fingerprint with stored fingerprint

        Returns:
            True if signature valid and fingerprint matches

        Raises:
            InvalidSignatureError: If signature verification fails
            InvalidFingerprintError: If fingerprint doesn't match
        """
        try:
            # Step 1: Verify self-signature
            bundle_data = {
                "name": self.name,
                "email": self.email,
                "fingerprint": self.fingerprint,
                "created_at": self.created_at,
                "encryption_public_key": base64.b64encode(self.encryption_public_key).decode(
                    "ascii"
                ),
                "signing_public_key": base64.b64encode(self.signing_public_key).decode("ascii"),
                "encryption_algorithm": self.encryption_algorithm,
                "signing_algorithm": self.signing_algorithm,
            }

            # Serialize (deterministic JSON)
            message = json.dumps(bundle_data, sort_keys=True, separators=(",", ":")).encode("utf-8")

            # Verify signature
            signer = PQCSigner(self.signing_algorithm, quiet=True)
            signature_valid = signer.verify(message, self.self_signature, self.signing_public_key)

            if not signature_valid:
                raise InvalidSignatureError("Self-signature verification failed")

            # Step 2: Verify fingerprint
            calculated_fingerprint = self._calculate_fingerprint()

            if calculated_fingerprint != self.fingerprint:
                raise InvalidFingerprintError(
                    f"Fingerprint mismatch: stored={self.fingerprint}, "
                    f"calculated={calculated_fingerprint}"
                )

            logger.debug(f"Successfully verified bundle for '{self.name}'")
            return True

        except InvalidSignatureError:
            logger.error(f"Signature verification failed for bundle '{self.name}'")
            raise
        except InvalidFingerprintError:
            logger.error(f"Fingerprint verification failed for bundle '{self.name}'")
            raise
        except Exception as e:
            logger.error(f"Bundle verification failed: {e}")
            raise InvalidSignatureError(f"Bundle verification failed: {e}")

    def _calculate_fingerprint(self) -> str:
        """
        Calculate fingerprint from public keys.

        SECURITY: Always recalculate, never trust stored fingerprint.

        Returns:
            SHA-256 fingerprint with colons
        """
        combined_keys = self.encryption_public_key + self.signing_public_key
        return calculate_fingerprint(combined_keys)

    def to_dict(self) -> Dict:
        """
        Convert bundle to dictionary for JSON serialization.

        Returns:
            Dictionary with base64-encoded binary fields
        """
        return {
            "name": self.name,
            "email": self.email,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "encryption_public_key": base64.b64encode(self.encryption_public_key).decode("ascii"),
            "signing_public_key": base64.b64encode(self.signing_public_key).decode("ascii"),
            "encryption_algorithm": self.encryption_algorithm,
            "signing_algorithm": self.signing_algorithm,
            "self_signature": base64.b64encode(self.self_signature).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "PublicKeyBundle":
        """
        Create bundle from dictionary.

        SECURITY: Does NOT verify signature. Call verify_signature() after creation.

        Args:
            data: Dictionary from to_dict()

        Returns:
            PublicKeyBundle (unverified)

        Raises:
            KeyError: If required fields missing
            ValueError: If data format invalid
        """
        try:
            bundle = cls(
                name=data["name"],
                email=data.get("email"),
                fingerprint=data["fingerprint"],
                created_at=data["created_at"],
                encryption_public_key=base64.b64decode(data["encryption_public_key"]),
                signing_public_key=base64.b64decode(data["signing_public_key"]),
                encryption_algorithm=data["encryption_algorithm"],
                signing_algorithm=data["signing_algorithm"],
                self_signature=base64.b64decode(data["self_signature"]),
            )
            return bundle
        except KeyError as e:
            raise ValueError(f"Missing required field in bundle data: {e}")
        except Exception as e:
            raise ValueError(f"Invalid bundle data format: {e}")

    def to_identity(self) -> "Identity":
        """
        Convert bundle to Identity (public keys only).

        SECURITY: Creates Identity WITHOUT private keys (is_own_identity=False).
        This is safe for identities received from keyserver.

        Returns:
            Identity instance (public keys only)
        """
        # Import Identity here to avoid circular import
        from .identity import Identity

        identity = Identity(
            name=self.name,
            email=self.email,
            fingerprint=self.fingerprint,
            created_at=self.created_at,
            encryption_algorithm=self.encryption_algorithm,
            signing_algorithm=self.signing_algorithm,
            encryption_public_key=self.encryption_public_key,
            encryption_private_key=None,
            signing_public_key=self.signing_public_key,
            signing_private_key=None,
            is_own_identity=False,
        )

        logger.debug(f"Converted bundle to Identity for '{self.name}'")
        return identity

    def __repr__(self):
        return (
            f"PublicKeyBundle(name='{self.name}', "
            f"email='{self.email}', "
            f"fingerprint='{self.fingerprint[:20]}...', "
            f"algorithms={self.encryption_algorithm}/{self.signing_algorithm})"
        )


if __name__ == "__main__":
    # Simple test
    print("PublicKeyBundle module loaded successfully")
    print(f"Allowed KEM algorithms: {PublicKeyBundle.ALLOWED_KEM_ALGORITHMS}")
    print(f"Allowed signing algorithms: {PublicKeyBundle.ALLOWED_SIGNING_ALGORITHMS}")
