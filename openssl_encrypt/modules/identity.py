#!/usr/bin/env python3
"""
Identity Management Module

This module provides identity management for asymmetric cryptography.
Each identity has:
- Encryption keypair (ML-KEM for key encapsulation)
- Signing keypair (ML-DSA for digital signatures)

Private keys are encrypted at rest using Argon2id + AES-256-GCM.

Directory structure:
    ~/.openssl_encrypt/identities/
    ├── alice/
    │   ├── identity.json
    │   ├── encryption_public.pem
    │   ├── encryption_private.pem
    │   ├── signing_public.pem
    │   └── signing_private.pem
    └── contacts/
        └── bob_public.json
"""

import base64
import json
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .crypt_utils import eprint
from .file_permissions import (
    PermissionLevel,
    create_secure_directory,
    create_secure_file,
    set_permissions,
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto_secure_memory import CryptoKey

# Import protection classes
from .identity_protection import (
    HSMNotAvailableError,
    IdentityKeyProtectionService,
    IdentityProtection,
    InvalidCredentialsError,
    ProtectionLevel,
)
from .pqc import PQCipher
from .pqc_signing import PQCSigner, calculate_fingerprint
from .secure_memory import secure_memzero

# Set up module-level logger
logger = logging.getLogger(__name__)

# Try to import argon2
try:
    import argon2

    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class IdentityError(Exception):
    """Base exception for identity operations"""

    pass


class IdentityNotFoundError(IdentityError):
    """Raised when identity not found"""

    pass


class IdentityExistsError(IdentityError):
    """Raised when identity already exists"""

    pass


class IdentityKeyChangedError(IdentityError):
    """Raised when importing/adding an identity whose name already exists but
    whose keys (fingerprint) differ from the stored ones (M8).

    This is the TOFU key-substitution case: the previously pinned contact's
    keys would be replaced by different keys. It must be accepted deliberately
    (explicit override / interactive confirmation), never silently on a plain
    --overwrite.
    """

    def __init__(self, name: str, old_fingerprint: str, new_fingerprint: str):
        self.name = name
        self.old_fingerprint = old_fingerprint
        self.new_fingerprint = new_fingerprint
        super().__init__(
            f"Key change detected for identity '{name}': the stored key "
            f"fingerprint ({old_fingerprint}) differs from the imported one "
            f"({new_fingerprint}). Refusing to replace a pinned identity's keys "
            f"without explicit confirmation."
        )


class IdentityAmbiguousError(IdentityError):
    """Raised when a fingerprint lookup matches more than one identity."""

    pass


import re

# Strict pattern for identity names: alphanumeric, hyphens, underscores, dots.
# No path separators, no ".." sequences, no leading dots.
_IDENTITY_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def validate_identity_name(name: str) -> None:
    """Validate that an identity name is safe for use as a directory name.

    Rejects path traversal attempts (e.g., "../../etc"), absolute paths,
    names with path separators, and names starting with dots.

    Args:
        name: Identity name to validate.

    Raises:
        IdentityError: If the name is invalid or potentially malicious.
    """
    if not name:
        raise IdentityError("Identity name cannot be empty")
    if len(name) > 255:
        raise IdentityError("Identity name too long (max 255 characters)")
    if not _IDENTITY_NAME_RE.match(name):
        raise IdentityError(
            f"Invalid identity name '{name}': must contain only "
            f"alphanumeric characters, hyphens, underscores, and dots, "
            f"and must not start with a dot"
        )
    if ".." in name:
        raise IdentityError(f"Invalid identity name '{name}': must not contain '..'")


@dataclass
class Identity:
    """
    User identity with encryption and signing keypairs.

    Attributes:
        name: Identity name (e.g., "alice")
        email: Optional email address
        fingerprint: SHA256 fingerprint of both public keys
        created_at: ISO 8601 timestamp
        encryption_algorithm: KEM algorithm (e.g., "ML-KEM-768")
        signing_algorithm: Signature algorithm (e.g., "ML-DSA-65")
        encryption_public_key: Public encryption key (bytes)
        encryption_private_key: Private encryption key (CryptoKey or None)
        signing_public_key: Public signing key (bytes)
        signing_private_key: Private signing key (CryptoKey or None)
        is_own_identity: True if we have private keys
        key_encryption_kdf: KDF used for private key encryption ("argon2id")

    Example:
        # Generate new identity
        identity = Identity.generate("alice", "alice@example.com", "passphrase")

        # Use with context manager for secure cleanup
        with identity:
            signature = sign_with_identity(identity, message)
    """

    name: str
    email: Optional[str]
    fingerprint: str
    created_at: str

    encryption_algorithm: str
    signing_algorithm: str

    encryption_public_key: bytes
    encryption_private_key: Optional[CryptoKey]

    signing_public_key: bytes
    signing_private_key: Optional[CryptoKey]

    is_own_identity: bool
    key_encryption_kdf: str = "argon2id"
    protection: Optional[IdentityProtection] = None  # HSM protection configuration

    @classmethod
    def generate(
        cls,
        name: str,
        email: Optional[str] = None,
        passphrase: Optional[str] = None,
        kem_algorithm: str = "ML-KEM-768",
        sig_algorithm: str = "ML-DSA-65",
        protection_level: ProtectionLevel = ProtectionLevel.PASSWORD_ONLY,
        hsm_slot: Optional[int] = None,
        require_touch: bool = True,
    ) -> "Identity":
        """
        Generate a new identity with fresh keypairs.

        Args:
            name: Identity name
            email: Optional email address
            passphrase: Passphrase to encrypt private keys (required for PASSWORD_ONLY or PASSWORD_AND_HSM)
            kem_algorithm: KEM algorithm for encryption
            sig_algorithm: Signature algorithm
            protection_level: Protection level (PASSWORD_ONLY, PASSWORD_AND_HSM, or HSM_ONLY)
            hsm_slot: Yubikey slot (1 or 2, None = auto-detect)
            require_touch: Whether Yubikey touch is required

        Returns:
            New Identity instance

        Raises:
            ValueError: If algorithm not supported
            RuntimeError: If key generation fails
            HSMNotAvailableError: If HSM required but not available
        """
        validate_identity_name(name)
        logger.info(f"Generating identity '{name}' with {kem_algorithm} + {sig_algorithm}")

        try:
            # Generate encryption keypair (KEM)
            kem = PQCipher(kem_algorithm, quiet=True)
            enc_public_key, enc_private_key = kem.generate_keypair()

            # Generate signing keypair
            signer = PQCSigner(sig_algorithm, quiet=True)
            sig_public_key, sig_private_key = signer.generate_keypair()

            # Calculate fingerprint
            combined_keys = enc_public_key + sig_public_key
            fingerprint = calculate_fingerprint(combined_keys)

            # Wrap private keys in CryptoKey for secure memory
            enc_priv_crypto = CryptoKey(key_data=enc_private_key)
            secure_memzero(enc_private_key)  # Clean original

            sig_priv_crypto = CryptoKey(key_data=sig_private_key)
            secure_memzero(sig_private_key)  # Clean original

            # Create protection configuration
            protection = None
            if protection_level != ProtectionLevel.PASSWORD_ONLY:
                protection_service = IdentityKeyProtectionService()
                protection = protection_service.create_protection_config(
                    level=protection_level, hsm_slot=hsm_slot, require_touch=require_touch
                )

            identity = cls(
                name=name,
                email=email,
                fingerprint=fingerprint,
                created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                encryption_algorithm=kem_algorithm,
                signing_algorithm=sig_algorithm,
                encryption_public_key=enc_public_key,
                encryption_private_key=enc_priv_crypto,
                signing_public_key=sig_public_key,
                signing_private_key=sig_priv_crypto,
                is_own_identity=True,
                protection=protection,
            )

            logger.info(f"Generated identity '{name}' with fingerprint {fingerprint[:40]}...")
            return identity

        except Exception as e:
            logger.error(f"Failed to generate identity: {e}")
            raise IdentityError(f"Identity generation failed: {e}")

    @classmethod
    def load(
        cls,
        path: Path,
        passphrase: Optional[str] = None,
        load_private_keys: bool = True,
    ) -> "Identity":
        """
        Load identity from directory.

        Args:
            path: Path to identity directory
            passphrase: Passphrase to decrypt private keys
            load_private_keys: Whether to load private keys (requires passphrase)

        Returns:
            Identity instance

        Raises:
            IdentityNotFoundError: If identity directory not found
            ValueError: If passphrase required but not provided
        """
        if not path.exists():
            raise IdentityNotFoundError(f"Identity not found at {path}")

        # Load identity.json
        identity_json_path = path / "identity.json"
        if not identity_json_path.exists():
            raise IdentityNotFoundError(f"identity.json not found in {path}")

        with open(identity_json_path, "r") as f:
            data = json.load(f)

        name = data["name"]
        logger.debug(f"Loading identity '{name}' from {path}")

        # Load protection configuration (for backward compatibility, assume PASSWORD_ONLY if not present)
        protection = None
        if "protection" in data:
            protection = IdentityProtection.from_dict(data["protection"])
        elif "version" in data and data["version"] >= 2:
            # Version 2+ should always have protection field
            logger.warning(
                f"Identity version {data['version']} missing protection field, assuming PASSWORD_ONLY"
            )
        # If no version or version 1, assume PASSWORD_ONLY (backward compatible)

        # Load public keys
        enc_pub_path = path / "encryption_public.pem"
        sig_pub_path = path / "signing_public.pem"

        with open(enc_pub_path, "rb") as f:
            enc_public_key = f.read()
        with open(sig_pub_path, "rb") as f:
            sig_public_key = f.read()

        # Check if private keys exist
        enc_priv_path = path / "encryption_private.pem"
        sig_priv_path = path / "signing_private.pem"

        has_private_keys = enc_priv_path.exists() and sig_priv_path.exists()
        is_own_identity = has_private_keys

        # Load and decrypt private keys if requested
        enc_private_key = None
        sig_private_key = None

        if load_private_keys and has_private_keys:
            # Allow None passphrase for HSM_ONLY protection
            if not passphrase and (not protection or protection.level != ProtectionLevel.HSM_ONLY):
                raise ValueError("Passphrase required to load private keys")

            # Load encrypted private keys
            with open(enc_priv_path, "rb") as f:
                enc_priv_encrypted = f.read()
            with open(sig_priv_path, "rb") as f:
                sig_priv_encrypted = f.read()

            # Decrypt private keys (pass protection and identity name)
            enc_private_key = _decrypt_private_key(enc_priv_encrypted, passphrase, protection, name)
            sig_private_key = _decrypt_private_key(sig_priv_encrypted, passphrase, protection, name)

        identity = cls(
            name=name,
            email=data.get("email"),
            fingerprint=data["fingerprint"],
            created_at=data["created_at"],
            encryption_algorithm=data["encryption_algorithm"],
            signing_algorithm=data["signing_algorithm"],
            encryption_public_key=enc_public_key,
            encryption_private_key=enc_private_key,
            signing_public_key=sig_public_key,
            signing_private_key=sig_private_key,
            is_own_identity=is_own_identity,
            key_encryption_kdf=data.get("key_encryption_kdf", "argon2id"),
            protection=protection,
        )

        logger.info(
            f"Loaded identity '{name}' (private_keys={has_private_keys and load_private_keys})"
        )
        return identity

    def save(
        self,
        path: Path,
        passphrase: Optional[str] = None,
        overwrite: bool = False,
    ) -> None:
        """
        Save identity to directory.

        Args:
            path: Path to identity directory (will be created)
            passphrase: Passphrase to encrypt private keys
            overwrite: Allow overwriting existing identity

        Raises:
            IdentityExistsError: If identity exists and overwrite=False
            ValueError: If private keys exist but no passphrase provided
        """
        if path.exists() and not overwrite:
            raise IdentityExistsError(f"Identity already exists at {path}")

        # Create directory with secure permissions
        create_secure_directory(path)

        logger.debug(f"Saving identity '{self.name}' to {path}")

        # Save identity.json
        identity_data = {
            "version": 2 if self.protection else 1,  # Version 2 if HSM protection used
            "name": self.name,
            "email": self.email,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "encryption_algorithm": self.encryption_algorithm,
            "signing_algorithm": self.signing_algorithm,
            "key_encryption_kdf": self.key_encryption_kdf,
            "is_own_identity": self.is_own_identity,
        }

        # Add protection configuration if present
        if self.protection:
            identity_data["protection"] = self.protection.to_dict()

        identity_json_path = path / "identity.json"
        fd = create_secure_file(identity_json_path, PermissionLevel.OWNER_ONLY)
        with os.fdopen(fd, "w") as f:
            json.dump(identity_data, f, indent=2)

        # Save public keys
        enc_pub_path = path / "encryption_public.pem"
        sig_pub_path = path / "signing_public.pem"

        with open(enc_pub_path, "wb") as f:
            f.write(self.encryption_public_key)
        set_permissions(enc_pub_path, PermissionLevel.OWNER_WRITE_PUBLIC_READ)

        with open(sig_pub_path, "wb") as f:
            f.write(self.signing_public_key)
        set_permissions(sig_pub_path, PermissionLevel.OWNER_WRITE_PUBLIC_READ)

        # Save private keys if available
        if self.encryption_private_key or self.signing_private_key:
            # Allow None passphrase for HSM_ONLY protection
            if not passphrase and (
                not self.protection or self.protection.level != ProtectionLevel.HSM_ONLY
            ):
                raise ValueError("Passphrase required to save private keys")

            if self.encryption_private_key:
                enc_priv_encrypted = _encrypt_private_key(
                    self.encryption_private_key.get_bytes(), passphrase, self.protection, self.name
                )
                enc_priv_path = path / "encryption_private.pem"
                fd = create_secure_file(enc_priv_path, PermissionLevel.OWNER_ONLY)
                with os.fdopen(fd, "wb") as f:
                    f.write(enc_priv_encrypted)

            if self.signing_private_key:
                sig_priv_encrypted = _encrypt_private_key(
                    self.signing_private_key.get_bytes(), passphrase, self.protection, self.name
                )
                sig_priv_path = path / "signing_private.pem"
                fd = create_secure_file(sig_priv_path, PermissionLevel.OWNER_ONLY)
                with os.fdopen(fd, "wb") as f:
                    f.write(sig_priv_encrypted)

        logger.info(f"Saved identity '{self.name}' to {path}")

    def export_public(self) -> Dict:
        """
        Export only public keys as dictionary.

        Returns:
            Dictionary with public keys and metadata

        Note:
            This is suitable for sharing with others.
            Private keys are never included.
        """
        return {
            "name": self.name,
            "email": self.email,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "encryption_algorithm": self.encryption_algorithm,
            "signing_algorithm": self.signing_algorithm,
            "encryption_public_key": base64.b64encode(self.encryption_public_key).decode(),
            "signing_public_key": base64.b64encode(self.signing_public_key).decode(),
        }

    @classmethod
    def import_public(cls, data: Dict) -> "Identity":
        """
        Import identity from public key export.

        Args:
            data: Dictionary from export_public()

        Returns:
            Identity instance (without private keys)

        Raises:
            IdentityError: If the imported name fails validation.
        """
        validate_identity_name(data["name"])
        identity = cls(
            name=data["name"],
            email=data.get("email"),
            fingerprint=data["fingerprint"],
            created_at=data["created_at"],
            encryption_algorithm=data["encryption_algorithm"],
            signing_algorithm=data["signing_algorithm"],
            encryption_public_key=base64.b64decode(data["encryption_public_key"]),
            encryption_private_key=None,
            signing_public_key=base64.b64decode(data["signing_public_key"]),
            signing_private_key=None,
            is_own_identity=False,
        )
        # Verify fingerprint matches the actual public keys to detect tampering
        if not identity.check_fingerprint_consistency():
            raise IdentityError(
                f"Fingerprint verification failed for imported identity '{data['name']}': "
                f"the fingerprint does not match the public keys"
            )
        return identity

    def calculate_fingerprint(self) -> str:
        """
        (Re)calculate fingerprint from public keys.

        Returns:
            SHA256 fingerprint with colons
        """
        combined_keys = self.encryption_public_key + self.signing_public_key
        return calculate_fingerprint(combined_keys)

    def check_fingerprint_consistency(self) -> bool:
        """
        Check that the stored fingerprint matches the fingerprint recomputed
        from this identity's own public keys.

        SECURITY NOTE (M8): this proves only INTERNAL CONSISTENCY of a bundle
        (the fingerprint field matches the keys it ships with), NOT
        AUTHENTICITY. It does not establish that the keys belong to the named
        party - an attacker can hand you a bundle with their own keys and a
        matching fingerprint. Authenticity is provided by TOFU pinning
        (IdentityStore.add_identity refuses a key change) and, for sender
        verification, by signature checks.

        Returns:
            True if the stored and recomputed fingerprints match.
        """
        calculated = self.calculate_fingerprint()
        return calculated == self.fingerprint

    def verify_fingerprint(self) -> bool:
        """Deprecated alias for check_fingerprint_consistency() (M8).

        The old name implied authenticity verification; it only checks internal
        consistency. Kept for backward compatibility.
        """
        return self.check_fingerprint_consistency()

    def __enter__(self):
        """Context manager entry - returns self"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - secure cleanup of private keys"""
        if self.encryption_private_key:
            self.encryption_private_key.clear()
        if self.signing_private_key:
            self.signing_private_key.clear()

    def __repr__(self):
        return (
            f"Identity(name='{self.name}', "
            f"email='{self.email}', "
            f"fingerprint='{self.fingerprint[:20]}...', "
            f"has_private_keys={self.is_own_identity})"
        )


class IdentityStore:
    """
    Manages collection of identities.

    Directory structure:
        ~/.openssl_encrypt/identities/
        ├── alice/           # Own identity
        ├── bob/             # Own identity
        └── contacts/        # Other people's public keys
            └── charlie/

    Example:
        store = IdentityStore()
        identities = store.list_identities()

        alice = store.get_by_name("alice")
        bob = store.get_by_fingerprint("3a:4b:...")
    """

    def __init__(self, base_path: Optional[Path] = None):
        """
        Initialize identity store.

        Args:
            base_path: Custom base path (default: ~/.openssl_encrypt/identities/)
        """
        if base_path:
            self.base_path = Path(base_path)
        else:
            home = Path.home()
            self.base_path = home / ".openssl_encrypt" / "identities"

        self.contacts_path = self.base_path / "contacts"

        # Create directories if they don't exist
        create_secure_directory(self.base_path)
        create_secure_directory(self.contacts_path)

    def list_identities(self, include_contacts: bool = True) -> List[Identity]:
        """
        List all identities.

        Args:
            include_contacts: Include contacts (public keys only)

        Returns:
            List of Identity instances
        """
        identities = []

        # Own identities (with private keys)
        for item in self.base_path.iterdir():
            if item.is_dir() and item.name != "contacts":
                try:
                    identity = Identity.load(item, load_private_keys=False)
                    identities.append(identity)
                except Exception as e:
                    logger.warning(f"Failed to load identity from {item}: {e}")

        # Contacts (public keys only)
        if include_contacts:
            for item in self.contacts_path.iterdir():
                if item.is_dir():
                    try:
                        identity = Identity.load(item, load_private_keys=False)
                        identities.append(identity)
                    except Exception as e:
                        logger.warning(f"Failed to load contact from {item}: {e}")

        return identities

    def get_by_name(
        self,
        name: str,
        passphrase: Optional[str] = None,
        load_private_keys: bool = False,
    ) -> Optional[Identity]:
        """
        Get identity by name.

        Args:
            name: Identity name
            passphrase: Passphrase for private key decryption
            load_private_keys: Whether to load private keys

        Returns:
            Identity or None if not found
        """
        validate_identity_name(name)

        # Check own identities first
        path = self.base_path / name
        if path.exists():
            return Identity.load(path, passphrase, load_private_keys)

        # Check contacts
        contact_path = self.contacts_path / name
        if contact_path.exists():
            return Identity.load(contact_path, passphrase, load_private_keys)

        return None

    def get_by_fingerprint(
        self,
        fingerprint: str,
        passphrase: Optional[str] = None,
        load_private_keys: bool = False,
    ) -> Optional[Identity]:
        """
        Get identity by fingerprint.

        Args:
            fingerprint: The FULL fingerprint to match (M8: prefix matching was
                removed - an empty/short prefix used to silently resolve to the
                first stored identity, a real identity-confusion risk).
            passphrase: Passphrase for private key decryption
            load_private_keys: Whether to load private keys

        Returns:
            Identity or None if not found

        Raises:
            IdentityError: If the fingerprint is empty.
            IdentityAmbiguousError: If more than one identity matches (only
                possible on a genuine fingerprint collision).
        """
        # M8: require a non-empty full fingerprint and match exactly. The old
        # `startswith` allowed "" (matches the first identity) and short,
        # ambiguous prefixes.
        if not fingerprint or not fingerprint.strip():
            raise IdentityError("A full fingerprint is required for lookup (empty given)")

        matches = [
            identity
            for identity in self.list_identities(include_contacts=True)
            if identity.fingerprint == fingerprint
        ]
        if not matches:
            return None
        if len(matches) > 1:
            raise IdentityAmbiguousError(
                f"Fingerprint {fingerprint} matches {len(matches)} identities; refusing to guess"
            )

        identity = matches[0]
        # Reload with private keys if requested
        if load_private_keys and passphrase:
            path = self.base_path / identity.name
            if not path.exists():
                path = self.contacts_path / identity.name
            return Identity.load(path, passphrase, load_private_keys)
        return identity

    def add_identity(
        self,
        identity: Identity,
        passphrase: Optional[str] = None,
        overwrite: bool = False,
        allow_key_change: bool = False,
    ) -> None:
        """
        Add identity to store.

        Args:
            identity: Identity to add
            passphrase: Passphrase for private key encryption
            overwrite: Allow overwriting existing identity (same name)
            allow_key_change: Allow replacing an EXISTING identity's keys with
                DIFFERENT keys (a fingerprint change). Required in addition to
                overwrite for the key-substitution case - a plain overwrite
                must not silently re-pin a contact to a different key (M8).

        Raises:
            IdentityExistsError: If identity exists and overwrite=False
            IdentityKeyChangedError: If an identity with this name exists, its
                stored fingerprint differs from the new one, and
                allow_key_change is False (TOFU pinning).
        """
        validate_identity_name(identity.name)

        # M8: TOFU key-change detection. If a contact/identity with this name is
        # already pinned, compare the stored key fingerprint to the incoming
        # one. A different fingerprint is a key substitution and must be
        # accepted deliberately - even with overwrite=True.
        if not allow_key_change:
            existing = self.get_by_name(identity.name)
            if existing is not None and existing.fingerprint != identity.fingerprint:
                raise IdentityKeyChangedError(
                    identity.name, existing.fingerprint, identity.fingerprint
                )

        if identity.is_own_identity:
            path = self.base_path / identity.name
        else:
            path = self.contacts_path / identity.name

        identity.save(path, passphrase, overwrite)

    def delete_identity(self, name: str) -> bool:
        """
        Delete identity from store.

        Args:
            name: Identity name

        Returns:
            True if deleted, False if not found
        """
        import shutil

        validate_identity_name(name)

        # Check own identities
        path = self.base_path / name
        if path.exists():
            shutil.rmtree(path)
            logger.info(f"Deleted identity '{name}'")
            return True

        # Check contacts
        contact_path = self.contacts_path / name
        if contact_path.exists():
            shutil.rmtree(contact_path)
            logger.info(f"Deleted contact '{name}'")
            return True

        return False

    def identity_exists(self, name: str) -> bool:
        """
        Check if identity exists.

        Args:
            name: Identity name

        Returns:
            True if identity exists
        """
        validate_identity_name(name)
        path = self.base_path / name
        contact_path = self.contacts_path / name
        return path.exists() or contact_path.exists()

    def find_by_fingerprints(self, fingerprints: List[str]) -> List[Identity]:
        """
        Find identities that match any of the given fingerprints.
        Returns only own identities (with private keys).

        Args:
            fingerprints: List of fingerprints to search for

        Returns:
            List of matching Identity objects (without private keys loaded)
        """
        matches = []
        for identity in self.list_identities(include_contacts=False):
            if identity.fingerprint in fingerprints:
                matches.append(identity)
        return matches


def _encrypt_private_key(
    private_key: bytes,
    passphrase: Optional[str],
    protection: Optional[IdentityProtection] = None,
    identity_name: str = "",
) -> bytes:
    """
    Encrypt private key for at-rest storage.

    Supports both legacy password-only encryption and HSM-based protection.

    Format (legacy): [salt:16][nonce:12][ciphertext][tag:16]
    Format (HSM): [nonce:12][ciphertext][tag:16] (salt stored in protection config)

    Args:
        private_key: Private key bytes
        passphrase: Passphrase for encryption (None for HSM_ONLY)
        protection: Optional protection configuration (None = legacy PASSWORD_ONLY)
        identity_name: Identity name (required for HSM challenge)

    Returns:
        Encrypted private key
    """
    if not ARGON2_AVAILABLE:
        raise RuntimeError("argon2-cffi required for private key encryption")

    # Use HSM protection service if configured
    if protection and protection.level != ProtectionLevel.PASSWORD_ONLY:
        protection_service = IdentityKeyProtectionService()
        return protection_service.encrypt_private_key(
            private_key_data=private_key,
            password=passphrase,
            protection=protection,
            identity_name=identity_name,
        )

    # Legacy password-only encryption (backward compatible)
    if not passphrase:
        raise ValueError("Passphrase required for PASSWORD_ONLY encryption")

    # Generate salt
    salt = secrets.token_bytes(16)

    # Derive key with Argon2id
    key = argon2.low_level.hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,  # 64 MB
        parallelism=4,
        hash_len=32,
        type=argon2.low_level.Type.ID,
    )

    # Encrypt with AES-256-GCM
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, private_key, None)

    # Clean sensitive data
    secure_memzero(key)

    # Return: salt + nonce + ciphertext (includes tag)
    return salt + nonce + ciphertext


def _decrypt_private_key(
    encrypted_data: bytes,
    passphrase: Optional[str],
    protection: Optional[IdentityProtection] = None,
    identity_name: str = "",
) -> CryptoKey:
    """
    Decrypt private key from at-rest storage.

    Supports both legacy password-only encryption and HSM-based protection.

    Args:
        encrypted_data: Encrypted private key
        passphrase: Passphrase for decryption (None for HSM_ONLY)
        protection: Optional protection configuration (None = legacy PASSWORD_ONLY)
        identity_name: Identity name (required for HSM challenge)

    Returns:
        CryptoKey with decrypted private key

    Raises:
        ValueError: If decryption fails
        InvalidCredentialsError: If password or HSM response invalid
    """
    if not ARGON2_AVAILABLE:
        raise RuntimeError("argon2-cffi required for private key decryption")

    # Use HSM protection service if configured
    if protection and protection.level != ProtectionLevel.PASSWORD_ONLY:
        protection_service = IdentityKeyProtectionService()
        try:
            private_key_bytes = protection_service.decrypt_private_key(
                encrypted_data=encrypted_data,
                password=passphrase,
                protection=protection,
                identity_name=identity_name,
            )
            # Wrap in CryptoKey for secure memory
            crypto_key = CryptoKey(key_data=private_key_bytes)
            # Clean temporary data
            secure_memzero(private_key_bytes)
            return crypto_key
        except InvalidCredentialsError:
            raise ValueError("Failed to decrypt private key: Invalid password or HSM response")

    # Legacy password-only decryption (backward compatible)
    if not passphrase:
        raise ValueError("Passphrase required for PASSWORD_ONLY decryption")

    if len(encrypted_data) < 28:  # 16 salt + 12 nonce
        raise ValueError("Invalid encrypted private key format")

    # Extract components
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]

    # Derive key with Argon2id
    key = argon2.low_level.hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=argon2.low_level.Type.ID,
    )

    try:
        # Decrypt with AES-256-GCM
        cipher = AESGCM(key)
        private_key_bytes = cipher.decrypt(nonce, ciphertext, None)

        # Wrap in CryptoKey for secure memory
        crypto_key = CryptoKey(key_data=private_key_bytes)

        # Clean temporary data
        secure_memzero(private_key_bytes)
        secure_memzero(key)

        return crypto_key

    except Exception as e:
        secure_memzero(key)
        raise ValueError(f"Failed to decrypt private key: {e}")


if __name__ == "__main__":
    # Simple test
    eprint("Testing Identity Management...")

    # Generate identity
    identity = Identity.generate("test_user", "test@example.com", "test_passphrase")
    eprint(f"Generated: {identity}")
    eprint(f"Fingerprint: {identity.fingerprint}")

    # Test fingerprint verification
    assert identity.verify_fingerprint(), "Fingerprint verification failed"
    eprint("✓ Fingerprint verified")

    # Test context manager
    with identity:
        eprint("✓ Context manager works")

    eprint("\nAll tests passed!")
