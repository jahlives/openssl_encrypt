#!/usr/bin/env python3
"""
Identity Key Protection Module

This module provides HSM-based protection for identity private keys.
Supports three protection levels:
- PASSWORD_ONLY: Traditional password-only protection
- PASSWORD_AND_HSM: Requires both password AND hardware token (maximum security)
- HSM_ONLY: Hardware token only (for automation)

The protection uses the existing Yubikey Challenge-Response plugin to derive
an HSM pepper that is combined with the password for key derivation.
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .secure_memory import SecureBytes, secure_memzero


class ProtectionLevel(Enum):
    """Protection level for identity private keys."""

    PASSWORD_ONLY = "password_only"
    """Traditional password-only protection (default, backward compatible)."""

    PASSWORD_AND_HSM = "password_and_hsm"
    """Requires both password AND HSM (maximum security)."""

    HSM_ONLY = "hsm_only"
    """Requires only HSM, no password (for automation)."""


@dataclass
class PasswordProtectionConfig:
    """Configuration for password-based key protection."""

    kdf: str = "argon2id"
    time_cost: int = 3
    memory_cost: int = 65536  # 64 MB
    parallelism: int = 4
    salt: bytes = field(default_factory=lambda: b"")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "kdf": self.kdf,
            "kdf_params": {
                "time_cost": self.time_cost,
                "memory_cost": self.memory_cost,
                "parallelism": self.parallelism,
            },
            "salt": base64.b64encode(self.salt).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PasswordProtectionConfig":
        """Create from dictionary (JSON deserialization)."""
        params = data.get("kdf_params", {})
        return cls(
            kdf=data.get("kdf", "argon2id"),
            time_cost=params.get("time_cost", 3),
            memory_cost=params.get("memory_cost", 65536),
            parallelism=params.get("parallelism", 4),
            salt=base64.b64decode(data.get("salt", "")),
        )


@dataclass
class HSMProtectionConfig:
    """Configuration for HSM-based key protection."""

    hsm_type: str = "yubikey"
    slot: Optional[int] = None  # None = auto-detect
    challenge_salt: bytes = field(default_factory=lambda: b"")
    require_touch: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.hsm_type,
            "slot": self.slot,
            "challenge_salt": base64.b64encode(self.challenge_salt).decode("ascii"),
            "require_touch": self.require_touch,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HSMProtectionConfig":
        """Create from dictionary (JSON deserialization)."""
        return cls(
            hsm_type=data.get("type", "yubikey"),
            slot=data.get("slot"),
            challenge_salt=base64.b64decode(data.get("challenge_salt", "")),
            require_touch=data.get("require_touch", True),
        )


@dataclass
class IdentityProtection:
    """Complete protection configuration for an identity."""

    level: ProtectionLevel
    password_config: Optional[PasswordProtectionConfig] = None
    hsm_config: Optional[HSMProtectionConfig] = None

    def requires_password(self) -> bool:
        """Check if password is required for this protection level."""
        return self.level in (ProtectionLevel.PASSWORD_ONLY, ProtectionLevel.PASSWORD_AND_HSM)

    def requires_hsm(self) -> bool:
        """Check if HSM is required for this protection level."""
        return self.level in (ProtectionLevel.HSM_ONLY, ProtectionLevel.PASSWORD_AND_HSM)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {"level": self.level.value}
        if self.password_config:
            result["password"] = self.password_config.to_dict()
        if self.hsm_config:
            result["hsm"] = self.hsm_config.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IdentityProtection":
        """Create from dictionary (JSON deserialization)."""
        level = ProtectionLevel(data.get("level", "password_only"))

        password_config = None
        if "password" in data:
            password_config = PasswordProtectionConfig.from_dict(data["password"])

        hsm_config = None
        if "hsm" in data:
            hsm_config = HSMProtectionConfig.from_dict(data["hsm"])

        return cls(level=level, password_config=password_config, hsm_config=hsm_config)


# Exceptions
class IdentityProtectionError(Exception):
    """Base exception for identity protection errors."""

    pass


class HSMNotAvailableError(IdentityProtectionError):
    """HSM is not available or not configured."""

    pass


class HSMTouchTimeoutError(IdentityProtectionError):
    """Timeout waiting for HSM touch."""

    pass


class InvalidCredentialsError(IdentityProtectionError):
    """Invalid password or HSM response."""

    pass


class IdentityKeyProtectionService:
    """
    Service for protecting identity private keys with password and/or HSM.

    Security Model:
    ===============

    PASSWORD_ONLY:
        key_material = password
        derived_key = Argon2id(key_material, salt)

    PASSWORD_AND_HSM:
        hsm_pepper = HMAC-SHA1(yubikey_secret, challenge)
        key_material = password + hsm_pepper
        derived_key = Argon2id(key_material, salt)

    HSM_ONLY:
        hsm_pepper = HMAC-SHA1(yubikey_secret, challenge)
        key_material = hsm_pepper
        derived_key = Argon2id(key_material, salt)

    The derived key is then used to encrypt private keys with AES-256-GCM.
    """

    # Constants
    SALT_SIZE = 16
    CHALLENGE_SALT_SIZE = 32
    NONCE_SIZE = 12
    KEY_SIZE = 32  # AES-256

    def __init__(self, hsm_plugin=None):
        """
        Initialize the protection service.

        Args:
            hsm_plugin: Optional Yubikey plugin instance (lazy loaded if not provided)
        """
        self._hsm_plugin = hsm_plugin
        self._hsm_checked = False
        self._cached_pepper = None  # Cache pepper for single operation

    def _get_hsm_plugin(self):
        """Lazy-load the HSM plugin."""
        if self._hsm_plugin is None and not self._hsm_checked:
            self._hsm_checked = True
            try:
                from openssl_encrypt.plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin

                self._hsm_plugin = YubikeyHSMPlugin()
            except ImportError:
                pass
        return self._hsm_plugin

    def is_hsm_available(self) -> bool:
        """Check if HSM is available."""
        plugin = self._get_hsm_plugin()
        if plugin is None:
            return False
        # Check if plugin initialized successfully
        init_result = plugin.initialize({})
        return init_result.success

    def detect_hsm_slot(self) -> Optional[int]:
        """Detect configured HSM slot (1 or 2)."""
        plugin = self._get_hsm_plugin()
        if plugin is None:
            return None
        # Call the plugin's slot detection
        try:
            return plugin._find_challenge_response_slot()
        except Exception:
            return None

    def _generate_hsm_challenge(self, challenge_salt: bytes, identity_name: str) -> bytes:
        """
        Generate HSM challenge.

        Challenge = SHA256(challenge_salt || "identity" || identity_name)

        This ensures each identity has a unique challenge even when using
        the same Yubikey.

        Args:
            challenge_salt: Random salt for challenge (32 bytes)
            identity_name: Name of the identity

        Returns:
            SHA256 hash (32 bytes, truncated to 16 for Yubikey)
        """
        challenge_input = challenge_salt + b"identity" + identity_name.encode("utf-8")
        full_challenge = hashlib.sha256(challenge_input).digest()
        # Yubikey Challenge-Response expects 16-byte challenge
        return full_challenge[:16]

    def _get_hsm_pepper(self, hsm_config: HSMProtectionConfig, identity_name: str) -> bytes:
        """
        Get HSM pepper via Challenge-Response.

        Args:
            hsm_config: HSM configuration
            identity_name: Identity name (used in challenge)

        Returns:
            20-byte HMAC-SHA1 response from Yubikey

        Raises:
            HSMNotAvailableError: Yubikey not found
            HSMTouchTimeoutError: Touch timeout
        """
        # Check cache first
        if self._cached_pepper is not None:
            return self._cached_pepper

        plugin = self._get_hsm_plugin()
        if plugin is None:
            raise HSMNotAvailableError("Yubikey plugin not available")

        # Check if Yubikey is available
        init_result = plugin.initialize({})
        if not init_result.success:
            raise HSMNotAvailableError(
                f"No Yubikey detected. Please insert your Yubikey. ({init_result.message})"
            )

        # Generate challenge
        challenge = self._generate_hsm_challenge(hsm_config.challenge_salt, identity_name)

        # Determine slot
        slot = hsm_config.slot
        if slot is None:
            slot = self.detect_hsm_slot()
            if slot is None:
                raise HSMNotAvailableError(
                    "No Challenge-Response slot configured on Yubikey. "
                    "Please configure slot 1 or 2 for HMAC-SHA1 Challenge-Response."
                )

        # Show touch prompt if required
        if hsm_config.require_touch:
            print("Touch your Yubikey to continue...", flush=True)

        # Perform Challenge-Response
        try:
            from openssl_encrypt.modules.plugin_system.plugin_base import (
                PluginCapability,
                PluginSecurityContext,
            )

            context = PluginSecurityContext(
                plugin_id=plugin.plugin_id,
                capabilities={PluginCapability.ACCESS_CONFIG},
            )
            context.metadata["salt"] = challenge
            context.config["slot"] = slot

            result = plugin.get_hsm_pepper(challenge, context)
            if not result.success:
                raise HSMNotAvailableError(f"HSM operation failed: {result.message}")

            pepper = result.data.get("hsm_pepper")
            if pepper is None or len(pepper) != 20:
                raise HSMNotAvailableError("Invalid HSM pepper returned")

            # Cache for this operation
            self._cached_pepper = pepper
            return pepper

        except TimeoutError:
            raise HSMTouchTimeoutError(
                "Yubikey touch timeout. Please try again and touch your Yubikey."
            )
        except Exception as e:
            if isinstance(e, (HSMNotAvailableError, HSMTouchTimeoutError)):
                raise
            raise HSMNotAvailableError(f"HSM operation failed: {e}")

    def clear_pepper_cache(self):
        """Clear cached HSM pepper."""
        if self._cached_pepper is not None:
            secure_memzero(bytearray(self._cached_pepper))
            self._cached_pepper = None

    def _derive_key(
        self,
        password: Optional[str],
        hsm_pepper: Optional[bytes],
        password_config: PasswordProtectionConfig,
    ) -> bytes:
        """
        Derive encryption key using Argon2id.

        Args:
            password: User password (or None for HSM_ONLY)
            hsm_pepper: HSM pepper (or None for PASSWORD_ONLY)
            password_config: KDF parameters

        Returns:
            32-byte derived key

        Raises:
            ValueError: If neither password nor hsm_pepper provided
        """
        # Build key material
        key_material = b""

        if password:
            key_material += password.encode("utf-8")

        if hsm_pepper:
            key_material += hsm_pepper

        if not key_material:
            raise ValueError("Either password or HSM pepper must be provided")

        # Derive key with Argon2id
        derived_key = hash_secret_raw(
            secret=key_material,
            salt=password_config.salt,
            time_cost=password_config.time_cost,
            memory_cost=password_config.memory_cost,
            parallelism=password_config.parallelism,
            hash_len=self.KEY_SIZE,
            type=Type.ID,
        )

        # Zero key_material
        key_material_array = bytearray(key_material)
        secure_memzero(key_material_array)

        return derived_key

    def encrypt_private_key(
        self,
        private_key_data: bytes,
        password: Optional[str],
        protection: IdentityProtection,
        identity_name: str,
    ) -> bytes:
        """
        Encrypt a private key with password and/or HSM.

        Args:
            private_key_data: Raw private key bytes
            password: User password (if required by protection level)
            protection: Protection configuration
            identity_name: Identity name (for HSM challenge)

        Returns:
            Encrypted data: nonce (12) + ciphertext + tag (16)

        Raises:
            ValueError: If required credentials not provided
            HSMNotAvailableError: If HSM required but not available
        """
        # Validate inputs
        if protection.requires_password() and not password:
            raise ValueError("Password required for this protection level")

        if protection.password_config is None:
            raise ValueError("Password config required")

        # Get HSM pepper if required
        hsm_pepper = None
        if protection.requires_hsm():
            if protection.hsm_config is None:
                raise ValueError("HSM config required for this protection level")
            hsm_pepper = self._get_hsm_pepper(protection.hsm_config, identity_name)

        # Derive encryption key
        encryption_key = self._derive_key(
            password=password if protection.requires_password() else None,
            hsm_pepper=hsm_pepper,
            password_config=protection.password_config,
        )

        try:
            # Encrypt with AES-256-GCM
            nonce = secrets.token_bytes(self.NONCE_SIZE)
            aesgcm = AESGCM(encryption_key)
            ciphertext = aesgcm.encrypt(nonce, private_key_data, None)

            return nonce + ciphertext

        finally:
            # Secure cleanup
            secure_memzero(bytearray(encryption_key))
            if hsm_pepper:
                secure_memzero(bytearray(hsm_pepper))

    def decrypt_private_key(
        self,
        encrypted_data: bytes,
        password: Optional[str],
        protection: IdentityProtection,
        identity_name: str,
    ) -> bytes:
        """
        Decrypt a private key with password and/or HSM.

        Args:
            encrypted_data: Encrypted private key (nonce + ciphertext + tag)
            password: User password (if required by protection level)
            protection: Protection configuration
            identity_name: Identity name (for HSM challenge)

        Returns:
            Decrypted private key bytes

        Raises:
            ValueError: If required credentials not provided
            HSMNotAvailableError: If HSM required but not available
            InvalidCredentialsError: If decryption fails
        """
        # Validate inputs
        if protection.requires_password() and not password:
            raise ValueError("Password required for this protection level")

        if protection.password_config is None:
            raise ValueError("Password config required")

        if len(encrypted_data) < self.NONCE_SIZE + 16:  # nonce + min tag
            raise InvalidCredentialsError("Invalid encrypted data size")

        # Get HSM pepper if required
        hsm_pepper = None
        if protection.requires_hsm():
            if protection.hsm_config is None:
                raise ValueError("HSM config required for this protection level")
            hsm_pepper = self._get_hsm_pepper(protection.hsm_config, identity_name)

        # Derive encryption key
        encryption_key = self._derive_key(
            password=password if protection.requires_password() else None,
            hsm_pepper=hsm_pepper,
            password_config=protection.password_config,
        )

        try:
            # Extract nonce and ciphertext
            nonce = encrypted_data[: self.NONCE_SIZE]
            ciphertext = encrypted_data[self.NONCE_SIZE :]

            # Decrypt with AES-256-GCM
            aesgcm = AESGCM(encryption_key)
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                return plaintext
            except Exception:
                raise InvalidCredentialsError(
                    "Failed to decrypt private key. Invalid password or HSM response."
                )

        finally:
            # Secure cleanup
            secure_memzero(bytearray(encryption_key))
            if hsm_pepper:
                secure_memzero(bytearray(hsm_pepper))

    def create_protection_config(
        self, level: ProtectionLevel, hsm_slot: Optional[int] = None, require_touch: bool = True
    ) -> IdentityProtection:
        """
        Create a new protection configuration.

        Args:
            level: Desired protection level
            hsm_slot: HSM slot (None = auto-detect)
            require_touch: Whether HSM touch is required

        Returns:
            New IdentityProtection instance

        Raises:
            HSMNotAvailableError: If HSM required but not available
        """
        # Create password config (always needed for salt storage)
        password_config = PasswordProtectionConfig(salt=secrets.token_bytes(self.SALT_SIZE))

        # Create HSM config if required
        hsm_config = None
        if level in (ProtectionLevel.PASSWORD_AND_HSM, ProtectionLevel.HSM_ONLY):
            if not self.is_hsm_available():
                raise HSMNotAvailableError("HSM protection requested but no Yubikey available")

            hsm_config = HSMProtectionConfig(
                hsm_type="yubikey",
                slot=hsm_slot or self.detect_hsm_slot(),
                challenge_salt=secrets.token_bytes(self.CHALLENGE_SALT_SIZE),
                require_touch=require_touch,
            )

        return IdentityProtection(
            level=level, password_config=password_config, hsm_config=hsm_config
        )
