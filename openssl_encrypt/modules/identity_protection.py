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
import os
import secrets
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypt_utils import eprint, tty_write
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


# Upper bounds on Argon2 cost parameters read from an identity file's password
# protection block. These come from the (untrusted) identity file and are
# consumed by IdentityKeyProtectionService._derive_key BEFORE the AEAD tag
# authenticates the private key, so a tampered/attacker-authored identity with a
# huge memory_cost would OOM the host pre-authentication (gitlab#129, same class
# as gitlab#128). Legitimate identities use the 64 MB default, far under these
# caps. Mirrors recovery_slots._validate_argon2_params.
_IDENTITY_ARGON2_MAX_TIME = 64
_IDENTITY_ARGON2_MAX_MEMORY = 2 * 1024 * 1024  # KiB (2 GiB)
_IDENTITY_ARGON2_MAX_PARALLELISM = 16


def _validate_identity_argon2_params(time_cost, memory_cost, parallelism) -> None:
    """Reject out-of-range Argon2 cost params from an untrusted identity file."""
    from .crypt_errors import ValidationError

    checks = (
        ("time_cost", time_cost, 1, _IDENTITY_ARGON2_MAX_TIME),
        ("memory_cost", memory_cost, 8, _IDENTITY_ARGON2_MAX_MEMORY),
        ("parallelism", parallelism, 1, _IDENTITY_ARGON2_MAX_PARALLELISM),
    )
    for name, value, lo, hi in checks:
        # bool is an int subclass; reject it and any non-int explicitly.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"Invalid Argon2 {name} in identity protection: {value!r}")
        if not (lo <= value <= hi):
            raise ValidationError(
                f"Argon2 {name} in identity protection out of allowed range "
                f"[{lo}, {hi}]: {value}"
            )


@dataclass
class HSMProtectionConfig:
    """Configuration for HSM-based key protection."""

    hsm_type: str = "yubikey"
    slot: Optional[int] = None  # None = auto-detect
    challenge_salt: bytes = field(default_factory=lambda: b"")
    require_touch: bool = True
    # PIV / PKCS#11 configuration (gitlab#218), persisted so a PIV-protected
    # identity can be unlocked later without the user re-supplying it -- no
    # unlock subcommand takes these flags. None of the three is secret: a
    # PKCS#11 module path, a PIV key slot id, and a biometric-PIN flag.
    pkcs11_lib_path: Optional[str] = None
    piv_slot: Optional[int] = None
    biometric: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {
            "type": self.hsm_type,
            "slot": self.slot,
            "challenge_salt": base64.b64encode(self.challenge_salt).decode("ascii"),
            "require_touch": self.require_touch,
        }
        # Only emit PIV fields when present, so non-PIV identities keep their
        # existing on-disk shape byte-for-byte.
        if self.pkcs11_lib_path is not None:
            data["pkcs11_lib_path"] = self.pkcs11_lib_path
        if self.piv_slot is not None:
            data["piv_slot"] = self.piv_slot
        if self.biometric:
            data["biometric"] = self.biometric
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HSMProtectionConfig":
        """Create from dictionary (JSON deserialization)."""
        return cls(
            hsm_type=data.get("type", "yubikey"),
            slot=data.get("slot"),
            challenge_salt=base64.b64decode(data.get("challenge_salt", "")),
            require_touch=data.get("require_touch", True),
            pkcs11_lib_path=data.get("pkcs11_lib_path"),
            piv_slot=data.get("piv_slot"),
            biometric=data.get("biometric", False),
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


# Standard directories a PKCS#11 module may legitimately live in. A PIV
# identity persists its module path and that path is dlopen'd at unlock, so an
# attacker-supplied identity file (a non-default --identity-store) could
# otherwise point it at a planted .so and get code execution. Restricting the
# load to these directories (plus an explicit opt-in for non-standard installs)
# turns that back into inert configuration (gitlab#218 review finding 2).
_STANDARD_PKCS11_DIRS = (
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/usr/local/lib64",
    "/lib",
    "/lib64",
)

# Environment variable for adding trusted PKCS#11 module directories (os.pathsep
# separated) when a module lives outside the standard locations.
PKCS11_ALLOW_ENV = "OPENSSL_ENCRYPT_PKCS11_ALLOW"


def _allowed_pkcs11_dirs() -> list:
    """The directories a PKCS#11 module may be loaded from (realpath'd)."""
    dirs = [os.path.realpath(d) for d in _STANDARD_PKCS11_DIRS]
    for extra in os.environ.get(PKCS11_ALLOW_ENV, "").split(os.pathsep):
        extra = extra.strip()
        if extra:
            dirs.append(os.path.realpath(extra))
    return dirs


def validate_pkcs11_module_path(path: Optional[str]) -> None:
    """Refuse a PKCS#11 module path that is not a real file in a trusted dir.

    Applied wherever the PIV plugin is loaded from a (possibly persisted) path,
    so a tampered identity file cannot dlopen an attacker-chosen library
    (gitlab#218 review finding 2). Symlinks are resolved first, so the *target*
    must be within an allowed directory.

    Args:
        path: The PKCS#11 module path from the identity's PIV config or argv.

    Raises:
        ValueError: If the path is empty, not absolute, missing, not a regular
            file, or resolves outside the allowed directories.
    """
    if not path or not os.path.isabs(path):
        raise ValueError(f"PKCS#11 module path must be an absolute path (got {path!r}).")
    resolved = os.path.realpath(path)
    if not os.path.isfile(resolved):
        raise ValueError(f"PKCS#11 module not found or not a regular file: {resolved}")
    for base in _allowed_pkcs11_dirs():
        if resolved == base or resolved.startswith(base + os.sep):
            return
    raise ValueError(
        f"PKCS#11 module {resolved} is outside the trusted module directories "
        f"({', '.join(_STANDARD_PKCS11_DIRS)}). Loading it would run its code; a "
        f"module named by an untrusted identity file is refused (gitlab#218). "
        f"Install the module in a standard library directory, or add its "
        f"directory to {PKCS11_ALLOW_ENV}."
    )


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

    def __init__(
        self,
        hsm_plugin=None,
        hsm_type: str = "yubikey",
        pkcs11_lib_path: Optional[str] = None,
        piv_slot: Optional[int] = None,
        biometric: bool = False,
    ):
        """
        Initialize the protection service.

        Args:
            hsm_plugin: Optional explicit plugin instance — bypasses
                hsm_type-based lookup. Useful for tests and direct injection.
            hsm_type: Which HSM plugin to load when none is injected.
                Supported: "yubikey" (default, preserves existing behavior),
                "onlykey", "piv". Other values cause _get_hsm_plugin to return
                None.
            pkcs11_lib_path: PKCS#11 module path for hsm_type="piv" (required
                for PIV; ignored otherwise). Persisted with the identity so it
                is available at unlock time (gitlab#218).
            piv_slot: PIV key slot id (e.g. 0x9A) for hsm_type="piv".
            biometric: Whether the PIV token uses biometric PIN entry.
        """
        self._hsm_plugin = hsm_plugin
        self._hsm_type = hsm_type
        self._pkcs11_lib_path = pkcs11_lib_path
        self._piv_slot = piv_slot
        self._biometric = biometric
        self._hsm_checked = False
        self._cached_pepper = None  # Cache pepper for single operation

    @property
    def _device_label(self) -> str:
        """Human-readable name of the configured HSM device (gitlab#218).

        The error messages below hardcoded "Yubikey", which misled OnlyKey
        users into thinking the wrong device was expected.
        """
        if self._hsm_type == "onlykey":
            return "OnlyKey"
        if self._hsm_type == "piv":
            return "PIV token"
        return "Yubikey"

    def _get_hsm_plugin(self):
        """Lazy-load the HSM plugin according to self._hsm_type."""
        if self._hsm_plugin is not None:
            return self._hsm_plugin
        if self._hsm_checked:
            return self._hsm_plugin  # may be None — already attempted
        self._hsm_checked = True
        try:
            if self._hsm_type == "yubikey":
                from openssl_encrypt.plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin

                self._hsm_plugin = YubikeyHSMPlugin()
            elif self._hsm_type == "onlykey":
                from openssl_encrypt.plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin

                self._hsm_plugin = OnlykeyHSMPlugin()
            elif self._hsm_type == "piv":
                # PIV is configured at construction (path/slot/biometric),
                # unlike the CR plugins whose slot arrives via the security
                # context (gitlab#218). The same construction the encrypt path
                # uses; the plugin defaults to an interactive PIN prompt.
                from openssl_encrypt.plugins.hsm.piv_card import PIVHSMPlugin

                # The path may come from a persisted (untrusted) identity file
                # and is about to be dlopen'd -- refuse anything outside the
                # trusted module directories (gitlab#218 finding 2).
                validate_pkcs11_module_path(self._pkcs11_lib_path)
                self._hsm_plugin = PIVHSMPlugin(
                    pkcs11_lib_path=self._pkcs11_lib_path,
                    slot_index=0,
                    piv_slot=(self._piv_slot if self._piv_slot is not None else 0x9A),
                    biometric=bool(self._biometric),
                )
            # Other hsm_type values → leave self._hsm_plugin as None
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
            raise HSMNotAvailableError(f"{self._device_label} plugin not available")

        # Check if the device is available
        init_result = plugin.initialize({})
        if not init_result.success:
            raise HSMNotAvailableError(
                f"No {self._device_label} detected. Please insert your "
                f"{self._device_label}. ({init_result.message})"
            )

        # Generate challenge
        challenge = self._generate_hsm_challenge(hsm_config.challenge_salt, identity_name)

        # Determine slot. Only the Challenge-Response devices use an HMAC-SHA1
        # slot; PIV keys are addressed by their configured piv_slot at plugin
        # construction, so slot stays None for PIV and is ignored below
        # (gitlab#218).
        slot = hsm_config.slot
        if slot is None and self._hsm_type in ("yubikey", "onlykey"):
            slot = self.detect_hsm_slot()
            if slot is None:
                raise HSMNotAvailableError(
                    f"No Challenge-Response slot configured on your "
                    f"{self._device_label}. Please configure an HMAC-SHA1 "
                    "Challenge-Response slot."
                )

        # Write touch prompt directly to the terminal (bypasses stdout/stderr
        # redirection) so it's always visible to the user. PIV handles its own
        # PIN/biometric prompt inside the plugin, so this Yubikey/OnlyKey touch
        # prompt is skipped for it (gitlab#218).
        if hsm_config.require_touch and self._hsm_type in ("yubikey", "onlykey"):
            tty_write(f"👆 Touch your {self._device_label} to continue...\n")

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
            # Only set the CR slot when there is one. For PIV slot is None, and
            # injecting {"slot": None} would OVERRIDE the plugin's constructed
            # slot_index (dict.get finds the key and returns None instead of
            # falling back), breaking real PIV derivation (gitlab#218).
            if slot is not None:
                context.config["slot"] = slot

            result = plugin.get_hsm_pepper(challenge, context)
            if not result.success:
                raise HSMNotAvailableError(f"HSM operation failed: {result.message}")

            pepper = result.data.get("hsm_pepper")
            # Check the exact length the configured device returns rather than a
            # hardcoded 20: Yubikey/OnlyKey return a 20-byte HMAC-SHA1 response,
            # PIV a 32-byte HKDF-derived pepper (gitlab#218). Failing closed on an
            # unexpected length rejects a truncated/garbage response. For a given
            # identity the same device+challenge yields the same length every
            # time, so create and unlock stay consistent.
            expected_len = 20 if self._hsm_type in ("yubikey", "onlykey") else 32
            if pepper is None or len(pepper) != expected_len:
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

        # Bound the (untrusted, file-supplied) Argon2 cost before deriving: these
        # parameters are consumed before the AEAD tag authenticates the private
        # key, so an oversized memory_cost would OOM the host pre-authentication
        # (gitlab#129). Legitimate identities use the 64 MB default, far under
        # the cap.
        _validate_identity_argon2_params(
            password_config.time_cost,
            password_config.memory_cost,
            password_config.parallelism,
        )

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
                raise HSMNotAvailableError(
                    f"HSM protection requested but no {self._device_label} available"
                )

            # PIV has no HMAC-SHA1 slot to detect; its key is addressed by
            # piv_slot at construction. Persist the PIV config so the identity
            # can be unlocked later without re-supplying it (gitlab#218).
            if self._hsm_type in ("yubikey", "onlykey"):
                resolved_slot = hsm_slot or self.detect_hsm_slot()
            else:
                resolved_slot = hsm_slot

            hsm_config = HSMProtectionConfig(
                hsm_type=self._hsm_type,
                slot=resolved_slot,
                challenge_salt=secrets.token_bytes(self.CHALLENGE_SALT_SIZE),
                require_touch=require_touch,
                pkcs11_lib_path=self._pkcs11_lib_path,
                piv_slot=self._piv_slot,
                biometric=self._biometric,
            )

        return IdentityProtection(
            level=level, password_config=password_config, hsm_config=hsm_config
        )
