#!/usr/bin/env python3
"""
USB Drive Encryption and Portable Installation Module

Creates encrypted, self-contained USB drives with OpenSSL Encrypt portable
installations, featuring auto-run capabilities and secure workspaces.

This module provides air-gapped portable security for scenarios where
network connectivity is not available or desired.

Security Features:
- Encrypted workspace with AES-256-GCM
- Tamper detection and integrity verification
- Secure file deletion on eject
- Isolated portable environment
- Pre-loaded encrypted keystores
"""

import base64
import hashlib
import json
import logging
import os
import platform
import secrets
import shutil
import stat
import tempfile
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Import secure memory functions
try:
    from ..crypt_errors import KeystoreError
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.crypt_errors import KeystoreError
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

# Set up module logger
logger = logging.getLogger(__name__)


# The KDF a new drive gets when the user names no rounds at all.
#
# Without this, a plain `create-usb --usb-path X` built an empty dict, passed
# hash_config=None, and derived with PBKDF2-HMAC-SHA256 at 100 000 iterations
# -- what crypt_cli's own comment calls "below the OWASP floor" -- to protect
# an encrypted keystore and integrity manifest on removable media, the
# highest offline-exposure artifact this tool writes (gitlab#205).
#
# Expressed as hash ROUNDS rather than a raised PBKDF2 count on purpose. The
# fallback's iteration count is recorded nowhere a verifier can read: the
# drive's security_profile lives inside .integrity, which is encrypted with
# the key derived from that profile, and verify_usb_integrity always builds a
# STANDARD creator. Raising it would derive a different key, fail to decrypt
# .integrity, and report a good drive as TAMPERED. Rounds, by contrast, are
# stored in hash_config.json and .integrity and read back on verify, so a new
# drive carries its own parameters and the no-config path stays untouched for
# drives already in existence.
_DEFAULT_USB_HASH_ROUNDS = 600_000


def default_usb_hash_config() -> Dict[str, int]:
    """The hash config a create-usb with no explicit rounds should record."""
    return {"sha512": _DEFAULT_USB_HASH_ROUNDS}


class USBCreationError(KeystoreError):
    """USB drive creation specific errors"""

    pass


class USBSecurityProfile(Enum):
    """Security profiles for USB drives"""

    STANDARD = "standard"
    HIGH_SECURITY = "high-security"
    PARANOID = "paranoid"


class USBDriveCreator:
    """
    USB Drive Encryption and Portable Installation System

    Creates self-contained, encrypted USB drives with OpenSSL Encrypt
    portable installations and secure workspaces.
    """

    # USB Drive configuration
    PORTABLE_DIR = "openssl_encrypt_portable"
    CONFIG_DIR = "config"
    DATA_DIR = "data"
    LOGS_DIR = "logs"

    # Security constants
    SALT_LENGTH = 32
    KEY_LENGTH = 32  # 256-bit AES key
    NONCE_LENGTH = 12  # GCM nonce
    TAG_LENGTH = 16  # GCM authentication tag

    # Integrity constants
    INTEGRITY_FILE = ".integrity"
    SALT_FILE = "salt.bin"  # per-drive KDF salt (plaintext; salts are not secret)
    VERSION = "1.0"

    # Integrity manifest scan version (gitlab#132 F13). v2 manifests additionally
    # detect ADDED executable-type files and tampered/added root-level autorun.*
    # that were not present at creation. v1 manifests (drives created before this
    # fix) carry no such flag and are verified exactly as before — only listed
    # files are checked — so existing drives keep working (backward compatible).
    INTEGRITY_SCAN_VERSION = 2
    # v2 integrity is an ALLOWLIST, not an extension denylist: every file in the
    # tool tree is recorded at creation, and verification flags ANY file present
    # afterward that is not in that record — so a planted .dll/.so/.pyd/.exe or
    # any other payload dropped into the tool tree is caught, not just a fixed set
    # of extensions (gitlab#132 F13). The genuinely user-mutable subtrees below —
    # the encrypt/decrypt workspace and logs — are excluded so ordinary use
    # (encrypting files onto the drive) does not trip verification.
    #   (values compared against the FIRST path component under portable_root)
    _INTEGRITY_MUTABLE_SUBDIRS = ("data", "logs")  # == DATA_DIR, LOGS_DIR
    # Artifacts legitimately not in the manifest: the manifest itself, and files
    # written after it (the cryptographic hash manifest + its instructions).
    _INTEGRITY_EXCLUDED_NAMES = (".integrity", "hash_manifest.enc", "VERIFY_INTEGRITY.md")
    # Root-level auto-run files (they live at the USB root, above the portable
    # directory, and are executed by the OS on insert — so they must be integrity
    # protected and any unexpected one must be flagged).
    _ROOT_AUTORUN_NAMES = ("autorun.inf", "autorun.sh", ".autorun")

    # Legacy fixed salt used by pre-fix drives. Retained ONLY so that USB drives
    # created before per-drive salts were introduced remain decryptable/verifiable.
    # New drives MUST use a random per-drive salt (see _load_or_create_salt).
    _LEGACY_FIXED_SALT = b"openssl_encrypt_usb_v1.0_salt_2024"

    def __init__(self, security_profile: USBSecurityProfile = USBSecurityProfile.STANDARD):
        """
        Initialize USB Drive Creator

        Args:
            security_profile: Security level for the USB drive
        """
        if not CRYPTO_AVAILABLE:
            raise USBCreationError("Cryptography dependencies not available")

        self.security_profile = security_profile
        self.temp_files = []  # Track temp files for cleanup

        logger.debug(
            f"USB Drive Creator initialized with security profile: {security_profile.value}"
        )

    def create_portable_usb(
        self,
        usb_path: Union[str, Path],
        password: str,
        executable_path: Optional[str] = None,
        keystore_path: Optional[str] = None,
        include_logs: bool = False,
        custom_config: Optional[Dict] = None,
        hash_config: Optional[Dict] = None,
        algorithm: str = "fernet",
        manifest_password: Optional[str] = None,
        manifest_security_profile: Optional[str] = None,
        manifest_hash_config: Optional[Dict] = None,
        force: bool = False,
    ) -> Dict[str, any]:
        """
        Create encrypted portable USB drive

        Args:
            usb_path: Path to USB drive root
            password: Master password for USB encryption
            executable_path: Path to OpenSSL Encrypt executable (optional)
            keystore_path: Path to keystore to include (optional)
            include_logs: Whether to enable logging on USB
            custom_config: Custom configuration overrides
            hash_config: Hash chaining configuration (same format as main CLI)

        Returns:
            Dictionary with creation results and metadata
        """
        try:
            usb_path = Path(usb_path)

            if not usb_path.exists():
                raise USBCreationError(f"USB path does not exist: {usb_path}")

            if not self._is_removable_drive(usb_path):
                logger.warning(f"Path {usb_path} may not be a removable drive")

            # Refuse to clobber a root autorun file the user already has
            # (gitlab#207). These are written unconditionally at the USB
            # ROOT, above the portable directory, so a mistyped --usb-path --
            # which only produced a log warning -- silently replaced them.
            if not force:
                clashes = [name for name in self._ROOT_AUTORUN_NAMES if (usb_path / name).exists()]
                if clashes:
                    raise USBCreationError(
                        f"{usb_path} already contains {', '.join(clashes)}. "
                        "Creating a drive here would overwrite them. Re-run with "
                        "--yes if this is the drive you meant."
                    )

            # A supplied path that does not exist is a typo, not a choice
            # (gitlab#206). Both options used to take a silent else branch
            # that recorded `included: False`, and the CLI summary simply
            # omitted the line -- so the user believed their keystore was on
            # the drive. Checked up front, before anything is written.
            for option, candidate in (
                ("--executable-path", executable_path),
                ("--keystore-to-include", keystore_path),
            ):
                if candidate and not os.path.exists(candidate):
                    raise USBCreationError(f"{option} does not exist: {candidate}")

            # Create secure password key
            secure_password = SecureBytes(password.encode("utf-8"))

            # Create directory structure
            portable_root = usb_path / self.PORTABLE_DIR
            config_dir = portable_root / self.CONFIG_DIR
            data_dir = portable_root / self.DATA_DIR

            # Create directories
            for dir_path in [portable_root, config_dir, data_dir]:
                dir_path.mkdir(parents=True, exist_ok=True)

            if include_logs:
                logs_dir = portable_root / self.LOGS_DIR
                logs_dir.mkdir(exist_ok=True)

            # Copy entire openssl_encrypt project for full CLI compatibility
            project_copy_info = self._copy_openssl_encrypt_project(portable_root)

            # Generate a unique per-drive KDF salt (defeats precomputation and
            # ensures two drives with the same password do not share a key), then
            # derive the encryption key from the password using hash chaining.
            salt = self._load_or_create_salt(portable_root, create=True)
            encryption_key = self._derive_encryption_key(secure_password, hash_config, salt)

            # Create portable configuration
            config = self._create_portable_config(custom_config, include_logs)
            config_path = config_dir / "portable.conf"

            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
            self._restrict_to_owner(config_path)

            # Copy executable if provided
            executable_info = {}
            if executable_path and os.path.exists(executable_path):
                dest_exe = portable_root / "openssl_encrypt"
                if platform.system() == "Windows":
                    dest_exe = portable_root / "openssl_encrypt.exe"

                shutil.copy2(executable_path, dest_exe)
                dest_exe.chmod(0o755)  # Make executable
                executable_info["included"] = True
                executable_info["path"] = str(dest_exe.relative_to(usb_path))
            else:
                executable_info["included"] = False
                executable_info["note"] = "Executable not provided or not found"

            # Create encrypted keystore if provided
            keystore_info = {}
            if keystore_path and os.path.exists(keystore_path):
                keystore_info = self._encrypt_keystore_to_usb(
                    keystore_path, config_dir / "keystore.encrypted", encryption_key
                )
            else:
                keystore_info["included"] = False

            # Create encrypted workspace with transparent encryption support
            workspace_info = self._create_encrypted_workspace(data_dir, encryption_key)

            # Create transparent encryption helper scripts
            self._create_transparent_encryption_helpers(portable_root, hash_config, algorithm)

            # Create auto-run files
            autorun_info = self._create_autorun_files(usb_path, portable_root)

            # Store hash_config in a separate metadata file if complex hashing is used
            if hash_config:
                self._store_hash_config_metadata(config_dir, hash_config)

            # Generate integrity file and cryptographic hash manifest. Pass
            # usb_path so the root-level autorun.* files (above portable_root)
            # are integrity-protected (gitlab#132 F13).
            integrity_info = self._create_integrity_file(
                portable_root, encryption_key, hash_config, usb_root=usb_path
            )
            manifest_info = self._create_hash_manifest(
                portable_root,
                password,
                hash_config,
                manifest_password,
                manifest_security_profile,
                manifest_hash_config,
                algorithm,
            )

            # Clean up sensitive data
            secure_memzero(encryption_key)

            return {
                "success": True,
                "usb_path": str(usb_path),
                "portable_root": str(portable_root.relative_to(usb_path)),
                "security_profile": self.security_profile.value,
                "executable": executable_info,
                "keystore": keystore_info,
                "workspace": workspace_info,
                "autorun": autorun_info,
                "integrity": integrity_info,
                "manifest": manifest_info,
                "project_copy": project_copy_info,
                "created_at": time.time(),
            }

        except Exception as e:
            # Clean up on error
            self._cleanup_temp_files()
            raise USBCreationError(f"Failed to create portable USB: {e}")

        finally:
            # Always clean up secure memory
            if "secure_password" in locals():
                secure_memzero(secure_password)
            if "encryption_key" in locals():
                secure_memzero(encryption_key)

    def verify_usb_integrity(
        self,
        usb_path: Union[str, Path],
        password: str,
        hash_config: Optional[Dict] = None,
    ) -> Dict[str, any]:
        """
        Verify USB drive integrity and tamper detection

        Args:
            usb_path: Path to USB drive root
            password: Master password for verification
            hash_config: Hash chaining configuration (same format as main CLI)

        Returns:
            Dictionary with verification results
        """
        try:
            usb_path = Path(usb_path)
            portable_root = usb_path / self.PORTABLE_DIR

            if not portable_root.exists():
                raise USBCreationError(f"Portable installation not found: {portable_root}")

            # First, try to read the hash_config from the integrity file if not provided
            if hash_config is None:
                try:
                    stored_hash_config = self._read_hash_config_from_integrity(
                        portable_root, password
                    )
                    if stored_hash_config:
                        hash_config = stored_hash_config
                        logger.debug("Successfully read hash_config from USB integrity file")
                except Exception as e:
                    logger.debug(f"Could not read hash_config from integrity file: {e}")
                    # Continue with None hash_config (will use PBKDF2 fallback)

            # Create secure password key
            secure_password = SecureBytes(password.encode("utf-8"))
            encryption_key = None
            try:
                # Load this drive's salt (legacy fixed salt for pre-fix drives).
                salt = self._load_or_create_salt(portable_root, create=False)
                encryption_key = self._derive_encryption_key(secure_password, hash_config, salt)

                # Verify integrity file
                integrity_path = portable_root / self.INTEGRITY_FILE
                if not integrity_path.exists():
                    raise USBCreationError("Integrity file missing - USB may be tampered")

                return self._verify_integrity_file(portable_root, encryption_key, usb_root=usb_path)
            finally:
                # finally, not the success path only (gitlab#201): the common
                # outcome here is a wrong password or an actually tampered
                # drive, and both used to leave the key and password resident.
                if encryption_key is not None:
                    secure_memzero(encryption_key)
                secure_memzero(secure_password)

        except Exception as e:
            raise USBCreationError(f"USB verification failed: {e}")

    def _load_or_create_salt(self, portable_root: Path, create: bool = False) -> bytes:
        """Load this drive's per-drive KDF salt, or create one at USB-creation time.

        Salts are not secret, so the file is stored in plaintext. A unique random
        salt per drive defeats precomputation/rainbow-table attacks and ensures two
        drives sharing a password do not share a key.

        Backward compatibility: drives created before per-drive salts existed have no
        salt file; for those (create=False) we fall back to the legacy fixed salt so
        they remain verifiable. New drives (create=True) always get a random salt.

        Args:
            portable_root: The portable installation root on the USB drive.
            create: If True, generate and persist a new random salt when none exists.

        Returns:
            The salt bytes to use for key derivation.
        """
        salt_path = portable_root / self.CONFIG_DIR / self.SALT_FILE

        if salt_path.exists():
            salt = salt_path.read_bytes()
            if len(salt) >= 16:
                return salt
            logger.warning("USB salt file is too short; treating drive as un-salted")

        if create:
            salt = secrets.token_bytes(self.SALT_LENGTH)
            salt_path.parent.mkdir(parents=True, exist_ok=True)
            salt_path.write_bytes(salt)
            self._restrict_to_owner(salt_path)
            return salt

        # Pre-fix drive without a salt file: use the legacy fixed salt for compat.
        return self._LEGACY_FIXED_SALT

    def _derive_encryption_key(
        self,
        password: SecureBytes,
        hash_config: Optional[Dict] = None,
        salt: Optional[bytes] = None,
    ) -> bytearray:
        """
        Derive encryption key from password using complex hash chaining system

        Uses the same multi-hash approach as the main CLI for consistency.
        Falls back to PBKDF2 if no hash config provided or if import fails.

        Returns a bytearray, not bytes (gitlab#201): this key protects an
        encrypted keystore and the integrity manifest on removable media, and
        secure_memzero refuses immutable input -- it returned False and every
        caller discarded that, so the key stayed resident while the code read
        as if it had been wiped.

        Args:
            password: The master password.
            hash_config: Hash chaining configuration (same format as main CLI).
            salt: Per-drive KDF salt. If None, the legacy fixed salt is used (only
                appropriate for reading pre-fix drives); callers creating or verifying
                a drive must pass the drive's salt from _load_or_create_salt().
        """
        if salt is None:
            salt = self._LEGACY_FIXED_SALT

        if hash_config is None:
            # Fallback to simple PBKDF2 if no hash config provided
            return self._derive_key_pbkdf2_fallback(password, salt)

        try:
            # Import the complex hash chaining functionality from crypt_core
            from ..crypt_core import multi_hash_password

            # Use the same multi-hash system as main CLI
            hashed_password = multi_hash_password(
                password=bytes(password),
                salt=salt,
                hash_config=hash_config,
                quiet=True,  # Suppress output during USB creation
                progress=False,
                debug=False,
            )

            # Ensure we get exactly the key length we need (32 bytes for AES-256)
            if len(hashed_password) != self.KEY_LENGTH:
                # Hash the result to get the exact length we need
                import hashlib

                normalized = bytearray(hashlib.sha256(hashed_password).digest())
                del normalized[self.KEY_LENGTH :]
                secure_memzero(hashed_password)
                return normalized

            return bytearray(hashed_password)

        except ImportError:
            # Fallback if crypt_core not available
            return self._derive_key_pbkdf2_fallback(password, salt)
        except Exception as e:
            # Log the error but continue with fallback
            logger.warning(f"Complex hash derivation failed, using PBKDF2 fallback: {e}")
            return self._derive_key_pbkdf2_fallback(password, salt)

    def _derive_key_pbkdf2_fallback(
        self, password: SecureBytes, salt: Optional[bytes] = None
    ) -> bytearray:
        """Fallback PBKDF2 key derivation.

        Args:
            password: The master password.
            salt: Per-drive KDF salt. If None, the legacy fixed salt is used (only
                appropriate for reading pre-fix drives).
        """
        if salt is None:
            salt = self._LEGACY_FIXED_SALT

        # Adjust iterations based on security profile
        iterations = {
            USBSecurityProfile.STANDARD: 100_000,
            USBSecurityProfile.HIGH_SECURITY: 500_000,
            USBSecurityProfile.PARANOID: 1_000_000,
        }[self.security_profile]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=iterations,
        )

        # bytearray, so secure_memzero can actually wipe it (gitlab#201).
        return bytearray(kdf.derive(bytes(password)))

    def _create_portable_config(self, custom_config: Optional[Dict], include_logs: bool) -> Dict:
        """Create portable configuration file"""
        config = {
            "portable_mode": True,
            "version": self.VERSION,
            "security_profile": self.security_profile.value,
            "auto_encrypt_workspace": True,
            "secure_deletion_on_exit": True,
            "network_disabled": True,  # Air-gapped mode
            "logging_enabled": include_logs,
            "workspace_path": "data/",
            "keystore_path": (
                "config/keystore.encrypted"
                if custom_config and custom_config.get("include_keystore")
                else None
            ),
            "created_at": time.time(),
        }

        # Apply custom overrides
        if custom_config:
            config.update(custom_config)

        return config

    def _encrypt_keystore_to_usb(self, keystore_path: str, output_path: Path, key: bytes) -> Dict:
        """Encrypt and copy keystore to USB"""
        try:
            with open(keystore_path, "rb") as f:
                keystore_data = f.read()

            # Encrypt keystore data
            cipher = AESGCM(key)
            nonce = os.urandom(self.NONCE_LENGTH)

            encrypted_data = cipher.encrypt(nonce, keystore_data, None)

            # Write encrypted keystore
            with open(output_path, "wb") as f:
                f.write(nonce + encrypted_data)

            return {
                "included": True,
                "original_size": len(keystore_data),
                "encrypted_size": len(nonce + encrypted_data),
                "path": str(output_path.name),
            }

        except Exception as e:
            raise USBCreationError(f"Failed to encrypt keystore: {e}")

    def _create_encrypted_workspace(self, workspace_dir: Path, key: bytes) -> Dict:
        """Create encrypted workspace directory"""
        try:
            # Create workspace metadata file
            metadata = {
                "encrypted": True,
                "created_at": time.time(),
                "security_profile": self.security_profile.value,
            }

            metadata_path = workspace_dir / ".workspace"
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)

            # Create README for workspace
            readme_content = """# 🔒 Encrypted USB Workspace

This directory contains encrypted files created by OpenSSL Encrypt Portable.

## 📁 File Encryption Workflow:

### Encrypt a file:
```bash
python3 ../encrypt_file.py /path/to/file.txt PASSWORD
```

### Decrypt a file:
```bash
# View content directly (stdout - default)
python3 ../decrypt_file.py filename.txt.enc PASSWORD

# Save to specific file
python3 ../decrypt_file.py filename.txt.enc PASSWORD output.txt
```

### Examples:
```bash
# Encrypt document.pdf to the USB workspace
python3 ../encrypt_file.py /home/user/document.pdf mypassword

# Quick view encrypted text file (prints to terminal)
python3 ../decrypt_file.py secret.txt.enc mypassword

# Save decrypted file to specific location
python3 ../decrypt_file.py document.pdf.enc mypassword /home/user/recovered.pdf

# Pipe content to other commands
python3 ../decrypt_file.py data.txt.enc mypassword | grep "important"
```

## 🔐 Security Features:
- ✅ AES-256-GCM encryption
- ✅ Complex hash chaining (same as main CLI)
- ✅ Automatic workspace management
- ✅ Tamper detection & integrity verification
- ✅ Cross-platform compatibility

## 💡 Tips:
- Files are automatically named with .enc extension
- Use the same password as your USB master password
- Encrypted files are stored safely in this workspace directory
"""

            readme_path = workspace_dir / "README.txt"
            with open(readme_path, "w", encoding="utf-8") as f:
                f.write(readme_content)

            return {
                "created": True,
                "path": str(workspace_dir.name),
                "encryption": "AES-256-GCM",
            }

        except Exception as e:
            raise USBCreationError(f"Failed to create workspace: {e}")

    def _create_autorun_files(self, usb_root: Path, portable_root: Path) -> Dict:
        """Create auto-run files for different platforms"""
        autorun_info = {"files_created": []}

        try:
            # Windows autorun.inf
            autorun_inf = usb_root / "autorun.inf"
            autorun_content = f"""[AutoRun]
open={portable_root.name}/openssl_encrypt.exe
icon={portable_root.name}/openssl_encrypt.exe,0
label=OpenSSL Encrypt Portable
action=Launch OpenSSL Encrypt Portable

[Content]
MusicFiles=false
PictureFiles=false
VideoFiles=false
"""

            with open(autorun_inf, "w", encoding="utf-8") as f:
                f.write(autorun_content)
            autorun_info["files_created"].append("autorun.inf")

            # Linux/Unix autorun script
            autorun_sh = usb_root / "autorun.sh"
            autorun_script = f"""#!/bin/bash
# OpenSSL Encrypt Portable Auto-Launch Script

SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
PORTABLE_DIR="$SCRIPT_DIR/{portable_root.name}"

if [ -x "$PORTABLE_DIR/openssl_encrypt" ]; then
    echo "Launching OpenSSL Encrypt Portable..."
    cd "$PORTABLE_DIR"
    ./openssl_encrypt --portable-mode
else
    echo "OpenSSL Encrypt executable not found or not executable"
    echo "Please check the installation in $PORTABLE_DIR"
fi
"""

            with open(autorun_sh, "w", encoding="utf-8") as f:
                f.write(autorun_script)
            autorun_sh.chmod(0o755)  # Make executable
            autorun_info["files_created"].append("autorun.sh")

            # macOS .autorun file
            autorun_mac = usb_root / ".autorun"
            with open(autorun_mac, "w", encoding="utf-8") as f:
                f.write(f"{portable_root.name}/openssl_encrypt --portable-mode\n")
            autorun_info["files_created"].append(".autorun")

            return autorun_info

        except Exception as e:
            raise USBCreationError(f"Failed to create autorun files: {e}")

    # Bound on how much of any single file the verifier will hash. The drive is
    # untrusted (gitlab#132); this stops a substituted huge file, or a FIFO /
    # symlink to an unbounded stream (e.g. /dev/zero), from exhausting memory or
    # looping forever. A legitimate tool file is far smaller; a file exceeding
    # this simply hashes differently and surfaces as tampered.
    _MAX_HASH_BYTES = 1 * 1024 * 1024 * 1024  # 1 GiB
    # Bound on the .integrity blob read before authentication (it is a small
    # JSON manifest; an attacker could otherwise plant a multi-GB file there).
    _MAX_INTEGRITY_BYTES = 128 * 1024 * 1024  # 128 MiB

    # config/hash_config.json is plaintext, unauthenticated, and sits on the
    # drive being verified, yet its contents set the KDF work factor before
    # any integrity check runs (gitlab#200). It is a handful of small
    # integers; anything larger is an attack, not a drive.
    _MAX_HASH_CONFIG_BYTES = 64 * 1024

    # An allowlist rather than a per-key ceiling, because the file is
    # unauthenticated: there is no reason to honour a shape create-usb never
    # writes. These are exactly the keys the CLI builds (crypt_cli.py, the
    # create-usb/verify-usb hash_config blocks), plus the "type" that
    # multi_hash_password mutates in. A memory-hard block (argon2, scrypt,
    # balloon, derivation_config) is not among them, so the OOM vector is
    # refused by shape.
    _ALLOWED_HASH_CONFIG_ROUNDS = frozenset(
        {
            "sha512",
            "sha384",
            "sha256",
            "sha224",
            "sha3_512",
            "sha3_384",
            "sha3_256",
            "sha3_224",
            "blake2b",
            "blake3",
            "shake256",
            "shake128",
            "whirlpool",
            "pbkdf2_iterations",
        }
    )
    # Well above any real configuration (the CLI's own presets top out in the
    # low millions of PBKDF2 iterations) and far below a denial of service.
    _MAX_HASH_CONFIG_ROUNDS = 10_000_000
    _ALLOWED_HASH_CONFIG_TYPES = frozenset({"id", "i", "d", "argon2id", "argon2i", "argon2d"})

    @classmethod
    def _validated_drive_hash_config(cls, raw: Any) -> Optional[Dict]:
        """Accept a hash_config read off an untrusted drive, or reject it.

        Returns None rather than raising: the caller's contract for "no
        usable stored config" is already None, and a refused config must
        fall back to the built-in derivation exactly as a missing file does
        -- not abort the verification the user asked for.
        """
        if not isinstance(raw, dict):
            return None

        for key, value in raw.items():
            if key == "type":
                if value not in cls._ALLOWED_HASH_CONFIG_TYPES:
                    return None
                continue
            if key not in cls._ALLOWED_HASH_CONFIG_ROUNDS:
                return None
            # bool is an int subclass; reject it and every non-int explicitly.
            if isinstance(value, bool) or not isinstance(value, int):
                return None
            if not (0 <= value <= cls._MAX_HASH_CONFIG_ROUNDS):
                return None

        return raw

    def _sha256_file(self, path: Path) -> str:
        """SHA-256 of a regular file on a drive we do not trust.

        Streamed in fixed-size chunks and hard-bounded so a very large
        attacker-supplied file cannot exhaust memory (gitlab#132), and opened
        so that a substituted non-regular file cannot hang or redirect the
        read (gitlab#202).

        The byte bound alone did NOT deliver what its previous docstring
        claimed: `open(path, "rb")` on a FIFO blocks inside open() itself,
        before a single byte is read, so a manifest-listed file replaced by a
        named pipe hung verify-usb forever -- on the exact path whose job is
        to report tampering. O_NONBLOCK makes that open return instead, and
        the S_ISREG check turns the substitution into a refusal.

        O_NOFOLLOW likewise refuses a listed name replaced by a symlink,
        which would otherwise read a file from outside the drive entirely.

        Raises:
            OSError: If the path is not a regular file, or is a symlink. The
                callers treat that as tampering, which is the correct
                verdict: a real manifest lists regular files, so anything
                else at that path is a substitution.
        """
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        try:
            mode = os.fstat(fd).st_mode
            if not stat.S_ISREG(mode):
                raise OSError(f"Not a regular file: {path}")
            # Clear O_NONBLOCK now that we know it is a regular file, so the
            # reads below behave normally.
            if hasattr(os, "O_NONBLOCK"):
                import fcntl

                fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK)

            h = hashlib.sha256()
            remaining = self._MAX_HASH_BYTES
            with os.fdopen(fd, "rb") as f:
                fd = None  # fdopen owns it now
                while remaining > 0:
                    chunk = f.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    h.update(chunk)
                    remaining -= len(chunk)
            return h.hexdigest()
        finally:
            if fd is not None:
                os.close(fd)

    def _integrity_excluded(self, rel: str) -> bool:
        """True if the ``portable_root``-relative path is excluded from integrity
        coverage (gitlab#132 F13): the user-mutable workspace/logs subtrees, or an
        artifact that legitimately is not in the manifest (the manifest itself and
        files written after it)."""
        if rel in self._INTEGRITY_EXCLUDED_NAMES:
            return True
        first = rel.replace("\\", "/").split("/", 1)[0]
        return first in self._INTEGRITY_MUTABLE_SUBDIRS

    def _create_integrity_file(
        self,
        portable_root: Path,
        key: bytes,
        hash_config: Optional[Dict] = None,
        usb_root: Optional[Path] = None,
    ) -> Dict:
        """Create integrity verification file.

        gitlab#132 F13: records a v2 manifest that is an ALLOWLIST of every file
        in the tool tree (not a fixed set of extensions), so verification can
        detect ANY file added afterward — a planted .dll/.so/.pyd/.exe or any
        other payload — plus tampered/added root-level ``autorun.*`` files (which
        live above ``portable_root`` and are auto-executed by the OS on insert).
        The user-mutable workspace (``data/``) and ``logs/`` are excluded so that
        ordinary use — encrypting files onto the drive — does not fail
        verification.
        """
        try:
            # Allowlist: checksum EVERY file in the tool tree except the
            # user-mutable workspace/logs and the manifest artifacts.
            checksums = {}
            for file_path in portable_root.rglob("*"):
                if not file_path.is_file():
                    continue
                rel = str(file_path.relative_to(portable_root))
                if self._integrity_excluded(rel):
                    continue
                checksums[rel] = self._sha256_file(file_path)

            # F13: hash the root-level autorun files (they live at the USB root,
            # above portable_root, and the OS auto-executes them on insert).
            root_checksums = {}
            if usb_root is not None:
                for name in self._ROOT_AUTORUN_NAMES:
                    autorun_path = usb_root / name
                    if autorun_path.is_file():
                        root_checksums[name] = self._sha256_file(autorun_path)

            # Create integrity data
            integrity_data = {
                "version": self.VERSION,
                "scan_version": self.INTEGRITY_SCAN_VERSION,  # F13
                "created_at": time.time(),
                "security_profile": self.security_profile.value,
                "checksums": checksums,
                "root_checksums": root_checksums,  # F13: root-level autorun.*
                "file_count": len(checksums),
                "hash_config": hash_config,  # Store hash configuration for verification
            }

            # Encrypt integrity data
            integrity_json = json.dumps(integrity_data, separators=(",", ":")).encode("utf-8")

            cipher = AESGCM(key)
            nonce = os.urandom(self.NONCE_LENGTH)
            encrypted_integrity = cipher.encrypt(nonce, integrity_json, None)

            # Write integrity file
            integrity_path = portable_root / self.INTEGRITY_FILE
            with open(integrity_path, "wb") as f:
                f.write(nonce + encrypted_integrity)
            self._restrict_to_owner(integrity_path)

            return {
                "created": True,
                "files_verified": len(checksums),
                "path": self.INTEGRITY_FILE,
            }

        except Exception as e:
            raise USBCreationError(f"Failed to create integrity file: {e}")

    def _verify_integrity_file(
        self, portable_root: Path, key: bytes, usb_root: Optional[Path] = None
    ) -> Dict:
        """Verify integrity file and check for tampering.

        gitlab#132 F13: for v2 manifests, this is an ALLOWLIST check — it flags
        ANY file present in the tool tree that is not in the recorded manifest
        (a planted binary/script of any type), plus tampered/added/removed
        root-level ``autorun.*`` files, while excluding the user-mutable
        workspace (``data/``) and ``logs/``. v1 manifests (drives created before
        this fix) carry no scan_version and are verified exactly as before
        (listed files only), so existing drives keep working.
        """
        try:
            integrity_path = portable_root / self.INTEGRITY_FILE

            with open(integrity_path, "rb") as f:
                # Bounded read: the .integrity blob is small; cap it so an
                # attacker cannot plant a huge file here to exhaust memory
                # before authentication (gitlab#132).
                encrypted_data = f.read(self._MAX_INTEGRITY_BYTES)

            # Extract nonce and decrypt
            nonce = encrypted_data[: self.NONCE_LENGTH]
            ciphertext = encrypted_data[self.NONCE_LENGTH :]

            cipher = AESGCM(key)
            decrypted_data = cipher.decrypt(nonce, ciphertext, None)

            # Parse integrity data
            integrity_data = json.loads(decrypted_data.decode("utf-8"))
            stored_checksums = integrity_data["checksums"]
            # scan_version 1 (or absent) => legacy manifest; skip added/autorun
            # detection so pre-fix drives verify exactly as they did before.
            scan_version = integrity_data.get("scan_version", 1)
            root_checksums = integrity_data.get("root_checksums", {})

            # Verify current checksums
            verification_results = {
                "verified_files": 0,
                "failed_files": 0,
                "missing_files": 0,
                "added_files": 0,  # F13
                "tampered_files": [],
                "missing_file_list": [],
                "added_file_list": [],  # F13
            }

            for file_path, expected_hash in stored_checksums.items():
                full_path = portable_root / file_path

                if not full_path.exists():
                    verification_results["missing_files"] += 1
                    verification_results["missing_file_list"].append(file_path)
                    continue

                try:
                    current_hash = self._sha256_file(full_path)
                except OSError:
                    # A listed name that is no longer a regular file -- a
                    # planted FIFO, a directory, a symlink out of the drive --
                    # is a substitution, so it IS tampering (gitlab#202).
                    verification_results["failed_files"] += 1
                    verification_results["tampered_files"].append(file_path)
                    continue

                if current_hash == expected_hash:
                    verification_results["verified_files"] += 1
                else:
                    verification_results["failed_files"] += 1
                    verification_results["tampered_files"].append(file_path)

            # F13: root-level autorun.* — verify the recorded ones and flag any
            # autorun file that was tampered, removed, or newly added.
            if usb_root is not None and scan_version >= 2:
                for name, expected_hash in root_checksums.items():
                    autorun_path = usb_root / name
                    if not autorun_path.is_file():
                        verification_results["missing_files"] += 1
                        verification_results["missing_file_list"].append(name)
                        continue
                    try:
                        autorun_hash = self._sha256_file(autorun_path)
                    except OSError:
                        autorun_hash = None
                    if autorun_hash == expected_hash:
                        verification_results["verified_files"] += 1
                    else:
                        verification_results["failed_files"] += 1
                        verification_results["tampered_files"].append(name)
                for name in self._ROOT_AUTORUN_NAMES:
                    if (usb_root / name).is_file() and name not in root_checksums:
                        verification_results["added_files"] += 1
                        verification_results["added_file_list"].append(name)

            # F13: ALLOWLIST — flag any file present in the tool tree that is not
            # in the recorded manifest (a planted binary/script of ANY type),
            # excluding the user-mutable workspace/logs and the manifest
            # artifacts. This is the counterpart of the allowlist recorded at
            # creation, so a wrong file type cannot slip past a fixed extension
            # list.
            if scan_version >= 2:
                for file_path in portable_root.rglob("*"):
                    rel = str(file_path.relative_to(portable_root))
                    if self._integrity_excluded(rel):
                        continue
                    if file_path.is_file():
                        if rel not in stored_checksums:
                            verification_results["added_files"] += 1
                            verification_results["added_file_list"].append(rel)
                    elif not file_path.is_dir():
                        # A special file (FIFO/socket/device) planted on the drive
                        # is neither a legit tool file nor a directory — flag it.
                        verification_results["added_files"] += 1
                        verification_results["added_file_list"].append(rel)

            # Overall verification status
            verification_results["integrity_ok"] = (
                verification_results["failed_files"] == 0
                and verification_results["missing_files"] == 0
                and verification_results["added_files"] == 0  # F13
            )

            verification_results["created_at"] = integrity_data["created_at"]
            verification_results["original_file_count"] = integrity_data["file_count"]

            return verification_results

        except Exception as e:
            raise USBCreationError(f"Failed to verify integrity: {e}")

    def _is_removable_drive(self, path: Path) -> bool:
        """Check if path is likely a removable drive (best effort)"""
        try:
            # This is a basic check - in production you might want more sophisticated detection
            path_str = str(path).lower()

            # Windows drive letters
            if platform.system() == "Windows":
                return len(path_str) <= 3 and ":" in path_str

            # Unix-like systems - check for common removable mount points
            removable_patterns = ["/media/", "/mnt/", "/Volumes/"]
            return any(pattern in path_str for pattern in removable_patterns)

        except Exception:
            return False  # When in doubt, proceed anyway

    def _store_hash_config_metadata(self, config_dir: Path, hash_config: Dict) -> None:
        """Store hash_config in a separate metadata file"""
        try:
            metadata_file = config_dir / "hash_config.json"
            with open(metadata_file, "w", encoding="utf-8") as f:
                json.dump(hash_config, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to store hash_config metadata: {e}")

    def _read_hash_config_from_integrity(
        self, portable_root: Path, password: str
    ) -> Optional[Dict]:
        """
        Try to read hash_config from metadata files.

        First tries to read from the separate hash_config.json file,
        then falls back to trying to decrypt the integrity file with PBKDF2.
        """
        try:
            # First, try to read from the separate metadata file
            config_dir = portable_root / self.CONFIG_DIR
            metadata_file = config_dir / "hash_config.json"

            if metadata_file.exists():
                # Bounded read, then validate: this file is unauthenticated
                # and on the drive under examination, and its contents set
                # the KDF work factor before any integrity check runs
                # (gitlab#200). An uncapped json.load OOMs on a planted
                # multi-GB file before parsing even finishes.
                with open(metadata_file, "r") as f:
                    blob = f.read(self._MAX_HASH_CONFIG_BYTES + 1)
                if len(blob) > self._MAX_HASH_CONFIG_BYTES:
                    logger.warning(
                        "Ignoring hash_config.json on the drive: larger than "
                        f"{self._MAX_HASH_CONFIG_BYTES} bytes"
                    )
                    return None
                try:
                    hash_config = json.loads(blob)
                except ValueError:
                    logger.warning("Ignoring hash_config.json on the drive: not valid JSON")
                    return None
                validated = self._validated_drive_hash_config(hash_config)
                if validated is None:
                    logger.warning(
                        "Ignoring hash_config.json on the drive: unrecognised or "
                        "out-of-range key-derivation parameters"
                    )
                    return None
                logger.debug("Successfully read hash_config from metadata file")
                return validated

            # Fallback: try to decrypt integrity file with PBKDF2 (for backwards compatibility)
            integrity_path = portable_root / self.INTEGRITY_FILE
            if not integrity_path.exists():
                return None

            # Try to decrypt with PBKDF2 (fallback method)
            secure_password = SecureBytes(password.encode("utf-8"))
            pbkdf2_key = None
            try:
                salt = self._load_or_create_salt(portable_root, create=False)
                pbkdf2_key = self._derive_key_pbkdf2_fallback(secure_password, salt)

                with open(integrity_path, "rb") as f:
                    # Bounded read: the .integrity blob is small; cap it so an
                    # attacker cannot plant a huge file here to exhaust memory
                    # before authentication (gitlab#132).
                    encrypted_data = f.read(self._MAX_INTEGRITY_BYTES)

                # Extract nonce and decrypt
                nonce = encrypted_data[: self.NONCE_LENGTH]
                ciphertext = encrypted_data[self.NONCE_LENGTH :]

                cipher = AESGCM(bytes(pbkdf2_key))
                try:
                    decrypted_data = cipher.decrypt(nonce, ciphertext, None)
                    integrity_data = json.loads(decrypted_data.decode("utf-8"))
                except Exception:
                    # PBKDF2 decryption failed, so complex hashing was likely
                    # used; the caller has to supply the hash_config.
                    return None

                # This blob IS authenticated (AES-GCM under the
                # password-derived key), unlike the plaintext
                # hash_config.json handled above, so it needs no allowlist.
                hash_config = integrity_data.get("hash_config")
                if hash_config:
                    logger.debug("Successfully read hash_config from integrity file")
                return hash_config
            finally:
                # finally, not per-branch (gitlab#201): a raise between
                # deriving the key and the decrypt attempt -- a missing salt
                # file, an unreadable .integrity -- used to leave both
                # resident via the outer handler.
                if pbkdf2_key is not None:
                    secure_memzero(pbkdf2_key)
                secure_memzero(secure_password)

        except Exception as e:
            logger.debug(f"Failed to read hash_config from metadata: {e}")
            return None

    def _create_transparent_encryption_helpers(
        self,
        portable_root: Path,
        hash_config: Optional[Dict] = None,
        algorithm: str = "fernet",
    ) -> None:
        """Create unified helper script for encryption/decryption"""
        try:
            # Create a single unified portable script
            crypt_script = portable_root / "crypt.py"

            # Python script - unified CLI wrapper
            crypt_code = '''#!/usr/bin/env python3
"""
Portable USB Crypto Helper
Unified wrapper around the main CLI with USB workspace integration
"""
import sys
import os
import subprocess
import tempfile
from pathlib import Path


def eprint(*args, **kwargs):
    """Local, not imported: this file runs as a standalone script on the
    drive, so `from ..crypt_utils import eprint` raised ImportError on the
    first run (gitlab#206)."""
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)


def show_help():
    eprint("Usage: python crypt.py <encrypt|decrypt> [options...]")
    eprint("")
    eprint("Unified crypto wrapper with automatic USB workspace handling")
    eprint("Supports all OpenSSL Encrypt CLI arguments")
    eprint("")
    eprint("ENCRYPT:")
    eprint("  python crypt.py encrypt -i <file> [options...]")
    eprint("  → Automatically saves to USB workspace as <file>.enc")
    eprint("")
    eprint("DECRYPT:")
    eprint("  python crypt.py decrypt -i <file> [options...]")
    eprint("  → Smart workspace file resolution, outputs to stdout by default")
    eprint("  → Use -o <file> to save to data/decrypted/ (relative paths)")
    eprint("  → Use -o /absolute/path to save anywhere")
    eprint("")
    eprint("PASSWORD:")
    eprint("  You will be prompted, or set CRYPT_PASSWORD in the environment.")
    eprint("  Do NOT pass it as an argument: every other user on the machine")
    eprint("  can read the command line, and your shell records it in history.")
    eprint("")
    eprint("Examples:")
    eprint("  python crypt.py encrypt -i document.pdf")
    eprint("  python crypt.py encrypt -i document.pdf --algorithm aes-gcm-siv")
    eprint("  python crypt.py decrypt -i document.pdf.enc")
    eprint("  python crypt.py decrypt -i document.pdf.enc -o recovered.pdf")
    eprint("    → Saves to: data/decrypted/recovered.pdf")
    eprint("  python crypt.py decrypt -i document.pdf.enc --verbose")

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ['encrypt', 'decrypt']:
        show_help()
        sys.exit(1)

    operation = sys.argv[1]
    args = sys.argv[2:]  # All remaining arguments

    try:
        # Set up paths
        script_dir = Path(__file__).parent
        lib_dir = script_dir / "openssl_encrypt_lib"
        workspace_dir = script_dir / "data"
        workspace_dir.mkdir(exist_ok=True)

        # Build base CLI command
        cli_path = lib_dir / "openssl_encrypt" / "crypt.py"
        cmd = [sys.executable, str(cli_path), operation]

        if operation == "encrypt":
            # For encryption, handle workspace output automatically
            # Parse args to find -i and potentially modify -o
            modified_args = []
            i = 0
            input_file = None
            output_specified = False

            while i < len(args):
                if args[i] == "-i" and i + 1 < len(args):
                    input_file = args[i + 1]
                    modified_args.extend([args[i], args[i + 1]])
                    i += 2
                elif args[i] == "-o" and i + 1 < len(args):
                    # User specified output, keep it
                    modified_args.extend([args[i], args[i + 1]])
                    output_specified = True
                    i += 2
                else:
                    modified_args.append(args[i])
                    i += 1

            # If no output specified, auto-generate workspace output
            if not output_specified and input_file:
                output_file = workspace_dir / (Path(input_file).name + ".enc")
                modified_args.extend(["-o", str(output_file)])
                eprint(f"🔒 Encrypting {{Path(input_file).name}} to USB workspace...")

            cmd.extend(modified_args)

        elif operation == "decrypt":
            # For decryption, handle smart workspace file resolution and output paths
            modified_args = []
            i = 0
            input_file = None
            output_to_stdout = True
            output_file = None

            while i < len(args):
                if args[i] == "-i" and i + 1 < len(args):
                    input_file = args[i + 1]

                    # Smart workspace file resolution
                    if not input_file.startswith('/') and not Path(input_file).is_absolute():
                        workspace_file = workspace_dir / input_file
                        if workspace_file.exists():
                            input_file = str(workspace_file)
                            eprint(f"📁 Using file from USB workspace: {{input_file}}")

                    modified_args.extend([args[i], input_file])
                    i += 2
                elif args[i] == "-o":
                    output_to_stdout = False
                    if i + 1 < len(args):
                        output_file = args[i + 1]

                        # Handle output path - if relative, put in data/decrypted/
                        if not output_file.startswith('/') and not Path(output_file).is_absolute():
                            decrypted_dir = workspace_dir / "decrypted"
                            decrypted_dir.mkdir(exist_ok=True)
                            output_file = str(decrypted_dir / output_file)
                            eprint(f"💾 Saving decrypted file to: {{Path(output_file).relative_to(script_dir)}}")

                        modified_args.extend([args[i], output_file])
                        i += 2
                    else:
                        modified_args.append(args[i])
                        i += 1
                else:
                    modified_args.append(args[i])
                    i += 1

            # If outputting to stdout, use temp file
            if output_to_stdout:
                temp_f = tempfile.NamedTemporaryFile(mode='w+b', delete=False)
                temp_output = temp_f.name
                temp_f.close()
                modified_args.extend(["-o", temp_output])

                eprint(f"🔓 Decrypting {{Path(input_file).name if input_file else 'file'}}...")

                cmd.extend(modified_args)
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(lib_dir))

                try:
                    if result.returncode == 0:
                        # Output decrypted content to stdout
                        with open(temp_output, 'rb') as f:
                            content = f.read()

                        try:
                            # Try to decode as text first
                            text_content = content.decode('utf-8')
                            print(text_content, end='')
                        except UnicodeDecodeError:
                            # Binary content, output raw bytes
                            sys.stdout.buffer.write(content)

                        eprint("\\n✓ File decrypted successfully")
                    else:
                        eprint("✗ Decryption failed")
                        if result.stderr.strip():
                            eprint(result.stderr)
                        sys.exit(1)
                finally:
                    # Clean up temporary file
                    try:
                        os.unlink(temp_output)
                    except Exception:
                        pass
                return
            else:
                if input_file:
                    eprint(f"🔓 Decrypting {{Path(input_file).name}}...")
                cmd.extend(modified_args)

        # Run the CLI command
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(lib_dir))

        if result.returncode == 0:
            if operation == "encrypt":
                # Extract output filename from CLI output if possible
                output_name = "encrypted file"
                if "Writing encrypted file:" in result.stdout:
                    try:
                        output_name = Path(result.stdout.split("Writing encrypted file: ")[1].split("\\n")[0]).name
                    except:
                        pass
                eprint(f"✓ File encrypted to: {{output_name}}")
            elif operation == "decrypt":
                eprint("✓ File decrypted successfully")

            if result.stdout.strip():
                eprint(result.stdout)
        else:
            eprint(f"✗ {{operation.title()}} failed")
            if result.stderr.strip():
                eprint(result.stderr)
            sys.exit(1)

    except Exception as e:
        eprint(f"✗ {{operation.title()}} failed: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    main()
'''

            with open(crypt_script, "w", encoding="utf-8") as f:
                f.write(crypt_code)
            crypt_script.chmod(0o755)

            # Create convenience batch files for Windows
            if platform.system() == "Windows":
                encrypt_bat = portable_root / "encrypt_file.bat"
                decrypt_bat = portable_root / "decrypt_file.bat"

                # Real newlines: these were written from a non-raw string
                # containing a literal backslash-n, so each file was one
                # unusable line (gitlab#206). The password is no longer taken
                # as an argument -- %2 put the master password in the process
                # list and the command history.
                for bat_path, action in ((encrypt_bat, "encrypt"), (decrypt_bat, "decrypt")):
                    with open(bat_path, "w", encoding="utf-8") as f:
                        f.write(
                            "@echo off\r\n"
                            f"python crypt.py {action} -i %1 %2 %3 %4 %5 %6 %7 %8 %9\r\n"
                            "pause\r\n"
                        )

            logger.debug("Created transparent encryption helper scripts")

        except Exception as e:
            logger.warning(f"Failed to create encryption helpers: {{e}}")

    def _cleanup_temp_files(self):
        """Clean up temporary files"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file {temp_file}: {e}")

        self.temp_files.clear()

    def _create_hash_manifest(
        self,
        portable_root: Path,
        password: str,
        hash_config: Optional[Dict] = None,
        manifest_password: Optional[str] = None,
        manifest_security_profile: Optional[str] = None,
        manifest_hash_config: Optional[Dict] = None,
        algorithm: str = "fernet",
    ) -> Dict:
        """
        Create cryptographic hash manifest for manual verification.

        This creates an encrypted file containing SHA3-512 hashes of all Python scripts
        and other critical files. Users can decrypt this manifest manually to verify
        file integrity without relying on potentially tampered verification code.
        """
        try:
            import base64
            import hashlib
            import json
            import secrets
            import time

            # Determine manifest password (3-tier approach)
            if manifest_password:
                # Tier 2 or 3: Use custom manifest password
                actual_manifest_password = manifest_password
                actual_manifest_hash_config = (
                    manifest_hash_config if manifest_hash_config else hash_config
                )
            else:
                # Tier 1: Use main password and hash config
                actual_manifest_password = password
                actual_manifest_hash_config = hash_config

            # Files to hash for manifest
            files_to_hash = []
            hash_patterns = [
                "*.py",
                "*.exe",
                "openssl_encrypt",
                "*.sh",
                "*.bat",
                "*.conf",
            ]

            for pattern in hash_patterns:
                files_to_hash.extend(portable_root.rglob(pattern))

            # Calculate SHA3-512 hashes
            file_hashes = {}
            for file_path in files_to_hash:
                if file_path.is_file() and not file_path.name.startswith("."):
                    try:
                        with open(file_path, "rb") as f:
                            file_content = f.read()

                        # Use SHA3-512 for maximum collision resistance
                        file_hash = hashlib.sha3_512(file_content).hexdigest()
                        relative_path = str(file_path.relative_to(portable_root))
                        file_hashes[relative_path] = {
                            "sha3_512": file_hash,
                            "size": len(file_content),
                            "type": file_path.suffix,
                        }

                    except Exception as e:
                        logger.warning(f"Failed to hash file {file_path}: {e}")

            # Create manifest data
            manifest_data = {
                "version": "1.0",
                "created_at": time.time(),
                "description": "Cryptographic hash manifest for manual verification",
                "hash_algorithm": "SHA3-512",
                "file_count": len(file_hashes),
                "files": file_hashes,
                "manifest_config": {
                    "password_type": "custom" if manifest_password else "main",
                    "security_profile": manifest_security_profile,
                    "hash_config_type": (
                        "custom" if manifest_hash_config else "main" if hash_config else "pbkdf2"
                    ),
                },
            }

            # Serialize to JSON
            manifest_json = json.dumps(manifest_data, indent=2)

            # Use the same encryption format as main CLI
            try:
                import os
                import tempfile

                from ..crypt_core import EncryptionAlgorithm, encrypt_file

                # Both temp paths are CLAIMED by mkstemp, not derived by
                # string concatenation (gitlab#204). The output used to be
                # `temp_input_path + ".enc"` -- an unclaimed sibling in the
                # shared temp directory whose name anyone able to list it
                # could derive, and encrypt_file's default secure_mode=False
                # meant a symlink planted there was followed, giving a local
                # attacker an arbitrary file overwrite as this user.
                input_fd, temp_input_path = tempfile.mkstemp(suffix=".manifest")
                with os.fdopen(input_fd, "w", encoding="utf-8") as temp_input:
                    temp_input.write(manifest_json)

                output_fd, temp_output_path = tempfile.mkstemp(suffix=".manifest.enc")
                os.close(output_fd)

                try:
                    # Convert string algorithm to EncryptionAlgorithm enum
                    if isinstance(algorithm, str):
                        algo_enum = EncryptionAlgorithm(algorithm)
                    else:
                        algo_enum = algorithm

                    # Use the main CLI encryption function
                    success = encrypt_file(
                        input_file=temp_input_path,
                        output_file=temp_output_path,
                        password=actual_manifest_password.encode("utf-8"),
                        hash_config=actual_manifest_hash_config,
                        algorithm=algo_enum,
                        quiet=True,
                        progress=False,
                        verbose=False,
                        debug=False,
                        # O_NOFOLLOW on the output: refuse a symlink at that
                        # path rather than writing through it (gitlab#204).
                        secure_mode=True,
                    )

                    if success:
                        # Copy the encrypted result to final location
                        manifest_file = portable_root / "hash_manifest.enc"
                        with open(temp_output_path, "rb") as temp_f:
                            encrypted_content = temp_f.read()

                        with open(manifest_file, "wb") as final_f:
                            final_f.write(encrypted_content)
                    else:
                        raise Exception("Main CLI encryption failed")

                finally:
                    # Clean up temporary files
                    try:
                        os.unlink(temp_input_path)
                        if os.path.exists(temp_output_path):
                            os.unlink(temp_output_path)
                    except Exception as e:
                        logger.warning(f"Failed to cleanup temp files: {e}")

            except Exception as e:
                logger.warning(f"Main CLI encryption failed: {e}, using fallback format")

                # Derive key for manifest encryption. gitlab#132 F19: pass this
                # drive's unique per-drive salt (salt.bin) instead of letting
                # _derive_encryption_key fall back to the global fixed salt,
                # which would otherwise defeat precomputation resistance for the
                # manifest key on every drive that hits this fallback path.
                manifest_salt = self._load_or_create_salt(portable_root, create=True)
                secure_password = SecureBytes(actual_manifest_password.encode("utf-8"))
                manifest_key = None
                try:
                    manifest_key = self._derive_encryption_key(
                        secure_password, actual_manifest_hash_config, manifest_salt
                    )
                    # Encrypt manifest
                    cipher = AESGCM(manifest_key)
                    nonce = secrets.token_bytes(self.NONCE_LENGTH)
                    encrypted_manifest = cipher.encrypt(nonce, manifest_json.encode("utf-8"), None)

                    # Write encrypted manifest (fallback format)
                    manifest_file = portable_root / "hash_manifest.enc"
                    with open(manifest_file, "wb") as f:
                        f.write(nonce + encrypted_manifest)
                finally:
                    # gitlab#132: the fallback path derives its own key/password
                    # and must wipe them on all exits — including if key
                    # derivation itself raises (the primary encrypt_file path
                    # handles its own key hygiene).
                    if manifest_key is not None:
                        secure_memzero(manifest_key)
                    secure_memzero(secure_password)

            # Create verification instructions
            instructions_content = f"""# 🔐 Hash Manifest Verification Instructions

This USB drive contains an encrypted hash manifest for manual security verification.

## 📋 What is this?
The hash manifest contains SHA3-512 hashes of all critical files (Python scripts, executables, etc.).
You can decrypt and verify this manifest manually to ensure files haven't been tampered with.

## 🛡️ Security Model:
- **If you can decrypt this file with your password** → hashes are authentic
- **If file won't decrypt** → manifest has been tampered with
- **If hashes don't match** → files have been tampered with

## 🔍 Manual Verification Steps:

### Step 1: Decrypt the manifest
```bash
# Option A: Using system OpenSSL (if available)
# Note: This is a complex process requiring manual key derivation

# Option B: Using main OpenSSL Encrypt CLI (if available)
python3 /path/to/openssl_encrypt/crypt.py decrypt hash_manifest.enc

# Option C: Using portable Python script (advanced users)
# See verification script below
```

### Step 2: Compare file hashes
```bash
# Calculate fresh SHA3-512 hashes
sha3sum -a 512 *.py *.sh *.bat

# Compare with decrypted manifest hashes
# All hashes should match exactly
```

## ⚙️ Configuration:
- **Manifest Password**: {"Custom password" if manifest_password else "Same as main password"}
- **Security Profile**: {manifest_security_profile or "Same as main profile"}
- **Hash Config**: {"Custom configuration" if manifest_hash_config else "Same as main config" if hash_config else "PBKDF2 fallback"}

## 📝 File Coverage:
This manifest covers {len(file_hashes)} files including Python scripts, executables, and configuration files.

## 🚨 Security Warning:
Only trust this manifest if:
1. You can decrypt it with your password
2. The USB has been in your physical control
3. File hashes match fresh calculations

If any verification step fails, assume the USB has been compromised!
"""

            instructions_file = portable_root / "VERIFY_INTEGRITY.md"
            with open(instructions_file, "w", encoding="utf-8") as f:
                f.write(instructions_content)

            # Clean up sensitive data (handled by main CLI encryption function)

            return {
                "created": True,
                "manifest_file": str(manifest_file.relative_to(portable_root)),
                "instructions_file": str(instructions_file.relative_to(portable_root)),
                "files_covered": len(file_hashes),
                "password_type": "custom" if manifest_password else "main",
                "security_profile": manifest_security_profile,
                "hash_algorithm": "SHA3-512",
            }

        except Exception as e:
            logger.error(f"Failed to create hash manifest: {e}")
            return {"created": False, "error": str(e)}

    # Never copied onto a drive that is carried around (gitlab#203). The
    # copy previously had no filter at all, so a source checkout put the
    # unittests tree -- including four test identity private keys -- onto
    # removable media unencrypted, typically FAT32 where the mode bits
    # copy2 preserves mean nothing.
    _PROJECT_COPY_EXCLUDE_NAMES = frozenset({"unittests", "__pycache__", ".git", ".pytest_cache"})
    _PROJECT_COPY_EXCLUDE_SUFFIXES = (
        ".pem",
        ".key",
        ".pqc",
        ".pyc",
        ".pyo",
    )

    @staticmethod
    def _restrict_to_owner(path) -> None:
        """Make a drive artifact owner-only where the filesystem allows it.

        Nothing on this path was chmod'd except the three files deliberately
        made 0755, so the salt, the integrity manifest, the portable config
        and the encrypted keystore were created at the process umask --
        typically 0644 (gitlab#207). That is meaningless on FAT32, which is
        the common case, and exposed the moment the target is a real
        filesystem, which create-usb permits.

        Best effort by design: a chmod on a filesystem without POSIX modes
        raises, and failing the whole drive creation over it would be worse
        than the exposure it prevents.
        """
        try:
            os.chmod(path, 0o600)
        except OSError as error:
            logger.debug(f"Could not restrict permissions on {path}: {error}")

    @classmethod
    def _project_copy_ignore(cls, directory, names):
        """shutil.copytree ignore callback: key material and build junk.

        Deliberately name-based rather than path-based so it applies at
        every depth -- a key does not become safe to ship by sitting one
        directory further down.
        """
        ignored = set()
        for name in names:
            if name in cls._PROJECT_COPY_EXCLUDE_NAMES:
                ignored.add(name)
            elif name.endswith(cls._PROJECT_COPY_EXCLUDE_SUFFIXES):
                ignored.add(name)
        return ignored

    def _copy_openssl_encrypt_project(self, portable_root: Path) -> None:
        """Copy the openssl_encrypt project to USB for full CLI compatibility.

        Key material, the test tree and build caches are excluded
        (gitlab#203), and symlinks are copied as links rather than
        dereferenced -- dereferencing pulls a target's contents in from
        outside the copied subtree.
        """
        try:
            import inspect
            import shutil

            # Find the openssl_encrypt project root by going up from this file
            current_file = Path(inspect.getfile(inspect.currentframe()))

            # Navigate up to find the project root (where setup.py or pyproject.toml should be)
            project_root = current_file.parent
            while project_root != project_root.parent:
                # Look for project markers
                if any(
                    (project_root / marker).exists()
                    for marker in ["setup.py", "pyproject.toml", "openssl_encrypt"]
                ):
                    if (project_root / "openssl_encrypt").exists():
                        break
                project_root = project_root.parent

            if not (project_root / "openssl_encrypt").exists():
                logger.warning(
                    "Could not find openssl_encrypt project root, using fallback location"
                )
                # Try alternative approach - look for the module directory
                import openssl_encrypt

                project_root = Path(openssl_encrypt.__file__).parent.parent

            # Target directory on USB
            usb_project_dir = portable_root / "openssl_encrypt_lib"

            # Copy the openssl_encrypt module
            openssl_encrypt_src = project_root / "openssl_encrypt"
            if openssl_encrypt_src.exists():
                if usb_project_dir.exists():
                    shutil.rmtree(usb_project_dir)

                # Filtered copy: no key material, no test tree, no caches,
                # and symlinks stay symlinks (gitlab#203).
                shutil.copytree(
                    openssl_encrypt_src,
                    usb_project_dir / "openssl_encrypt",
                    ignore=self._project_copy_ignore,
                    symlinks=True,
                )

                # Copy essential project files
                essential_files = [
                    "README.md",
                    "LICENSE",
                    "requirements.txt",
                    "setup.py",
                    "pyproject.toml",
                ]
                for file_name in essential_files:
                    src_file = project_root / file_name
                    if src_file.exists():
                        shutil.copy2(src_file, usb_project_dir / file_name)

                # Create __init__.py to make it a package
                (usb_project_dir / "__init__.py").touch()

                logger.debug(f"Successfully copied openssl_encrypt project to {usb_project_dir}")

                return {
                    "copied": True,
                    "source": str(openssl_encrypt_src),
                    "target": str(usb_project_dir),
                    "size": self._get_directory_size(usb_project_dir),
                }
            else:
                logger.warning(f"OpenSSL Encrypt source directory not found: {openssl_encrypt_src}")
                return {"copied": False, "error": "Source directory not found"}

        except Exception as e:
            logger.error(f"Failed to copy openssl_encrypt project: {e}")
            return {"copied": False, "error": str(e)}

    def _get_directory_size(self, directory: Path) -> int:
        """Calculate total size of a directory in bytes"""
        total_size = 0
        try:
            for file_path in directory.rglob("*"):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
        except Exception:
            pass
        return total_size


# Convenience functions
def create_portable_usb(
    usb_path: str, password: str, hash_config: Optional[Dict] = None, **kwargs
) -> Dict[str, any]:
    """
    Create encrypted portable USB drive

    Args:
        usb_path: Path to USB drive
        password: Master password for encryption
        hash_config: Hash chaining configuration (same format as main CLI)
        **kwargs: Additional options for USBDriveCreator

    Returns:
        Creation results dictionary
    """
    security_profile = USBSecurityProfile(kwargs.pop("security_profile", "standard"))
    creator = USBDriveCreator(security_profile)
    return creator.create_portable_usb(usb_path, password, hash_config=hash_config, **kwargs)


def verify_usb_integrity(
    usb_path: str, password: str, hash_config: Optional[Dict] = None
) -> Dict[str, any]:
    """
    Verify USB drive integrity

    Args:
        usb_path: Path to USB drive
        password: Master password for verification
        hash_config: Hash chaining configuration (same format as main CLI)

    Returns:
        Verification results dictionary
    """
    creator = USBDriveCreator()
    return creator.verify_usb_integrity(usb_path, password, hash_config)
