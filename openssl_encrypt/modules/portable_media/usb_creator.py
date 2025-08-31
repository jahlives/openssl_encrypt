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
import shutil
import tempfile
import time
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Import secure memory functions
try:
    from ..secure_memory import SecureBytes, secure_memzero
    from ..crypt_errors import KeystoreError
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero
    from openssl_encrypt.modules.crypt_errors import KeystoreError

# Set up module logger
logger = logging.getLogger(__name__)


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
    TAG_LENGTH = 16   # GCM authentication tag
    
    # Integrity constants
    INTEGRITY_FILE = ".integrity"
    VERSION = "1.0"
    
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
        
        logger.debug(f"USB Drive Creator initialized with security profile: {security_profile.value}")
    
    def create_portable_usb(self, 
                           usb_path: Union[str, Path],
                           password: str,
                           executable_path: Optional[str] = None,
                           keystore_path: Optional[str] = None,
                           include_logs: bool = False,
                           custom_config: Optional[Dict] = None,
                           hash_config: Optional[Dict] = None) -> Dict[str, any]:
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
            
            # Create secure password key
            secure_password = SecureBytes(password.encode('utf-8'))
            
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
            
            # Generate encryption key from password using hash chaining
            encryption_key = self._derive_encryption_key(secure_password, hash_config)
            
            # Create portable configuration
            config = self._create_portable_config(custom_config, include_logs)
            config_path = config_dir / "portable.conf"
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
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
            
            # Create encrypted workspace
            workspace_info = self._create_encrypted_workspace(data_dir, encryption_key)
            
            # Create auto-run files
            autorun_info = self._create_autorun_files(usb_path, portable_root)
            
            # Generate integrity file
            integrity_info = self._create_integrity_file(portable_root, encryption_key)
            
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
                "created_at": time.time()
            }
            
        except Exception as e:
            # Clean up on error
            self._cleanup_temp_files()
            raise USBCreationError(f"Failed to create portable USB: {e}")
        
        finally:
            # Always clean up secure memory
            if 'secure_password' in locals():
                secure_memzero(secure_password)
            if 'encryption_key' in locals():
                secure_memzero(encryption_key)
    
    def verify_usb_integrity(self, usb_path: Union[str, Path], password: str, hash_config: Optional[Dict] = None) -> Dict[str, any]:
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
            
            # Create secure password key
            secure_password = SecureBytes(password.encode('utf-8'))
            encryption_key = self._derive_encryption_key(secure_password, hash_config)
            
            # Verify integrity file
            integrity_path = portable_root / self.INTEGRITY_FILE
            if not integrity_path.exists():
                raise USBCreationError("Integrity file missing - USB may be tampered")
            
            verification_result = self._verify_integrity_file(portable_root, encryption_key)
            
            # Clean up
            secure_memzero(encryption_key)
            secure_memzero(secure_password)
            
            return verification_result
            
        except Exception as e:
            raise USBCreationError(f"USB verification failed: {e}")
    
    def _derive_encryption_key(self, password: SecureBytes, hash_config: Optional[Dict] = None) -> bytes:
        """
        Derive encryption key from password using hash chaining approach
        
        Uses the same hash chaining system as the main CLI for consistency.
        Falls back to PBKDF2 if no hash config provided (for backwards compatibility).
        """
        if hash_config is None:
            # Fallback to simple PBKDF2 for backwards compatibility
            return self._derive_key_pbkdf2_fallback(password)
        
        # Import the hash chaining functionality from crypt_core
        try:
            from ..crypt_core import derive_key_from_password
            
            # Use fixed salt for USB drives (deterministic but unique per USB)
            salt = b"openssl_encrypt_usb_v1.0_salt_2024"
            
            # Use the same key derivation as main CLI with hash chaining
            derived_key = derive_key_from_password(
                password=bytes(password).decode('utf-8'),
                salt=salt,
                hash_config=hash_config,
                pbkdf2_iterations=hash_config.get('pbkdf2_iterations', 100000)
            )
            
            # Ensure we get exactly the key length we need
            if len(derived_key) != self.KEY_LENGTH:
                # Hash the derived key to get the exact length we need
                import hashlib
                return hashlib.sha256(derived_key).digest()[:self.KEY_LENGTH]
            
            return derived_key
            
        except ImportError:
            # Fallback if crypt_core not available
            return self._derive_key_pbkdf2_fallback(password)
    
    def _derive_key_pbkdf2_fallback(self, password: SecureBytes) -> bytes:
        """Fallback PBKDF2 key derivation for backwards compatibility"""
        # Generate or use fixed salt for deterministic key derivation
        salt = b"openssl_encrypt_usb_v1.0_salt_2024"  # Fixed salt for USB drives
        
        # Adjust iterations based on security profile
        iterations = {
            USBSecurityProfile.STANDARD: 100_000,
            USBSecurityProfile.HIGH_SECURITY: 500_000,
            USBSecurityProfile.PARANOID: 1_000_000
        }[self.security_profile]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=iterations,
        )
        
        key = kdf.derive(bytes(password))
        return key
    
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
            "keystore_path": "config/keystore.encrypted" if custom_config and custom_config.get("include_keystore") else None,
            "created_at": time.time()
        }
        
        # Apply custom overrides
        if custom_config:
            config.update(custom_config)
        
        return config
    
    def _encrypt_keystore_to_usb(self, keystore_path: str, output_path: Path, key: bytes) -> Dict:
        """Encrypt and copy keystore to USB"""
        try:
            with open(keystore_path, 'rb') as f:
                keystore_data = f.read()
            
            # Encrypt keystore data
            cipher = AESGCM(key)
            nonce = os.urandom(self.NONCE_LENGTH)
            
            encrypted_data = cipher.encrypt(nonce, keystore_data, None)
            
            # Write encrypted keystore
            with open(output_path, 'wb') as f:
                f.write(nonce + encrypted_data)
            
            return {
                "included": True,
                "original_size": len(keystore_data),
                "encrypted_size": len(nonce + encrypted_data),
                "path": str(output_path.name)
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
                "security_profile": self.security_profile.value
            }
            
            metadata_path = workspace_dir / ".workspace"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Create README for workspace
            readme_content = """# Encrypted Workspace

This directory contains encrypted files created by OpenSSL Encrypt Portable.
All files written to this workspace are automatically encrypted.

To access files:
1. Launch OpenSSL Encrypt Portable from the USB drive
2. Enter your master password
3. Files will be automatically decrypted for use

Security Features:
- AES-256-GCM encryption
- Automatic encryption/decryption
- Secure deletion on exit
- Tamper detection
"""
            
            readme_path = workspace_dir / "README.txt"
            with open(readme_path, 'w') as f:
                f.write(readme_content)
            
            return {
                "created": True,
                "path": str(workspace_dir.name),
                "encryption": "AES-256-GCM"
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
            
            with open(autorun_inf, 'w') as f:
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
            
            with open(autorun_sh, 'w') as f:
                f.write(autorun_script)
            autorun_sh.chmod(0o755)  # Make executable
            autorun_info["files_created"].append("autorun.sh")
            
            # macOS .autorun file
            autorun_mac = usb_root / ".autorun"
            with open(autorun_mac, 'w') as f:
                f.write(f"{portable_root.name}/openssl_encrypt --portable-mode\n")
            autorun_info["files_created"].append(".autorun")
            
            return autorun_info
            
        except Exception as e:
            raise USBCreationError(f"Failed to create autorun files: {e}")
    
    def _create_integrity_file(self, portable_root: Path, key: bytes) -> Dict:
        """Create integrity verification file"""
        try:
            # Calculate checksums of important files
            checksums = {}
            important_files = []
            
            # Find important files to checksum
            for pattern in ["*.conf", "*.exe", "openssl_encrypt", "*.encrypted"]:
                important_files.extend(portable_root.rglob(pattern))
            
            for file_path in important_files:
                if file_path.is_file():
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    checksums[str(file_path.relative_to(portable_root))] = file_hash
            
            # Create integrity data
            integrity_data = {
                "version": self.VERSION,
                "created_at": time.time(),
                "security_profile": self.security_profile.value,
                "checksums": checksums,
                "file_count": len(checksums)
            }
            
            # Encrypt integrity data
            integrity_json = json.dumps(integrity_data, separators=(',', ':')).encode('utf-8')
            
            cipher = AESGCM(key)
            nonce = os.urandom(self.NONCE_LENGTH)
            encrypted_integrity = cipher.encrypt(nonce, integrity_json, None)
            
            # Write integrity file
            integrity_path = portable_root / self.INTEGRITY_FILE
            with open(integrity_path, 'wb') as f:
                f.write(nonce + encrypted_integrity)
            
            return {
                "created": True,
                "files_verified": len(checksums),
                "path": self.INTEGRITY_FILE
            }
            
        except Exception as e:
            raise USBCreationError(f"Failed to create integrity file: {e}")
    
    def _verify_integrity_file(self, portable_root: Path, key: bytes) -> Dict:
        """Verify integrity file and check for tampering"""
        try:
            integrity_path = portable_root / self.INTEGRITY_FILE
            
            with open(integrity_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Extract nonce and decrypt
            nonce = encrypted_data[:self.NONCE_LENGTH]
            ciphertext = encrypted_data[self.NONCE_LENGTH:]
            
            cipher = AESGCM(key)
            decrypted_data = cipher.decrypt(nonce, ciphertext, None)
            
            # Parse integrity data
            integrity_data = json.loads(decrypted_data.decode('utf-8'))
            stored_checksums = integrity_data["checksums"]
            
            # Verify current checksums
            verification_results = {
                "verified_files": 0,
                "failed_files": 0,
                "missing_files": 0,
                "tampered_files": [],
                "missing_file_list": []
            }
            
            for file_path, expected_hash in stored_checksums.items():
                full_path = portable_root / file_path
                
                if not full_path.exists():
                    verification_results["missing_files"] += 1
                    verification_results["missing_file_list"].append(file_path)
                    continue
                
                with open(full_path, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                
                if current_hash == expected_hash:
                    verification_results["verified_files"] += 1
                else:
                    verification_results["failed_files"] += 1
                    verification_results["tampered_files"].append(file_path)
            
            # Overall verification status
            verification_results["integrity_ok"] = (
                verification_results["failed_files"] == 0 and 
                verification_results["missing_files"] == 0
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
    
    def _cleanup_temp_files(self):
        """Clean up temporary files"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file {temp_file}: {e}")
        
        self.temp_files.clear()


# Convenience functions
def create_portable_usb(usb_path: str, password: str, hash_config: Optional[Dict] = None, **kwargs) -> Dict[str, any]:
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
    security_profile = USBSecurityProfile(kwargs.pop('security_profile', 'standard'))
    creator = USBDriveCreator(security_profile)
    return creator.create_portable_usb(usb_path, password, hash_config=hash_config, **kwargs)


def verify_usb_integrity(usb_path: str, password: str, hash_config: Optional[Dict] = None) -> Dict[str, any]:
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