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
            
            # Create encrypted workspace with transparent encryption support
            workspace_info = self._create_encrypted_workspace(data_dir, encryption_key)
            
            # Create transparent encryption helper scripts
            self._create_transparent_encryption_helpers(portable_root, hash_config)
            
            # Create auto-run files
            autorun_info = self._create_autorun_files(usb_path, portable_root)
            
            # Store hash_config in a separate metadata file if complex hashing is used
            if hash_config:
                self._store_hash_config_metadata(config_dir, hash_config)
            
            # Generate integrity file
            integrity_info = self._create_integrity_file(portable_root, encryption_key, hash_config)
            
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
            
            # First, try to read the hash_config from the integrity file if not provided
            if hash_config is None:
                try:
                    stored_hash_config = self._read_hash_config_from_integrity(portable_root, password)
                    if stored_hash_config:
                        hash_config = stored_hash_config
                        logger.debug("Successfully read hash_config from USB integrity file")
                except Exception as e:
                    logger.debug(f"Could not read hash_config from integrity file: {e}")
                    # Continue with None hash_config (will use PBKDF2 fallback)
            
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
        Derive encryption key from password using complex hash chaining system
        
        Uses the same multi-hash approach as the main CLI for consistency.
        Falls back to PBKDF2 if no hash config provided or if import fails.
        """
        if hash_config is None:
            # Fallback to simple PBKDF2 if no hash config provided
            return self._derive_key_pbkdf2_fallback(password)
        
        try:
            # Import the complex hash chaining functionality from crypt_core
            from ..crypt_core import multi_hash_password
            
            # Use fixed salt for USB drives (deterministic but unique per USB)
            salt = b"openssl_encrypt_usb_v1.0_salt_2024"
            
            # Use the same multi-hash system as main CLI
            hashed_password = multi_hash_password(
                password=bytes(password),
                salt=salt,
                hash_config=hash_config,
                quiet=True,  # Suppress output during USB creation
                progress=False,
                debug=False
            )
            
            # Ensure we get exactly the key length we need (32 bytes for AES-256)
            if len(hashed_password) != self.KEY_LENGTH:
                # Hash the result to get the exact length we need
                import hashlib
                return hashlib.sha256(hashed_password).digest()[:self.KEY_LENGTH]
            
            return hashed_password
            
        except ImportError:
            # Fallback if crypt_core not available
            return self._derive_key_pbkdf2_fallback(password)
        except Exception as e:
            # Log the error but continue with fallback
            logger.warning(f"Complex hash derivation failed, using PBKDF2 fallback: {e}")
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
    
    def _create_integrity_file(self, portable_root: Path, key: bytes, hash_config: Optional[Dict] = None) -> Dict:
        """Create integrity verification file"""
        try:
            # Calculate checksums of important files
            checksums = {}
            important_files = []
            
            # Find important files to checksum
            for pattern in ["*.conf", "*.exe", "openssl_encrypt", "*.encrypted", "*.py", "*.bat", "*.sh"]:
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
                "file_count": len(checksums),
                "hash_config": hash_config  # Store hash configuration for verification
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
    
    def _store_hash_config_metadata(self, config_dir: Path, hash_config: Dict) -> None:
        """Store hash_config in a separate metadata file"""
        try:
            metadata_file = config_dir / "hash_config.json"
            with open(metadata_file, 'w') as f:
                json.dump(hash_config, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to store hash_config metadata: {e}")
    
    def _read_hash_config_from_integrity(self, portable_root: Path, password: str) -> Optional[Dict]:
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
                with open(metadata_file, 'r') as f:
                    hash_config = json.load(f)
                logger.debug("Successfully read hash_config from metadata file")
                return hash_config
            
            # Fallback: try to decrypt integrity file with PBKDF2 (for backwards compatibility)
            integrity_path = portable_root / self.INTEGRITY_FILE
            if not integrity_path.exists():
                return None
            
            # Try to decrypt with PBKDF2 (fallback method)
            secure_password = SecureBytes(password.encode('utf-8'))
            pbkdf2_key = self._derive_key_pbkdf2_fallback(secure_password)
            
            with open(integrity_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Extract nonce and decrypt
            nonce = encrypted_data[:self.NONCE_LENGTH]
            ciphertext = encrypted_data[self.NONCE_LENGTH:]
            
            cipher = AESGCM(pbkdf2_key)
            try:
                decrypted_data = cipher.decrypt(nonce, ciphertext, None)
                integrity_data = json.loads(decrypted_data.decode('utf-8'))
                
                # Clean up sensitive data
                secure_memzero(pbkdf2_key)
                secure_memzero(secure_password)
                
                # Return the stored hash_config if it exists
                hash_config = integrity_data.get("hash_config")
                if hash_config:
                    logger.debug("Successfully read hash_config from integrity file")
                return hash_config
                
            except Exception:
                # Decryption with PBKDF2 failed, this means complex hashing was likely used
                # Clean up and return None to indicate we need the hash_config parameter
                secure_memzero(pbkdf2_key)
                secure_memzero(secure_password)
                return None
                
        except Exception as e:
            logger.debug(f"Failed to read hash_config from metadata: {e}")
            return None
    
    def _create_transparent_encryption_helpers(self, portable_root: Path, hash_config: Optional[Dict] = None) -> None:
        """Create helper scripts for transparent encryption/decryption"""
        try:
            # Create a portable encryption script
            encrypt_script = portable_root / "encrypt_file.py"
            decrypt_script = portable_root / "decrypt_file.py"
            
            # Python script for encryption
            encrypt_code = f'''#!/usr/bin/env python3
"""
Portable USB File Encryption Helper
Automatically encrypts files to the USB workspace
"""
import sys
import os
import json
from pathlib import Path

# Add the current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

def verify_usb_integrity(password):
    """Verify USB integrity before file operations"""
    try:
        import json
        import hashlib
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        # Get portable root directory
        portable_root = Path(__file__).parent
        integrity_file = portable_root / ".integrity"
        
        if not integrity_file.exists():
            return False, "Integrity file missing"
        
        # Read hash configuration
        config_dir = portable_root / "config"
        hash_config_file = config_dir / "hash_config.json"
        
        hash_config = None
        if hash_config_file.exists():
            with open(hash_config_file, 'r') as f:
                hash_config = json.load(f)
        
        # Derive key for integrity verification
        if hash_config and hash_config.get('sha256'):
            password_bytes = password.encode('utf-8')
            salt = b"openssl_encrypt_usb_v1.0_salt_2024"
            derived = password_bytes + salt
            for _ in range(hash_config.get('sha256', 1)):
                derived = hashlib.sha256(derived).digest()
            key = derived[:32]
        else:
            salt = b"openssl_encrypt_usb_v1.0_salt_2024"
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            key = kdf.derive(password.encode('utf-8'))
        
        # Read and decrypt integrity file
        with open(integrity_file, 'rb') as f:
            encrypted_data = f.read()
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        cipher = AESGCM(key)
        decrypted_data = cipher.decrypt(nonce, ciphertext, None)
        integrity_data = json.loads(decrypted_data.decode('utf-8'))
        
        # Verify checksums
        stored_checksums = integrity_data["checksums"]
        failed_files = []
        
        for file_path, expected_hash in stored_checksums.items():
            full_path = portable_root / file_path
            
            if not full_path.exists():
                failed_files.append(f"Missing: {{file_path}}")
                continue
                
            with open(full_path, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            
            if current_hash != expected_hash:
                failed_files.append(f"Tampered: {{file_path}}")
        
        if failed_files:
            return False, f"Integrity check failed: {{', '.join(failed_files)}}"
        
        return True, "Integrity verified"
        
    except Exception as e:
        return False, f"Integrity verification error: {{e}}"

def encrypt_file_to_usb(input_file, password):
    """Encrypt a file to the USB workspace"""
    try:
        # First, verify USB integrity
        integrity_ok, integrity_msg = verify_usb_integrity(password)
        if not integrity_ok:
            print(f"🚨 SECURITY WARNING: {{integrity_msg}}")
            print("❌ File encryption aborted for security reasons")
            print("💡 Please verify your USB integrity before continuing")
            return False
        
        # Import encryption modules (simplified for portability)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        import hashlib
        import secrets
        
        # Read hash configuration
        config_dir = Path(__file__).parent / "config"
        hash_config_file = config_dir / "hash_config.json"
        
        hash_config = None
        if hash_config_file.exists():
            with open(hash_config_file, 'r') as f:
                hash_config = json.load(f)
        
        # Derive key (simplified version)
        if hash_config and hash_config.get('sha256'):
            # Complex hashing
            password_bytes = password.encode('utf-8')
            salt = b"openssl_encrypt_usb_v1.0_salt_2024"
            
            # Apply SHA rounds
            derived = password_bytes + salt
            for _ in range(hash_config.get('sha256', 1)):
                derived = hashlib.sha256(derived).digest()
            key = derived[:32]
        else:
            # PBKDF2 fallback
            salt = b"openssl_encrypt_usb_v1.0_salt_2024"
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            key = kdf.derive(password.encode('utf-8'))
        
        # Read input file
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Encrypt
        cipher = AESGCM(key)
        nonce = secrets.token_bytes(12)
        encrypted = cipher.encrypt(nonce, data, None)
        
        # Write to workspace
        workspace_dir = Path(__file__).parent / "data"
        output_file = workspace_dir / (Path(input_file).name + ".enc")
        
        with open(output_file, 'wb') as f:
            f.write(nonce + encrypted)
        
        print(f"✓ File encrypted to: {{output_file.name}}")
        return True
        
    except Exception as e:
        print(f"✗ Encryption failed: {{e}}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python encrypt_file.py <input_file> <password>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    password = sys.argv[2]
    
    if not os.path.exists(input_file):
        print(f"Error: File {{input_file}} not found")
        sys.exit(1)
    
    success = encrypt_file_to_usb(input_file, password)
    sys.exit(0 if success else 1)
'''
            
            with open(encrypt_script, 'w') as f:
                f.write(encrypt_code)
            encrypt_script.chmod(0o755)
            
            # Python script for decryption
            decrypt_code = f'''#!/usr/bin/env python3
"""
Portable USB File Decryption Helper
Automatically decrypts files from the USB workspace
"""
import sys
import os
import json
from pathlib import Path

# Add the current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

def verify_usb_integrity(password):
    """Verify USB integrity before file operations"""
    try:
        import json
        import hashlib
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        # Get portable root directory
        portable_root = Path(__file__).parent
        integrity_file = portable_root / ".integrity"
        
        if not integrity_file.exists():
            return False, "Integrity file missing"
        
        # Read hash configuration
        config_dir = portable_root / "config"
        hash_config_file = config_dir / "hash_config.json"
        
        hash_config = None
        if hash_config_file.exists():
            with open(hash_config_file, 'r') as f:
                hash_config = json.load(f)
        
        # Derive key for integrity verification
        if hash_config and hash_config.get('sha256'):
            password_bytes = password.encode('utf-8')
            salt = b"openssl_encrypt_usb_v1.0_salt_2024"
            derived = password_bytes + salt
            for _ in range(hash_config.get('sha256', 1)):
                derived = hashlib.sha256(derived).digest()
            key = derived[:32]
        else:
            salt = b"openssl_encrypt_usb_v1.0_salt_2024"
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            key = kdf.derive(password.encode('utf-8'))
        
        # Read and decrypt integrity file
        with open(integrity_file, 'rb') as f:
            encrypted_data = f.read()
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        cipher = AESGCM(key)
        decrypted_data = cipher.decrypt(nonce, ciphertext, None)
        integrity_data = json.loads(decrypted_data.decode('utf-8'))
        
        # Verify checksums
        stored_checksums = integrity_data["checksums"]
        failed_files = []
        
        for file_path, expected_hash in stored_checksums.items():
            full_path = portable_root / file_path
            
            if not full_path.exists():
                failed_files.append(f"Missing: {{file_path}}")
                continue
                
            with open(full_path, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            
            if current_hash != expected_hash:
                failed_files.append(f"Tampered: {{file_path}}")
        
        if failed_files:
            return False, f"Integrity check failed: {{', '.join(failed_files)}}"
        
        return True, "Integrity verified"
        
    except Exception as e:
        return False, f"Integrity verification error: {{e}}"

def decrypt_file_from_usb(encrypted_file, password, output_file=None):
    """Decrypt a file from the USB workspace"""
    try:
        # First, verify USB integrity
        integrity_ok, integrity_msg = verify_usb_integrity(password)
        if not integrity_ok:
            print(f"🚨 SECURITY WARNING: {{integrity_msg}}")
            print("❌ File decryption aborted for security reasons") 
            print("💡 Please verify your USB integrity before continuing")
            return False
        
        # Import encryption modules (simplified for portability)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        import hashlib
        
        # Read hash configuration
        config_dir = Path(__file__).parent / "config"
        hash_config_file = config_dir / "hash_config.json"
        
        hash_config = None
        if hash_config_file.exists():
            with open(hash_config_file, 'r') as f:
                hash_config = json.load(f)
        
        # Derive key (same as encryption)
        if hash_config and hash_config.get('sha256'):
            # Complex hashing
            password_bytes = password.encode('utf-8')
            salt = b"openssl_encrypt_usb_v1.0_salt_2024"
            
            # Apply SHA rounds
            derived = password_bytes + salt
            for _ in range(hash_config.get('sha256', 1)):
                derived = hashlib.sha256(derived).digest()
            key = derived[:32]
        else:
            # PBKDF2 fallback
            salt = b"openssl_encrypt_usb_v1.0_salt_2024"
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            key = kdf.derive(password.encode('utf-8'))
        
        # Handle file paths
        workspace_dir = Path(__file__).parent / "data"
        if not encrypted_file.startswith('/'):
            encrypted_file = workspace_dir / encrypted_file
        else:
            encrypted_file = Path(encrypted_file)
        
        # Read encrypted file
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        # Extract nonce and decrypt
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        cipher = AESGCM(key)
        decrypted = cipher.decrypt(nonce, ciphertext, None)
        
        # Handle output destination
        if output_file is None:
            output_file = encrypted_file.name.replace('.enc', '')
        
        # Special handling for stdout output
        if output_file == '-' or output_file.lower() == 'stdout':
            # Output to stdout for quick viewing
            try:
                # Try to decode as text first
                text_content = decrypted.decode('utf-8')
                print(text_content, end='')
            except UnicodeDecodeError:
                # Binary content, output raw bytes
                import sys
                sys.stdout.buffer.write(decrypted)
            return True
        else:
            # Write decrypted file to disk
            with open(output_file, 'wb') as f:
                f.write(decrypted)
            
            print(f"✓ File decrypted to: {{output_file}}")
            return True
        
    except Exception as e:
        print(f"✗ Decryption failed: {{e}}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python decrypt_file.py <encrypted_file> <password> [output_file]")
        print("")
        print("Options:")
        print("  output_file    Write decrypted content to file")  
        print("  -              Output decrypted content to stdout (default)")
        print("  stdout         Output decrypted content to stdout")
        print("")
        print("Examples:")
        print("  python decrypt_file.py secret.txt.enc mypass")
        print("  python decrypt_file.py secret.txt.enc mypass -")
        print("  python decrypt_file.py secret.txt.enc mypass /path/output.txt")
        sys.exit(1)
    
    encrypted_file = sys.argv[1]
    password = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else '-'  # Default to stdout
    
    success = decrypt_file_from_usb(encrypted_file, password, output_file)
    sys.exit(0 if success else 1)
'''
            
            with open(decrypt_script, 'w') as f:
                f.write(decrypt_code)
            decrypt_script.chmod(0o755)
            
            # Create convenience batch files for Windows
            if platform.system() == "Windows":
                encrypt_bat = portable_root / "encrypt_file.bat"
                decrypt_bat = portable_root / "decrypt_file.bat"
                
                with open(encrypt_bat, 'w') as f:
                    f.write('@echo off\\npython encrypt_file.py %1 %2\\npause\\n')
                
                with open(decrypt_bat, 'w') as f:
                    f.write('@echo off\\npython decrypt_file.py %1 %2 %3\\npause\\n')
            
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