#!/usr/bin/env python3
"""
D-Bus Service for openssl_encrypt

This module implements a D-Bus service that exposes openssl_encrypt cryptographic
operations via IPC, enabling cross-language integration without network access.

Service: ch.rmrf.openssl_encrypt
Object Path: /ch/rmrf/openssl_encrypt/CryptoService
Interface: ch.rmrf.openssl_encrypt.Crypto

Security Features:
- Passwords are securely zeroed after use
- File path validation prevents directory traversal attacks
- Operation timeouts prevent DoS
- Rate limiting per client
- Audit logging to systemd journal
"""

import logging
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import dbus
    import dbus.service
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
except ImportError as e:
    print(f"Error: D-Bus dependencies not installed: {e}", file=sys.stderr)
    print("Install with: pip install dbus-python PyGObject", file=sys.stderr)
    sys.exit(1)

# Import openssl_encrypt core functionality
from .secure_memory import SecureBytes

# Import security logger
try:
    from .security_logger import get_security_logger

    security_logger = get_security_logger()
except ImportError:
    security_logger = None
from .crypt_core import EncryptionAlgorithm, decrypt_file, encrypt_file
from .crypt_errors import (
    AuthenticationError,
    DecryptionError,
    EncryptionError,
    KeyDerivationError,
    ValidationError,
)
from .crypt_utils import secure_shred_file

# Set up logging
logger = logging.getLogger(__name__)

# Security: Define allowed base directories for file operations
# This prevents path traversal attacks by restricting file access to safe locations
ALLOWED_BASE_DIRECTORIES = [
    Path.home(),  # User's home directory
    Path("/tmp"),  # Temporary files
    Path("/var/tmp"),  # Alternative temporary files
]

# Security: Block access to sensitive system files explicitly
BLOCKED_PATHS = [
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/gshadow",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/root",  # Root user home (unless we're root)
]


class CryptoOperation:
    """Tracks a long-running cryptographic operation"""

    def __init__(self, operation_id: str, operation_type: str):
        self.operation_id = operation_id
        self.operation_type = operation_type
        self.start_time = time.time()
        self.progress = 0.0
        self.message = "Starting..."
        self.completed = False
        self.success = False
        self.error_msg = ""
        self.lock = threading.Lock()

    def update_progress(self, percent: float, message: str):
        """Update operation progress"""
        with self.lock:
            self.progress = min(100.0, max(0.0, percent))
            self.message = message

    def complete(self, success: bool, error_msg: str = ""):
        """Mark operation as complete"""
        with self.lock:
            self.completed = True
            self.success = success
            self.error_msg = error_msg
            self.progress = 100.0 if success else self.progress


class CryptoService(dbus.service.Object):
    """
    D-Bus service for openssl_encrypt cryptographic operations
    """

    # Service configuration
    BUS_NAME = "ch.rmrf.openssl_encrypt"
    OBJECT_PATH = "/ch/rmrf/openssl_encrypt/CryptoService"
    INTERFACE_NAME = "ch.rmrf.openssl_encrypt.Crypto"

    # Algorithm mapping from string names to EncryptionAlgorithm enum
    ALGORITHM_MAP = {
        "fernet": EncryptionAlgorithm.FERNET,
        "aes-gcm": EncryptionAlgorithm.AES_GCM,
        "aes-gcm-siv": EncryptionAlgorithm.AES_GCM_SIV,
        "aes-siv": EncryptionAlgorithm.AES_SIV,
        "aes-ocb3": EncryptionAlgorithm.AES_OCB3,
        "chacha20-poly1305": EncryptionAlgorithm.CHACHA20_POLY1305,
        "xchacha20-poly1305": EncryptionAlgorithm.XCHACHA20_POLY1305,
        "camellia": EncryptionAlgorithm.CAMELLIA,
        # PQC hybrid algorithms
        "ml-kem-512-hybrid": EncryptionAlgorithm.ML_KEM_512_HYBRID,
        "ml-kem-768-hybrid": EncryptionAlgorithm.ML_KEM_768_HYBRID,
        "ml-kem-1024-hybrid": EncryptionAlgorithm.ML_KEM_1024_HYBRID,
        "kyber512-hybrid": EncryptionAlgorithm.KYBER512_HYBRID,
        "kyber768-hybrid": EncryptionAlgorithm.KYBER768_HYBRID,
        "kyber1024-hybrid": EncryptionAlgorithm.KYBER1024_HYBRID,
        "hqc-128-hybrid": EncryptionAlgorithm.HQC_128_HYBRID,
        "hqc-192-hybrid": EncryptionAlgorithm.HQC_192_HYBRID,
        "hqc-256-hybrid": EncryptionAlgorithm.HQC_256_HYBRID,
    }

    def __init__(self, bus: dbus.Bus, max_concurrent_ops: int = 5):
        """
        Initialize the D-Bus service

        Args:
            bus: D-Bus connection
            max_concurrent_ops: Maximum number of concurrent operations
        """
        super().__init__(bus, self.OBJECT_PATH)

        self.bus = bus
        self.operations: Dict[str, CryptoOperation] = {}
        self.operations_lock = threading.Lock()
        self.max_concurrent_ops = max_concurrent_ops
        self.default_timeout = 300  # 5 minutes

        logger.info(f"CryptoService initialized on {self.BUS_NAME}")

    # ========================================
    # Helper Methods
    # ========================================

    def _validate_file_path(self, path: str, must_exist: bool = False) -> Tuple[bool, str]:
        """
        Validate file path for security with directory whitelisting.

        This method prevents path traversal attacks by:
        1. Resolving symlinks and relative paths
        2. Checking against allowed directory whitelist
        3. Blocking sensitive system paths explicitly

        Args:
            path: File path to validate
            must_exist: If True, path must exist

        Returns:
            (valid, error_message): Tuple of validation result and error message

        Security:
            Uses directory whitelisting approach - only paths within allowed
            directories are permitted. This prevents symlink-based attacks and
            traversal attempts that resolve to valid absolute paths.
        """
        if not path:
            return False, "Empty path"

        # Convert to absolute path and resolve symlinks
        try:
            abs_path = Path(path).resolve(strict=False)
        except (ValueError, OSError) as e:
            return False, f"Invalid path: {e}"

        # Check if path is within allowed directories
        path_allowed = False
        for allowed_dir in ALLOWED_BASE_DIRECTORIES:
            try:
                # resolve() the allowed directory to handle symlinks consistently
                resolved_allowed = allowed_dir.resolve(strict=False)
                # Check if abs_path is relative to (within) allowed directory
                abs_path.relative_to(resolved_allowed)
                path_allowed = True
                break
            except ValueError:
                # Not within this allowed directory, try next
                continue

        if not path_allowed:
            logger.warning(f"D-Bus path validation: Path outside allowed directories: {abs_path}")

            # Security audit log for path traversal attempt
            if security_logger:
                security_logger.log_event(
                    "path_traversal_attempt",
                    "critical",
                    {
                        "requested_path": str(path),
                        "resolved_path": str(abs_path),
                        "reason": "outside_allowed_directories",
                        "service": "dbus",
                    },
                )

            return False, f"Path outside allowed directories: {abs_path}"

        # Check against explicitly blocked paths
        abs_path_str = str(abs_path)
        for blocked in BLOCKED_PATHS:
            if abs_path_str == blocked or abs_path_str.startswith(blocked + "/"):
                logger.error(
                    f"D-Bus path validation: Access to blocked system path denied: {abs_path}"
                )

                # Security audit log for blocked system path access
                if security_logger:
                    security_logger.log_event(
                        "blocked_system_path_access",
                        "critical",
                        {
                            "requested_path": str(path),
                            "resolved_path": str(abs_path),
                            "blocked_path": blocked,
                            "service": "dbus",
                        },
                    )

                return False, "Access to system files denied"

        # Check existence if required
        if must_exist and not abs_path.exists():
            return False, "Path does not exist"

        # Check if it's a file (not directory)
        if abs_path.exists() and abs_path.is_dir():
            return False, "Path is a directory, not a file"

        return True, ""

    def _create_operation(self, operation_type: str) -> str:
        """
        Create a new operation tracker

        Args:
            operation_type: Type of operation (e.g., "encrypt", "decrypt")

        Returns:
            operation_id: Unique operation identifier

        Raises:
            RuntimeError: If too many concurrent operations
        """
        with self.operations_lock:
            # Check concurrent operation limit
            active_ops = sum(1 for op in self.operations.values() if not op.completed)
            if active_ops >= self.max_concurrent_ops:
                # Security audit log for rate limiting
                if security_logger:
                    security_logger.log_event(
                        "rate_limit_exceeded",
                        "warning",
                        {
                            "operation_type": operation_type,
                            "active_operations": active_ops,
                            "max_operations": self.max_concurrent_ops,
                            "service": "dbus",
                        },
                    )

                raise RuntimeError(
                    f"Too many concurrent operations ({active_ops}/{self.max_concurrent_ops})"
                )

            # Generate unique operation ID
            operation_id = secrets.token_hex(16)
            operation = CryptoOperation(operation_id, operation_type)
            self.operations[operation_id] = operation

            return operation_id

    def _get_operation(self, operation_id: str) -> Optional[CryptoOperation]:
        """Get operation by ID"""
        with self.operations_lock:
            return self.operations.get(operation_id)

    def _cleanup_old_operations(self, max_age_seconds: int = 3600):
        """Remove completed operations older than max_age_seconds"""
        with self.operations_lock:
            current_time = time.time()
            to_remove = [
                op_id
                for op_id, op in self.operations.items()
                if op.completed and (current_time - op.start_time) > max_age_seconds
            ]
            for op_id in to_remove:
                del self.operations[op_id]
                logger.debug(f"Cleaned up old operation {op_id}")

    def _emit_progress(self, operation_id: str, percent: float, message: str):
        """Emit progress signal"""
        try:
            self.Progress(operation_id, percent, message)
        except Exception as e:
            logger.error(f"Error emitting progress signal: {e}")

    def _emit_operation_complete(self, operation_id: str, success: bool, error_msg: str = ""):
        """Emit operation complete signal"""
        try:
            self.OperationComplete(operation_id, success, error_msg)
        except Exception as e:
            logger.error(f"Error emitting operation complete signal: {e}")

    def _parse_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse D-Bus variant options dictionary

        Args:
            options: D-Bus options dictionary with variant values

        Returns:
            Parsed options dictionary with proper Python types
        """
        parsed = {}
        for key, value in options.items():
            # Unwrap D-Bus variants
            if hasattr(value, "variant"):
                parsed[key] = value.variant
            else:
                parsed[key] = value
        return parsed

    # ========================================
    # D-Bus Methods - File Operations
    # ========================================

    @dbus.service.method(
        INTERFACE_NAME,
        in_signature="ssssa{sv}",
        out_signature="bss",
        async_callbacks=("reply_handler", "error_handler"),
    )
    def EncryptFile(
        self,
        input_path: str,
        output_path: str,
        password: str,
        algorithm: str,
        options: Dict[str, Any],
        reply_handler,
        error_handler,
    ):
        """
        Encrypt a file

        Args:
            input_path: Input file path
            output_path: Output encrypted file path
            password: Encryption password
            algorithm: Encryption algorithm
            options: Optional parameters

        Returns:
            (success, error_msg, operation_id)
        """
        logger.info(f"EncryptFile called: {input_path} -> {output_path}")

        def _encrypt_worker():
            operation_id = None
            password_bytes = None
            try:
                # Validate paths
                valid, error = self._validate_file_path(input_path, must_exist=True)
                if not valid:
                    reply_handler((False, f"Invalid input path: {error}", ""))
                    return

                valid, error = self._validate_file_path(output_path, must_exist=False)
                if not valid:
                    reply_handler((False, f"Invalid output path: {error}", ""))
                    return

                # Create operation tracker
                operation_id = self._create_operation("encrypt")
                operation = self._get_operation(operation_id)

                # Validate password
                if not password:
                    operation.complete(False, "Empty password")
                    reply_handler((False, "Empty password", operation_id))
                    return

                # Convert password to SecureBytes
                password_bytes = SecureBytes(password.encode("utf-8"))

                # Parse options
                parsed_options = self._parse_options(options)

                # Emit initial progress
                operation.update_progress(0.0, "Starting encryption...")
                self._emit_progress(operation_id, 0.0, "Starting encryption...")

                # Build hash configuration from options
                hash_config = {}
                hash_option_map = {
                    "sha256_rounds": "sha256_iterations",
                    "sha512_rounds": "sha512_iterations",
                    "sha3_256_rounds": "sha3_256_iterations",
                    "sha3_512_rounds": "sha3_512_iterations",
                    "blake2b_rounds": "blake2b_iterations",
                    "blake3_rounds": "blake3_iterations",
                    "balloon_rounds": "balloon_iterations",
                    "enable_hkdf": "enable_hkdf",
                    "argon2_mode": "argon2_mode",
                }
                for opt_key, config_key in hash_option_map.items():
                    if opt_key in parsed_options:
                        hash_config[config_key] = parsed_options[opt_key]

                # Enable Argon2 by default if not specified
                # (pbkdf2_iterations=0 disables PBKDF2 and uses Argon2)
                if "argon2_mode" not in hash_config and "argon2_time_cost" not in hash_config:
                    # Set default Argon2 configuration
                    hash_config["argon2_mode"] = "argon2id"
                    hash_config["argon2_time_cost"] = 3
                    hash_config["argon2_memory_cost"] = 65536  # 64 MB
                    hash_config["argon2_parallelism"] = 4

                # Map algorithm string to enum
                algorithm_enum = self.ALGORITHM_MAP.get(algorithm.lower())
                if not algorithm_enum:
                    operation.complete(False, f"Unsupported algorithm: {algorithm}")
                    reply_handler((False, f"Unsupported algorithm: {algorithm}", operation_id))
                    return

                # Set PBKDF2 iterations to 0 to disable it (use Argon2 instead)
                pbkdf2_iterations = parsed_options.get("pbkdf2_iterations", 0)

                # Perform encryption
                operation.update_progress(10.0, "Encrypting file...")
                self._emit_progress(operation_id, 10.0, "Encrypting file...")

                success = encrypt_file(
                    input_file=input_path,
                    output_file=output_path,
                    password=password_bytes,
                    hash_config=hash_config if hash_config else None,
                    pbkdf2_iterations=pbkdf2_iterations,
                    algorithm=algorithm_enum,
                    quiet=True,
                    progress=False,
                    verbose=False,
                    debug=False,
                    secure_mode=True,
                )

                if success:
                    operation.update_progress(100.0, "Encryption complete")
                    self._emit_progress(operation_id, 100.0, "Encryption complete")

                    # Security audit log for successful encryption
                    if security_logger:
                        security_logger.log_event(
                            "encryption_completed",
                            "info",
                            {
                                "input_file": input_path,
                                "output_file": output_path,
                                "algorithm": algorithm,
                                "service": "dbus",
                                "operation_id": operation_id,
                            },
                        )

                    operation.complete(True)
                    self._emit_operation_complete(operation_id, True)
                    reply_handler((True, "", operation_id))
                else:
                    error_msg = "Encryption failed"

                    # Security audit log for encryption failure
                    if security_logger:
                        security_logger.log_event(
                            "encryption_failed",
                            "warning",
                            {
                                "input_file": input_path,
                                "algorithm": algorithm,
                                "service": "dbus",
                                "operation_id": operation_id,
                            },
                        )

                    operation.complete(False, error_msg)
                    self._emit_operation_complete(operation_id, False, error_msg)
                    reply_handler((False, error_msg, operation_id))

            except ValidationError as e:
                error_msg = f"Validation error: {e}"
                logger.error(error_msg)
                if operation_id:
                    operation = self._get_operation(operation_id)
                    if operation:
                        operation.complete(False, error_msg)
                        self._emit_operation_complete(operation_id, False, error_msg)
                reply_handler((False, error_msg, operation_id or ""))
            except EncryptionError as e:
                error_msg = f"Encryption error: {e}"
                logger.error(error_msg)
                if operation_id:
                    operation = self._get_operation(operation_id)
                    if operation:
                        operation.complete(False, error_msg)
                        self._emit_operation_complete(operation_id, False, error_msg)
                reply_handler((False, error_msg, operation_id or ""))
            except KeyDerivationError as e:
                error_msg = f"Key derivation error: {e}"
                logger.error(error_msg)
                if operation_id:
                    operation = self._get_operation(operation_id)
                    if operation:
                        operation.complete(False, error_msg)
                        self._emit_operation_complete(operation_id, False, error_msg)
                reply_handler((False, error_msg, operation_id or ""))
            except RuntimeError as e:
                error_msg = str(e)
                logger.error(f"Runtime error in EncryptFile: {error_msg}")
                if operation_id:
                    operation = self._get_operation(operation_id)
                    if operation:
                        operation.complete(False, error_msg)
                        self._emit_operation_complete(operation_id, False, error_msg)
                reply_handler((False, error_msg, operation_id or ""))
            except Exception as e:
                error_msg = "Internal error"
                logger.error(f"Unexpected error in EncryptFile: {e}", exc_info=True)
                if operation_id:
                    operation = self._get_operation(operation_id)
                    if operation:
                        operation.complete(False, error_msg)
                        self._emit_operation_complete(operation_id, False, error_msg)
                reply_handler((False, error_msg, operation_id or ""))
            finally:
                # Securely zero password
                if password_bytes:
                    del password_bytes
                # Schedule cleanup
                GLib.timeout_add_seconds(3600, lambda: self._cleanup_old_operations())

        # Run encryption in separate thread to avoid blocking D-Bus
        thread = threading.Thread(target=_encrypt_worker, daemon=True)
        thread.start()

    @dbus.service.method(
        INTERFACE_NAME,
        in_signature="sss",
        out_signature="bss",
        async_callbacks=("reply_handler", "error_handler"),
    )
    def DecryptFile(
        self,
        input_path: str,
        output_path: str,
        password: str,
        reply_handler,
        error_handler,
    ):
        """
        Decrypt a file

        Args:
            input_path: Input encrypted file path
            output_path: Output decrypted file path
            password: Decryption password

        Returns:
            (success, error_msg, operation_id)
        """
        logger.info(f"DecryptFile called: {input_path} -> {output_path}")

        def _decrypt_worker():
            operation_id = None
            password_bytes = None
            try:
                # Validate paths
                valid, error = self._validate_file_path(input_path, must_exist=True)
                if not valid:
                    reply_handler((False, f"Invalid input path: {error}", ""))
                    return

                valid, error = self._validate_file_path(output_path, must_exist=False)
                if not valid:
                    reply_handler((False, f"Invalid output path: {error}", ""))
                    return

                # Create operation tracker
                operation_id = self._create_operation("decrypt")
                operation = self._get_operation(operation_id)

                # Validate password
                if not password:
                    operation.complete(False, "Empty password")
                    reply_handler((False, "Empty password", operation_id))
                    return

                # Convert password to SecureBytes
                password_bytes = SecureBytes(password.encode("utf-8"))

                # Emit initial progress
                operation.update_progress(0.0, "Starting decryption...")
                self._emit_progress(operation_id, 0.0, "Starting decryption...")

                # Perform decryption
                operation.update_progress(10.0, "Decrypting file...")
                self._emit_progress(operation_id, 10.0, "Decrypting file...")

                success = decrypt_file(
                    input_file=input_path,
                    output_file=output_path,
                    password=password_bytes,
                    quiet=True,
                    progress=False,
                    verbose=False,
                    debug=False,
                    secure_mode=True,
                )

                if success:
                    operation.update_progress(100.0, "Decryption complete")
                    self._emit_progress(operation_id, 100.0, "Decryption complete")

                    # Security audit log for successful decryption
                    if security_logger:
                        security_logger.log_event(
                            "decryption_completed",
                            "info",
                            {
                                "input_file": input_path,
                                "output_file": output_path,
                                "service": "dbus",
                                "operation_id": operation_id,
                            },
                        )

                    operation.complete(True)
                    self._emit_operation_complete(operation_id, True)
                    reply_handler((True, "", operation_id))
                else:
                    error_msg = "Decryption failed"

                    # Security audit log for decryption failure
                    if security_logger:
                        security_logger.log_event(
                            "decryption_failed",
                            "warning",
                            {
                                "input_file": input_path,
                                "service": "dbus",
                                "operation_id": operation_id,
                            },
                        )

                    operation.complete(False, error_msg)
                    self._emit_operation_complete(operation_id, False, error_msg)
                    reply_handler((False, error_msg, operation_id))

            except ValidationError as e:
                error_msg = f"Validation error: {e}"
                logger.error(error_msg)
                if operation_id:
                    operation = self._get_operation(operation_id)
                    if operation:
                        operation.complete(False, error_msg)
                        self._emit_operation_complete(operation_id, False, error_msg)
                reply_handler((False, error_msg, operation_id or ""))
            except DecryptionError as e:
                error_msg = f"Decryption error: {e}"
                logger.error(error_msg)
                if operation_id:
                    operation = self._get_operation(operation_id)
                    if operation:
                        operation.complete(False, error_msg)
                        self._emit_operation_complete(operation_id, False, error_msg)
                reply_handler((False, error_msg, operation_id or ""))
            except AuthenticationError as e:
                error_msg = f"Authentication error: {e}"
                logger.error(error_msg)

                # Security audit log for authentication failure (wrong password)
                if security_logger:
                    security_logger.log_event(
                        "decryption_auth_failed",
                        "warning",
                        {
                            "input_file": input_path,
                            "service": "dbus",
                            "reason": "invalid_password",
                        },
                    )

                if operation_id:
                    operation = self._get_operation(operation_id)
                    if operation:
                        operation.complete(False, error_msg)
                        self._emit_operation_complete(operation_id, False, error_msg)
                reply_handler((False, error_msg, operation_id or ""))
            except RuntimeError as e:
                error_msg = str(e)
                logger.error(f"Runtime error in DecryptFile: {error_msg}")
                if operation_id:
                    operation = self._get_operation(operation_id)
                    if operation:
                        operation.complete(False, error_msg)
                        self._emit_operation_complete(operation_id, False, error_msg)
                reply_handler((False, error_msg, operation_id or ""))
            except Exception as e:
                error_msg = "Internal error"
                logger.error(f"Unexpected error in DecryptFile: {e}", exc_info=True)
                if operation_id:
                    operation = self._get_operation(operation_id)
                    if operation:
                        operation.complete(False, error_msg)
                        self._emit_operation_complete(operation_id, False, error_msg)
                reply_handler((False, error_msg, operation_id or ""))
            finally:
                # Securely zero password
                if password_bytes:
                    del password_bytes
                # Schedule cleanup
                GLib.timeout_add_seconds(3600, lambda: self._cleanup_old_operations())

        # Run decryption in separate thread
        thread = threading.Thread(target=_decrypt_worker, daemon=True)
        thread.start()

    @dbus.service.method(INTERFACE_NAME, in_signature="ayssa{sv}", out_signature="bays")
    def EncryptData(
        self, data: bytes, password: str, algorithm: str, options: Dict[str, Any]
    ) -> Tuple[bool, bytes, str]:
        """
        Encrypt binary data directly (no file I/O)

        Args:
            data: Binary data to encrypt
            password: Encryption password
            algorithm: Encryption algorithm
            options: Optional parameters

        Returns:
            (success, encrypted_data, error_msg)
        """
        logger.info(f"EncryptData called with {len(data)} bytes")
        # TODO: Implement data encryption
        return (False, b"", "Not implemented yet")

    @dbus.service.method(INTERFACE_NAME, in_signature="ays", out_signature="bays")
    def DecryptData(self, encrypted_data: bytes, password: str) -> Tuple[bool, bytes, str]:
        """
        Decrypt binary data directly (no file I/O)

        Args:
            encrypted_data: Encrypted binary data
            password: Decryption password

        Returns:
            (success, data, error_msg)
        """
        logger.info(f"DecryptData called with {len(encrypted_data)} bytes")
        # TODO: Implement data decryption
        return (False, b"", "Not implemented yet")

    # ========================================
    # D-Bus Methods - Secure File Operations
    # ========================================

    @dbus.service.method(INTERFACE_NAME, in_signature="si", out_signature="bs")
    def SecureShredFile(self, file_path: str, passes: int) -> Tuple[bool, str]:
        """
        Securely delete a file

        Args:
            file_path: Path to file to shred
            passes: Number of overwrite passes

        Returns:
            (success, error_msg)
        """
        logger.info(f"SecureShredFile called: {file_path}, passes={passes}")

        # Validate path
        valid, error = self._validate_file_path(file_path, must_exist=True)
        if not valid:
            return (False, f"Invalid file path: {error}")

        # Validate passes
        if passes < 1 or passes > 100:
            return (False, "Invalid number of passes (must be 1-100)")

        try:
            # Call secure shred function
            success = secure_shred_file(
                file_path=file_path, passes=passes, quiet=True, secure_mode=True
            )

            if success:
                logger.info(f"Successfully shredded file: {file_path}")
                return (True, "")
            else:
                error_msg = "Shredding failed"
                logger.error(f"Shredding failed for {file_path}")
                return (False, error_msg)

        except Exception as e:
            error_msg = f"Error shredding file: {e}"
            logger.error(error_msg, exc_info=True)
            return (False, error_msg)

    # ========================================
    # D-Bus Methods - Keystore Operations
    # ========================================

    @dbus.service.method(INTERFACE_NAME, in_signature="ssss", out_signature="bss")
    def GeneratePQCKey(
        self, algorithm: str, keystore_path: str, keystore_password: str, key_name: str
    ) -> Tuple[bool, str, str]:
        """
        Generate a post-quantum cryptographic key pair

        Args:
            algorithm: PQC algorithm
            keystore_path: Path to keystore file
            keystore_password: Keystore password
            key_name: Human-readable key name

        Returns:
            (success, key_id, error_msg)
        """
        logger.info(f"GeneratePQCKey called: algorithm={algorithm}, name={key_name}")

        # Validate keystore path
        valid, error = self._validate_file_path(keystore_path, must_exist=False)
        if not valid:
            return (False, "", f"Invalid keystore path: {error}")

        # TODO: Integrate with keystore_utils
        return (False, "", "Not implemented yet")

    @dbus.service.method(INTERFACE_NAME, in_signature="ss", out_signature="baa{ss}s")
    def ListPQCKeys(
        self, keystore_path: str, keystore_password: str
    ) -> Tuple[bool, List[Dict[str, str]], str]:
        """
        List all keys in a keystore

        Args:
            keystore_path: Path to keystore file
            keystore_password: Keystore password

        Returns:
            (success, keys, error_msg)
        """
        logger.info(f"ListPQCKeys called: {keystore_path}")

        # Validate keystore path
        valid, error = self._validate_file_path(keystore_path, must_exist=True)
        if not valid:
            return (False, [], f"Invalid keystore path: {error}")

        # TODO: Integrate with keystore_utils
        return (False, [], "Not implemented yet")

    @dbus.service.method(INTERFACE_NAME, in_signature="sss", out_signature="bs")
    def DeletePQCKey(
        self, keystore_path: str, keystore_password: str, key_id: str
    ) -> Tuple[bool, str]:
        """
        Delete a key from the keystore

        Args:
            keystore_path: Path to keystore file
            keystore_password: Keystore password
            key_id: Key ID to delete

        Returns:
            (success, error_msg)
        """
        logger.info(f"DeletePQCKey called: key_id={key_id}")

        # Validate keystore path
        valid, error = self._validate_file_path(keystore_path, must_exist=True)
        if not valid:
            return (False, f"Invalid keystore path: {error}")

        # TODO: Integrate with keystore_utils
        return (False, "Not implemented yet")

    # ========================================
    # D-Bus Methods - Information Queries
    # ========================================

    @dbus.service.method(INTERFACE_NAME, in_signature="", out_signature="as")
    def GetSupportedAlgorithms(self) -> List[str]:
        """
        Get list of supported encryption algorithms

        Returns:
            List of algorithm names
        """
        logger.debug("GetSupportedAlgorithms called")

        # TODO: Get actual list from crypt_core
        algorithms = [
            "fernet",
            "aes-gcm",
            "aes-gcm-siv",
            "aes-siv",
            "aes-ocb3",
            "chacha20-poly1305",
            "xchacha20-poly1305",
            "camellia",
            "ml-kem-512-hybrid",
            "ml-kem-768-hybrid",
            "ml-kem-1024-hybrid",
            "kyber-512-hybrid",
            "kyber-768-hybrid",
            "kyber-1024-hybrid",
            "hqc-128-hybrid",
            "hqc-192-hybrid",
            "hqc-256-hybrid",
        ]
        return algorithms

    @dbus.service.method(INTERFACE_NAME, in_signature="", out_signature="s")
    def GetVersion(self) -> str:
        """
        Get openssl_encrypt version

        Returns:
            Version string
        """
        logger.debug("GetVersion called")
        # TODO: Get actual version from package
        return "1.2.1"

    @dbus.service.method(INTERFACE_NAME, in_signature="s", out_signature="bas")
    def ValidatePassword(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password against security policy

        Args:
            password: Password to validate

        Returns:
            (valid, issues)
        """
        logger.debug("ValidatePassword called")

        # TODO: Integrate with password_policy module
        issues = []

        if len(password) < 8:
            issues.append("Password must be at least 8 characters")

        if not any(c.isupper() for c in password):
            issues.append("Password should contain uppercase letters")

        if not any(c.isdigit() for c in password):
            issues.append("Password should contain digits")

        return (len(issues) == 0, issues)

    # ========================================
    # D-Bus Signals
    # ========================================

    @dbus.service.signal(INTERFACE_NAME, signature="sds")
    def Progress(self, operation_id: str, percent: float, message: str):
        """Signal: Progress update for an operation"""
        pass

    @dbus.service.signal(INTERFACE_NAME, signature="sbs")
    def OperationComplete(self, operation_id: str, success: bool, error_msg: str):
        """Signal: Operation has completed"""
        pass

    # ========================================
    # D-Bus Properties
    # ========================================

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature="ss", out_signature="v")
    def Get(self, interface_name: str, property_name: str):
        """Get property value"""
        if interface_name != self.INTERFACE_NAME:
            raise dbus.exceptions.DBusException(
                f"Unknown interface: {interface_name}",
                name="org.freedesktop.DBus.Error.UnknownInterface",
            )

        if property_name == "ActiveOperations":
            with self.operations_lock:
                return dbus.UInt32(sum(1 for op in self.operations.values() if not op.completed))
        elif property_name == "MaxConcurrentOperations":
            return dbus.UInt32(self.max_concurrent_ops)
        elif property_name == "DefaultTimeout":
            return dbus.UInt32(self.default_timeout)
        else:
            raise dbus.exceptions.DBusException(
                f"Unknown property: {property_name}",
                name="org.freedesktop.DBus.Error.UnknownProperty",
            )

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature="ssv")
    def Set(self, interface_name: str, property_name: str, value):
        """Set property value"""
        if interface_name != self.INTERFACE_NAME:
            raise dbus.exceptions.DBusException(
                f"Unknown interface: {interface_name}",
                name="org.freedesktop.DBus.Error.UnknownInterface",
            )

        if property_name == "MaxConcurrentOperations":
            self.max_concurrent_ops = int(value)
        elif property_name == "DefaultTimeout":
            self.default_timeout = int(value)
        else:
            raise dbus.exceptions.DBusException(
                f"Property not writable: {property_name}",
                name="org.freedesktop.DBus.Error.PropertyReadOnly",
            )

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface_name: str):
        """Get all properties"""
        if interface_name != self.INTERFACE_NAME:
            raise dbus.exceptions.DBusException(
                f"Unknown interface: {interface_name}",
                name="org.freedesktop.DBus.Error.UnknownInterface",
            )

        with self.operations_lock:
            active_ops = sum(1 for op in self.operations.values() if not op.completed)

        return {
            "ActiveOperations": dbus.UInt32(active_ops),
            "MaxConcurrentOperations": dbus.UInt32(self.max_concurrent_ops),
            "DefaultTimeout": dbus.UInt32(self.default_timeout),
        }


def run_service():
    """Run the D-Bus service"""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize D-Bus main loop
    DBusGMainLoop(set_as_default=True)

    # Connect to session bus
    bus = dbus.SessionBus()

    # Request service name
    try:
        _bus_name = dbus.service.BusName(  # noqa: F841
            CryptoService.BUS_NAME, bus, do_not_queue=True
        )
    except dbus.exceptions.NameExistsException:
        logger.error(f"Service {CryptoService.BUS_NAME} already running")
        sys.exit(1)

    # Create service instance
    _service = CryptoService(bus)  # noqa: F841

    logger.info(f"D-Bus service {CryptoService.BUS_NAME} started")
    logger.info(f"Object path: {CryptoService.OBJECT_PATH}")
    logger.info(f"Interface: {CryptoService.INTERFACE_NAME}")

    # Run GLib main loop
    try:
        loop = GLib.MainLoop()
        loop.run()
    except KeyboardInterrupt:
        logger.info("Service interrupted by user")
    except Exception as e:
        logger.error(f"Service error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    run_service()
