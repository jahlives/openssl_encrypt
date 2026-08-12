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

import argparse
import logging
import os
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
from .dbus_kdf_config import build_encrypt_hash_config, config_provides_key_stretching

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
    "/root",  # Root user home (allowed in system-bus mode, see __init__)
]

# H7: polkit action ids - must match openssl_encrypt/dbus/ch.rmrf.openssl_encrypt.policy
POLKIT_ACTION_ENCRYPT = "ch.rmrf.openssl_encrypt.encrypt"
POLKIT_ACTION_DECRYPT = "ch.rmrf.openssl_encrypt.decrypt"
POLKIT_ACTION_SHRED = "ch.rmrf.openssl_encrypt.shred"
POLKIT_ACTION_KEYSTORE = "ch.rmrf.openssl_encrypt.keystore"
POLKIT_ACTION_GENERATE_KEY = "ch.rmrf.openssl_encrypt.generate_key"
POLKIT_ACTION_DELETE_KEY = "ch.rmrf.openssl_encrypt.delete_key"
# gitlab#250 (F12): mutating a service property via the D-Bus Properties.Set
# method is an admin/configuration action and must be authorized like the rest.
POLKIT_ACTION_CONFIGURE = "ch.rmrf.openssl_encrypt.configure"

# gitlab#250 (F13): bounds for the writable properties. MaxConcurrentOperations
# must stay >= 1 (0/negative makes the concurrency gate refuse every operation)
# and below a sane ceiling (a huge value removes the limit); DefaultTimeout must
# stay a positive, bounded number of seconds.
_MAX_CONCURRENT_OPS_CEILING = 64
_MIN_DEFAULT_TIMEOUT = 1
_MAX_DEFAULT_TIMEOUT = 86400  # 24 h

# CheckAuthorizationFlags.AllowUserInteraction - lets polkit prompt the
# caller's authentication agent instead of silently denying
_POLKIT_ALLOW_USER_INTERACTION = 1


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

    def __init__(self, bus: dbus.Bus, max_concurrent_ops: int = 5, system_bus: bool = False):
        """
        Initialize the D-Bus service

        Args:
            bus: D-Bus connection
            max_concurrent_ops: Maximum number of concurrent operations
            system_bus: True when running on the system bus. Every method is
                then gated by polkit (admin authorization) and the path
                policy is widened to system paths - that mode exists so a
                non-root admin can encrypt files only root has access to.
                On the session bus (default) only same-UID callers are
                accepted and paths stay restricted to home/tmp.
        """
        super().__init__(bus, self.OBJECT_PATH)

        self.bus = bus
        self.system_bus = system_bus
        self.operations: Dict[str, CryptoOperation] = {}
        self.operations_lock = threading.Lock()
        self.max_concurrent_ops = max_concurrent_ops
        self.default_timeout = 300  # 5 minutes

        if system_bus:
            # The purpose of system-bus mode is reaching root-only files, so
            # the whitelist is the whole filesystem - but the explicitly
            # blocked critical paths stay blocked (encrypting /etc/shadow or
            # /boot bricks the system; a real root shell exists for that),
            # except /root which is precisely where root-only files live.
            self._allowed_base_directories = [Path("/")]
            self._blocked_paths = [p for p in BLOCKED_PATHS if p != "/root"]
        else:
            self._allowed_base_directories = list(ALLOWED_BASE_DIRECTORIES)
            self._blocked_paths = list(BLOCKED_PATHS)

        logger.info(
            f"CryptoService initialized on {self.BUS_NAME} "
            f"({'system' if system_bus else 'session'} bus mode)"
        )

    # ========================================
    # Helper Methods
    # ========================================

    def _authorize_caller(self, sender: Optional[str], action_id: str) -> Tuple[bool, str]:
        """
        Authorize the D-Bus caller for an operation (H7) - fail closed.

        Session bus: the caller's UID must equal the service's UID. The
        session bus is per-user anyway; this is defense-in-depth against
        leaked/forwarded bus sockets.

        System bus: the caller is checked against polkit with the given
        action id (the .policy defaults require admin authentication), with
        user interaction allowed so the caller's polkit agent can prompt.

        Args:
            sender: Unique D-Bus name of the caller (from sender_keyword)
            action_id: polkit action id for the requested operation

        Returns:
            (authorized, error_message)
        """

        def _deny(reason: str) -> Tuple[bool, str]:
            logger.warning(f"D-Bus authorization denied for {sender!r} ({action_id}): {reason}")
            if security_logger:
                security_logger.log_event(
                    "dbus_authorization_denied",
                    "critical",
                    {
                        "sender": str(sender),
                        "action_id": action_id,
                        "reason": reason,
                        "bus": "system" if self.system_bus else "session",
                        "service": "dbus",
                    },
                )
            return False, reason

        if not sender:
            return _deny("caller identity unavailable")

        try:
            caller_uid = int(self.bus.get_unix_user(sender))
        except Exception as e:
            return _deny(f"could not resolve caller UID: {e}")

        if not self.system_bus:
            if caller_uid == os.getuid():
                return True, ""
            return _deny(f"caller UID {caller_uid} does not match service UID")

        # System bus: ask polkit (fail closed on any error)
        try:
            authority_obj = self.bus.get_object(
                "org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority"
            )
            authority = dbus.Interface(authority_obj, "org.freedesktop.PolicyKit1.Authority")
            subject = ("system-bus-name", {"name": dbus.String(sender)})
            is_authorized, _is_challenge, _details = authority.CheckAuthorization(
                subject,
                action_id,
                {},
                dbus.UInt32(_POLKIT_ALLOW_USER_INTERACTION),
                "",
            )
        except Exception as e:
            return _deny(f"polkit authorization check failed: {e}")

        if bool(is_authorized):
            return True, ""
        return _deny("not authorized by polkit")

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
        for allowed_dir in self._allowed_base_directories:
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
        for blocked in self._blocked_paths:
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

        # Existence/type checks - stat() can raise (e.g. PermissionError on
        # an unreadable parent directory); treat that as a clean denial
        # instead of letting the exception escape to the D-Bus layer
        try:
            path_exists = abs_path.exists()
            is_directory = path_exists and abs_path.is_dir()
        except OSError as e:
            return False, f"Cannot access path: {e}"

        # Check existence if required
        if must_exist and not path_exists:
            return False, "Path does not exist"

        # Check if it's a file (not directory)
        if is_directory:
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
        sender_keyword="sender",
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
        sender=None,
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

        authorized, auth_error = self._authorize_caller(sender, POLKIT_ACTION_ENCRYPT)
        if not authorized:
            reply_handler((False, f"Access denied: {auth_error}", ""))
            return

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

                # Build the hash configuration in the structure crypt_core
                # actually consumes (gitlab#228, security F1). The previous
                # hand-built dict used key names crypt_core never reads
                # (sha512_iterations, argon2_time_cost, enable_hkdf, ...), so no
                # KDF/hash was ever enabled and the non-empty dict also defeated
                # encrypt_file's STANDARD-template default -- collapsing every
                # D-Bus-encrypted file's key to a single unstretched SHA-256.
                hash_config = build_encrypt_hash_config(parsed_options)

                # Fail closed: never derive a key without password stretching.
                # A client cannot, through any option combination, coax this
                # path into an unstretched single-hash key (CWE-916).
                if not config_provides_key_stretching(hash_config):
                    operation.complete(
                        False, "Refusing to encrypt: no key-stretching KDF configured"
                    )
                    reply_handler(
                        (
                            False,
                            "Refusing to encrypt: the requested options enable no "
                            "key-stretching KDF (Argon2/scrypt/balloon) and no hash "
                            "rounds",
                            operation_id,
                        )
                    )
                    return

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
                    hash_config=hash_config,
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
        sender_keyword="sender",
    )
    def DecryptFile(
        self,
        input_path: str,
        output_path: str,
        password: str,
        reply_handler,
        error_handler,
        sender=None,
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

        authorized, auth_error = self._authorize_caller(sender, POLKIT_ACTION_DECRYPT)
        if not authorized:
            reply_handler((False, f"Access denied: {auth_error}", ""))
            return

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

    @dbus.service.method(
        INTERFACE_NAME, in_signature="ayssa{sv}", out_signature="bays", sender_keyword="sender"
    )
    def EncryptData(
        self, data: bytes, password: str, algorithm: str, options: Dict[str, Any], sender=None
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

        authorized, auth_error = self._authorize_caller(sender, POLKIT_ACTION_ENCRYPT)
        if not authorized:
            return (False, b"", f"Access denied: {auth_error}")

        # TODO: Implement data encryption
        return (False, b"", "Not implemented yet")

    @dbus.service.method(
        INTERFACE_NAME, in_signature="ays", out_signature="bays", sender_keyword="sender"
    )
    def DecryptData(
        self, encrypted_data: bytes, password: str, sender=None
    ) -> Tuple[bool, bytes, str]:
        """
        Decrypt binary data directly (no file I/O)

        Args:
            encrypted_data: Encrypted binary data
            password: Decryption password

        Returns:
            (success, data, error_msg)
        """
        logger.info(f"DecryptData called with {len(encrypted_data)} bytes")

        authorized, auth_error = self._authorize_caller(sender, POLKIT_ACTION_DECRYPT)
        if not authorized:
            return (False, b"", f"Access denied: {auth_error}")

        # TODO: Implement data decryption
        return (False, b"", "Not implemented yet")

    # ========================================
    # D-Bus Methods - Secure File Operations
    # ========================================

    @dbus.service.method(
        INTERFACE_NAME, in_signature="si", out_signature="bs", sender_keyword="sender"
    )
    def SecureShredFile(self, file_path: str, passes: int, sender=None) -> Tuple[bool, str]:
        """
        Securely delete a file

        Args:
            file_path: Path to file to shred
            passes: Number of overwrite passes

        Returns:
            (success, error_msg)
        """
        logger.info(f"SecureShredFile called: {file_path}, passes={passes}")

        authorized, auth_error = self._authorize_caller(sender, POLKIT_ACTION_SHRED)
        if not authorized:
            return (False, f"Access denied: {auth_error}")

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

    @dbus.service.method(
        INTERFACE_NAME, in_signature="ssss", out_signature="bss", sender_keyword="sender"
    )
    def GeneratePQCKey(
        self, algorithm: str, keystore_path: str, keystore_password: str, key_name: str, sender=None
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

        authorized, auth_error = self._authorize_caller(sender, POLKIT_ACTION_GENERATE_KEY)
        if not authorized:
            return (False, "", f"Access denied: {auth_error}")

        # Validate keystore path
        valid, error = self._validate_file_path(keystore_path, must_exist=False)
        if not valid:
            return (False, "", f"Invalid keystore path: {error}")

        # TODO: Integrate with keystore_utils
        return (False, "", "Not implemented yet")

    @dbus.service.method(
        INTERFACE_NAME, in_signature="ss", out_signature="baa{ss}s", sender_keyword="sender"
    )
    def ListPQCKeys(
        self, keystore_path: str, keystore_password: str, sender=None
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

        authorized, auth_error = self._authorize_caller(sender, POLKIT_ACTION_KEYSTORE)
        if not authorized:
            return (False, [], f"Access denied: {auth_error}")

        # Validate keystore path
        valid, error = self._validate_file_path(keystore_path, must_exist=True)
        if not valid:
            return (False, [], f"Invalid keystore path: {error}")

        # TODO: Integrate with keystore_utils
        return (False, [], "Not implemented yet")

    @dbus.service.method(
        INTERFACE_NAME, in_signature="sss", out_signature="bs", sender_keyword="sender"
    )
    def DeletePQCKey(
        self, keystore_path: str, keystore_password: str, key_id: str, sender=None
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

        authorized, auth_error = self._authorize_caller(sender, POLKIT_ACTION_DELETE_KEY)
        if not authorized:
            return (False, f"Access denied: {auth_error}")

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

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature="ssv", sender_keyword="sender")
    def Set(self, interface_name: str, property_name: str, value, sender=None):
        """Set property value.

        gitlab#250 (F12): mutating a property is authorized like every other
        operation (polkit ``configure`` action / same-UID on the session bus),
        failing closed. gitlab#250 (F13): the value is range-checked so a caller
        cannot wedge the concurrency gate (0/negative) or remove the limit
        (huge), nor set a degenerate timeout.
        """
        if interface_name != self.INTERFACE_NAME:
            raise dbus.exceptions.DBusException(
                f"Unknown interface: {interface_name}",
                name="org.freedesktop.DBus.Error.UnknownInterface",
            )

        authorized, auth_error = self._authorize_caller(sender, POLKIT_ACTION_CONFIGURE)
        if not authorized:
            raise dbus.exceptions.DBusException(
                f"Access denied: {auth_error}",
                name="org.freedesktop.DBus.Error.AccessDenied",
            )

        try:
            int_value = int(value)
        except (TypeError, ValueError, OverflowError):
            # OverflowError covers a variant double of +/-inf; nan raises
            # ValueError. Either way this is pre-mutation, so nothing changes.
            raise dbus.exceptions.DBusException(
                f"Property {property_name} requires an integer value",
                name="org.freedesktop.DBus.Error.InvalidArgs",
            )

        if property_name == "MaxConcurrentOperations":
            if not (1 <= int_value <= _MAX_CONCURRENT_OPS_CEILING):
                raise dbus.exceptions.DBusException(
                    f"MaxConcurrentOperations must be between 1 and "
                    f"{_MAX_CONCURRENT_OPS_CEILING}",
                    name="org.freedesktop.DBus.Error.InvalidArgs",
                )
            self.max_concurrent_ops = int_value
        elif property_name == "DefaultTimeout":
            if not (_MIN_DEFAULT_TIMEOUT <= int_value <= _MAX_DEFAULT_TIMEOUT):
                raise dbus.exceptions.DBusException(
                    f"DefaultTimeout must be between {_MIN_DEFAULT_TIMEOUT} and "
                    f"{_MAX_DEFAULT_TIMEOUT} seconds",
                    name="org.freedesktop.DBus.Error.InvalidArgs",
                )
            self.default_timeout = int_value
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


def run_service(system_bus: bool = False):
    """Run the D-Bus service

    Args:
        system_bus: Bind the system bus instead of the session bus. In this
            mode every method call is authorized through polkit (admin
            authentication per the shipped .policy) so that a non-root admin
            can operate on files only root has access to.
    """
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize D-Bus main loop
    DBusGMainLoop(set_as_default=True)

    # Connect to the requested bus
    bus = dbus.SystemBus() if system_bus else dbus.SessionBus()

    # Request service name
    try:
        _bus_name = dbus.service.BusName(  # noqa: F841
            CryptoService.BUS_NAME, bus, do_not_queue=True
        )
    except dbus.exceptions.NameExistsException:
        logger.error(f"Service {CryptoService.BUS_NAME} already running")
        sys.exit(1)

    # Create service instance
    _service = CryptoService(bus, system_bus=system_bus)  # noqa: F841

    logger.info(
        f"D-Bus service {CryptoService.BUS_NAME} started "
        f"({'system' if system_bus else 'session'} bus)"
    )
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
    parser = argparse.ArgumentParser(description="openssl_encrypt D-Bus service")
    parser.add_argument(
        "--system",
        action="store_true",
        help=(
            "Bind the system bus (root service, polkit-authorized) instead "
            "of the per-user session bus"
        ),
    )
    args = parser.parse_args()
    run_service(system_bus=args.system)
