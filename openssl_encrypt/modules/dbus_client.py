#!/usr/bin/env python3
"""
D-Bus Client Library for openssl_encrypt

This module provides a Python client interface for the openssl_encrypt D-Bus service,
making it easy to use encryption operations from Python applications.

Example usage:
    from openssl_encrypt.modules.dbus_client import CryptoClient

    client = CryptoClient()

    # Encrypt a file
    success, error, op_id = client.encrypt_file(
        "/path/to/input.txt",
        "/path/to/output.enc",
        "my_secure_password",
        "ml-kem-768-hybrid"
    )

    # Decrypt a file
    success, error, op_id = client.decrypt_file(
        "/path/to/output.enc",
        "/path/to/decrypted.txt",
        "my_secure_password"
    )
"""

import logging
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import dbus
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
except ImportError as e:
    print(f"Error: D-Bus dependencies not installed: {e}", file=sys.stderr)
    print("Install with: pip install dbus-python PyGObject", file=sys.stderr)
    sys.exit(1)

logger = logging.getLogger(__name__)


class CryptoClient:
    """
    Client for openssl_encrypt D-Bus service

    This class provides a Pythonic interface to the D-Bus service,
    handling connection management and method calls.
    """

    # Service configuration
    BUS_NAME = "ch.rmrf.openssl_encrypt"
    OBJECT_PATH = "/ch/rmrf/openssl_encrypt/CryptoService"
    INTERFACE_NAME = "ch.rmrf.openssl_encrypt.Crypto"

    def __init__(self, use_system_bus: bool = False, timeout: int = 300):
        """
        Initialize D-Bus client

        Args:
            use_system_bus: If True, connect to system bus (default: session bus)
            timeout: Default timeout for operations in seconds
        """
        self.timeout = timeout
        self.progress_callbacks: Dict[str, Callable] = {}
        self.completion_callbacks: Dict[str, Callable] = {}

        # Initialize D-Bus main loop
        DBusGMainLoop(set_as_default=True)

        # Connect to bus
        try:
            if use_system_bus:
                self.bus = dbus.SystemBus()
            else:
                self.bus = dbus.SessionBus()

            # Get proxy object
            self.proxy = self.bus.get_object(self.BUS_NAME, self.OBJECT_PATH)
            self.interface = dbus.Interface(self.proxy, self.INTERFACE_NAME)
            self.properties = dbus.Interface(self.proxy, dbus.PROPERTIES_IFACE)

            # Connect to signals
            self.bus.add_signal_receiver(
                self._on_progress,
                signal_name="Progress",
                dbus_interface=self.INTERFACE_NAME,
                bus_name=self.BUS_NAME,
                path=self.OBJECT_PATH,
            )

            self.bus.add_signal_receiver(
                self._on_operation_complete,
                signal_name="OperationComplete",
                dbus_interface=self.INTERFACE_NAME,
                bus_name=self.BUS_NAME,
                path=self.OBJECT_PATH,
            )

            logger.info(f"Connected to D-Bus service {self.BUS_NAME}")

        except dbus.exceptions.DBusException as e:
            raise ConnectionError(f"Failed to connect to D-Bus service: {e}")

    # ========================================
    # Signal Handlers
    # ========================================

    def _on_progress(self, operation_id: str, percent: float, message: str):
        """Handle Progress signal"""
        logger.debug(f"Progress: {operation_id} - {percent}% - {message}")
        if operation_id in self.progress_callbacks:
            try:
                self.progress_callbacks[operation_id](operation_id, percent, message)
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")

    def _on_operation_complete(self, operation_id: str, success: bool, error_msg: str):
        """Handle OperationComplete signal"""
        logger.debug(f"Operation complete: {operation_id} - success={success}")
        if operation_id in self.completion_callbacks:
            try:
                self.completion_callbacks[operation_id](operation_id, success, error_msg)
            except Exception as e:
                logger.error(f"Error in completion callback: {e}")

    # ========================================
    # File Operations
    # ========================================

    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        password: str,
        algorithm: str = "fernet",
        options: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable] = None,
        completion_callback: Optional[Callable] = None,
    ) -> Tuple[bool, str, str]:
        """
        Encrypt a file

        Args:
            input_path: Path to input file
            output_path: Path to output encrypted file
            password: Encryption password
            algorithm: Encryption algorithm (default: "fernet")
            options: Optional encryption parameters
            progress_callback: Callback for progress updates (operation_id, percent, message)
            completion_callback: Callback when operation completes (operation_id, success, error_msg)

        Returns:
            (success, error_msg, operation_id)

        Example:
            def on_progress(op_id, percent, message):
                print(f"Progress: {percent}% - {message}")

            def on_complete(op_id, success, error):
                print(f"Complete: success={success}")

            success, error, op_id = client.encrypt_file(
                "/path/to/file.txt",
                "/path/to/file.enc",
                "password",
                "ml-kem-768-hybrid",
                {"balloon_rounds": 5},
                on_progress,
                on_complete
            )
        """
        if options is None:
            options = {}

        try:
            # Call D-Bus method
            success, error_msg, operation_id = self.interface.EncryptFile(
                input_path,
                output_path,
                password,
                algorithm,
                dbus.Dictionary(options, signature="sv"),
                timeout=self.timeout,
            )

            # Register callbacks
            if progress_callback and operation_id:
                self.progress_callbacks[operation_id] = progress_callback
            if completion_callback and operation_id:
                self.completion_callbacks[operation_id] = completion_callback

            return (bool(success), str(error_msg), str(operation_id))

        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in encrypt_file: {e}")
            return (False, str(e), "")

    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        password: str,
        progress_callback: Optional[Callable] = None,
        completion_callback: Optional[Callable] = None,
    ) -> Tuple[bool, str, str]:
        """
        Decrypt a file

        Args:
            input_path: Path to encrypted file
            output_path: Path to output decrypted file
            password: Decryption password
            progress_callback: Callback for progress updates
            completion_callback: Callback when operation completes

        Returns:
            (success, error_msg, operation_id)
        """
        try:
            # Call D-Bus method
            success, error_msg, operation_id = self.interface.DecryptFile(
                input_path, output_path, password, timeout=self.timeout
            )

            # Register callbacks
            if progress_callback and operation_id:
                self.progress_callbacks[operation_id] = progress_callback
            if completion_callback and operation_id:
                self.completion_callbacks[operation_id] = completion_callback

            return (bool(success), str(error_msg), str(operation_id))

        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in decrypt_file: {e}")
            return (False, str(e), "")

    def encrypt_data(
        self,
        data: bytes,
        password: str,
        algorithm: str = "fernet",
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, bytes, str]:
        """
        Encrypt binary data directly

        Args:
            data: Binary data to encrypt
            password: Encryption password
            algorithm: Encryption algorithm
            options: Optional parameters

        Returns:
            (success, encrypted_data, error_msg)
        """
        if options is None:
            options = {}

        try:
            success, encrypted_data, error_msg = self.interface.EncryptData(
                dbus.ByteArray(data),
                password,
                algorithm,
                dbus.Dictionary(options, signature="sv"),
                timeout=self.timeout,
            )

            return (bool(success), bytes(encrypted_data), str(error_msg))

        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in encrypt_data: {e}")
            return (False, b"", str(e))

    def decrypt_data(self, encrypted_data: bytes, password: str) -> Tuple[bool, bytes, str]:
        """
        Decrypt binary data directly

        Args:
            encrypted_data: Encrypted binary data
            password: Decryption password

        Returns:
            (success, data, error_msg)
        """
        try:
            success, data, error_msg = self.interface.DecryptData(
                dbus.ByteArray(encrypted_data), password, timeout=self.timeout
            )

            return (bool(success), bytes(data), str(error_msg))

        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in decrypt_data: {e}")
            return (False, b"", str(e))

    # ========================================
    # Secure File Operations
    # ========================================

    def secure_shred_file(self, file_path: str, passes: int = 3) -> Tuple[bool, str]:
        """
        Securely delete a file

        Args:
            file_path: Path to file to shred
            passes: Number of overwrite passes (default: 3)

        Returns:
            (success, error_msg)
        """
        try:
            success, error_msg = self.interface.SecureShredFile(
                file_path, passes, timeout=self.timeout
            )
            return (bool(success), str(error_msg))

        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in secure_shred_file: {e}")
            return (False, str(e))

    # ========================================
    # Keystore Operations
    # ========================================

    def generate_pqc_key(
        self,
        algorithm: str,
        keystore_path: str,
        keystore_password: str,
        key_name: str,
    ) -> Tuple[bool, str, str]:
        """
        Generate a post-quantum cryptographic key pair

        Args:
            algorithm: PQC algorithm (e.g., "ml-kem-768", "kyber-1024")
            keystore_path: Path to keystore file
            keystore_password: Keystore password
            key_name: Human-readable key name

        Returns:
            (success, key_id, error_msg)
        """
        try:
            success, key_id, error_msg = self.interface.GeneratePQCKey(
                algorithm,
                keystore_path,
                keystore_password,
                key_name,
                timeout=self.timeout,
            )
            return (bool(success), str(key_id), str(error_msg))

        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in generate_pqc_key: {e}")
            return (False, "", str(e))

    def list_pqc_keys(
        self, keystore_path: str, keystore_password: str
    ) -> Tuple[bool, List[Dict[str, str]], str]:
        """
        List all keys in a keystore

        Args:
            keystore_path: Path to keystore file
            keystore_password: Keystore password

        Returns:
            (success, keys, error_msg)
            keys: List of dictionaries with key_id, key_name, algorithm, created
        """
        try:
            success, keys, error_msg = self.interface.ListPQCKeys(
                keystore_path, keystore_password, timeout=self.timeout
            )

            # Convert D-Bus array to Python list of dicts
            keys_list = [dict(key) for key in keys]

            return (bool(success), keys_list, str(error_msg))

        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in list_pqc_keys: {e}")
            return (False, [], str(e))

    def delete_pqc_key(
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
        try:
            success, error_msg = self.interface.DeletePQCKey(
                keystore_path, keystore_password, key_id, timeout=self.timeout
            )
            return (bool(success), str(error_msg))

        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in delete_pqc_key: {e}")
            return (False, str(e))

    # ========================================
    # Information Queries
    # ========================================

    def get_supported_algorithms(self) -> List[str]:
        """
        Get list of supported encryption algorithms

        Returns:
            List of algorithm names
        """
        try:
            algorithms = self.interface.GetSupportedAlgorithms()
            return list(algorithms)
        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in get_supported_algorithms: {e}")
            return []

    def get_version(self) -> str:
        """
        Get openssl_encrypt version

        Returns:
            Version string
        """
        try:
            version = self.interface.GetVersion()
            return str(version)
        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in get_version: {e}")
            return ""

    def validate_password(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password against security policy

        Args:
            password: Password to validate

        Returns:
            (valid, issues)
            issues: List of validation issue messages
        """
        try:
            valid, issues = self.interface.ValidatePassword(password)
            return (bool(valid), list(issues))
        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error in validate_password: {e}")
            return (False, [str(e)])

    # ========================================
    # Properties
    # ========================================

    def get_active_operations(self) -> int:
        """
        Get number of active operations

        Returns:
            Number of active operations
        """
        try:
            value = self.properties.Get(self.INTERFACE_NAME, "ActiveOperations")
            return int(value)
        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error getting ActiveOperations: {e}")
            return 0

    def get_max_concurrent_operations(self) -> int:
        """
        Get maximum number of concurrent operations

        Returns:
            Maximum concurrent operations
        """
        try:
            value = self.properties.Get(self.INTERFACE_NAME, "MaxConcurrentOperations")
            return int(value)
        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error getting MaxConcurrentOperations: {e}")
            return 0

    def set_max_concurrent_operations(self, value: int):
        """
        Set maximum number of concurrent operations

        Args:
            value: Maximum concurrent operations
        """
        try:
            self.properties.Set(self.INTERFACE_NAME, "MaxConcurrentOperations", dbus.UInt32(value))
        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error setting MaxConcurrentOperations: {e}")

    def get_default_timeout(self) -> int:
        """
        Get default operation timeout in seconds

        Returns:
            Timeout in seconds
        """
        try:
            value = self.properties.Get(self.INTERFACE_NAME, "DefaultTimeout")
            return int(value)
        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error getting DefaultTimeout: {e}")
            return 0

    def set_default_timeout(self, value: int):
        """
        Set default operation timeout in seconds

        Args:
            value: Timeout in seconds
        """
        try:
            self.properties.Set(self.INTERFACE_NAME, "DefaultTimeout", dbus.UInt32(value))
        except dbus.exceptions.DBusException as e:
            logger.error(f"D-Bus error setting DefaultTimeout: {e}")


def main():
    """Example usage of the D-Bus client"""
    import tempfile

    # Set up logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Create client
    client = CryptoClient()

    # Get version
    version = client.get_version()
    print(f"openssl_encrypt version: {version}")

    # Get supported algorithms
    algorithms = client.get_supported_algorithms()
    print(f"\nSupported algorithms: {', '.join(algorithms[:5])}...")

    # Validate password
    valid, issues = client.validate_password("weak")
    print(f"\nPassword 'weak' valid: {valid}")
    if issues:
        print(f"Issues: {', '.join(issues)}")

    # Example encryption (would need actual files)
    print("\nExample usage:")
    print(
        """
    # Define progress callback
    def on_progress(op_id, percent, message):
        print(f"Progress: {percent:.1f}% - {message}")

    # Encrypt a file
    success, error, op_id = client.encrypt_file(
        "/path/to/input.txt",
        "/path/to/output.enc",
        "secure_password_123",
        "ml-kem-768-hybrid",
        {"balloon_rounds": 5},
        progress_callback=on_progress
    )

    if success:
        print(f"Encryption started: {op_id}")
    else:
        print(f"Encryption failed: {error}")
    """
    )


if __name__ == "__main__":
    main()
