#!/usr/bin/env python3
"""
Example Python client for openssl_encrypt D-Bus service

This example demonstrates how to use the D-Bus client library
to encrypt and decrypt files.
"""

import sys
import tempfile
from pathlib import Path

# Add parent directory to path for import
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from openssl_encrypt.modules.dbus_client import CryptoClient


def progress_callback(operation_id: str, percent: float, message: str):
    """Progress callback for encryption/decryption operations"""
    print(f"  [{operation_id[:8]}...] {percent:5.1f}% - {message}")


def completion_callback(operation_id: str, success: bool, error_msg: str):
    """Completion callback for encryption/decryption operations"""
    if success:
        print(f"  ✓ Operation {operation_id[:8]}... completed successfully")
    else:
        print(f"  ✗ Operation {operation_id[:8]}... failed: {error_msg}")


def main():
    print("openssl_encrypt D-Bus Client Example")
    print("=" * 60)

    # Create client
    try:
        client = CryptoClient()
        print("✓ Connected to D-Bus service")
    except ConnectionError as e:
        print(f"✗ Failed to connect to D-Bus service: {e}")
        print("\nMake sure the service is running:")
        print("  python3 -m openssl_encrypt.modules.dbus_service")
        return 1

    # Get service information
    print("\n1. Service Information")
    print("-" * 60)
    version = client.get_version()
    print(f"Version: {version}")

    algorithms = client.get_supported_algorithms()
    print(f"Supported algorithms ({len(algorithms)}):")
    for algo in algorithms[:10]:
        print(f"  - {algo}")
    if len(algorithms) > 10:
        print(f"  ... and {len(algorithms) - 10} more")

    # Validate passwords
    print("\n2. Password Validation")
    print("-" * 60)
    test_passwords = ["weak", "StrongPass123!", "short"]
    for pwd in test_passwords:
        valid, issues = client.validate_password(pwd)
        status = "✓" if valid else "✗"
        print(f"{status} '{pwd}': {' / '.join(issues) if issues else 'Valid'}")

    # Get service properties
    print("\n3. Service Properties")
    print("-" * 60)
    active_ops = client.get_active_operations()
    max_ops = client.get_max_concurrent_operations()
    timeout = client.get_default_timeout()
    print(f"Active operations: {active_ops}")
    print(f"Max concurrent operations: {max_ops}")
    print(f"Default timeout: {timeout} seconds")

    # File encryption example
    print("\n4. File Encryption Example")
    print("-" * 60)

    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        test_file = f.name
        f.write("This is a test file for encryption.\n")
        f.write("It contains some sample data.\n" * 10)

    encrypted_file = test_file + ".enc"
    decrypted_file = test_file + ".dec"

    print(f"Test file: {test_file}")
    print(f"Encrypted file: {encrypted_file}")
    print(f"Decrypted file: {decrypted_file}")

    # Encrypt the file
    print("\nEncrypting file...")
    success, error, op_id = client.encrypt_file(
        input_path=test_file,
        output_path=encrypted_file,
        password="TestPassword123!",
        algorithm="fernet",
        options={
            "sha512_rounds": 10000,
            "enable_hkdf": True,
        },
        progress_callback=progress_callback,
        completion_callback=completion_callback,
    )

    if not success:
        print(f"✗ Encryption failed: {error}")
        return 1

    print(f"✓ Encryption initiated: {op_id}")

    # Note: In a real application, you would wait for the operation to complete
    # by listening to signals or polling the operation status
    import time

    time.sleep(2)  # Give it time to complete

    # Decrypt the file
    print("\nDecrypting file...")
    success, error, op_id = client.decrypt_file(
        input_path=encrypted_file,
        output_path=decrypted_file,
        password="TestPassword123!",
        progress_callback=progress_callback,
        completion_callback=completion_callback,
    )

    if not success:
        print(f"✗ Decryption failed: {error}")
        return 1

    print(f"✓ Decryption initiated: {op_id}")
    time.sleep(2)  # Give it time to complete

    # Verify decrypted content
    try:
        with open(test_file, "r") as f1, open(decrypted_file, "r") as f2:
            original = f1.read()
            decrypted = f2.read()
            if original == decrypted:
                print("✓ Decrypted content matches original")
            else:
                print("✗ Decrypted content does not match original")
    except FileNotFoundError:
        print("✗ Decrypted file not found (operation may still be running)")

    # PQC key generation example
    print("\n5. Post-Quantum Key Generation Example")
    print("-" * 60)

    keystore_file = tempfile.mktemp(suffix=".pqc")
    print(f"Keystore file: {keystore_file}")

    print("\nGenerating ML-KEM-768 key...")
    success, key_id, error = client.generate_pqc_key(
        algorithm="ml-kem-768",
        keystore_path=keystore_file,
        keystore_password="KeystorePassword123!",
        key_name="Example Key",
    )

    if success:
        print(f"✓ Key generated: {key_id}")
    else:
        print(f"✗ Key generation failed: {error}")
        if "Not implemented" in error:
            print("  (Keystore integration pending)")

    # Cleanup
    print("\n6. Cleanup")
    print("-" * 60)
    print("Cleaning up temporary files...")
    for f in [test_file, encrypted_file, decrypted_file, keystore_file]:
        try:
            Path(f).unlink()
            print(f"  ✓ Deleted {f}")
        except FileNotFoundError:
            pass

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
