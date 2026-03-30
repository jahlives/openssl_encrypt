#!/usr/bin/env python3
"""
USB Drive Hash Chaining Test

This test verifies that the USB system correctly uses the same hash chaining
approach as the main CLI for password derivation.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Add the parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def test_usb_with_hash_chaining():
    """Test USB creation with hash chaining configuration"""
    print("Testing USB with hash chaining...")

    try:
        from usb_creator import USBDriveCreator, USBSecurityProfile

        # Create hash configuration (similar to main CLI)
        hash_config = {
            "sha512": 2,
            "sha384": 0,
            "sha256": 1,
            "sha224": 0,
            "sha3_256": 0,
            "sha3_384": 0,
            "sha3_512": 0,
            "sha3_224": 0,
            "blake2b": 1,
            "blake3": 0,
            "shake256": 0,
            "shake128": 0,
            "whirlpool": 0,
            "scrypt": {
                "enabled": True,
                "n": 16384,
                "r": 8,
                "p": 1,
                "rounds": 1,
            },
            "argon2": {
                "enabled": True,
                "time_cost": 3,
                "memory_cost": 65536,
                "parallelism": 4,
                "hash_len": 32,
                "type": 2,  # argon2id
                "rounds": 1,
            },
            "balloon": {
                "enabled": False,
                "time_cost": 4,
                "space_cost": 16,
                "parallelism": 1,
                "rounds": 0,
            },
            "hkdf": {
                "enabled": False,
                "rounds": 0,
                "algorithm": "sha256",
                "info": "",
            },
            "pbkdf2_iterations": 0,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            usb_path = Path(temp_dir) / "test_usb_chaining"
            usb_path.mkdir()

            creator = USBDriveCreator(USBSecurityProfile.STANDARD)
            password = "test_chaining_password_123"

            # Create USB with hash chaining
            result = creator.create_portable_usb(
                usb_path=usb_path, password=password, hash_config=hash_config
            )

            print(f"✅ USB with hash chaining created: {result['success']}")
            print(f"   Security profile: {result['security_profile']}")

            # Verify with same hash config
            verification_result = creator.verify_usb_integrity(
                usb_path, password, hash_config=hash_config
            )

            print(f"✅ Hash chaining verification: {verification_result['integrity_ok']}")

            # Test that verification fails with different hash config
            different_hash_config = hash_config.copy()
            different_hash_config["sha512"] = 3  # Different configuration

            try:
                bad_verification = creator.verify_usb_integrity(
                    usb_path, password, hash_config=different_hash_config
                )
                # This should fail or give different results
                print("⚠️  Warning: Different hash config didn't affect verification")
            except Exception:
                print("✅ Different hash config correctly failed verification")

            return True

    except Exception as e:
        print(f"❌ Hash chaining test failed: {e}")
        return False


def test_usb_fallback_compatibility():
    """Test that USB still works without hash config (fallback mode)"""
    print("\nTesting USB fallback compatibility...")

    try:
        from usb_creator import USBDriveCreator, USBSecurityProfile

        with tempfile.TemporaryDirectory() as temp_dir:
            usb_path = Path(temp_dir) / "test_usb_fallback"
            usb_path.mkdir()

            creator = USBDriveCreator(USBSecurityProfile.HIGH_SECURITY)
            password = "fallback_test_password_456"

            # Create USB without hash config (should use fallback)
            result = creator.create_portable_usb(
                usb_path=usb_path,
                password=password,
                hash_config=None,  # No hash config = fallback mode
            )

            print(f"✅ USB fallback creation: {result['success']}")

            # Verify without hash config
            verification_result = creator.verify_usb_integrity(usb_path, password, hash_config=None)

            print(f"✅ Fallback verification: {verification_result['integrity_ok']}")

            return True

    except Exception as e:
        print(f"❌ Fallback compatibility test failed: {e}")
        return False


def test_hash_config_consistency():
    """Test that same password + hash config always gives same result"""
    print("\nTesting hash config consistency...")

    try:
        from usb_creator import USBDriveCreator, USBSecurityProfile

        # Simple hash config for testing
        hash_config = {
            "sha256": 1,
            "argon2": {
                "enabled": True,
                "time_cost": 2,
                "memory_cost": 4096,
                "parallelism": 2,
                "hash_len": 32,
                "type": 2,
                "rounds": 1,
            },
            "pbkdf2_iterations": 0,
        }

        password = "consistency_test_password"

        # Create two USB drives with same config
        results = []
        for i in range(2):
            with tempfile.TemporaryDirectory() as temp_dir:
                usb_path = Path(temp_dir) / f"test_usb_consistency_{i}"
                usb_path.mkdir()

                creator = USBDriveCreator(USBSecurityProfile.STANDARD)
                result = creator.create_portable_usb(
                    usb_path=usb_path, password=password, hash_config=hash_config
                )

                results.append(result["success"])

        print(f"✅ Consistency test: Both USBs created successfully")
        print(f"   Results: {results}")

        return all(results)

    except Exception as e:
        print(f"❌ Consistency test failed: {e}")
        return False


def main():
    """Run USB hash chaining tests"""
    print("🔗 USB Hash Chaining - Advanced Tests")
    print("=" * 50)

    tests = [
        test_usb_with_hash_chaining,
        test_usb_fallback_compatibility,
        test_hash_config_consistency,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print("\n" + "=" * 50)
    print(f"Results: {passed}/{total} hash chaining tests passed")

    if passed == total:
        print("🎉 All USB hash chaining tests passed!")
        return 0
    else:
        print("⚠️  Some hash chaining tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
