#!/usr/bin/env python3
"""
Basic QR Code Key Distribution Test

This test verifies the basic functionality of QR code key distribution
without requiring external dependencies.
"""

import base64
import hashlib
import json
import os
import sys
import tempfile
from io import BytesIO

# Add the parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def test_qr_payload_creation():
    """Test basic payload creation and parsing without QR generation"""
    print("Testing QR payload creation...")

    try:
        from qr_distribution import QRKeyDistribution, QRKeyError

        # Create test key data
        test_key = b"this is a test encryption key for QR code distribution"
        key_name = "test_key_001"

        # Create QR distribution instance (without actual QR generation)
        qr_dist = QRKeyDistribution()

        # Test payload preparation
        from qr_distribution import SecureBytes

        payload = qr_dist._prepare_key_payload(SecureBytes(test_key), key_name, compression=True)

        print(f"✅ Payload created: {len(payload)} bytes")

        # Parse the payload to verify structure
        json_data = json.loads(payload.decode("utf-8"))

        assert json_data["header"] == qr_dist.MAGIC_HEADER
        assert json_data["metadata"]["name"] == key_name
        assert json_data["metadata"]["compressed"] == True
        assert json_data["metadata"]["size"] == len(test_key)

        print("✅ Payload structure validated")

        # Test payload parsing
        key_b64 = json_data["key"]
        key_content = base64.b64decode(key_b64)

        # Decompress
        import zlib

        decompressed_key = zlib.decompress(key_content)

        assert decompressed_key == test_key
        print("✅ Key data round-trip successful")

        # Test checksum
        expected_checksum = base64.b64decode(json_data["checksum"])
        actual_checksum = hashlib.sha256(test_key).digest()[: qr_dist.CHECKSUM_LENGTH]

        assert expected_checksum == actual_checksum
        print("✅ Checksum validation successful")

        return True

    except ImportError as e:
        print(f"⚠️  QR dependencies not available: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False


def test_multi_qr_splitting():
    """Test multi-QR data splitting logic"""
    print("\nTesting multi-QR data splitting...")

    try:
        from qr_distribution import QRKeyDistribution

        # Create large test data that would require multi-QR
        large_key_data = b"X" * 4096  # 4KB key data
        key_name = "large_test_key"

        qr_dist = QRKeyDistribution()

        # Prepare payload
        from qr_distribution import SecureBytes

        payload = qr_dist._prepare_key_payload(
            SecureBytes(large_key_data),
            key_name,
            compression=False,  # Don't compress for predictable size
        )

        print(f"Large payload size: {len(payload)} bytes")

        # Calculate chunk size
        metadata_overhead = 200
        chunk_size = qr_dist.MAX_SINGLE_QR_SIZE - metadata_overhead

        # Split into chunks (simulate multi-QR creation logic)
        chunks = [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)]
        total_chunks = len(chunks)

        print(f"Would create {total_chunks} QR codes")
        print(f"Chunk sizes: {[len(chunk) for chunk in chunks]}")

        assert total_chunks > 1, "Should require multiple QR codes"
        assert total_chunks <= 99, "Should not exceed 99 QR codes"

        # Test overall checksum
        overall_checksum = hashlib.sha256(payload).hexdigest()[:16]
        print(f"Overall checksum: {overall_checksum}")

        print("✅ Multi-QR splitting logic validated")
        return True

    except Exception as e:
        print(f"❌ Multi-QR test failed: {e}")
        return False


def test_error_handling():
    """Test error handling scenarios"""
    print("\nTesting error handling...")

    try:
        from qr_distribution import QRKeyDistribution, QRKeyError

        qr_dist = QRKeyDistribution()

        # Test empty key data
        try:
            qr_dist.create_key_qr(b"", "empty_key")
            print("❌ Should have failed with empty key data")
            return False
        except QRKeyError:
            print("✅ Empty key data correctly rejected")

        # Test invalid JSON parsing
        try:
            invalid_qr_data = "invalid json data"
            encoded_data = base64.b64encode(invalid_qr_data.encode()).decode()
            qr_dist._parse_single_qr_data(encoded_data)
            print("❌ Should have failed with invalid JSON")
            return False
        except QRKeyError:
            print("✅ Invalid JSON correctly rejected")

        return True

    except Exception as e:
        print(f"❌ Error handling test failed: {e}")
        return False


def main():
    """Run basic QR functionality tests"""
    print("🔒 QR Code Key Distribution - Basic Tests")
    print("=" * 50)

    tests = [test_qr_payload_creation, test_multi_qr_splitting, test_error_handling]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print("\n" + "=" * 50)
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All basic QR tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
