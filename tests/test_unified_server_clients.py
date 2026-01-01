#!/usr/bin/env python3
"""
Test script for client libraries against unified server.

Tests:
1. Keyserver client registration and JWT token
2. Telemetry client registration and JWT token
3. Token isolation (keyserver token != telemetry token)
"""

import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from openssl_encrypt.plugins.keyserver import KeyserverConfig
from openssl_encrypt.plugins.telemetry.api_key_manager import APIKeyManager


class MockTelemetryConfig:
    """Mock config for telemetry testing"""
    def __init__(self):
        self.server_url = "http://localhost:8080"
        self.buffer_path = Path("/tmp/telemetry_test_buffer.db")
        self.batch_size = 100


def test_keyserver_registration():
    """Test keyserver client registration"""
    print("\n=== Testing Keyserver Client ===")

    import requests

    try:
        # Test direct registration with unified server
        print("Registering with keyserver...")
        response = requests.post("http://localhost:8080/api/v1/keys/register", timeout=10)

        if response.status_code != 200:
            print(f"✗ Registration failed with status {response.status_code}")
            print(f"  Response: {response.text}")
            return False

        result = response.json()
        print(f"✓ Registration successful!")
        print(f"  Client ID: {result['client_id']}")
        print(f"  Token: {result['token'][:50]}...")
        print(f"  Expires: {result['expires_at']}")
        print(f"  Type: {result['token_type']}")

        # Save token for later tests
        token_file = Path("/tmp/keyserver_test_token")
        token_file.write_text(result['token'])
        print(f"✓ Token saved to {token_file}")

        return True
    except Exception as e:
        print(f"✗ Registration failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_telemetry_registration():
    """Test telemetry client registration"""
    print("\n=== Testing Telemetry Client ===")

    # Create config
    config = MockTelemetryConfig()

    # Create key manager
    manager = APIKeyManager(config)

    # Test registration
    print("Registering with telemetry...")
    try:
        success = manager.register()
        if not success:
            print("✗ Registration returned False")
            return False

        print(f"✓ Registration successful!")

        # Load saved data
        data = manager._load_key_data()
        print(f"  Client ID: {data['client_id']}")
        print(f"  Token: {data['token'][:50]}...")
        print(f"  Expires: {data['expires']}")

        # Test get_api_key
        token = manager.get_api_key()
        print(f"✓ get_api_key() works")
        print(f"  Token matches: {token == data['token']}")

        return True
    except Exception as e:
        print(f"✗ Registration failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_token_isolation():
    """Verify that keyserver and telemetry tokens are different"""
    print("\n=== Testing Token Isolation ===")

    try:
        # Load keyserver token from file
        ks_token_file = Path("/tmp/keyserver_test_token")
        if not ks_token_file.exists():
            print("✗ Keyserver token file not found")
            return False
        ks_token = ks_token_file.read_text().strip()

        # Load telemetry token
        tm_config = MockTelemetryConfig()
        tm_manager = APIKeyManager(tm_config)
        tm_data = tm_manager._load_key_data()

        if not tm_data or "token" not in tm_data:
            print("✗ Telemetry token not found")
            return False
        tm_token = tm_data["token"]

        print(f"Keyserver token: {ks_token[:50] if ks_token else 'None'}...")
        print(f"Telemetry token: {tm_token[:50] if tm_token else 'None'}...")

        if not ks_token or not tm_token:
            print("✗ Missing token(s)")
            return False

        if ks_token == tm_token:
            print("✗ SECURITY ISSUE: Tokens are identical!")
            return False
        else:
            print("✓ Tokens are different (isolated)")

            # Try to decode JWTs to verify issuer claims (optional)
            try:
                import jwt
                ks_decoded = jwt.decode(ks_token, options={"verify_signature": False})
                tm_decoded = jwt.decode(tm_token, options={"verify_signature": False})

                print(f"✓ Keyserver issuer: {ks_decoded.get('iss')}")
                print(f"✓ Telemetry issuer: {tm_decoded.get('iss')}")

                if ks_decoded.get('iss') == tm_decoded.get('iss'):
                    print("✗ SECURITY ISSUE: Same issuer!")
                    return False

                print("✓ Different issuers (proper isolation)")
            except ImportError:
                print("  (PyJWT not available, skipping issuer check)")

            return True

    except Exception as e:
        print(f"✗ Token isolation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Client Library Tests - Unified Server")
    print("=" * 60)

    results = []

    # Test keyserver
    results.append(("Keyserver Registration", test_keyserver_registration()))

    # Test telemetry
    results.append(("Telemetry Registration", test_telemetry_registration()))

    # Test token isolation
    results.append(("Token Isolation", test_token_isolation()))

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)

    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{name:.<40} {status}")

    all_passed = all(result[1] for result in results)

    print("=" * 60)
    if all_passed:
        print("✓ ALL TESTS PASSED")
        return 0
    else:
        print("✗ SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
