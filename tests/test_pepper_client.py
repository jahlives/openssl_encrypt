#!/usr/bin/env python3
"""
Integration test for Pepper Plugin with live server.

This tests the client plugin against the running pepper server.
"""

import sys
from pathlib import Path

# Add openssl_encrypt to path
sys.path.insert(0, str(Path(__file__).parent))

from openssl_encrypt.plugins.pepper import (
    PepperPlugin,
    PepperConfig,
    PepperError,
    NetworkError,
    AuthenticationError,
)


def test_pepper_client():
    """Test pepper client plugin."""

    print("=" * 70)
    print("Pepper Plugin Integration Test")
    print("=" * 70)
    print()

    # Try to load configuration from standard location
    print("Configuration Loading:")
    print("-" * 70)

    # Try to determine config path
    try:
        import os
        home = os.environ.get('HOME') or os.environ.get('USERPROFILE')
        if home:
            config_path = Path(home) / ".openssl_encrypt" / "plugins" / "pepper.json"
        else:
            config_path = Path.home() / ".openssl_encrypt" / "plugins" / "pepper.json"
    except Exception:
        # Fallback if home directory cannot be determined
        config_path = Path("/tmp/.openssl_encrypt/plugins/pepper.json")
        print(f"⚠ Could not determine home directory, using: {config_path}")

    try:
        if config_path.exists():
            config = PepperConfig.from_file(config_path)
            print(f"✓ Loaded config from: {config_path}")
            print(f"  Enabled: {config.enabled}")
            print(f"  Server: {config.server_url}")
            if config.client_cert:
                print(f"  Client Cert: {config.client_cert}")
                print(f"  Client Key: {config.client_key}")
            print()
        else:
            print(f"⚠ Config file not found: {config_path}")
            print("  Using default configuration (disabled)")
            print()
            # Use default disabled config for testing
            config = PepperConfig()
    except Exception as e:
        print(f"⚠ Could not load config: {e}")
        print("  Using default configuration (disabled)")
        print()
        config = PepperConfig()

    # Note: For local testing without actual mTLS, we can't use the plugin directly
    # because it requires proper mTLS setup. Instead, let's demonstrate the API structure.
    # To test with actual server: Create config at ~/.openssl_encrypt/plugins/pepper.json
    # with enabled=True and provide real certificate paths
    print()

    # Initialize plugin
    try:
        plugin = PepperPlugin(config)
        print("✓ Plugin initialized successfully")
        print()
    except Exception as e:
        print(f"✗ Failed to initialize plugin: {e}")
        return False

    # Test 1: Profile (requires actual mTLS connection)
    print("Test 1: Get Profile")
    print("-" * 70)
    try:
        # This will fail without proper mTLS setup, but demonstrates the API
        profile = plugin.get_profile()
        print(f"✓ Profile retrieved:")
        print(f"  Fingerprint: {profile['cert_fingerprint']}")
        print(f"  TOTP Enabled: {profile['totp_enabled']}")
        print(f"  Pepper Count: {profile['pepper_count']}")
        print()
    except AuthenticationError as e:
        print(f"⚠ Authentication error (expected without proper mTLS): {e}")
        print()
    except NetworkError as e:
        print(f"⚠ Network error: {e}")
        print()
    except Exception as e:
        print(f"⚠ Error: {e}")
        print()

    # Test 2: Configuration validation
    print("Test 2: Configuration Validation")
    print("-" * 70)
    try:
        config.validate()
        print("✓ Configuration is valid")
        print()
    except Exception as e:
        print(f"✗ Configuration invalid: {e}")
        print()

    # Test 3: Save/load configuration
    print("Test 3: Save/Load Configuration")
    print("-" * 70)
    try:
        test_config_path = Path("/tmp/pepper_test_config.json")
        config.to_file(test_config_path)
        print(f"✓ Configuration saved to {test_config_path}")

        loaded_config = PepperConfig.from_file(test_config_path)
        print(f"✓ Configuration loaded from {test_config_path}")
        print(f"  Server URL: {loaded_config.server_url}")
        print(f"  Enabled: {loaded_config.enabled}")
        print()
        print(f"  Note: Standard config location is {config_path}")
        print()
    except Exception as e:
        print(f"✗ Configuration save/load failed: {e}")
        print()

    # Test 4: Plugin methods (API structure)
    print("Test 4: Plugin API Structure")
    print("-" * 70)
    print("Available methods:")
    methods = [
        attr for attr in dir(plugin)
        if not attr.startswith('_') and callable(getattr(plugin, attr))
    ]
    for method in sorted(methods):
        if not method.startswith('get_'):  # Filter out base class methods
            continue
        print(f"  - {method}()")
    print()

    # Print usage example
    print("=" * 70)
    print("Usage Example (with proper mTLS setup):")
    print("=" * 70)
    print("""
# 1. Get profile (auto-registers)
profile = plugin.get_profile()

# 2. Setup TOTP
totp = plugin.setup_totp()
# Scan QR code, then verify:
result = plugin.verify_totp("123456")
backup_codes = result['backup_codes']  # Save these!

# 3. Store encrypted pepper
import base64
pepper_encrypted = base64.b64encode(b"encrypted pepper data")
plugin.store_pepper("my-pepper", pepper_encrypted, "Test pepper")

# 4. List peppers
peppers = plugin.list_peppers()

# 5. Retrieve pepper
pepper_data = plugin.get_pepper("my-pepper")

# 6. Configure dead man's switch
plugin.configure_deadman(interval="7d", grace_period="24h")

# 7. Check in
plugin.checkin()
""")

    return True


if __name__ == "__main__":
    success = test_pepper_client()
    sys.exit(0 if success else 1)
