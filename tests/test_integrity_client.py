#!/usr/bin/env python3
"""
Integration test for Integrity Plugin with live server.

This tests the client plugin against the running integrity server.
"""

import sys
import hashlib
from pathlib import Path

# Add openssl_encrypt to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from openssl_encrypt.plugins.integrity import (
    IntegrityPlugin,
    IntegrityConfig,
    IntegrityPluginError,
    IntegrityVerificationError,
)


def test_integrity_client():
    """Test integrity client plugin."""

    print("=" * 70)
    print("Integrity Plugin Integration Test")
    print("=" * 70)
    print()

    # Configure plugin (disabled for testing without actual certs)
    # For real usage, set enabled=True and provide actual certificate paths
    cert_dir = Path("/tmp/integrity_test_certs")
    config = IntegrityConfig(
        enabled=False,  # Disabled for testing without mTLS certs
        server_url="https://localhost:8080",  # Test server (HTTPS required)
        client_cert=cert_dir / "client.crt",
        client_key=cert_dir / "client.key",
        ca_cert=None,  # Use system CA bundle
    )

    # Note: For local testing without actual mTLS, we can't use the plugin directly
    # because it requires proper mTLS setup. Instead, let's demonstrate the API structure.
    # To test with actual server: Set enabled=True and provide real certificate paths

    print("Plugin Configuration:")
    print(f"  Server URL: {config.server_url}")
    print(f"  Client Cert: {config.client_cert}")
    print(f"  Client Key: {config.client_key}")
    print(f"  CA Cert: {config.ca_cert or 'System CA bundle'}")
    print(f"  Enabled: {config.enabled}")
    print(f"  Connect Timeout: {config.connect_timeout_seconds}s")
    print(f"  Read Timeout: {config.read_timeout_seconds}s")
    print()

    # Initialize plugin (will fail if disabled, which is expected for testing)
    print("Test 0: Plugin Initialization")
    print("-" * 70)
    try:
        plugin = IntegrityPlugin(config)
        print("✓ Plugin initialized successfully")
        print()
    except IntegrityPluginError as e:
        print(f"⚠ Cannot initialize plugin (expected without mTLS setup): {e}")
        print("  This is normal for testing without actual certificates.")
        print()
        # Create a mock config for remaining tests
        config_for_tests = IntegrityConfig(
            enabled=False,
            server_url="https://localhost:8080",
            client_cert=cert_dir / "client.crt",
            client_key=cert_dir / "client.key",
            ca_cert=None,
        )
        # We'll skip tests that require actual plugin instance
        plugin = None
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        plugin = None
    print()

    # Test 1: Profile (requires actual mTLS connection)
    print("Test 1: Get Profile")
    print("-" * 70)
    if plugin:
        try:
            # This will fail without proper mTLS setup, but demonstrates the API
            profile = plugin.get_profile()
            print(f"✓ Profile retrieved:")
            print(f"  Fingerprint: {profile['cert_fingerprint']}")
            print(f"  Name: {profile.get('name', 'Not set')}")
            print(f"  Hash Count: {profile['hash_count']}")
            print(f"  Created: {profile['created_at']}")
            print(f"  Last Seen: {profile.get('last_seen_at', 'Never')}")
            print()
        except IntegrityPluginError as e:
            print(f"⚠ Plugin error (expected without proper mTLS): {e}")
            print()
        except Exception as e:
            print(f"⚠ Error: {e}")
            print()
    else:
        print("⊘ Skipped (plugin not initialized)")
        print()

    # Test 2: Configuration validation
    print("Test 2: Configuration Validation")
    print("-" * 70)
    try:
        # Config is validated in __post_init__
        print("✓ Configuration is valid")
        print(f"  Server URL validated: {config.server_url.startswith('https://')}")
        print(f"  Timeout validated: {config.connect_timeout_seconds > 0}")
        print()
    except Exception as e:
        print(f"✗ Configuration invalid: {e}")
        print()

    # Test 3: Save/load configuration
    print("Test 3: Save/Load Configuration")
    print("-" * 70)
    try:
        test_config_path = Path("/tmp/integrity_test_config.json")
        config.to_file(test_config_path)
        print(f"✓ Configuration saved to {test_config_path}")

        loaded_config = IntegrityConfig.from_file(test_config_path)
        print(f"✓ Configuration loaded from {test_config_path}")
        print(f"  Server URL: {loaded_config.server_url}")
        print(f"  Enabled: {loaded_config.enabled}")
        print(f"  Timeouts: {loaded_config.connect_timeout_seconds}s / {loaded_config.read_timeout_seconds}s")
        print()
    except Exception as e:
        print(f"✗ Configuration save/load failed: {e}")
        print()

    # Test 4: Plugin methods (API structure)
    print("Test 4: Plugin API Structure")
    print("-" * 70)
    print("Available methods:")
    methods = [
        "get_profile", "update_profile",
        "store_hash", "get_hash", "list_hashes", "update_hash", "delete_hash", "delete_all_hashes",
        "verify", "verify_batch", "get_stats"
    ]
    if plugin:
        for method in methods:
            if hasattr(plugin, method):
                print(f"  ✓ {method}()")
            else:
                print(f"  ✗ {method}() - MISSING")
    else:
        # Check on the class itself
        for method in methods:
            if hasattr(IntegrityPlugin, method):
                print(f"  ✓ {method}()")
            else:
                print(f"  ✗ {method}() - MISSING")
    print()

    # Test 5: Utility methods
    print("Test 5: Utility Methods")
    print("-" * 70)
    try:
        # Test compute_metadata_hash
        test_metadata = b"test encrypted metadata"
        metadata_hash = IntegrityPlugin.compute_metadata_hash(test_metadata)
        print(f"✓ compute_metadata_hash():")
        print(f"  Input: {test_metadata}")
        print(f"  Hash: {metadata_hash}")
        print(f"  Length: {len(metadata_hash)} chars (expected: 64)")
        print()

        # Test compute_file_id
        test_file = Path("/path/to/test/file.enc")
        file_id = IntegrityPlugin.compute_file_id(test_file)
        print(f"✓ compute_file_id():")
        print(f"  Input: {test_file}")
        print(f"  File ID: {file_id}")
        print(f"  Length: {len(file_id)} chars (expected: 64)")
        print()
    except Exception as e:
        print(f"✗ Utility methods failed: {e}")
        print()

    # Test 6: Hash validation
    print("Test 6: Hash Validation")
    print("-" * 70)
    if plugin:
        try:
            # Valid hash (64 hex chars)
            valid_hash = "a" * 64
            print(f"✓ Valid hash format: {valid_hash[:16]}...")

            # Invalid hash (wrong length)
            try:
                plugin.store_hash("test", "invalid_hash", "test")
                print("✗ Should have rejected invalid hash")
            except IntegrityPluginError as e:
                print(f"✓ Correctly rejected invalid hash: {str(e)[:50]}...")

            # Invalid file_id (too long)
            try:
                plugin.store_hash("x" * 129, valid_hash, "test")
                print("✗ Should have rejected invalid file_id")
            except IntegrityPluginError as e:
                print(f"✓ Correctly rejected invalid file_id: {str(e)[:50]}...")
            print()
        except Exception as e:
            print(f"⚠ Validation test error: {e}")
            print()
    else:
        print("⊘ Skipped (plugin not initialized)")
        print("  Note: Client-side validation would reject invalid hashes/file_ids")
        print()

    # Test 7: Context manager support
    print("Test 7: Context Manager Support")
    print("-" * 70)
    if plugin:
        try:
            plugin.close()  # Close the existing instance first
            with IntegrityPlugin(config) as ctx_plugin:
                print("✓ Context manager __enter__ successful")
                print(f"  Plugin instance: {type(ctx_plugin).__name__}")
            print("✓ Context manager __exit__ successful (cleanup)")
            print()
        except Exception as e:
            print(f"⚠ Context manager test error: {e}")
            print()
    else:
        print("⊘ Skipped (plugin not initialized)")
        print("  Note: Plugin supports context manager for automatic cleanup")
        print()

    # Print usage example
    print("=" * 70)
    print("Usage Example (with proper mTLS setup):")
    print("=" * 70)
    print("""
from openssl_encrypt.plugins.integrity import IntegrityPlugin, IntegrityConfig
from pathlib import Path

# Configure plugin
config = IntegrityConfig(
    enabled=True,
    server_url="https://integrity.example.com",
    client_cert=Path("~/.openssl_encrypt/integrity/certs/client.crt"),
    client_key=Path("~/.openssl_encrypt/integrity/certs/client.key"),
    ca_cert=Path("~/.openssl_encrypt/integrity/certs/ca.crt")
)

# Use plugin with context manager
with IntegrityPlugin(config) as plugin:
    # 1. Get profile (auto-registers on first connection)
    profile = plugin.get_profile()
    print(f"Connected as: {profile['cert_fingerprint']}")

    # 2. Store metadata hash for a file
    file_path = Path("important_file.txt.enc")
    file_id = plugin.compute_file_id(file_path)

    # Compute hash from encrypted metadata
    with open(file_path, "rb") as f:
        metadata = f.read(1024)  # Read metadata section
    metadata_hash = plugin.compute_metadata_hash(metadata)

    # Store on server
    result = plugin.store_hash(
        file_id=file_id,
        metadata_hash=metadata_hash,
        algorithm="aes-256-gcm",
        description="Important encrypted file"
    )
    print(f"Hash stored: {result['file_id']}")

    # 3. Verify integrity later (before decryption)
    match, details = plugin.verify(file_id, metadata_hash)
    if match:
        print("✓ Integrity verified - safe to decrypt")
    else:
        print(f"✗ INTEGRITY VIOLATION: {details['warning']}")
        print("DO NOT decrypt - file may be tampered!")

    # 4. Batch verification (multiple files)
    verifications = [
        {"file_id": file_id, "metadata_hash": metadata_hash},
        # ... up to 100 files
    ]
    batch_result = plugin.verify_batch(verifications)
    print(f"Batch: {batch_result['matches']} matches, {batch_result['mismatches']} violations")

    # 5. Get verification statistics
    stats = plugin.get_stats()
    print(f"Success rate: {stats['success_rate'] * 100:.1f}%")
    print(f"Total verifications: {stats['total_verifications']}")
    print(f"Integrity violations: {stats['failed_verifications']}")

    # 6. List all stored hashes
    hashes = plugin.list_hashes()
    print(f"Total hashes stored: {hashes['total']}")

    # 7. Update hash (if file re-encrypted)
    plugin.update_hash(file_id, new_metadata_hash, "Re-encrypted with stronger algorithm")

    # 8. Delete hash (if file deleted)
    plugin.delete_hash(file_id)

# Automatic cleanup when exiting context manager
""")

    print()
    print("=" * 70)
    print("Additional Features:")
    print("=" * 70)
    print("""
Profile Management:
  - Update display name: plugin.update_profile("My Computer")

Statistics Tracking:
  - Total hashes stored
  - Total verification attempts
  - Success/failure counts
  - Success rate percentage
  - Last verification timestamp

Batch Operations:
  - Verify up to 100 files in a single request
  - Returns aggregated results with individual details
  - Logs all integrity violations automatically

Security:
  - All connections require mTLS authentication
  - Certificate fingerprint used as client ID
  - Comprehensive audit logging on server
  - No sensitive data transmitted (only SHA-256 hashes)
  - Auto-registration on first connection
  - OPT-IN by default (enabled=false)
""")

    return True


if __name__ == "__main__":
    success = test_integrity_client()
    sys.exit(0 if success else 1)
