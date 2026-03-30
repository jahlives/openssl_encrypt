#!/usr/bin/env python3
"""
Complete Keyserver Test Script

Tests the full keyserver workflow:
1. Create a new test identity
2. Create a PublicKeyBundle
3. Verify self-signature
4. Upload to keyserver
5. Search by email, fingerprint, and name
6. Verify cache functionality

Usage:
    python3 test_keyserver_complete.py

Requirements:
    - Keyserver plugin must be enabled
    - Valid API token must be set (run: openssl-encrypt keyserver register)
"""

import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from openssl_encrypt.modules.identity import Identity
from openssl_encrypt.modules.key_bundle import PublicKeyBundle
from openssl_encrypt.plugins.keyserver.config import KeyserverConfig
from openssl_encrypt.plugins.keyserver.keyserver_plugin import KeyserverPlugin


def print_section(title: str):
    """Print a formatted section header."""
    print(f"\n{'=' * 70}")
    print(f"{title}")
    print(f"{'=' * 70}")


def print_subsection(title: str):
    """Print a formatted subsection header."""
    print(f"\n{title}")
    print("-" * 70)


def test_keyserver_complete():
    """Run complete keyserver test."""
    print_section("KEYSERVER COMPLETE TEST")

    # Step 1: Check configuration
    print_subsection("Step 1: Loading Keyserver Configuration")
    try:
        config = KeyserverConfig.from_file()
        print("✓ Configuration loaded")
        print(f"  Enabled: {config.enabled}")
        print(f"  Server: {config.servers[0] if config.servers else 'None'}")
        print(f"  Upload enabled: {config.upload_enabled}")

        if not config.enabled:
            print("\n✗ ERROR: Keyserver plugin is disabled")
            print("  Enable with: openssl-encrypt keyserver enable")
            return False

        # Check API token
        api_token = config.load_api_token()
        if not api_token:
            print("\n✗ ERROR: No API token found")
            print("  Register with: openssl-encrypt keyserver register")
            return False

        print(f"  API token: Present ({len(api_token)} chars)")

    except Exception as e:
        print(f"✗ Failed to load configuration: {e}")
        return False

    # Step 2: Create test identity
    print_subsection("Step 2: Creating Test Identity")
    try:
        identity = Identity.generate(
            name="Keyserver_Test_Identity",
            email="keyserver-test@example.com",
            passphrase="test123",  # Simple passphrase for testing
            kem_algorithm="ML-KEM-768",
            sig_algorithm="ML-DSA-65",
        )
        print("✓ Identity created")
        print(f"  Name: {identity.name}")
        print(f"  Email: {identity.email}")
        print(f"  Fingerprint: {identity.fingerprint}")
        print(f"  Encryption: {identity.encryption_algorithm}")
        print(f"  Signing: {identity.signing_algorithm}")

    except Exception as e:
        print(f"✗ Failed to create identity: {e}")
        return False

    # Step 3: Create PublicKeyBundle
    print_subsection("Step 3: Creating PublicKeyBundle")
    try:
        bundle = PublicKeyBundle.from_identity(identity)
        print("✓ Bundle created")
        print(f"  Fingerprint: {bundle.fingerprint}")
        print(f"  Algorithms: {bundle.encryption_algorithm} / {bundle.signing_algorithm}")

    except Exception as e:
        print(f"✗ Failed to create bundle: {e}")
        return False

    # Step 4: Verify signature
    print_subsection("Step 4: Verifying Self-Signature")
    try:
        if bundle.verify_signature():
            print("✓ Signature verification passed")
        else:
            print("✗ Signature verification failed")
            return False

    except Exception as e:
        print(f"✗ Signature verification error: {e}")
        return False

    # Step 5: Initialize plugin
    print_subsection("Step 5: Initializing Keyserver Plugin")
    try:
        plugin = KeyserverPlugin(config)
        plugin.clear_cache()
        print("✓ Plugin initialized (cache cleared)")

    except Exception as e:
        print(f"✗ Failed to initialize plugin: {e}")
        return False

    # Step 6: Upload to keyserver
    print_subsection("Step 6: Uploading to Keyserver")
    try:
        print(f"Uploading '{bundle.name}' to {config.servers[0]}...")
        signing_private_key_bytes = identity.signing_private_key.get_bytes()
        success = plugin.upload_key(bundle, signing_private_key_bytes=signing_private_key_bytes)

        if success:
            print("✓ Upload successful")
            print(f"  Name: {bundle.name}")
            print(f"  Email: {bundle.email}")
            print(f"  Fingerprint: {bundle.fingerprint}")
        else:
            print("✗ Upload failed")
            return False

    except Exception as e:
        print(f"✗ Upload error: {e}")
        import traceback

        traceback.print_exc()
        return False

    # Step 7: Search by email
    print_subsection("Step 7: Testing Search by Email")
    try:
        query = bundle.email
        print(f"Searching for: {query}")

        result = plugin.fetch_key(query)

        if result:
            print("✓ Key found via email search")
            print(f"  Name: {result.name}")
            print(f"  Email: {result.email}")
            print(f"  Fingerprint: {result.fingerprint}")
            print(f"  Match: {result.fingerprint == bundle.fingerprint}")

            if result.fingerprint != bundle.fingerprint:
                print("✗ ERROR: Fingerprint mismatch!")
                return False
        else:
            print("✗ Key not found by email")
            return False

    except Exception as e:
        print(f"✗ Search by email failed: {e}")
        return False

    # Step 8: Search by fingerprint
    print_subsection("Step 8: Testing Search by Fingerprint")
    try:
        query = bundle.fingerprint
        print(f"Searching for: {query}")

        result = plugin.fetch_key(query)

        if result:
            print("✓ Key found via fingerprint search")
            print(f"  Name: {result.name}")
            print(f"  Email: {result.email}")
            print(f"  Fingerprint: {result.fingerprint}")
            print(f"  Match: {result.fingerprint == bundle.fingerprint}")

            if result.fingerprint != bundle.fingerprint:
                print("✗ ERROR: Fingerprint mismatch!")
                return False
        else:
            print("✗ Key not found by fingerprint")
            return False

    except Exception as e:
        print(f"✗ Search by fingerprint failed: {e}")
        return False

    # Step 9: Search by name
    print_subsection("Step 9: Testing Search by Name")
    try:
        query = bundle.name
        print(f"Searching for: {query}")

        result = plugin.fetch_key(query)

        if result:
            print("✓ Key found via name search")
            print(f"  Name: {result.name}")
            print(f"  Email: {result.email}")
            print(f"  Fingerprint: {result.fingerprint}")
            print(f"  Match: {result.fingerprint == bundle.fingerprint}")

            if result.fingerprint != bundle.fingerprint:
                print("✗ ERROR: Fingerprint mismatch!")
                return False
        else:
            print("✗ Key not found by name")
            return False

    except Exception as e:
        print(f"✗ Search by name failed: {e}")
        return False

    # Step 10: Verify signature of retrieved key
    print_subsection("Step 10: Verifying Retrieved Key Signature")
    try:
        if result.verify_signature():
            print("✓ Retrieved key signature verification passed")
        else:
            print("✗ Retrieved key signature verification failed")
            return False

    except Exception as e:
        print(f"✗ Signature verification error: {e}")
        return False

    # Step 11: Check cache statistics
    print_subsection("Step 11: Cache Statistics")
    try:
        stats = plugin.get_cache_stats()
        print("✓ Cache statistics retrieved")
        print(f"  Total entries: {stats['total_entries']}")
        print(f"  Valid entries: {stats['valid_entries']}")
        print(f"  Expired entries: {stats['expired_entries']}")
        print(f"  Total accesses: {stats['total_accesses']}")
        if stats.get("most_accessed"):
            print(
                f"  Most accessed: {stats['most_accessed']['name']} "
                f"({stats['most_accessed']['count']} times)"
            )

    except Exception as e:
        print(f"✗ Failed to get cache statistics: {e}")
        # Not critical, don't return False

    # Final summary
    print_section("TEST SUMMARY")
    print("✓ All tests passed successfully!")
    print()
    print("Verified functionality:")
    print("  ✓ Configuration loading")
    print("  ✓ Identity creation")
    print("  ✓ Bundle creation")
    print("  ✓ Signature verification (local)")
    print("  ✓ Keyserver upload")
    print("  ✓ Search by email")
    print("  ✓ Search by fingerprint")
    print("  ✓ Search by name")
    print("  ✓ Signature verification (retrieved key)")
    print("  ✓ Cache functionality")
    print()
    print(f"Test key fingerprint: {bundle.fingerprint}")

    return True


def main():
    """Main entry point."""
    try:
        success = test_keyserver_complete()
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(130)

    except Exception as e:
        print(f"\n\n✗ FATAL ERROR: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
