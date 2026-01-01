#!/usr/bin/env python3
"""
Example usage of the Pepper Plugin.

This script demonstrates how to use the pepper plugin for secure remote
pepper storage with mTLS authentication.

IMPORTANT: This is a demonstration only. In production:
1. Generate proper client certificates for mTLS
2. Encrypt peppers client-side before storing
3. Store TOTP backup codes securely
4. Configure dead man's switch appropriately
"""

import sys
from pathlib import Path

from openssl_encrypt.plugins.pepper import PepperPlugin, PepperConfig, PepperError


def main():
    """Example pepper plugin usage."""

    # Example 1: Configuration
    print("=" * 60)
    print("Example 1: Configure Pepper Plugin")
    print("=" * 60)

    config = PepperConfig(
        enabled=True,
        server_url="https://localhost:8080",  # Your pepper server
        client_cert=Path("~/.openssl_encrypt/pepper/client.crt"),
        client_key=Path("~/.openssl_encrypt/pepper/client.key"),
        ca_cert=None,  # Use system CA bundle
    )

    print(f"Enabled: {config.enabled}")
    print(f"Server: {config.server_url}")
    print(f"Client Cert: {config.client_cert}")
    print()

    # Example 2: Initialize Plugin
    print("=" * 60)
    print("Example 2: Initialize Plugin")
    print("=" * 60)

    try:
        plugin = PepperPlugin(config)
        print("✓ Plugin initialized successfully")
    except PepperError as e:
        print(f"✗ Plugin initialization failed: {e}")
        return
    print()

    # Example 3: Get Profile (auto-register)
    print("=" * 60)
    print("Example 3: Get/Create Profile")
    print("=" * 60)

    try:
        profile = plugin.get_profile()
        print(f"Certificate Fingerprint: {profile['cert_fingerprint']}")
        print(f"Name: {profile.get('name', 'Not set')}")
        print(f"TOTP Enabled: {profile['totp_enabled']}")
        print(f"Pepper Count: {profile['pepper_count']}")
        print(f"Created: {profile['created_at']}")
    except PepperError as e:
        print(f"✗ Failed to get profile: {e}")
        return
    print()

    # Example 4: Update Profile
    print("=" * 60)
    print("Example 4: Update Profile Name")
    print("=" * 60)

    try:
        profile = plugin.update_profile("My Laptop")
        print(f"✓ Profile updated: {profile['name']}")
    except PepperError as e:
        print(f"✗ Failed to update profile: {e}")
    print()

    # Example 5: Setup TOTP
    print("=" * 60)
    print("Example 5: Setup TOTP 2FA")
    print("=" * 60)

    try:
        totp_setup = plugin.setup_totp()
        print("✓ TOTP setup initiated")
        print(f"Secret: {totp_setup['secret']}")
        print(f"URI: {totp_setup['uri']}")
        print("\nScan this QR code with your authenticator app:")
        print("(QR code SVG saved to totp_qr.svg)")

        # Save QR code to file
        with open("totp_qr.svg", "w") as f:
            f.write(totp_setup['qr_svg'])

        print("\nAfter scanning, verify with: plugin.verify_totp('123456')")

        # In a real scenario, you would:
        # 1. Display QR code to user
        # 2. Wait for user to scan with authenticator app
        # 3. Prompt user to enter code
        # 4. Call plugin.verify_totp(code)
        # 5. Save backup codes securely

    except PepperError as e:
        print(f"✗ TOTP setup failed: {e}")
    print()

    # Example 6: Store Encrypted Pepper
    print("=" * 60)
    print("Example 6: Store Encrypted Pepper")
    print("=" * 60)

    try:
        # IMPORTANT: In production, encrypt this data client-side!
        pepper_data = b"This should be encrypted client-side!"

        result = plugin.store_pepper(
            name="example-pepper",
            pepper_encrypted=pepper_data,
            description="Example pepper for demonstration"
        )
        print(f"✓ Pepper stored: {result['name']}")
        print(f"  Created: {result['created_at']}")
        print(f"  Description: {result['description']}")
    except PepperError as e:
        print(f"✗ Failed to store pepper: {e}")
    print()

    # Example 7: List Peppers
    print("=" * 60)
    print("Example 7: List All Peppers")
    print("=" * 60)

    try:
        peppers = plugin.list_peppers()
        print(f"✓ Found {len(peppers)} pepper(s):")
        for pepper in peppers:
            print(f"  - {pepper['name']}")
            print(f"    Description: {pepper['description']}")
            print(f"    Access Count: {pepper['access_count']}")
    except PepperError as e:
        print(f"✗ Failed to list peppers: {e}")
    print()

    # Example 8: Retrieve Pepper
    print("=" * 60)
    print("Example 8: Retrieve Pepper")
    print("=" * 60)

    try:
        pepper_data = plugin.get_pepper("example-pepper")
        print(f"✓ Retrieved pepper: {len(pepper_data)} bytes")
        # IMPORTANT: Decrypt pepper_data client-side!
        print(f"  Data (should be decrypted): {pepper_data[:50]}...")
    except PepperError as e:
        print(f"✗ Failed to retrieve pepper: {e}")
    print()

    # Example 9: Configure Dead Man's Switch
    print("=" * 60)
    print("Example 9: Configure Dead Man's Switch")
    print("=" * 60)

    try:
        deadman = plugin.configure_deadman(
            interval="7d",  # Check in every 7 days
            grace_period="24h",  # 24 hour grace period
            enabled=True
        )
        print("✓ Dead man's switch configured")
        print(f"  Enabled: {deadman['enabled']}")
        print(f"  Interval: {deadman['interval_seconds']} seconds (7 days)")
        print(f"  Grace Period: {deadman['grace_period_seconds']} seconds (24 hours)")
        print(f"  Next Deadline: {deadman['next_deadline']}")
        print(f"  Time Remaining: {deadman['time_remaining_seconds']} seconds")
    except PepperError as e:
        print(f"✗ Failed to configure deadman: {e}")
    print()

    # Example 10: Check In
    print("=" * 60)
    print("Example 10: Dead Man's Switch Check-In")
    print("=" * 60)

    try:
        deadman = plugin.checkin()
        print("✓ Checked in successfully")
        print(f"  Next Deadline: {deadman['next_deadline']}")
    except PepperError as e:
        print(f"✗ Failed to check in: {e}")
    print()

    # Example 11: Panic Operations (DESTRUCTIVE - commented out)
    print("=" * 60)
    print("Example 11: Panic Operations (COMMENTED OUT)")
    print("=" * 60)
    print("WARNING: Panic operations are DESTRUCTIVE and cannot be undone!")
    print("They require TOTP verification.")
    print()
    print("To panic delete a single pepper:")
    print("  result = plugin.panic_single('example-pepper', totp_code='123456')")
    print()
    print("To panic delete ALL peppers:")
    print("  result = plugin.panic_all(totp_code='123456')")
    print()

    # Example cleanup
    print("=" * 60)
    print("Example Complete!")
    print("=" * 60)
    print("\nNOTE: In production:")
    print("  1. Always encrypt peppers client-side before storing")
    print("  2. Always decrypt peppers client-side after retrieving")
    print("  3. Securely store TOTP backup codes")
    print("  4. Use proper client certificates for mTLS")
    print("  5. Configure dead man's switch appropriately")


if __name__ == "__main__":
    main()
