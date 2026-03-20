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
from ...modules.crypt_utils import eprint


def main():
    """Example pepper plugin usage."""

    # Example 1: Configuration
    eprint("=" * 60)
    eprint("Example 1: Configure Pepper Plugin")
    eprint("=" * 60)

    config = PepperConfig(
        enabled=True,
        server_url="https://localhost:8080",  # Your pepper server
        client_cert=Path("~/.openssl_encrypt/pepper/client.crt"),
        client_key=Path("~/.openssl_encrypt/pepper/client.key"),
        ca_cert=None,  # Use system CA bundle
    )

    eprint(f"Enabled: {config.enabled}")
    eprint(f"Server: {config.server_url}")
    eprint(f"Client Cert: {config.client_cert}")
    eprint()

    # Example 2: Initialize Plugin
    eprint("=" * 60)
    eprint("Example 2: Initialize Plugin")
    eprint("=" * 60)

    try:
        plugin = PepperPlugin(config)
        eprint("✓ Plugin initialized successfully")
    except PepperError as e:
        eprint(f"✗ Plugin initialization failed: {e}")
        return
    eprint()

    # Example 3: Get Profile (auto-register)
    eprint("=" * 60)
    eprint("Example 3: Get/Create Profile")
    eprint("=" * 60)

    try:
        profile = plugin.get_profile()
        eprint(f"Certificate Fingerprint: {profile['cert_fingerprint']}")
        eprint(f"Name: {profile.get('name', 'Not set')}")
        eprint(f"TOTP Enabled: {profile['totp_enabled']}")
        eprint(f"Pepper Count: {profile['pepper_count']}")
        eprint(f"Created: {profile['created_at']}")
    except PepperError as e:
        eprint(f"✗ Failed to get profile: {e}")
        return
    eprint()

    # Example 4: Update Profile
    eprint("=" * 60)
    eprint("Example 4: Update Profile Name")
    eprint("=" * 60)

    try:
        profile = plugin.update_profile("My Laptop")
        eprint(f"✓ Profile updated: {profile['name']}")
    except PepperError as e:
        eprint(f"✗ Failed to update profile: {e}")
    eprint()

    # Example 5: Setup TOTP
    eprint("=" * 60)
    eprint("Example 5: Setup TOTP 2FA")
    eprint("=" * 60)

    try:
        totp_setup = plugin.setup_totp()
        eprint("✓ TOTP setup initiated")
        eprint(f"Secret: {totp_setup['secret']}")
        eprint(f"URI: {totp_setup['uri']}")
        eprint("\nScan this QR code with your authenticator app:")
        eprint("(QR code SVG saved to totp_qr.svg)")

        # Save QR code to file
        with open("totp_qr.svg", "w") as f:
            f.write(totp_setup['qr_svg'])

        eprint("\nAfter scanning, verify with: plugin.verify_totp('123456')")

        # In a real scenario, you would:
        # 1. Display QR code to user
        # 2. Wait for user to scan with authenticator app
        # 3. Prompt user to enter code
        # 4. Call plugin.verify_totp(code)
        # 5. Save backup codes securely

    except PepperError as e:
        eprint(f"✗ TOTP setup failed: {e}")
    eprint()

    # Example 6: Store Encrypted Pepper
    eprint("=" * 60)
    eprint("Example 6: Store Encrypted Pepper")
    eprint("=" * 60)

    try:
        # IMPORTANT: In production, encrypt this data client-side!
        pepper_data = b"This should be encrypted client-side!"

        result = plugin.store_pepper(
            name="example-pepper",
            pepper_encrypted=pepper_data,
            description="Example pepper for demonstration"
        )
        eprint(f"✓ Pepper stored: {result['name']}")
        eprint(f"  Created: {result['created_at']}")
        eprint(f"  Description: {result['description']}")
    except PepperError as e:
        eprint(f"✗ Failed to store pepper: {e}")
    eprint()

    # Example 7: List Peppers
    eprint("=" * 60)
    eprint("Example 7: List All Peppers")
    eprint("=" * 60)

    try:
        peppers = plugin.list_peppers()
        eprint(f"✓ Found {len(peppers)} pepper(s):")
        for pepper in peppers:
            eprint(f"  - {pepper['name']}")
            eprint(f"    Description: {pepper['description']}")
            eprint(f"    Access Count: {pepper['access_count']}")
    except PepperError as e:
        eprint(f"✗ Failed to list peppers: {e}")
    eprint()

    # Example 8: Retrieve Pepper
    eprint("=" * 60)
    eprint("Example 8: Retrieve Pepper")
    eprint("=" * 60)

    try:
        pepper_data = plugin.get_pepper("example-pepper")
        eprint(f"✓ Retrieved pepper: {len(pepper_data)} bytes")
        # IMPORTANT: Decrypt pepper_data client-side!
        eprint(f"  Data (should be decrypted): {pepper_data[:50]}...")
    except PepperError as e:
        eprint(f"✗ Failed to retrieve pepper: {e}")
    eprint()

    # Example 9: Configure Dead Man's Switch
    eprint("=" * 60)
    eprint("Example 9: Configure Dead Man's Switch")
    eprint("=" * 60)

    try:
        deadman = plugin.configure_deadman(
            interval="7d",  # Check in every 7 days
            grace_period="24h",  # 24 hour grace period
            enabled=True
        )
        eprint("✓ Dead man's switch configured")
        eprint(f"  Enabled: {deadman['enabled']}")
        eprint(f"  Interval: {deadman['interval_seconds']} seconds (7 days)")
        eprint(f"  Grace Period: {deadman['grace_period_seconds']} seconds (24 hours)")
        eprint(f"  Next Deadline: {deadman['next_deadline']}")
        eprint(f"  Time Remaining: {deadman['time_remaining_seconds']} seconds")
    except PepperError as e:
        eprint(f"✗ Failed to configure deadman: {e}")
    eprint()

    # Example 10: Check In
    eprint("=" * 60)
    eprint("Example 10: Dead Man's Switch Check-In")
    eprint("=" * 60)

    try:
        deadman = plugin.checkin()
        eprint("✓ Checked in successfully")
        eprint(f"  Next Deadline: {deadman['next_deadline']}")
    except PepperError as e:
        eprint(f"✗ Failed to check in: {e}")
    eprint()

    # Example 11: Panic Operations (DESTRUCTIVE - commented out)
    eprint("=" * 60)
    eprint("Example 11: Panic Operations (COMMENTED OUT)")
    eprint("=" * 60)
    eprint("WARNING: Panic operations are DESTRUCTIVE and cannot be undone!")
    eprint("They require TOTP verification.")
    eprint()
    eprint("To panic delete a single pepper:")
    eprint("  result = plugin.panic_single('example-pepper', totp_code='123456')")
    eprint()
    eprint("To panic delete ALL peppers:")
    eprint("  result = plugin.panic_all(totp_code='123456')")
    eprint()

    # Example cleanup
    eprint("=" * 60)
    eprint("Example Complete!")
    eprint("=" * 60)
    eprint("\nNOTE: In production:")
    eprint("  1. Always encrypt peppers client-side before storing")
    eprint("  2. Always decrypt peppers client-side after retrieving")
    eprint("  3. Securely store TOTP backup codes")
    eprint("  4. Use proper client certificates for mTLS")
    eprint("  5. Configure dead man's switch appropriately")


if __name__ == "__main__":
    main()
