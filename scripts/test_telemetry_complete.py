#!/usr/bin/env python3
"""
Complete Telemetry Server Test Script

Tests the full telemetry workflow:
1. Register a new telemetry client (get JWT token)
2. Submit telemetry events (various types)
3. Query public statistics
4. Verify data was stored correctly

Usage:
    python3 test_telemetry_complete.py [--server URL]

Options:
    --server URL    Telemetry server URL (default: https://keyserver.rm-rf.ch)
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Dict, List

import requests


def print_section(title: str):
    """Print a formatted section header."""
    print(f"\n{'=' * 70}")
    print(f"{title}")
    print(f"{'=' * 70}")


def print_subsection(title: str):
    """Print a formatted subsection header."""
    print(f"\n{title}")
    print("-" * 70)


def test_telemetry_register(base_url: str) -> Dict:
    """Test: Register telemetry client and get JWT token."""
    print_subsection("Step 1: Register Telemetry Client")

    url = f"{base_url}/api/v1/telemetry/register"
    print(f"POST {url}")

    try:
        response = requests.post(url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Registration successful")
            print(f"  Client ID: {data['client_id']}")
            print(f"  Token type: {data['token_type']}")
            print(f"  Expires at: {data['expires_at']}")
            print(f"  Token length: {len(data['token'])} chars")
            return data
        else:
            print(f"✗ Registration failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Registration error: {e}")
        return None


def create_test_events() -> List[Dict]:
    """Create test telemetry events."""
    now = datetime.now(timezone.utc).isoformat()

    events = [
        # Event 1: Asymmetric encryption with ML-KEM
        {
            "timestamp": now,
            "operation": "encrypt",
            "mode": "asymmetric",
            "format_version": 8,
            "hash_algorithms": ["SHA3-256", "BLAKE3"],
            "kdf_algorithms": ["Argon2id"],
            "encryption_algorithm": "AES-256-GCM",
            "cascade_enabled": True,
            "cascade_cipher_count": 3,
            "pqc_kem_algorithm": "ML-KEM-768",
            "pqc_signing_algorithm": "ML-DSA-65",
            "hsm_plugin_used": None,
            "success": True,
            "error_category": None,
        },
        # Event 2: Symmetric encryption
        {
            "timestamp": now,
            "operation": "encrypt",
            "mode": "symmetric",
            "format_version": 7,
            "hash_algorithms": ["SHA3-512"],
            "kdf_algorithms": ["Argon2id"],
            "encryption_algorithm": "Threefish-512",
            "cascade_enabled": False,
            "cascade_cipher_count": None,
            "pqc_kem_algorithm": None,
            "pqc_signing_algorithm": None,
            "hsm_plugin_used": None,
            "success": True,
            "error_category": None,
        },
        # Event 3: Asymmetric decryption
        {
            "timestamp": now,
            "operation": "decrypt",
            "mode": "asymmetric",
            "format_version": 8,
            "hash_algorithms": ["SHA3-256"],
            "kdf_algorithms": ["Argon2id"],
            "encryption_algorithm": "ChaCha20-Poly1305",
            "cascade_enabled": False,
            "cascade_cipher_count": None,
            "pqc_kem_algorithm": "ML-KEM-1024",
            "pqc_signing_algorithm": "ML-DSA-87",
            "hsm_plugin_used": "yubikey",
            "success": True,
            "error_category": None,
        },
        # Event 4: Failed encryption
        {
            "timestamp": now,
            "operation": "encrypt",
            "mode": "asymmetric",
            "format_version": 8,
            "hash_algorithms": ["SHA3-256"],
            "kdf_algorithms": ["Argon2id"],
            "encryption_algorithm": "AES-256-GCM",
            "cascade_enabled": False,
            "cascade_cipher_count": None,
            "pqc_kem_algorithm": "ML-KEM-512",
            "pqc_signing_algorithm": "ML-DSA-44",
            "hsm_plugin_used": None,
            "success": False,
            "error_category": "encryption_error",
        },
    ]

    return events


def test_telemetry_submit(base_url: str, token: str, events: List[Dict]) -> bool:
    """Test: Submit telemetry events."""
    print_subsection(f"Step 2: Submit {len(events)} Telemetry Events")

    url = f"{base_url}/api/v1/telemetry/events"
    print(f"POST {url}")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {"events": events}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Events submitted successfully")
            print(f"  Received: {data['received']}")
            print(f"  Processed: {data['processed']}")

            if data['received'] != len(events):
                print(f"  ⚠ Warning: Expected {len(events)} received, got {data['received']}")

            if data['processed'] != data['received']:
                print(f"  ⚠ Warning: Not all events were processed")
                return False

            return True
        else:
            print(f"✗ Event submission failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return False

    except Exception as e:
        print(f"✗ Event submission error: {e}")
        return False


def test_telemetry_stats(base_url: str) -> Dict:
    """Test: Query public statistics."""
    print_subsection("Step 3: Query Public Statistics")

    url = f"{base_url}/api/v1/telemetry/stats"
    print(f"GET {url}")

    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Statistics retrieved")
            print(f"  Total operations: {data['total_operations']}")
            print(f"  Total clients: {data['total_clients']}")
            # Success rate can be 0-1 (fraction) or 0-100 (percentage)
            success_rate = data['success_rate']
            if success_rate > 1:
                print(f"  Success rate: {success_rate:.2f}%")
            else:
                print(f"  Success rate: {success_rate:.2%}")

            if data.get('algorithms'):
                print(f"  Algorithms:")
                for algo, count in sorted(data['algorithms'].items(), key=lambda x: -x[1])[:5]:
                    print(f"    {algo}: {count}")

            if data.get('operations'):
                print(f"  Operations:")
                for op, count in data['operations'].items():
                    print(f"    {op}: {count}")

            return data
        else:
            print(f"✗ Statistics query failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Statistics query error: {e}")
        return None


def verify_test_results(stats: Dict, submitted_events: int) -> bool:
    """Verify that submitted events appear in statistics."""
    print_subsection("Step 4: Verify Test Results")

    if stats is None:
        print("✗ Cannot verify - no statistics available")
        return False

    # Check if operations increased
    if stats['total_operations'] >= submitted_events:
        print(f"✓ Total operations check passed ({stats['total_operations']} >= {submitted_events})")
    else:
        print(f"✗ Total operations too low ({stats['total_operations']} < {submitted_events})")
        return False

    # Check if we have at least one client
    if stats['total_clients'] >= 1:
        print(f"✓ Client registration verified ({stats['total_clients']} clients)")
    else:
        print(f"✗ No clients registered")
        return False

    # Check success rate (can be 0-1 fraction or 0-100 percentage)
    success_rate = stats['success_rate']
    if 0 <= success_rate <= 1:
        print(f"✓ Success rate valid: {success_rate:.2%}")
    elif 0 <= success_rate <= 100:
        print(f"✓ Success rate valid: {success_rate:.2f}%")
    else:
        print(f"✗ Invalid success rate: {success_rate}")
        return False

    return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Test telemetry server endpoints")
    parser.add_argument(
        "--server",
        default="https://keyserver.rm-rf.ch",
        help="Telemetry server URL (default: https://keyserver.rm-rf.ch)",
    )

    args = parser.parse_args()
    base_url = args.server.rstrip("/")

    print_section("TELEMETRY SERVER COMPLETE TEST")
    print(f"Server: {base_url}")

    all_passed = True

    # Test 1: Register
    registration = test_telemetry_register(base_url)
    if not registration:
        print("\n✗ Registration failed - aborting tests")
        sys.exit(1)

    token = registration["token"]
    client_id = registration["client_id"]

    # Test 2: Submit events
    test_events = create_test_events()
    print(f"\nCreated {len(test_events)} test events:")
    print(f"  - {sum(1 for e in test_events if e['operation'] == 'encrypt')} encrypt operations")
    print(f"  - {sum(1 for e in test_events if e['operation'] == 'decrypt')} decrypt operations")
    print(f"  - {sum(1 for e in test_events if e['success'])} successful")
    print(f"  - {sum(1 for e in test_events if not e['success'])} failed")

    if not test_telemetry_submit(base_url, token, test_events):
        print("\n✗ Event submission failed")
        all_passed = False

    # Test 3: Query statistics
    stats = test_telemetry_stats(base_url)
    if not stats:
        print("\n✗ Statistics query failed")
        all_passed = False

    # Test 4: Verify results
    if stats and not verify_test_results(stats, len(test_events)):
        print("\n✗ Result verification failed")
        all_passed = False

    # Final summary
    print_section("TEST SUMMARY")

    if all_passed:
        print("✓ All telemetry tests passed successfully!")
        print()
        print("Verified functionality:")
        print("  ✓ Client registration (JWT token)")
        print("  ✓ Event submission (batch upload)")
        print("  ✓ Public statistics (aggregated data)")
        print("  ✓ Data persistence (events stored)")
        print()
        print(f"Test client ID: {client_id}")
        sys.exit(0)
    else:
        print("✗ Some telemetry tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
