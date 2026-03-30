#!/usr/bin/env python3
"""
Complete Pepper Server Test Script

Tests the pepper server with mTLS authentication:
1. Get/create client profile
2. Create a pepper
3. List peppers
4. Get specific pepper
5. Update pepper
6. Delete pepper

Configuration:
    Uses ~/.openssl_encrypt/plugins/pepper/pepper.json for:
    - Server URL
    - Client certificate path
    - Client key path

Usage:
    python3 test_pepper_complete.py

Requirements:
    - Client certificate and key for mTLS
    - Pepper plugin configured
"""

import base64
import json
import os
import sys
from pathlib import Path
from typing import Dict, Optional

import requests


def load_pepper_config() -> Optional[Dict]:
    """
    Load pepper config from standard location.

    Returns:
        Config dict or None if not found
    """
    config_path = (
        Path.home() / ".openssl_encrypt" / "plugins" / "pepper" / "pepper.json"
    )

    if not config_path.exists():
        print(f"✗ Config file not found: {config_path}")
        print("  Create config file with server_url, client_cert, and client_key")
        return None

    try:
        with open(config_path, "r") as f:
            config = json.load(f)

        # Expand paths
        if config.get("client_cert"):
            config["client_cert"] = str(Path(config["client_cert"]).expanduser())
        if config.get("client_key"):
            config["client_key"] = str(Path(config["client_key"]).expanduser())
        if config.get("ca_cert"):
            config["ca_cert"] = str(Path(config["ca_cert"]).expanduser())

        return config

    except Exception as e:
        print(f"✗ Failed to load config: {e}")
        return None


def print_section(title: str):
    """Print a formatted section header."""
    print(f"\n{'=' * 70}")
    print(f"{title}")
    print(f"{'=' * 70}")


def print_subsection(title: str):
    """Print a formatted subsection header."""
    print(f"\n{title}")
    print("-" * 70)


def test_get_profile(base_url: str, cert: tuple) -> Dict:
    """Test: Get client profile."""
    print_subsection("Step 1: Get Client Profile")

    url = f"{base_url}/api/v1/pepper/profile"
    print(f"GET {url}")

    try:
        response = requests.get(url, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Profile retrieved")
            print(
                f"  Certificate fingerprint: {data.get('cert_fingerprint', 'N/A')[:40]}..."
            )
            print(f"  Name: {data.get('name', 'N/A')}")
            print(f"  Pepper count: {data.get('pepper_count', 0)}")
            print(f"  TOTP enabled: {data.get('totp_enabled', False)}")
            return data
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_create_pepper(base_url: str, cert: tuple) -> Dict:
    """Test: Create a pepper."""
    print_subsection("Step 2: Create Test Pepper")

    url = f"{base_url}/api/v1/pepper/peppers"
    print(f"POST {url}")

    # Create test pepper (encrypted blob)
    test_data = b"This is a test pepper value - keep it secret!"
    encrypted_blob = base64.b64encode(test_data).decode("ascii")

    payload = {
        "name": "test-pepper",
        "description": "Test pepper for integration testing",
        "pepper_encrypted": encrypted_blob,
    }

    try:
        response = requests.post(url, json=payload, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Pepper created")
            print(f"  Name: {data.get('name')}")
            print(f"  Description: {data.get('description')}")
            print(f"  Created: {data.get('created_at')}")
            return data
        elif response.status_code == 409:
            print(f"⚠ Pepper already exists (continuing...)")
            return {"name": "test-pepper", "exists": True}
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_list_peppers(base_url: str, cert: tuple) -> Dict:
    """Test: List all peppers."""
    print_subsection("Step 3: List Peppers")

    url = f"{base_url}/api/v1/pepper/peppers"
    print(f"GET {url}")

    try:
        response = requests.get(url, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Peppers listed")
            print(f"  Total count: {data.get('total', 0)}")

            if data.get("peppers"):
                print(f"  Peppers:")
                for p in data["peppers"][:5]:  # Show first 5
                    print(
                        f"    - {p['name']}: {p.get('description', 'No description')}"
                    )

            return data
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_get_pepper(base_url: str, cert: tuple, name: str) -> Dict:
    """Test: Get specific pepper."""
    print_subsection(f"Step 4: Get Pepper '{name}'")

    url = f"{base_url}/api/v1/pepper/peppers/{name}"
    print(f"GET {url}")

    try:
        response = requests.get(url, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Pepper retrieved")
            print(f"  Name: {data.get('name')}")
            print(f"  Description: {data.get('description')}")
            print(f"  Access count: {data.get('access_count', 0)}")
            print(f"  Last accessed: {data.get('last_accessed_at', 'Never')}")
            print(
                f"  Encrypted pepper size: {len(data.get('pepper_encrypted', ''))} chars"
            )
            return data
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_update_pepper(base_url: str, cert: tuple, name: str) -> Dict:
    """Test: Update pepper."""
    print_subsection(f"Step 5: Update Pepper '{name}'")

    url = f"{base_url}/api/v1/pepper/peppers/{name}"
    print(f"PUT {url}")

    # Update with new encrypted blob and description
    updated_data = b"This is an updated test pepper value!"
    encrypted_blob = base64.b64encode(updated_data).decode("ascii")

    payload = {
        "pepper_encrypted": encrypted_blob,
        "description": "Updated test pepper description",
    }

    try:
        response = requests.put(url, json=payload, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Pepper updated")
            print(f"  Name: {data.get('name')}")
            print(f"  Description: {data.get('description')}")
            return data
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_delete_pepper(base_url: str, cert: tuple, name: str) -> bool:
    """Test: Delete pepper."""
    print_subsection(f"Step 6: Delete Pepper '{name}'")

    url = f"{base_url}/api/v1/pepper/peppers/{name}"
    print(f"DELETE {url}")

    try:
        response = requests.delete(url, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Pepper deleted")
            print(f"  Message: {data.get('message', 'Deleted successfully')}")
            return True
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return False

    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def main():
    """Main entry point."""
    print_section("PEPPER SERVER COMPLETE TEST")

    # Load config
    config = load_pepper_config()
    if not config:
        sys.exit(1)

    base_url = config.get("server_url", "").rstrip("/")
    client_cert = config.get("client_cert")
    client_key = config.get("client_key")

    if not all([base_url, client_cert, client_key]):
        print("✗ Missing required config: server_url, client_cert, client_key")
        sys.exit(1)

    # Check cert files exist
    if not Path(client_cert).exists():
        print(f"✗ Client certificate not found: {client_cert}")
        sys.exit(1)
    if not Path(client_key).exists():
        print(f"✗ Client key not found: {client_key}")
        sys.exit(1)

    print(f"Server: {base_url}")
    print(f"Client cert: {client_cert}")
    print(f"Client key: {client_key}")

    cert = (client_cert, client_key)
    all_passed = True

    # Test 1: Get profile
    profile = test_get_profile(base_url, cert)
    if not profile:
        print("\n✗ Profile test failed")
        all_passed = False

    # Test 2: Create pepper
    pepper = test_create_pepper(base_url, cert)
    if not pepper:
        print("\n✗ Create pepper failed")
        all_passed = False

    # Test 3: List peppers
    pepper_list = test_list_peppers(base_url, cert)
    if not pepper_list:
        print("\n✗ List peppers failed")
        all_passed = False

    # Test 4: Get pepper
    if pepper:
        pepper_detail = test_get_pepper(base_url, cert, "test-pepper")
        if not pepper_detail:
            print("\n✗ Get pepper failed")
            all_passed = False

    # Test 5: Update pepper
    if pepper:
        updated = test_update_pepper(base_url, cert, "test-pepper")
        if not updated:
            print("\n✗ Update pepper failed")
            all_passed = False

    # Test 6: Delete pepper
    if pepper:
        deleted = test_delete_pepper(base_url, cert, "test-pepper")
        if not deleted:
            print("\n✗ Delete pepper failed")
            all_passed = False

    # Final summary
    print_section("TEST SUMMARY")

    if all_passed:
        print("✓ All pepper server tests passed!")
        print()
        print("Verified functionality:")
        print("  ✓ mTLS authentication")
        print("  ✓ Client profile retrieval")
        print("  ✓ Pepper creation")
        print("  ✓ Pepper listing")
        print("  ✓ Pepper retrieval")
        print("  ✓ Pepper update")
        print("  ✓ Pepper deletion")
        sys.exit(0)
    else:
        print("✗ Some pepper server tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
