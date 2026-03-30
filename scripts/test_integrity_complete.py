#!/usr/bin/env python3
"""
Complete Integrity Server Test Script

Tests the integrity server with mTLS authentication:
1. Get/create client profile
2. Store metadata hash
3. List hashes
4. Get specific hash
5. Verify hash
6. Update hash
7. Delete hash

Configuration:
    Uses ~/.openssl_encrypt/plugins/integrity/integrity.json for:
    - Server URL
    - Client certificate path
    - Client key path

Usage:
    python3 test_integrity_complete.py

Requirements:
    - Client certificate and key for mTLS
    - Integrity plugin configured
"""

import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, Optional

import requests


def load_integrity_config() -> Optional[Dict]:
    """
    Load integrity config from standard location.

    Returns:
        Config dict or None if not found
    """
    config_path = (
        Path.home() / ".openssl_encrypt" / "plugins" / "integrity" / "integrity.json"
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

    url = f"{base_url}/api/v1/integrity/profile"
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
            print(f"  Hash count: {data.get('hash_count', 0)}")
            print(f"  Created: {data.get('created_at', 'N/A')}")
            return data
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_store_hash(base_url: str, cert: tuple) -> Dict:
    """Test: Store metadata hash."""
    print_subsection("Step 2: Store Metadata Hash")

    url = f"{base_url}/api/v1/integrity/hashes"
    print(f"POST {url}")

    # Generate test hash
    test_file_id = hashlib.sha256(b"test-file.enc").hexdigest()
    test_metadata_hash = hashlib.sha256(b"test-metadata-content").hexdigest()

    payload = {
        "file_id": test_file_id,
        "metadata_hash": test_metadata_hash,
        "description": "Test encrypted file for integration testing",
    }

    try:
        response = requests.post(url, json=payload, cert=cert, timeout=10)

        if response.status_code in [200, 201]:
            data = response.json()
            print(f"✓ Hash stored")
            print(f"  File ID: {data.get('file_id')[:40]}...")
            print(f"  Metadata hash: {data.get('metadata_hash')[:40]}...")
            print(f"  Description: {data.get('description')}")
            return data
        elif response.status_code == 409:
            print(f"⚠ Hash already exists (continuing...)")
            return {
                "file_id": test_file_id,
                "metadata_hash": test_metadata_hash,
                "exists": True,
            }
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_list_hashes(base_url: str, cert: tuple) -> Dict:
    """Test: List all hashes."""
    print_subsection("Step 3: List Metadata Hashes")

    url = f"{base_url}/api/v1/integrity/hashes"
    print(f"GET {url}")

    try:
        response = requests.get(url, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Hashes listed")
            print(f"  Total count: {data.get('total', 0)}")

            if data.get("hashes"):
                print(f"  Hashes:")
                for h in data["hashes"][:5]:  # Show first 5
                    file_id_short = h["file_id"][:20] + "..."
                    print(
                        f"    - {file_id_short}: {h.get('description', 'No description')}"
                    )

            return data
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_get_hash(base_url: str, cert: tuple, file_id: str) -> Dict:
    """Test: Get specific hash."""
    print_subsection(f"Step 4: Get Hash for File")

    url = f"{base_url}/api/v1/integrity/hashes/{file_id}"
    print(f"GET {url}")
    print(f"  File ID: {file_id[:40]}...")

    try:
        response = requests.get(url, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Hash retrieved")
            print(f"  File ID: {data.get('file_id')[:40]}...")
            print(f"  Metadata hash: {data.get('metadata_hash')[:40]}...")
            print(f"  Description: {data.get('description')}")
            print(f"  Verification count: {data.get('verification_count', 0)}")
            return data
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_verify_hash(
    base_url: str, cert: tuple, file_id: str, metadata_hash: str
) -> Dict:
    """Test: Verify hash."""
    print_subsection(f"Step 5: Verify Metadata Hash")

    url = f"{base_url}/api/v1/integrity/verify"
    print(f"POST {url}")

    payload = {"file_id": file_id, "metadata_hash": metadata_hash}

    try:
        response = requests.post(url, json=payload, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Verification result")
            print(f"  Valid: {data.get('valid')}")
            print(f"  Message: {data.get('message')}")
            return data
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_update_hash(base_url: str, cert: tuple, file_id: str) -> Dict:
    """Test: Update hash."""
    print_subsection(f"Step 6: Update Metadata Hash")

    url = f"{base_url}/api/v1/integrity/hashes/{file_id}"
    print(f"PUT {url}")

    # Generate new metadata hash
    new_metadata_hash = hashlib.sha256(b"updated-metadata-content").hexdigest()

    payload = {
        "metadata_hash": new_metadata_hash,
        "description": "Updated test encrypted file",
    }

    try:
        response = requests.put(url, json=payload, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Hash updated")
            print(f"  File ID: {data.get('file_id')[:40]}...")
            print(f"  New metadata hash: {data.get('metadata_hash')[:40]}...")
            print(f"  Description: {data.get('description')}")
            return data
        else:
            print(f"✗ Failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def test_delete_hash(base_url: str, cert: tuple, file_id: str) -> bool:
    """Test: Delete hash."""
    print_subsection(f"Step 7: Delete Metadata Hash")

    url = f"{base_url}/api/v1/integrity/hashes/{file_id}"
    print(f"DELETE {url}")

    try:
        response = requests.delete(url, cert=cert, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print(f"✓ Hash deleted")
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
    print_section("INTEGRITY SERVER COMPLETE TEST")

    # Load config
    config = load_integrity_config()
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

    # Test 2: Store hash
    stored_hash = test_store_hash(base_url, cert)
    if not stored_hash:
        print("\n✗ Store hash failed")
        all_passed = False

    file_id = stored_hash.get("file_id") if stored_hash else None
    metadata_hash = stored_hash.get("metadata_hash") if stored_hash else None

    # Test 3: List hashes
    hash_list = test_list_hashes(base_url, cert)
    if not hash_list:
        print("\n✗ List hashes failed")
        all_passed = False

    # Test 4: Get hash
    if file_id:
        hash_detail = test_get_hash(base_url, cert, file_id)
        if not hash_detail:
            print("\n✗ Get hash failed")
            all_passed = False

    # Test 5: Verify hash
    if file_id and metadata_hash:
        verified = test_verify_hash(base_url, cert, file_id, metadata_hash)
        if not verified:
            print("\n✗ Verify hash failed")
            all_passed = False

    # Test 6: Update hash
    if file_id:
        updated = test_update_hash(base_url, cert, file_id)
        if not updated:
            print("\n✗ Update hash failed")
            all_passed = False

    # Test 7: Delete hash
    if file_id:
        deleted = test_delete_hash(base_url, cert, file_id)
        if not deleted:
            print("\n✗ Delete hash failed")
            all_passed = False

    # Final summary
    print_section("TEST SUMMARY")

    if all_passed:
        print("✓ All integrity server tests passed!")
        print()
        print("Verified functionality:")
        print("  ✓ mTLS authentication")
        print("  ✓ Client profile retrieval")
        print("  ✓ Hash storage")
        print("  ✓ Hash listing")
        print("  ✓ Hash retrieval")
        print("  ✓ Hash verification")
        print("  ✓ Hash update")
        print("  ✓ Hash deletion")
        sys.exit(0)
    else:
        print("✗ Some integrity server tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
