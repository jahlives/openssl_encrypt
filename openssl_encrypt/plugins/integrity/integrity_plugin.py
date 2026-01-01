#!/usr/bin/env python3
"""
OpenSSL Encrypt Integrity Plugin - Client implementation.

This plugin provides integrity verification for encrypted file metadata by storing
and verifying SHA-256 hashes on a remote server with mTLS authentication.

FEATURES:
- Store metadata hashes for encrypted files
- Verify file integrity before decryption
- Batch verification support (up to 100 files)
- Tamper detection with comprehensive audit logging
- Profile management and statistics

SECURITY:
- mTLS authentication with client certificates
- HTTPS-only connections
- No sensitive data transmitted (only SHA-256 hashes)
- Auto-registration on first connection
- OPT-IN by default (enabled=False in config)
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from .config import IntegrityConfig

logger = logging.getLogger(__name__)


class IntegrityPluginError(Exception):
    """Base exception for integrity plugin errors"""

    pass


class IntegrityVerificationError(Exception):
    """Raised when integrity verification fails"""

    pass


class IntegrityPlugin:
    """
    Client plugin for integrity verification operations.

    This plugin communicates with the integrity server to:
    - Store metadata hashes for encrypted files
    - Verify file integrity by comparing stored and current hashes
    - Manage client profile and view statistics

    All operations require mTLS authentication.
    """

    def __init__(self, config: Optional[IntegrityConfig] = None):
        """
        Initialize integrity plugin.

        Args:
            config: IntegrityConfig instance (default: load from file)

        Raises:
            IntegrityPluginError: If config is invalid or plugin not enabled
        """
        if config is None:
            config = IntegrityConfig.from_file()

        if not config.enabled:
            raise IntegrityPluginError(
                "Integrity plugin is disabled. Set enabled=true in config and provide mTLS certificates."
            )

        self.config = config
        self._session: Optional[requests.Session] = None

        logger.info(f"Initialized integrity plugin: {config.server_url}")

    def _get_session(self) -> requests.Session:
        """Get or create requests session with mTLS configuration."""
        if self._session is None:
            self._session = requests.Session()

            # Configure mTLS client certificates
            if self.config.client_cert and self.config.client_key:
                self._session.cert = (str(self.config.client_cert), str(self.config.client_key))

            # Configure CA cert for server verification
            if self.config.ca_cert:
                self._session.verify = str(self.config.ca_cert)
            else:
                # Default to system CA bundle
                self._session.verify = True

            # Set timeouts
            self._session.timeout = (self.config.connect_timeout_seconds, self.config.read_timeout_seconds)

        return self._session

    def _make_request(
        self, method: str, endpoint: str, json_data: Optional[Dict] = None, params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Make HTTP request to integrity server.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., "/hashes")
            json_data: JSON request body (optional)
            params: Query parameters (optional)

        Returns:
            Response JSON data

        Raises:
            IntegrityPluginError: If request fails
        """
        url = f"{self.config.server_url}/api/v1/integrity{endpoint}"
        session = self._get_session()

        try:
            response = session.request(method=method, url=url, json=json_data, params=params)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.SSLError as e:
            raise IntegrityPluginError(f"mTLS authentication failed: {e}. Check your client certificates.")
        except requests.exceptions.Timeout as e:
            raise IntegrityPluginError(f"Request timeout: {e}")
        except requests.exceptions.RequestException as e:
            raise IntegrityPluginError(f"Request failed: {e}")
        except json.JSONDecodeError as e:
            raise IntegrityPluginError(f"Invalid JSON response: {e}")

    # Profile Management

    def get_profile(self) -> Dict[str, Any]:
        """
        Get client profile information.

        Auto-registers client on first request.

        Returns:
            Profile data with:
            - cert_fingerprint: Client certificate fingerprint
            - cert_dn: Certificate distinguished name
            - name: Display name (if set)
            - created_at: Registration timestamp
            - last_seen_at: Last activity timestamp
            - hash_count: Number of stored hashes

        Raises:
            IntegrityPluginError: If request fails
        """
        return self._make_request("GET", "/profile")

    def update_profile(self, name: str) -> Dict[str, Any]:
        """
        Update client profile.

        Args:
            name: Display name (1-255 characters)

        Returns:
            Updated profile data

        Raises:
            IntegrityPluginError: If request fails or name invalid
        """
        if not name or len(name) > 255:
            raise IntegrityPluginError("Name must be 1-255 characters")

        return self._make_request("PUT", "/profile", json_data={"name": name})

    # Hash Storage

    def store_hash(
        self, file_id: str, metadata_hash: str, algorithm: Optional[str] = None, description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Store metadata hash for a file.

        Args:
            file_id: Unique file identifier (e.g., SHA-256 of filename or path)
            metadata_hash: SHA-256 hash of encrypted file metadata (64 hex chars)
            algorithm: Encryption algorithm used (optional, max 50 chars)
            description: Description/notes (optional, max 1000 chars)

        Returns:
            Stored hash data with timestamps and verification count

        Raises:
            IntegrityPluginError: If request fails or parameters invalid
        """
        # Validate inputs
        if not file_id or len(file_id) > 128:
            raise IntegrityPluginError("file_id must be 1-128 characters")
        if len(metadata_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in metadata_hash):
            raise IntegrityPluginError("metadata_hash must be 64 hex characters (SHA-256)")
        if algorithm and len(algorithm) > 50:
            raise IntegrityPluginError("algorithm must be max 50 characters")
        if description and len(description) > 1000:
            raise IntegrityPluginError("description must be max 1000 characters")

        request_data = {
            "file_id": file_id,
            "metadata_hash": metadata_hash.lower(),  # Normalize to lowercase
        }
        if algorithm:
            request_data["algorithm"] = algorithm
        if description:
            request_data["description"] = description

        return self._make_request("POST", "/hashes", json_data=request_data)

    def get_hash(self, file_id: str) -> Dict[str, Any]:
        """
        Get stored hash for a file.

        Args:
            file_id: File identifier

        Returns:
            Hash data with metadata and verification stats

        Raises:
            IntegrityPluginError: If file not found or request fails
        """
        return self._make_request("GET", f"/hashes/{file_id}")

    def list_hashes(self) -> Dict[str, Any]:
        """
        List all stored hashes for this client.

        Returns:
            Dictionary with:
            - hashes: List of hash records
            - total: Total count

        Raises:
            IntegrityPluginError: If request fails
        """
        return self._make_request("GET", "/hashes")

    def update_hash(
        self, file_id: str, metadata_hash: str, description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update stored hash for a file.

        Args:
            file_id: File identifier
            metadata_hash: New SHA-256 hash (64 hex chars)
            description: Updated description (optional)

        Returns:
            Updated hash data

        Raises:
            IntegrityPluginError: If file not found or parameters invalid
        """
        if len(metadata_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in metadata_hash):
            raise IntegrityPluginError("metadata_hash must be 64 hex characters (SHA-256)")
        if description and len(description) > 1000:
            raise IntegrityPluginError("description must be max 1000 characters")

        request_data = {"metadata_hash": metadata_hash.lower()}
        if description is not None:  # Allow empty string to clear description
            request_data["description"] = description

        return self._make_request("PUT", f"/hashes/{file_id}", json_data=request_data)

    def delete_hash(self, file_id: str) -> Dict[str, Any]:
        """
        Delete stored hash for a file.

        Args:
            file_id: File identifier

        Returns:
            Deletion confirmation

        Raises:
            IntegrityPluginError: If file not found or request fails
        """
        return self._make_request("DELETE", f"/hashes/{file_id}")

    def delete_all_hashes(self) -> Dict[str, Any]:
        """
        Delete all stored hashes for this client.

        WARNING: This cannot be undone!

        Returns:
            Dictionary with:
            - message: Confirmation message
            - deleted_count: Number of hashes deleted

        Raises:
            IntegrityPluginError: If request fails
        """
        return self._make_request("DELETE", "/hashes")

    # Integrity Verification

    def verify(self, file_id: str, metadata_hash: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify file integrity by comparing hashes.

        Args:
            file_id: File identifier
            metadata_hash: Current SHA-256 hash to verify

        Returns:
            Tuple of (match: bool, details: dict)
            - match: True if hashes match, False if mismatch or not found
            - details: Full verification response with stored hash and warning

        Raises:
            IntegrityPluginError: If request fails
        """
        if len(metadata_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in metadata_hash):
            raise IntegrityPluginError("metadata_hash must be 64 hex characters (SHA-256)")

        request_data = {"file_id": file_id, "metadata_hash": metadata_hash.lower()}

        response = self._make_request("POST", "/verify", json_data=request_data)

        match = response.get("match", False)
        if not match and response.get("warning"):
            logger.warning(f"INTEGRITY VIOLATION for {file_id}: {response['warning']}")

        return match, response

    def verify_batch(self, verifications: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Verify integrity of multiple files at once.

        Args:
            verifications: List of dicts with "file_id" and "metadata_hash" keys
                          Maximum 100 files per batch

        Returns:
            Dictionary with:
            - results: List of verification results
            - total: Total files verified
            - matches: Number of successful matches
            - mismatches: Number of integrity violations

        Raises:
            IntegrityPluginError: If request fails or batch too large
        """
        if not verifications:
            raise IntegrityPluginError("verifications list cannot be empty")
        if len(verifications) > 100:
            raise IntegrityPluginError("Maximum 100 files per batch")

        # Validate and normalize all hashes
        normalized_verifications = []
        for v in verifications:
            if "file_id" not in v or "metadata_hash" not in v:
                raise IntegrityPluginError("Each verification must have 'file_id' and 'metadata_hash'")

            hash_value = v["metadata_hash"]
            if len(hash_value) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hash_value):
                raise IntegrityPluginError(f"Invalid hash for {v['file_id']}: must be 64 hex characters")

            normalized_verifications.append({"file_id": v["file_id"], "metadata_hash": hash_value.lower()})

        request_data = {"verifications": normalized_verifications}
        response = self._make_request("POST", "/verify/batch", json_data=request_data)

        # Log any mismatches
        if response.get("mismatches", 0) > 0:
            logger.warning(f"BATCH VERIFICATION: {response['mismatches']} integrity violations detected!")
            for result in response.get("results", []):
                if not result.get("match") and result.get("warning"):
                    logger.warning(f"  - {result['file_id']}: {result['warning']}")

        return response

    # Statistics

    def get_stats(self) -> Dict[str, Any]:
        """
        Get integrity verification statistics for this client.

        Returns:
            Dictionary with:
            - total_hashes: Total stored hashes
            - total_verifications: Total verification attempts
            - successful_verifications: Successful matches
            - failed_verifications: Integrity violations
            - files_not_found: Verifications where hash not found
            - success_rate: Success rate (0.0-1.0)
            - last_verification: Most recent verification timestamp

        Raises:
            IntegrityPluginError: If request fails
        """
        return self._make_request("GET", "/stats")

    # Utility Methods

    @staticmethod
    def compute_metadata_hash(metadata: bytes) -> str:
        """
        Compute SHA-256 hash of metadata.

        Args:
            metadata: Raw metadata bytes

        Returns:
            64-character hex SHA-256 hash (lowercase)
        """
        return hashlib.sha256(metadata).hexdigest().lower()

    @staticmethod
    def compute_file_id(file_path: Path) -> str:
        """
        Compute file identifier from file path.

        Uses SHA-256 hash of absolute path for consistent identification.

        Args:
            file_path: Path to file

        Returns:
            64-character hex SHA-256 hash of absolute path
        """
        abs_path = str(file_path.resolve())
        return hashlib.sha256(abs_path.encode("utf-8")).hexdigest().lower()

    def close(self):
        """Close HTTP session and cleanup resources."""
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources."""
        self.close()


# Example usage
if __name__ == "__main__":
    # Example: Store and verify file integrity
    config = IntegrityConfig(
        enabled=True,
        server_url="https://integrity.example.com",
        client_cert=Path("~/.openssl_encrypt/integrity/certs/client.crt").expanduser(),
        client_key=Path("~/.openssl_encrypt/integrity/certs/client.key").expanduser(),
        ca_cert=Path("~/.openssl_encrypt/integrity/certs/ca.crt").expanduser(),
    )

    with IntegrityPlugin(config) as plugin:
        # Get profile (auto-registers on first connection)
        profile = plugin.get_profile()
        print(f"Connected as: {profile['cert_fingerprint']}")

        # Store metadata hash
        file_id = IntegrityPlugin.compute_file_id(Path("important_file.txt.enc"))
        metadata_hash = IntegrityPlugin.compute_metadata_hash(b"encrypted metadata here")

        result = plugin.store_hash(file_id, metadata_hash, algorithm="aes-256-gcm", description="Important file")
        print(f"Stored hash: {result['file_id']}")

        # Verify integrity
        match, details = plugin.verify(file_id, metadata_hash)
        if match:
            print("✓ Integrity verified!")
        else:
            print(f"✗ INTEGRITY VIOLATION: {details.get('warning')}")

        # Get statistics
        stats = plugin.get_stats()
        print(f"Verification success rate: {stats['success_rate'] * 100:.1f}%")
