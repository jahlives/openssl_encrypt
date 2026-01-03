#!/usr/bin/env python3
"""
Keyserver Plugin - Fetch and upload public keys from/to remote keyserver.

This plugin provides secure, opt-in key distribution via a remote keyserver.

SECURITY GUARANTEES:
- Plugin NEVER receives private keys or passwords
- Plugin ONLY receives identifier strings for search
- Plugin ONLY returns PublicKeyBundle (public keys)
- All bundles verified before caching or returning
- API token required for uploads (Bearer token authentication)
- Download/search is public (no authentication)

Features:
- Fetch public keys by fingerprint/name/email
- Upload own identity to keyserver (requires API token)
- Revoke keys (requires API token)
- SQLite cache with TTL
- HTTPS-only communication
"""

import hashlib
import logging
import ssl
from typing import Optional, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from ...modules.key_bundle import PublicKeyBundle
from ...modules.plugin_system.plugin_base import BasePlugin, PluginCapability, PluginType
from .cache import KeyserverCache
from .config import KeyserverConfig

logger = logging.getLogger(__name__)


class CertPinningAdapter(HTTPAdapter):
    """
    HTTPAdapter that validates server certificate fingerprints.

    Implements certificate pinning by comparing the server's certificate
    SHA-256 fingerprint against a list of expected fingerprints.
    """

    def __init__(self, expected_fingerprints: list, *args, **kwargs):
        """
        Initialize adapter with expected certificate fingerprints.

        Args:
            expected_fingerprints: List of SHA-256 fingerprints (hex strings)
        """
        self.expected_fingerprints = [fp.lower().replace(":", "") for fp in expected_fingerprints]
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        """Initialize pool manager with custom SSL context."""
        kwargs['assert_hostname'] = True
        kwargs['cert_reqs'] = ssl.CERT_REQUIRED
        return super().init_poolmanager(*args, **kwargs)

    def cert_verify(self, conn, url, verify, cert):
        """Verify certificate fingerprint after standard SSL verification."""
        # First do standard SSL verification
        super().cert_verify(conn, url, verify, cert)

        # Then verify certificate pinning
        if not self.expected_fingerprints:
            return  # No pinning configured

        # Get the peer certificate
        sock = conn.sock
        if sock is None:
            raise ssl.SSLError("No socket connection available for certificate pinning")

        try:
            # Get DER-encoded certificate
            cert_der = sock.getpeercert(binary_form=True)
            if cert_der is None:
                raise ssl.SSLError("Could not retrieve peer certificate")

            # Compute SHA-256 fingerprint
            fingerprint = hashlib.sha256(cert_der).hexdigest()

            # Validate against expected fingerprints
            if fingerprint not in self.expected_fingerprints:
                raise ssl.SSLError(
                    f"Certificate pinning failed: fingerprint {fingerprint} not in expected list"
                )

            logger.debug(f"Certificate pinning validated: {fingerprint}")

        except ssl.SSLError:
            raise
        except Exception as e:
            raise ssl.SSLError(f"Certificate pinning validation failed: {e}")


class KeyserverError(Exception):
    """Base exception for keyserver operations"""

    pass


class NetworkError(KeyserverError):
    """Raised when network request fails"""

    pass


class AuthenticationError(KeyserverError):
    """Raised when API token authentication fails"""

    pass


class KeyserverPlugin(BasePlugin):
    """
    Main keyserver plugin implementation.

    This plugin:
    1. Fetches public keys from remote keyserver
    2. Caches keys locally with TTL
    3. Uploads keys to keyserver (requires API token)
    4. Verifies all bundles before use

    SECURITY:
    - Only receives identifier strings
    - Only returns PublicKeyBundle (public keys)
    - Never accesses private keys or passwords
    - All bundles verified before returning
    """

    def __init__(self, config: Optional[KeyserverConfig] = None):
        """
        Initialize keyserver plugin.

        Args:
            config: Optional configuration object
        """
        # Initialize base plugin
        super().__init__(
            plugin_id="openssl_encrypt_keyserver",
            name="OpenSSL Encrypt Keyserver",
            version="1.0.0",
        )

        # Configuration
        if config is None:
            config = KeyserverConfig.from_file()
        self.config = config

        # Cache
        self.cache = KeyserverCache(
            cache_path=self.config.cache_path,
            max_entries=self.config.cache_max_entries,
            ttl_seconds=self.config.cache_ttl_seconds,
        )

        # Create requests session with certificate pinning if enabled
        self.session = requests.Session()
        if self.config.enable_cert_pinning and self.config.cert_fingerprints:
            adapter = CertPinningAdapter(self.config.cert_fingerprints)
            self.session.mount("https://", adapter)
            logger.info(
                f"Certificate pinning enabled with {len(self.config.cert_fingerprints)} fingerprints"
            )
        else:
            logger.debug("Certificate pinning not enabled")

        logger.info(f"Initialized keyserver plugin (enabled={self.config.enabled})")

    def get_required_capabilities(self) -> Set[PluginCapability]:
        """
        Return required capabilities for this plugin.

        Returns:
            Set of PluginCapability
        """
        return {
            PluginCapability.NETWORK_ACCESS,  # Fetch from/upload to keyserver
            PluginCapability.ACCESS_CONFIG,  # Read plugin configuration
            PluginCapability.WRITE_LOGS,  # Logging
        }

    def get_plugin_type(self) -> PluginType:
        """
        Return plugin type.

        Returns:
            PluginType.KEYSERVER
        """
        return PluginType.KEYSERVER

    def get_description(self) -> str:
        """
        Return human-readable description of plugin functionality.

        Returns:
            Plugin description string
        """
        return (
            "Keyserver plugin for fetching and uploading public keys. "
            "Supports caching, API token authentication, and key verification."
        )

    def execute(self, context: PluginSecurityContext) -> PluginResult:
        """
        Execute keyserver plugin based on context.

        For keyserver plugins, the main operations (fetch, upload, revoke)
        are called directly rather than through execute(). This method exists
        to satisfy the BasePlugin interface.

        Returns:
            PluginResult indicating plugin is active
        """
        return PluginResult.success_result("Keyserver plugin active")

    def fetch_key(self, identifier: str) -> Optional[PublicKeyBundle]:
        """
        Fetch public key bundle by identifier.

        SECURITY: Receives ONLY identifier string (fingerprint/name/email).
        Returns ONLY PublicKeyBundle (public keys). Never receives or returns
        private keys.

        Resolution order:
        1. Check cache (fast)
        2. Fetch from keyservers (slow)
        3. Verify signature before returning

        Args:
            identifier: Fingerprint, name, or email to search for

        Returns:
            PublicKeyBundle if found and verified, None otherwise

        Note:
            - Returns None if plugin disabled
            - Returns None if key not found
            - Returns None if signature verification fails
        """
        if not self.config.enabled:
            logger.debug("Keyserver plugin disabled, returning None")
            return None

        # Priority 1: Check cache
        cached_bundle = self.cache.get(identifier)
        if cached_bundle:
            logger.debug(f"Found '{identifier}' in cache")
            return cached_bundle

        # Priority 2: Fetch from keyservers
        logger.debug(f"Cache miss for '{identifier}', fetching from keyservers")

        for server in self.config.servers:
            try:
                bundle = self._fetch_from_server(server, identifier)

                if bundle:
                    # CRITICAL: Verify signature before caching or returning
                    try:
                        if bundle.verify_signature():
                            # Cache for future use
                            self.cache.put(bundle)
                            logger.info(
                                f"Fetched and verified bundle for '{identifier}' from {server}"
                            )
                            return bundle
                        else:
                            logger.warning(
                                f"Signature verification failed for bundle from {server}"
                            )
                    except Exception as e:
                        logger.error(f"Signature verification failed: {e}")

            except NetworkError as e:
                logger.warning(f"Failed to fetch from {server}: {e}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error fetching from {server}: {e}")
                continue

        logger.info(f"Key not found for '{identifier}' on any keyserver")
        return None

    def _fetch_from_server(self, server_url: str, identifier: str) -> Optional[PublicKeyBundle]:
        """
        Fetch bundle from specific keyserver.

        Args:
            server_url: Keyserver base URL (e.g., "https://keys.example.com")
            identifier: Fingerprint, name, or email to search for

        Returns:
            PublicKeyBundle if found (unverified), None otherwise

        Raises:
            NetworkError: If network request fails
        """
        # Build search URL
        search_url = f"{server_url}/api/v1/keys/search"
        params = {"q": identifier}

        try:
            # HTTP GET (public, no authentication)
            response = self.session.get(
                search_url,
                params=params,
                timeout=(self.config.connect_timeout_seconds, self.config.read_timeout_seconds),
            )

            # Handle response
            if response.status_code == 200:
                data = response.json()

                if "key" in data and data["key"]:
                    # Deserialize bundle
                    bundle = PublicKeyBundle.from_dict(data["key"])
                    return bundle
                else:
                    # Key not found
                    return None

            elif response.status_code == 404:
                # Key not found
                return None

            else:
                raise NetworkError(
                    f"Keyserver returned status {response.status_code}: {response.text}"
                )

        except requests.exceptions.Timeout:
            raise NetworkError("Request timeout")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection failed: {e}")
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Request failed: {e}")
        except Exception as e:
            raise NetworkError(f"Unexpected error: {e}")

    def register(self, server_url: Optional[str] = None) -> dict:
        """
        Register with keyserver and obtain JWT token.

        This creates a new client registration on the keyserver and returns
        a JWT token that can be used for authenticated operations (upload/revoke).

        Args:
            server_url: Optional specific server URL. If None, uses first configured server.

        Returns:
            dict with keys: client_id, token, expires_at, token_type

        Raises:
            NetworkError: If network request fails
            ValueError: If no servers configured
        """
        if not self.config.enabled:
            raise ValueError("Keyserver plugin disabled")

        # Determine which server to register with
        if server_url is None:
            if not self.config.servers:
                raise ValueError("No keyservers configured")
            server_url = self.config.servers[0]

        register_url = f"{server_url}/api/v1/keys/register"

        try:
            # HTTP POST (no authentication required for registration)
            response = self.session.post(
                register_url,
                timeout=(self.config.connect_timeout_seconds, self.config.read_timeout_seconds),
            )

            if response.status_code == 200:
                data = response.json()
                # Save JWT token to token file
                self.config.save_api_token(data["token"])
                logger.info(f"Registered with keyserver, client_id={data['client_id']}")
                return data
            else:
                raise NetworkError(
                    f"Registration failed with status {response.status_code}: {response.text}"
                )

        except requests.exceptions.Timeout:
            raise NetworkError("Request timeout")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection failed: {e}")
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Request failed: {e}")

    def upload_key(self, bundle: PublicKeyBundle) -> bool:
        """
        Upload public key bundle to keyserver.

        SECURITY: Requires JWT token for authentication (Bearer token).

        Args:
            bundle: PublicKeyBundle to upload

        Returns:
            True if uploaded successfully, False otherwise

        Raises:
            AuthenticationError: If JWT token not set or invalid
            NetworkError: If network request fails
        """
        if not self.config.enabled:
            logger.error("Keyserver plugin disabled")
            return False

        if not self.config.upload_enabled:
            logger.error("Uploads disabled in configuration")
            return False

        # Get JWT token
        api_token = self.config.load_api_token()
        if not api_token:
            raise AuthenticationError(
                "JWT token not set. Use 'openssl-encrypt keyserver register' to register and obtain token."
            )

        # Verify bundle signature before uploading
        try:
            if not bundle.verify_signature():
                logger.error("Cannot upload bundle with invalid signature")
                return False
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

        # Upload to all configured servers
        success = False
        for server in self.config.servers:
            try:
                if self._upload_to_server(server, bundle, api_token):
                    logger.info(f"Uploaded bundle to {server}")
                    success = True
                else:
                    logger.warning(f"Failed to upload to {server}")

            except Exception as e:
                logger.error(f"Failed to upload to {server}: {e}")

        return success

    def _upload_to_server(self, server_url: str, bundle: PublicKeyBundle, api_token: str) -> bool:
        """
        Upload bundle to specific keyserver.

        Args:
            server_url: Keyserver base URL
            bundle: PublicKeyBundle to upload
            api_token: API token for authentication

        Returns:
            True if uploaded successfully

        Raises:
            AuthenticationError: If authentication fails
            NetworkError: If network request fails
        """
        upload_url = f"{server_url}/api/v1/keys"

        # Serialize bundle
        data = bundle.to_dict()

        # Headers with Bearer token
        headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

        try:
            # HTTP POST (requires authentication)
            response = self.session.post(
                upload_url,
                json=data,
                headers=headers,
                timeout=(self.config.connect_timeout_seconds, self.config.read_timeout_seconds),
            )

            if response.status_code == 200:
                return True
            elif response.status_code == 401:
                raise AuthenticationError("Invalid API token")
            elif response.status_code == 409:
                logger.warning("Key already exists on server")
                return False
            else:
                raise NetworkError(
                    f"Upload failed with status {response.status_code}: {response.text}"
                )

        except requests.exceptions.Timeout:
            raise NetworkError("Request timeout")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection failed: {e}")
        except AuthenticationError:
            raise
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Request failed: {e}")

    def revoke_key(self, fingerprint: str, signature: bytes) -> bool:
        """
        Revoke key on keyserver.

        SECURITY: Requires JWT token for authentication (Bearer token).
        Also requires revocation signature to prove ownership.

        Args:
            fingerprint: Fingerprint of key to revoke
            signature: Revocation signature (signed by key being revoked)

        Returns:
            True if revoked successfully

        Raises:
            AuthenticationError: If JWT token not set or invalid
            NetworkError: If network request fails
        """
        if not self.config.enabled:
            logger.error("Keyserver plugin disabled")
            return False

        # Get JWT token
        api_token = self.config.load_api_token()
        if not api_token:
            raise AuthenticationError(
                "JWT token not set. Use 'openssl-encrypt keyserver register' to register and obtain token."
            )

        # Revoke on all configured servers
        success = False
        for server in self.config.servers:
            try:
                revoke_url = f"{server}/api/v1/keys/{fingerprint}/revoke"

                # Headers with Bearer token
                headers = {
                    "Authorization": f"Bearer {api_token}",
                    "Content-Type": "application/json",
                }

                # Data with revocation signature
                data = {"signature": signature.hex()}

                # HTTP POST (requires authentication)
                response = self.session.post(
                    revoke_url,
                    json=data,
                    headers=headers,
                    timeout=(
                        self.config.connect_timeout_seconds,
                        self.config.read_timeout_seconds,
                    ),
                )

                if response.status_code == 200:
                    logger.info(f"Revoked key {fingerprint} on {server}")
                    success = True
                elif response.status_code == 401:
                    raise AuthenticationError("Invalid API token")
                elif response.status_code == 404:
                    logger.warning(f"Key {fingerprint} not found on {server}")
                else:
                    logger.warning(
                        f"Revocation failed on {server} with status {response.status_code}"
                    )

            except Exception as e:
                logger.error(f"Failed to revoke on {server}: {e}")

        return success

    def clear_cache(self) -> int:
        """
        Clear all cached entries.

        Returns:
            Number of entries cleared
        """
        return self.cache.clear_all()

    def get_cache_stats(self) -> dict:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        return self.cache.get_stats()


if __name__ == "__main__":
    # Simple test
    print("KeyserverPlugin module loaded successfully")
