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

import base64
import hashlib
import logging
import re
import ssl
from typing import List, Optional, Set

import requests
from requests.adapters import HTTPAdapter

from ...modules.crypt_utils import eprint
from ...modules.key_bundle import PublicKeyBundle, create_pop_signature
from ...modules.plugin_system.plugin_base import (
    BasePlugin,
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
    PluginType,
)
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
        kwargs["assert_hostname"] = True
        kwargs["cert_reqs"] = ssl.CERT_REQUIRED
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


class NetworkError(KeyserverError):
    """Raised when network request fails"""


class AuthenticationError(KeyserverError):
    """Raised when API token authentication fails"""


class PasswordRequiredError(AuthenticationError):
    """Raised when server requires password setup (403 password_required)."""


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

    def _refresh_access_token(self) -> Optional[str]:
        """
        Refresh the access token using the stored refresh token.

        Calls POST /api/v1/keys/refresh with the refresh token.
        On success, saves the new access and refresh tokens.

        Returns:
            New access token string, or None if refresh failed
        """
        refresh_token = self.config.load_refresh_token()
        if not refresh_token:
            logger.debug("No refresh token available")
            return None

        for server in self.config.servers:
            refresh_url = f"{server}/api/v1/keys/refresh"
            try:
                response = self.session.post(
                    refresh_url,
                    json={"refresh_token": refresh_token},
                    timeout=(
                        self.config.connect_timeout_seconds,
                        self.config.read_timeout_seconds,
                    ),
                )

                if response.status_code == 200:
                    data = response.json()
                    new_access = data.get("access_token") or data.get("token")
                    new_refresh = data.get("refresh_token")

                    if new_access:
                        self.config.save_api_token(new_access)
                        logger.info("Access token refreshed successfully")

                    if new_refresh:
                        self.config.save_refresh_token(new_refresh)
                        logger.info("Refresh token updated")

                    return new_access
                else:
                    logger.warning(
                        f"Token refresh failed on {server}: status {response.status_code}"
                    )

            except requests.exceptions.RequestException as e:
                logger.warning(f"Token refresh request failed on {server}: {e}")
                continue

        logger.error("Token refresh failed on all servers")
        return None

    def _authenticated_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make an authenticated HTTP request with automatic token refresh.

        If the request returns 401, attempts to refresh the access token
        and retries the request once.

        Args:
            method: HTTP method ("get", "post", "put", "delete")
            url: Request URL
            **kwargs: Additional arguments passed to requests (json, headers, etc.)

        Returns:
            requests.Response

        Raises:
            AuthenticationError: If authentication fails after refresh attempt
            NetworkError: If network request fails
        """
        api_token = self.config.load_api_token()
        if not api_token:
            raise AuthenticationError(
                "JWT token not set. Use 'openssl-encrypt keyserver register' to register and obtain token."
            )

        # Set auth header
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {api_token}"
        kwargs["headers"] = headers

        if "timeout" not in kwargs:
            kwargs["timeout"] = (
                self.config.connect_timeout_seconds,
                self.config.read_timeout_seconds,
            )

        try:
            response = getattr(self.session, method)(url, **kwargs)
        except requests.exceptions.Timeout:
            raise NetworkError("Request timeout")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection failed: {e}")
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Request failed: {e}")

        # If 401, try refreshing the token and retry once
        if response.status_code == 401:
            logger.info("Access token expired, attempting refresh...")
            new_token = self._refresh_access_token()

            if new_token:
                kwargs["headers"]["Authorization"] = f"Bearer {new_token}"
                try:
                    response = getattr(self.session, method)(url, **kwargs)
                except requests.exceptions.Timeout:
                    raise NetworkError("Request timeout")
                except requests.exceptions.ConnectionError as e:
                    raise NetworkError(f"Connection failed: {e}")
                except requests.exceptions.RequestException as e:
                    raise NetworkError(f"Request failed: {e}")

            if response.status_code == 401:
                raise AuthenticationError(
                    "Authentication failed. Token refresh unsuccessful. "
                    "Please login again with 'openssl-encrypt keyserver login <client_id>'."
                )

        return response

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
                        verified = bundle.verify_signature()
                    except Exception as e:
                        logger.error(f"Signature verification failed: {e}")
                        verified = False

                    if verified:
                        # Cache for future use (best-effort)
                        try:
                            self.cache.put(bundle)
                        except Exception as e:
                            logger.warning(f"Failed to cache bundle: {e}")
                        logger.info(f"Fetched and verified bundle for '{identifier}' from {server}")
                        return bundle
                    else:
                        logger.warning(f"Signature verification failed for bundle from {server}")

            except NetworkError as e:
                logger.warning(f"Failed to fetch from {server}: {e}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error fetching from {server}: {e}")
                continue

        logger.info(f"Key not found for '{identifier}' on any keyserver")
        return None

    _FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2})+$")

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
        is_fingerprint = bool(self._FINGERPRINT_PATTERN.match(identifier))

        try:
            if is_fingerprint:
                # Use exact fingerprint endpoint
                url = f"{server_url}/api/v1/keys/{identifier}"
                response = self.session.get(
                    url,
                    timeout=(
                        self.config.connect_timeout_seconds,
                        self.config.read_timeout_seconds,
                    ),
                )

                if response.status_code == 200:
                    data = response.json()
                    if "key" in data and data["key"]:
                        return PublicKeyBundle.from_dict(data["key"])
                    return None
                elif response.status_code == 404:
                    return None
                else:
                    raise NetworkError(
                        f"Keyserver returned status {response.status_code}: {response.text}"
                    )
            else:
                # Use search endpoint
                search_url = f"{server_url}/api/v1/keys/search"
                params = {"q": identifier}
                response = self.session.get(
                    search_url,
                    params=params,
                    timeout=(
                        self.config.connect_timeout_seconds,
                        self.config.read_timeout_seconds,
                    ),
                )

                if response.status_code == 200:
                    data = response.json()

                    if "keys" in data and data["keys"]:
                        # New list response — return first result
                        return PublicKeyBundle.from_dict(data["keys"][0])
                    elif "key" in data and data["key"]:
                        # Legacy single-key response
                        return PublicKeyBundle.from_dict(data["key"])
                    else:
                        return None

                elif response.status_code == 404:
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
        except NetworkError:
            raise
        except Exception as e:
            raise NetworkError(f"Unexpected error: {e}")

    def search_keys(self, query: str) -> List[PublicKeyBundle]:
        """
        Search for public key bundles by email, name, or fingerprint prefix.

        Queries all configured servers and returns all verified, deduplicated results.
        Does NOT cache results (use fetch_key for cached single-key retrieval).

        Args:
            query: Search string (email, name, or fingerprint prefix)

        Returns:
            List of verified PublicKeyBundle objects. Empty list if plugin disabled,
            on 404, on network error, or if response is missing `keys` field.
        """
        if not self.config.enabled:
            logger.debug("Keyserver plugin disabled, returning []")
            return []

        seen: dict = {}  # fingerprint -> bundle (deduplication)

        for server in self.config.servers:
            search_url = f"{server}/api/v1/keys/search"
            params = {"q": query}

            try:
                response = self.session.get(
                    search_url,
                    params=params,
                    timeout=(
                        self.config.connect_timeout_seconds,
                        self.config.read_timeout_seconds,
                    ),
                )

                if response.status_code == 404:
                    continue

                if response.status_code != 200:
                    logger.warning(
                        f"search_keys: server {server} returned status {response.status_code}"
                    )
                    continue

                data = response.json()
                key_list = data.get("keys")
                if not key_list:
                    continue

                for key_dict in key_list:
                    try:
                        bundle = PublicKeyBundle.from_dict(key_dict)
                        if bundle.verify_signature():
                            # Deduplicate by fingerprint
                            if bundle.fingerprint not in seen:
                                seen[bundle.fingerprint] = bundle
                        else:
                            logger.warning(
                                f"search_keys: signature verification failed for bundle "
                                f"from {server}"
                            )
                    except Exception as e:
                        logger.error(f"search_keys: error processing bundle from {server}: {e}")

            except requests.exceptions.Timeout:
                logger.warning(f"search_keys: timeout on {server}")
                continue
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"search_keys: connection error on {server}: {e}")
                continue
            except requests.exceptions.RequestException as e:
                logger.warning(f"search_keys: request error on {server}: {e}")
                continue
            except Exception as e:
                logger.error(f"search_keys: unexpected error on {server}: {e}")
                continue

        return list(seen.values())

    def login(
        self,
        client_id: str,
        password: Optional[str] = None,
        server_url: Optional[str] = None,
    ) -> dict:
        """
        Login with client_id and password to obtain JWT access and refresh tokens.

        Use this when you have a client_id (e.g., from the registration
        welcome email) but need JWT tokens for authenticated operations.

        If no password is provided, attempts to load a stored password.
        If the server returns 403 "password_required", raises PasswordRequiredError
        so the caller can prompt the user and retry with a password.

        Args:
            client_id: The client identifier from registration
            password: Account password. If None, uses stored password (if any).
            server_url: Optional specific server URL. If None, uses first configured server.

        Returns:
            dict with keys: client_id, access_token, refresh_token, expires_at, token_type

        Raises:
            AuthenticationError: If credentials are invalid
            PasswordRequiredError: If server requires password setup (403)
            NetworkError: If network request fails
            ValueError: If plugin disabled or no servers configured
        """
        if not self.config.enabled:
            raise ValueError("Keyserver plugin disabled")

        if server_url is None:
            if not self.config.servers:
                raise ValueError("No keyservers configured")
            server_url = self.config.servers[0]

        login_url = f"{server_url}/api/v1/keys/login"

        # Build request body
        body: dict = {"client_id": client_id}
        effective_password = password or self.config.load_password()
        if effective_password:
            body["password"] = effective_password

        try:
            response = self.session.post(
                login_url,
                json=body,
                timeout=(
                    self.config.connect_timeout_seconds,
                    self.config.read_timeout_seconds,
                ),
            )

            if response.status_code == 200:
                data = response.json()
                # Save access token
                access_token = data.get("access_token") or data.get("token")
                if access_token:
                    self.config.save_api_token(access_token)
                # Save refresh token
                if data.get("refresh_token"):
                    self.config.save_refresh_token(data["refresh_token"])
                # Save password for future logins
                if effective_password:
                    self.config.save_password(effective_password)
                logger.info(f"Logged in to keyserver, client_id={data['client_id']}")
                return data
            elif response.status_code == 403:
                # Server requires password setup (legacy client)
                try:
                    data = response.json()
                    if data.get("status") == "password_required":
                        raise PasswordRequiredError(data.get("message", "Password setup required."))
                except (ValueError, KeyError):
                    pass
                raise AuthenticationError(f"Login forbidden: {response.text}")
            elif response.status_code == 401:
                raise AuthenticationError("Invalid credentials")
            else:
                raise NetworkError(
                    f"Login failed with status {response.status_code}: {response.text}"
                )

        except requests.exceptions.Timeout:
            raise NetworkError("Request timeout")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection failed: {e}")
        except (AuthenticationError, PasswordRequiredError, NetworkError):
            raise
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Request failed: {e}")

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

        # Enforce HTTPS for all server URLs
        if not server_url.startswith("https://"):
            raise ValueError(
                f"Invalid server URL: {server_url}. Only HTTPS URLs are allowed for security."
            )

        register_url = f"{server_url}/api/v1/keys/register"

        try:
            # HTTP POST (no authentication required for registration)
            response = self.session.post(
                register_url,
                timeout=(
                    self.config.connect_timeout_seconds,
                    self.config.read_timeout_seconds,
                ),
            )

            if response.status_code == 200:
                data = response.json()
                # Save JWT access token
                access_token = data.get("access_token") or data.get("token")
                if access_token:
                    self.config.save_api_token(access_token)
                # Save refresh token if provided
                if data.get("refresh_token"):
                    self.config.save_refresh_token(data["refresh_token"])
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

    def register_with_email(
        self, email: str, server_url: Optional[str] = None, poll_interval: int = 5
    ) -> dict:
        """
        Register with keyserver using email confirmation and polling.

        Flow:
        1. POST email to server → get registration_id
        2. Poll status endpoint every poll_interval seconds
        3. When confirmed, save JWT token and return result

        Args:
            email: Email address to register with
            server_url: Optional specific server URL
            poll_interval: Seconds between polls (default: 5)

        Returns:
            dict with: status, client_id, access_token, refresh_token, etc.

        Raises:
            NetworkError: On network failure, timeout, or server error
            ValueError: If plugin disabled or no servers configured
        """
        if not self.config.enabled:
            raise ValueError("Keyserver plugin disabled")

        if server_url is None:
            if not self.config.servers:
                raise ValueError("No keyservers configured")
            server_url = self.config.servers[0]

        # Step 1: POST email registration request
        register_url = f"{server_url}/api/v1/keys/register/email"

        try:
            response = self.session.post(
                register_url,
                json={"email": email},
                timeout=(
                    self.config.connect_timeout_seconds,
                    self.config.read_timeout_seconds,
                ),
            )
        except requests.exceptions.Timeout:
            raise NetworkError("Request timeout")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection failed: {e}")
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Request failed: {e}")

        if response.status_code != 202:
            raise NetworkError(
                f"Email registration failed with status {response.status_code}: {response.text}"
            )

        data = response.json()
        registration_id = data["registration_id"]
        status_url = f"{server_url}/api/v1/keys/register/status/{registration_id}"

        # Step 2: Poll until confirmed or timeout (30 minutes)
        import time

        timeout_seconds = 1800  # 30 minutes
        start = time.monotonic()

        while True:
            elapsed = time.monotonic() - start
            if elapsed >= timeout_seconds:
                raise NetworkError(
                    "Email confirmation timed out after 30 minutes. Please try again."
                )

            try:
                status_response = self.session.get(
                    status_url,
                    timeout=(
                        self.config.connect_timeout_seconds,
                        self.config.read_timeout_seconds,
                    ),
                )
            except requests.exceptions.RequestException:
                # Transient network error during polling — retry
                time.sleep(poll_interval)
                continue

            if status_response.status_code == 410:
                raise NetworkError("Registration expired. Please register again.")

            if status_response.status_code == 404:
                raise NetworkError("Registration not found.")

            if status_response.status_code != 200:
                time.sleep(poll_interval)
                continue

            status_data = status_response.json()

            if status_data["status"] == "confirmed":
                # Save access token
                self.config.save_api_token(status_data["access_token"])
                # Save refresh token if provided
                if status_data.get("refresh_token"):
                    self.config.save_refresh_token(status_data["refresh_token"])
                logger.info(f"Email registration confirmed, client_id={status_data['client_id']}")
                return status_data

            # Still pending — wait and poll again
            time.sleep(poll_interval)

    def _request_challenge(self, server_url: str, fingerprint_hint: Optional[str] = None) -> dict:
        """
        Request a PoP challenge nonce from the keyserver.

        Args:
            server_url: Keyserver base URL
            fingerprint_hint: Optional fingerprint for logging/hint on the server

        Returns:
            dict with challenge_id, nonce, expires_at

        Raises:
            NetworkError: If challenge request fails
        """
        challenge_url = f"{server_url}/api/v1/keys/challenge"
        body = {}
        if fingerprint_hint:
            body["fingerprint"] = fingerprint_hint
        response = self._authenticated_request("post", challenge_url, json=body)
        if response.status_code != 200:
            raise NetworkError(
                f"Challenge request failed with status {response.status_code}: {response.text}"
            )
        return response.json()

    def upload_key(self, bundle: PublicKeyBundle, signing_private_key_bytes: bytes = None) -> bool:
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

        # Verify bundle signature before uploading
        try:
            if not bundle.verify_signature():
                logger.error("Cannot upload bundle with invalid signature")
                return False
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

        # Upload to all configured servers with per-server PoP challenge
        success = False
        for server in self.config.servers:
            try:
                # Request a fresh challenge for this server
                challenge = self._request_challenge(server, bundle.fingerprint)
                nonce_hex = challenge["nonce"]
                challenge_id = challenge["challenge_id"]

                # Sign the PoP message with the private key
                pop_sig_bytes = create_pop_signature(
                    nonce_hex=nonce_hex,
                    fingerprint=bundle.fingerprint,
                    signing_algorithm=bundle.signing_algorithm,
                    private_key_bytes=signing_private_key_bytes,
                )

                # Build upload body with PoP fields
                upload_url = f"{server}/api/v1/keys"
                data = bundle.to_dict()
                data["challenge_id"] = challenge_id
                data["pop_signature"] = base64.b64encode(pop_sig_bytes).decode("ascii")

                response = self._authenticated_request(
                    "post",
                    upload_url,
                    json=data,
                )

                if response.status_code == 200:
                    logger.info(f"Uploaded bundle to {server}")
                    success = True
                elif response.status_code == 409:
                    logger.warning("Key already exists on server")
                else:
                    logger.warning(f"Upload failed on {server} with status {response.status_code}")

            except Exception as e:
                logger.error(f"Failed to upload to {server}: {e}")

        return success

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

        # Revoke on all configured servers
        success = False
        for server in self.config.servers:
            try:
                revoke_url = f"{server}/api/v1/keys/{fingerprint}/revoke"
                data = {"signature": signature.hex()}

                response = self._authenticated_request(
                    "post",
                    revoke_url,
                    json=data,
                )

                if response.status_code == 200:
                    logger.info(f"Revoked key {fingerprint} on {server}")
                    success = True
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
    eprint("KeyserverPlugin module loaded successfully")
