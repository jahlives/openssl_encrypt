"""
FIDO2 HSM Pepper Plugin

Implements hardware-bound key derivation using FIDO2 hmac-secret extension.
Works with any FIDO2 authenticator supporting hmac-secret (YubiKey 5, Nitrokey 3, SoloKey v2, etc.).

Security Properties:
- Hardware-bound: Pepper requires physical security key
- PIN protected: User verification required
- Deterministic: Same salt → same pepper
- Never stored: Derived on-demand
- Standard protocol: FIDO2 hmac-secret extension

Usage:
    # One-time registration
    openssl_encrypt hsm fido2-register --description "YubiKey 5 NFC"

    # Encrypt with FIDO2 pepper
    openssl_encrypt encrypt --hsm fido2 secret.txt

    # Decrypt
    openssl_encrypt decrypt --hsm fido2 secret.txt.enc
"""

import os
import json
import secrets
import getpass
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from base64 import b64encode, b64decode

try:
    from fido2.hid import CtapHidDevice
    from fido2.client import Fido2Client, UserInteraction, DefaultClientDataCollector
    from fido2.ctap2.extensions import HmacSecretExtension
    from fido2.webauthn import (
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
        PublicKeyCredentialParameters,
        AuthenticatorSelectionCriteria,
    )
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.extensions import HmacSecretExtension
    FIDO2_AVAILABLE = True

    class CLIUserInteraction(UserInteraction):
        """User interaction handler for CLI prompts (PIN, touch)."""

        def prompt_up(self):
            """Prompt user to touch their security key."""
            print("\n🔐 Touch your security key now...")

        def request_pin(self, permissions, rd_id):
            """Request PIN from user."""
            print("🔑 Your security key requires a PIN.")
            return getpass.getpass("Enter PIN: ")

        def request_uv(self, permissions, rd_id):
            """Request user verification."""
            return True

except ImportError:
    FIDO2_AVAILABLE = False
    CLIUserInteraction = None  # Placeholder when FIDO2 is not available

from ....modules.plugin_system.plugin_base import (
    HSMPlugin,
    PluginResult,
    PluginSecurityContext,
    PluginCapability,
)
from ....modules.plugin_system.plugin_config import ensure_plugin_data_dir

logger = logging.getLogger(__name__)


class FIDO2HSMPlugin(HSMPlugin):
    """
    FIDO2-based HSM pepper plugin using hmac-secret extension.

    Derives 32-byte hardware-bound pepper from 16-byte salt using FIDO2 authenticator.
    Supports multiple credentials for backup/recovery.
    """

    plugin_id = "fido2_hsm"
    name = "FIDO2 hmac-secret HSM"
    version = "1.0.0"

    # Default configuration
    DEFAULT_RP_ID = "openssl-encrypt.local"
    DEFAULT_TIMEOUT = 30000  # 30 seconds
    DEFAULT_CONFIG_DIR = Path.home() / ".openssl_encrypt" / "plugins" / "fido2"
    DEFAULT_CREDENTIAL_FILE = "credentials.json"

    def __init__(
        self,
        rp_id: Optional[str] = None,
        require_uv: bool = True,  # Changed default to True - PIN is required for hmac-secret
        timeout: int = DEFAULT_TIMEOUT,
        credential_file: Optional[Path] = None,
    ):
        """
        Initialize FIDO2 HSM plugin.

        IMPORTANT: The FIDO2 hmac-secret extension requires a PIN/UV to work correctly.
        Without PIN, the hmac-secret output is encrypted with ephemeral keys, making it
        non-deterministic and unusable for encryption/decryption.

        Args:
            rp_id: Relying Party ID (default: openssl-encrypt.local)
            require_uv: Require user verification (PIN/biometric) - default False for compatibility
            timeout: Operation timeout in milliseconds
            credential_file: Custom credential file path
        """
        super().__init__(
            plugin_id=self.plugin_id,
            name=self.name,
            version=self.version
        )

        self.rp_id = rp_id or self.DEFAULT_RP_ID
        self.require_uv = require_uv
        self.timeout = timeout

        # Setup credential storage
        if credential_file:
            self.credential_file = Path(credential_file)
            self.config_dir = self.credential_file.parent
        else:
            self.config_dir = self.DEFAULT_CONFIG_DIR
            self.credential_file = self.config_dir / self.DEFAULT_CREDENTIAL_FILE

        # Ensure config directory exists with proper permissions
        self._ensure_config_dir()

    def _ensure_config_dir(self):
        """Create config directory with secure permissions (0o700)."""
        try:
            # Check if using default config directory or custom path
            if self.config_dir == self.DEFAULT_CONFIG_DIR or str(self.config_dir).startswith(str(Path.home() / ".openssl_encrypt" / "plugins")):
                # Use centralized helper for default config directories
                config_dir = ensure_plugin_data_dir("fido2", "")
                if config_dir is None:
                    raise RuntimeError("Failed to create secure FIDO2 config directory")
                self.config_dir = config_dir
            else:
                # Custom directory - create it directly with secure permissions
                self.config_dir.mkdir(parents=True, exist_ok=True)
                if hasattr(os, "chmod"):
                    os.chmod(self.config_dir, 0o700)
                logger.info(f"Created custom FIDO2 config directory: {self.config_dir}")
        except Exception as e:
            logger.error(f"Failed to create config directory: {e}")
            raise

    def get_required_capabilities(self) -> set:
        """
        Return required plugin capabilities.

        Returns:
            Set containing ACCESS_CONFIG and WRITE_LOGS capabilities
        """
        return {PluginCapability.ACCESS_CONFIG, PluginCapability.WRITE_LOGS}

    def get_description(self) -> str:
        """
        Return human-readable plugin description.

        Returns:
            Plugin description string
        """
        return (
            "FIDO2 Hardware Security Module using hmac-secret extension. "
            "Derives hardware-bound pepper from FIDO2 authenticators (YubiKey, Nitrokey, etc.). "
            "Requires PIN authentication and physical touch for each operation."
        )

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> PluginResult:
        """
        Initialize plugin and verify FIDO2 library availability.

        Args:
            config: Optional configuration dictionary

        Returns:
            PluginResult indicating initialization success/failure
        """
        # Check FIDO2 library availability
        if not FIDO2_AVAILABLE:
            return PluginResult.error_result(
                "FIDO2 library not available. Install with: pip install fido2>=1.1.0"
            )

        # Apply custom configuration if provided
        if config:
            if "rp_id" in config:
                self.rp_id = config["rp_id"]
            if "require_uv" in config:
                self.require_uv = config["require_uv"]
            if "timeout" in config:
                self.timeout = config["timeout"]
            if "credential_file" in config:
                self.credential_file = Path(config["credential_file"])

        return PluginResult.success_result(
            f"FIDO2 HSM plugin initialized (RP ID: {self.rp_id})"
        )

    def _find_device(self) -> Optional[CtapHidDevice]:
        """
        Find connected FIDO2 device.

        Returns:
            CtapHidDevice if found, None otherwise
        """
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            return None

        # Return first available device
        # TODO: Support device selection when multiple devices present
        return devices[0]

    def _check_hmac_secret_support(self, device: CtapHidDevice) -> bool:
        """
        Check if device supports hmac-secret extension.

        Args:
            device: FIDO2 device to check

        Returns:
            True if hmac-secret is supported, False otherwise
        """
        try:
            ctap2 = Ctap2(device)
            info = ctap2.get_info()

            # Check if hmac-secret extension is supported
            if hasattr(info, "extensions") and info.extensions:
                return "hmac-secret" in info.extensions

            return False
        except Exception as e:
            logger.error(f"Failed to check hmac-secret support: {e}")
            return False

    def _load_credentials(self) -> List[Dict[str, Any]]:
        """
        Load credentials from JSON file.

        Returns:
            List of credential dictionaries
        """
        if not self.credential_file.exists():
            return []

        try:
            with open(self.credential_file, "r") as f:
                data = json.load(f)
                return data.get("credentials", [])
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            return []

    def _save_credential(self, credential_data: Dict[str, Any]):
        """
        Save credential to JSON file with atomic write.

        Args:
            credential_data: Credential data to save
        """
        # Load existing credentials
        credentials = self._load_credentials()

        # Add new credential
        credentials.append(credential_data)

        # Prepare full data structure
        data = {
            "version": 1,
            "rp_id": self.rp_id,
            "credentials": credentials,
        }

        # Atomic write: write to temp file, then replace
        temp_file = self.credential_file.with_suffix(".tmp")
        try:
            with open(temp_file, "w") as f:
                json.dump(data, f, indent=2)

            # Set secure permissions (0o600)
            os.chmod(temp_file, 0o600)

            # Atomic replace
            temp_file.replace(self.credential_file)

            logger.info(f"Credential saved successfully: {credential_data.get('id')}")
        except Exception as e:
            # Clean up temp file on error
            if temp_file.exists():
                temp_file.unlink()
            logger.error(f"Failed to save credential: {e}")
            raise

    def get_hsm_pepper(
        self,
        salt: bytes,
        context: PluginSecurityContext,
    ) -> PluginResult:
        """
        Derive hardware-bound pepper using FIDO2 hmac-secret.

        This is the main interface called by the encryption core.

        Args:
            salt: 16-byte salt value
            context: Plugin security context

        Returns:
            PluginResult with 32-byte pepper in data["hsm_pepper"]
        """
        # 1. Validate salt length
        if len(salt) != 16:
            return PluginResult.error_result(
                f"Invalid salt length: expected 16 bytes, got {len(salt)} bytes"
            )

        # 2. Pad salt to 32 bytes for FIDO2 hmac-secret extension
        # The extension requires 32-byte salt, so we pad with the salt itself
        salt_32 = salt + salt  # 16 + 16 = 32 bytes

        # Debug output
        import binascii
        logger.debug(f"Input salt (hex): {binascii.hexlify(salt).decode()}")
        logger.debug(f"Padded salt (hex): {binascii.hexlify(salt_32).decode()}")

        # 3. Load credentials
        credentials = self._load_credentials()
        if not credentials:
            return PluginResult.error_result(
                "No FIDO2 credentials registered. Run: openssl_encrypt hsm fido2-register"
            )

        # 4. Find connected device
        device = self._find_device()
        if not device:
            return PluginResult.error_result(
                "No FIDO2 device found. Please connect your security key."
            )

        # 4. Verify hmac-secret support
        if not self._check_hmac_secret_support(device):
            return PluginResult.error_result(
                "Connected device does not support hmac-secret extension"
            )

        # 5. Create FIDO2 client with DefaultClientDataCollector and HmacSecretExtension
        origin = f"https://{self.rp_id}"
        client_data_collector = DefaultClientDataCollector(origin=origin)

        # Create HmacSecretExtension with allow_hmac_secret=True to enable hmac-secret
        hmac_ext = HmacSecretExtension(allow_hmac_secret=True)

        client = Fido2Client(
            device,
            client_data_collector,
            user_interaction=CLIUserInteraction(),
            extensions=[hmac_ext]
        )

        # 6. Build allow_credentials list (all registered credentials)
        allow_list = [
            PublicKeyCredentialDescriptor(
                type="public-key",
                id=b64decode(cred["credential_id"])
            )
            for cred in credentials
        ]

        # 7. Get assertion with prf extension (WebAuthn 3 standard)
        # The HmacSecretExtension will translate this to hmac-secret for the authenticator
        # CRITICAL: User verification must be "preferred" or "required" for hmac-secret
        # to work deterministically. Without UV/PIN, the output is encrypted with
        # ephemeral keys and changes on each call.
        try:
            result = client.get_assertion(
                PublicKeyCredentialRequestOptions(
                    rp_id=self.rp_id,
                    challenge=secrets.token_bytes(32),
                    allow_credentials=allow_list,
                    user_verification="required" if self.require_uv else "preferred",
                    timeout=self.timeout,
                    extensions={"prf": {"eval": {"first": salt_32}}},  # Use prf format
                )
            )
        except Exception as e:
            logger.error(f"FIDO2 assertion failed: {e}")
            return PluginResult.error_result(f"Failed to get assertion: {e}")

        # 8. Extract 32-byte pepper from hmac-secret output
        try:
            # Try multiple sources for the PROCESSED extension results
            extension_results = None
            using_raw = False

            # Method 1: Get from result._get_extension_results (should be processed)
            if hasattr(result, '_get_extension_results'):
                try:
                    extension_results = result._get_extension_results(0)
                    if extension_results and ('prf' in extension_results or 'hmac-secret' in extension_results):
                        logger.debug(f"Method 1: Using _get_extension_results: {list(extension_results.keys())}")
                except Exception as e:
                    logger.debug(f"Method 1 failed: {e}")
                    extension_results = None

            # Method 2: Try get_response().client_extension_results (WebAuthn API)
            if not extension_results or (not extension_results.get('prf') and not extension_results.get('hmac-secret')):
                try:
                    auth_response = result.get_response(0)
                    if hasattr(auth_response, 'client_extension_results'):
                        client_ext = auth_response.client_extension_results
                        if client_ext and ('prf' in client_ext or 'hmac-secret' in client_ext):
                            extension_results = client_ext
                            logger.debug(f"Method 2: Using client_extension_results: {list(extension_results.keys())}")
                except Exception as e:
                    logger.debug(f"Method 2 failed: {e}")

            # Method 3: Fall back to raw auth_data.extensions (WILL NOT WORK - encrypted!)
            if not extension_results or (not extension_results.get('prf') and not extension_results.get('hmac-secret')):
                if hasattr(result, '_assertions') and result._assertions:
                    first_assertion = result._assertions[0]
                    auth_data = first_assertion.auth_data
                    if hasattr(auth_data, 'extensions') and auth_data.extensions:
                        using_raw = True
                        extension_results = auth_data.extensions
                        logger.debug(f"Method 3: Using RAW auth_data.extensions (ENCRYPTED - WILL FAIL!): {list(extension_results.keys())}")
                    else:
                        extension_results = {}
                else:
                    extension_results = {}

            # Warn if using encrypted data
            if using_raw:
                logger.warning("Using encrypted hmac-secret data - decryption will fail!")
                logger.warning("This indicates the HmacSecretExtension is not processing results correctly")

            prf_data = None
            if extension_results:
                # Try prf first (WebAuthn 3)
                prf_data = extension_results.get('prf') or extension_results.get(b'prf')
                # Fallback to hmac-secret
                if not prf_data:
                    prf_data = extension_results.get('hmac-secret') or extension_results.get(b'hmac-secret')

            if not prf_data:
                return PluginResult.error_result(
                    "prf/hmac-secret extension not returned by authenticator. "
                    "The credential may not have prf/hmac-secret enabled. Try re-registering."
                )

            # Debug: Show the actual structure
            logger.debug(f"prf_data type: {type(prf_data)}")
            logger.debug(f"prf_data value: {prf_data}")
            if isinstance(prf_data, dict):
                logger.debug(f"prf_data keys: {list(prf_data.keys())}")
                for key, val in prf_data.items():
                    logger.debug(f"  {key}: type={type(val)}, len={len(val) if hasattr(val, '__len__') else 'N/A'}")

            # The prf extension returns {"results": {"first": <base64url string>}}
            # The hmac-secret extension returns {"output1": <32 bytes>} or just bytes
            if isinstance(prf_data, dict):
                if 'results' in prf_data and 'first' in prf_data['results']:
                    pepper_value = prf_data['results']['first']
                    # WebAuthn prf returns base64url-encoded strings, need to decode
                    if isinstance(pepper_value, str):
                        from fido2.utils import websafe_decode
                        pepper = websafe_decode(pepper_value)
                        logger.debug("Decoded base64url pepper from prf extension")
                    else:
                        pepper = pepper_value
                elif 'output1' in prf_data:
                    pepper = prf_data['output1']
                else:
                    return PluginResult.error_result(
                        f"Unexpected prf/hmac-secret data format: {prf_data}"
                    )
            elif isinstance(prf_data, bytes):
                # Raw bytes output from hmac-secret extension
                # Take the first 32 bytes (one salt = one 32-byte output)
                pepper = prf_data[:32]
            else:
                return PluginResult.error_result(
                    f"Unexpected prf/hmac-secret data type: {type(prf_data)}"
                )

            # Validate pepper length (should be 32 bytes after extraction)
            if len(pepper) < 32:
                return PluginResult.error_result(
                    f"Invalid pepper length: expected 32 bytes, got {len(pepper)} bytes"
                )

            # Debug output
            import binascii
            logger.debug(f"Derived pepper (hex): {binascii.hexlify(pepper).decode()}")

            logger.info(f"Successfully derived FIDO2 pepper ({len(pepper)} bytes)")

            return PluginResult.success_result(
                f"FIDO2 pepper derived ({len(pepper)} bytes)",
                data={"hsm_pepper": pepper}
            )

        except Exception as e:
            logger.error(f"Failed to extract pepper: {e}")
            return PluginResult.error_result(f"Failed to extract pepper: {e}")

    def register_credential(
        self,
        description: Optional[str] = None,
        is_backup: bool = False,
    ) -> PluginResult:
        """
        Register new FIDO2 credential with hmac-secret extension.

        This is a one-time setup operation that creates a new credential
        on the FIDO2 authenticator.

        Args:
            description: Human-readable description for the credential
            is_backup: Mark as backup credential

        Returns:
            PluginResult indicating registration success/failure
        """
        # 1. Find connected device
        device = self._find_device()
        if not device:
            return PluginResult.error_result(
                "No FIDO2 device found. Please connect your security key."
            )

        # 2. Verify hmac-secret support
        if not self._check_hmac_secret_support(device):
            return PluginResult.error_result(
                "Connected device does not support hmac-secret extension. "
                "Supported devices: YubiKey 5, Nitrokey 3, SoloKey v2, etc."
            )

        # 3. Create FIDO2 client with DefaultClientDataCollector and HmacSecretExtension
        origin = f"https://{self.rp_id}"
        client_data_collector = DefaultClientDataCollector(origin=origin)

        # Create HmacSecretExtension with allow_hmac_secret=True to enable hmac-secret
        hmac_ext = HmacSecretExtension(allow_hmac_secret=True)

        client = Fido2Client(
            device,
            client_data_collector,
            user_interaction=CLIUserInteraction(),
            extensions=[hmac_ext]
        )

        # 4. Generate credential ID
        credentials = self._load_credentials()
        if credentials and not is_backup:
            # Check if primary credential already exists
            primary_exists = any(not cred.get("is_backup", False) for cred in credentials)
            if primary_exists:
                return PluginResult.error_result(
                    "Primary credential already exists. Use --backup flag to register backup credential."
                )

        # Generate credential ID
        cred_count = len(credentials)
        if is_backup:
            credential_id = f"backup-{cred_count}"
        else:
            credential_id = "primary"

        # 5. Prepare creation options
        user_id = secrets.token_bytes(32)

        # Create proper WebAuthn objects
        rp = PublicKeyCredentialRpEntity(id=self.rp_id, name="OpenSSL Encrypt")
        user = PublicKeyCredentialUserEntity(
            id=user_id,
            name="openssl-encrypt-user",
            display_name="OpenSSL Encrypt User"
        )

        challenge = secrets.token_bytes(32)

        pub_key_params = [
            PublicKeyCredentialParameters(type="public-key", alg=-7),  # ES256
            PublicKeyCredentialParameters(type="public-key", alg=-8),  # EdDSA
        ]

        # Require UV for registration to ensure hmac-secret works deterministically
        authenticator_selection = AuthenticatorSelectionCriteria(
            user_verification="required" if self.require_uv else "preferred"
        )

        try:
            # Request prf extension during credential creation (WebAuthn 3 standard)
            # The HmacSecretExtension will translate this to hmac-secret for the authenticator
            result = client.make_credential(
                PublicKeyCredentialCreationOptions(
                    rp=rp,
                    user=user,
                    challenge=challenge,
                    pub_key_cred_params=pub_key_params,
                    timeout=self.timeout,
                    authenticator_selection=authenticator_selection,
                    extensions={"prf": {}},  # Use prf extension (WebAuthn 3)
                )
            )
        except Exception as e:
            logger.error(f"Credential creation failed: {e}")
            return PluginResult.error_result(f"Failed to create credential: {e}")

        # 6. Extract credential data
        try:
            # Access the nested structure correctly for v1.2+
            credential_id_bytes = result.raw_id  # raw_id is the credential ID
            attestation_object = result.response.attestation_object
            aaguid = attestation_object.auth_data.credential_data.aaguid

            # 7. Build credential data structure
            credential_data = {
                "id": credential_id,
                "credential_id": b64encode(credential_id_bytes).decode("ascii"),
                "created_at": datetime.utcnow().isoformat() + "Z",
                "authenticator_aaguid": str(aaguid) if aaguid else "unknown",
                "description": description or f"FIDO2 Device ({credential_id})",
                "is_backup": is_backup,
            }

            # 8. Save credential
            self._save_credential(credential_data)

            logger.info(f"FIDO2 credential registered: {credential_id}")

            return PluginResult.success_result(
                f"FIDO2 credential registered successfully: {credential_data['description']}",
                data={"credential_id": credential_id}
            )

        except Exception as e:
            logger.error(f"Failed to process credential: {e}")
            return PluginResult.error_result(f"Failed to process credential: {e}")

    def list_devices(self) -> List[Dict[str, Any]]:
        """
        List connected FIDO2 devices.

        Returns:
            List of device information dictionaries
        """
        devices = []
        for device in CtapHidDevice.list_devices():
            try:
                ctap2 = Ctap2(device)
                info = ctap2.get_info()

                devices.append({
                    "product_name": getattr(device, "product_name", "Unknown"),
                    "manufacturer": getattr(device, "manufacturer", "Unknown"),
                    "aaguid": str(info.aaguid) if hasattr(info, "aaguid") else "Unknown",
                    "versions": info.versions if hasattr(info, "versions") else [],
                    "extensions": list(info.extensions) if hasattr(info, "extensions") and info.extensions else [],
                    "hmac_secret_support": self._check_hmac_secret_support(device),
                })
            except Exception as e:
                logger.error(f"Failed to get device info: {e}")
                devices.append({
                    "product_name": "Unknown",
                    "error": str(e),
                })

        return devices

    def is_registered(self) -> bool:
        """
        Check if any FIDO2 credentials are registered.

        Returns:
            True if credentials exist, False otherwise
        """
        return len(self._load_credentials()) > 0

    def unregister(self, credential_id: Optional[str] = None, remove_all: bool = False) -> PluginResult:
        """
        Remove FIDO2 credential(s).

        Args:
            credential_id: Specific credential ID to remove (None = remove primary)
            remove_all: Remove all credentials

        Returns:
            PluginResult indicating removal success/failure
        """
        if not self.credential_file.exists():
            return PluginResult.error_result("No credentials registered")

        credentials = self._load_credentials()
        if not credentials:
            return PluginResult.error_result("No credentials found")

        if remove_all:
            # Remove entire credential file
            try:
                self.credential_file.unlink()
                logger.info("All FIDO2 credentials removed")
                return PluginResult.success_result("All credentials removed successfully")
            except Exception as e:
                logger.error(f"Failed to remove credentials: {e}")
                return PluginResult.error_result(f"Failed to remove credentials: {e}")

        # Remove specific credential
        target_id = credential_id or "primary"

        # Filter out the target credential
        remaining = [c for c in credentials if c["id"] != target_id]

        if len(remaining) == len(credentials):
            return PluginResult.error_result(f"Credential not found: {target_id}")

        # Save remaining credentials
        data = {
            "version": 1,
            "rp_id": self.rp_id,
            "credentials": remaining,
        }

        try:
            with open(self.credential_file, "w") as f:
                json.dump(data, f, indent=2)

            os.chmod(self.credential_file, 0o600)

            logger.info(f"Credential removed: {target_id}")
            return PluginResult.success_result(f"Credential removed: {target_id}")

        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")
            return PluginResult.error_result(f"Failed to save credentials: {e}")
