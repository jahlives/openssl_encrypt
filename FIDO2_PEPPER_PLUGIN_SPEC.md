# FIDO2 Pepper Plugin Specification

*For Claude Code Implementation*

---

## Overview

This document specifies a FIDO2-based Pepper Plugin for openssl_encrypt. The plugin uses the FIDO2 `hmac-secret` extension to derive a hardware-bound pepper from a security key.

### Goals

- Provide hardware-bound pepper without server dependency
- Support any FIDO2 authenticator with `hmac-secret` extension (YubiKey 5, Nitrokey 3, SoloKey, Security Keys)
- No "slot programming" required — uses standard FIDO2 credential creation
- 32-byte pepper output (vs 20-byte from OTP HMAC-SHA1)
- PIN protection via FIDO2 User Verification

### Non-Goals

- Replacing existing OTP Challenge-Response plugin (both will coexist)
- Resident/Discoverable credentials (uses non-resident to avoid slot limits)
- Platform authenticators (Windows Hello, Touch ID) — hardware tokens only for now

---

## Dependencies

```
fido2>=1.1.0  # python-fido2 by Yubico
```

PyPI: https://pypi.org/project/fido2/
Docs: https://python-fido2.readthedocs.io/

---

## Architecture

### File Structure

```
openssl_encrypt/
├── plugins/
│   ├── hsm/
│   │   ├── __init__.py
│   │   ├── base.py                    # Abstract base class for HSM plugins
│   │   ├── yubikey_challenge_response.py  # Existing OTP plugin
│   │   └── fido2_pepper.py            # NEW: FIDO2 plugin
│   └── ...
├── config/
│   └── fido2_credentials.py           # Credential storage handling
└── ...
```

### Class Hierarchy

```
HSMPepperPlugin (ABC)
├── YubikeyChallengeResponsePlugin  # Existing
└── FIDO2PepperPlugin               # New
```

---

## Data Structures

### Credential Storage

Location: `~/.config/openssl_encrypt/fido2_credentials.json`

```json
{
  "version": 1,
  "rp_id": "openssl-encrypt.local",
  "credentials": {
    "identity_name": {
      "credential_id": "<base64-encoded>",
      "salt": "<base64-encoded, 32 bytes>",
      "created_at": "2025-12-31T12:00:00Z",
      "authenticator_aaguid": "<uuid>",
      "description": "YubiKey 5 NFC"
    }
  }
}
```

### Configuration

In main config (`~/.config/openssl_encrypt/config.yaml`):

```yaml
plugins:
  fido2_pepper:
    enabled: true
    
    # Relying Party ID (constant, do not change after credentials created)
    rp_id: "openssl-encrypt.local"
    
    # Security settings
    require_user_verification: true   # Require PIN
    require_user_presence: true       # Require touch
    
    # Timeout for user interaction
    timeout_seconds: 30
    
    # Credential file location (default shown)
    credential_file: null  # Uses default path
```

---

## Implementation

### 1. Base Class (if not exists)

**File:** `openssl_encrypt/plugins/hsm/base.py`

```python
"""Abstract base class for HSM pepper plugins."""

from abc import ABC, abstractmethod
from typing import Optional


class HSMPepperPlugin(ABC):
    """
    Abstract base for hardware-backed pepper sources.
    
    Implementations:
    - YubikeyChallengeResponsePlugin (OTP HMAC-SHA1)
    - FIDO2PepperPlugin (FIDO2 hmac-secret)
    - TPMPepperPlugin (future)
    """
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if hardware is connected and usable."""
        pass
    
    @abstractmethod
    def get_pepper(self, identity_name: str) -> bytes:
        """
        Get pepper for given identity.
        
        Args:
            identity_name: Name of the identity
            
        Returns:
            Pepper bytes (length depends on implementation)
            
        Raises:
            HSMNotAvailableError: Hardware not connected
            HSMNotRegisteredError: No credential for this identity
            HSMUserCancelledError: User cancelled (timeout, PIN cancel)
        """
        pass
    
    @abstractmethod
    def register(
        self, 
        identity_name: str,
        description: Optional[str] = None
    ) -> None:
        """
        Register hardware for an identity.
        
        Args:
            identity_name: Name of the identity
            description: Optional human-readable description
            
        Raises:
            HSMNotAvailableError: Hardware not connected
            HSMAlreadyRegisteredError: Identity already has credential
        """
        pass
    
    @abstractmethod
    def is_registered(self, identity_name: str) -> bool:
        """Check if identity has registered credential."""
        pass
    
    @abstractmethod
    def unregister(self, identity_name: str) -> None:
        """Remove credential for identity."""
        pass
    
    @property
    @abstractmethod
    def pepper_size(self) -> int:
        """Return pepper size in bytes."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable plugin name."""
        pass
```

### 2. Exceptions

**File:** `openssl_encrypt/plugins/hsm/exceptions.py`

```python
"""HSM plugin exceptions."""


class HSMError(Exception):
    """Base exception for HSM operations."""
    pass


class HSMNotAvailableError(HSMError):
    """Hardware not connected or not supported."""
    pass


class HSMNotRegisteredError(HSMError):
    """No credential registered for this identity."""
    pass


class HSMAlreadyRegisteredError(HSMError):
    """Credential already exists for this identity."""
    pass


class HSMUserCancelledError(HSMError):
    """User cancelled operation (timeout, PIN cancel)."""
    pass


class HSMPINRequiredError(HSMError):
    """PIN required but not configured on device."""
    pass


class HSMExtensionNotSupportedError(HSMError):
    """Required extension (hmac-secret) not supported."""
    pass
```

### 3. FIDO2 Pepper Plugin

**File:** `openssl_encrypt/plugins/hsm/fido2_pepper.py`

```python
"""
FIDO2 Pepper Plugin using hmac-secret extension.

Provides hardware-bound pepper derivation using any FIDO2 authenticator
that supports the hmac-secret extension.
"""

import os
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from base64 import b64encode, b64decode

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorAttachment,
)
from fido2.ctap2.extensions import HmacSecretExtension

from .base import HSMPepperPlugin
from .exceptions import (
    HSMNotAvailableError,
    HSMNotRegisteredError,
    HSMAlreadyRegisteredError,
    HSMUserCancelledError,
    HSMExtensionNotSupportedError,
)


class CLIUserInteraction(UserInteraction):
    """User interaction handler for CLI."""
    
    def prompt_up(self) -> None:
        """Called when user presence (touch) is required."""
        print("Touch your security key...", flush=True)
    
    def request_pin(self, permissions, rd_id) -> Optional[str]:
        """Called when PIN is required."""
        import getpass
        return getpass.getpass("Enter FIDO2 PIN: ")
    
    def request_uv(self, permissions, rd_id) -> bool:
        """Called for built-in user verification."""
        print("Perform user verification on your authenticator...", flush=True)
        return True


class FIDO2PepperPlugin(HSMPepperPlugin):
    """
    FIDO2-based pepper derivation using hmac-secret extension.
    
    Security Model:
    1. Registration creates a new FIDO2 credential with hmac-secret
    2. A random 32-byte salt is generated and stored locally
    3. Pepper = HMAC(authenticator_secret, salt)
    4. Pepper is derived on-demand, never stored
    
    The pepper is bound to:
    - The specific authenticator (hardware)
    - The credential (RP + user)
    - The salt (stored locally)
    
    Without all three, the pepper cannot be reproduced.
    """
    
    PEPPER_SIZE = 32  # hmac-secret outputs 32 bytes
    SALT_SIZE = 32
    CREDENTIAL_FILE_VERSION = 1
    
    def __init__(
        self,
        rp_id: str = "openssl-encrypt.local",
        require_user_verification: bool = True,
        require_user_presence: bool = True,
        timeout_seconds: int = 30,
        credential_file: Optional[Path] = None,
    ):
        """
        Initialize FIDO2 Pepper Plugin.
        
        Args:
            rp_id: Relying Party ID (domain-like string)
            require_user_verification: Require PIN entry
            require_user_presence: Require physical touch
            timeout_seconds: Timeout for user interaction
            credential_file: Path to credential storage file
        """
        self.rp_id = rp_id
        self.rp_name = "openssl_encrypt"
        self.require_uv = require_user_verification
        self.require_up = require_user_presence
        self.timeout = timeout_seconds
        
        if credential_file is None:
            config_dir = Path.home() / ".config" / "openssl_encrypt"
            credential_file = config_dir / "fido2_credentials.json"
        self.credential_file = Path(credential_file)
        
        self._credentials_cache: Optional[Dict[str, Any]] = None
    
    @property
    def name(self) -> str:
        return "FIDO2 (hmac-secret)"
    
    @property
    def pepper_size(self) -> int:
        return self.PEPPER_SIZE
    
    # =========================================================================
    # Device Discovery
    # =========================================================================
    
    def _find_device(self) -> CtapHidDevice:
        """
        Find connected FIDO2 device.
        
        Returns:
            First available FIDO2 HID device
            
        Raises:
            HSMNotAvailableError: No device found
        """
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise HSMNotAvailableError(
                "No FIDO2 security key detected. "
                "Please insert your security key and try again."
            )
        return devices[0]
    
    def _check_hmac_secret_support(self, device: CtapHidDevice) -> bool:
        """Check if device supports hmac-secret extension."""
        from fido2.ctap2 import Ctap2
        try:
            ctap2 = Ctap2(device)
            info = ctap2.info
            extensions = info.extensions or []
            return "hmac-secret" in extensions
        except Exception:
            return False
    
    def is_available(self) -> bool:
        """Check if a compatible FIDO2 device is connected."""
        try:
            device = self._find_device()
            return self._check_hmac_secret_support(device)
        except HSMNotAvailableError:
            return False
    
    def list_devices(self) -> List[Dict[str, Any]]:
        """
        List all connected FIDO2 devices with their capabilities.
        
        Returns:
            List of device info dicts
        """
        from fido2.ctap2 import Ctap2
        
        result = []
        for device in CtapHidDevice.list_devices():
            info = {
                "path": str(device.descriptor.path),
                "product_name": device.descriptor.product_name,
                "serial_number": device.descriptor.serial_number,
                "hmac_secret_supported": False,
            }
            try:
                ctap2 = Ctap2(device)
                ctap_info = ctap2.info
                info["hmac_secret_supported"] = "hmac-secret" in (ctap_info.extensions or [])
                info["aaguid"] = str(ctap_info.aaguid) if ctap_info.aaguid else None
            except Exception:
                pass
            result.append(info)
        return result
    
    # =========================================================================
    # Credential Storage
    # =========================================================================
    
    def _load_credentials(self) -> Dict[str, Any]:
        """Load credentials from file."""
        if self._credentials_cache is not None:
            return self._credentials_cache
        
        if not self.credential_file.exists():
            self._credentials_cache = {
                "version": self.CREDENTIAL_FILE_VERSION,
                "rp_id": self.rp_id,
                "credentials": {}
            }
            return self._credentials_cache
        
        with open(self.credential_file, "r") as f:
            data = json.load(f)
        
        # Version check
        if data.get("version") != self.CREDENTIAL_FILE_VERSION:
            raise ValueError(
                f"Unsupported credential file version: {data.get('version')}"
            )
        
        # RP ID check
        if data.get("rp_id") != self.rp_id:
            raise ValueError(
                f"Credential file RP ID mismatch: "
                f"expected {self.rp_id}, got {data.get('rp_id')}"
            )
        
        self._credentials_cache = data
        return self._credentials_cache
    
    def _save_credentials(self, data: Dict[str, Any]) -> None:
        """Save credentials to file."""
        self.credential_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Write atomically
        tmp_file = self.credential_file.with_suffix(".tmp")
        with open(tmp_file, "w") as f:
            json.dump(data, f, indent=2)
        tmp_file.replace(self.credential_file)
        
        # Restrict permissions
        self.credential_file.chmod(0o600)
        
        self._credentials_cache = data
    
    def _get_credential(self, identity_name: str) -> Dict[str, Any]:
        """
        Get credential for identity.
        
        Raises:
            HSMNotRegisteredError: No credential found
        """
        data = self._load_credentials()
        cred = data["credentials"].get(identity_name)
        if cred is None:
            raise HSMNotRegisteredError(
                f"No FIDO2 credential registered for identity '{identity_name}'. "
                f"Run: openssl_encrypt fido2 register --identity {identity_name}"
            )
        return cred
    
    # =========================================================================
    # Public API
    # =========================================================================
    
    def is_registered(self, identity_name: str) -> bool:
        """Check if identity has a registered FIDO2 credential."""
        data = self._load_credentials()
        return identity_name in data["credentials"]
    
    def register(
        self,
        identity_name: str,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Register a FIDO2 credential for an identity.
        
        Creates a new FIDO2 credential with hmac-secret extension enabled.
        The credential ID and a random salt are stored locally.
        
        Args:
            identity_name: Name of the identity
            description: Optional description (e.g., "YubiKey 5 NFC")
            
        Returns:
            Registration info dict
            
        Raises:
            HSMNotAvailableError: No device connected
            HSMAlreadyRegisteredError: Identity already registered
            HSMExtensionNotSupportedError: Device doesn't support hmac-secret
        """
        # Check not already registered
        if self.is_registered(identity_name):
            raise HSMAlreadyRegisteredError(
                f"Identity '{identity_name}' already has a FIDO2 credential. "
                f"Use --add-backup to register additional authenticators, "
                f"or unregister first."
            )
        
        # Find and validate device
        device = self._find_device()
        if not self._check_hmac_secret_support(device):
            raise HSMExtensionNotSupportedError(
                "Your security key does not support the hmac-secret extension. "
                "Compatible keys include: YubiKey 5 series, Nitrokey 3, SoloKey v2."
            )
        
        # Create client
        client = Fido2Client(
            device,
            f"https://{self.rp_id}",
            user_interaction=CLIUserInteraction(),
        )
        
        # Generate user ID (random, not sensitive)
        user_id = secrets.token_bytes(32)
        
        # Create credential
        rp = PublicKeyCredentialRpEntity(id=self.rp_id, name=self.rp_name)
        user = PublicKeyCredentialUserEntity(
            id=user_id,
            name=identity_name,
            display_name=identity_name,
        )
        
        # Request hmac-secret extension
        extensions = {"hmacCreateSecret": True}
        
        uv = (
            UserVerificationRequirement.REQUIRED
            if self.require_uv
            else UserVerificationRequirement.DISCOURAGED
        )
        
        try:
            result = client.make_credential(
                PublicKeyCredentialCreationOptions(
                    rp=rp,
                    user=user,
                    challenge=secrets.token_bytes(32),
                    pub_key_cred_params=[
                        PublicKeyCredentialParameters(
                            type=PublicKeyCredentialType.PUBLIC_KEY,
                            alg=-7,  # ES256
                        ),
                        PublicKeyCredentialParameters(
                            type=PublicKeyCredentialType.PUBLIC_KEY,
                            alg=-257,  # RS256 fallback
                        ),
                    ],
                    timeout=self.timeout * 1000,
                    authenticator_selection={
                        "authenticator_attachment": AuthenticatorAttachment.CROSS_PLATFORM,
                        "user_verification": uv,
                    },
                    extensions=extensions,
                )
            )
        except Exception as e:
            if "timeout" in str(e).lower() or "cancel" in str(e).lower():
                raise HSMUserCancelledError(f"Registration cancelled: {e}")
            raise HSMNotAvailableError(f"Registration failed: {e}")
        
        # Verify hmac-secret was enabled
        auth_data = result.attestation_object.auth_data
        if not auth_data.extensions or not auth_data.extensions.get("hmac-secret"):
            raise HSMExtensionNotSupportedError(
                "Authenticator did not enable hmac-secret extension."
            )
        
        # Extract credential ID
        credential_id = auth_data.credential_data.credential_id
        aaguid = auth_data.credential_data.aaguid
        
        # Generate salt for this credential
        salt = secrets.token_bytes(self.SALT_SIZE)
        
        # Store credential
        data = self._load_credentials()
        data["credentials"][identity_name] = {
            "credential_id": b64encode(credential_id).decode("ascii"),
            "salt": b64encode(salt).decode("ascii"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "authenticator_aaguid": str(aaguid) if aaguid else None,
            "description": description or device.descriptor.product_name,
        }
        self._save_credentials(data)
        
        return {
            "identity": identity_name,
            "authenticator": description or device.descriptor.product_name,
            "aaguid": str(aaguid) if aaguid else None,
        }
    
    def get_pepper(self, identity_name: str) -> bytes:
        """
        Derive pepper using FIDO2 hmac-secret.
        
        Args:
            identity_name: Name of the identity
            
        Returns:
            32-byte pepper
            
        Raises:
            HSMNotAvailableError: No device connected
            HSMNotRegisteredError: No credential for identity
            HSMUserCancelledError: User cancelled (timeout/PIN)
        """
        # Load credential
        cred = self._get_credential(identity_name)
        credential_id = b64decode(cred["credential_id"])
        salt = b64decode(cred["salt"])
        
        # Find device
        device = self._find_device()
        
        # Create client
        client = Fido2Client(
            device,
            f"https://{self.rp_id}",
            user_interaction=CLIUserInteraction(),
        )
        
        # Request assertion with hmac-secret
        uv = (
            UserVerificationRequirement.REQUIRED
            if self.require_uv
            else UserVerificationRequirement.DISCOURAGED
        )
        
        try:
            result = client.get_assertion(
                PublicKeyCredentialRequestOptions(
                    rp_id=self.rp_id,
                    challenge=secrets.token_bytes(32),
                    timeout=self.timeout * 1000,
                    allow_credentials=[
                        PublicKeyCredentialDescriptor(
                            type=PublicKeyCredentialType.PUBLIC_KEY,
                            id=credential_id,
                        )
                    ],
                    user_verification=uv,
                    extensions={"hmacGetSecret": {"salt1": salt}},
                )
            )
        except Exception as e:
            if "timeout" in str(e).lower() or "cancel" in str(e).lower():
                raise HSMUserCancelledError(
                    f"Operation cancelled or timed out: {e}"
                )
            if "pin" in str(e).lower():
                raise HSMUserCancelledError(f"PIN error: {e}")
            raise HSMNotAvailableError(f"Assertion failed: {e}")
        
        # Extract hmac-secret output
        assertion = result.get_response(0)
        ext_results = assertion.extension_results
        
        if not ext_results or "hmacGetSecret" not in ext_results:
            raise HSMExtensionNotSupportedError(
                "Authenticator did not return hmac-secret output."
            )
        
        pepper = ext_results["hmacGetSecret"]["output1"]
        
        if len(pepper) != self.PEPPER_SIZE:
            raise ValueError(
                f"Unexpected pepper size: {len(pepper)} (expected {self.PEPPER_SIZE})"
            )
        
        return pepper
    
    def unregister(self, identity_name: str) -> None:
        """
        Remove FIDO2 credential for identity.
        
        Note: This only removes the local credential reference.
        The credential on the authenticator cannot be deleted
        (FIDO2 limitation for non-resident credentials).
        
        Args:
            identity_name: Name of the identity
            
        Raises:
            HSMNotRegisteredError: No credential found
        """
        data = self._load_credentials()
        
        if identity_name not in data["credentials"]:
            raise HSMNotRegisteredError(
                f"No FIDO2 credential registered for identity '{identity_name}'."
            )
        
        del data["credentials"][identity_name]
        self._save_credentials(data)
    
    def list_registered(self) -> Dict[str, Dict[str, Any]]:
        """
        List all registered credentials.
        
        Returns:
            Dict mapping identity names to credential info
        """
        data = self._load_credentials()
        return {
            name: {
                "created_at": cred["created_at"],
                "description": cred.get("description"),
                "aaguid": cred.get("authenticator_aaguid"),
            }
            for name, cred in data["credentials"].items()
        }
```

### 4. CLI Commands

**File:** `openssl_encrypt/cli/fido2_commands.py`

```python
"""CLI commands for FIDO2 pepper management."""

import click
from typing import Optional

from ..plugins.hsm.fido2_pepper import FIDO2PepperPlugin
from ..plugins.hsm.exceptions import (
    HSMNotAvailableError,
    HSMNotRegisteredError,
    HSMAlreadyRegisteredError,
    HSMUserCancelledError,
    HSMExtensionNotSupportedError,
)


@click.group(name="fido2")
def fido2_group():
    """FIDO2 security key management for pepper derivation."""
    pass


@fido2_group.command(name="status")
def fido2_status():
    """Show FIDO2 device status and registered credentials."""
    plugin = FIDO2PepperPlugin()
    
    # List devices
    click.echo("Connected FIDO2 devices:")
    devices = plugin.list_devices()
    if not devices:
        click.echo("  (none)")
    else:
        for dev in devices:
            status = "✓ hmac-secret" if dev["hmac_secret_supported"] else "✗ no hmac-secret"
            click.echo(f"  • {dev['product_name']} [{status}]")
    
    click.echo()
    
    # List credentials
    click.echo("Registered credentials:")
    creds = plugin.list_registered()
    if not creds:
        click.echo("  (none)")
    else:
        for name, info in creds.items():
            click.echo(f"  • {name}")
            click.echo(f"    Authenticator: {info.get('description', 'unknown')}")
            click.echo(f"    Registered: {info['created_at']}")


@fido2_group.command(name="register")
@click.option("--identity", "-i", required=True, help="Identity name")
@click.option("--description", "-d", help="Description (e.g., 'YubiKey 5 NFC')")
def fido2_register(identity: str, description: Optional[str]):
    """Register a FIDO2 security key for an identity."""
    plugin = FIDO2PepperPlugin()
    
    try:
        click.echo(f"Registering FIDO2 credential for identity '{identity}'...")
        click.echo("You may need to enter your PIN and touch the key.")
        click.echo()
        
        result = plugin.register(identity, description)
        
        click.echo()
        click.echo(click.style("✓ Registration successful!", fg="green"))
        click.echo(f"  Identity: {result['identity']}")
        click.echo(f"  Authenticator: {result['authenticator']}")
        
    except HSMNotAvailableError as e:
        raise click.ClickException(str(e))
    except HSMAlreadyRegisteredError as e:
        raise click.ClickException(str(e))
    except HSMExtensionNotSupportedError as e:
        raise click.ClickException(str(e))
    except HSMUserCancelledError as e:
        raise click.ClickException(str(e))


@fido2_group.command(name="unregister")
@click.option("--identity", "-i", required=True, help="Identity name")
@click.confirmation_option(prompt="Are you sure you want to unregister?")
def fido2_unregister(identity: str):
    """Remove FIDO2 registration for an identity."""
    plugin = FIDO2PepperPlugin()
    
    try:
        plugin.unregister(identity)
        click.echo(click.style(f"✓ Credential removed for '{identity}'", fg="green"))
    except HSMNotRegisteredError as e:
        raise click.ClickException(str(e))


@fido2_group.command(name="test")
@click.option("--identity", "-i", required=True, help="Identity name")
def fido2_test(identity: str):
    """Test FIDO2 pepper derivation for an identity."""
    plugin = FIDO2PepperPlugin()
    
    try:
        click.echo(f"Testing FIDO2 pepper derivation for '{identity}'...")
        click.echo()
        
        pepper = plugin.get_pepper(identity)
        
        click.echo()
        click.echo(click.style("✓ Pepper derivation successful!", fg="green"))
        click.echo(f"  Pepper size: {len(pepper)} bytes")
        click.echo(f"  Pepper (hex, first 8 bytes): {pepper[:8].hex()}...")
        
    except HSMNotAvailableError as e:
        raise click.ClickException(str(e))
    except HSMNotRegisteredError as e:
        raise click.ClickException(str(e))
    except HSMUserCancelledError as e:
        raise click.ClickException(str(e))
```

---

## Integration with Key Derivation

### Modified Key Derivation Flow

When `--fido2-pepper` flag is used:

```
┌─────────────────────────────────────────────────────────────┐
│                    Key Derivation                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  User Input:                                                │
│    • Password (optional, depending on protection level)     │
│    • FIDO2 touch + PIN                                      │
│                                                             │
│  From Storage:                                              │
│    • Salt (from encrypted file header)                      │
│    • Credential ID + Pepper Salt (from local config)        │
│                                                             │
│  Derivation:                                                │
│    fido2_pepper = FIDO2_HMAC(credential, pepper_salt)      │
│    key_material = password || fido2_pepper                  │
│    key = Argon2id(key_material, salt)                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Protection Levels with FIDO2

```python
class ProtectionLevel(Enum):
    PASSWORD_ONLY = "password_only"
    PASSWORD_AND_FIDO2 = "password_and_fido2"  # Both required
    FIDO2_ONLY = "fido2_only"                  # Hardware only
```

---

## CLI Usage Examples

```bash
# Check device status
openssl_encrypt fido2 status

# Register security key for identity
openssl_encrypt fido2 register --identity alice
openssl_encrypt fido2 register --identity alice --description "YubiKey 5 NFC (primary)"

# Test pepper derivation
openssl_encrypt fido2 test --identity alice

# Encrypt with FIDO2 pepper (password + FIDO2)
openssl_encrypt encrypt --identity alice --fido2-pepper secret.txt

# Encrypt with FIDO2 only (no password)
openssl_encrypt encrypt --identity alice --fido2-only secret.txt

# Decrypt
openssl_encrypt decrypt --identity alice --fido2-pepper secret.txt.enc

# Remove registration
openssl_encrypt fido2 unregister --identity alice
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Stolen laptop | Pepper requires physical security key |
| Stolen security key | PIN required (user verification) |
| Stolen credential file | Useless without matching security key |
| Credential file tampering | Detected on use (wrong pepper = decryption fails) |
| Side-channel on pepper | Pepper never stored, derived on demand |

### Recommendations

1. **Always enable PIN** (`require_user_verification: true`)
2. **Register backup authenticator** for recovery
3. **Store credential file backup** (encrypted, offline)
4. **Use with password** for defense in depth (`PASSWORD_AND_FIDO2`)

---

## Testing

### Unit Tests

```python
# tests/plugins/hsm/test_fido2_pepper.py

import pytest
from unittest.mock import Mock, patch
from openssl_encrypt.plugins.hsm.fido2_pepper import FIDO2PepperPlugin


class TestFIDO2PepperPlugin:
    """Tests for FIDO2 pepper plugin."""
    
    def test_credential_storage_roundtrip(self, tmp_path):
        """Test credential save and load."""
        cred_file = tmp_path / "creds.json"
        plugin = FIDO2PepperPlugin(credential_file=cred_file)
        
        # Initially empty
        assert plugin.list_registered() == {}
        assert not plugin.is_registered("test")
    
    @patch("fido2.hid.CtapHidDevice.list_devices")
    def test_is_available_no_device(self, mock_list):
        """Test is_available when no device connected."""
        mock_list.return_value = []
        plugin = FIDO2PepperPlugin()
        assert plugin.is_available() is False
    
    # ... more tests
```

### Integration Tests (Manual)

```bash
# Requires physical security key
pytest tests/integration/test_fido2_integration.py -v --fido2-device
```

---

## Future Enhancements

1. **Backup Credentials**: Multiple authenticators per identity
2. **Platform Authenticators**: Windows Hello, Touch ID support
3. **Resident Credentials**: Optional discoverable credentials
4. **PRF Extension**: Use newer PRF extension when available (supersedes hmac-secret)

---

## References

- [FIDO2 Specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html)
- [hmac-secret Extension](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension)
- [python-fido2 Documentation](https://python-fido2.readthedocs.io/)
- [WebAuthn Guide](https://webauthn.guide/)
