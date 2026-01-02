# FIDO2 Pepper Plugin - Implementation Analysis & Adjustments

## Executive Summary

Analysis of the FIDO2 pepper plugin specification against the current openssl_encrypt codebase. This document identifies required adjustments to align the spec with existing architecture and provides implementation recommendations.

**Status:** ✅ Specification is well-designed and compatible with current architecture
**Required Changes:** Minor adjustments to align with existing patterns
**Estimated Effort:** Medium (3-5 days for full implementation + testing)

---

## Current Architecture Analysis

### 1. HSM Plugin System (Existing)

**Location:** `openssl_encrypt/modules/plugin_system/plugin_base.py`

**Current HSMPlugin Base Class:**
```python
class HSMPlugin(BasePlugin):
    """Base class for Hardware Security Module (HSM) plugins."""

    def get_plugin_type(self) -> PluginType:
        return PluginType.HSM

    @abc.abstractmethod
    def get_hsm_pepper(self, salt: bytes, context: PluginSecurityContext) -> PluginResult:
        """Derive HSM pepper from salt using hardware security module."""
        pass
```

**Key Observations:**
- ✅ HSMPlugin base class already exists
- ✅ get_hsm_pepper() is the standard interface
- ✅ Returns PluginResult with hsm_pepper in data dict
- ✅ Salt is passed as bytes (16 bytes for encryption)
- ✅ Security context provides config and logging capabilities

### 2. Existing Yubikey Plugin (Reference Implementation)

**Location:** `openssl_encrypt/plugins/hsm/yubikey_challenge_response.py`

**Key Patterns:**
```python
class YubikeyHSMPlugin(HSMPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="yubikey_hsm",
            name="Yubikey Challenge-Response HSM",
            version="1.0.0"
        )

    def get_required_capabilities(self) -> Set[PluginCapability]:
        return {PluginCapability.ACCESS_CONFIG, PluginCapability.WRITE_LOGS}

    def get_hsm_pepper(self, salt: bytes, context: PluginSecurityContext) -> PluginResult:
        # Validate salt (16 bytes)
        # Perform hardware operation
        # Return PluginResult with hsm_pepper and optional metadata
        return PluginResult.success_result(
            "Success message",
            data={"hsm_pepper": response, "slot": slot}
        )

    def initialize(self, config: Dict[str, Any]) -> PluginResult:
        # Optional initialization method
        pass
```

### 3. Integration with Core System

**Location:** `openssl_encrypt/modules/crypt_core.py:4405-4464`

**HSM Plugin Invocation Pattern:**
```python
# In encrypt_file_symmetric():
if hsm_plugin:
    # Create security context
    hsm_context = PluginSecurityContext(
        plugin_id=hsm_plugin.plugin_id,
        capabilities={PluginCapability.ACCESS_CONFIG, PluginCapability.WRITE_LOGS},
    )
    hsm_context.metadata["salt"] = salt

    # Execute HSM plugin
    result = hsm_plugin.get_hsm_pepper(salt, hsm_context)

    if not result.success:
        raise KeyDerivationError(f"HSM pepper derivation failed: {result.message}")

    hsm_pepper = result.data.get("hsm_pepper")
    hsm_slot_used = result.data.get("slot")

    # Validate pepper
    # - Must be bytes
    # - Must be 16-128 bytes
    # - Warns if all zeros
```

### 4. CLI Integration

**Location:** `openssl_encrypt/modules/crypt_cli.py:4918-4933`

**Current HSM Loading Pattern:**
```python
# Direct import approach (not dynamic loading)
if args.hsm:
    if args.hsm.lower() == "yubikey":
        from ..plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin
        hsm_plugin_instance = YubikeyHSMPlugin()

        # Optional initialization
        init_result = hsm_plugin_instance.initialize({})
        if not init_result.success:
            print(f"Error initializing HSM plugin: {init_result.message}")
```

**CLI Arguments:**
```python
@click.option("--hsm", type=str, help="Enable HSM plugin (e.g., 'yubikey')")
@click.option("--hsm-slot", type=int, help="HSM slot number (optional)")
```

---

## Specification Adjustments Required

### 1. ❌ Remove Abstract Base Class Proposal

**Issue:** Spec proposes new `HSMPepperPlugin` abstract base class

**Spec (Lines 116-199):**
```python
class HSMPepperPlugin(ABC):
    @abstractmethod
    def is_available(self) -> bool: pass

    @abstractmethod
    def get_pepper(self, identity_name: str) -> bytes: pass

    @abstractmethod
    def register(self, identity_name: str, description: Optional[str] = None) -> None: pass

    # ... more methods
```

**Problem:**
- Existing system uses `HSMPlugin` base class from plugin_system
- Method signature differs: `get_hsm_pepper(salt, context)` not `get_pepper(identity)`
- Integration pattern is salt-based, not identity-based
- Would break existing Yubikey plugin

**✅ Resolution:**
- Use existing `HSMPlugin` base class
- Implement `get_hsm_pepper(salt, context)` method
- Add registration/management as additional methods (not in base)
- Keep identity management separate from core pepper derivation

### 2. ❌ Remove Separate Exceptions File

**Issue:** Spec proposes `exceptions.py` file (Lines 202-242)

**Current Architecture:**
- Plugins return `PluginResult` objects with success/failure
- Errors communicated via `PluginResult.error_result(message)`
- Core system handles failures gracefully
- Exceptions only raised for critical errors

**✅ Resolution:**
- Return `PluginResult.error_result()` for operational failures
- Only raise exceptions for truly exceptional conditions (e.g., internal bugs)
- Use standard Python exceptions when needed
- Error messages in PluginResult include user-friendly guidance

### 3. ⚠️ Adjust FIDO2PepperPlugin Interface

**Issue:** Spec's FIDO2PepperPlugin doesn't match HSMPlugin interface

**Spec's Interface:**
```python
class FIDO2PepperPlugin(HSMPepperPlugin):  # Wrong base class
    def get_pepper(self, identity_name: str) -> bytes:  # Wrong signature
        ...

    def register(self, identity_name: str, ...) -> Dict[str, Any]:  # Extra method
        ...
```

**✅ Corrected Interface:**
```python
class FIDO2PepperPlugin(HSMPlugin):  # Correct base class
    def __init__(self, rp_id: str = "openssl-encrypt.local", ...):
        super().__init__(
            plugin_id="fido2_hsm",
            name="FIDO2 hmac-secret HSM",
            version="1.0.0"
        )
        # ... initialization

    def get_required_capabilities(self) -> Set[PluginCapability]:
        return {PluginCapability.ACCESS_CONFIG, PluginCapability.WRITE_LOGS}

    def get_hsm_pepper(self, salt: bytes, context: PluginSecurityContext) -> PluginResult:
        """
        Standard HSM plugin interface.

        Args:
            salt: 16-byte encryption salt (used as FIDO2 hmac-secret input)
            context: Security context with config and logging

        Returns:
            PluginResult with hsm_pepper (32 bytes) in data dict
        """
        # Use salt directly as hmac-secret salt1
        # No identity lookup needed - salt uniquely identifies encryption
        ...

    # Additional methods for credential management (not in base)
    def register_credential(self, identity_name: str, ...) -> PluginResult:
        """Register FIDO2 credential for an identity."""
        ...

    def list_credentials(self) -> List[Dict[str, Any]]:
        """List registered credentials."""
        ...
```

### 4. ⚠️ Identity vs Salt-Based Design

**Issue:** Spec uses identity-based credential lookup

**Spec's Flow:**
```
identity_name → credential_id + salt → FIDO2 assertion → pepper
```

**Current System's Flow:**
```
encryption salt (16 bytes) → HSM operation → pepper
```

**Problem:**
- Current system doesn't pass identity to get_hsm_pepper()
- Salt is generated per-file during encryption
- No identity concept in core encryption flow

**✅ Resolution - Option A (Recommended): Salt-Only Design**

Use encryption salt directly as FIDO2 hmac-secret input:

```python
def get_hsm_pepper(self, salt: bytes, context: PluginSecurityContext) -> PluginResult:
    """
    Derive pepper using salt directly with FIDO2 hmac-secret.

    Design:
    - Uses a single FIDO2 credential (no per-identity credentials)
    - Salt is used directly as hmac-secret salt1
    - Same credential works for all encrypted files
    - User touches security key + enters PIN for each operation
    """
    # Use default credential (registered once)
    credential_id = self._get_default_credential()

    # Use salt directly as hmac-secret input
    pepper = self._get_hmac_secret(credential_id, salt)

    return PluginResult.success_result(
        "FIDO2 pepper derived",
        data={"hsm_pepper": pepper}
    )
```

**Advantages:**
- ✅ Matches existing HSM plugin pattern
- ✅ No identity management complexity
- ✅ Works with current CLI (no identity flags needed)
- ✅ Simpler implementation
- ✅ Each file has unique pepper (derived from unique salt)

**✅ Resolution - Option B: Hybrid Design**

Support optional identity-based credentials as enhancement:

```python
def get_hsm_pepper(self, salt: bytes, context: PluginSecurityContext) -> PluginResult:
    """
    Derive pepper using FIDO2 hmac-secret.

    Supports two modes:
    1. Default credential (no identity) - standard HSM flow
    2. Identity-specific credential - advanced feature
    """
    # Check if identity specified in context config
    identity = context.config.get("identity")

    if identity:
        # Identity-based credential (advanced)
        cred_data = self._get_credential(identity)
        credential_id = cred_data["credential_id"]
        # Combine salt with stored pepper salt
        derived_salt = self._derive_salt(salt, cred_data["salt"])
    else:
        # Default credential (standard)
        credential_id = self._get_default_credential()
        derived_salt = salt

    pepper = self._get_hmac_secret(credential_id, derived_salt)

    return PluginResult.success_result(
        "FIDO2 pepper derived",
        data={"hsm_pepper": pepper}
    )
```

**Recommendation:** Start with **Option A** (simpler), add Option B later if needed.

### 5. ⚠️ CLI Commands Structure

**Issue:** Spec proposes standalone `fido2_commands.py` file

**Current Pattern:** Commands are integrated into main CLI structure

**✅ Resolution:**

Add FIDO2 commands to existing CLI structure:

```python
# In openssl_encrypt/modules/crypt_cli.py or separate hsm_cli.py

@click.group(name="hsm")
def hsm_group():
    """Hardware Security Module management."""
    pass

@hsm_group.command(name="fido2-register")
@click.option("--description", "-d", help="Device description")
def fido2_register(description):
    """Register FIDO2 security key."""
    from ..plugins.hsm.fido2_pepper import FIDO2PepperPlugin
    plugin = FIDO2PepperPlugin()
    # Register default credential
    ...

@hsm_group.command(name="fido2-test")
def fido2_test():
    """Test FIDO2 pepper derivation."""
    ...

@hsm_group.command(name="fido2-status")
def fido2_status():
    """Show FIDO2 device and credential status."""
    ...
```

**CLI Integration:**
```bash
# Register FIDO2 key (one-time setup)
openssl_encrypt hsm fido2-register --description "YubiKey 5 NFC"

# Test derivation
openssl_encrypt hsm fido2-test

# Encrypt with FIDO2 pepper
openssl_encrypt encrypt --hsm fido2 secret.txt

# Decrypt with FIDO2 pepper
openssl_encrypt decrypt --hsm fido2 secret.txt.enc
```

### 6. ✅ Credential Storage (Keep As-Is)

**Spec's Approach:** JSON file at `~/.config/openssl_encrypt/fido2_credentials.json`

**Verdict:** ✅ Good design, keep as-is

**Structure:**
```json
{
  "version": 1,
  "rp_id": "openssl-encrypt.local",
  "default_credential": {
    "credential_id": "<base64>",
    "created_at": "2025-12-31T12:00:00Z",
    "authenticator_aaguid": "<uuid>",
    "description": "YubiKey 5 NFC"
  }
}
```

**Note:** Simplified to single default credential (not per-identity).

### 7. ✅ Configuration (Adjust Path)

**Spec:** Plugin-specific config in main config.yaml

**Current:** Config passed via context.config dict

**✅ Resolution:**

Support both approaches:

```yaml
# In ~/.config/openssl_encrypt/config.yaml (optional)
plugins:
  fido2_hsm:
    enabled: true
    rp_id: "openssl-encrypt.local"
    require_user_verification: true
    require_user_presence: true
    timeout_seconds: 30
```

Or passed via CLI:
```bash
openssl_encrypt encrypt --hsm fido2 --hsm-config rp_id=openssl-encrypt.local file.txt
```

### 8. ⚠️ Protection Levels (Future Enhancement)

**Spec Lines 915-920:** Proposes new protection levels

```python
class ProtectionLevel(Enum):
    PASSWORD_ONLY = "password_only"
    PASSWORD_AND_FIDO2 = "password_and_fido2"
    FIDO2_ONLY = "fido2_only"
```

**Current System:**
- Password always required for symmetric encryption
- HSM pepper is added to key derivation when --hsm flag used
- No "hardware-only" mode

**✅ Resolution:**

Phase 1: Keep current behavior
```bash
# Password + FIDO2 pepper (default)
openssl_encrypt encrypt --hsm fido2 file.txt
```

Phase 2: Add FIDO2-only mode later
```bash
# FIDO2 only (no password prompt)
openssl_encrypt encrypt --hsm fido2 --no-password file.txt
```

---

## Recommended Implementation Plan

### Phase 1: Core FIDO2 Plugin (Week 1-2)

**Files to Create:**
```
openssl_encrypt/plugins/hsm/fido2_pepper.py  # Main plugin
```

**Implementation Checklist:**
- [x] Define FIDO2PepperPlugin class extending HSMPlugin
- [ ] Implement get_hsm_pepper(salt, context) method
- [ ] Implement device discovery (CtapHidDevice.list_devices())
- [ ] Implement hmac-secret credential creation
- [ ] Implement hmac-secret assertion (pepper derivation)
- [ ] Implement credential storage (JSON file)
- [ ] Add comprehensive error handling
- [ ] Add logging and user feedback

**Core Method:**
```python
def get_hsm_pepper(self, salt: bytes, context: PluginSecurityContext) -> PluginResult:
    """
    Derive 32-byte pepper using FIDO2 hmac-secret extension.

    Process:
    1. Load default credential from ~/.config/openssl_encrypt/fido2_credentials.json
    2. Find connected FIDO2 device
    3. Request assertion with hmac-secret extension (salt1=salt)
    4. Extract 32-byte pepper from extension output
    5. Return PluginResult with pepper
    """
    try:
        # Load credential
        credential_id = self._load_default_credential()

        # Find device
        device = self._find_device()

        # Create FIDO2 client
        client = Fido2Client(device, f"https://{self.rp_id}", user_interaction=CLIUserInteraction())

        # Get assertion with hmac-secret
        result = client.get_assertion(
            PublicKeyCredentialRequestOptions(
                rp_id=self.rp_id,
                challenge=secrets.token_bytes(32),
                allow_credentials=[PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=credential_id)],
                user_verification=UserVerificationRequirement.REQUIRED,
                extensions={"hmacGetSecret": {"salt1": salt}},
                timeout=self.timeout * 1000,
            )
        )

        # Extract pepper
        assertion = result.get_response(0)
        pepper = assertion.extension_results["hmacGetSecret"]["output1"]

        return PluginResult.success_result(
            f"FIDO2 pepper derived ({len(pepper)} bytes)",
            data={"hsm_pepper": pepper}
        )

    except Exception as e:
        return PluginResult.error_result(f"FIDO2 pepper derivation failed: {e}")
```

### Phase 2: CLI Integration (Week 2)

**Files to Modify:**
```
openssl_encrypt/modules/crypt_cli.py  # Add FIDO2 plugin loading
openssl_encrypt/modules/hsm_cli.py    # Create HSM command group (optional)
```

**Implementation:**
```python
# In crypt_cli.py, update HSM loading:
if args.hsm:
    if args.hsm.lower() == "yubikey":
        from ..plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin
        hsm_plugin_instance = YubikeyHSMPlugin()
    elif args.hsm.lower() == "fido2":
        from ..plugins.hsm.fido2_pepper import FIDO2PepperPlugin
        hsm_plugin_instance = FIDO2PepperPlugin()
    else:
        raise click.ClickException(f"Unknown HSM plugin: {args.hsm}")
```

**CLI Commands:**
```python
@click.group(name="hsm")
def hsm_group():
    """Hardware Security Module management."""
    pass

@hsm_group.command(name="fido2-register")
@click.option("--description", "-d", help="Device description")
def fido2_register(description):
    """Register FIDO2 security key for pepper derivation."""
    plugin = FIDO2PepperPlugin()
    result = plugin.register_credential(description=description)
    if result.success:
        click.echo(click.style("✓ FIDO2 key registered!", fg="green"))
    else:
        raise click.ClickException(result.message)

@hsm_group.command(name="fido2-status")
def fido2_status():
    """Show FIDO2 device and credential status."""
    plugin = FIDO2PepperPlugin()
    # Show connected devices
    # Show registered credentials
    ...

@hsm_group.command(name="fido2-test")
def fido2_test():
    """Test FIDO2 pepper derivation."""
    plugin = FIDO2PepperPlugin()
    # Generate test salt
    # Derive pepper
    # Show success
    ...
```

### Phase 3: Testing (Week 3)

**Unit Tests:**
```python
# tests/plugins/hsm/test_fido2_pepper.py

class TestFIDO2PepperPlugin:
    def test_credential_storage(self, tmp_path):
        """Test credential file operations."""
        ...

    @patch("fido2.hid.CtapHidDevice.list_devices")
    def test_device_detection(self, mock_devices):
        """Test device discovery."""
        ...

    def test_pepper_validation(self):
        """Test pepper size and format validation."""
        ...
```

**Integration Tests (Manual):**
```bash
# Requires physical FIDO2 key
pytest tests/integration/test_fido2_integration.py -v --fido2-device
```

### Phase 4: Documentation (Week 3)

**Files to Create:**
```
openssl_encrypt/docs/FIDO2_HSM_GUIDE.md
```

**Content:**
- Setup instructions
- Registration process
- Usage examples
- Troubleshooting
- Security considerations
- Comparison with Yubikey OTP plugin

---

## Key Differences from Spec

| Aspect | Spec | Adjusted Implementation |
|--------|------|-------------------------|
| Base Class | HSMPepperPlugin (new) | HSMPlugin (existing) |
| Main Method | get_pepper(identity) | get_hsm_pepper(salt, context) |
| Credential Management | Per-identity credentials | Single default credential |
| Exceptions | Custom exception classes | PluginResult error patterns |
| CLI Structure | Standalone fido2_commands.py | Integrated into hsm group |
| Identity Support | Built-in | Optional future enhancement |
| Protection Levels | New enum | Use existing pattern |

---

## Security Considerations

### ✅ Maintained Security Properties

1. **Hardware Binding:** ✓ Pepper requires physical FIDO2 key
2. **PIN Protection:** ✓ User verification enforced
3. **Pepper Never Stored:** ✓ Derived on-demand from hardware
4. **Salt Uniqueness:** ✓ Each file has unique salt → unique pepper
5. **Defense in Depth:** ✓ Password + HSM pepper

### ⚠️ Adjusted Security Model

**Original Spec:**
- Per-identity credentials
- Stored salt combined with encryption salt
- Credential ID bound to identity

**Adjusted Model:**
- Single default credential (simpler)
- Encryption salt used directly
- Credential ID constant across all files

**Security Impact:**
- ✅ Still secure (pepper uniqueness from unique salts)
- ✅ Simpler threat model
- ✅ Easier to understand and verify

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Stolen laptop | Requires physical FIDO2 key |
| Stolen FIDO2 key | Requires PIN |
| Stolen credential file | Useless without matching key |
| Malicious plugin | Sandbox + capability enforcement |
| Side-channel attacks | Pepper never stored, derived in hardware |

---

## Dependencies

**Required:**
```
fido2>=1.1.0  # python-fido2 library
```

**Installation:**
```bash
pip install fido2
```

**Compatibility:**
- Python 3.7+
- Linux, macOS, Windows
- Any FIDO2 authenticator with hmac-secret extension
  - YubiKey 5 series
  - Nitrokey 3
  - SoloKey v2
  - Google Titan Security Key
  - etc.

---

## Migration from Yubikey OTP Plugin

Users can use both plugins simultaneously:

```bash
# Legacy: Yubikey OTP Challenge-Response (20-byte pepper)
openssl_encrypt encrypt --hsm yubikey secret.txt

# New: FIDO2 hmac-secret (32-byte pepper)
openssl_encrypt encrypt --hsm fido2 secret.txt
```

**No migration needed** - both plugins coexist independently.

---

## Future Enhancements

1. **Multiple Credentials:** Support backup authenticators
2. **Identity-Based Credentials:** Per-identity credential management
3. **Platform Authenticators:** Windows Hello, Touch ID support
4. **PRF Extension:** Use newer PRF extension when available
5. **FIDO2-Only Mode:** No password required (hardware-only)
6. **Credential Backup:** Encrypted credential file backup/restore

---

## Conclusion

The FIDO2 pepper plugin specification is **well-designed and compatible** with the existing architecture. Key adjustments:

1. ✅ Use existing `HSMPlugin` base class
2. ✅ Implement `get_hsm_pepper(salt, context)` interface
3. ✅ Simplify to single default credential (not per-identity)
4. ✅ Return `PluginResult` objects (not exceptions)
5. ✅ Integrate CLI commands into HSM command group
6. ✅ Salt-based design matches existing pattern

**Recommendation:** Proceed with adjusted specification. Implementation effort is reasonable and provides significant security enhancement with FIDO2 standard support.

---

*Analysis Date: 2026-01-02*
*Analyzer: Claude Sonnet 4.5*
*Target: openssl_encrypt v1.4.0-development*
