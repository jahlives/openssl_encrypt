"""
HSM (Hardware Security Module) Management CLI

Command-line interface for managing HSM plugins, including FIDO2 registration and testing.

Usage:
    openssl_encrypt hsm fido2-register --description "YubiKey 5 NFC"
    openssl_encrypt hsm fido2-status
    openssl_encrypt hsm fido2-test
    openssl_encrypt hsm fido2-list
    openssl_encrypt hsm fido2-unregister
"""

import sys
import secrets
import click
from pathlib import Path
from typing import Optional

# Import FIDO2 plugin
try:
    from ..plugins.hsm.fido2_pepper import FIDO2HSMPlugin, FIDO2_AVAILABLE
except ImportError:
    FIDO2_AVAILABLE = False
    FIDO2HSMPlugin = None


@click.group(name="hsm")
def hsm_group():
    """Hardware Security Module management commands."""
    pass


@hsm_group.command(name="fido2-register")
@click.option(
    "--description",
    "-d",
    help="Human-readable description for the security key (e.g., 'YubiKey 5 NFC')",
    default=None,
)
@click.option(
    "--backup",
    is_flag=True,
    help="Register as backup credential (primary must already exist)",
)
@click.option(
    "--rp-id",
    help="Custom Relying Party ID (default: openssl-encrypt.local)",
    default=None,
)
def fido2_register(description: Optional[str], backup: bool, rp_id: Optional[str]):
    """
    Register a new FIDO2 credential for hardware-bound encryption.

    This is a one-time setup operation that creates a new credential on your
    FIDO2 authenticator (YubiKey, Nitrokey, etc.). The credential will be used
    to derive hardware-bound pepper values for encryption/decryption.

    Examples:
        # Register primary credential
        openssl_encrypt hsm fido2-register --description "YubiKey 5 NFC"

        # Register backup credential
        openssl_encrypt hsm fido2-register --description "Nitrokey 3" --backup
    """
    # Check FIDO2 availability
    if not FIDO2_AVAILABLE:
        click.echo("❌ Error: FIDO2 library not available", err=True)
        click.echo("Install with: pip install fido2>=1.1.0", err=True)
        sys.exit(1)

    # Initialize plugin
    plugin = FIDO2HSMPlugin(rp_id=rp_id) if rp_id else FIDO2HSMPlugin()

    # Initialize plugin
    init_result = plugin.initialize()
    if not init_result.success:
        click.echo(f"❌ Error: {init_result.message}", err=True)
        sys.exit(1)

    click.echo("\n🔐 FIDO2 Credential Registration")
    click.echo("=" * 50)

    if backup:
        click.echo("📦 Registering backup credential...")
    else:
        click.echo("🔑 Registering primary credential...")

    if description:
        click.echo(f"Description: {description}")

    click.echo("\nPlease insert your FIDO2 security key and follow the prompts.")
    click.echo("You may need to:")
    click.echo("  1. Enter your security key PIN")
    click.echo("  2. Touch your security key\n")

    # Register credential
    result = plugin.register_credential(description=description, is_backup=backup)

    if result.success:
        click.echo(f"\n✅ {result.message}")
        click.echo(f"\nCredential ID: {result.data.get('credential_id')}")
        click.echo(f"Configuration saved to: {plugin.credential_file}")
        click.echo("\nYou can now use this credential with:")
        click.echo("  openssl_encrypt encrypt --hsm fido2 <file>")
    else:
        click.echo(f"\n❌ Registration failed: {result.message}", err=True)
        sys.exit(1)


@hsm_group.command(name="fido2-status")
@click.option(
    "--rp-id",
    help="Custom Relying Party ID (default: openssl-encrypt.local)",
    default=None,
)
def fido2_status(rp_id: Optional[str]):
    """
    Show FIDO2 registration status and list registered credentials.

    Displays information about all registered FIDO2 credentials, including
    their IDs, descriptions, creation dates, and backup status.

    Example:
        openssl_encrypt hsm fido2-status
    """
    # Check FIDO2 availability
    if not FIDO2_AVAILABLE:
        click.echo("❌ Error: FIDO2 library not available", err=True)
        click.echo("Install with: pip install fido2>=1.1.0", err=True)
        sys.exit(1)

    # Initialize plugin
    plugin = FIDO2HSMPlugin(rp_id=rp_id) if rp_id else FIDO2HSMPlugin()

    click.echo("\n🔐 FIDO2 Registration Status")
    click.echo("=" * 50)

    # Check if registered
    if not plugin.is_registered():
        click.echo("❌ No FIDO2 credentials registered")
        click.echo("\nTo register a credential, run:")
        click.echo("  openssl_encrypt hsm fido2-register --description 'My Security Key'")
        sys.exit(0)

    # Load credentials
    credentials = plugin._load_credentials()

    click.echo(f"✅ {len(credentials)} credential(s) registered")
    click.echo(f"Configuration file: {plugin.credential_file}")
    click.echo(f"Relying Party ID: {plugin.rp_id}\n")

    # Display each credential
    for i, cred in enumerate(credentials, 1):
        click.echo(f"Credential #{i}:")
        click.echo(f"  ID: {cred['id']}")
        click.echo(f"  Description: {cred.get('description', 'N/A')}")
        click.echo(f"  Created: {cred.get('created_at', 'N/A')}")
        click.echo(f"  AAGUID: {cred.get('authenticator_aaguid', 'N/A')}")
        click.echo(f"  Backup: {'Yes' if cred.get('is_backup', False) else 'No'}")
        click.echo()


@hsm_group.command(name="fido2-test")
@click.option(
    "--rp-id",
    help="Custom Relying Party ID (default: openssl-encrypt.local)",
    default=None,
)
def fido2_test(rp_id: Optional[str]):
    """
    Test FIDO2 pepper derivation with a random salt.

    This command verifies that your FIDO2 credential is working correctly
    by performing a test pepper derivation. You will need to authenticate
    with your security key (PIN + touch).

    Example:
        openssl_encrypt hsm fido2-test
    """
    # Check FIDO2 availability
    if not FIDO2_AVAILABLE:
        click.echo("❌ Error: FIDO2 library not available", err=True)
        click.echo("Install with: pip install fido2>=1.1.0", err=True)
        sys.exit(1)

    # Initialize plugin
    plugin = FIDO2HSMPlugin(rp_id=rp_id) if rp_id else FIDO2HSMPlugin()

    # Initialize plugin
    init_result = plugin.initialize()
    if not init_result.success:
        click.echo(f"❌ Error: {init_result.message}", err=True)
        sys.exit(1)

    click.echo("\n🔐 FIDO2 Pepper Derivation Test")
    click.echo("=" * 50)

    # Check if registered
    if not plugin.is_registered():
        click.echo("❌ No FIDO2 credentials registered", err=True)
        click.echo("\nRegister a credential first:")
        click.echo("  openssl_encrypt hsm fido2-register")
        sys.exit(1)

    # Generate random test salt
    test_salt = secrets.token_bytes(16)
    click.echo(f"Test salt: {test_salt.hex()}")
    click.echo("\nPlease insert your FIDO2 security key and follow the prompts.")
    click.echo("You may need to:")
    click.echo("  1. Enter your security key PIN")
    click.echo("  2. Touch your security key\n")

    # Create dummy security context
    from ..modules.plugin_system.plugin_base import PluginSecurityContext, PluginCapability
    context = PluginSecurityContext(
        plugin_id=plugin.plugin_id,
        capabilities=plugin.get_required_capabilities()
    )

    # Test pepper derivation
    result = plugin.get_hsm_pepper(test_salt, context)

    if result.success:
        pepper = result.data.get("hsm_pepper")
        click.echo(f"\n✅ Test successful!")
        click.echo(f"Pepper length: {len(pepper)} bytes")
        click.echo(f"Pepper (hex): {pepper.hex()}")
        click.echo("\nYour FIDO2 credential is working correctly.")
    else:
        click.echo(f"\n❌ Test failed: {result.message}", err=True)
        sys.exit(1)


@hsm_group.command(name="fido2-list")
def fido2_list():
    """
    List connected FIDO2 devices and their capabilities.

    Shows information about all connected FIDO2 authenticators, including
    their names, manufacturers, supported features, and hmac-secret support.

    Example:
        openssl_encrypt hsm fido2-list
    """
    # Check FIDO2 availability
    if not FIDO2_AVAILABLE:
        click.echo("❌ Error: FIDO2 library not available", err=True)
        click.echo("Install with: pip install fido2>=1.1.0", err=True)
        sys.exit(1)

    # Initialize plugin
    plugin = FIDO2HSMPlugin()

    click.echo("\n🔐 Connected FIDO2 Devices")
    click.echo("=" * 50)

    # List devices
    devices = plugin.list_devices()

    if not devices:
        click.echo("❌ No FIDO2 devices found")
        click.echo("\nPlease connect a FIDO2 security key (YubiKey, Nitrokey, etc.)")
        sys.exit(0)

    click.echo(f"Found {len(devices)} device(s):\n")

    for i, device in enumerate(devices, 1):
        if "error" in device:
            click.echo(f"Device #{i}: {device.get('product_name', 'Unknown')}")
            click.echo(f"  Error: {device['error']}\n")
            continue

        click.echo(f"Device #{i}: {device.get('product_name', 'Unknown')}")
        click.echo(f"  Manufacturer: {device.get('manufacturer', 'Unknown')}")
        click.echo(f"  AAGUID: {device.get('aaguid', 'Unknown')}")
        click.echo(f"  Versions: {', '.join(device.get('versions', []))}")
        click.echo(f"  Extensions: {', '.join(device.get('extensions', []))}")

        # Highlight hmac-secret support
        hmac_support = device.get("hmac_secret_support", False)
        if hmac_support:
            click.echo(f"  hmac-secret: ✅ Supported")
        else:
            click.echo(f"  hmac-secret: ❌ Not supported")

        click.echo()


@hsm_group.command(name="fido2-unregister")
@click.option(
    "--credential-id",
    "-c",
    help="Specific credential ID to remove (e.g., 'primary', 'backup-1')",
    default=None,
)
@click.option(
    "--all",
    "remove_all",
    is_flag=True,
    help="Remove all registered credentials",
)
@click.option(
    "--rp-id",
    help="Custom Relying Party ID (default: openssl-encrypt.local)",
    default=None,
)
@click.confirmation_option(
    prompt="Are you sure you want to remove FIDO2 credentials? This cannot be undone."
)
def fido2_unregister(credential_id: Optional[str], remove_all: bool, rp_id: Optional[str]):
    """
    Remove FIDO2 credential registration.

    WARNING: This will remove credential registration from the local configuration.
    You will need to re-register to use FIDO2 encryption again.

    Note: This does NOT remove the credential from your security key itself.
    Use your authenticator's management tools for that.

    Examples:
        # Remove primary credential
        openssl_encrypt hsm fido2-unregister

        # Remove specific backup credential
        openssl_encrypt hsm fido2-unregister --credential-id backup-1

        # Remove all credentials
        openssl_encrypt hsm fido2-unregister --all
    """
    # Check FIDO2 availability
    if not FIDO2_AVAILABLE:
        click.echo("❌ Error: FIDO2 library not available", err=True)
        click.echo("Install with: pip install fido2>=1.1.0", err=True)
        sys.exit(1)

    # Initialize plugin
    plugin = FIDO2HSMPlugin(rp_id=rp_id) if rp_id else FIDO2HSMPlugin()

    click.echo("\n🔐 FIDO2 Credential Removal")
    click.echo("=" * 50)

    # Check if registered
    if not plugin.is_registered():
        click.echo("❌ No FIDO2 credentials registered")
        sys.exit(0)

    # Unregister
    result = plugin.unregister(credential_id=credential_id, remove_all=remove_all)

    if result.success:
        click.echo(f"\n✅ {result.message}")

        if remove_all:
            click.echo(f"Configuration file removed: {plugin.credential_file}")
        else:
            click.echo(f"Configuration updated: {plugin.credential_file}")

    else:
        click.echo(f"\n❌ Removal failed: {result.message}", err=True)
        sys.exit(1)


# For testing this module directly
if __name__ == "__main__":
    hsm_group()
