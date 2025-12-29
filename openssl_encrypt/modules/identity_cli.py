#!/usr/bin/env python3
"""
Identity CLI Module

Provides CLI commands for managing identities:
- create: Generate new identity
- list: Show all identities
- show: Display identity details
- export: Export public identity
- import: Import public identity
- delete: Remove identity
- change-password: Change identity passphrase
"""

import getpass
import json
import os
import sys
from pathlib import Path
from typing import Optional

from .identity import Identity, IdentityError, IdentityStore
from .identity_protection import HSMNotAvailableError, IdentityKeyProtectionService, ProtectionLevel
from .pqc_signing import LIBOQS_AVAILABLE


def get_identity_store(base_path: Optional[Path] = None) -> IdentityStore:
    """Get IdentityStore instance with path resolution.

    Priority (lowest to highest):
    1. Default: ~/.openssl_encrypt/identities/
    2. Environment variable: OPENSSL_ENCRYPT_IDENTITY_STORE
    3. Explicit base_path parameter

    Args:
        base_path: Optional path to identity store. Can be Path or str.

    Returns:
        IdentityStore instance
    """
    if base_path is None:
        # Check environment variable
        env_path = os.environ.get("OPENSSL_ENCRYPT_IDENTITY_STORE")
        if env_path:
            base_path = Path(env_path).expanduser()
        else:
            base_path = Path.home() / ".openssl_encrypt" / "identities"
    elif isinstance(base_path, str):
        base_path = Path(base_path).expanduser()
    return IdentityStore(base_path=base_path)


def prompt_passphrase(prompt: str = "Passphrase: ", confirm: bool = False) -> str:
    """
    Prompt for passphrase with optional confirmation.

    Args:
        prompt: Prompt message
        confirm: If True, ask for confirmation

    Returns:
        Passphrase string

    Raises:
        ValueError: If passphrases don't match
    """
    passphrase = getpass.getpass(prompt)

    if confirm:
        confirm_passphrase = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm_passphrase:
            raise ValueError("Passphrases do not match")

    return passphrase


def cmd_create(args) -> int:
    """
    Create a new identity.

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 = success, 1 = error)
    """
    if not LIBOQS_AVAILABLE:
        print(
            "ERROR: liboqs not available. Cannot create identity.",
            file=sys.stderr,
        )
        return 1

    try:
        # Determine protection level from --hsm argument
        hsm_option = getattr(args, "hsm", "none")
        if hsm_option == "none" or hsm_option is None:
            protection_level = ProtectionLevel.PASSWORD_ONLY
        elif hsm_option == "yubikey":
            protection_level = ProtectionLevel.PASSWORD_AND_HSM
        elif hsm_option == "yubikey-only":
            protection_level = ProtectionLevel.HSM_ONLY
        else:
            print(f"ERROR: Unknown HSM option: {hsm_option}", file=sys.stderr)
            return 1

        # Check HSM availability if required
        if protection_level in (ProtectionLevel.PASSWORD_AND_HSM, ProtectionLevel.HSM_ONLY):
            protection_service = IdentityKeyProtectionService()
            if not protection_service.is_hsm_available():
                print("ERROR: Yubikey not found. Please insert your Yubikey.", file=sys.stderr)
                return 1

            detected_slot = protection_service.detect_hsm_slot()
            if detected_slot is None:
                print(
                    "ERROR: No Challenge-Response slot configured on Yubikey.\n"
                    "Please configure slot 1 or 2 for HMAC-SHA1 Challenge-Response.",
                    file=sys.stderr,
                )
                return 1

            hsm_slot = getattr(args, "hsm_slot", None)
            if hsm_slot is None:
                hsm_slot = detected_slot
                print(f"Using Yubikey slot {hsm_slot} (auto-detected)")

        # Get passphrase (not required for HSM_ONLY)
        passphrase = None
        if protection_level != ProtectionLevel.HSM_ONLY:
            passphrase = prompt_passphrase("Passphrase for new identity: ", confirm=True)

            if len(passphrase) < 8:
                print(
                    "ERROR: Passphrase must be at least 8 characters",
                    file=sys.stderr,
                )
                return 1

        # Get algorithms
        kem_algo = getattr(args, "kem_algorithm", "ML-KEM-768")
        sig_algo = getattr(args, "sig_algorithm", "ML-DSA-65")

        # Generate identity
        print(f"Generating identity for '{args.name}'...")

        if protection_level in (ProtectionLevel.PASSWORD_AND_HSM, ProtectionLevel.HSM_ONLY):
            print("Touch your Yubikey to generate keys...")

        hsm_slot_arg = getattr(args, "hsm_slot", None)
        require_touch = not getattr(args, "no_touch", False)

        identity = Identity.generate(
            name=args.name,
            email=args.email,
            passphrase=passphrase,
            kem_algorithm=kem_algo,
            sig_algorithm=sig_algo,
            protection_level=protection_level,
            hsm_slot=hsm_slot_arg,
            require_touch=require_touch,
        )

        # Save to store
        store = get_identity_store(getattr(args, "identity_store", None))
        store.add_identity(identity, passphrase, overwrite=getattr(args, "overwrite", False))

        print("\nIdentity created successfully!")
        print(f"Name: {identity.name}")
        if identity.email:
            print(f"Email: {identity.email}")
        print(f"Fingerprint: {identity.fingerprint}")
        print(f"Encryption: {identity.encryption_algorithm}")
        print(f"Signing: {identity.signing_algorithm}")

        # Show protection level
        if identity.protection:
            print(f"\nProtection: {identity.protection.level.value}")
            if protection_level == ProtectionLevel.PASSWORD_AND_HSM:
                print("  → Both password AND Yubikey required for decryption")
            elif protection_level == ProtectionLevel.HSM_ONLY:
                print("  → Only Yubikey required (no password)")
        else:
            print("\nProtection: password_only (default)")

        return 0

    except IdentityError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except HSMNotAvailableError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: Failed to create identity: {e}", file=sys.stderr)
        return 1


def cmd_list(args) -> int:
    """
    List all identities.

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 = success)
    """
    try:
        store = get_identity_store(getattr(args, "identity_store", None))

        # Get identities based on filter
        include_contacts = getattr(args, "include_contacts", True)
        identities = store.list_identities(include_contacts=include_contacts)

        if not identities:
            print("No identities found.")
            return 0

        # Separate own identities and contacts
        own_identities = [i for i in identities if i.is_own_identity]
        contacts = [i for i in identities if not i.is_own_identity]

        # Display own identities
        if own_identities:
            print("Own Identities:")
            print("-" * 80)
            for identity in own_identities:
                print(f"Name: {identity.name}")
                if identity.email:
                    print(f"  Email: {identity.email}")
                print(f"  Fingerprint: {identity.fingerprint}")
                alg_str = f"{identity.encryption_algorithm} / "
                alg_str += identity.signing_algorithm
                print(f"  Algorithms: {alg_str}")
                print()

        # Display contacts
        if contacts and include_contacts:
            print("\nContacts (public keys only):")
            print("-" * 80)
            for identity in contacts:
                print(f"Name: {identity.name}")
                if identity.email:
                    print(f"  Email: {identity.email}")
                print(f"  Fingerprint: {identity.fingerprint}")
                alg_str = f"{identity.encryption_algorithm} / "
                alg_str += identity.signing_algorithm
                print(f"  Algorithms: {alg_str}")
                print()

        # Summary
        total = len(identities)
        own_count = len(own_identities)
        contact_count = len(contacts)

        if include_contacts:
            print(f"Total: {total} ({own_count} own, {contact_count} contacts)")
        else:
            print(f"Total: {own_count} own identities")

        return 0

    except Exception as e:
        print(f"ERROR: Failed to list identities: {e}", file=sys.stderr)
        return 1


def cmd_show(args) -> int:
    """
    Show detailed information about an identity.

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 = success, 1 = error)
    """
    try:
        store = get_identity_store(getattr(args, "identity_store", None))

        # Try to load identity
        identity = store.get_by_name(args.identity_name, passphrase=None, load_private_keys=False)

        if identity is None:
            print(
                f"ERROR: Identity '{args.identity_name}' not found ❌",
                file=sys.stderr,
            )
            return 1

        # Display information
        print("Identity Information:")
        print("=" * 80)
        print(f"Name: {identity.name}")
        if identity.email:
            print(f"Email: {identity.email}")
        print(f"Fingerprint: {identity.fingerprint}")
        identity_type = (
            "Own identity (has private keys)"
            if identity.is_own_identity
            else "Contact (public keys only)"
        )
        print(f"Type: {identity_type}")
        print()

        print("Algorithms:")
        print(f"  Encryption: {identity.encryption_algorithm}")
        print(f"  Signing: {identity.signing_algorithm}")
        print()

        print("Public Keys:")
        print(f"  Encryption key size: {len(identity.encryption_public_key)} bytes")
        print(f"  Signing key size: {len(identity.signing_public_key)} bytes")

        if identity.is_own_identity:
            print()
            print("Private Keys: YES (encrypted on disk)")

            # Show protection information
            if identity.protection:
                print()
                print("Protection:")
                print(f"  Level: {identity.protection.level.value}")
                if identity.protection.requires_password():
                    print("  Password: Required")
                if identity.protection.requires_hsm():
                    print(f"  HSM: Required ({identity.protection.hsm_config.hsm_type})")
                    if identity.protection.hsm_config.slot:
                        print(f"    Slot: {identity.protection.hsm_config.slot}")
                    print(f"    Touch required: {identity.protection.hsm_config.require_touch}")
            else:
                print()
                print("Protection: password_only (default)")

        return 0

    except Exception as e:
        print(f"ERROR: Failed to show identity: {e}", file=sys.stderr)
        return 1


def cmd_export(args) -> int:
    """
    Export public identity to file.

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 = success, 1 = error)
    """
    try:
        store = get_identity_store(getattr(args, "identity_store", None))

        # Load identity
        identity = store.get_by_name(args.identity_name, passphrase=None, load_private_keys=False)

        if identity is None:
            print(
                f"ERROR: Identity '{args.identity_name}' not found ❌",
                file=sys.stderr,
            )
            return 1

        # Export public data
        public_data = identity.export_public()

        # Determine output file
        if args.output:
            output_file = Path(args.output)
        else:
            output_file = Path(f"{args.identity_name}_public.json")

        # Check if file exists
        if output_file.exists() and not getattr(args, "overwrite", False):
            error_msg = (
                f"ERROR: Output file '{output_file}' already exists. " "Use --overwrite to replace."
            )
            print(error_msg, file=sys.stderr)
            return 1

        # Write to file
        with open(output_file, "w") as f:
            json.dump(public_data, f, indent=2)

        print(f"Public identity exported to: {output_file}")
        print(f"Fingerprint: {identity.fingerprint}")

        return 0

    except Exception as e:
        print(f"ERROR: Failed to export identity: {e}", file=sys.stderr)
        return 1


def cmd_import(args) -> int:
    """
    Import public identity from file.

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 = success, 1 = error)
    """
    try:
        # Read file
        input_file = Path(args.file)

        if not input_file.exists():
            print(f"ERROR: File '{input_file}' not found", file=sys.stderr)
            return 1

        with open(input_file, "r") as f:
            public_data = json.load(f)

        # Import identity
        identity = Identity.import_public(public_data)

        # Add to store
        store = get_identity_store(getattr(args, "identity_store", None))
        store.add_identity(
            identity,
            passphrase=None,
            overwrite=getattr(args, "overwrite", False),
        )

        print("Identity imported successfully!")
        print(f"Name: {identity.name}")
        if identity.email:
            print(f"Email: {identity.email}")
        print(f"Fingerprint: {identity.fingerprint}")

        return 0

    except IdentityError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON file: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: Failed to import identity: {e}", file=sys.stderr)
        return 1


def cmd_delete(args) -> int:
    """
    Delete an identity.

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 = success, 1 = error)
    """
    try:
        store = get_identity_store(getattr(args, "identity_store", None))

        # Check if identity exists
        identity = store.get_by_name(args.identity_name, passphrase=None, load_private_keys=False)

        if identity is None:
            print(
                f"ERROR: Identity '{args.identity_name}' not found ❌",
                file=sys.stderr,
            )
            return 1

        # Confirm deletion unless --force
        if not getattr(args, "force", False):
            print(f"WARNING: This will delete identity '{args.identity_name}'")
            print(f"Fingerprint: {identity.fingerprint}")
            if identity.is_own_identity:
                print("This includes the private keys!")

            response = input("Are you sure? (yes/no): ")
            if response.lower() not in ["yes", "y"]:
                print("Deletion cancelled.")
                return 0

        # Delete identity
        result = store.delete_identity(args.identity_name)

        if result:
            print(f"Identity '{args.identity_name}' deleted successfully.")
            return 0
        else:
            print(
                f"ERROR: Failed to delete identity '{args.identity_name}'",
                file=sys.stderr,
            )
            return 1

    except Exception as e:
        print(f"ERROR: Failed to delete identity: {e}", file=sys.stderr)
        return 1


def cmd_change_password(args) -> int:
    """
    Change the passphrase for an identity.

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 = success, 1 = error)
    """
    try:
        store = get_identity_store(getattr(args, "identity_store", None))

        # Check if identity exists and is own identity
        identity_check = store.get_by_name(
            args.identity_name, passphrase=None, load_private_keys=False
        )

        if identity_check is None:
            print(
                f"ERROR: Identity '{args.identity_name}' not found ❌",
                file=sys.stderr,
            )
            return 1

        if not identity_check.is_own_identity:
            error_msg = (
                f"ERROR: Cannot change passphrase for contact "
                f"'{args.identity_name}' (no private keys)"
            )
            print(error_msg, file=sys.stderr)
            return 1

        # Get old passphrase
        old_passphrase = prompt_passphrase("Current passphrase: ")

        # Load identity with old passphrase
        try:
            identity = store.get_by_name(
                args.identity_name,
                passphrase=old_passphrase,
                load_private_keys=True,
            )
        except ValueError:
            print("ERROR: Incorrect passphrase", file=sys.stderr)
            return 1

        # Get new passphrase
        new_passphrase = prompt_passphrase("New passphrase: ", confirm=True)

        if len(new_passphrase) < 8:
            print(
                "ERROR: New passphrase must be at least 8 characters",
                file=sys.stderr,
            )
            return 1

        # Save with new passphrase
        store.add_identity(identity, new_passphrase, overwrite=True)

        print(f"Passphrase changed successfully for '{args.identity_name}'")

        return 0

    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: Failed to change passphrase: {e}", file=sys.stderr)
        return 1


def main(args) -> int:
    """
    Main entry point for identity CLI commands.

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 = success, non-zero = error)
    """
    # Dispatch to appropriate command
    command = getattr(args, "identity_action", None)

    if command == "create":
        return cmd_create(args)
    elif command == "list":
        return cmd_list(args)
    elif command == "show":
        return cmd_show(args)
    elif command == "export":
        return cmd_export(args)
    elif command == "import":
        return cmd_import(args)
    elif command == "delete":
        return cmd_delete(args)
    elif command == "change-password":
        return cmd_change_password(args)
    else:
        print("ERROR: Unknown identity command", file=sys.stderr)
        return 1
