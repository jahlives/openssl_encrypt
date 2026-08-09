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

from .crypt_utils import eprint, prompt_and_read, sanitize_for_display
from .identity import (
    Identity,
    IdentityError,
    IdentityKeyChangedError,
    IdentityStore,
    validate_identity_name,
)
from .identity_protection import HSMNotAvailableError, IdentityKeyProtectionService, ProtectionLevel
from .json_validator import JSONSecurityError, SecureJSONValidator, get_json_validator
from .pqc_signing import LIBOQS_AVAILABLE

# Upper bound on an identity document, whether it arrives on stdin or in a
# file. Derived from the JSON validator's own limit rather than duplicated, so
# the two cannot drift apart.
#
# Note the units differ deliberately: this bound is enforced in BYTES (below),
# while SecureJSONValidator compares len() in CHARACTERS (json_validator.py).
# Bytes are the stricter reading for any non-ASCII document, so a document
# accepted here always satisfies the validator too.
MAX_IDENTITY_DOCUMENT_BYTES = SecureJSONValidator.MAX_JSON_SIZE


class IdentityDocumentTooLarge(IdentityError):
    """Raised when an identity document exceeds MAX_IDENTITY_DOCUMENT_BYTES."""


def _read_bounded(stream) -> str:
    """Read an identity document without materialising an unbounded one.

    Reads one character more than the limit: since every character encodes to
    at least one byte, a stream longer than the limit always yields more than
    MAX_IDENTITY_DOCUMENT_BYTES bytes here and is rejected. Truncation can
    therefore never be followed by acceptance.

    Args:
        stream: A text stream positioned at the start of the document.

    Returns:
        The document text.

    Raises:
        IdentityDocumentTooLarge: If the document exceeds the byte bound.
    """
    raw = stream.read(MAX_IDENTITY_DOCUMENT_BYTES + 1)
    # surrogatepass only ever over-counts (3 bytes for a lone surrogate from a
    # surrogateescape-configured stream), which is the safe direction.
    if len(raw.encode("utf-8", "surrogatepass")) > MAX_IDENTITY_DOCUMENT_BYTES:
        raise IdentityDocumentTooLarge(
            f"identity document exceeds {MAX_IDENTITY_DOCUMENT_BYTES} bytes"
        )
    return raw


def _parse_identity_document(raw: str) -> object:
    """Parse an untrusted identity document.

    Routes through SecureJSONValidator first: its pre-parse linear depth
    scan (#94) exists because json.loads recurses, and a hostile deeply
    nested document would otherwise reach the interpreter stack. Both the
    stdin and the file path use it -- an imported bundle is untrusted
    whichever way it arrived.

    Args:
        raw: The document as read from stdin or a file.

    Returns:
        The parsed document.

    Raises:
        JSONSecurityError: If the document violates a security constraint.
        json.JSONDecodeError: If the document is not valid JSON.
    """
    get_json_validator().validate_json_security(raw)
    return json.loads(raw)


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
        eprint(
            "ERROR: liboqs not available. Cannot create identity.",
            file=sys.stderr,
        )
        return 1

    try:
        # Determine protection level + HSM type from --hsm argument
        hsm_option = getattr(args, "hsm", "none")
        hsm_type = "yubikey"  # default — used only when protection_level requires HSM
        if hsm_option == "none" or hsm_option is None:
            protection_level = ProtectionLevel.PASSWORD_ONLY
        elif hsm_option == "yubikey":
            protection_level = ProtectionLevel.PASSWORD_AND_HSM
            hsm_type = "yubikey"
        elif hsm_option == "yubikey-only":
            protection_level = ProtectionLevel.HSM_ONLY
            hsm_type = "yubikey"
        elif hsm_option == "onlykey":
            protection_level = ProtectionLevel.PASSWORD_AND_HSM
            hsm_type = "onlykey"
        elif hsm_option == "onlykey-only":
            protection_level = ProtectionLevel.HSM_ONLY
            hsm_type = "onlykey"
        else:
            eprint(f"ERROR: Unknown HSM option: {hsm_option}", file=sys.stderr)
            return 1

        # Check HSM availability if required
        if protection_level in (
            ProtectionLevel.PASSWORD_AND_HSM,
            ProtectionLevel.HSM_ONLY,
        ):
            protection_service = IdentityKeyProtectionService(hsm_type=hsm_type)
            device_label = "OnlyKey" if hsm_type == "onlykey" else "Yubikey"
            if not protection_service.is_hsm_available():
                eprint(
                    f"ERROR: {device_label} not found. Please insert your {device_label}.",
                    file=sys.stderr,
                )
                return 1

            detected_slot = protection_service.detect_hsm_slot()
            if detected_slot is None:
                slot_range = "1..12" if hsm_type == "onlykey" else "1 or 2"
                eprint(
                    f"ERROR: No Challenge-Response slot configured on {device_label}.\n"
                    f"Please configure slot {slot_range} for HMAC-SHA1 Challenge-Response.",
                    file=sys.stderr,
                )
                return 1

            hsm_slot = getattr(args, "hsm_slot", None)
            if hsm_slot is None:
                hsm_slot = detected_slot
                eprint(f"Using {device_label} slot {hsm_slot} (auto-detected)")

        # Get passphrase (not required for HSM_ONLY)
        passphrase = None
        if protection_level != ProtectionLevel.HSM_ONLY:
            passphrase = prompt_passphrase("Passphrase for new identity: ", confirm=True)

            if len(passphrase) < 8:
                eprint(
                    "ERROR: Passphrase must be at least 8 characters",
                    file=sys.stderr,
                )
                return 1

        # Get algorithms
        kem_algo = getattr(args, "kem_algorithm", "ML-KEM-768")
        sig_algo = getattr(args, "sig_algorithm", "ML-DSA-65")

        # Generate identity
        eprint(f"Generating identity for '{sanitize_for_display(args.name)}'...")

        if protection_level in (
            ProtectionLevel.PASSWORD_AND_HSM,
            ProtectionLevel.HSM_ONLY,
        ):
            eprint("Touch your Yubikey to generate keys...")

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
            # Bind the identity to the device the user selected. Without this,
            # `--hsm onlykey` was silently recorded and unlocked as yubikey
            # (gitlab#218); hsm_type is otherwise the "yubikey" default.
            hsm_type=hsm_type,
        )

        # Save to store. This is the user's OWN identity being generated
        # locally; --overwrite is the deliberate intent to (re)generate it
        # (e.g. key rotation), so the contact-substitution TOFU gate does not
        # apply here (allow_key_change=True). The gate is for imported contacts.
        store = get_identity_store(getattr(args, "identity_store", None))
        store.add_identity(
            identity,
            passphrase,
            overwrite=getattr(args, "overwrite", False),
            allow_key_change=True,
        )

        eprint("\nIdentity created successfully!")
        eprint(f"Name: {sanitize_for_display(identity.name)}")
        if identity.email:
            eprint(f"Email: {sanitize_for_display(identity.email)}")
        eprint(f"Fingerprint: {sanitize_for_display(identity.fingerprint)}")
        eprint(f"Encryption: {sanitize_for_display(identity.encryption_algorithm)}")
        eprint(f"Signing: {sanitize_for_display(identity.signing_algorithm)}")

        # Show protection level
        if identity.protection:
            eprint(f"\nProtection: {identity.protection.level.value}")
            if protection_level == ProtectionLevel.PASSWORD_AND_HSM:
                eprint("  → Both password AND Yubikey required for decryption")
            elif protection_level == ProtectionLevel.HSM_ONLY:
                eprint("  → Only Yubikey required (no password)")
        else:
            eprint("\nProtection: password_only (default)")

        return 0

    except IdentityError as e:
        eprint(f"ERROR: {sanitize_for_display(e)}", file=sys.stderr)
        return 1
    except ValueError as e:
        eprint(f"ERROR: {sanitize_for_display(e)}", file=sys.stderr)
        return 1
    except HSMNotAvailableError as e:
        eprint(f"ERROR: {sanitize_for_display(e)}", file=sys.stderr)
        return 1
    except Exception as e:
        eprint(f"ERROR: Failed to create identity: {sanitize_for_display(e)}", file=sys.stderr)
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
        skipped: list = []
        identities = store.list_identities(include_contacts=include_contacts, skipped=skipped)

        # Separate own identities and contacts
        own_identities = [i for i in identities if i.is_own_identity]
        contacts = [i for i in identities if not i.is_own_identity]

        if getattr(args, "json", False):
            # Machine-readable output for the desktop GUI (gitlab#183): a
            # single JSON document on stdout, nothing else. Deliberately NOT
            # display-sanitized — the transport escapes control characters
            # (ensure_ascii) and the consumer renders the values itself. The
            # key names kem_algorithm/sig_algorithm are the GUI's contract.
            def _entry(identity: Identity) -> dict:
                return {
                    "name": identity.name,
                    "email": identity.email,
                    "fingerprint": identity.fingerprint,
                    "kem_algorithm": identity.encryption_algorithm,
                    "sig_algorithm": identity.signing_algorithm,
                    "created_at": identity.created_at,
                }

            # ensure_ascii pinned explicitly, not left to the default: it is
            # what keeps a direct `identity list --json` in a terminal free of
            # decoded escape sequences, and "nicer output" is a tempting edit.
            listing_json = json.dumps(
                {
                    "own": [_entry(i) for i in own_identities],
                    "contacts": [_entry(i) for i in contacts],
                    # Absent entries must be visible: a consumer that treats
                    # this listing as complete would otherwise silently drop
                    # a recipient or report an own identity as deleted
                    # (gitlab#183).
                    "skipped": [{"entry": s["entry"], "reason": s["reason"]} for s in skipped],
                    # Same disambiguation the human path gets: a consumer
                    # showing this listing must be able to tell the user a
                    # name is contested (gitlab#173).
                    "shadowed": store.find_shadowed_names(),
                    # Distinct from a name collision: an entry inside the
                    # container needs a manual move, not a delete.
                    "contacts_container_entry": store.has_misplaced_container_entry(),
                },
                indent=2,
                ensure_ascii=True,
            )
            print(listing_json)
            return 0

        # A store written before gitlab#173 can carry a name that exists as
        # both an own identity and a contact. get_by_name resolves the own
        # identity, so the contact is invisible here until the own identity
        # is deleted -- at which point it silently takes over the name.
        if store.has_misplaced_container_entry():
            # Deliberately NOT reported as a name collision: `identity
            # delete contacts` is refused (reserved name), and routing it
            # there would remove every pinned contact in the store.
            eprint(
                "WARNING: an identity is stored inside the store's own "
                "'contacts/' directory, where it is not listed below but is "
                "still resolvable by name."
            )
            eprint(
                "  Move its identity.json and *.pem files into a directory of "
                "their own next to it to make it usable again, or delete those "
                "files to discard it. 'identity delete' cannot touch this "
                "entry: the name 'contacts' is reserved for the store."
            )
            eprint()

        shadowed = store.find_shadowed_names()
        if shadowed:
            eprint(
                "WARNING: these names exist as BOTH an own identity and a "
                "contact, so deleting the identity would hand the name to the "
                "contact's keys:"
            )
            for name in shadowed:
                eprint(f"  - {sanitize_for_display(name)}")
            eprint(
                "  Verify the contact's fingerprint out of band, then remove "
                "the entry you did not intend to keep with "
                "'identity delete <name> --kind own|contact'. Back up the "
                "identity store first: deleting an own identity destroys its "
                "private keys."
            )
            eprint()

        if skipped:
            eprint(
                f"WARNING: {len(skipped)} store entr"
                f"{'y' if len(skipped) == 1 else 'ies'} could not be loaded "
                f"and {'is' if len(skipped) == 1 else 'are'} not listed below:"
            )
            for entry in skipped:
                eprint(
                    f"  - {sanitize_for_display(entry['entry'])}: "
                    f"{sanitize_for_display(entry['reason'])}"
                )
            eprint()

        if not identities:
            eprint("No identities found.")
            return 0

        # Display own identities
        if own_identities:
            eprint("Own Identities:")
            eprint("-" * 80)
            for identity in own_identities:
                eprint(f"Name: {sanitize_for_display(identity.name)}")
                if identity.email:
                    eprint(f"  Email: {sanitize_for_display(identity.email)}")
                eprint(f"  Fingerprint: {sanitize_for_display(identity.fingerprint)}")
                alg_str = f"{identity.encryption_algorithm} / "
                alg_str += identity.signing_algorithm
                eprint(f"  Algorithms: {sanitize_for_display(alg_str)}")
                eprint()

        # Display contacts
        if contacts and include_contacts:
            eprint("\nContacts (public keys only):")
            eprint("-" * 80)
            for identity in contacts:
                eprint(f"Name: {sanitize_for_display(identity.name)}")
                if identity.email:
                    eprint(f"  Email: {sanitize_for_display(identity.email)}")
                eprint(f"  Fingerprint: {sanitize_for_display(identity.fingerprint)}")
                alg_str = f"{identity.encryption_algorithm} / "
                alg_str += identity.signing_algorithm
                eprint(f"  Algorithms: {sanitize_for_display(alg_str)}")
                eprint()

        # Summary
        total = len(identities)
        own_count = len(own_identities)
        contact_count = len(contacts)

        if include_contacts:
            eprint(f"Total: {total} ({own_count} own, {contact_count} contacts)")
        else:
            eprint(f"Total: {own_count} own identities")

        return 0

    except Exception as e:
        eprint(f"ERROR: Failed to list identities: {sanitize_for_display(e)}", file=sys.stderr)
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
            eprint(
                f"ERROR: Identity '{sanitize_for_display(args.identity_name)}' not found ❌",
                file=sys.stderr,
            )
            return 1

        # Display information
        eprint("Identity Information:")
        eprint("=" * 80)
        eprint(f"Name: {sanitize_for_display(identity.name)}")
        if identity.email:
            eprint(f"Email: {sanitize_for_display(identity.email)}")
        eprint(f"Fingerprint: {sanitize_for_display(identity.fingerprint)}")
        identity_type = (
            "Own identity (has private keys)"
            if identity.is_own_identity
            else "Contact (public keys only)"
        )
        eprint(f"Type: {identity_type}")
        eprint()

        eprint("Algorithms:")
        eprint(f"  Encryption: {sanitize_for_display(identity.encryption_algorithm)}")
        eprint(f"  Signing: {sanitize_for_display(identity.signing_algorithm)}")
        eprint()

        eprint("Public Keys:")
        eprint(f"  Encryption key size: {len(identity.encryption_public_key)} bytes")
        eprint(f"  Signing key size: {len(identity.signing_public_key)} bytes")

        if identity.is_own_identity:
            eprint()
            eprint("Private Keys: YES (encrypted on disk)")

            # Show protection information
            if identity.protection:
                eprint()
                eprint("Protection:")
                eprint(f"  Level: {identity.protection.level.value}")
                if identity.protection.requires_password():
                    eprint("  Password: Required")
                if identity.protection.requires_hsm():
                    eprint(
                        f"  HSM: Required ({sanitize_for_display(identity.protection.hsm_config.hsm_type)})"
                    )
                    # slot/require_touch come from identity.json with no
                    # type check — same hostile-store vector as hsm_type.
                    if identity.protection.hsm_config.slot:
                        eprint(
                            f"    Slot: {sanitize_for_display(identity.protection.hsm_config.slot)}"
                        )
                    eprint(
                        f"    Touch required: "
                        f"{sanitize_for_display(identity.protection.hsm_config.require_touch)}"
                    )
            else:
                eprint()
                eprint("Protection: password_only (default)")

        return 0

    except Exception as e:
        eprint(f"ERROR: Failed to show identity: {sanitize_for_display(e)}", file=sys.stderr)
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
            eprint(
                f"ERROR: Identity '{sanitize_for_display(args.identity_name)}' not found ❌",
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
            eprint(error_msg, file=sys.stderr)
            return 1

        # Write to file. Explicit UTF-8, not the locale default: under a
        # latin-1 locale a name or email would round-trip to different
        # characters, and the base64 key fields are ASCII, so the fingerprint
        # check would still pass on a mangled name.
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(public_data, f, indent=2)

        eprint(f"Public identity exported to: {output_file}")
        eprint(f"Fingerprint: {sanitize_for_display(identity.fingerprint)}")

        return 0

    except Exception as e:
        eprint(f"ERROR: Failed to export identity: {sanitize_for_display(e)}", file=sys.stderr)
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
        # The document may arrive as a file or, for callers that already hold
        # it in memory (the GUI's paste field), on stdin (gitlab#164).
        # Deliberately NOT an argv value: /proc/PID/cmdline is world-readable,
        # which would publish the contact metadata to every local process and
        # would irreversibly expose anything pasted into that field by
        # mistake -- a private key or passphrase is leaked at execve, before
        # this function can reject it.
        file_arg = getattr(args, "file", None)
        # A source counts only if it is the right type. argparse guarantees
        # this, but programmatic callers need not, and a stray attribute must
        # never select a branch by accident.
        from_stdin = getattr(args, "data_stdin", False) is True

        if from_stdin:
            raw = _read_bounded(sys.stdin)
        elif isinstance(file_arg, (str, Path)):
            input_file = Path(file_arg)

            # is_file() rather than exists(): a FIFO or character device
            # passes exists(), and reading one blocks forever (/dev/zero) or
            # never returns (an unwritten FIFO).
            if not input_file.is_file():
                eprint(
                    f"ERROR: '{input_file}' is not a regular file",
                    file=sys.stderr,
                )
                return 1

            # Same bounded read as stdin: the size check must happen before
            # the document is materialised, not after.
            with open(input_file, "r", encoding="utf-8") as f:
                raw = _read_bounded(f)
        else:
            eprint("ERROR: one of --file or --data-stdin is required", file=sys.stderr)
            return 1

        public_data = _parse_identity_document(raw)

        if not isinstance(public_data, dict):
            # json.loads happily returns a list, a string or a number; passing
            # one on produces a TypeError from deep inside import_public.
            eprint("ERROR: identity document must be a JSON object", file=sys.stderr)
            return 1

        # Import identity
        identity = Identity.import_public(public_data)

        # An alias renames the local label only. The fingerprint is computed
        # from the algorithms and public keys (Identity.calculate_fingerprint)
        # and does not cover the name, so renaming cannot mask a key change --
        # but the name becomes a directory name, so it gets the same
        # validation import_public applies to the document's own name.
        alias = getattr(args, "alias", None)
        if isinstance(alias, str):
            validate_identity_name(alias)
            identity.name = alias

        # Add to store
        store = get_identity_store(getattr(args, "identity_store", None))
        overwrite = getattr(args, "overwrite", False)
        allow_key_change = getattr(args, "allow_key_change", False)
        try:
            store.add_identity(
                identity,
                passphrase=None,
                overwrite=overwrite,
                allow_key_change=allow_key_change,
            )
        except IdentityKeyChangedError as e:
            # M8: TOFU key-change. Refuse non-interactively; prompt on a TTY.
            #
            # The refusal keys on the document's SOURCE, not only on isatty().
            # With --data-stdin the bundle and the confirmation would share one
            # channel, and a pty EOF is soft: a supplier could send
            # `{...}<^D>yes` and have isatty() still report True, so whoever
            # supplied the untrusted bundle would also supply the confirmation
            # that it is trustworthy. That is precisely what pinning exists to
            # prevent, so a stdin-sourced document never gets the prompt.
            # The highest-stakes block in the tool: sanitized even though the
            # values are validated upstream today, so a future reordering of
            # checks (or an unvalidated store on disk) cannot let an ANSI
            # payload erase the MITM advisory below (gitlab#172).
            eprint("\n⚠️  WARNING: the key for this contact has CHANGED.")
            eprint(f"  Identity:        {sanitize_for_display(e.name)}")
            eprint(f"  Stored (pinned): {sanitize_for_display(e.old_fingerprint)}")
            eprint(f"  Imported:        {sanitize_for_display(e.new_fingerprint)}")
            eprint(
                "  A changed key can mean the contact re-keyed - or that this "
                "bundle is forged / a man-in-the-middle. Only accept if you "
                "have verified the new fingerprint out of band."
            )
            if from_stdin or not sys.stdin.isatty():
                eprint(
                    "ERROR: refusing to replace a pinned key non-interactively. "
                    "Re-run with --allow-key-change once you have verified the "
                    "new fingerprint.",
                    file=sys.stderr,
                )
                return 1
            response = prompt_and_read("Accept the new key and replace the pinned one? (yes/no): ")
            if response.strip().lower() not in ("yes", "y"):
                eprint("Import cancelled - pinned key kept.")
                return 1
            store.add_identity(identity, passphrase=None, overwrite=True, allow_key_change=True)

        eprint("Identity imported successfully!")
        eprint(f"Name: {sanitize_for_display(identity.name)}")
        if identity.email:
            eprint(f"Email: {sanitize_for_display(identity.email)}")
        eprint(f"Fingerprint: {sanitize_for_display(identity.fingerprint)}")

        return 0

    # Every message below can interpolate text derived from the untrusted
    # document (a rejected name/alias, a validator complaint quoting a key),
    # so each one is escaped before it reaches the terminal (gitlab#172).
    except IdentityError as e:
        eprint(f"ERROR: {sanitize_for_display(e)}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        eprint(
            f"ERROR: Invalid JSON identity document: {sanitize_for_display(e)}",
            file=sys.stderr,
        )
        return 1
    except JSONSecurityError as e:
        eprint(
            f"ERROR: Rejected identity document: {sanitize_for_display(e)}",
            file=sys.stderr,
        )
        return 1
    except Exception as e:
        eprint(
            f"ERROR: Failed to import identity: {sanitize_for_display(e)}",
            file=sys.stderr,
        )
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
        name = args.identity_name
        # A value counts only if it is one of the three. argparse guarantees
        # that, but programmatic callers need not, and a stray attribute must
        # never select a branch by accident -- it falls back to the same
        # default argparse would have supplied.
        kind = getattr(args, "kind", "both")
        if not isinstance(kind, str):
            kind = "both"
        elif kind not in ("own", "contact", "both"):
            # An explicit but invalid value is an ERROR, never silently
            # upgraded to "both": that would fail open to the most
            # destructive branch, which removes the private keys AND the
            # pinned key.
            eprint(
                f"ERROR: --kind must be 'own', 'contact' or 'both', not "
                f"'{sanitize_for_display(kind)}' ❌",
                file=sys.stderr,
            )
            return 1

        # Both locations are inspected directly rather than through
        # get_by_name, which resolves the own identity first and would hide a
        # shadowed contact from the confirmation prompt -- exactly the entry
        # the user needs to see before deciding (gitlab#173).
        entries = store.describe_name(name)

        if not entries:
            eprint(
                f"ERROR: Identity '{sanitize_for_display(name)}' not found ❌",
                file=sys.stderr,
            )
            return 1

        labels = {"own": "own identity", "contact": "contact"}
        targeted = [e for e in entries if kind in ("both", e["kind"])]
        if not targeted:
            present = ", ".join(e["kind"] for e in entries)
            eprint(
                f"ERROR: No {kind} entry named '{sanitize_for_display(name)}' "
                f"(found: {present}) ❌",
                file=sys.stderr,
            )
            return 1

        shadowed = len(entries) > 1

        if shadowed:
            # Never delete both sides of a collision without saying so: one
            # side holds private keys, the other holds a TOFU pin.
            eprint(
                f"NOTE: '{sanitize_for_display(name)}' exists as BOTH an own "
                f"identity and a contact."
            )
            for entry in entries:
                eprint(
                    f"  - {entry['kind']}: fingerprint "
                    f"{sanitize_for_display(entry['fingerprint'])}"
                )
            eprint(
                "  Deleting the own identity destroys its private keys, so any "
                "file encrypted to it becomes unreadable. Deleting the contact "
                "drops its pinned key, so a later import of that name is "
                "accepted as first use with no key-change warning."
            )
            eprint(
                "  Use --kind own or --kind contact to remove just one; "
                "back up the identity store first."
            )
            eprint()

        # Confirm deletion unless --force
        if not getattr(args, "force", False):
            removing = " and ".join(labels[e["kind"]] for e in targeted)
            eprint(f"WARNING: This will delete the {removing} named '{sanitize_for_display(name)}'")
            for entry in targeted:
                eprint(
                    f"  {entry['kind']} fingerprint: "
                    f"{sanitize_for_display(entry['fingerprint'])}"
                )
                if entry["kind"] == "own":
                    eprint("  This includes the private keys!")

            response = prompt_and_read("Are you sure? (yes/no): ")
            if response.lower() not in ["yes", "y"]:
                eprint("Deletion cancelled.")
                return 0

        removed = store.delete_identity(name, kind=kind)

        if removed:
            eprint(
                f"Deleted the {' and '.join(labels[k] for k in removed)} named "
                f"'{sanitize_for_display(name)}'."
            )
            # After removing one side of a collision, say what the name now
            # resolves to: that promotion is precisely the event this issue
            # is about, so it must not be left implicit.
            survivors = [e for e in entries if e["kind"] not in removed]
            for entry in survivors:
                eprint(
                    f"NOTE: '{sanitize_for_display(name)}' now resolves to the "
                    f"{labels[entry['kind']]} entry, fingerprint "
                    f"{sanitize_for_display(entry['fingerprint'])}."
                )
            if not survivors and shadowed:
                eprint("Both entries are gone, so the name no longer resolves to anything.")
            return 0

        eprint(
            f"ERROR: Failed to delete identity '{sanitize_for_display(name)}'",
            file=sys.stderr,
        )
        return 1

    except Exception as e:
        eprint(f"ERROR: Failed to delete identity: {sanitize_for_display(e)}", file=sys.stderr)
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
            eprint(
                f"ERROR: Identity '{sanitize_for_display(args.identity_name)}' not found ❌",
                file=sys.stderr,
            )
            return 1

        if not identity_check.is_own_identity:
            error_msg = (
                f"ERROR: Cannot change passphrase for contact "
                f"'{sanitize_for_display(args.identity_name)}' (no private keys)"
            )
            eprint(error_msg, file=sys.stderr)
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
            eprint("ERROR: Incorrect passphrase", file=sys.stderr)
            return 1

        # Get new passphrase
        new_passphrase = prompt_passphrase("New passphrase: ", confirm=True)

        if len(new_passphrase) < 8:
            eprint(
                "ERROR: New passphrase must be at least 8 characters",
                file=sys.stderr,
            )
            return 1

        # Save with new passphrase
        store.add_identity(identity, new_passphrase, overwrite=True)

        eprint(f"Passphrase changed successfully for '{sanitize_for_display(args.identity_name)}'")

        return 0

    except ValueError as e:
        eprint(f"ERROR: {sanitize_for_display(e)}", file=sys.stderr)
        return 1
    except Exception as e:
        eprint(f"ERROR: Failed to change passphrase: {sanitize_for_display(e)}", file=sys.stderr)
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
        eprint("ERROR: Unknown identity command", file=sys.stderr)
        return 1
