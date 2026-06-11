#!/usr/bin/env python3
"""
Wrapper module for PQC keystore integration with crypt_core.py

This module provides enhanced versions of encrypt_file and decrypt_file
that ensure key IDs are properly stored in metadata for keystore integration.
"""

import base64
import json
import os
from typing import Any, Dict, Optional, Tuple, Union

from .crypt_core import decrypt_file as original_decrypt_file
from .crypt_core import encrypt_file as original_encrypt_file
from .crypt_utils import eprint
from .keystore_utils import extract_key_id_from_metadata, get_pqc_key_for_decryption


def encrypt_file_with_keystore(
    input_file: str,
    output_file: str,
    password: Union[str, bytes],
    hash_config: Optional[Dict[str, Any]] = None,
    quiet: bool = False,
    algorithm: str = "aes-gcm",
    pqc_keypair: Optional[Tuple[bytes, bytes]] = None,
    keystore_file: Optional[str] = None,
    keystore_password: Optional[str] = None,
    key_id: Optional[str] = None,
    dual_encryption: bool = False,
    pqc_dual_encryption: bool = False,  # For backward compatibility, prefer using dual_encryption
    **kwargs,
) -> bool:
    """
    Enhanced version of encrypt_file that ensures key ID is properly stored in metadata

    Args:
        input_file: Path to input file
        output_file: Path to output file
        password: Password for encryption
        hash_config: Hash configuration
        quiet: Whether to suppress output
        algorithm: Encryption algorithm
        pqc_keypair: PQC key pair (public_key, private_key)
        keystore_file: Path to keystore file
        keystore_password: Password for keystore
        key_id: ID of the key to use from keystore
        dual_encryption: Whether to use dual encryption (requires both keystore and file passwords)
        pqc_dual_encryption: Whether to use dual encryption for PQC keys (requires both keystore and file passwords)
        **kwargs: Additional arguments for encrypt_file

    Returns:
        bool: Success or failure
    """
    # Create a copy of hash_config or initialize it with required fields
    if hash_config is None:
        hash_config = {
            "sha256": 0,
            "sha512": 0,
            "sha3_256": 0,
            "sha3_512": 0,
            "blake2b": 0,
            "shake256": 0,
            "scrypt": {"enabled": False},
            "argon2": {"enabled": False},
        }

    hash_config_copy = hash_config.copy()

    # If we're using a keystore key, ensure the key ID is in hash_config
    if key_id is not None:
        if not quiet:
            eprint(f"Storing key ID in metadata: {key_id}")
        hash_config_copy["pqc_keystore_key_id"] = key_id

        # If dual encryption is enabled, set the flag in the metadata
        if dual_encryption:
            if not quiet:
                eprint("Setting dual encryption flag in metadata")
            hash_config_copy["dual_encryption"] = True

            # M7: the legacy password-verification hash (PBKDF2-HMAC-SHA256 at
            # only 10k iterations of the file password, stored in cleartext
            # metadata) is intentionally NOT written. It was a redundant UX
            # pre-check: the dual-encryption AES-GCM tag already authenticates
            # the file password on decrypt (keystore_cli get_key), so the weak
            # hash added nothing but a cheap offline brute-force oracle for the
            # second factor. Files written by older versions still carry it and
            # remain readable (the decrypt path validates it when present).

    # Unify the dual encryption flags for consistency
    use_dual_encryption = dual_encryption or pqc_dual_encryption

    # When dual encryption is used AND a keypair is already provided (i.e. already
    # stored in the keystore), do NOT embed the private key in metadata.  Embedding
    # it and then removing it post-encryption breaks AEAD binding because the
    # metadata used as AAD during encryption would differ from the metadata stored
    # in the file after modification.
    #
    # SECURITY FIX (C6): When a keypair is NOT provided (pqc_keypair is None),
    # encrypt_file generates one internally and may embed the private key.
    # We MUST NOT strip it from metadata post-encryption because the metadata
    # (including the private key) was already bound as AAD.  Modifying metadata
    # after encryption invalidates the AEAD authentication tag, making the file
    # undecryptable or silently removing integrity protection.
    # The private key is stored encrypted in the metadata, so keeping it there
    # alongside a keystore copy is redundant but cryptographically safe.
    embed_private_key_in_metadata = use_dual_encryption and not (pqc_keypair and key_id)

    # Call the original encrypt_file
    result = original_encrypt_file(
        input_file,
        output_file,
        password,
        hash_config=hash_config_copy,
        quiet=quiet,
        algorithm=algorithm,
        pqc_keypair=pqc_keypair,
        pqc_dual_encrypt_key=embed_private_key_in_metadata,  # Only embed when key not already in keystore
        **kwargs,
    )

    if not result:
        return False

    # If dual encryption is enabled for PQC keys, store the key in keystore.
    # Skip this when the keypair was provided (key is already in keystore, not in metadata).
    #
    # SECURITY FIX (C6): We store the private key in the keystore but do NOT
    # strip it from the encrypted file's metadata.  The metadata was used as AAD
    # during AEAD encryption; modifying it afterward invalidates the authentication
    # tag.  The encrypted private key remains in the file (harmless — it is
    # encrypted) and the keystore copy provides the convenience lookup.
    if use_dual_encryption and key_id is not None and keystore_file is not None and not pqc_keypair:
        if not quiet:
            eprint("Storing PQC key in keystore and removing from metadata")

        try:
            # Read the entire output file (metadata + encrypted data)
            with open(output_file, "rb") as f:
                content = f.read()

            # Find the colon separator
            colon_pos = content.find(b":")
            if colon_pos > 0:
                metadata_b64 = content[:colon_pos]
                encrypted_data = content[colon_pos:]

                try:
                    metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                    metadata = json.loads(metadata_json)

                    # Get format version
                    format_version = metadata.get("format_version", 3)

                    # Check if private key is in metadata based on format version
                    pqc_private_key_present = False
                    if format_version in [4, 5, 6, 7, 8, 9, 10]:
                        # Format version 4/5/6/7/8/9/10 - check in encryption section
                        if "encryption" in metadata and "pqc_private_key" in metadata["encryption"]:
                            pqc_private_key_present = True
                    else:
                        # Legacy format - check in root level
                        if "pqc_private_key" in metadata:
                            pqc_private_key_present = True

                    if pqc_private_key_present:
                        # Import the store_pqc_key_in_keystore function locally to avoid circular imports
                        from .keystore_utils import store_pqc_key_in_keystore

                        # Store the key in the keystore - passing the complete metadata
                        store_pqc_key_in_keystore(
                            metadata,
                            keystore_file,
                            keystore_password,
                            key_id=key_id,
                            quiet=quiet,
                        )

                        # SECURITY FIX (C6): Do NOT strip the private key from the
                        # file's metadata.  The metadata was used as AAD during AEAD
                        # encryption; modifying it afterward would invalidate the
                        # authentication tag.  The encrypted private key stays in the
                        # file (it is already encrypted with the user's derived key)
                        # and the keystore provides a convenience copy.
                        if not quiet:
                            eprint(
                                "Successfully stored PQC key in keystore "
                                "(encrypted copy retained in file metadata for AEAD integrity)"
                            )
                except Exception as e:
                    if not quiet:
                        eprint(f"Warning: Error processing metadata: {e}")
        except Exception as e:
            if not quiet:
                eprint(f"Warning: Error storing PQC key in keystore: {e}")
                eprint("Continuing with the private key stored in metadata for safety")

    # Verify that the key ID and dual encryption flag are in the metadata
    if key_id is not None:
        # Open the encrypted file and check metadata
        with open(output_file, "rb") as f:
            content = f.read(32768)  # Read enough for the header - sized for large PQC keys (HQC-256)

        # Find the colon separator
        colon_pos = content.find(b":")
        if colon_pos > 0:
            metadata_b64 = content[:colon_pos]
            try:
                metadata_json = base64.b64decode(metadata_b64).decode("utf-8")

                try:
                    metadata = json.loads(metadata_json)
                    need_update = False
                    format_version = metadata.get("format_version", 3)

                    if format_version == 5:
                        # For format version 5, use the same structure as v4 (derivation_config.kdf_config)
                        if "derivation_config" not in metadata:
                            metadata["derivation_config"] = {}
                        if "kdf_config" not in metadata["derivation_config"]:
                            metadata["derivation_config"]["kdf_config"] = {}

                        kdf_config = metadata["derivation_config"]["kdf_config"]

                        # Check if key ID is missing
                        if (
                            "pqc_keystore_key_id" not in kdf_config
                            or kdf_config["pqc_keystore_key_id"] != key_id
                        ):
                            if not quiet:
                                eprint("Key ID not found in metadata, adding it to kdf_config (v5)")
                            kdf_config["pqc_keystore_key_id"] = key_id
                            need_update = True

                        # Check if dual_encryption flag is missing
                        if dual_encryption and "dual_encryption" not in kdf_config:
                            if not quiet:
                                eprint(
                                    "Dual encryption flag missing from metadata, adding it to kdf_config (v5)"
                                )
                            kdf_config["dual_encryption"] = True
                            need_update = True
                    elif format_version == 4:
                        # For format version 4, check in derivation_config.kdf_config
                        if "derivation_config" not in metadata:
                            metadata["derivation_config"] = {}
                        if "kdf_config" not in metadata["derivation_config"]:
                            metadata["derivation_config"]["kdf_config"] = {}

                        kdf_config = metadata["derivation_config"]["kdf_config"]

                        # Check if key ID is missing
                        if (
                            "pqc_keystore_key_id" not in kdf_config
                            or kdf_config["pqc_keystore_key_id"] != key_id
                        ):
                            if not quiet:
                                eprint("Key ID not found in metadata, adding it to kdf_config")
                            kdf_config["pqc_keystore_key_id"] = key_id
                            need_update = True

                        # Check if dual_encryption flag is missing
                        if dual_encryption and "dual_encryption" not in kdf_config:
                            if not quiet:
                                eprint(
                                    "Dual encryption flag missing from metadata, adding it to kdf_config"
                                )
                            kdf_config["dual_encryption"] = True
                            need_update = True
                    else:
                        # For format version 1-3, check in hash_config
                        # Check if key ID is missing
                        if "hash_config" in metadata and (
                            "pqc_keystore_key_id" not in metadata["hash_config"]
                            or metadata["hash_config"]["pqc_keystore_key_id"] != key_id
                        ):
                            if not quiet:
                                eprint("Key ID not found in metadata, adding it manually")

                            # Key ID is missing from metadata, add it
                            if "hash_config" not in metadata:
                                metadata["hash_config"] = {}

                            metadata["hash_config"]["pqc_keystore_key_id"] = key_id
                            need_update = True

                        # Check if dual_encryption flag is missing
                        if dual_encryption and (
                            "hash_config" in metadata
                            and "dual_encryption" not in metadata["hash_config"]
                        ):
                            if not quiet:
                                eprint("Dual encryption flag missing from metadata, adding it")

                            if "hash_config" not in metadata:
                                metadata["hash_config"] = {}

                            metadata["hash_config"]["dual_encryption"] = True
                            need_update = True

                    # If we need to update the metadata, rewrite the file —
                    # BUT only when AEAD binding is NOT active.  Rewriting
                    # metadata after AEAD encryption invalidates the
                    # authentication tag.
                    if need_update:
                        # Check whether the file uses AEAD binding
                        aead_bound = metadata.get("aead_binding", False)
                        if aead_bound:
                            if not quiet:
                                eprint(
                                    "Warning: metadata flags missing but file uses AEAD binding; "
                                    "skipping metadata rewrite to preserve authentication tag"
                                )
                        else:
                            # Safe to rewrite — no AEAD binding on this file
                            new_metadata_json = json.dumps(metadata)
                            new_metadata_b64 = base64.b64encode(
                                new_metadata_json.encode("utf-8")
                            )

                            # Rewrite the file with updated metadata
                            with open(output_file, "rb") as f:
                                full_content = f.read()

                            with open(output_file, "wb") as f:
                                f.write(new_metadata_b64)
                                f.write(full_content[colon_pos:])

                            if not quiet:
                                if dual_encryption:
                                    eprint(
                                        "Updated metadata with key ID and dual encryption flag"
                                    )
                                else:
                                    eprint("Updated metadata with key ID")
                except json.JSONDecodeError:
                    if not quiet:
                        eprint("Warning: Could not parse metadata as JSON")
            except Exception as e:
                if not quiet:
                    eprint(f"Warning: Error checking metadata: {e}")

    # Verify with our extract function
    extracted_key_id = extract_key_id_from_metadata(output_file, False)
    if key_id is not None and extracted_key_id != key_id and not quiet:
        eprint(
            f"Warning: Key ID in metadata ({extracted_key_id}) "
            + f"doesn't match original key ID ({key_id})"
        )

    return True


def decrypt_file_with_keystore(
    input_file: str,
    output_file: str,
    password: Union[str, bytes],
    quiet: bool = False,
    pqc_private_key: Optional[bytes] = None,
    keystore_file: Optional[str] = None,
    keystore_password: Optional[str] = None,
    key_id: Optional[str] = None,
    dual_encryption: bool = False,
    **kwargs,
) -> bool:
    """
    Enhanced version of decrypt_file that automatically extracts key ID from metadata

    Args:
        input_file: Path to input file
        output_file: Path to output file
        password: Password for decryption
        quiet: Whether to suppress output
        pqc_private_key: PQC private key
        keystore_file: Path to keystore file
        keystore_password: Password for keystore
        key_id: ID of the key to use from keystore
        dual_encryption: Whether this file uses dual encryption
        **kwargs: Additional arguments for decrypt_file

    Returns:
        bool: Success or failure
    """
    # Read the metadata first to determine format version and other details
    format_version = 1
    metadata = None
    try:
        with open(input_file, "rb") as f:
            content = f.read(32768)  # Read enough for the header - sized for large PQC keys

        # Find the colon separator
        colon_pos = content.find(b":")
        if colon_pos > 0:
            metadata_b64 = content[:colon_pos]
            try:
                metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                metadata = json.loads(metadata_json)
                format_version = metadata.get("format_version", 1)
                if not quiet:
                    eprint(f"Detected format version: {format_version}")
            except Exception:
                pass  # Ignore parsing errors
    except Exception:
        pass  # Ignore file reading errors

    # Check for dual encryption in metadata if not explicitly specified
    if not dual_encryption:
        # Check if this file uses dual encryption
        if metadata:
            # Check based on format version
            if format_version in [4, 5, 6, 7, 8, 9, 10]:
                # Version 4/5/6/7/8/9/10 format - check in derivation_config.kdf_config
                if (
                    "derivation_config" in metadata
                    and "kdf_config" in metadata["derivation_config"]
                    and "dual_encryption" in metadata["derivation_config"]["kdf_config"]
                ):
                    dual_encryption = metadata["derivation_config"]["kdf_config"]["dual_encryption"]
                    if dual_encryption and not quiet:
                        version_label = f" (v{format_version})" if format_version != 4 else ""
                        eprint(
                            f"File uses dual encryption - requires both keystore and file passwords{version_label}"
                        )
            else:
                # Version 3 format - check in hash_config
                if "hash_config" in metadata and "dual_encryption" in metadata["hash_config"]:
                    dual_encryption = metadata["hash_config"]["dual_encryption"]
                    if dual_encryption and not quiet:
                        eprint(
                            "File uses dual encryption - requires both keystore and file passwords"
                        )
        else:
            # Try reading the metadata manually
            try:
                with open(input_file, "rb") as f:
                    content = f.read(32768)  # Read enough for the header - sized for large PQC keys

                # Find the colon separator
                colon_pos = content.find(b":")
                if colon_pos > 0:
                    metadata_b64 = content[:colon_pos]
                    try:
                        metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                        metadata = json.loads(metadata_json)

                        # Check for dual encryption flag, handling v3, v4, v5, v6, v7, v8, v9, and v10 formats
                        format_version = metadata.get("format_version", 1)
                        if format_version in [4, 5, 6, 7, 8, 9, 10]:
                            # Version 4/5/6/7/8/9/10 format - check in derivation_config.kdf_config
                            if (
                                "derivation_config" in metadata
                                and "kdf_config" in metadata["derivation_config"]
                                and "dual_encryption" in metadata["derivation_config"]["kdf_config"]
                            ):
                                dual_encryption = metadata["derivation_config"]["kdf_config"][
                                    "dual_encryption"
                                ]
                                if dual_encryption and not quiet:
                                    version_label = (
                                        f" (v{format_version})" if format_version != 4 else ""
                                    )
                                    eprint(
                                        f"File uses dual encryption - requires both keystore and file passwords{version_label}"
                                    )
                        else:
                            # Version 3 format - check in hash_config
                            if (
                                "hash_config" in metadata
                                and "dual_encryption" in metadata["hash_config"]
                            ):
                                dual_encryption = metadata["hash_config"]["dual_encryption"]
                                if dual_encryption and not quiet:
                                    eprint(
                                        "File uses dual encryption - requires both keystore and file passwords"
                                    )
                    except Exception:
                        pass  # Ignore parsing errors
            except Exception:
                pass  # Ignore file reading errors

    # If dual encryption is enabled, verify the file password using the hash in metadata
    if dual_encryption:
        try:
            # Read the metadata again (or use what we already read)
            if not "metadata" in locals() or metadata is None:
                with open(input_file, "rb") as f:
                    content = f.read(32768)  # Read enough for the header - sized for large PQC keys

                # Find the colon separator
                colon_pos = content.find(b":")
                if colon_pos > 0:
                    metadata_b64 = content[:colon_pos]
                    metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                    metadata = json.loads(metadata_json)

            # First check if we have a valid password
            if password is None:
                if not quiet:
                    eprint("ERROR: No password provided for dual-encrypted file")
                raise ValueError("File password is required for dual-encrypted files")

            # Convert string password to bytes if needed
            pw_verify_bytes = password
            if isinstance(password, str):
                pw_verify_bytes = password.encode("utf-8")

            # Validate password length
            if len(pw_verify_bytes) < 8:  # Require at least 8 characters
                if not quiet:
                    eprint(
                        "ERROR: File password is too short for dual-encryption (minimum 8 characters)"
                    )
                raise ValueError("File password is too short for dual-encryption")

            # Check for password verification fields based on format version
            format_version = metadata.get("format_version", 1)
            verify_hash = None
            verify_salt = None

            if format_version in [4, 5, 6, 7, 8, 9, 10]:
                # Version 4/5/6/7/8/9/10 format - check in derivation_config.kdf_config
                if (
                    "derivation_config" in metadata
                    and "kdf_config" in metadata["derivation_config"]
                    and "pqc_dual_encrypt_verify" in metadata["derivation_config"]["kdf_config"]
                    and "pqc_dual_encrypt_verify_salt"
                    in metadata["derivation_config"]["kdf_config"]
                ):
                    # Get stored values
                    verify_hash = base64.b64decode(
                        metadata["derivation_config"]["kdf_config"]["pqc_dual_encrypt_verify"]
                    )
                    verify_salt = base64.b64decode(
                        metadata["derivation_config"]["kdf_config"]["pqc_dual_encrypt_verify_salt"]
                    )
            else:
                # Version 3 format - check in hash_config
                if (
                    "hash_config" in metadata
                    and "pqc_dual_encrypt_verify" in metadata["hash_config"]
                    and "pqc_dual_encrypt_verify_salt" in metadata["hash_config"]
                ):
                    # Get stored values
                    verify_hash = base64.b64decode(
                        metadata["hash_config"]["pqc_dual_encrypt_verify"]
                    )
                    verify_salt = base64.b64decode(
                        metadata["hash_config"]["pqc_dual_encrypt_verify_salt"]
                    )

            # Legacy files (pre-M7) carry a PBKDF2 verification hash. If present
            # we still honour it (backward compatibility); its absence is the
            # normal case for files written after M7 - the file password is
            # then authenticated by the dual-encryption AES-GCM tag downstream.
            if verify_hash and verify_salt:
                # Calculate hash with current password
                import hashlib

                current_pw_hash = hashlib.pbkdf2_hmac("sha256", pw_verify_bytes, verify_salt, 10000)

                # Verify hash matches - use specialized MAC verification to prevent timing attacks
                from .secure_ops import verify_mac

                if not verify_mac(verify_hash, current_pw_hash):
                    if not quiet:
                        eprint("Password verification failed - incorrect file password")
                    raise ValueError(
                        "Invalid password for dual-encrypted file - password verification failed"
                    )
                elif not quiet:
                    eprint("File password verification successful")
            else:
                # No verifier in metadata: normal for post-M7 files. The file
                # password is verified by the AES-GCM tag during key retrieval,
                # so no pre-check is needed here.
                if kwargs.get("verbose"):
                    eprint(
                        "No password pre-check hash in metadata - file password will be "
                        "verified by the dual-encryption AES-GCM tag"
                    )

        except ValueError as ve:
            # Re-raise these as they're expected for validation failures
            raise ve
        except Exception as e:
            if not quiet:
                eprint(f"Warning: Error in password verification: {e}")

    # If key_id is not provided, try to extract it from metadata
    if key_id is None and keystore_file is not None:
        extracted_key_id = extract_key_id_from_metadata(input_file, not quiet)

        if extracted_key_id:
            if not quiet:
                eprint(f"Using key ID from metadata: {extracted_key_id}")
            key_id = extracted_key_id

    # Try to get the PQC key using our improved helper function
    if keystore_file is not None and key_id is not None and key_id != "EMBEDDED_PRIVATE_KEY":
        import getpass

        from .keystore_utils import get_pqc_key_for_decryption

        # Create minimal args object for get_pqc_key_for_decryption
        class SimpleArgs:
            pass

        args = SimpleArgs()
        args.keystore = keystore_file
        args.keystore_password = keystore_password
        args.input = input_file
        args.password = password
        args.quiet = quiet
        args.verbose = kwargs.get("verbose", False)

        # Get the key using our improved helper, passing the metadata we already extracted
        pqc_keypair, retrieved_private_key, extracted_key_id = get_pqc_key_for_decryption(
            args, None, metadata
        )

        # Only update the private key if we got one
        if retrieved_private_key:
            if not quiet:
                eprint(f"Successfully retrieved PQC key for decryption using helper function")
            pqc_private_key = retrieved_private_key

            # Update the key_id in case it was found by the helper
            if extracted_key_id and not key_id:
                key_id = extracted_key_id
        elif not quiet:
            eprint(f"Trying alternative approach to retrieve private key")

    # If we don't have a private key yet, try the classic keystore approach
    if pqc_private_key is None and key_id is not None and keystore_file is not None:
        import getpass

        from .keystore_cli import KeyNotFoundError, PQCKeystore
        # Check if keystore file exists
        if not os.path.exists(keystore_file):
            if not quiet:
                eprint(f"Error: Keystore file not found at {keystore_file}")
            if dual_encryption:
                raise ValueError(f"Keystore not found at {keystore_file}")
        else:
            try:
                keystore = PQCKeystore(keystore_file)

                # If no keystore password provided, prompt for it
                if keystore_password is None:
                    keystore_password = getpass.getpass("Enter keystore password: ")

                keystore.load_keystore(keystore_password)

                # Debug - print keys in keystore
                if kwargs.get("verbose", False):
                    try:
                        keys = keystore.list_keys()
                        if not quiet:
                            eprint(f"Keys in keystore: {len(keys)}")
                            for k in keys:
                                eprint(f"  - {k['key_id']} ({k.get('algorithm', 'unknown')})")

                        # Check if key ID exists
                        if key_id not in [k["key_id"] for k in keys]:
                            if not quiet:
                                eprint(f"Key ID {key_id} not found in keystore")
                    except Exception as le:
                        if not quiet and kwargs.get("verbose", False):
                            eprint(f"Error listing keys: {le}")

                # Determine if we need to pass the file password for dual encryption
                file_password_for_key = None
                if dual_encryption:
                    # For dual-encrypted keys, we need to pass the file password
                    if isinstance(password, bytes):
                        # Convert bytes to string if needed
                        try:
                            file_password_for_key = password.decode("utf-8")
                        except UnicodeDecodeError:
                            # If we can't decode as UTF-8, use as bytes
                            file_password_for_key = password
                    else:
                        file_password_for_key = password

                    if not quiet:
                        eprint(f"Using file password for dual-encrypted key")

                    # Verify the file password format
                    if not file_password_for_key:
                        raise ValueError("File password is required for dual-encrypted files")

                # Get the key with file password for dual encryption
                try:
                    _, private_key = keystore.get_key(key_id, None, file_password_for_key)
                except Exception as e:
                    error_msg = str(e).lower()
                    # Check for various password/decryption error messages
                    if dual_encryption and (
                        "incorrect file password" in error_msg
                        or "invalid" in error_msg
                        or "failed to handle dual encryption" in error_msg
                        or "could not decrypt" in error_msg
                    ):
                        # This is an expected error for incorrect file passwords with dual encryption
                        if not quiet:
                            eprint(f"Dual encryption verification failed: {e}")
                        raise ValueError(
                            f"Invalid password for dual-encrypted key - password authentication failed"
                        )
                    else:
                        # Pass through other errors
                        raise

                if not quiet:
                    eprint(f"Retrieved private key for key ID {key_id} from keystore")
                    if dual_encryption:
                        eprint("Key successfully decrypted with both keystore and file passwords")

                pqc_private_key = private_key
            except Exception as e:
                if not quiet:
                    eprint(f"Error retrieving key from keystore: {e}")
                # Re-raise for dual-encrypted files that require keystore access
                if dual_encryption:
                    raise ValueError("Failed to retrieve key from keystore for dual-encrypted file")

    # First check if we need a keystore but couldn't get the key
    if (
        dual_encryption
        and key_id is not None
        and key_id != "EMBEDDED_PRIVATE_KEY"
        and pqc_private_key is None
    ):
        if not keystore_file or not os.path.exists(keystore_file):
            if not quiet:
                eprint(
                    "ERROR: This file requires a keystore for decryption but no valid keystore was provided."
                )
            raise ValueError(f"Keystore not found at {keystore_file}")
        if not quiet:
            eprint(
                "ERROR: Unable to retrieve key from keystore. Make sure both keystore and file passwords are correct."
            )
        raise ValueError(
            "Failed to retrieve key from keystore for dual-encrypted file - password verification failed"
        )

    # Check if we have the pqc_private_key before proceeding
    if (
        dual_encryption
        and key_id is not None
        and key_id != "EMBEDDED_PRIVATE_KEY"
        and pqc_private_key is None
    ):
        if not quiet:
            eprint("ERROR: This file is dual-encrypted but no private key was found.")
        raise ValueError("Unable to retrieve private key for dual-encrypted file")

    # Call the original decrypt_file with improved error handling
    try:
        # If we got a pqc_private_key from our helper function, use it
        if "pqc_private_key" not in locals() or pqc_private_key is None:
            # We might still have a private key in kwargs
            pqc_private_key = kwargs.get("pqc_private_key")

        if not quiet and pqc_private_key:
            eprint("Using PQC private key for decryption")

        result = original_decrypt_file(
            input_file,
            output_file,
            password,
            quiet=quiet,
            pqc_private_key=pqc_private_key,  # Pass the retrieved private key
            **kwargs,
        )

        # If this was a dual-encrypted file and we succeeded without keystore access,
        # this suggests the private key is still in the metadata - raise an error
        if (
            dual_encryption
            and keystore_file is not None
            and not os.path.exists(keystore_file)
            and result
        ):
            if not quiet:
                eprint(
                    "WARNING: Decryption succeeded without keystore. This suggests the private key is still in the metadata."
                )
            raise ValueError(
                "Decryption succeeded without keystore, but private key not found. This suggests a bug in the dual encryption logic."
            )

        return result
    except Exception as e:
        error_msg = str(e).lower()
        # Check if this might be a password error from dual encryption
        if dual_encryption and (
            "invalid input" in error_msg
            or "invalid parameter" in error_msg
            or "decryption failed" in error_msg
            or "invalid file password" in error_msg
            or "mac" in error_msg
            or "verification" in error_msg
        ):
            if not quiet:
                eprint(f"Decryption failed - possible invalid file password: {e}")
            raise ValueError(f"Password verification failed for decryption - invalid password")
        else:
            # Re-raise the original error
            raise
