#!/usr/bin/env python3
"""
Debug script for PQC keystore decryption issues
"""

import argparse
import base64
import getpass
import json
import os
import sys
from typing import Optional

# Create a debug log file
DEBUG_LOG = "/tmp/debug/decrypt_debug.log"


def log(message):
    """Log a message to the debug file and print it"""
    with open(DEBUG_LOG, "a") as f:
        f.write(f"{message}\n")
    print(message)


def extract_key_id_from_metadata(encrypted_file, verbose=True):
    """Extract key ID from encrypted file metadata with verbose logging"""
    log(f"Extracting key ID from metadata: {encrypted_file}")

    try:
        with open(encrypted_file, "rb") as f:
            data = f.read(3000)  # Read enough for the header

        log(f"Read {len(data)} bytes from file")

        # Find the colon separator
        colon_pos = data.find(b":")
        if colon_pos > 0:
            log(f"Found colon separator at position {colon_pos}")
            metadata_b64 = data[:colon_pos]
            log(f"Extracted base64 metadata ({len(metadata_b64)} bytes)")

            try:
                metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                log(f"Decoded metadata JSON ({len(metadata_json)} chars)")
                log(f"Metadata preview: {metadata_json[:100]}...")

                # First try direct JSON parsing
                try:
                    metadata = json.loads(metadata_json)
                    log(f"Successfully parsed metadata as JSON")

                    # Check format version for proper path
                    format_version = metadata.get("format_version", 1)
                    log(f"Metadata format version: {format_version}")

                    if format_version == 4:
                        # Format v4 structure - check in derivation_config.kdf_config
                        if "derivation_config" in metadata:
                            log(f"Found derivation_config in v4 metadata")

                            if "kdf_config" in metadata["derivation_config"]:
                                log(f"Found kdf_config in derivation_config")

                                if (
                                    "pqc_keystore_key_id"
                                    in metadata["derivation_config"]["kdf_config"]
                                ):
                                    key_id = metadata["derivation_config"]["kdf_config"][
                                        "pqc_keystore_key_id"
                                    ]
                                    log(f"Found key ID in v4 metadata kdf_config: {key_id}")
                                    return key_id
                                else:
                                    log(f"No pqc_keystore_key_id in kdf_config")
                                    log(
                                        f"kdf_config keys: {metadata['derivation_config']['kdf_config'].keys()}"
                                    )
                            else:
                                log(f"No kdf_config found in derivation_config")
                                log(
                                    f"derivation_config keys: {metadata['derivation_config'].keys()}"
                                )
                        else:
                            log(f"No derivation_config found in v4 metadata")
                            log(f"Metadata keys: {metadata.keys()}")
                    else:
                        # Format v1-3 structure - check in hash_config
                        if "hash_config" in metadata:
                            log(f"Found hash_config in metadata")

                            if "pqc_keystore_key_id" in metadata["hash_config"]:
                                key_id = metadata["hash_config"]["pqc_keystore_key_id"]
                                log(f"Found key ID in hash_config: {key_id}")
                                return key_id
                            else:
                                log(f"No pqc_keystore_key_id in hash_config")
                                log(f"hash_config keys: {metadata['hash_config'].keys()}")
                        else:
                            log(f"No hash_config found in metadata")
                            log(f"Metadata keys: {metadata.keys()}")
                except json.JSONDecodeError as e:
                    log(f"JSON parsing failed: {e}")
                    log("Trying regex fallback")

                # Fall back to regex for UUID pattern
                import re

                uuid_pattern = r"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"
                matches = re.findall(uuid_pattern, metadata_json)

                if matches:
                    log(f"Found {len(matches)} UUID matches: {matches}")

                    # Look for key ID marker
                    key_id_pos = metadata_json.find("pqc_keystore_key_id")
                    if key_id_pos >= 0:
                        log(f"Found 'pqc_keystore_key_id' at position {key_id_pos}")

                        # Find closest UUID after this position
                        closest_match = None
                        closest_distance = float("inf")

                        for match in matches:
                            match_pos = metadata_json.find(match, key_id_pos)
                            if match_pos >= 0:
                                distance = match_pos - key_id_pos
                                log(
                                    f"UUID {match} found at position {match_pos}, distance {distance}"
                                )
                                if distance < closest_distance:
                                    closest_match = match
                                    closest_distance = distance

                        if closest_match:
                            log(f"Using closest UUID match: {closest_match}")
                            return closest_match

                    # If we couldn't find one near the marker, return the first match
                    log(f"Using first UUID match: {matches[0]}")
                    return matches[0]
                else:
                    log("No UUID patterns found in metadata")
            except Exception as e:
                log(f"Error decoding metadata: {e}")
        else:
            log("No colon separator found in file")
    except Exception as e:
        log(f"Error reading file: {e}")

    log("Failed to extract key ID from metadata")
    return None


def load_key_from_keystore(keystore_file, key_id, keystore_password):
    """Load a key from the keystore with detailed logging"""
    log(f"Loading key from keystore: {keystore_file}")
    log(f"Key ID: {key_id}")

    try:
        # Import PQCKeystore class
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from openssl_encrypt.modules.keystore_cli import PQCKeystore

        log("Successfully imported PQCKeystore class")

        # Create keystore instance
        keystore = PQCKeystore(keystore_file)
        log("Created PQCKeystore instance")

        # Load keystore
        log(f"Loading keystore with password (length: {len(keystore_password)})")
        keystore.load_keystore(keystore_password)
        log("Successfully loaded keystore")

        # List keys for debugging
        keys = keystore.list_keys()
        log(f"Keys in keystore: {keys}")

        # Check if our key ID is in the keystore
        key_ids = [k["key_id"] for k in keys]
        if key_id in key_ids:
            log(f"Found key ID {key_id} in keystore")
        else:
            log(f"Key ID {key_id} NOT found in keystore")
            log(f"Available key IDs: {key_ids}")

        # Get key
        log(f"Retrieving key {key_id} from keystore")
        public_key, private_key = keystore.get_key(key_id)

        if public_key and private_key:
            log(f"Successfully retrieved key pair")
            log(f"Public key length: {len(public_key)}")
            log(f"Private key length: {len(private_key)}")
            return private_key
        else:
            log(f"Failed to retrieve complete key pair")
            return None

    except Exception as e:
        log(f"Error accessing keystore: {e}")
        return None


def decrypt_file_direct(input_file, output_file, password, pqc_private_key):
    """Attempt direct decryption with the given private key"""
    log(f"Direct decryption attempt")
    log(f"Input file: {input_file}")
    log(f"Output file: {output_file}")
    log(f"Password provided: {bool(password)}")
    log(f"Private key provided: {bool(pqc_private_key)}")

    try:
        # Import the decryption function
        from openssl_encrypt.modules.crypt_core import decrypt_file

        # Call the original decrypt function directly
        success = decrypt_file(
            input_file,
            output_file,
            password,
            quiet=False,
            verbose=True,
            pqc_private_key=pqc_private_key,
        )

        log(f"Decryption result: {success}")
        return success
    except Exception as e:
        log(f"Error during direct decryption: {e}")
        import traceback

        log(traceback.format_exc())
        return False


def main():
    parser = argparse.ArgumentParser(description="Debug PQC keystore decryption")
    parser.add_argument("input_file", help="Encrypted input file")
    parser.add_argument(
        "--output", "-o", help="Output file (default: input_file.dec)", default=None
    )
    parser.add_argument("--keystore", required=True, help="Keystore file")
    parser.add_argument("--password", help="File password")
    parser.add_argument("--keystore-password", help="Keystore password")

    args = parser.parse_args()

    # Clear previous debug log
    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== Decryption Debug Log ===\n")

    # Set output file if not specified
    output_file = args.output or f"{args.input_file}.dec"

    log(f"Input file: {args.input_file}")
    log(f"Output file: {output_file}")
    log(f"Keystore: {args.keystore}")

    # Get passwords if not provided
    file_password = args.password
    if not file_password:
        file_password = getpass.getpass("Enter file password: ")
    log(f"File password provided: {bool(file_password)}")

    keystore_password = args.keystore_password
    if not keystore_password:
        keystore_password = getpass.getpass("Enter keystore password: ")
    log(f"Keystore password provided: {bool(keystore_password)}")

    # Step 1: Extract key ID from metadata
    key_id = extract_key_id_from_metadata(args.input_file)

    if not key_id:
        log("ERROR: Failed to extract key ID from file metadata")
        return 1

    log(f"Successfully extracted key ID: {key_id}")

    # Step 2: Load the key from the keystore
    private_key = load_key_from_keystore(args.keystore, key_id, keystore_password)

    if not private_key:
        log("ERROR: Failed to retrieve private key from keystore")
        return 1

    # Step 3: Attempt direct decryption with the loaded key
    success = decrypt_file_direct(args.input_file, output_file, file_password, private_key)

    if success:
        log(f"SUCCESS: File decrypted to {output_file}")

        # Read decrypted content
        try:
            with open(output_file, "r") as f:
                content = f.read()
            log(f"Decrypted content: {content}")
        except Exception as e:
            log(f"Error reading decrypted file: {e}")
    else:
        log(f"FAILED: Could not decrypt file")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
