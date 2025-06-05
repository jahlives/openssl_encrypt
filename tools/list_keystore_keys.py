#!/usr/bin/env python3
"""
Script to list keys in a keystore
"""

import argparse
import sys

from openssl_encrypt.modules.keystore_cli import PQCKeystore


def main():
    parser = argparse.ArgumentParser(description="List keys in keystore")
    parser.add_argument("--keystore", required=True, help="Path to keystore file")
    parser.add_argument("--password", required=True, help="Keystore password")
    parser.add_argument("--verbose", action="store_true", help="Show verbose details")

    args = parser.parse_args()

    try:
        # Load the keystore
        keystore = PQCKeystore(args.keystore)
        keystore.load_keystore(args.password)

        # List keys
        keys = keystore.list_keys()

        if not keys:
            print("No keys found in keystore.")
            return

        print(f"Found {len(keys)} keys in keystore: {args.keystore}")
        print("-" * 70)

        for key in keys:
            print(f"Key ID: {key['key_id']}")
            print(f"Algorithm: {key.get('algorithm', 'unknown')}")
            print(f"Created: {key.get('created', 'unknown')}")
            print(f"Description: {key.get('description', '')}")

            if "dual_encrypted" in key:
                print(f"Dual encryption: {key.get('dual_encrypted', False)}")

            if args.verbose:
                print(f"Tags: {', '.join(key.get('tags', []))}")
                print(f"Uses master password: {key.get('use_master_password', True)}")

            print("-" * 70)

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
