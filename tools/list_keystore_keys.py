#!/usr/bin/env python3
"""
Script to list keys in a keystore
"""

import argparse
import getpass
import os
import sys

from openssl_encrypt.modules.keystore_cli import PQCKeystore

# Environment variable carrying the keystore password for non-interactive use
# (avoids putting it on argv, where ps / /proc/<pid>/cmdline / shell history
# would expose it -- gitlab#249, F32, CWE-214).
KEYSTORE_PASSWORD_ENV = "KEYSTORE_PASSWORD"


def resolve_keystore_password(cli_password, environ=None, prompt=None):
    """Resolve the keystore password without requiring it on the command line.

    Precedence: an explicit ``--password`` value (with a one-time stderr warning
    that argv is world-readable), then the ``KEYSTORE_PASSWORD`` environment
    variable, then an interactive ``getpass`` prompt.

    Args:
        cli_password: The value of ``--password`` (or None if not supplied).
        environ: Environment mapping to read (defaults to os.environ).
        prompt: Callable returning the password interactively (defaults to
            getpass.getpass); injectable for testing.

    Returns:
        The resolved password string.
    """
    if environ is None:
        environ = os.environ
    if prompt is None:

        def prompt():
            return getpass.getpass("Enter keystore password: ")

    if cli_password is not None:
        print(
            "Warning: passing --password on the command line exposes it via ps / "
            "/proc/<pid>/cmdline / shell history. Prefer the KEYSTORE_PASSWORD "
            "environment variable or the interactive prompt.",
            file=sys.stderr,
        )
        return cli_password

    env_password = environ.get(KEYSTORE_PASSWORD_ENV)
    if env_password:
        return env_password

    return prompt()


def main():
    parser = argparse.ArgumentParser(description="List keys in keystore")
    parser.add_argument("--keystore", required=True, help="Path to keystore file")
    parser.add_argument(
        "--password",
        default=None,
        help=(
            "Keystore password (INSECURE: visible in ps/argv). Prefer the "
            f"{KEYSTORE_PASSWORD_ENV} environment variable or the interactive prompt."
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="Show verbose details")

    args = parser.parse_args()

    password = resolve_keystore_password(args.password)

    try:
        # Load the keystore
        keystore = PQCKeystore(args.keystore)
        keystore.load_keystore(password)

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
