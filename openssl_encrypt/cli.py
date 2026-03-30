#!/usr/bin/env python3
"""
Main CLI entry point for openssl_encrypt.

This module provides the main entry point for the openssl-encrypt command,
delegating to the actual CLI implementation in modules.crypt_cli or launching GUI.
"""

import argparse
import sys

from .modules.crypt_utils import eprint


def main():
    """Main entry point for the openssl-encrypt command."""
    # Check if --gui is the first argument
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        # Launch GUI
        from .crypt_gui import main as gui_main

        gui_main()
        return

    # Check if gui is anywhere in arguments (for help text)
    if "--help" in sys.argv or "-h" in sys.argv:
        # Create a simple parser to show GUI option in help
        parser = argparse.ArgumentParser(
            prog="openssl-encrypt",
            description="Encrypt or decrypt files with a password",
            add_help=False,
        )
        parser.add_argument(
            "--gui", action="store_true", help="Launch graphical user interface"
        )
        parser.add_argument(
            "--help", "-h", action="store_true", help="Show this help message and exit"
        )

        # If only asking for help, show GUI option first
        if len(sys.argv) == 2 and ("--help" in sys.argv or "-h" in sys.argv):
            eprint("usage: openssl-encrypt [--gui] | [command] [options...]")
            eprint("")
            eprint("Encrypt or decrypt files with password protection")
            eprint("")
            eprint("Available commands:")
            eprint("  encrypt              Encrypt files with password protection")
            eprint("  decrypt              Decrypt previously encrypted files")
            eprint("  shred                Securely delete files")
            eprint("  generate-password    Generate cryptographically secure passwords")
            eprint("  list-algorithms      List available cryptographic algorithms")
            eprint("  security-info        Display security information and algorithms")
            eprint("  check-argon2         Verify Argon2 implementation")
            eprint("  check-pqc           Check post-quantum cryptography support")
            eprint("  version             Show version information")
            eprint("")
            eprint("Steganography:")
            eprint(
                "  Use --stego-hide with encrypt command to hide encrypted data in images"
            )
            eprint(
                "  Use --stego-extract with decrypt command to extract data from images"
            )
            eprint("")
            eprint("Global options:")
            eprint("  --gui               Launch graphical user interface")
            eprint("  -h, --help          Show this help message")
            eprint("")
            eprint("For detailed help on a command: openssl-encrypt <command> --help")
            return

    # Otherwise, delegate to the CLI
    from .modules.crypt_cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
