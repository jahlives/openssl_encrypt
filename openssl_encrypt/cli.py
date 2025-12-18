#!/usr/bin/env python3
"""
Main CLI entry point for openssl_encrypt.

This module provides the main entry point for the openssl-encrypt command,
delegating to the actual CLI implementation in modules.crypt_cli or launching GUI.
"""

import argparse
import sys


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
        parser.add_argument("--gui", action="store_true", help="Launch graphical user interface")
        parser.add_argument(
            "--help", "-h", action="store_true", help="Show this help message and exit"
        )

        # If only asking for help, show GUI option first
        if len(sys.argv) == 2 and ("--help" in sys.argv or "-h" in sys.argv):
            print("usage: openssl-encrypt [--gui] | [command] [options...]")
            print("")
            print("Encrypt or decrypt files with password protection")
            print("")
            print("Available commands:")
            print("  encrypt              Encrypt files with password protection")
            print("  decrypt              Decrypt previously encrypted files")
            print("  shred                Securely delete files")
            print("  generate-password    Generate cryptographically secure passwords")
            print("  security-info        Display security information and algorithms")
            print("  check-argon2         Verify Argon2 implementation")
            print("  check-pqc           Check post-quantum cryptography support")
            print("  version             Show version information")
            print("")
            print("Steganography:")
            print("  Use --stego-hide with encrypt command to hide encrypted data in images")
            print("  Use --stego-extract with decrypt command to extract data from images")
            print("")
            print("Global options:")
            print("  --gui               Launch graphical user interface")
            print("  -h, --help          Show this help message")
            print("")
            print("For detailed help on a command: openssl-encrypt <command> --help")
            return

    # Otherwise, delegate to the CLI
    from .modules.crypt_cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
