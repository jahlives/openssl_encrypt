#!/usr/bin/env python3
"""
Secure File Encryption Tool - Main Entry Point

This is the main entry point for the file encryption tool, importing the necessary
modules and providing a simple interface for the CLI.
"""

import argparse
import logging

# Import the CLI module to execute the main function
import os
import sys

# Add the parent directory to sys.path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import and apply ML-KEM patches for CLI support
from openssl_encrypt.modules import ml_kem_patch

ml_kem_patch.apply_patches()


def configure_logging(verbose=False, debug=False):
    """
    Configure logging based on verbose and debug flags.

    When verbose=False and debug=False, set level to WARNING to suppress INFO and DEBUG messages.
    When verbose=True and debug=False, set level to INFO to show more detailed information.
    When debug=True, set level to DEBUG to show all logging messages.
    """
    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")


# Use absolute import when running as script
if __name__ == "__main__":
    from openssl_encrypt.modules.crypt_cli import main

    # Parse just the verbose and debug flags to configure logging before main() runs
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--verbose", "-v", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show detailed debug information (WARNING: logs passwords and sensitive data - test files only!)"
    )
    args, _ = parser.parse_known_args()

    # Configure logging based on verbose and debug flags
    configure_logging(args.verbose, args.debug)

    # Call the main function with all arguments
    main()
