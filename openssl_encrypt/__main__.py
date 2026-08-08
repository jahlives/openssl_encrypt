#!/usr/bin/env python3
"""Main entry point for openssl_encrypt package.

Allows running the package with: python -m openssl_encrypt

Routes through cli.main, NOT modules.crypt_cli.main. Importing the CLI
directly here made `python -m openssl_encrypt` a second entry point that
skipped cli.py, so --gui -- handled only there -- was invisible to it and
argparse rejected the run with "the following arguments are required:
action" (gitlab#197).
"""

from .cli import main

if __name__ == "__main__":
    main()
