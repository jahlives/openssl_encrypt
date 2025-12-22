#!/usr/bin/env python3
"""Main entry point for openssl_encrypt package.

Allows running the package with: python -m openssl_encrypt
"""

from .modules.crypt_cli import main

if __name__ == "__main__":
    main()
