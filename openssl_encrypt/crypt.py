#!/usr/bin/env python3
"""
Secure File Encryption Tool - Main Entry Point

This is the main entry point for the file encryption tool, importing the necessary
modules and providing a simple interface for the CLI.
"""

# Import the CLI module to execute the main function
from .modules.crypt_cli import main

if __name__ == "__main__":
    # Call the main function directly
    main()
