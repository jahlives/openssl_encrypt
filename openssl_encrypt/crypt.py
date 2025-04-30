#!/usr/bin/env python3
"""
Secure File Encryption Tool - Main Entry Point

This is the main entry point for the file encryption tool, importing the necessary
modules and providing a simple interface for the CLI.
"""

# Import the CLI module to execute the main function
import os
import sys

# Add the parent directory to sys.path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Use absolute import when running as script
if __name__ == "__main__":
    from openssl_encrypt.modules.crypt_cli import main
    # Call the main function directly
    main()
