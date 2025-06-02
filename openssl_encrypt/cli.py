#!/usr/bin/env python3
"""
Main CLI entry point for openssl_encrypt.

This module provides the main entry point for the openssl-encrypt command,
delegating to the actual CLI implementation in modules.crypt_cli or launching GUI.
"""

import sys
import argparse

def main():
    """Main entry point for the openssl-encrypt command."""
    # Check if --gui is the first argument
    if len(sys.argv) > 1 and sys.argv[1] == '--gui':
        # Launch GUI
        from .crypt_gui import main as gui_main
        gui_main()
        return
    
    # Check if gui is anywhere in arguments (for help text)
    if '--help' in sys.argv or '-h' in sys.argv:
        # Create a simple parser to show GUI option in help
        parser = argparse.ArgumentParser(
            prog='openssl-encrypt',
            description='Encrypt or decrypt files with a password',
            add_help=False
        )
        parser.add_argument('--gui', action='store_true', 
                          help='Launch graphical user interface')
        parser.add_argument('--help', '-h', action='store_true',
                          help='Show this help message and exit')
        
        # If only asking for help, show GUI option first
        if len(sys.argv) == 2 and ('--help' in sys.argv or '-h' in sys.argv):
            print("usage: openssl-encrypt [--gui] | [command] [options...]")
            print("")
            print("Encrypt or decrypt files with a password")
            print("")
            print("options:")
            print("  --gui                 Launch graphical user interface")
            print("  -h, --help            Show help for command-line interface")
            print("")
            print("For command-line interface help, use: openssl-encrypt encrypt --help")
            return
    
    # Otherwise, delegate to the CLI
    from .modules.crypt_cli import main as cli_main
    cli_main()

if __name__ == "__main__":
    main()