#!/usr/bin/env python3
"""
Command-line entry point for PQC keystore
"""

import sys
import argparse
import os
from openssl_encrypt.modules.keystore_cli import PQCKeystore, KeystoreSecurityLevel, main

def create_keystore(args):
    """
    Create a new keystore with the specified parameters
    """
    # Determine security level
    security_level = KeystoreSecurityLevel.STANDARD
    if args.security_level == "high":
        security_level = KeystoreSecurityLevel.HIGH
    elif args.security_level == "paranoid":
        security_level = KeystoreSecurityLevel.PARANOID
    
    # Check if keystore exists
    if os.path.exists(args.keystore_path) and not args.force:
        print(f"Keystore already exists at {args.keystore_path}. Use --force to overwrite.")
        return 1
    elif os.path.exists(args.keystore_path) and args.force:
        # Remove existing file before creating new one
        try:
            os.remove(args.keystore_path)
            print(f"Removed existing keystore at {args.keystore_path}")
        except Exception as e:
            print(f"Failed to remove existing keystore: {e}")
            return 1
        
    # Create keystore
    keystore = PQCKeystore(args.keystore_path)
    
    # Handle password
    if args.keystore_password:
        password = args.keystore_password
    else:
        # Using input() instead of getpass for better compatibility
        print("WARNING: Using standard input for password. Not secure in shared environments.")
        try:
            password = input("Enter keystore password: ")
            confirm = input("Confirm password: ")
            if password != confirm:
                print("Passwords do not match")
                return 1
        except EOFError:
            print("Error: Unable to read password from input. Please provide it using --keystore-password")
            return 1
    
    # Create the keystore
    try:
        keystore.create_keystore(password, security_level)
        print(f"Keystore created successfully at {args.keystore_path}")
        print(f"Security level: {security_level.value}")
        return 0
    except Exception as e:
        print(f"Error creating keystore: {str(e)}")
        # Enable verbose output for debugging
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return 1

def list_keys(args):
    """List keys in a keystore"""
    # Create keystore
    keystore = PQCKeystore(args.keystore_path)
    
    # Handle password
    if args.keystore_password:
        password = args.keystore_password
    else:
        print("WARNING: Using standard input for password. Not secure in shared environments.")
        try:
            password = input("Enter keystore password: ")
        except EOFError:
            print("Error: Unable to read password from input. Please provide it using --keystore-password")
            return 1
            
    # Load keystore
    try:
        keystore.load_keystore(password)
    except Exception as e:
        print(f"Error loading keystore: {str(e)}")
        return 1
        
    # List keys
    keys = keystore.list_keys()
    
    if args.json:
        import json
        print(json.dumps(keys, indent=2))
    else:
        if not keys:
            print("No keys in keystore")
        else:
            print(f"Keys in {args.keystore_path}:")
            for key in keys:
                tags = ", ".join(key.get("tags", []))
                print(f"ID: {key['key_id']}")
                print(f"  Algorithm: {key.get('algorithm', 'unknown')}")
                print(f"  Created: {key.get('created', 'unknown')}")
                print(f"  Description: {key.get('description', '')}")
                print(f"  Tags: {tags}")
                print(f"  Uses master password: {key.get('use_master_password', True)}")
                print()
                
    return 0

def keystore_cli_fixed():
    """
    Fixed keystore CLI entry point that properly handles all command parameters
    """
    parser = argparse.ArgumentParser(description="PQC Keystore Management Fixed CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new keystore")
    create_parser.add_argument("--keystore-path", required=True, help="Path to the keystore file")
    create_parser.add_argument("--keystore-password", help="Password for the keystore (will prompt if not provided)")
    create_parser.add_argument("--security-level", choices=["standard", "high", "paranoid"], 
                               default="standard", help="Security level for the keystore")
    create_parser.add_argument("--force", action="store_true", help="Overwrite existing keystore")
    create_parser.set_defaults(func=create_keystore)
    
    # List keys command
    list_parser = subparsers.add_parser("list-keys", help="List keys in the keystore")
    list_parser.add_argument("--keystore-path", required=True, help="Path to the keystore file")
    list_parser.add_argument("--keystore-password", help="Password for the keystore (will prompt if not provided)")
    list_parser.add_argument("--json", action="store_true", help="Output as JSON")
    list_parser.set_defaults(func=list_keys)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Call the appropriate function
    if hasattr(args, "func"):
        return args.func(args)
    else:
        # Output error for unknown command
        print(f"Error: Unknown command '{args.command}'. Use --help to see available commands.")
        return 1

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["create", "list-keys"]:
        sys.exit(keystore_cli_fixed())
    else:
        # Use the original CLI for other commands
        sys.exit(main())