#!/usr/bin/env python3
"""
Test script for decrypting files with embedded PQC private keys
"""

import sys
import argparse
from openssl_encrypt.modules.crypt_core import decrypt_file

def decrypt_with_password(input_file, output_file, password):
    """
    Decrypt a file with password only, using embedded private key if present.
    """
    print(f"Decrypting {input_file} to {output_file} with password")
    
    # Convert string password to bytes
    password_bytes = password.encode('utf-8')
    
    # Decrypt the file
    result = decrypt_file(
        input_file,
        output_file,
        password_bytes,
        False,  # not quiet
        True,   # show progress
        True    # verbose
    )
    
    if result is True or (isinstance(result, bytes) and len(result) > 0):
        print("Decryption successful!")
        return True
    else:
        print("Decryption failed!")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Test embedded PQC private key decryption")
    parser.add_argument('--input', '-i', default='/tmp/test.txt', help='Input encrypted file (default: /tmp/test.txt)')
    parser.add_argument('--output', '-o', default='decrypted_output.txt', help='Output file (default: decrypted_output.txt)')
    parser.add_argument('--password', '-p', default='1234', help='Password (default: 1234)')
    
    args = parser.parse_args()
    
    # Decrypt the file
    success = decrypt_with_password(args.input, args.output, args.password)
    
    # Check decryption result
    if success:
        print(f"File successfully decrypted to {args.output}")
        with open(args.output, 'r') as f:
            content = f.read()
            print(f"Content: {content}")
        
        # Return success
        return 0
    else:
        print("Decryption failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())