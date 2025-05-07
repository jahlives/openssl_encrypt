#!/usr/bin/env python3
"""
Check if a file has the expected openssl_encrypt format
"""

import os
import sys
import base64
import binascii

def analyze_file(file_path):
    """Analyze a file to determine if it has the openssl_encrypt format"""
    print(f"Analyzing file: {file_path}")
    print(f"File size: {os.path.getsize(file_path)} bytes")
    print()
    
    # Read the first part of the file
    try:
        with open(file_path, 'rb') as f:
            header = f.read(100)  # Read first 100 bytes for header analysis
            content = f.read(1000)  # Read more for content analysis
        
        print(f"First 100 bytes (hex): {header.hex()[:100]}...")
        
        # Check for colon separator
        colon_pos = header.find(b':')
        if colon_pos > 0:
            print(f"Found colon separator at position {colon_pos}")
            
            # Try to decode base64 metadata
            metadata_b64 = header[:colon_pos]
            print(f"Base64 metadata: {metadata_b64}")
            
            try:
                metadata = base64.b64decode(metadata_b64)
                print(f"Decoded metadata: {metadata[:100]}...")
                
                # Check if it starts with a bracket (JSON format)
                if metadata.startswith(b'{'):
                    print("✅ Metadata appears to be in JSON format")
                else:
                    print("❌ Metadata does not start with JSON object")
            except binascii.Error:
                print("❌ Metadata is not valid base64")
        else:
            print("❌ No colon separator found - not in openssl_encrypt format")
            
            # Check if it might be raw data
            try:
                text = header.decode('utf-8', errors='replace')
                print(f"Content preview (as text): {text}")
                if text.isprintable():
                    print("File appears to be plain text, not encrypted")
            except UnicodeDecodeError:
                print("File contains binary data, but not in expected format")
        
        # Additional format checks
        if b'OSENC' in header:
            print("Found OSENC marker - legacy format detected")
    
    except Exception as e:
        print(f"Error analyzing file: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_file_format.py <file_path>")
        return 1
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} does not exist")
        return 1
    
    analyze_file(file_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())