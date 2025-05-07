#!/usr/bin/env python3
"""
Detailed hex analysis of an encrypted file
"""

import os
import sys
import binascii

def hex_dump(data, bytes_per_line=16):
    """Create a formatted hex dump of binary data"""
    result = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        
        # Create ASCII representation
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        
        line = f"{i:04x}: {hex_part.ljust(bytes_per_line*3)} | {ascii_part}"
        result.append(line)
    
    return '\n'.join(result)

def find_colon(file_path):
    """Find all positions of the colon character in a file"""
    colon_positions = []
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    for i, byte in enumerate(data):
        if byte == ord(':'):
            colon_positions.append(i)
            # Show context around the colon
            start = max(0, i - 20)
            end = min(len(data), i + 20)
            context = data[start:end]
            print(f"Colon at position {i}: Context: {context}")
            
            # If this is likely the metadata separator, print more details
            if i > 100:  # Assuming metadata is at least 100 bytes
                print(f"Potential metadata separator at position {i}")
                print(f"Content before: {data[i-50:i]}")
                print(f"Content after: {data[i+1:i+51]}")
                
                # Try to decode metadata
                try:
                    metadata = data[:i]
                    import base64
                    decoded = base64.b64decode(metadata)
                    print(f"Decoded metadata: {decoded[:100]}")
                except Exception as e:
                    print(f"Failed to decode metadata: {e}")
    
    return colon_positions

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_hex_file.py <file_path>")
        return 1
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} does not exist")
        return 1
    
    # Read the file
    with open(file_path, 'rb') as f:
        data = f.read(4096)  # Read up to 4KB for analysis
    
    print(f"File: {file_path}")
    print(f"Size: {os.path.getsize(file_path)} bytes")
    
    # Look for colon byte (0x3A)
    colon_pos = -1
    for i, byte in enumerate(data):
        if byte == 0x3A:  # ASCII colon
            colon_pos = i
            break
    
    if colon_pos >= 0:
        print(f"Found colon at position: {colon_pos}")
        
        # Show hex dump around colon
        start = max(0, colon_pos - 32)
        end = min(len(data), colon_pos + 33)
        
        print("\nHex dump around colon:")
        print(hex_dump(data[start:end]))
        
        # Extract and analyze metadata
        metadata = data[:colon_pos]
        
        print(f"\nMetadata length: {len(metadata)} bytes")
        
        # Check if metadata is valid base64
        try:
            import base64
            decoded = base64.b64decode(metadata)
            print(f"✅ Metadata is valid base64 ({len(decoded)} bytes decoded)")
            
            # Check for JSON format
            if decoded.startswith(b'{'):
                print("✅ Decoded metadata starts with JSON object")
                
                # Try to parse as JSON
                try:
                    import json
                    metadata_json = json.loads(decoded)
                    print("✅ Metadata is valid JSON")
                    
                    # Check for key ID
                    if 'hash_config' in metadata_json and 'pqc_keystore_key_id' in metadata_json['hash_config']:
                        key_id = metadata_json['hash_config']['pqc_keystore_key_id']
                        print(f"✅ Found key ID in metadata: {key_id}")
                    else:
                        print("❌ No key ID found in metadata")
                        print(f"hash_config keys: {metadata_json.get('hash_config', {}).keys()}")
                except json.JSONDecodeError as e:
                    print(f"❌ Metadata is not valid JSON: {e}")
            else:
                print(f"❌ Decoded metadata does not start with JSON object: {decoded[:20]}")
        except binascii.Error as e:
            print(f"❌ Metadata is not valid base64: {e}")
    else:
        print("❌ No colon found in the first 4KB of the file")
        
        # Search for colon in entire file
        print("\nSearching for colon in entire file...")
        colon_positions = find_colon(file_path)
        
        if colon_positions:
            print(f"Found {len(colon_positions)} colons at positions: {colon_positions}")
        else:
            print("No colon found in the entire file")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())