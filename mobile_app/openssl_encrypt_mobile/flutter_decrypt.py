#!/usr/bin/env python3
"""
Simple CLI-compatible decryption script for Flutter GUI
Avoids complex imports and environment issues
"""

import sys
import json
import os

def main():
    if len(sys.argv) != 3:
        print("ERROR: Usage: python flutter_decrypt.py <encrypted_json> <password>")
        sys.exit(1)
    
    encrypted_json = sys.argv[1]
    password = sys.argv[2]
    
    try:
        # Import our corrected crypto core
        from mobile_crypto_core import MobileCryptoCore
        core = MobileCryptoCore()
        
        # Decrypt using CLI-compatible implementation
        result = core.decrypt_text(encrypted_json, password)
        
        # Output result
        print(result)
        
    except ImportError as ie:
        print(f"ERROR: Import failed: {str(ie)}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Python decryption failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()