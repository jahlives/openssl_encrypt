#!/usr/bin/env python3
"""
Script to apply the keystore loading fix by patching the necessary code in pqc_keystore.py
"""

import os
import sys
import tempfile
import shutil
import argparse

def apply_keystore_fix():
    """Apply the fix to the pqc_keystore.py file"""
    # Paths
    pqc_keystore_path = os.path.join(os.getcwd(), "openssl_encrypt", "modules", "pqc_keystore.py")
    backup_path = pqc_keystore_path + ".bak"
    
    # Check if file exists
    if not os.path.exists(pqc_keystore_path):
        print(f"Error: Could not find {pqc_keystore_path}")
        return False
    
    # Make a backup
    print(f"Creating backup at {backup_path}")
    shutil.copy2(pqc_keystore_path, backup_path)
    
    # Read the file
    print(f"Reading {pqc_keystore_path}")
    with open(pqc_keystore_path, 'r') as f:
        content = f.read()
    
    # Apply the first fix: change in save_keystore method
    old_code1 = """                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"""
    new_code1 = """                # Use same associated_data approach as in load_keystore for consistency
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))"""
    
    if old_code1 in content:
        content = content.replace(old_code1, new_code1)
        print("Fixed save_keystore method: changed associated_data from None to header JSON")
    else:
        print("Warning: Could not find the target code in save_keystore method")
    
    # Apply the second fix: make load_keystore more robust
    old_code2 = """                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"""
    
    new_code2 = """                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                
                # Try both approaches for backward compatibility - first with header as associated_data
                try:
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                except Exception:
                    # Fall back to the original approach for older keystores
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"""
    
    if old_code2 in content:
        content = content.replace(old_code2, new_code2)
        print("Fixed load_keystore method: added fallback for different associated_data approaches")
    else:
        print("Warning: Could not find the target code in load_keystore method")
    
    # Write the updated file
    print(f"Writing updated file to {pqc_keystore_path}")
    with open(pqc_keystore_path, 'w') as f:
        f.write(content)
    
    print("\nFix applied successfully! The patch ensures consistent use of associated_data between "
          "saving and loading the keystore, with fallback for backward compatibility.")
    print(f"\nOriginal file backed up at: {backup_path}")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply the keystore loading fix")
    parser.add_argument("--apply", action="store_true", help="Apply the fix to the pqc_keystore.py file")
    
    args = parser.parse_args()
    
    if args.apply:
        if apply_keystore_fix():
            print("\nFix successfully applied!")
    else:
        print("Usage: python apply_keystore_fix.py --apply")
        print("Run with --apply to patch the pqc_keystore.py file")