#!/usr/bin/env python3
"""
Simple targeted fix for the pqc_keystore.py file
"""

import os


def fix_pqc_keystore():
    """Apply a targeted fix to the pqc_keystore.py file"""
    file_path = os.path.join(os.getcwd(), "openssl_encrypt", "modules", "pqc_keystore.py")

    # First check if file exists
    if not os.path.exists(file_path):
        print(f"Error: Cannot find file {file_path}")
        return False

    # Create a backup
    backup_path = f"{file_path}.bak3"
    print(f"Creating backup at {backup_path}")

    # Read the file
    with open(file_path, "r") as f:
        content = f.read()

    # Save backup
    with open(backup_path, "w") as f:
        f.write(content)

    # Fix the AES-GCM section in save_keystore
    target_pattern = """                # Always use empty string as associated_data for AES-GCM to ensure compatibility
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"""

    replacement = """                # BUGFIX: Use header as associated_data for consistency with load_keystore
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))"""

    # Apply the fix
    new_content = content.replace(target_pattern, replacement)

    # Fix the ChaCha20 section for consistency
    chacha_pattern = """                # Always use None for associated_data for consistent encryption
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"""

    chacha_replacement = """                # BUGFIX: Use header as associated_data for consistency with load_keystore
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))"""

    new_content = new_content.replace(chacha_pattern, chacha_replacement)

    # Write the updated file
    with open(file_path, "w") as f:
        f.write(new_content)

    print(f"Successfully applied fix to {file_path}")
    print("Now run 'python verify_fix.py' to test the fix.")
    return True


if __name__ == "__main__":
    fix_pqc_keystore()
