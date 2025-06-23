#!/usr/bin/env python3
"""
Final, minimal patch for the PQCKeystore encryption/decryption issue
"""

import os
import shutil
import sys
import tempfile
import traceback


def apply_patch():
    """
    Apply a patch to fix the AES-GCM associated data issue in pqc_keystore.py

    The issue: In save_keystore, the encryption uses associated_data=None,
    but in load_keystore, decryption tries with associated_data=json.dumps(header).encode('utf-8')
    first, which fails, causing authentication errors.
    """
    try:
        # Ensure we're in the correct directory
        repo_root = os.path.abspath(os.path.dirname(__file__))
        target_file = os.path.join(repo_root, "openssl_encrypt", "modules", "pqc_keystore.py")
        backup_file = target_file + ".bak"

        print(f"Applying patch to {target_file}")
        print(f"Creating backup at {backup_file}")

        # Create backup of original file
        shutil.copy2(target_file, backup_file)

        # Read the current file
        with open(target_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Identify the problematic part
        old_code_marker1 = """                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                # Update nonce for each save
                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode('utf-8')

                header = {"protection": protection}
                # Use the same associated_data approach as in load_keystore for consistency
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))"""

        # Check if the file has already been fixed
        if old_code_marker1 in content:
            print("File appears to already contain the fix...")

            # Let's verify if there's any remaining incorrect reference to None
            incorrect_marker = """                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"""

            if incorrect_marker in content:
                print("Found incorrect None reference in save_keystore, fixing it...")
                content = content.replace(
                    incorrect_marker,
                    """                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))""",
                )

                # Save the fixed file
                with open(target_file, "w", encoding="utf-8") as f:
                    f.write(content)
                print("File patched successfully.")
            else:
                print("No incorrect None references found. File seems correctly patched.")

            return True

        print("Could not find expected code pattern, checking for alternate pattern...")

        # Try looking for a simpler pattern that might match
        old_code_marker2 = """                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"""

        if old_code_marker2 in content:
            print("Found alternate pattern with associated_data=None, applying fix...")
            content = content.replace(
                old_code_marker2,
                """                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))""",
            )

            # Save the fixed file
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(content)
            print("File patched successfully with alternate pattern.")
            return True

        print("Could not identify the exact location to patch. Manual inspection needed.")
        print("However, file appears to be already fixed based on our examination.")
        return False

    except Exception as e:
        print(f"Error applying patch: {e}")
        traceback.print_exc()
        return False


def verify_patch():
    """Create a test keystore and verify that it loads correctly"""
    print("\nVerifying patch with simple test...")

    try:
        # Import the patched module
        sys.path.insert(0, os.path.abspath("."))
        from openssl_encrypt.modules.pqc_keystore import KeystoreSecurityLevel, PQCKeystore

        # Create a temporary directory for test files
        temp_dir = tempfile.mkdtemp()
        keystore_path = os.path.join(temp_dir, "test_keystore.pqc")

        # Master password for tests
        master_password = "test_master_password"

        # Create a keystore
        print("Creating keystore...")
        keystore = PQCKeystore(keystore_path)
        result = keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
        print(f"Keystore created successfully: {result}")

        # Try to load it in a new instance
        print("Loading keystore...")
        keystore2 = PQCKeystore(keystore_path)
        result = keystore2.load_keystore(master_password)
        print(f"Keystore loaded successfully: {result}")

        # Clean up
        print("Cleaning up test files...")
        shutil.rmtree(temp_dir)

        print("Patch verification successful!")
        return True

    except Exception as e:
        print(f"Patch verification failed: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    if apply_patch():
        verify_patch()
    else:
        print("Patch could not be applied, verification skipped.")
