#!/usr/bin/env python3
"""
Script to fix indentation issues in the PQCKeystore methods
"""

import os
import shutil


def fix_file():
    """Fix indentation issues in pqc_keystore.py"""
    target_file = os.path.join(
        os.path.abspath("."), "openssl_encrypt", "modules", "pqc_keystore.py"
    )
    backup_file = target_file + ".bak_indent"

    # Create a backup
    shutil.copy2(target_file, backup_file)
    print(f"Created backup at {backup_file}")

    with open(target_file, "r", encoding="utf-8") as f:
        content = f.read()

    # Fix indentation for load_keystore and save_keystore methods
    content = content.replace(
        "    def create_keystore(self, master_password: str, \n"
        "                        security_level: KeystoreSecurityLevel = KeystoreSecurityLevel.STANDARD) -> bool:\n"
        '        """\n'
        "        Create a new keystore file\n"
        "        \n"
        "        Args:\n"
        "            master_password: Master password for the keystore\n"
        "            security_level: Security level for key protection\n"
        "            \n"
        "        Returns:\n"
        "            bool: True if the keystore was created successfully\n"
        "        \n"
        "        Raises:\n"
        "            ValidationError: If the keystore already exists\n"
        "            InternalError: If the keystore cannot be created\n"
        '        """\n'
        "        if self.keystore_path is None:\n"
        '            raise ValidationError("No keystore path specified")\n'
        "            \n"
        "        if os.path.exists(self.keystore_path):\n"
        '            raise ValidationError(f"Keystore already exists at {self.keystore_path}")\n'
        "            \n"
        "        # Initialize empty keystore\n"
        "        self.keystore_data = {\n"
        '            "keystore_version": self.KEYSTORE_VERSION,\n'
        '            "creation_date": datetime.datetime.now().isoformat(),\n'
        '            "last_modified": datetime.datetime.now().isoformat(),\n'
        '            "keys": [],\n'
        '            "default_key_id": None,\n'
        '            "protection": self._get_protection_params(security_level)\n'
        "        }\n"
        "        \n"
        "        # Create directory if it doesn't exist\n"
        "        try:\n"
        "            # Handle the case where the keystore is in the current directory\n"
        "            dir_path = os.path.dirname(self.keystore_path)\n"
        "            if dir_path:\n"
        "                os.makedirs(dir_path, exist_ok=True)\n"
        "        except Exception as e:\n"
        '            raise InternalError(f"Failed to create directory: {str(e)}")\n'
        "        \n"
        "        try:\n"
        "            # Encrypt and save the keystore\n"
        "            return self.save_keystore(master_password)\n"
        "        except Exception as e:\n"
        "            import traceback\n"
        "            traceback.print_exc()\n"
        '            raise InternalError(f"Failed to create keystore: {str(e)}")\n'
        "            \n"
        "        def load_keystore(self, master_password: str) -> bool:",
        # Replace with properly indented version
        "    def create_keystore(self, master_password: str, \n"
        "                        security_level: KeystoreSecurityLevel = KeystoreSecurityLevel.STANDARD) -> bool:\n"
        '        """\n'
        "        Create a new keystore file\n"
        "        \n"
        "        Args:\n"
        "            master_password: Master password for the keystore\n"
        "            security_level: Security level for key protection\n"
        "            \n"
        "        Returns:\n"
        "            bool: True if the keystore was created successfully\n"
        "        \n"
        "        Raises:\n"
        "            ValidationError: If the keystore already exists\n"
        "            InternalError: If the keystore cannot be created\n"
        '        """\n'
        "        if self.keystore_path is None:\n"
        '            raise ValidationError("No keystore path specified")\n'
        "            \n"
        "        if os.path.exists(self.keystore_path):\n"
        '            raise ValidationError(f"Keystore already exists at {self.keystore_path}")\n'
        "            \n"
        "        # Initialize empty keystore\n"
        "        self.keystore_data = {\n"
        '            "keystore_version": self.KEYSTORE_VERSION,\n'
        '            "creation_date": datetime.datetime.now().isoformat(),\n'
        '            "last_modified": datetime.datetime.now().isoformat(),\n'
        '            "keys": [],\n'
        '            "default_key_id": None,\n'
        '            "protection": self._get_protection_params(security_level)\n'
        "        }\n"
        "        \n"
        "        # Create directory if it doesn't exist\n"
        "        try:\n"
        "            # Handle the case where the keystore is in the current directory\n"
        "            dir_path = os.path.dirname(self.keystore_path)\n"
        "            if dir_path:\n"
        "                os.makedirs(dir_path, exist_ok=True)\n"
        "        except Exception as e:\n"
        '            raise InternalError(f"Failed to create directory: {str(e)}")\n'
        "        \n"
        "        try:\n"
        "            # Encrypt and save the keystore\n"
        "            return self.save_keystore(master_password)\n"
        "        except Exception as e:\n"
        "            import traceback\n"
        "            traceback.print_exc()\n"
        '            raise InternalError(f"Failed to create keystore: {str(e)}")\n'
        "            \n"
        "    def load_keystore(self, master_password: str) -> bool:",
    )

    # Fix load_keystore indentation
    content = content.replace(
        "        def load_keystore(self, master_password: str) -> bool:",
        "    def load_keystore(self, master_password: str) -> bool:",
    )

    # Fix save_keystore indentation
    content = content.replace(
        "        def save_keystore(self, master_password: str = None) -> bool:",
        "    def save_keystore(self, master_password: str = None) -> bool:",
    )

    # Write the fixed content back to the file
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Fixed indentation issues in {target_file}")
    return True


if __name__ == "__main__":
    fix_file()
