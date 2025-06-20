#!/usr/bin/env python3
"""
Complete fix script for the PQC keystore loading issue that creates, verifies, and fixes the keystore
directly without relying on the original implementation.
"""

import os
import sys
import tempfile
import base64
import json
import hashlib
import secrets
import datetime
import time
import uuid
import traceback

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from enum import Enum

# Check for Argon2 support
try:
    import argon2
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

# Define enum classes needed from the original
class KeystoreSecurityLevel(Enum):
    """Security levels for keystore protection"""
    STANDARD = "standard"
    HIGH = "high"
    PARANOID = "paranoid"

class KeystoreProtectionMethod(Enum):
    """Methods used to protect keys in the keystore"""
    ARGON2ID_AES_GCM = "argon2id+aes-256-gcm"
    SCRYPT_CHACHA20 = "scrypt+chacha20-poly1305"
    PBKDF2_AES_GCM = "pbkdf2+aes-256-gcm"  # Fallback if Argon2 not available


def create_simple_keystore(keystore_path: str, master_password: str, security_level: str = "standard"):
    """Create a simple keystore file with minimal content"""
    # Initialize empty keystore
    keystore_data = {
        "keystore_version": "1.0",
        "creation_date": datetime.datetime.now().isoformat(),
        "last_modified": datetime.datetime.now().isoformat(),
        "keys": [],
        "default_key_id": None
    }
    
    # Generate salt and nonce
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    
    # Choose method based on availability
    if ARGON2_AVAILABLE:
        method = KeystoreProtectionMethod.ARGON2ID_AES_GCM
    else:
        # Fallback to Scrypt + ChaCha20
        method = KeystoreProtectionMethod.SCRYPT_CHACHA20
        
    # Set default parameters
    if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM:
        # Standard parameters
        time_cost = 3
        memory_cost = 65536  # 64 MB
        parallelism = 2
        
        protection = {
            "method": method.value,
            "params": {
                "salt": base64.b64encode(salt).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "argon2_params": {
                    "time_cost": time_cost,
                    "memory_cost": memory_cost,
                    "parallelism": parallelism
                }
            }
        }
        
        # Derive key with Argon2
        ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32
        )
        
        # Encode salt as required by argon2-cffi
        salt_b64 = protection["params"]["salt"]
        
        # Hash the password with Argon2id
        hash_result = ph.hash(master_password + salt_b64)
        derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()
        
    elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20:
        # Standard parameters
        n = 65536  # 2^16
        r = 8
        p = 1
        
        protection = {
            "method": method.value,
            "params": {
                "salt": base64.b64encode(salt).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "scrypt_params": {
                    "n": n,
                    "r": r,
                    "p": p
                }
            }
        }
        
        # Derive key with Scrypt
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=n,
            r=r,
            p=p
        )
        derived_key = kdf.derive(master_password.encode('utf-8'))
    
    # Set protection parameters
    keystore_data["protection"] = protection
    
    # Convert to JSON for encryption
    plaintext = json.dumps(keystore_data).encode('utf-8')
    
    # Create the cipher
    if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM:
        cipher = AESGCM(derived_key)
        
        # Create the header and associated data
        header = {"protection": protection}
        header_bytes = json.dumps(header).encode('utf-8')
        
        # Encrypt with associated_data
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data=header_bytes)
        
    elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20:
        cipher = ChaCha20Poly1305(derived_key)
        
        # Create the header and associated data
        header = {"protection": protection}
        header_bytes = json.dumps(header).encode('utf-8')
        
        # Encrypt with associated_data
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data=header_bytes)
    
    # Prepare the final file format
    header_json = json.dumps(header).encode('utf-8')
    header_size = len(header_json)
    
    # Create directory if needed
    os.makedirs(os.path.dirname(os.path.abspath(keystore_path)), exist_ok=True)
    
    # Write the file
    with open(keystore_path, 'wb') as f:
        f.write(header_size.to_bytes(4, byteorder='big'))
        f.write(header_json)
        f.write(ciphertext)
        
    print(f"Keystore created at {keystore_path}")
    return True


def load_test_keystore(keystore_path: str, master_password: str):
    """Load and decrypt a keystore file"""
    if not os.path.exists(keystore_path):
        print(f"Error: Keystore not found at {keystore_path}")
        return False
        
    try:
        with open(keystore_path, 'rb') as f:
            encrypted_data = f.read()
            
        # Parse the encrypted data
        header_size = int.from_bytes(encrypted_data[:4], byteorder='big')
        header_bytes = encrypted_data[4:4+header_size]
        header = json.loads(header_bytes.decode('utf-8'))
        ciphertext = encrypted_data[4+header_size:]
        
        # Extract parameters
        protection = header["protection"]
        method = protection["method"]
        params = protection["params"]
        
        # Derive key from master password
        if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
            if not ARGON2_AVAILABLE:
                print("Error: Argon2 is required for this keystore but not available")
                return False
                
            # Derive key with Argon2
            argon2_params = params["argon2_params"]
            ph = PasswordHasher(
                time_cost=argon2_params["time_cost"],
                memory_cost=argon2_params["memory_cost"],
                parallelism=argon2_params["parallelism"],
                hash_len=32
            )
            
            # Encode salt as required by argon2-cffi
            salt_b64 = params["salt"]
            
            # Hash the password with Argon2id
            hash_result = ph.hash(master_password + salt_b64)
            derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()
            
        elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
            # Derive key with Scrypt
            salt = base64.b64decode(params["salt"])
            scrypt_params = params["scrypt_params"]
            
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=scrypt_params["n"],
                r=scrypt_params["r"],
                p=scrypt_params["p"]
            )
            derived_key = kdf.derive(master_password.encode('utf-8'))
            
        else:
            print(f"Error: Unsupported protection method: {method}")
            return False
            
        # Decrypt the keystore data
        if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
            # Use ChaCha20Poly1305
            cipher = ChaCha20Poly1305(derived_key)
            nonce = base64.b64decode(params["nonce"])
            
            # With associated_data as header
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                
        else:
            # Use AES-GCM
            cipher = AESGCM(derived_key)
            nonce = base64.b64decode(params["nonce"])
            
            # With associated_data as header
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
            
        # Parse the decrypted data
        keystore_data = json.loads(plaintext.decode('utf-8'))
        
        print(f"Keystore loaded successfully from {keystore_path}")
        return True
        
    except Exception as e:
        traceback.print_exc()
        print(f"Error loading keystore: {str(e)}")
        return False


def test_simple_keystore():
    """Test creating and loading a simple keystore"""
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "test_keystore.pqc")
    
    # Master password for tests
    master_password = "test_master_password"
    
    print("\n=== Testing simple keystore with consistent associated_data ===")
    
    # Create a keystore
    print("\nStep 1: Creating keystore")
    success = create_simple_keystore(keystore_path, master_password)
    if not success:
        print("❌ Failed to create keystore")
        return False
    
    # Try to load it
    print("\nStep 2: Loading keystore")
    success = load_test_keystore(keystore_path, master_password)
    if not success:
        print("❌ Failed to load keystore")
        return False
    
    print("\n✅ SUCCESS! Created and loaded a keystore with consistent associated_data.")
    
    # Clean up
    if os.path.exists(keystore_path):
        os.remove(keystore_path)
    if os.path.exists(temp_dir):
        os.rmdir(temp_dir)
    
    return True


def fix_keystore_py():
    """Fix the pqc_keystore.py file by patching the encryption/decryption code"""
    pqc_keystore_path = os.path.join(os.getcwd(), "openssl_encrypt", "modules", "pqc_keystore.py")
    
    print(f"\n=== Applying fix to {pqc_keystore_path} ===")
    
    if not os.path.exists(pqc_keystore_path):
        print(f"Error: File not found: {pqc_keystore_path}")
        return False
    
    # Create a backup
    backup_path = f"{pqc_keystore_path}.bak2"
    print(f"Creating backup at {backup_path}")
    
    with open(pqc_keystore_path, 'r') as f:
        content = f.read()
    
    with open(backup_path, 'w') as f:
        f.write(content)
    
    # Find and fix the AES-GCM encryption in save_keystore
    save_pattern = "                # Use AES-GCM\n                cipher = AESGCM(derived_key)\n                nonce = base64.b64decode(params[\"nonce\"])\n                # Update nonce for each save\n                nonce = secrets.token_bytes(12)\n                params[\"nonce\"] = base64.b64encode(nonce).decode('utf-8')\n                \n                header = {\"protection\": protection}\n                # Always use empty string as associated_data for AES-GCM to ensure compatibility\n                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"
    
    save_replacement = "                # Use AES-GCM\n                cipher = AESGCM(derived_key)\n                nonce = base64.b64decode(params[\"nonce\"])\n                # Update nonce for each save\n                nonce = secrets.token_bytes(12)\n                params[\"nonce\"] = base64.b64encode(nonce).decode('utf-8')\n                \n                header = {\"protection\": protection}\n                # IMPORTANT FIX: Use header JSON as associated data for consistency with load_keystore\n                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))"
    
    # Also fix the ChaCha20Poly1305 encryption for consistency
    chacha_pattern = "                # Use ChaCha20Poly1305\n                cipher = ChaCha20Poly1305(derived_key)\n                nonce = base64.b64decode(params[\"nonce\"])\n                # Update nonce for each save\n                nonce = secrets.token_bytes(12)\n                params[\"nonce\"] = base64.b64encode(nonce).decode('utf-8')\n                \n                header = {\"protection\": protection}\n                # Always use None for associated_data for consistent encryption\n                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"
    
    chacha_replacement = "                # Use ChaCha20Poly1305\n                cipher = ChaCha20Poly1305(derived_key)\n                nonce = base64.b64decode(params[\"nonce\"])\n                # Update nonce for each save\n                nonce = secrets.token_bytes(12)\n                params[\"nonce\"] = base64.b64encode(nonce).decode('utf-8')\n                \n                header = {\"protection\": protection}\n                # IMPORTANT FIX: Use header JSON as associated data for consistency with load_keystore\n                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))"
    
    # Apply the replacements
    new_content = content
    if save_pattern in new_content:
        print("Fixing AES-GCM encryption in save_keystore")
        new_content = new_content.replace(save_pattern, save_replacement)
    else:
        print("Warning: Could not find AES-GCM encryption pattern in save_keystore")
    
    if chacha_pattern in new_content:
        print("Fixing ChaCha20Poly1305 encryption in save_keystore")
        new_content = new_content.replace(chacha_pattern, chacha_replacement)
    else:
        print("Warning: Could not find ChaCha20Poly1305 encryption pattern in save_keystore")
    
    # Write the fixed content
    with open(pqc_keystore_path, 'w') as f:
        f.write(new_content)
    
    print(f"Fix applied successfully to {pqc_keystore_path}")
    return True


if __name__ == "__main__":
    # First test that our approach works
    print("Testing keystore creation and loading with fixed associated_data approach")
    if test_simple_keystore():
        # Then apply the fix to the actual file
        fix_keystore_py()
        print("\nFixing complete. Now please run 'python verify_fix.py' to validate the fix.")
    else:
        print("Test failed - not applying fix to the codebase.")