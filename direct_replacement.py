#!/usr/bin/env python3
"""
Script that replaces specific methods in pqc_keystore.py with working versions
"""

import os
import re
import shutil
import traceback

def apply_direct_replacement():
    """
    Apply direct replacements to the pqc_keystore.py file
    """
    # Paths
    repo_root = os.path.abspath(".")
    target_file = os.path.join(repo_root, 'openssl_encrypt', 'modules', 'pqc_keystore.py')
    backup_file = target_file + '.original'
    
    # Make a backup if it doesn't exist
    if not os.path.exists(backup_file):
        print(f"Creating backup of original file at {backup_file}")
        shutil.copy2(target_file, backup_file)
    
    try:
        # Read the current file
        with open(target_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Define the save_keystore method replacement
        save_keystore_method = '''    def save_keystore(self, master_password: str = None) -> bool:
        """
        Save the keystore to file
        
        Args:
            master_password: Master password for the keystore, if None uses cached master key
            
        Returns:
            bool: True if the keystore was saved successfully
            
        Raises:
            ValidationError: If no keystore data exists
            InternalError: If the keystore cannot be saved
        """
        if self.keystore_data is None:
            raise ValidationError("No keystore data to save")
            
        try:
            # Prepare the data
            self.keystore_data["last_modified"] = datetime.datetime.now().isoformat()
            plaintext = json.dumps(self.keystore_data).encode('utf-8')
            
            # Get encryption parameters
            protection = self.keystore_data["protection"]
            method = protection["method"]
            params = protection["params"]
            
            # Check if we can use the cached master key
            derived_key = None
            if master_password is None:
                if self.master_key is not None and time.time() - self.master_key_time < self.cache_timeout:
                    derived_key = self.master_key
                else:
                    raise ValidationError("Master password required (cached key expired)")
                    
            # If we don't have a cached key, derive it from the password
            if derived_key is None:
                if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
                    if not ARGON2_AVAILABLE:
                        raise ValidationError("Argon2 is required for this keystore but not available")
                        
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
                    salt = base64.b64decode(salt_b64)
                    
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
                    
                elif method == KeystoreProtectionMethod.PBKDF2_AES_GCM.value:
                    # Derive key with PBKDF2
                    salt = base64.b64decode(params["salt"])
                    pbkdf2_params = params["pbkdf2_params"]
                    
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=pbkdf2_params["iterations"]
                    )
                    derived_key = kdf.derive(master_password.encode('utf-8'))
                    
                else:
                    raise ValidationError(f"Unsupported protection method: {method}")
                    
                # Cache the key for future operations
                # Note: Clone the derived key securely
                self.master_key = bytes(derived_key)
                self.master_key_time = time.time()
                
            # Encrypt the keystore data
            if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                # Use ChaCha20Poly1305
                cipher = ChaCha20Poly1305(derived_key)
                nonce = base64.b64decode(params["nonce"])
                # Update nonce for each save
                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode('utf-8')
                
                header = {"protection": protection}
                # Use header as associated_data for consistent encryption
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))
            else:
                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                # Update nonce for each save
                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode('utf-8')
                
                header = {"protection": protection}
                # IMPORTANT: For consistent encryption/decryption, use None as associated_data
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)
                
            # Prepare the final file format
            header_json = json.dumps(header).encode('utf-8')
            header_size = len(header_json)
            
            with open(self.keystore_path, 'wb') as f:
                f.write(header_size.to_bytes(4, byteorder='big'))
                f.write(header_json)
                f.write(ciphertext)
                
            return True
            
        except Exception as e:
            raise InternalError(f"Failed to save keystore: {str(e)}")'''
        
        # Define the load_keystore method replacement
        load_keystore_method = '''    def load_keystore(self, master_password: str) -> bool:
        """
        Load the keystore from file
        
        Args:
            master_password: Master password for the keystore
            
        Returns:
            bool: True if the keystore was loaded successfully
            
        Raises:
            ValidationError: If the keystore file doesn't exist
            AuthenticationError: If the master password is incorrect
            InternalError: If the keystore cannot be loaded
        """
        if self.keystore_path is None:
            raise ValidationError("No keystore path specified")
            
        if not os.path.exists(self.keystore_path):
            raise ValidationError(f"Keystore not found at {self.keystore_path}")
            
        try:
            with open(self.keystore_path, 'rb') as f:
                encrypted_data = f.read()
                
            # Parse the encrypted data
            header_size = int.from_bytes(encrypted_data[:4], byteorder='big')
            header = json.loads(encrypted_data[4:4+header_size].decode('utf-8'))
            ciphertext = encrypted_data[4+header_size:]
            
            # Extract parameters
            protection = header["protection"]
            method = protection["method"]
            params = protection["params"]
            
            # Derive key from master password
            if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
                if not ARGON2_AVAILABLE:
                    raise ValidationError("Argon2 is required for this keystore but not available")
                    
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
                salt = base64.b64decode(salt_b64)
                
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
                
            elif method == KeystoreProtectionMethod.PBKDF2_AES_GCM.value:
                # Derive key with PBKDF2
                salt = base64.b64decode(params["salt"])
                pbkdf2_params = params["pbkdf2_params"]
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=pbkdf2_params["iterations"]
                )
                derived_key = kdf.derive(master_password.encode('utf-8'))
                
            else:
                raise ValidationError(f"Unsupported protection method: {method}")
                
            # Decrypt the keystore data
            if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                # Use ChaCha20Poly1305
                cipher = ChaCha20Poly1305(derived_key)
                nonce = base64.b64decode(params["nonce"])
                
                # Try multiple approaches for robustness - order matters for backward compatibility
                try:
                    # First try with header as associated_data (recommended approach)
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                except Exception as e1:
                    try:
                        # Then try without associated_data (older versions)
                        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
                    except Exception as e2:
                        try:
                            # Finally try with empty string
                            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=b'')
                        except Exception as e3:
                            # Raise the original error
                            raise e1
            else:
                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                
                # For AES-GCM, associated_data must match exactly between encryption and decryption
                # Try multiple approaches for backward compatibility - order matters
                try:
                    # First try without associated_data (matches save_keystore)
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
                except Exception as e1:
                    try:
                        # Then try with header as associated_data
                        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                    except Exception as e2:
                        try:
                            # Finally try with empty string
                            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=b'')
                        except Exception as e3:
                            # Raise the original error
                            raise e1
                
            # Parse the decrypted data
            self.keystore_data = json.loads(plaintext.decode('utf-8'))
            
            # Store the derived key for later use (cached)
            self.master_key = bytes(derived_key)
            self.master_key_time = time.time()
            
            return True
            
        except Exception as e:
            # Clear any cached keys
            self._clear_cached_keys()
            
            if isinstance(e, (KeyError, json.JSONDecodeError)):
                raise InternalError(f"Invalid keystore format: {str(e)}")
            elif "MAC check failed" in str(e) or "Cipher tag does not match" in str(e):
                raise AuthenticationError("Invalid master password or corrupted keystore")
            else:
                raise InternalError(f"Failed to load keystore: {str(e)}")'''
                
        # Use regular expressions to replace the methods
        # Replace save_keystore method
        save_pattern = r'def save_keystore\(self, master_password: str = None\) -> bool:.*?return True\s+\s+except Exception as e:.*?raise InternalError\(f"Failed to save keystore: {str\(e\)}"\)'
        content = re.sub(save_pattern, save_keystore_method, content, flags=re.DOTALL)
        
        # Replace load_keystore method
        load_pattern = r'def load_keystore\(self, master_password: str\) -> bool:.*?return True\s+\s+except Exception as e:.*?raise InternalError\(f"Failed to load keystore: {str\(e\)}"\)'
        content = re.sub(load_pattern, load_keystore_method, content, flags=re.DOTALL)
        
        # Write the updated content back to the file
        with open(target_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("Successfully applied direct replacements to methods")
        return True
        
    except Exception as e:
        print(f"Error applying replacements: {e}")
        traceback.print_exc()
        return False

def run_verify_script():
    """Run the verify_fix.py script to test if the fix worked"""
    import subprocess
    
    print("\nRunning verification script...")
    try:
        result = subprocess.run(["python", "verify_fix.py"], 
                               capture_output=True, text=True, check=False)
        
        print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)
            
        return result.returncode == 0
    except Exception as e:
        print(f"Error running verification script: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if apply_direct_replacement():
        if run_verify_script():
            print("\n✅ SUCCESS! The fix has been applied and verified.")
        else:
            print("\n❌ ERROR: The fix was applied but verification failed.")
    else:
        print("\n❌ ERROR: Failed to apply the fix.")