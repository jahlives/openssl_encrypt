# PQC Keystore Dual-Encryption Enhancement

This document describes the implementation of the Dual-Encryption feature for PQC keystore private keys.

## Overview

The Dual-Encryption enhancement improves security by requiring two passwords to decrypt a file:
1. The keystore master password
2. The individual file password used during encryption

This provides defense-in-depth protection for encrypted files, ensuring that even if an attacker has the keystore password, they cannot decrypt the file without also knowing the file-specific password.

## Implementation Details

The implementation involves several key components:

### 1. Key Derivation and Capture

During encryption, the file password is used to derive a cryptographic key using PBKDF2 or Argon2. This derived key is captured in the encryption process and passed to the keystore for dual encryption.

The main modification is in `keystore_wrapper.py`, where we:
* Temporarily hook into the `generate_key` function to capture the derived file key
* Pass this key to the keystore when adding or updating a PQC key

```python
# When using dual encryption, we need to capture the derived key
derived_file_key = None

# We'll use a function replacement to capture the key
def wrapper_generate_key(*args, **kwargs):
    nonlocal derived_file_key
    result = original_generate_key(*args, **kwargs)
    # The first item in the result tuple is the derived key
    derived_file_key = result[0]
    return result

# Replace the original function temporarily
if dual_encrypt_key and key_id is not None:
    import openssl_encrypt.modules.crypt_core as crypt_core
    crypt_core.generate_key = wrapper_generate_key
```

### 2. Dual Encryption in PQCKeystore

The `PQCKeystore.add_key` method was enhanced to support dual encryption of private keys:

```python
# If dual encryption is enabled and a file key is provided, encrypt with it first
if dual_encryption and file_key:
    # Use AES-GCM to encrypt the private key with the file key
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # Generate a nonce for AES-GCM
    nonce = os.urandom(12)
    
    # Create the cipher with the file key
    cipher = AESGCM(file_key)
    
    # Encrypt the private key
    ciphertext = cipher.encrypt(nonce, private_key, None)
    
    # Combine the nonce and ciphertext
    private_key_to_encrypt = nonce + ciphertext
```

### 3. Dual Decryption

When decrypting a file, the `PQCKeystore.get_key` method was enhanced to handle dual-encrypted keys:

```python
# Check if this is a dual-encrypted key and we have a file key
dual_encryption = key_data.get("dual_encryption", False)
if dual_encryption and file_key:
    # Import necessary AEAD cipher for decryption
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # Split the private key into nonce and ciphertext
    # Nonce is the first 12 bytes
    nonce = private_key[:12]
    ciphertext = private_key[12:]
    
    # Create the cipher with the file key
    cipher = AESGCM(file_key)
    
    # Decrypt the private key
    decrypted_private_key = cipher.decrypt(nonce, ciphertext, None)
    private_key = decrypted_private_key
```

### 4. File Key Derivation During Decryption

Similar to encryption, during decryption we need to derive the file key from the file password and pass it to the keystore for dual decryption.

The key derivation is done using the same mechanism as during encryption, ensuring that the same key is derived if the same password is provided.

## Security Aspects

This enhancement provides several security benefits:

1. **Defense in Depth**: An attacker needs both the keystore password and the file password to decrypt a file.
2. **Separation of Concerns**: The keystore password protects all keys, while individual file passwords protect specific files.
3. **Brute Force Resistance**: Even if an attacker has the keystore password, they still need to brute force the file password, which is computationally expensive due to PBKDF2/Argon2.

## Testing

A comprehensive test script `tests/keystore/test_keystore_dual_encryption.py` has been created to verify the implementation:

```
python -m tests.keystore.test_keystore_dual_encryption --dual --wrong-password
```

The test script verifies that:
1. Files can be encrypted and decrypted with the correct password
2. Files encrypted with dual encryption CANNOT be decrypted with an incorrect password

## Backward Compatibility

The implementation maintains backward compatibility with existing keystores and files. The dual encryption feature is only enabled when specifically requested.

## Future Improvements

Possible future enhancements include:
1. Adding a command-line flag to enable/disable dual encryption
2. Adding the ability to upgrade existing keys to dual encryption
3. Adding a separate password for each key in the keystore