# PQC Keystore Dual-Encryption Implementation

This document describes the implementation of the dual-encryption mechanism for the PQC keystore, which adds an additional layer of security by encrypting private keys with both the keystore master password and the individual file password.

## Overview

The dual-encryption enhancement improves security through a defense-in-depth approach:
1. The keystore master password protects access to all stored keys
2. The individual file password provides an additional layer of encryption for each file
3. Both passwords are required to successfully decrypt a file

This implementation follows the TODO.md requirements and ensures backward compatibility with existing keystores.

## Implementation Details

The implementation spans several key components:

### 1. Keystore CLI (`keystore_cli.py`)

#### `PQCKeystore.add_key` Method
- Added parameters for dual encryption: `dual_encryption` and `file_password`
- Implements encryption of the private key with the file password before encrypting with the master password
- Stores dual encryption salt and flag in the key metadata

#### `PQCKeystore.get_key` Method
- Added `file_password` parameter to support dual decryption
- Checks for the `dual_encryption` flag in the key metadata
- Implements decryption with both the master password and file password when dual encryption is enabled
- Uses AES-GCM for the additional encryption layer

#### `get_key_from_keystore` Function
- Added `file_password` parameter to properly pass the file password to the `get_key` method

### 2. Keystore Wrapper (`keystore_wrapper.py`)

#### `encrypt_file_with_keystore` Function
- Added `dual_encryption` parameter
- Sets the `dual_encryption` flag in the metadata when dual encryption is enabled
- Verifies that the flag is properly stored in the metadata

#### `decrypt_file_with_keystore` Function
- Added `dual_encryption` parameter
- Checks metadata for the `dual_encryption` flag
- Passes the file password to the keystore for dual decryption

### 3. Keystore Utils (`keystore_utils.py`)

#### `get_pqc_key_for_decryption` Function
- Updated to check for the `dual_encryption` flag in metadata
- Passes the file password to `get_key_from_keystore` when dual encryption is enabled

#### `auto_generate_pqc_key` Function
- Added support for the `dual_encrypt_key` flag
- Properly passes the file password when generating keys with dual encryption

## Test Implementation

The `test_dual_encryption_fix.py` script thoroughly tests the dual encryption implementation:

1. Creates a keystore and adds a key with dual encryption
2. Encrypts a file using the dual encryption feature
3. Verifies that the key ID and dual_encryption flag are properly stored in metadata
4. Tests decryption with correct keystore and file passwords
5. Tests decryption with incorrect file password (ensures it fails)

## Usage

To use dual encryption:

1. When encrypting:
   ```python
   encrypt_file_with_keystore(
       input_file, 
       output_file, 
       file_password,
       keystore_file=keystore_path,
       keystore_password=keystore_password,
       key_id=key_id,
       dual_encryption=True
   )
   ```

2. When decrypting:
   ```python
   decrypt_file_with_keystore(
       encrypted_file,
       output_file,
       file_password,
       keystore_file=keystore_path,
       keystore_password=keystore_password,
       key_id=key_id,
       dual_encryption=True
   )
   ```

## Security Considerations

1. Dual encryption requires both passwords to be correct for successful decryption
2. Each layer of encryption uses a different salt to prevent correlation attacks
3. AES-GCM is used for the file password encryption layer, providing authenticated encryption
4. Keys are securely erased from memory using `secure_memzero` after use
5. The dual encryption flag is stored in metadata for backward compatibility

## Backward Compatibility

The implementation maintains backward compatibility:
- Files encrypted without dual encryption can still be decrypted
- The dual encryption feature is only enabled when explicitly requested
- The keystore format is compatible with existing keystores

## Conclusion

The dual encryption implementation successfully enhances the security of the PQC keystore by requiring both the keystore master password and the individual file password for decryption. This defense-in-depth approach significantly improves the security posture of the system against various types of attacks.