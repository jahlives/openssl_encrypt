# PQC Keystore Dual-Encryption Implementation

This document describes the implementation of the dual-encryption mechanism for the PQC keystore, which adds an additional layer of security by encrypting private keys with both the keystore master password and the individual file password.

## Overview

The dual-encryption enhancement improves security through a defense-in-depth approach:
1. The keystore master password protects access to all stored keys
2. The individual file password provides an additional layer of encryption for each file
3. Both passwords are required to successfully decrypt a file

This implementation follows the TODO.md requirements and ensures backward compatibility with existing keystores.

## Security Model

In standard mode, a file encrypted with a keystore key can be decrypted if:
1. The user has access to the keystore file
2. The user knows the keystore password
3. The user has the file password

In dual encryption mode, a file can be decrypted only if:
1. The user has access to the keystore file
2. The user knows the keystore password
3. The user knows the file password that was used to encrypt that specific file

This creates a stronger security model because even if the keystore file and password are compromised, the attacker would still need the specific file password used during encryption for each individual file.

## Implementation Details

The implementation spans several key components:

### 1. Keystore CLI (`keystore_cli.py`)

#### `PQCKeystore.add_key` Method
- Added parameters for dual encryption: `dual_encryption` and `file_password`
- Implements encryption of the private key with the file password before encrypting with the master password
- Stores dual encryption salt and flag in the key metadata
- Uses a secure random salt (16 bytes) specifically for file password key derivation
- Implements AES-GCM for the additional encryption layer

#### `PQCKeystore.get_key` Method
- Added `file_password` parameter to support dual decryption
- Checks for the `dual_encryption` flag in the key metadata
- Implements decryption with both the master password and file password when dual encryption is enabled
- Throws specific error messages for incorrect file passwords
- Uses secure memory handling to clean up sensitive key material

#### `get_key_from_keystore` Function
- Added `file_password` parameter to properly pass the file password to the `get_key` method
- Provides appropriate error handling for dual encryption errors

### 2. Keystore Wrapper (`keystore_wrapper.py`)

#### `encrypt_file_with_keystore` Function
- Added `dual_encryption` parameter
- Sets the `dual_encryption` flag in the metadata when dual encryption is enabled
- Verifies that the flag is properly stored in the metadata
- Ensures the key ID is correctly stored in the metadata

#### `decrypt_file_with_keystore` Function
- Added `dual_encryption` parameter
- Checks metadata for the `dual_encryption` flag
- Passes the file password to the keystore for dual decryption
- Implements robust error handling for incorrect file passwords
- Properly converts between string and bytes password formats
- Catches and properly identifies dual encryption verification failures

### 3. Keystore Utils (`keystore_utils.py`)

#### `get_pqc_key_for_decryption` Function
- Updated to check for the `dual_encryption` flag in metadata
- Passes the file password to `get_key_from_keystore` when dual encryption is enabled
- Provides detailed error messages for debugging

#### `auto_generate_pqc_key` Function
- Added support for the `dual_encrypt_key` flag
- Properly passes the file password when generating keys with dual encryption
- Sets the dual_encryption flag in hash_config for metadata storage

### 4. CLI Interface (`crypt_cli.py`)

#### Command-line Arguments
- Added `--dual-encrypt-key` flag to enable dual encryption
- Ensures the flag is properly passed to the wrapper functions

#### Encryption Process
- Sets the dual_encryption flag in metadata during encryption
- Ensures the flag is properly stored in the file metadata
- Properly passes the file password to keystore operations

#### Decryption Process
- Extracts and respects the dual_encryption flag from metadata
- Checks for dual encryption during decryption
- Properly handles dual encryption failures with informative error messages

## Test Implementation

We've created several test scripts to verify the dual encryption implementation:

### 1. Basic Test (`tests/dual_encryption/test_dual_encryption_fix.py`)
- Creates a keystore and adds a key with dual encryption
- Encrypts a file using the dual encryption feature
- Verifies that the key ID and dual_encryption flag are properly stored in metadata
- Tests decryption with correct keystore and file passwords
- Tests decryption with incorrect file password (ensures it fails)

### 2. Direct API Test (`direct_keystore_dual_encryption_test.py`)
- Tests dual encryption directly through the API
- Focuses on ensuring the keystore's dual encryption works correctly
- Verifies proper error handling for incorrect passwords
- Checks metadata flag storage and recognition

### 3. CLI Test (`tests/dual_encryption/test_dual_encryption_cli.py`)
- Tests dual encryption through the command-line interface
- Ensures CLI arguments properly enable dual encryption
- Verifies CLI error handling for incorrect passwords

### 4. Comprehensive Test (`tests/dual_encryption/test_dual_encryption_comprehensive.py`)
- Performs end-to-end testing of both API and CLI interfaces
- Verifies metadata handling across different interfaces
- Tests all error cases and edge conditions
- Ensures consistency between direct API and CLI behavior

## Usage

### Using the API

To use dual encryption from the API:

1. When encrypting:
   ```python
   encrypt_file_with_keystore(
       input_file, 
       output_file, 
       file_password,  # Can be string or bytes
       keystore_file=keystore_path,
       keystore_password=keystore_password,
       key_id=key_id,
       dual_encryption=True  # This is the key parameter
   )
   ```

2. When decrypting:
   ```python
   decrypt_file_with_keystore(
       encrypted_file,
       output_file,
       file_password,  # Must match the original file password
       keystore_file=keystore_path,
       keystore_password=keystore_password,
       key_id=key_id,
       dual_encryption=True  # Can be omitted; will be detected from metadata
   )
   ```

### Using the CLI

1. When encrypting:
   ```bash
   python -m openssl_encrypt.crypt encrypt \
     -i input_file.txt \
     -o encrypted_file.enc \
     --algorithm kyber768-hybrid \
     --password "file_password" \
     --keystore keystore.pqc \
     --keystore-password "keystore_password" \
     --key-id "your-key-id" \
     --dual-encrypt-key \
     --force-password
   ```

2. When decrypting:
   ```bash
   python -m openssl_encrypt.crypt decrypt \
     -i encrypted_file.enc \
     -o decrypted_file.txt \
     --password "file_password" \
     --keystore keystore.pqc \
     --keystore-password "keystore_password" \
     --force-password
   ```

The dual encryption flag is automatically detected from the file's metadata during decryption.

## Security Considerations

1. **Password Requirements:** Dual encryption requires both passwords to be correct for successful decryption. This creates a strong two-factor security model.

2. **Salt Management:** Each layer of encryption uses a different random salt to prevent correlation attacks:
   - The keystore master password uses the salt stored in the keystore encryption parameters
   - The file password uses a unique salt generated specifically for that key

3. **Authenticated Encryption:** AES-GCM is used for the file password encryption layer, providing both confidentiality and integrity protection.

4. **Secure Memory Handling:** Sensitive key material is securely erased from memory using `secure_memzero` after use to prevent key disclosure through memory attacks.

5. **Error Handling:** Error messages are carefully designed to provide useful feedback without revealing unnecessary details about the encryption.

6. **Metadata Storage:** The dual encryption flag is stored in metadata, which allows the decryption process to automatically determine whether dual encryption was used.

7. **Key ID Verification:** The key ID is verified during decryption to ensure the correct key is being used.

8. **Private Key Removal:** Private keys are completely removed from metadata before saving encrypted files:
   - Implementation creates a completely new metadata object rather than modifying the existing one
   - Only essential fields are copied to the new metadata object
   - A comprehensive list of fields to exclude is maintained to ensure no sensitive data is inadvertently included
   - This prevents private key exposure through metadata examination

9. **Dual Encryption Flag Consistency:** The implementation checks for multiple flag variants:
   - Both `dual_encryption` and `pqc_dual_encrypt_key` flags are recognized
   - This ensures backward compatibility with various flag naming conventions
   - The system consistently sets a standardized flag regardless of input flag name

## Improved Error Handling

The implementation includes robust error handling for dual encryption:

1. **Incorrect File Password Detection:** 
   - Clearly differentiates between keystore password errors and file password errors
   - Provides specific error messages for dual encryption failures
   - Prevents successful decryption with incorrect file passwords

2. **Multiple Error Types:**
   - Handles both AES-GCM decryption failures and internal keystore errors
   - Catches various error patterns related to password issues

3. **User Feedback:**
   - CLI provides clear feedback when dual encryption is enabled
   - Informs users when a file requires both passwords
   - Gives actionable error messages when decryption fails

4. **Missing Keystore Detection:**
   - Improved error checking for missing or inaccessible keystore files
   - Clear error messages when a keystore is missing but required
   - Prevents silent failure when keystore cannot be accessed

5. **File Password Validation:**
   - Strict validation of file password format (string or bytes)
   - Proper encoding conversion between string and bytes formats
   - Size and format validation before attempting decryption
   - Early detection of invalid password formats

6. **Verbose Mode Support:**
   - Added proper handling of verbose parameter through kwargs
   - Debug information is provided when verbose mode is enabled
   - Helps troubleshoot encryption/decryption issues in development

## Backward Compatibility

The implementation maintains backward compatibility:
- Files encrypted without dual encryption can still be decrypted normally
- The dual encryption feature is only enabled when explicitly requested with the `--dual-encrypt-key` flag
- The keystore format is compatible with existing keystores
- Metadata format remains backward compatible

## Recent Implementation Fixes

The following major improvements have been made to the dual encryption implementation:

1. **Private Key Metadata Cleaning:**
   - Fixed the metadata cleaning process in `keystore_wrapper.py`
   - Implemented a complete metadata reconstruction approach rather than selective deletion
   - Ensures no sensitive key material remains in the metadata after encryption
   - Created a comprehensive list of fields to exclude from clean metadata

2. **Dual Encryption Flag Handling:**
   - Unified dual encryption flag detection by checking for multiple flag names
   - In `keystore_cli.py`, added support for both `dual_encryption` and `from_dual_encrypted_file` flags
   - Standardized flag setting to ensure consistent behavior regardless of input flag name
   - Fixed flag checking during key retrieval operations

3. **Keystore Access Validation:**
   - Added explicit checks for keystore availability during decryption
   - Fixed error handling in `decrypt_file_with_keystore` to properly report missing keystores
   - Implemented proper error propagation from keystore operations to the calling code
   - Added detailed error messages for keystore access issues

4. **File Password Handling:**
   - Improved validation of file password format and type
   - Added proper conversion between string and bytes formats for passwords
   - Fixed encoding issues with Unicode passwords
   - Added robust error handling for password format issues

5. **Verbose Mode Support:**
   - Fixed the verbose parameter handling in `keystore_wrapper.py`
   - Implemented proper kwargs access with default fallback values
   - Added informative debug output when verbose mode is enabled
   - Improved error reporting for debugging purposes

6. **Test Implementation:**
   - Updated `tests/keystore/test_keystore_dual_encryption.py` to properly test dual encryption features
   - Added comprehensive tests for error conditions and edge cases
   - Fixed test cases to properly create and use dual-encrypted keys
   - Added validation of metadata cleaning during tests

## Conclusion

The dual encryption implementation successfully enhances the security of the PQC keystore by requiring both the keystore master password and the individual file password for decryption. This defense-in-depth approach significantly improves the security posture of the system against various types of attacks.

By requiring both passwords to be correct, the implementation ensures that even if the keystore and its master password are compromised, an attacker would still need to know the specific file password used for each encrypted file. This provides a substantial security improvement for sensitive data protection.

The recent fixes have addressed key issues in the implementation, making it more robust, secure, and user-friendly. The improved error handling, metadata cleaning, and flag consistency ensure that the system behaves predictably and securely in all usage scenarios.