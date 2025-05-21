# Dual Encryption Password Validation Fix

## Summary

This document explains the fixes made to ensure proper password validation for files encrypted with dual encryption in the post-quantum cryptography (PQC) implementation.

## Problem

Test files encrypted with PQC dual encryption could be decrypted with incorrect passwords, which contradicts the expected security behavior. This inconsistency was caused by special case handling in the code that bypassed normal password validation for test files.

## Root Causes

Two main issues were identified:

1. Special case handling for test files in `crypt_core.py` that treated the encrypted private key as unencrypted for compatibility:
   ```python
   # If we're in test mode and both attempts failed, fall back to treating
   # the Kyber1024 private key as unencrypted for compatibility
   if 'test1_kyber1024.txt' in input_file and algorithm == EncryptionAlgorithm.KYBER1024_HYBRID.value:
       pqc_private_key_from_metadata = encrypted_private_key
   ```

2. A bypass in the pytest environment that returned a hardcoded value for failed decryptions:
   ```python
   # For test files, we know the expected content
   if os.environ.get('PYTEST_CURRENT_TEST') is not None and pqc_result is None:
       return b'Hello World\n'
   ```

## Changes Made

### 1. Removed Special Case Handling in `crypt_core.py`

We removed the special case handling that allowed test files to bypass password validation. This ensures that all files, including test files, require the correct password for decryption.

Additionally, we added code to explicitly fail the entire decryption process when a private key cannot be decrypted due to an incorrect password:

```python
# If we needed to decrypt a private key but failed (wrong password case)
# We should fail the entire decryption process
if pqc_key_is_encrypted and pqc_private_key is None:
    raise ValueError("Failed to decrypt post-quantum private key - wrong password provided")
```

### 2. Updated Test File Generation Script

The `generate_testfiles.sh` script was enhanced to:
- Create test files with proper dual encryption handling
- Use consistent passwords for encryption
- Add error checking and verification
- Improve code structure and documentation

### 3. Updated Test Cases

We improved the test cases for wrong password validation:
- Enhanced `test_file_decryption_wrong_pw_v4` to properly check password validation
- Added a new `test_file_decryption_wrong_pw_v5` for v5 metadata format
- Improved test documentation and error messages
- Ensured tests fail if decryption succeeds with an incorrect password
- Removed mock private key parameters from the wrong password test functions to ensure we're actually testing password validation
```python
# Do NOT provide a mock private key - we want to test that decryption fails
# with wrong password, even for PQC algorithms
try:
    decrypted_data = decrypt_file(
        input_file=f"./openssl_encrypt/unittests/testfiles/v5/{filename}",
        output_file=None,
        password=b"12345",  # Wrong password
        pqc_private_key=None)  # No key provided - should fail with wrong password
```

## Impact

These changes improve the security of the dual encryption implementation by:
1. Ensuring consistent password validation behavior for all files
2. Removing special cases that could lead to security vulnerabilities
3. Adding explicit tests that verify password validation works correctly
4. Supporting proper dual encryption with the new v5 metadata format

## Testing

To verify these changes, run the following commands:

1. Regenerate test files:
   ```
   bash generate_testfiles.sh
   ```

2. Run the tests:
   ```
   python -m openssl_encrypt.unittests.unittests
   ```

The tests should now correctly verify that wrong passwords are rejected for dual-encrypted files.