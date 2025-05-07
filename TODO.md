# PQC Keystore Dual-Encryption Enhancement

## Overview
This enhancement adds a dual-encryption mechanism for PQC private keys stored in keystores. 
Currently, private keys in keystores are encrypted only with the keystore password, creating 
a security risk: if someone obtains the keystore password, they can decrypt any file encrypted 
with those keys without needing the individual file passwords.

The enhancement will encrypt private keys with both:
1. The keystore master password (as currently implemented)
2. The individual file password used during encryption

This creates a proper defense-in-depth design where both passwords are required for decryption.

## Implementation Tasks

### High Priority

- [x] Modify `PQCKeystore.add_key` method to accept `file_password` parameter for dual encryption
  - [x] Add an optional parameter to encrypt with both passwords
  - [x] Store encryption flags in key metadata

- [x] Update `keystore_utils.py` to provide `file_password` when storing keys in `auto_generate_pqc_key`
  - [x] Pass the file password from encryption arguments 
  - [x] Handle optional dual-encryption based on configuration

- [x] Update `PQCKeystore.get_key` method to accept `file_password` for decryption
  - [x] Modify to support dual-encrypted keys
  - [x] Add parameter for file password

- [x] Modify `keystore_utils.py`'s `extract_pqc_key` function to pass `file_password` to keystore
  - [x] Update to forward the file password from decryption arguments

- [x] Update the `crypt_core.py` `decrypt_file` function to pass file password to key extraction
  - [x] Ensure password flows through to keystore operations

- [x] Implement the dual-encryption mechanism for the private key in `PQCKeystore` class
  - [x] Layer the encryption: file password first, then master password
  - [x] Secure handling of intermediate encrypted data

### Medium Priority

- [x] Modify key storage format to include flag indicating dual encryption
  - [x] Add metadata field to track encryption method
  - [x] Ensure version compatibility

- [x] Create key derivation function to convert file password to key encryption key
  - [x] Standardize how file passwords are prepared for key encryption
  - [x] Ensure consistent salt usage

- [x] Add backwards compatibility for keys stored without dual encryption
  - [x] Detect encryption type during decryption
  - [x] Support legacy keys seamlessly

- [x] Update CLI arguments to include `--dual-encrypt-key` option
  - [x] Add flag to control dual-encryption behavior
  - [x] Document in help text

- [x] Write unit tests for the dual-encryption mechanism
  - [x] Test encryption/decryption with both passwords
  - [x] Test handling of invalid passwords
  - [x] Test backward compatibility

### Low Priority

- [x] Update documentation to explain the dual-encryption security model
  - [x] Explain benefits and usage in docs/keystore-usage.md
  - [x] Update security-notes.md with new model

## Implementation Notes

1. For the encryption mechanism:
   - Use a layered approach: encrypt with file password first, then with keystore password
   - This ensures you need both passwords to decrypt
   - Store the salt used for the file password derivation in the key metadata

2. For backward compatibility:
   - Check for the dual-encryption flag during decryption
   - If not present, use the current single-password approach
   - If present, apply both decryption steps

3. Security considerations:
   - Ensure secure handling of keys in memory
   - Use unique salts for each encryption operation
   - Clean up sensitive data promptly using secure_memzero