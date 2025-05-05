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

- [ ] Modify `PQCKeystore.add_key` method to accept `file_password` parameter for dual encryption
  - Add an optional parameter to encrypt with both passwords
  - Store encryption flags in key metadata

- [ ] Update `keystore_utils.py` to provide `file_password` when storing keys in `auto_generate_pqc_key`
  - Pass the file password from encryption arguments 
  - Handle optional dual-encryption based on configuration

- [ ] Update `PQCKeystore.get_key` method to accept `file_password` for decryption
  - Modify to support dual-encrypted keys
  - Add parameter for file password

- [ ] Modify `keystore_utils.py`'s `extract_pqc_key` function to pass `file_password` to keystore
  - Update to forward the file password from decryption arguments

- [ ] Update the `crypt_core.py` `decrypt_file` function to pass file password to key extraction
  - Ensure password flows through to keystore operations

- [ ] Implement the dual-encryption mechanism for the private key in `PQCKeystore` class
  - Layer the encryption: file password first, then master password
  - Secure handling of intermediate encrypted data

### Medium Priority

- [ ] Modify key storage format to include flag indicating dual encryption
  - Add metadata field to track encryption method
  - Ensure version compatibility

- [ ] Create key derivation function to convert file password to key encryption key
  - Standardize how file passwords are prepared for key encryption
  - Ensure consistent salt usage

- [ ] Add backwards compatibility for keys stored without dual encryption
  - Detect encryption type during decryption
  - Support legacy keys seamlessly

- [ ] Update CLI arguments to include `--dual-encrypt-key` option
  - Add flag to control dual-encryption behavior
  - Document in help text

- [ ] Write unit tests for the dual-encryption mechanism
  - Test encryption/decryption with both passwords
  - Test handling of invalid passwords
  - Test backward compatibility

### Low Priority

- [ ] Update documentation to explain the dual-encryption security model
  - Explain benefits and usage in docs/keystore-usage.md
  - Update security-notes.md with new model

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