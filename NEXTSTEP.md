# Next Steps: Kyber Private Key Encryption in Keystore Implementation

## Overview

This document outlines the plan for implementing secure storage and handling of Kyber private keys when using the keystore. The goal is to encrypt the private key using dual encryption (keystore password + file password), store it temporarily in metadata during the encryption process, then extract and store it in the keystore using the key ID, and finally remove it from the metadata before writing the encrypted file to disk.

## Background

Currently, when using PQC Kyber algorithms with a keystore:
1. The public key is stored in the metadata
2. The encrypted private key can be stored in metadata (for self-decryption) or in the keystore
3. When the `pqc_dual_encrypt_key` flag is set to True, we want to enhance this process to ensure the private key is properly stored in the keystore rather than in the file metadata

## Implementation Plan

### 1. Modify crypt_core.py (around line 1759-1784)

The current implementation already has logic for storing the encrypted private key in metadata when the `pqc_dual_encrypt_key` flag is set to True. We need to modify this to:

1. Encrypt the private key using the file password + keystore master password
2. Store this encrypted key in metadata temporarily with a special marker
3. Set a flag in metadata to indicate this key needs to be moved to keystore

```python
# Update the code in crypt_core.py
if pqc_dual_encrypt_key:
    metadata['pqc_dual_encrypt_key'] = True
    metadata['pqc_private_key_store_in_keystore'] = True  # Add this flag
    # Note: The private key is already encrypted in metadata['pqc_private_key']
```

### 2. Modify keystore_utils.py to Extract and Store the Key

Add a new function to extract the private key from metadata and store it in the keystore:

```python
def store_pqc_key_in_keystore(metadata, keystore_path, keystore_password, file_password, key_id=None, quiet=False):
    """
    Extract encrypted private key from metadata and store it in the keystore
    
    Args:
        metadata: The file metadata containing the encrypted key
        keystore_path: Path to the keystore file
        keystore_password: Password for the keystore
        file_password: The file password used for dual encryption
        key_id: Optional existing key ID to update (or create new if None)
        quiet: Whether to suppress output
        
    Returns:
        str: The key ID used to store the key
    """
    # Implementation details here
```

### 3. Modify keystore_cli.py to Support Key Updates

Enhance the PQCKeystore class to support updating an existing key:

```python
def update_key(self, key_id, algorithm=None, public_key=None, private_key=None, 
               description=None, tags=None, dual_encryption=None, file_password=None):
    """
    Update an existing key in the keystore
    
    Args:
        key_id: The key ID to update
        algorithm: New algorithm name (or None to keep existing)
        public_key: New public key (or None to keep existing)
        private_key: New private key (or None to keep existing)
        description: New description (or None to keep existing)
        tags: New tags (or None to keep existing)
        dual_encryption: Whether to use dual encryption
        file_password: File password for dual encryption
        
    Returns:
        bool: True if update was successful
    """
    # Implementation details
```

### 4. Modify the Encryption Process in crypt_core.py

Update the encrypt_file function to call the new store_pqc_key_in_keystore function and then remove the private key from metadata:

```python
# After encryption is complete, process private key storage
if ('pqc_private_key_store_in_keystore' in metadata and metadata['pqc_private_key_store_in_keystore'] and
    'pqc_keystore_key_id' in metadata and 'pqc_private_key' in metadata):
    
    # Extract key ID from metadata
    key_id = metadata['pqc_keystore_key_id']
    
    # Store private key in keystore
    from .keystore_utils import store_pqc_key_in_keystore
    store_pqc_key_in_keystore(
        metadata, 
        args.keystore, 
        keystore_password, 
        args.password, 
        key_id=key_id,
        quiet=getattr(args, 'quiet', False)
    )
    
    # Remove private key from metadata
    del metadata['pqc_private_key']
    del metadata['pqc_private_key_store_in_keystore']
    
    # Keep the dual_encrypt_key flag
    # Keep the key_id for decryption
```

### 5. Update the CLI Interface (crypt_cli.py)

Ensure the CLI properly passes the required parameters:

```python
# Add keystore-related arguments
if args.dual_encrypt_key and args.algorithm.startswith('kyber'):
    # Make sure keystore path is provided
    if not args.keystore:
        print("Error: --keystore parameter is required when using --dual-encrypt-key")
        return 1
        
    # Make sure keystore password is provided or prompted
    keystore_password = get_keystore_password(args)
    if not keystore_password:
        print("Error: Keystore password is required for dual encryption")
        return 1
```

### 6. Update Decryption Process (keystore_utils.py)

Modify the get_pqc_key_for_decryption function to handle the new flow:

```python
# When retrieving key from keystore for decryption
if key_id and key_id != "EMBEDDED_PRIVATE_KEY" and hasattr(args, 'keystore') and args.keystore:
    # Use existing code to get the key from the keystore
    # This already works with dual encryption when the dual_encryption flag is set
```

## Testing Plan

1. Create test cases to verify:
   - Key generation and storage in keystore works correctly
   - Private key is properly removed from metadata
   - Decryption works correctly with the key from keystore
   - Error handling for missing/incorrect passwords

2. Implement a comprehensive test script:
   ```python
   def test_pqc_dual_encrypt_key_storage():
       """Test private key storage in keystore with dual encryption"""
       # Test implementation
   ```

3. Test existing files to ensure backward compatibility is maintained

## Security Considerations

1. **Secure Memory Handling**:
   - Ensure all sensitive key material is handled in secure memory
   - Use `SecureBytes` and `secure_memzero` to clean up after use

2. **Error Handling**:
   - Provide clear error messages without leaking sensitive information
   - Handle missing keystore, incorrect passwords, and key access failures

3. **Auditing**:
   - Add logging for key storage operations (without sensitive data)
   - Track key usage and access attempts

## Implementation Timeline

1. Day 1: Implement core functionality in crypt_core.py and keystore_utils.py
2. Day 2: Implement CLI changes and error handling
3. Day 3: Develop and run comprehensive tests
4. Day 4: Documentation and code review

## Conclusion

This implementation will enhance security by ensuring private keys are properly stored in the keystore rather than in file metadata. By using dual encryption (keystore password + file password), we maintain the strong security model while adding convenience for users who need to access their files across multiple systems.