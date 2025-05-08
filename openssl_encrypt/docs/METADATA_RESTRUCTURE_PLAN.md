# Metadata Restructuring Plan (format_version 4)

## Overview

This document outlines the plan for restructuring the metadata format in openssl_encrypt from the current flat structure to a more organized hierarchical structure as defined in `meta.restructure`. The new format will be version 4, while maintaining backward compatibility with versions 1-3.

## Current vs New Structure

### Current Structure (version 3)
```json
{
  "format_version": 3,
  "salt": "base64_encoded_salt",
  "hash_config": { ... },
  "pbkdf2_iterations": 100000,
  "original_hash": "hash_of_original_content",
  "encrypted_hash": "hash_of_encrypted_content",
  "algorithm": "encryption_algorithm",
  "pqc_public_key": "base64_encoded_key",
  "pqc_key_salt": "base64_encoded_salt",
  "pqc_private_key": "base64_encoded_key",
  "pqc_key_encrypted": true
}
```

### New Structure (version 4)
```json
{
  "format_version": 4,
  "derivation_config": {
    "salt": "base64_encoded_salt",
    "hash_config": { ... },
    "kdf_config": {
      "scrypt": { ... },
      "argon2": { ... },
      "balloon": { ... },
      "pbkdf2": { ... }
    }
  },
  "hashes": {
    "original_hash": "hash_of_original_content",
    "encrypted_hash": "hash_of_encrypted_content"
  },
  "encryption": {
    "algorithm": "encryption_algorithm",
    "pqc_public_key": "base64_encoded_key",
    "pqc_key_salt": "base64_encoded_salt",
    "pqc_private_key": "base64_encoded_key",
    "pqc_key_encrypted": true
  }
}
```

## Implementation Plan

### 1. Core Metadata Functions

Create utility functions to:
- Generate new version 4 metadata structure during encryption
- Parse both old and new format versions during decryption
- Convert between formats if needed

### 2. Encryption Function Updates

- Modify the encryption function to use the new hierarchical structure
- Ensure all existing metadata fields are properly placed in the new structure
- Set format_version to 4 for new encryptions

### 3. Decryption Function Updates

- Add format_version 4 handling to the decryption logic
- Create backward compatibility layer that converts older formats to the new structure internally
- Ensure all existing code paths work with both old and new formats

### 4. Dependent Module Updates

Update the following modules to work with the new structure:
- keystore_wrapper.py
- keystore_utils.py
- crypt_utils.py

### 5. Testing

- Test encryption/decryption with new format
- Test backward compatibility with old formats
- Test edge cases and metadata extraction

### 6. Tool Updates

- Update utility tools to handle the new format
- Update debug and analysis tools

## Backward Compatibility Approach

To maintain backward compatibility:

1. During decryption, detect the format_version field
2. For versions 1-3, use existing logic to extract metadata
3. For version 4, use new logic to extract from hierarchical structure
4. After extraction, use a common internal representation

## Key Changes Required

1. **crypt_core.py**:
   - Update metadata creation during encryption
   - Add format_version 4 handling to decryption
   - Add conversion functions between formats

2. **keystore_wrapper.py**:
   - Update metadata handling for keystore integration
   - Ensure compatibility with format_version 4

3. **keystore_utils.py**:
   - Update functions to extract key info from metadata
   - Support both old and new structures

4. **Utility tools**:
   - Update to handle and display hierarchical structure

## Migration Considerations

- No migration needed for existing encrypted files (backward compatibility)
- New encryptions will use format_version 4
- Existing code using the metadata structure needs to be updated to handle the new format

## Timeline

1. Implement core changes in crypt_core.py
2. Update dependent modules
3. Update utility tools
4. Add comprehensive tests
5. Documentation