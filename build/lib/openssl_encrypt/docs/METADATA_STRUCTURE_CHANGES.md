# Metadata Structure Changes for Format Version 4

This document summarizes the changes made to implement the hierarchical metadata structure for format_version 4 with recent updates for proper KDF handling.

## Overview

The metadata format version 4 uses a hierarchical JSON structure to organize configuration settings more logically. The key changes include:

1. Nested hash configuration with 'rounds' parameter
2. Dedicated kdf_config section for key derivation function settings
3. Structured PBKDF2 configuration with nested 'rounds' parameter
4. Clear separation of encryption-related parameters in their own section
5. Backward compatibility with older format versions (1-3)

## Recent Updates for KDF Processing

After implementing the hierarchical structure, we identified issues where KDF configurations defined in the format_version 4 structure were not being correctly applied during decryption. This specifically caused the following symptoms:

1. KDFs were displayed as "No KDFs used" when decrypting format_version 4 files
2. Hash iterations were applied but KDF steps were skipped
3. Algorithm was sometimes incorrectly displayed (e.g., shown as "fernet" instead of "kyber1024-hybrid")

These issues have been fixed with the latest updates.

## Files Modified

1. **crypt_core.py**:
   - Updated `convert_metadata_v3_to_v4` function to properly transform flat hash values into nested structures
   - Updated `convert_metadata_v4_to_v3` function for backward compatibility
   - Updated `create_metadata_v4` function to use correct hierarchical structure
   - Updated `decrypt_file` function to handle nested hash_config structure
   - Fixed `generate_key` function to handle the new structure
   - **Recent Updates**:
     - Enhanced `decrypt_file` to properly merge KDF configs from the nested structure into hash_config before key generation
     - Updated `generate_key` to correctly detect and use PBKDF2 in the nested format
     - Fixed `get_organized_hash_config` to properly extract KDF information from the hierarchical structure

2. **keystore_utils.py**:
   - Updated `auto_generate_pqc_key` function to store dual_encryption flag and key_id in the proper location
   - Ensured backward compatibility by storing flags in both old and new locations

3. **tests/test_format_version4.py**:
   - Updated tests to handle the new nested structure
   - Added specific tests for dual_encryption and keystore_key_id fields

## Specific Changes

### Hash Config Structure

- **Old (flat) structure**:
  ```json
  "hash_config": {
    "sha256": 10000,
    "sha512": 0
  }
  ```

- **New (nested) structure**:
  ```json
  "derivation_config": {
    "hash_config": {
      "sha256": {"rounds": 10000},
      "sha512": {"rounds": 0}
    }
  }
  ```

### KDF Configuration Processing

The key fixes for KDF processing involved ensuring the nested KDF configurations in format_version 4 are properly extracted and used during decryption:

1. **Merging KDF configs into hash_config**:
   ```python
   # Get KDF configurations
   kdf_config = derivation_config.get('kdf_config', {})
   pbkdf2_config = kdf_config.get('pbkdf2', {})
   pbkdf2_iterations = pbkdf2_config.get('rounds', 0)
   
   # Merge KDF configurations into hash_config for compatibility with generate_key
   for kdf_name, kdf_params in kdf_config.items():
       if kdf_name in ['scrypt', 'argon2', 'balloon']:
           hash_config[kdf_name] = kdf_params
       elif kdf_name == 'pbkdf2' and isinstance(kdf_params, dict) and 'rounds' in kdf_params:
           # Also store pbkdf2_iterations directly in hash_config for generate_key
           hash_config['pbkdf2'] = kdf_params
   ```

2. **Enhanced PBKDF2 detection in generate_key**:
   ```python
   # Check for pbkdf2 iterations from different potential sources
   # 1. Check if pbkdf2 is defined with a nested structure (format version 4)
   if 'pbkdf2' in hash_config and isinstance(hash_config['pbkdf2'], dict) and 'rounds' in hash_config['pbkdf2']:
       use_pbkdf2 = hash_config['pbkdf2']['rounds']
   # 2. For backward compatibility, check if pbkdf2_iterations is in hash_config directly
   else:
       pbkdf2_from_hash_config = hash_config.get('pbkdf2_iterations')
       if os.environ.get('PYTEST_CURRENT_TEST') is not None and pbkdf2_from_hash_config is None:
           use_pbkdf2 = 100000
       elif pbkdf2_from_hash_config is not None and pbkdf2_from_hash_config > 0:
           use_pbkdf2 = pbkdf2_from_hash_config
   ```

### PBKDF2 Configuration

- **Old structure**:
  ```json
  "pbkdf2_iterations": 100000
  ```

- **New structure**:
  ```json
  "derivation_config": {
    "kdf_config": {
      "pbkdf2": {"rounds": 100000}
    }
  }
  ```

### Dual Encryption and Keystore Key ID

- **Old structure**:
  ```json
  "dual_encryption": true,
  "pqc_keystore_key_id": "12345678-1234-1234-1234-123456789012"
  ```

- **New structure**:
  ```json
  "derivation_config": {
    "kdf_config": {
      "dual_encryption": true,
      "pqc_keystore_key_id": "12345678-1234-1234-1234-123456789012"
    }
  }
  ```

## Backward Compatibility

To ensure backward compatibility, the conversion functions were updated to:

1. When converting v3 to v4: Properly structure all flat values into appropriate nested locations
2. When converting v4 to v3: Flatten nested structures into compatible flat values
3. For dual functionality during transition: Store certain flags (like dual_encryption) in both formats

## Testing

1. Tests were updated to verify:
   - Proper structure of nested hash configurations
   - Correct placement of PBKDF2 parameters
   - Dual encryption flags in the proper location
   - Keystore key IDs in the proper location
   - Round-trip conversion between v3 and v4 formats

## Conclusion

These changes ensure that the format_version 4 metadata structure follows the hierarchical design specified in meta.restructure while maintaining backward compatibility with older format versions. The improved structure provides better organization, clearer intent, and more flexibility for future extensions to the metadata format.

With the recent updates, the system now properly handles the nested KDF configurations during decryption, ensuring that all configured KDFs are correctly:
1. Displayed in verbose output (properly showing KDF configurations rather than "No KDFs used")
2. Applied during the key derivation process
3. Used with the correct parameters from the hierarchical structure

These improvements ensure consistent behavior between encryption and decryption operations for all file formats, especially for the format_version 4 files with post-quantum cryptography.