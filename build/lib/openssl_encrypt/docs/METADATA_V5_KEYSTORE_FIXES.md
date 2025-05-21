# Metadata Version 5 Keystore Integration Fixes

## Overview

This document describes the fixes made to properly support the storage and retrieval of keystore key IDs in the metadata format version 5 that was recently introduced for configurable data encryption with Kyber.

## Issue Description

The recent addition of metadata format version 5 for configurable data encryption algorithms introduced compatibility issues with the keystore functionality. Specifically, the following tests were failing:

- `test_pqc_dual_encryption`
- `test_pqc_dual_encryption_auto_key`
- `test_pqc_dual_encryption_sha3_key`
- `test_pqc_dual_encryption_wrong_password`

The root cause was that several functions in the keystore utilities checked specifically for `format_version == 4` or lower, but did not have equivalent handling for the new format version 5.

## Implemented Fixes

### 1. Updated `extract_key_id_from_metadata` in `keystore_utils.py`

Added explicit support for format_version 5, checking the same hierarchical structure as v4:
- Primarily checking in `derivation_config.kdf_config.pqc_keystore_key_id`
- Fallback check in legacy location `hash_config.pqc_keystore_key_id`

### 2. Updated `get_pqc_key_for_decryption` in `keystore_utils.py`

Added explicit support for format_version 5 when:
- Looking up key IDs in metadata
- Checking for dual encryption flags
- Extracting embedded private keys

### 3. Updated `encrypt_file_with_keystore` in `keystore_wrapper.py`

Modified to ensure key_id and dual_encryption flags are properly stored in format_version 5 metadata.

### 4. Updated `decrypt_file_with_keystore` in `keystore_wrapper.py`

Added explicit support for format_version 5 when:
- Checking for dual encryption flags
- Performing password verification

### 5. Updated `store_pqc_key_in_keystore` in `keystore_utils.py`

Added explicit support for format_version 5 when:
- Extracting encrypted private keys from metadata
- Extracting public keys from metadata
- Updating metadata with key IDs

### 6. Updated `auto_generate_pqc_key` in `keystore_utils.py`

Added explicit support for format_version 5 when:
- Storing key IDs in metadata
- Setting dual encryption flags
- Storing private and public keys

## Testing

All previously failing tests now pass successfully. The following tests were specifically verified:
- `test_pqc_dual_encryption`
- `test_pqc_dual_encryption_auto_key`
- `test_pqc_dual_encryption_sha3_key`
- `test_pqc_dual_encryption_wrong_password`

The full `TestPostQuantumCrypto` test suite now passes without errors. Importantly, the changes maintain backward compatibility with older metadata formats (v3 and v4), ensuring that existing encrypted files can still be decrypted correctly.

## Backward Compatibility

The modifications were carefully implemented to ensure that all existing functionality for v3 and v4 metadata formats continues to work properly. The changes add v5 support without affecting the handling of previous formats. This maintains the library's backward compatibility promises, allowing users to decrypt their existing files seamlessly.

Specifically, we validated that:
1. The extraction of key IDs works for all supported metadata formats
2. Dual encryption functionality works across all metadata versions
3. The existing test suite passes for all supported algorithms and formats