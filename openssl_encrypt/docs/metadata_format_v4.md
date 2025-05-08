# Metadata Format Version 4 Specification

## Overview

The format_version 4 introduces a restructured metadata format that provides better organization and clearer separation of concerns in the encrypted file's metadata. The new structure separates metadata into logical sections:

1. `derivation_config`: Contains settings related to key derivation
2. `hashes`: Contains hash information for integrity verification
3. `encryption`: Contains encryption algorithm and parameters

## Format Structure

```json
{
  "format_version": 4,
  "derivation_config": {
    "salt": "base64_encoded_salt",
    "hash_config": {
      "sha512": {
        "rounds": 10000
      },
      "sha256": {
        "rounds": 10000
      },
      "sha3_256": {
        "rounds": 10000
      },
      "sha3_512": {
        "rounds": 800000
      },
      "blake2b": {
        "rounds": 800000
      },
      "shake256": {
        "rounds": 800000
      },
      "whirlpool": {
        "rounds": 0
      }
    },
    "kdf_config": {
      "scrypt": {
        "enabled": true,
        "n": 128,
        "r": 8,
        "p": 1,
        "rounds": 100
      },
      "argon2": {
        "enabled": true,
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 4,
        "hash_len": 32,
        "type": 2,
        "rounds": 200
      },
      "balloon": {
        "enabled": true,
        "time_cost": 3,
        "space_cost": 65536,
        "parallelism": 4,
        "rounds": 5,
        "hash_len": 32
      },
      "pbkdf2": {
        "rounds": 0
      }
    }
  },
  "hashes": {
    "original_hash": "hash_of_original_content",
    "encrypted_hash": "hash_of_encrypted_content"
  },
  "encryption": {
    "algorithm": "kyber1024-hybrid",
    "pqc_public_key": "base64_encoded_public_key",
    "pqc_key_salt": "base64_encoded_key_salt",
    "pqc_private_key": "base64_encoded_private_key",
    "pqc_key_encrypted": true
  }
}
```

## Field Descriptions

### Top-Level Fields

- `format_version`: Always `4` for this version of the format
- `derivation_config`: Contains settings for key derivation
- `hashes`: Contains hash values for data integrity verification
- `encryption`: Contains encryption algorithm and parameters

### derivation_config Section

- `salt`: Base64-encoded salt used for key derivation
- `hash_config`: Configuration for various hash algorithms
  - Each hash algorithm has a `rounds` parameter
- `kdf_config`: Configuration for key derivation functions
  - `scrypt`: scrypt KDF parameters
  - `argon2`: Argon2 KDF parameters
  - `balloon`: Balloon hashing KDF parameters
  - `pbkdf2`: PBKDF2 iterations

### hashes Section

- `original_hash`: Hash of the original unencrypted content
- `encrypted_hash`: Hash of the encrypted content

### encryption Section

- `algorithm`: Encryption algorithm used (e.g., "aes-gcm", "kyber1024-hybrid")
- `pqc_public_key`: Base64-encoded public key for PQC algorithms
- `pqc_key_salt`: Base64-encoded salt used for encrypting the private key
- `pqc_private_key`: Base64-encoded encrypted private key (if stored)
- `pqc_key_encrypted`: Boolean indicating if the private key is encrypted

## Dual Encryption Support

For dual-encrypted files (those requiring both a keystore password and a file password), the following fields will be present:

```json
"derivation_config": {
  "kdf_config": {
    "dual_encryption": true,
    "pqc_keystore_key_id": "uuid-of-key-in-keystore",
    "pqc_dual_encrypt_verify": "base64_encoded_password_verification_hash",
    "pqc_dual_encrypt_verify_salt": "base64_encoded_password_verification_salt"
  }
}
```

## Backward Compatibility

The library maintains backward compatibility with all previous format versions (1-3). When reading encrypted files:

1. The format_version field is checked to determine the metadata structure
2. For versions 1-3, fields are read from the flat structure
3. For version 4, fields are read from the hierarchical structure

## Conversion Functions

The library provides utility functions to convert between formats:

- `convert_metadata_v3_to_v4`: Converts version 3 metadata to version 4
- `convert_metadata_v4_to_v3`: Converts version 4 metadata to version 3 (for compatibility)

## File Format

The overall file format remains the same as in previous versions:

```
base64(metadata_json):encrypted_data
```

Where:
- `metadata_json` is the JSON-serialized metadata
- `:` is a literal colon separator
- `encrypted_data` is the encrypted binary data