# Metadata Format Version 5 Specification

## Overview

The format_version 5 builds upon version 4 by introducing configurable data encryption algorithms when using post-quantum key encapsulation mechanisms (KEMs) like Kyber. This allows users to choose which symmetric encryption algorithm is used to encrypt the actual data when using PQC hybrid encryption.

## Key Changes from v4

Version 5 adds the following enhancements:
1. New `encryption_data` field in the `encryption` section that specifies which symmetric algorithm to use for data encryption
2. Support for multiple symmetric encryption algorithms with Kyber and other PQC algorithms

## Format Structure

```json
{
  "format_version": 5,
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
    "encryption_data": "aes-gcm",
    "pqc_public_key": "base64_encoded_public_key",
    "pqc_key_salt": "base64_encoded_key_salt",
    "pqc_private_key": "base64_encoded_private_key",
    "pqc_key_encrypted": true
  }
}
```

## Field Descriptions

### Top-Level Fields

- `format_version`: Always `5` for this version of the format
- `derivation_config`: Contains settings for key derivation (same as v4)
- `hashes`: Contains hash values for data integrity verification (same as v4)
- `encryption`: Contains encryption algorithm and parameters (updated for v5)

### encryption Section (Updated for v5)

- `algorithm`: Encryption algorithm used (e.g., "kyber768", "kyber1024-hybrid")
- `encryption_data`: Symmetric encryption algorithm used for the data portion (new in v5)
  - Valid values include:
    - "aes-gcm" (default)
    - "aes-gcm-siv"
    - "aes-ocb3"
    - "aes-siv"
    - "chacha20-poly1305"
    - "xchacha20-poly1305"
- `pqc_public_key`: Base64-encoded public key for PQC algorithms
- `pqc_key_salt`: Base64-encoded salt used for encrypting the private key
- `pqc_private_key`: Base64-encoded encrypted private key (if stored)
- `pqc_key_encrypted`: Boolean indicating if the private key is encrypted

## Backward Compatibility

Format version 5 maintains backward compatibility with all previous versions:
1. When reading v4 or earlier files, the absence of an `encryption_data` field will default to "aes-gcm"
2. When reading v5 files with software that supports only v4, the implementation will ignore the `encryption_data` field and use AES-GCM

## Dual Encryption Support

For dual-encrypted files, the structure remains the same as in v4, with the addition of the `encryption_data` field:

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

## File Format

The overall file format remains the same as in previous versions:

```
base64(metadata_json):encrypted_data
```

Where:
- `metadata_json` is the JSON-serialized metadata
- `:` is a literal colon separator
- `encrypted_data` is the encrypted binary data