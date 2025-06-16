# Metadata Formats - OpenSSL Encrypt

## Table of Contents

1. [Overview](#overview)
2. [Format Evolution](#format-evolution)
3. [Version 4 Specification](#version-4-specification)
4. [Version 5 Specification](#version-5-specification)
5. [Migration Guide](#migration-guide)
6. [Backward Compatibility](#backward-compatibility)
7. [Security Considerations](#security-considerations)
8. [Implementation Notes](#implementation-notes)

## Overview

OpenSSL Encrypt uses structured metadata to store encryption parameters, algorithm information, and security settings within encrypted files. The metadata format has evolved to support new features while maintaining backward compatibility.

### Format Versions

- **Version 3**: Legacy format (deprecated)
- **Version 4**: Restructured metadata with logical sections
- **Version 5**: Configurable data encryption algorithms for PQC (current)

### Metadata Purpose

The metadata serves several critical functions:

1. **Algorithm Identification**: Specifies encryption algorithms and parameters
2. **Key Derivation Configuration**: Stores settings for password-based key derivation
3. **Security Parameters**: Contains hash rounds, KDF settings, and security levels
4. **Version Control**: Enables backward compatibility and migration paths
5. **Integrity Verification**: Includes checksums and validation data

## Format Evolution

### Migration Timeline

```
v3 (Legacy) → v4 (Restructured) → v5 (PQC Enhanced) → v6 (Future)
    ↓              ↓                    ↓
Deprecated    Current Support    Current Default
```

### Key Improvements by Version

| Feature | v3 | v4 | v5 | Notes |
|---------|----|----|----|----|
| **Structured Metadata** | ❌ | ✅ | ✅ | Logical section organization |
| **Hash Configuration** | ❌ | ✅ | ✅ | Per-algorithm round settings |
| **KDF Configuration** | ❌ | ✅ | ✅ | Detailed KDF parameters |
| **PQC Algorithm Support** | ❌ | ✅ | ✅ | Post-quantum encryption |
| **Configurable Data Encryption** | ❌ | ❌ | ✅ | Multiple symmetric algorithms with PQC |
| **Enhanced Security Metadata** | ❌ | ❌ | ✅ | Extended security parameters |

## Version 4 Specification

### Overview

Format version 4 introduces a restructured metadata format with better organization and clearer separation of concerns:

1. **`derivation_config`**: Key derivation settings
2. **`hashes`**: Integrity verification data
3. **`encryption`**: Algorithm and encryption parameters

### Structure

```json
{
  "format_version": 4,
  "derivation_config": {
    "salt": "base64_encoded_salt",
    "hash_config": {
      "sha512": { "rounds": 10000 },
      "sha256": { "rounds": 10000 },
      "sha3_256": { "rounds": 10000 },
      "sha3_512": { "rounds": 800000 },
      "blake2b": { "rounds": 800000 },
      "shake256": { "rounds": 800000 },
      "whirlpool": { "rounds": 0 }
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
        "rounds": 100,
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 4,
        "hash_len": 32,
        "type": "id"
      },
      "balloon": {
        "enabled": true,
        "rounds": 10,
        "space_cost": 1048576,
        "time_cost": 20
      },
      "pbkdf2": {
        "enabled": true,
        "iterations": 100000
      }
    }
  },
  "hashes": {
    "file_hash": "sha256_hash_of_plaintext",
    "metadata_hash": "sha256_hash_of_metadata"
  },
  "encryption": {
    "algorithm": "kyber768-hybrid",
    "kyber_variant": "kyber768",
    "kyber_public_key": "base64_encoded_public_key",
    "kyber_encrypted_key": "base64_encoded_encrypted_symmetric_key",
    "kyber_key_id": "optional_key_identifier"
  }
}
```

### Key Sections

#### derivation_config
Contains all password-based key derivation settings:

- **salt**: Base64-encoded random salt for key derivation
- **hash_config**: Per-algorithm hash round configuration
- **kdf_config**: Detailed KDF parameters for each supported KDF

#### hashes
Integrity verification hashes:

- **file_hash**: SHA-256 hash of the original plaintext
- **metadata_hash**: SHA-256 hash of the metadata for tamper detection

#### encryption
Algorithm-specific encryption parameters:

- **algorithm**: Primary encryption algorithm identifier
- **PQC parameters**: Post-quantum specific settings (when applicable)
- **Key management**: Encrypted keys and identifiers

## Version 5 Specification

### Overview

Format version 5 builds upon version 4 by introducing configurable data encryption algorithms for post-quantum hybrid encryption. This allows users to choose which symmetric encryption algorithm encrypts the actual data when using PQC.

### Key Enhancements

1. **`encryption_data` field**: Specifies symmetric algorithm for data encryption
2. **Algorithm flexibility**: Support for multiple symmetric algorithms with PQC
3. **Enhanced hybrid modes**: More encryption combinations available

### Structure

```json
{
  "format_version": 5,
  "derivation_config": {
    "salt": "base64_encoded_salt",
    "hash_config": {
      "sha512": { "rounds": 10000 },
      "sha256": { "rounds": 10000 },
      "sha3_256": { "rounds": 10000 },
      "sha3_512": { "rounds": 800000 },
      "blake2b": { "rounds": 800000 },
      "shake256": { "rounds": 800000 },
      "whirlpool": { "rounds": 0 }
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
        "rounds": 100,
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 4,
        "hash_len": 32,
        "type": "id"
      },
      "balloon": {
        "enabled": true,
        "rounds": 10,
        "space_cost": 1048576,
        "time_cost": 20
      },
      "pbkdf2": {
        "enabled": true,
        "iterations": 100000
      }
    }
  },
  "hashes": {
    "file_hash": "sha256_hash_of_plaintext",
    "metadata_hash": "sha256_hash_of_metadata"
  },
  "encryption": {
    "algorithm": "ml-kem-768-hybrid",
    "encryption_data": "aes-gcm",
    "pqc_algorithm": "ml-kem-768",
    "pqc_public_key": "base64_encoded_public_key",
    "pqc_encrypted_key": "base64_encoded_encrypted_symmetric_key",
    "pqc_key_id": "optional_key_identifier",
    "hybrid_mode": true
  }
}
```

### New Fields in Version 5

#### encryption_data
Specifies the symmetric encryption algorithm used for data encryption:

- **aes-gcm**: AES-256-GCM (default)
- **aes-gcm-siv**: AES-256-GCM-SIV (nonce-misuse resistant)
- **aes-ocb3**: AES-256-OCB3 (deprecated)
- **aes-siv**: AES-256-SIV (deterministic)
- **chacha20-poly1305**: ChaCha20-Poly1305
- **xchacha20-poly1305**: XChaCha20-Poly1305
- **fernet**: Fernet (AES-128-CBC + HMAC)

#### Enhanced PQC Support
- **pqc_algorithm**: Specific post-quantum algorithm identifier
- **hybrid_mode**: Boolean indicating hybrid encryption usage
- **Algorithm normalization**: Standardized naming (ML-KEM vs legacy Kyber)

### Supported Algorithm Combinations

| PQC Algorithm | Symmetric Options | Example |
|---------------|------------------|---------|
| **ml-kem-512** | aes-gcm, chacha20-poly1305, aes-gcm-siv | `ml-kem-512-hybrid` + `aes-gcm` |
| **ml-kem-768** | aes-gcm, chacha20-poly1305, aes-gcm-siv | `ml-kem-768-hybrid` + `chacha20-poly1305` |
| **ml-kem-1024** | aes-gcm, chacha20-poly1305, aes-gcm-siv | `ml-kem-1024-hybrid` + `aes-gcm-siv` |
| **hqc-128** | aes-gcm, chacha20-poly1305 | `hqc-128-hybrid` + `aes-gcm` |
| **hqc-192** | aes-gcm, chacha20-poly1305 | `hqc-192-hybrid` + `chacha20-poly1305` |
| **hqc-256** | aes-gcm, chacha20-poly1305 | `hqc-256-hybrid` + `aes-gcm` |

## Migration Guide

### Automatic Migration

The library automatically handles migration between format versions during decryption:

```python
# Automatic detection and migration
def decrypt_file(encrypted_file, password):
    metadata = extract_metadata(encrypted_file)

    if metadata['format_version'] == 3:
        return decrypt_v3(encrypted_file, password)
    elif metadata['format_version'] == 4:
        return decrypt_v4(encrypted_file, password)
    elif metadata['format_version'] == 5:
        return decrypt_v5(encrypted_file, password)
    else:
        raise UnsupportedFormatError(f"Unsupported format version: {metadata['format_version']}")
```

### Manual Migration

For proactive migration of files to newer formats:

```bash
# Decrypt with old format, re-encrypt with new format
python -m openssl_encrypt.crypt decrypt -i old_file.enc -o temp_file.txt
python -m openssl_encrypt.crypt encrypt -i temp_file.txt -o new_file.enc --format-version 5
rm temp_file.txt
```

### Batch Migration Script

```bash
#!/bin/bash
# Migrate all encrypted files to format version 5

for file in *.enc; do
    echo "Migrating $file..."

    # Decrypt to temporary file
    python -m openssl_encrypt.crypt decrypt -i "$file" -o "${file%.enc}.tmp"

    # Re-encrypt with v5 format
    python -m openssl_encrypt.crypt encrypt -i "${file%.enc}.tmp" -o "${file%.enc}.v5.enc"

    # Verify new file works
    python -m openssl_encrypt.crypt decrypt -i "${file%.enc}.v5.enc" -o "${file%.enc}.verify"

    if cmp -s "${file%.enc}.tmp" "${file%.enc}.verify"; then
        echo "Migration successful for $file"
        mv "${file%.enc}.v5.enc" "$file"
        rm "${file%.enc}.tmp" "${file%.enc}.verify"
    else
        echo "Migration failed for $file"
        rm "${file%.enc}.v5.enc" "${file%.enc}.tmp" "${file%.enc}.verify"
    fi
done
```

## Backward Compatibility

### Supported Versions

| Format Version | Read Support | Write Support | Notes |
|----------------|--------------|---------------|-------|
| **v3** | ✅ Yes | ❌ No | Legacy support only |
| **v4** | ✅ Yes | ✅ Yes | Full support |
| **v5** | ✅ Yes | ✅ Yes | Current default |

### Compatibility Guarantees

1. **Read Compatibility**: All versions can be decrypted
2. **Algorithm Support**: Legacy algorithms remain supported for decryption
3. **Security Maintenance**: Security patches applied to all supported versions
4. **Deprecation Notice**: 12-month notice before removing support

### Legacy Algorithm Mapping

| Legacy Name | Current Name | Status |
|-------------|--------------|--------|
| `kyber512` | `ml-kem-512` | Deprecated naming |
| `kyber768` | `ml-kem-768` | Deprecated naming |
| `kyber1024` | `ml-kem-1024` | Deprecated naming |
| `aes-cbc` | `fernet` | Functionality equivalent |

## Security Considerations

### Metadata Protection

1. **Integrity Verification**: Metadata hash prevents tampering
2. **No Secret Exposure**: No sensitive data stored in metadata
3. **Version Binding**: Format version prevents downgrade attacks
4. **Algorithm Binding**: Prevents algorithm substitution attacks

### Attack Surface Analysis

#### Potential Vulnerabilities
- **Metadata Tampering**: Mitigated by metadata hash verification
- **Algorithm Downgrade**: Prevented by version validation
- **Parameter Manipulation**: Validated against security minimums
- **Information Leakage**: Metadata designed to reveal minimal information

#### Security Controls
- **Input Validation**: All metadata fields validated during parsing
- **Bounds Checking**: Security parameters checked against minimums
- **Constant-Time Operations**: Metadata comparison uses constant-time algorithms
- **Error Standardization**: Consistent error messages prevent information leakage

### Best Practices

1. **Use Latest Version**: Always use the newest format version for new files
2. **Migrate Regularly**: Update old files to newer formats periodically
3. **Verify Integrity**: Check metadata hashes during decryption
4. **Monitor Deprecation**: Stay informed about format deprecation timelines

## Implementation Notes

### Metadata Parsing

```python
def parse_metadata(metadata_bytes):
    """
    Parse metadata with version-specific handling.
    """
    try:
        metadata = json.loads(metadata_bytes.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise InvalidMetadataError("Failed to parse metadata JSON")

    # Validate format version
    if 'format_version' not in metadata:
        raise InvalidMetadataError("Missing format_version field")

    version = metadata['format_version']
    if version < 3 or version > 5:
        raise UnsupportedFormatError(f"Unsupported format version: {version}")

    # Version-specific validation
    if version >= 4:
        validate_v4_structure(metadata)
    if version >= 5:
        validate_v5_enhancements(metadata)

    return metadata
```

### Metadata Generation

```python
def generate_metadata_v5(encryption_params):
    """
    Generate version 5 metadata structure.
    """
    metadata = {
        "format_version": 5,
        "derivation_config": {
            "salt": base64.b64encode(encryption_params.salt).decode(),
            "hash_config": encryption_params.hash_config,
            "kdf_config": encryption_params.kdf_config
        },
        "hashes": {
            "file_hash": encryption_params.file_hash,
            "metadata_hash": ""  # Calculated after metadata creation
        },
        "encryption": {
            "algorithm": encryption_params.algorithm,
            "encryption_data": encryption_params.symmetric_algorithm,
            "hybrid_mode": encryption_params.is_hybrid
        }
    }

    # Add PQC-specific fields if applicable
    if encryption_params.is_pqc:
        metadata["encryption"].update({
            "pqc_algorithm": encryption_params.pqc_algorithm,
            "pqc_public_key": base64.b64encode(encryption_params.pqc_public_key).decode(),
            "pqc_encrypted_key": base64.b64encode(encryption_params.pqc_encrypted_key).decode(),
            "pqc_key_id": encryption_params.key_id
        })

    # Calculate and add metadata hash
    metadata_json = json.dumps(metadata, sort_keys=True)
    metadata["hashes"]["metadata_hash"] = hashlib.sha256(metadata_json.encode()).hexdigest()

    return metadata
```

### File Format Structure

```
┌─────────────────────────┐
│ Magic Bytes (8B)        │ "OSSL_ENC" format identifier
├─────────────────────────┤
│ Format Version (1B)     │ Format version number
├─────────────────────────┤
│ Metadata Length (4B)    │ Length of metadata section
├─────────────────────────┤
│ Metadata (Variable)     │ JSON metadata structure
├─────────────────────────┤
│ Salt (16-32B)          │ Random salt for key derivation
├─────────────────────────┤
│ IV/Nonce (12-24B)      │ Initialization vector/nonce
├─────────────────────────┤
│ PQC Data (Variable)     │ Post-quantum encrypted keys (if applicable)
├─────────────────────────┤
│ Encrypted Data          │ Ciphertext with authentication tag
├─────────────────────────┤
│ File Hash (32B)         │ SHA-256 hash of entire file
└─────────────────────────┘
```

---

This metadata formats documentation provides comprehensive information about the file format evolution and implementation details. For algorithm-specific information, see the [Algorithm Reference](algorithm-reference.md).

**Last updated**: June 16, 2025
