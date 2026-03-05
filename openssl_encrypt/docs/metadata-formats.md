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
- **Version 5**: Configurable data encryption algorithms for PQC
- **Version 6**: Reserved for future use
- **Version 7**: Secure chained salt derivation (v1.3.4 branch - identical to v9)
- **Version 8**: Multi-round KDF support (deprecated - security vulnerability)
- **Version 9**: Secure chained salt derivation for multi-round KDFs (v1.4.0+ default)
- **Version 10-11**: Independent XOR key composition mode
- **Version 12**: Streaming chunked encryption for large files (v1.4.0+)

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
v3 (Legacy) → v4 (Restructured) → v5 (PQC Enhanced) → v7/v9 (Secure Chained Salt)
    ↓              ↓                    ↓                      ↓
Deprecated    Supported          Supported              Supported
                                                         (v7: v1.3.4, v9: v1.4.0+)

v10-11 (Independent XOR) → v12 (Streaming Chunked + Reduced Algorithms)
                                    ↓
                              Current Default (v1.4.0+)

v8 (Multi-round KDF) - Deprecated immediately due to security vulnerability
```

### Key Improvements by Version

| Feature | v3 | v4 | v5 | v7 | v8 | v9 | v10-11 | v12 | Notes |
|---------|----|----|----|----|----|----|--------|-----|-------|
| **Structured Metadata** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Logical section organization |
| **Hash Configuration** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Per-algorithm round settings |
| **KDF Configuration** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Detailed KDF parameters |
| **PQC Algorithm Support** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Post-quantum encryption |
| **Configurable Data Encryption** | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Multiple symmetric algorithms with PQC |
| **Enhanced Security Metadata** | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Extended security parameters |
| **Multi-round KDF Support** | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | Multiple KDF rounds for increased security |
| **Secure Chained Salt Derivation** | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | **CRITICAL SECURITY FIX** - v7 and v9 are cryptographically identical |
| **Independent XOR Key Composition** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | XOR-based key composition mode |
| **Streaming Chunked Encryption** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | Per-chunk AEAD for large files with constant memory |

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

## Version 9 Specification

### Overview

**⚠️ SECURITY CRITICAL UPDATE**

Format version 9 addresses a critical security vulnerability discovered in version 8's multi-round KDF salt derivation. Version 8 and below used predictable salt derivation that allowed attackers to precompute all round salts, enabling optimized rainbow table attacks.

### Security Vulnerability (v8 and below)

In format versions ≤8, multi-round KDF salt derivation was predictable:

```python
# INSECURE (v8 and below)
for round_num in range(kdf_rounds):
    if round_num == 0:
        round_salt = base_salt  # From metadata
    else:
        # VULNERABLE: Predictable derivation
        round_salt = SHA256(base_salt + str(round_num).encode()).digest()[:16]

    password = kdf(password, round_salt)
```

**Attack Vector**: Since `base_salt` is stored in plaintext metadata, attackers can:
1. Extract `base_salt` from encrypted file
2. Precompute all round salts: `salt_1 = SHA256(base_salt + "1")`, `salt_2 = SHA256(base_salt + "2")`, etc.
3. Build optimized rainbow tables for each round
4. Significantly reduce security of multi-round KDFs

### Security Fix (v9)

Version 9 introduces **chained salt derivation** that forces sequential computation:

```python
# SECURE (v9)
for round_num in range(kdf_rounds):
    if round_num == 0:
        round_salt = base_salt  # From metadata
    else:
        # SECURE: Use previous round's output as next round's salt
        round_salt = previous_output[:16]

    current_output = kdf(previous_output, round_salt)
    previous_output = current_output
```

**Security Properties**:
- **Sequential Dependency**: Each round depends on the previous round's output
- **Precomputation Impossible**: Cannot compute round N salt without computing rounds 0 through N-1
- **Perfect Forward Security**: Compromise of one round doesn't compromise previous rounds
- **Increased Cost**: Attackers must complete all rounds sequentially for each password guess

### Structure

Version 9 uses the same metadata structure as version 5, with only the salt derivation behavior changed:

```json
{
  "format_version": 9,
  "derivation_config": {
    "salt": "base64_encoded_salt",
    "hash_config": {
      "blake3": { "rounds": 2 },
      "blake2b": { "rounds": 2 },
      "shake256": { "rounds": 2 }
    },
    "kdf_config": {
      "argon2": {
        "enabled": true,
        "rounds": 3,
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 4,
        "hash_len": 32,
        "type": "id"
      },
      "pbkdf2": {
        "rounds": 3,
        "iterations": 100000
      },
      "scrypt": {
        "enabled": true,
        "rounds": 2,
        "n": 16384,
        "r": 8,
        "p": 1
      }
    }
  },
  "hashes": {
    "file_hash": "sha256_hash_of_plaintext",
    "metadata_hash": "sha256_hash_of_metadata"
  },
  "encryption": {
    "algorithm": "aes-gcm",
    "encryption_data": "aes-gcm"
  }
}
```

### Affected Components

The chained salt derivation applies to all multi-round operations in v9:

#### Key Derivation Functions (KDFs)
- **Argon2** (Argon2id, Argon2i, Argon2d) - lines 2106-2147 in crypt_core.py
- **Balloon** - lines 2215-2259
- **Scrypt** - lines 2311-2356
- **HKDF** - lines 2426-2453
- **PBKDF2** - lines 2577-2600 and 2733-2746

#### Hash Functions
- **BLAKE3** - lines 1620-1636
- **BLAKE2b** - lines 1596-1609
- **SHAKE-256** - lines 1662-1680

### Implementation Pattern

All affected functions follow this pattern:

```python
def multi_round_kdf(password, base_salt, rounds, format_version):
    """Multi-round KDF with version-aware salt derivation."""
    current_password = password

    for i in range(rounds):
        # Version-aware salt derivation
        if format_version >= 9:
            # V9+ secure chained salt derivation
            if i == 0:
                round_salt = base_salt
            else:
                # Chained: use previous output as salt
                round_salt = current_password[:16]
        else:
            # Legacy: predictable derivation (v8 and below)
            if i == 0:
                round_salt = base_salt
            else:
                round_salt = hashlib.sha256(
                    base_salt + str(i).encode()
                ).digest()[:16]

        # Apply KDF
        current_password = kdf(current_password, round_salt)

    return current_password
```

### Backward Compatibility

Version 9 maintains full backward compatibility:

- **Decryption**: v8 and below files decrypt correctly using legacy salt derivation
- **Encryption**: New files automatically use v9 with secure chained salt
- **Detection**: Format version in metadata determines which method to use
- **Migration**: Re-encryption recommended but not required

### Performance Impact

The security fix has minimal performance impact:

- **Computation**: Same number of KDF rounds executed
- **Memory**: No additional memory required
- **Latency**: Salt extraction from previous output is O(1)
- **Overhead**: ~0.01% performance difference (within measurement noise)

### Security Analysis

#### Attack Complexity Comparison

| Metric | v8 (Vulnerable) | v9 (Secure) | Improvement |
|--------|----------------|-------------|-------------|
| **Salt Precomputation** | ✅ Possible | ❌ Impossible | ∞ |
| **Parallel Attack** | ✅ Possible | ❌ Impossible | ∞ |
| **Rainbow Tables** | ✅ Optimized | ❌ Sequential only | 100x-1000x |
| **Round Independence** | ✅ Independent | ❌ Dependent chain | N/A |

#### Security Level Increase

For a 3-round KDF configuration:
- **v8**: Attacker can precompute all salts, then parallelize password guessing
- **v9**: Attacker must compute all 3 rounds sequentially for each password guess
- **Result**: **Effective security increases by factor of KDF rounds**

### Migration Recommendations

#### Immediate Actions
1. **New Encryptions**: Automatically use v9 (no action required)
2. **High-Value Data**: Re-encrypt files containing sensitive data
3. **Multi-Round Configs**: Especially important for files using multiple KDF rounds

#### Re-encryption Example

```bash
# Re-encrypt a v8 file to v9
python -m openssl_encrypt.crypt decrypt -i sensitive_v8.enc -o temp.txt
python -m openssl_encrypt.crypt encrypt -i temp.txt -o sensitive_v9.enc
shred -u temp.txt

# Verify format version
python -m openssl_encrypt.crypt info -i sensitive_v9.enc
# Should show: "format_version": 9
```

#### Risk Assessment

Files at highest risk:
- **Multi-round KDF** (rounds > 1): CRITICAL - Directly affected by vulnerability
- **Short passwords**: HIGH - Rainbow tables more effective
- **Public metadata**: HIGH - Attackers can extract base_salt
- **Long-term storage**: MEDIUM - More time for offline attacks

Files at lower risk:
- **Single-round KDF** (rounds = 1): LOW - No salt derivation occurs
- **Strong passwords** (>20 chars, high entropy): MEDIUM - Rainbow tables less effective
- **Additional encryption layers**: MEDIUM - Defense in depth reduces risk

## Version 7 and 9 Equivalence

### Overview

Format versions 7 and 9 are **cryptographically identical** and implement the same security fix for the salt derivation vulnerability (CVE-330). The version number difference exists due to parallel development:

- **Version 7**: Introduced in v1.3.4 (releases/1.3.4 branch) - Focus on asymmetric encryption and PQC
- **Version 9**: Introduced in v1.4.0 (feature/v1.4.0-development branch) - Multi-feature release

### Implementation Unity

Both v7 and v9 use identical secure chained salt derivation:

```python
# Both v7 and v9 use this pattern:
if format_version >= 7 and format_version != 8:
    # Secure chained salt derivation
    round_salt = previous_output[:16]
else:
    # Legacy predictable derivation (v1-6, v8)
    round_salt = hashlib.sha256(base_salt + str(round_num).encode()).digest()[:16]
```

### Key Properties

1. **Cryptographic Equivalence**: v7 and v9 produce identical keys for the same inputs
2. **Security Level**: Both provide the same security improvements over v8 and below
3. **Interoperability**: Files encrypted with v7 decrypt correctly in v1.4.0+
4. **v8 Exception**: v8 deliberately excluded from secure derivation for backward compatibility

### Version Selection

- **v1.3.4 (releases/1.3.4)**: Creates v7 files
- **v1.4.0+ (feature/v1.4.0-development)**: Creates v9 files by default
- **Both versions**: Can decrypt v7, v8, and v9 files correctly

### Why v8 is Different

Version 8 remains vulnerable to maintain backward compatibility for existing v8 files. Files encrypted with v8 can still be decrypted, but new encryptions use v7 (in v1.3.4) or v9 (in v1.4.0+).

**Important**: The check `format_version != 8` ensures v8 continues to use predictable salt derivation for decryption, while v7 and v9 both use secure chained derivation.

## Version 12 Specification

### Overview

Format version 12 introduces **streaming chunked encryption** for large files, enabling encryption and decryption with constant memory usage regardless of file size. Files above a configurable threshold (default: 10 MB) are automatically split into independently authenticated chunks, each encrypted with its own AEAD nonce derived via HKDF.

### Key Enhancements

1. **Per-chunk AEAD**: Each chunk is independently encrypted with a unique nonce, preventing nonce reuse
2. **HKDF nonce derivation**: Deterministic per-chunk nonces derived via HKDF-SHA256 from a random prefix
3. **Trailer HMAC**: HMAC-SHA256 commitment over all chunk authentication tags for global integrity
4. **Auto-threshold**: Files above 10 MB automatically use streaming mode (configurable)
5. **Constant memory**: ~2-3 MB memory usage regardless of file size

### Metadata Structure

Version 12 extends the metadata with a `streaming` section:

```json
{
  "format_version": 12,
  "derivation_config": {
    "salt": "base64_encoded_salt",
    "hash_config": {
      "blake3": { "rounds": 2 },
      "blake2b": { "rounds": 2 },
      "shake256": { "rounds": 2 }
    },
    "kdf_config": {
      "argon2": {
        "enabled": true,
        "rounds": 3,
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 4,
        "hash_len": 32,
        "type": "id"
      },
      "scrypt": {
        "enabled": true,
        "rounds": 2,
        "n": 16384,
        "r": 8,
        "p": 1
      }
    }
  },
  "hashes": {
    "original_hash": "sha256_hex_hash_of_plaintext"
  },
  "encryption": {
    "algorithm": "aes-gcm",
    "cascade": false
  },
  "streaming": {
    "enabled": true,
    "chunk_size": 1048576,
    "chunk_count": 10,
    "nonce_prefix": "base64_encoded_8_bytes"
  }
}
```

#### Streaming Fields

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | boolean | Always `true` for streaming files |
| `chunk_size` | integer | Plaintext chunk size in bytes (default: 1,048,576 = 1 MB) |
| `chunk_count` | integer | Total number of chunks in the file |
| `nonce_prefix` | string | Base64-encoded 8-byte random prefix for HKDF nonce derivation |

### File Format

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Base64(JSON metadata)                                                    │
├──────────────────────────────────────────────────────────────────────────┤
│ : (colon separator, 1 byte)                                              │
├──────────────────────────────────────────────────────────────────────────┤
│ OESC (magic bytes, 4 bytes)                                              │
├──────────────────────────────────────────────────────────────────────────┤
│ Payload Version (u32le = 1)                                              │
├──────────────────────────────────────────────────────────────────────────┤
│ Chunk 0: [chunk_index:u32le] [ciphertext_len:u32le] [ciphertext + tag]   │
├──────────────────────────────────────────────────────────────────────────┤
│ Chunk 1: [chunk_index:u32le] [ciphertext_len:u32le] [ciphertext + tag]   │
├──────────────────────────────────────────────────────────────────────────┤
│ ...                                                                      │
├──────────────────────────────────────────────────────────────────────────┤
│ Chunk N-1: [chunk_index:u32le] [ciphertext_len:u32le] [ciphertext + tag] │
├──────────────────────────────────────────────────────────────────────────┤
│ Chunk Count (u32le, 4 bytes)                                             │
├──────────────────────────────────────────────────────────────────────────┤
│ Trailer HMAC (HMAC-SHA256, 32 bytes)                                     │
└──────────────────────────────────────────────────────────────────────────┘
```

### Per-Chunk Structure

Each chunk is serialized as:

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| `chunk_index` | 4 bytes | u32le | Zero-based chunk index |
| `ciphertext_len` | 4 bytes | u32le | Length of ciphertext + AEAD tag |
| `ciphertext + tag` | Variable | Raw bytes | AEAD-encrypted plaintext with appended authentication tag |

### Nonce Derivation

Per-chunk nonces are derived deterministically using HKDF-SHA256:

```python
info = b"oesc-chunk-nonce:" + struct.pack(">I", chunk_index)
ikm  = nonce_prefix + struct.pack(">I", chunk_index)

nonce = HKDF(
    algorithm=SHA256(),
    length=nonce_size,    # 12 bytes for AES-GCM/ChaCha20
    salt=nonce_prefix,    # 8 random bytes from metadata
    info=info
).derive(ikm)
```

**Security properties:**
- Unique nonce per chunk (different `chunk_index`)
- Unique nonces across files (different random `nonce_prefix`)
- Deterministic (enables decryption without storing nonces)

### AAD Construction

Each chunk's Additional Authenticated Data binds it to its position and the file metadata:

```
AAD = metadata_b64 + b":" + pack(">I", chunk_index) + b":" + pack(">I", chunk_count)
```

This prevents:
- **Metadata tampering**: Full metadata is authenticated per-chunk
- **Chunk reordering**: `chunk_index` is bound in AAD
- **Chunk truncation**: `chunk_count` is bound in AAD

### Trailer HMAC

A global HMAC-SHA256 commitment is computed over all chunk authentication tags:

```python
hmac_key = SHA256(encryption_key + b"oesc-trailer-hmac")
tag_material = concatenation of last 16 bytes of each chunk's ciphertext
trailer_hmac = HMAC-SHA256(hmac_key, tag_material)
```

The trailer HMAC provides a second layer of integrity beyond per-chunk AEAD, ensuring that no chunks have been modified, reordered, or removed.

### Supported Algorithms

Streaming chunked encryption requires AEAD algorithms. Supported ciphers:

| Algorithm | Nonce Size | Notes |
|-----------|-----------|-------|
| `aes-gcm` | 12 bytes | Industry standard, hardware-accelerated |
| `chacha20-poly1305` | 12 bytes | Software-optimized |
| `xchacha20-poly1305` | 12 bytes | Extended nonce variant |
| `aes-gcm-siv` | 12 bytes | Nonce-misuse resistant |
| `aes-siv` | 16 bytes | Deterministic AEAD |
| `threefish-512` | 32 bytes | Wide-block cipher |
| `threefish-1024` | 64 bytes | Wide-block cipher |
| `cascade` | Varies | Multi-algorithm cascade |

**Not supported**: `fernet` (no AEAD), PQC hybrid algorithms (use one-shot encryption).

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `STREAMING_MAGIC` | `b"OESC"` | 4-byte magic identifier |
| `PAYLOAD_VERSION` | `1` | Payload format version (u32le) |
| `DEFAULT_CHUNK_SIZE` | 1,048,576 (1 MB) | Default plaintext chunk size |
| `DEFAULT_STREAMING_THRESHOLD` | 10,485,760 (10 MB) | File size threshold for auto-activation |
| Trailer size | 36 bytes | 4 bytes (chunk count) + 32 bytes (HMAC) |

### Backward Compatibility

- **v12 files without streaming**: When the file is below the streaming threshold or uses a non-AEAD algorithm, v12 uses one-shot encryption identical to v9 (no `streaming` section in metadata)
- **Older versions**: Cannot decrypt v12 streaming files; must upgrade to v1.4.0+ or v1.5.0+
- **Non-streaming v12**: Older versions that support the algorithm set can decrypt non-streaming v12 files if format version checking allows it

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
| **v5** | ✅ Yes | ✅ Yes | Full support |
| **v6** | ✅ Yes | ✅ Yes | Full support |
| **v7** | ✅ Yes | ✅ Yes | **Secure chained salt** - v1.3.4 branch (cryptographically identical to v9) |
| **v8** | ✅ Yes | ❌ No | **Deprecated - Security vulnerability** |
| **v9** | ✅ Yes | ✅ Yes | **v1.4.0 default** - Secure chained salt derivation |
| **v10-11** | ✅ Yes | ✅ Yes | Independent XOR key composition mode |
| **v12** | ✅ Yes | ✅ Yes | **Current default (v1.4.0+)** - Streaming chunked encryption |

### Compatibility Guarantees

1. **Read Compatibility**: All versions can be decrypted
2. **Algorithm Support**: Legacy algorithms remain supported for decryption
3. **Security Maintenance**: Security patches applied to all supported versions
4. **Deprecation Notice**: 12-month notice before removing support
5. **v8 Security Exception**: v8 deprecated immediately due to security vulnerability (no 12-month notice)

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
    if version < 3 or version > 9:
        raise UnsupportedFormatError(f"Unsupported format version: {version}")

    # Check for deprecated v8
    if version == 8:
        import warnings
        warnings.warn(
            "Format version 8 is deprecated due to security vulnerability. "
            "Consider re-encrypting with version 9.",
            DeprecationWarning
        )

    # Version-specific validation
    if version >= 4:
        validate_v4_structure(metadata)
    if version >= 5:
        validate_v5_enhancements(metadata)
    if version >= 9:
        validate_v9_security(metadata)

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

**Last updated**: March 5, 2026 (v1.4.0 - Format Version 12 Streaming Chunked Encryption)
