# Algorithm Reference - OpenSSL Encrypt

> **⚠️ Removed in v1.5.0:** AES-OCB3, Camellia, the Whirlpool hash, the PBKDF2
> KDF chain, and the legacy Kyber algorithm names have been **completely
> removed** — both encryption and decryption. See
> [Removed Algorithms (v1.5.0)](#removed-algorithms-v150) below and
> [VERSION.md](VERSION.md).

## Table of Contents

1. [Overview](#overview)
2. [Cryptographic Algorithm Audit](#cryptographic-algorithm-audit)
3. [Post-Quantum Algorithms](#post-quantum-algorithms)
   - [ML-KEM CLI Implementation](#ml-kem-cli-implementation)
4. [Extended PQC Algorithm Support](#extended-pqc-algorithm-support)
5. [Algorithm Selection Guidelines](#algorithm-selection-guidelines)
6. [Implementation Details](#implementation-details)
7. [Compliance and Standards](#compliance-and-standards)
8. [Migration and Deprecation](#migration-and-deprecation)

## Overview

This document provides a comprehensive analysis of all cryptographic algorithms implemented in the OpenSSL Encrypt library, including compliance assessment against NIST and industry standards as of 2025.

### Algorithm Categories

- **Symmetric Encryption**: AEAD ciphers for data encryption
- **Post-Quantum KEMs**: Key encapsulation mechanisms for quantum resistance
- **Key Derivation Functions**: Password-based key derivation
- **Hash Functions**: Cryptographic hash algorithms
- **Digital Signatures**: Post-quantum signature algorithms (future)

## Cryptographic Algorithm Audit

### Symmetric Encryption Algorithms

| Algorithm | Status | Implementation | NIST/Industry Status | Security Notes |
|-----------|--------|----------------|---------------------|----------------|
| **AES-GCM** | ✅ Compliant | cryptography.hazmat.primitives.ciphers.aead.AESGCM | NIST SP 800-38D approved | Recommended with hardware acceleration (AES-NI) |
| **AES-GCM-SIV** | ✅ Compliant | cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV | RFC 8452 standardized | Nonce-misuse resistant, recommended for nonce-reuse scenarios |
| **AES-SIV** | ✅ Compliant | cryptography.hazmat.primitives.ciphers.aead.AESSIV | RFC 5297 standardized | Deterministic encryption, good for key-wrapping |
| **ChaCha20-Poly1305** | ✅ Compliant | cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305 | RFC 7539 standardized | Recommended for software-only implementations |
| **XChaCha20-Poly1305** | ✅ Compliant | Real 192-bit XChaCha20 via in-repo HChaCha20 (`modules/xchacha.py`) over `cryptography`'s ChaCha20; draft-irtf-cfrg-xchacha-03 compliant | Industry recommended | True 24-byte (192-bit) nonce, 2^96 collision bound; see nonce-format note below |
| **Fernet** | ✅ Compliant | cryptography.fernet.Fernet | Uses NIST-approved primitives | AES-128-CBC + HMAC-SHA256, ease of use |

> **XChaCha20-Poly1305 nonce formats (v1.5.0):** New files use real 192-bit
> XChaCha20 — the per-message subkey is derived with HChaCha20
> (`openssl_encrypt/modules/xchacha.py`), and the file carries
> `encryption.xchacha_nonce_format: 2`. Files written before v1.5.0 (field
> absent or `1`) used only the first 12 bytes of the stored nonce
> (96-bit-effective; not a vulnerability thanks to per-file keys, but not real
> XChaCha); they remain decryptable. The PQC hybrid data layer keeps 12-byte
> nonces under per-encryption KEM-derived keys. See
> [metadata-formats.md](metadata-formats.md#xchacha20-poly1305-nonce-format).

### Algorithm Selection Matrix

| Use Case | Primary Recommendation | Alternative | Notes |
|----------|----------------------|-------------|-------|
| **General Data Encryption** | AES-GCM | ChaCha20-Poly1305 | Hardware acceleration available |
| **Nonce Reuse Risk** | AES-GCM-SIV | XChaCha20-Poly1305 | Misuse-resistant options |
| **Software-Only Systems** | ChaCha20-Poly1305 | AES-GCM | No hardware acceleration needed |
| **Deterministic Encryption** | AES-SIV | N/A | For key wrapping scenarios |
| **Long-Lived Keys** | XChaCha20-Poly1305 | AES-GCM-SIV | Extended nonce space |
| **Legacy Compatibility** | Fernet | AES-GCM | Simple implementation |

## Post-Quantum Algorithms

### NIST Standardized Algorithms (2024-2025)

| Algorithm | NIST Standard | Security Level | Mathematical Foundation | Status |
|-----------|---------------|----------------|------------------------|--------|
| **ML-KEM-512** | FIPS 203 | Level 1 (AES-128 equivalent) | Module Lattices | ✅ Implemented |
| **ML-KEM-768** | FIPS 203 | Level 3 (AES-192 equivalent) | Module Lattices | ✅ Implemented |
| **ML-KEM-1024** | FIPS 203 | Level 5 (AES-256 equivalent) | Module Lattices | ✅ Implemented |
| **HQC-128** | Pending (2026) | Level 1 (AES-128 equivalent) | Error-Correcting Codes | ✅ Implemented |
| **HQC-192** | Pending (2026) | Level 3 (AES-192 equivalent) | Error-Correcting Codes | ✅ Implemented |
| **HQC-256** | Pending (2026) | Level 5 (AES-256 equivalent) | Error-Correcting Codes | ✅ Implemented |

### Hybrid Encryption Modes

All post-quantum algorithms are implemented in hybrid mode, combining PQ KEMs with classical symmetric encryption:

#### ML-KEM Hybrid Modes
- `ml-kem-512-hybrid`: ML-KEM-512 + AES-GCM
- `ml-kem-768-hybrid`: ML-KEM-768 + AES-GCM (recommended)
- `ml-kem-1024-hybrid`: ML-KEM-1024 + AES-GCM
- `ml-kem-512-chacha20`: ML-KEM-512 + ChaCha20-Poly1305
- `ml-kem-768-chacha20`: ML-KEM-768 + ChaCha20-Poly1305
- `ml-kem-1024-chacha20`: ML-KEM-1024 + ChaCha20-Poly1305

#### HQC Hybrid Modes
- `hqc-128-hybrid`: HQC-128 + AES-GCM
- `hqc-192-hybrid`: HQC-192 + AES-GCM
- `hqc-256-hybrid`: HQC-256 + AES-GCM
- `hqc-128-chacha20`: HQC-128 + ChaCha20-Poly1305
- `hqc-192-chacha20`: HQC-192 + ChaCha20-Poly1305
- `hqc-256-chacha20`: HQC-256 + ChaCha20-Poly1305

### ML-KEM CLI Implementation

The library includes transparent ML-KEM naming support in the command-line interface through an automatic conversion patch. This allows users to use standardized ML-KEM algorithm names while maintaining compatibility with the existing validation logic.

#### Algorithm Name Mapping

| ML-KEM Name | NIST Standard |
|-------------|---------------|
| `ml-kem-512-hybrid` | FIPS 203 Level 1 |
| `ml-kem-768-hybrid` | FIPS 203 Level 3 |
| `ml-kem-1024-hybrid` | FIPS 203 Level 5 |

#### Usage Examples

```bash
# Encryption with standardized ML-KEM names
python -m openssl_encrypt.crypt encrypt -i input.txt -o output.enc \
  --algorithm ml-kem-1024-hybrid --password test1234

# Decryption with ML-KEM names
python -m openssl_encrypt.crypt decrypt -i output.enc -o decrypted.txt \
  --algorithm ml-kem-1024-hybrid --password test1234
```

#### Implementation Details

- **Native ML-KEM**: ML-KEM is the canonical algorithm naming (FIPS 203)
- **Legacy Kyber names removed**: As of v1.5.0, legacy Kyber names are no longer accepted

### Security Analysis

#### Mathematical Diversity
- **ML-KEM**: Based on module lattice problems (Ring-LWE)
- **HQC**: Based on error-correcting codes (syndrome decoding)

This diversity provides protection against potential breakthroughs in either mathematical approach.

#### Performance Characteristics

| Algorithm | Key Generation | Encapsulation | Decapsulation | Key Size | Ciphertext Size |
|-----------|----------------|---------------|---------------|----------|-----------------|
| ML-KEM-512 | Fast | Fast | Fast | 1.6KB | 0.8KB |
| ML-KEM-768 | Fast | Fast | Fast | 2.4KB | 1.2KB |
| ML-KEM-1024 | Fast | Fast | Fast | 3.2KB | 1.6KB |
| HQC-128 | Medium | Medium | Medium | 2.4KB | 4.8KB |
| HQC-192 | Medium | Medium | Medium | 4.8KB | 9.6KB |
| HQC-256 | Slow | Slow | Slow | 7.2KB | 14.4KB |

## Extended PQC Algorithm Support

### Integration Architecture

The library supports extended post-quantum algorithms through integration with the Open Quantum Safe (OQS) library:

```
┌─────────────────────────────────────────────────────────┐
│                 Application Layer                        │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                PQC Adapter Layer                        │
│               (pqc_adapter.py)                          │
└─┬─────────────────────┬─────────────────────────────────┘
  │                     │
┌─▼──────────────┐ ┌────▼─────────────────────────────────┐
│ Native ML-KEM  │ │        LibOQS Integration            │
│ Implementation │ │       (pqc_liboqs.py)                │
└────────────────┘ └──────────────────────────────────────┘
```

### Future Algorithms (Planned)

| Algorithm | Type | Standard | Mathematical Foundation | Implementation Status |
|-----------|------|----------|------------------------|----------------------|
| **ML-DSA-44** | Signature | FIPS 204 | Module Lattices | 🔄 Planned |
| **ML-DSA-65** | Signature | FIPS 204 | Module Lattices | 🔄 Planned |
| **ML-DSA-87** | Signature | FIPS 204 | Module Lattices | 🔄 Planned |
| **SLH-DSA-SHA2-128F** | Signature | FIPS 205 | Hash Functions | 🔄 Planned |
| **SLH-DSA-SHA2-192F** | Signature | FIPS 205 | Hash Functions | 🔄 Planned |
| **SLH-DSA-SHA2-256F** | Signature | FIPS 205 | Hash Functions | 🔄 Planned |
| **FN-DSA-512** | Signature | FIPS 206 | NTRU Lattices | 🔄 Planned |
| **FN-DSA-1024** | Signature | FIPS 206 | NTRU Lattices | 🔄 Planned |

## Key Derivation Functions

### Password-Based Key Derivation

| Algorithm | Status | Implementation | Standard | Security Assessment |
|-----------|--------|----------------|----------|-------------------|
| **Scrypt** | ✅ Compliant | Memory-hard implementation | RFC 7914 | Good memory-hardness properties |
| **Argon2** | ✅ Compliant | id/i/d variants supported | RFC 9106 | Winner of Password Hashing Competition |
| **Balloon** | ✅ Compliant | Custom memory-hard function | Academic research | Alternative to Argon2 |

### Recommended KDF Configurations

#### Standard Security
```
Argon2id: 1GB memory, 3 iterations, 4 threads
```

#### High Security
```
Argon2id: 2GB memory, 4 iterations, 8 threads
+ Scrypt: N=65536, r=8, p=1
```

#### Paranoid Security
```
Argon2id: 4GB memory, 5 iterations, 8 threads
+ Scrypt: N=131072, r=16, p=2
+ Balloon: 2GB space, 4 rounds
```

## Hash Functions

### Cryptographic Hash Algorithms

| Algorithm | Status | Implementation | Standard | Security Assessment |
|-----------|--------|----------------|----------|-------------------|
| **SHA-256** | ✅ Compliant | Standard implementation | NIST FIPS 180-4 | Widely recommended |
| **SHA-512** | ✅ Compliant | Standard implementation | NIST FIPS 180-4 | Widely recommended |
| **SHA3-256** | ✅ Compliant | Standard implementation | NIST FIPS 202 | Resistant to length-extension |
| **SHA3-512** | ✅ Compliant | Standard implementation | NIST FIPS 202 | Resistant to length-extension |
| **BLAKE2b** | ✅ Compliant | Standard implementation | RFC 7693 | High-performance, secure |
| **SHAKE-256** | ✅ Compliant | Standard implementation | NIST FIPS 202 | Extendable Output Function |

### Multi-Hash Approach

The library implements a unique defense-in-depth approach by chaining multiple hash functions:

```
Password → SHA-512 → SHA3-256 → BLAKE2b → SHAKE-256 → Key
```

This provides protection against potential weaknesses in any single hash function.

## Algorithm Selection Guidelines

### For New Applications

1. **Symmetric Encryption**: AES-GCM (with hardware acceleration) or ChaCha20-Poly1305 (software-only)
2. **Post-Quantum Protection**: ML-KEM-768-hybrid (balanced security/performance)
3. **Key Derivation**: Argon2id
4. **Hash Functions**: SHA-256/SHA-512 with SHA3 backup

### For High-Security Applications

1. **Symmetric Encryption**: AES-GCM-SIV (nonce-misuse resistant)
2. **Post-Quantum Protection**: ML-KEM-1024-hybrid (maximum security)
3. **Algorithmic Diversity**: Consider HQC-256-hybrid for mathematical diversity
4. **Key Derivation**: Multi-layer approach with Argon2id + Scrypt

### For Long-Term Data Protection

1. **Post-Quantum Encryption**: Mandatory for data requiring 10+ year protection
2. **Algorithm Diversity**: Use both ML-KEM and HQC algorithms
3. **Hybrid Approach**: Always combine PQ with classical algorithms
4. **Regular Re-encryption**: Plan for algorithm migration

## Implementation Details

### Secure Implementation Practices

1. **Constant-Time Operations**: All sensitive comparisons use constant-time algorithms
2. **Memory Protection**: Sensitive data stored in secure memory areas
3. **Error Handling**: Standardized error messages prevent information leakage
4. **Side-Channel Resistance**: Timing jitter and uniform execution paths

### Code Example: Algorithm Selection

```python
def select_algorithm(security_level, performance_priority, quantum_resistance):
    """
    Select appropriate encryption algorithm based on requirements.
    """
    if quantum_resistance:
        if security_level == "maximum":
            return "ml-kem-1024-hybrid"
        elif security_level == "high":
            return "ml-kem-768-hybrid"
        else:
            return "ml-kem-512-hybrid"
    else:
        if performance_priority == "hardware":
            return "aes-gcm"
        elif performance_priority == "software":
            return "chacha20-poly1305"
        else:
            return "aes-gcm-siv"  # Nonce-misuse resistant
```

## Compliance and Standards

### NIST Compliance

- **FIPS 140-2**: Algorithms comply with FIPS 140-2 requirements
- **FIPS 203**: ML-KEM implementation follows NIST FIPS 203
- **SP 800-38D**: AES-GCM implementation follows NIST guidelines
### Industry Standards

- **RFC Compliance**: All implemented algorithms follow relevant RFCs
- **ISO Standards**: Support for ISO-standardized algorithms where applicable
- **Common Criteria**: Implementation supports Common Criteria evaluation

### Export Control Considerations

- **Encryption Strength**: All algorithms comply with export regulations
- **Documentation**: Proper documentation for export compliance
- **Notification**: Appropriate export notifications filed where required

## Migration and Deprecation

### Removed Algorithms (v1.5.0)

The following algorithms were removed in v1.5.0. Files encrypted with these algorithms must be decrypted using v1.4.x or earlier before upgrading.

| Algorithm | Replacement | Removed In |
|-----------|-------------|------------|
| **AES-OCB3** | AES-GCM | v1.5.0 |
| **Camellia** | AES-GCM | v1.5.0 |
| **Whirlpool** | SHA-512 or BLAKE2b | v1.5.0 |
| **PBKDF2** (KDF chain) | Argon2id or Scrypt | v1.5.0 |
| **Kyber512/768/1024** | ML-KEM-512/768/1024 | v1.5.0 |

### Migration Strategy

1. **Assessment Phase**: Inventory all encrypted data and algorithms used
2. **Risk Evaluation**: Assess quantum risk based on data sensitivity and lifetime
3. **Prioritized Migration**: Focus on highest-risk assets first
4. **Hybrid Transition**: Use hybrid classical/PQ encryption during migration
5. **Monitoring**: Stay informed about quantum computing developments

### Algorithm Lifecycle Management

```
Research → Evaluation → Implementation → Standardization → Deployment → Monitoring → Deprecation → Removal
    ↑                                                                                               ↓
    └─────────────────────────── Continuous Security Assessment ──────────────────────────────────┘
```

---

This algorithm reference provides comprehensive information about all cryptographic algorithms in OpenSSL Encrypt. For implementation details, see the [Security Documentation](security.md).

**Last updated**: February 25, 2026
