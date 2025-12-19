# Security Documentation - OpenSSL Encrypt

## Table of Contents

1. [Security Philosophy](#security-philosophy)
2. [Threat Model](#threat-model)
3. [Cryptographic Architecture](#cryptographic-architecture)
4. [Core Security Features](#core-security-features)
5. [Memory Security](#memory-security)
6. [Key Management](#key-management)
7. [Post-Quantum Cryptography](#post-quantum-cryptography)
8. [Side-Channel Protections](#side-channel-protections)
9. [Authentication and Data Integrity](#authentication-and-data-integrity)
10. [Password Security](#password-security)
11. [Best Practices for Users](#best-practices-for-users)
12. [Security Testing](#security-testing)
13. [Vulnerability Reporting](#vulnerability-reporting)

## Security Philosophy

The openssl_encrypt library is designed with security as a primary consideration, following these core principles:

### Defense in Depth
- Multiple layers of security controls to protect data
- Never rely on a single security measure
- Comprehensive protection across all components

### Core Security Principles
1. **Fail Secure**: Default to the most secure option when exceptions occur
2. **Zero Trust**: Validate all inputs and operations
3. **Least Privilege**: Restrict operations to the minimum necessary permissions
4. **Transparency**: Open source code and algorithms for public review

Our security design assumes:
- Attackers have full knowledge of the cryptographic algorithms used
- Security relies primarily on key secrecy and algorithm strength, not implementation obscurity
- Modern attackers have substantial computing resources at their disposal

## Threat Model

The library is designed to protect against the following threats:

### Primary Threats
- **Data Theft**: Unauthorized access to encrypted data
- **Data Tampering**: Modification of encrypted data without detection
- **Password Attacks**: Brute force, dictionary, and rainbow table attacks
- **Key Extraction**: Attempts to extract cryptographic keys from memory
- **Side-Channel Attacks**: Timing, power analysis, and other indirect attacks
- **Quantum Computing Attacks**: Future threats from quantum computers

### Secondary Threats
- **Implementation Vulnerabilities**: Buffer overflows, injection attacks
- **Metadata Leakage**: Information disclosure through file metadata
- **Downgrade Attacks**: Forcing use of weaker algorithms or parameters
- **Denial of Service**: Resource exhaustion through malformed inputs

### Out of Scope
- **Physical Attacks**: Direct hardware tampering (beyond cold boot attack protection)
- **Malware on Host System**: Keyloggers, rootkits, or other malicious software
- **Social Engineering**: Phishing or other human manipulation techniques

## Cryptographic Architecture

### Layered Security Design

The library implements a layered cryptographic architecture:

```
┌─────────────────────────────────────────────────────────┐
│                    User Interface                        │
│                (crypt_cli.py, crypt_gui.py)             │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                    Core Operations                       │
│                      (crypt_core.py)                     │
└─┬─────────────────────┬──────────────────┬──────────────┘
  │                     │                  │
┌─▼────────────────┐ ┌──▼─────────────┐ ┌──▼────────────────┐
│ Standard Crypto  │ │ Post-Quantum   │ │ Key Management    │
│ (AEAD Ciphers)   │ │ Cryptography   │ │ (Key Derivation)  │
└─────────────────┘ └─┬──────────────┘ └───────────────────┘
                      │
         ┌────────────▼────────────┐
         │ PQC Adapter Layer       │
         │ (pqc_adapter.py)        │
         └─────────────────────────┘
```

### Security Boundaries
1. **Memory Isolation**: Sensitive data is kept in secure memory areas
2. **Algorithm Isolation**: Different cryptographic algorithms are isolated through well-defined interfaces
3. **Key Separation**: Different keys are used for different purposes
4. **Error Containment**: Errors are contained and standardized to prevent information leakage

## Core Security Features

### Encryption Algorithms

The library supports multiple encryption algorithms with different security characteristics:

| Algorithm | Type | Key Size | Security Level | Use Case |
|-----------|------|----------|---------------|----------|
| AES-GCM | AEAD | 256-bit | High | Default for most data |
| AES-GCM-SIV | AEAD | 256-bit | High | Nonce-misuse resistant |
| ChaCha20-Poly1305 | AEAD | 256-bit | High | Alternative to AES |
| XChaCha20-Poly1305 | AEAD | 256-bit | High | Extended nonce space |
| AES-OCB3 | AEAD | 256-bit | High (deprecated) | Legacy support |
| AES-SIV | AEAD | 256-bit | High | Deterministic encryption |
| Fernet | AEAD | 256-bit | High | Compatibility with other systems |

All algorithms use authenticated encryption with associated data (AEAD) to ensure data integrity and authenticity.

### Template-Based Security Profiles

Pre-configured security templates for different use cases:

1. **Quick**: Balanced security for regular use
   - Argon2id (512MB RAM, 2 iterations)
   - Single-layer key derivation

2. **Standard** (default): Strong security
   - Argon2id (1GB RAM, 3 iterations)
   - PBKDF2 secondary KDF
   - BLAKE3 file hashing

3. **Paranoid**: Maximum security
   - Argon2id (2GB RAM, 4 iterations)
   - Multiple KDF layers
   - All available hash functions
   - Secure memory level: maximum

### File Format Security

The library uses a secure file format with:

1. **Metadata Header**: Format version, encryption algorithm, key derivation parameters
2. **Encrypted Content**: Authenticated encryption of data with integrity protection
3. **File Integrity**: Content hash for integrity verification and tamper detection

## Memory Security

### Secure Memory Management

Comprehensive memory security features:

1. **Protected Memory Buffers**: All sensitive data stored in locked memory
2. **Immediate Wiping**: Zero-fill memory immediately after use
3. **Swap Prevention**: Memory pages locked to prevent swapping to disk
4. **Side-Channel Mitigation**: Constant-time operations for sensitive comparisons
5. **Cold Boot Attack Protection**: Minimizes sensitive data lifetime in memory

### Secure Memory Implementation

Multi-pass overwrite sequence for sensitive data:

```python
def secure_memzero(data, full_verification=True):
    """
    Securely wipe data with multiple rounds of overwriting followed by zeroing.

    1. Random data (unpredictable)
    2. All ones (0xFF) - alternate bit pattern
    3. Alternating pattern (0xAA) - 10101010
    4. Inverse alternating pattern (0x55) - 01010101
    5. Final zeroing
    """
```

### Memory Protection Classes

1. **SecureBytes**: Automatic zeroing when no longer needed
2. **SecureContainer**: Secure container for sensitive data
3. **CryptoSecureBuffer**: Buffer specifically for cryptographic material
4. **CryptoKey**: Specialized container for key material

## Key Management

### Key Derivation Chain

Multi-layer key derivation to maximize password security:

1. **Primary KDF**: Argon2id (default)
   - Memory-hard function resistant to GPU attacks
   - Configurable parameters for memory, iterations, and parallelism
   - Default: 1GB memory, 3 iterations, 4 threads

2. **Secondary KDF Options**:
   - PBKDF2-HMAC-SHA512 (default)
   - Scrypt (optional)
   - Balloon Hashing (optional)

3. **Additional Hash Functions**:
   - SHA-256/512 (FIPS 180-4)
   - SHA3-256/512 (FIPS 202)
   - BLAKE2b - High-performance cryptographic hash
   - SHAKE-256 - Extendable-output function
   - Whirlpool - 512-bit cryptographic hash

### Key Storage and Management

- **Encrypted keystore** for PQC keys
- **Key wrapping** for secure key transit
- **Dual encryption** option (password + keystore)
- **Key identification** through secure fingerprinting
- **Key rotation** support with lifecycle management

### Secure Random Number Generation

The library uses cryptographically secure random number generation:

1. **secrets Module**: Primary source of cryptographic randomness
2. **OS-Level Entropy**: Direct access to OS entropy sources (/dev/urandom)
3. **Hardware RNG**: Optional integration with hardware random number generators

Used for:
- Cryptographic keys
- Initialization vectors (IVs) and nonces
- Salts for key derivation
- Challenge values for authentication
- Memory padding and canaries

## Post-Quantum Cryptography

### Quantum Threat Protection

For future-proof security against quantum computing threats:

### Supported PQ Algorithms

| Algorithm | Type | Security Level | Description |
|-----------|------|---------------|-------------|
| ML-KEM-512 | KEM | Level 1 (AES-128) | NIST standardized (FIPS 203) |
| ML-KEM-768 | KEM | Level 3 (AES-192) | NIST standardized (FIPS 203) |
| ML-KEM-1024 | KEM | Level 5 (AES-256) | NIST standardized (FIPS 203) |
| HQC-128 | KEM | Level 1 (AES-128) | Code-based alternative |
| HQC-192 | KEM | Level 3 (AES-192) | Code-based alternative |
| HQC-256 | KEM | Level 5 (AES-256) | Code-based alternative |

### Hybrid Encryption Approach

All post-quantum encryption uses hybrid encryption combining:
1. **Classical Encryption**: AES-GCM or ChaCha20-Poly1305 for data encryption
2. **Post-Quantum Key Encapsulation**: ML-KEM (Kyber) or HQC for key protection

This ensures data remains secure even if either classical or quantum algorithms are compromised.

### When to Use Post-Quantum Encryption

Consider post-quantum encryption for:
- Data that must remain confidential for 10+ years
- Information subject to "harvest now, decrypt later" attacks
- Highly sensitive data requiring maximum security
- Compliance with forward-looking security standards

## Side-Channel Protections

### Timing Attack Mitigation

1. **Constant-Time Comparison**: All sensitive comparisons use constant-time algorithms
2. **Timing Jitter**: Random delays to mask timing differences
3. **Uniform Error Paths**: All error paths take the same amount of time

### Implementation Example

```python
def constant_time_compare(a, b):
    """Compare two byte sequences in constant time."""
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y

    return result == 0
```

### Cache Timing Protection

1. **Memory Access Patterns**: Avoid revealing secret-dependent memory access patterns
2. **Cache Line Padding**: Critical data structures padded to cache line boundaries
3. **Memory Barriers**: Use of memory barriers to prevent optimization-based leaks

### Error Oracle Prevention

- Standardized error messages that don't leak information
- Consistent timing regardless of error condition
- Prevention of error message oracle attacks
- Rate limiting for password attempts

## Authentication and Data Integrity

### AEAD Integrity Protection

All supported encryption algorithms use authenticated encryption to protect against:
- Data tampering
- Bit flipping attacks
- Ciphertext malleability

### File-Level Authentication

Each encrypted file includes:
1. **HMAC-SHA256**: Keyed hash of file contents for integrity verification
2. **Signature Verification**: Optional digital signature (including post-quantum signatures)
3. **Metadata Authentication**: Protected metadata with integrity verification

## Password Security

### Password Strength Guidelines

1. **Length**: Use passwords with a minimum of 16 characters when possible
2. **Complexity**: Include a mix of uppercase, lowercase, numbers, and special characters
3. **Unpredictability**: Avoid predictable patterns or personal information
4. **Entropy**: Minimum 100 bits of entropy for strong passwords

### Password Policy Levels

```python
class PasswordPolicy:
    LEVEL_MINIMAL = "minimal"      # Just minimum length
    LEVEL_BASIC = "basic"          # Length + basic complexity
    LEVEL_STANDARD = "standard"    # Length + full complexity + entropy
    LEVEL_PARANOID = "paranoid"    # Length + full complexity + entropy + common password check
```

### Password Storage Recommendations

1. **Use a Password Manager**: Store encryption passwords in a reputable password manager
2. **Avoid Plaintext Storage**: Never store passwords in plaintext files
3. **Physical Storage**: If written down, store in secure, locked locations
4. **Password Rotation**: Change encryption passwords periodically

### Common Password Protection

The library includes detection of common and compromised passwords using SHA-256 hashed password lists without storing actual passwords in memory.

## Best Practices for Users

### System Security

1. **Keep systems and software updated**
2. **Use full-disk encryption** in addition to file encryption
3. **Maintain secure backups**
4. **Follow the principle of least privilege**
5. **Verify file integrity** after encryption/decryption

### Secure File Operations

1. **Atomic write operations** for file integrity
2. **Temporary files are encrypted**
3. **Secure file deletion** with multiple passes
4. **Directory permissions verification**
5. **Backup creation** before modifications (optional)

### Secure Shredding Implementation

Multi-pass overwrite sequence:
1. Random data (cryptographically secure)
2. Alternating patterns (0xFF, 0x00)
3. Final zero-fill pass
4. File truncation
5. Filesystem deletion

### Emergency Procedures

#### Data Compromise Response
1. Immediately revoke compromised passwords
2. Re-encrypt affected files with new passwords
3. Verify secure deletion of old files
4. Document incident and review security measures

#### Recovery Process
1. Maintain encrypted backups
2. Test recovery procedures regularly
3. Document all encryption parameters
4. Store recovery information securely

## Security Testing

### Automated Tests

The library includes extensive automated security tests:

1. **Functionality Tests**: Encryption/decryption correctness, algorithm compatibility, parameter validation
2. **Security Tests**: Key isolation verification, memory wiping verification, timing consistency checks
3. **Edge Case Tests**: Invalid inputs, malformed files, resource exhaustion scenarios

### Property-Based Testing

Verification of cryptographic properties:
- Roundtrip testing (encryption followed by decryption returns original)
- Key derivation consistency
- Constant-time operation verification
- Memory zeroing verification

### Security Test Cases

Tests that verify security properties:
- Constant-time comparison verification
- Memory wiping effectiveness
- Error handling consistency
- Side-channel resistance

## Vulnerability Reporting

### Responsible Disclosure

Security issues should be reported according to the project's security policy:

1. **Do not publicly disclose** issues before they are fixed
2. **Report issues directly** to the security team
3. **Allow reasonable time** for patches before disclosure

### Contact Channels

- **Email**: [Project security contact]
- **GitLab security advisories**
- **Encrypted communication** available upon request

---

This security documentation is updated regularly as security features and best practices evolve. The openssl_encrypt library provides comprehensive security protections through multiple layers of defense, helping protect your data against current threats.

**Last updated**: June 16, 2025
