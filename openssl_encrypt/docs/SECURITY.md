# Security Documentation

This document provides comprehensive security information for the openssl_encrypt library, including design principles, security features, implementation details, and best practices for users.

## Table of Contents

1. [Security Philosophy](#security-philosophy)
2. [Threat Model](#threat-model)
3. [Cryptographic Design](#cryptographic-design)
4. [Memory Security](#memory-security)
5. [Key Management](#key-management)
6. [File Security](#file-security)
7. [Post-Quantum Cryptography](#post-quantum-cryptography)
8. [Side-Channel Protections](#side-channel-protections)
9. [Thread Safety](#thread-safety)
10. [Secure Development Practices](#secure-development-practices)
11. [Security Testing](#security-testing)
12. [Vulnerability Reporting](#vulnerability-reporting)
13. [Best Practices for Users](#best-practices-for-users)
14. [Security Improvements History](#security-improvements-history)

## Security Philosophy

The openssl_encrypt library is designed with a security-first approach, following these core principles:

1. **Defense in Depth**: Multiple layers of security controls to protect data
2. **Fail Secure**: Default to the most secure option when exceptions occur
3. **Zero Trust**: Validate all inputs and operations
4. **Least Privilege**: Restrict operations to the minimum necessary permissions
5. **Transparency**: Open source code and algorithms for public review

Our security design assumes:
- Attackers have full knowledge of the cryptographic algorithms used
- Security relies primarily on key secrecy and algorithm strength, not implementation obscurity
- Modern attackers have substantial computing resources at their disposal

## Threat Model

The openssl_encrypt library is designed to protect against the following threats:

### Primary Threats
- **Data Theft**: Unauthorized access to encrypted data
- **Data Tampering**: Modification of encrypted data without detection
- **Password Attacks**: Brute force, dictionary, and rainbow table attacks
- **Key Extraction**: Attempts to extract cryptographic keys from memory
- **Side-Channel Attacks**: Timing, power analysis, and other indirect attacks

### Secondary Threats
- **Implementation Vulnerabilities**: Buffer overflows, injection attacks
- **Metadata Leakage**: Information disclosure through file metadata
- **Downgrade Attacks**: Forcing use of weaker algorithms or parameters
- **Denial of Service**: Resource exhaustion through malformed inputs

### Out of Scope
- **Physical Attacks**: Direct hardware tampering (beyond cold boot attack protection)
- **Malware on Host System**: Keyloggers, rootkits, or other malicious software
- **Social Engineering**: Phishing or other human manipulation techniques

## Cryptographic Design

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
| Camellia | AEAD | 256-bit | Medium (deprecated) | Legacy support |

All algorithms are used with authenticated encryption to ensure data integrity and authenticity.

### Post-Quantum Hybrid Encryption

For future-proof security, the library implements hybrid post-quantum encryption:

| Algorithm | Classical Component | Post-Quantum Component | Security Level |
|-----------|---------------------|------------------------|---------------|
| ML-KEM-512-Hybrid | AES-GCM | ML-KEM-512 (Kyber) | Medium |
| ML-KEM-768-Hybrid | AES-GCM | ML-KEM-768 (Kyber) | High |
| ML-KEM-1024-Hybrid | AES-GCM | ML-KEM-1024 (Kyber) | Very High |
| ML-KEM-512-ChaCha20 | ChaCha20-Poly1305 | ML-KEM-512 (Kyber) | Medium |
| ML-KEM-768-ChaCha20 | ChaCha20-Poly1305 | ML-KEM-768 (Kyber) | High |
| ML-KEM-1024-ChaCha20 | ChaCha20-Poly1305 | ML-KEM-1024 (Kyber) | Very High |
| HQC-128-Hybrid | AES-GCM | HQC-128 | Medium |
| HQC-192-Hybrid | AES-GCM | HQC-192 | High |
| HQC-256-Hybrid | AES-GCM | HQC-256 | Very High |

Hybrid encryption ensures that even if one component (classical or post-quantum) is compromised, the data remains protected by the other component.

### Key Derivation

Multiple layers of key derivation are used to maximize password security:

1. **Primary KDF**: Argon2id (default)
   - Memory-hard function resistant to GPU attacks
   - Configurable parameters for memory, iterations, and parallelism
   - Default: 1GB memory, 3 iterations, 4 threads

2. **Secondary KDF Options**:
   - PBKDF2-HMAC-SHA512 (default)
   - Scrypt (optional)
   - Balloon Hashing (optional)

3. **Additional Hash Functions**:
   - SHA-256/512
   - SHA3-256/512
   - BLAKE2b/BLAKE3
   - Whirlpool

This multi-layered approach ensures that even if weaknesses are discovered in one algorithm, others provide backup protection.

## Memory Security

### Secure Memory Management

The library implements comprehensive memory security features:

1. **Memory Protection**:
   - Sensitive data stored in mlock()'ed memory pages
   - Pages marked as non-swappable to prevent leakage to disk
   - Memory locations verified for integrity

2. **Memory Zeroing**:
   - Immediate zeroing of sensitive data after use
   - Secure wipe functions that cannot be optimized away by compilers
   - Double-check verification of zeroing operations

3. **Allocation Security**:
   - Secure memory allocator for sensitive data
   - Memory canaries to detect buffer overflows
   - Buffer underrun and overrun detection

4. **Object Lifecycle Management**:
   - Automatic secure cleanup in destructors
   - Context managers ensure proper cleanup even with exceptions
   - Explicit memory management for cryptographic keys

## Key Management

### Key Generation

- Strong key generation using cryptographically secure random number generators
- Hardware RNG support where available
- Entropy verification for generated keys
- Optional key derivation from existing material

### Key Storage

- Encrypted key storage in keystore
- Key wrapping for secure key transit
- Dual encryption option (password + keystore)
- Key identification through secure fingerprinting

### Key Usage

- Limited key lifetimes
- Key separation for different purposes
- Key rotation support
- Usage tracking and restrictions

## File Security

### File Format

The library uses a secure file format with the following components:

1. **Metadata Header**:
   - Format version
   - Encryption algorithm
   - Key derivation parameters (without revealing the key)
   - Authentication data

2. **Encrypted Content**:
   - Authenticated encryption of data
   - Integrity protection
   - Optional compression (disabled by default for security)

3. **File Integrity**:
   - Content hash for integrity verification
   - HMAC-based authentication
   - Tamper detection

### Secure File Operations

- Atomic write operations for file integrity
- Temporary files are encrypted
- Secure file deletion with multiple passes
- Directory permissions verification
- Backup creation before modifications (optional)

### Secure Shredding Implementation

Multi-pass overwrite sequence:
1. Random data (cryptographically secure)
2. Alternating patterns (0xFF, 0x00)
3. Final zero-fill pass
4. File truncation
5. Filesystem deletion

## Post-Quantum Cryptography

### Quantum Threat Model

The library assumes that large-scale quantum computers could eventually break:
- RSA and other factoring-based cryptography
- Elliptic curve cryptography
- Discrete logarithm-based systems

### Quantum-Resistant Algorithms

The library implements NIST-selected post-quantum algorithms:
- **ML-KEM** (previously Kyber): For key encapsulation
- **HQC**: For additional quantum resistance based on coding theory

### Hybrid Approach

For maximum security, the library uses hybrid cryptography that combines:
1. Traditional cryptography (AES-GCM, ChaCha20-Poly1305)
2. Post-quantum algorithms (ML-KEM, HQC)

This ensures that data remains secure even if either classical or quantum algorithms are compromised.

### Migration Path

The library provides a clear migration path for users:
- Automatic algorithm version detection
- Backward compatibility with older formats
- Support for both classical and post-quantum algorithms
- Documentation for algorithm migration

## Side-Channel Protections

### Timing Attack Mitigation

- Constant-time comparison for all sensitive operations
- Timing jitter added to cryptographic operations
- Uniform execution paths regardless of input values
- Side-channel resistant algorithm implementations

### Memory Access Patterns

- Cache-timing attack mitigations
- Protection against memory access pattern analysis
- Uniform memory access patterns for sensitive operations

### Error Oracle Prevention

- Standardized error messages that don't leak information
- Consistent timing regardless of error condition
- Prevention of error message oracle attacks
- Rate limiting for password attempts

## Thread Safety

The openssl_encrypt library is designed for safe use in multi-threaded applications, with comprehensive thread safety features:

### Thread Safety Mechanisms

- Thread-local storage for sensitive state
- Mutex locks for shared resources
- Atomic operations for race condition prevention
- Thread-safe data structures

### Thread-Safe Components

- **Memory Management**: Thread-safe secure memory allocation/deallocation
- **Cryptographic Operations**: Thread-safe implementation of all core operations
- **Error Handling**: Thread-local timing jitter for consistent error behavior

For comprehensive details on thread safety implementation and best practices, see the [thread_safety.md](thread_safety.md) document.

## Secure Development Practices

### Code Security

- Regular security audits
- Static analysis tools for code quality
- Dynamic analysis and fuzzing
- Code review process for all security-related changes

### Dependency Management

- Comprehensive review of all dependencies
- Dependency pinning with security checks
- Regular updates and security patching
- Minimal dependency approach where possible

### Testing

- Comprehensive test suite for all security features
- Negative testing (testing failure modes)
- Cryptographic test vectors
- Penetration testing and security evaluation

## Security Testing

### Automated Tests

The library includes extensive automated security tests:

1. **Functionality Tests**:
   - Encryption/decryption correctness
   - Algorithm compatibility
   - Parameter validation

2. **Security Tests**:
   - Key isolation verification
   - Memory wiping verification
   - Timing consistency checks
   - Error handling security

3. **Edge Case Tests**:
   - Invalid inputs
   - Malformed files
   - Resource exhaustion scenarios
   - Backward compatibility

### Manual Security Reviews

Regular security reviews focus on:
- Algorithm implementation correctness
- Side-channel vulnerability assessment
- Memory handling security
- Error management

## Vulnerability Reporting

Security issues should be reported according to the project's security policy:

1. **Responsible Disclosure**:
   - Do not publicly disclose issues before they are fixed
   - Report issues directly to the security team
   - Allow reasonable time for patches before disclosure

2. **Contact Channels**:
   - Email: security@example.com (replace with actual contact)
   - GitHub security advisories
   - Encrypted communication available

## Best Practices for Users

### Password Security

- Use strong, unique passwords (minimum 12 characters recommended)
- Consider passphrases instead of passwords
- Use password managers for storage
- Never reuse passwords across different systems
- Change passwords if compromise is suspected

### Key Management

- Keep backup copies of encryption keys
- Store keys securely (ideally in hardware security modules if available)
- Implement key rotation policies
- Use dual encryption for critical data

### System Security

- Keep systems and software updated
- Use full-disk encryption in addition to file encryption
- Maintain secure backups
- Follow the principle of least privilege
- Verify file integrity after encryption/decryption

### Response to Compromise

1. **Data Breach Response**:
   - Immediately revoke compromised passwords
   - Re-encrypt affected files with new passwords
   - Verify secure deletion of old files
   - Document the incident and review security measures

2. **Recovery Process**:
   - Maintain encrypted backups
   - Test recovery procedures regularly
   - Document all encryption parameters
   - Store recovery information securely

## Security Improvements History

The library maintains a history of security improvements and fixes:

### Recent Improvements

1. **Fixed XChaCha20Poly1305 nonce handling**:
   - Properly handles 24-byte nonces
   - Maintains backward compatibility

2. **Standardized nonce generation**:
   - Consistent generation for all algorithms
   - Proper nonce sizes for each algorithm
   - Validation to prevent weak nonces

3. **Fixed salt reuse issues**:
   - Modified PBKDF2 implementation for unique salts
   - Secure generation of salts
   - Proper zeroing of sensitive data

4. **Enhanced post-quantum cryptography**:
   - Added support for NIST-selected algorithms
   - Implemented hybrid encryption modes
   - Enhanced parameter validation
   - Fixed dual encryption with post-quantum algorithms

5. **Improved test security validation**:
   - Enhanced tests to verify security properties
   - Added tests for wrong credentials
   - Improved detection of test file formats

For a complete history of security improvements, see the [security_improvements.md](security_improvements.md) document.

---

This document is updated regularly as security features and best practices evolve. Last updated: May 22, 2025.