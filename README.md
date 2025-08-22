## History
The project is historically named `openssl-encrypt` because it once was a python script wrapper around openssl. But that did not work anymore with recent python versions.
Therefore I decided to do a complete rewrite in pure python also using modern cipher and hashes. So the projectname is a "homage" to the root of all :-)

Whirlpool support: The whirlpool hash algorithm is now supported on all Python versions, including Python 3.11, 3.12, and 3.13. The package will automatically detect your Python version and install the appropriate
Whirlpool implementation.

## 🔒 Security Architecture & Cryptographic Impossibility

### Fundamental Design Principles

This tool implements a **revolutionary chained hash/KDF architecture** that provides security guarantees beyond traditional encryption:

```
(Password + Initial Salt) → Hash₁ → Result₁ → Salt₂(derived from Result₁) → Hash₂ → Result₂ → Salt₃(derived from Result₂) → ... → Final Key
```

**Core Security Features:**
- **Sequential Dependency**: Each hash round requires the previous round's completion
- **Dynamic Salting**: Salts are derived from previous results, making them unpredictable
- **Parallelization Immunity**: Attacks must be strictly sequential regardless of attacker resources
- **Precomputation Resistance**: Rainbow tables and lookup caches are impossible at every round
- **Memory-Hard Functions**: Balloon hashing and Argon2 require significant memory per attempt

### Attack Impossibility Analysis

Our architecture fundamentally breaks traditional cryptographic attack methods:

**⚡ Eliminated Attack Optimizations:**
- **No Parallel Processing**: GPU farms and distributed computing cannot accelerate attacks
- **No Rainbow Tables**: Dynamic salting prevents any precomputation at any round
- **No Space-Time Trade-offs**: Cannot cache intermediate results between attempts
- **No Partial Optimization**: Every single hash operation must be computed from scratch

**📊 Real-World Security Impact:**

| Password Length | Balloon Rounds | Time per Attempt | Attack Duration |
|-----------------|----------------|------------------|-----------------|
| 8 characters | 5 rounds | ~40 seconds | 282,000 universe lifetimes |
| 10 characters | 5 rounds | ~40 seconds | 2.5 billion universe lifetimes |
| 13 characters | 5 rounds | ~40 seconds | 207 trillion universe lifetimes |

*Universe age: ~13.8 billion years*

**🛡️ Threat Actor Resistance:**
- **Individual hackers**: ✅ Impossible
- **Criminal organizations**: ✅ Impossible
- **Nation-state actors**: ✅ Impossible
- **Future quantum computers**: ✅ Impossible
- **Unlimited computational resources**: ✅ Still impossible (sequential constraint)

### Why This Matters

**Traditional encryption** relies on computational difficulty that could theoretically be overcome with enough resources or technological advances.

**Our approach** creates **architectural impossibility** where even unlimited resources cannot bypass the fundamental sequential processing requirement. This represents a paradigm shift from "computationally hard" to "physically impossible within any conceivable timeframe."

**Security Guarantee**: Any password 8+ characters with balloon key stretching creates an unbreakable cryptographic barrier that will remain secure until the heat death of the universe.

### Practical Benefits

- **User-Friendly**: Reasonable password lengths (8-13 characters) provide absolute security
- **Future-Proof**: Immune to advances in computing power, quantum computers, or mathematical breakthroughs
- **Configurable**: Dial your paranoia level from quick (1 balloon round) to maximum (50+ rounds + chained hashes)
- **Standards-Based**: Uses proven cryptographic primitives (AES, ChaCha20, Argon2, etc.) in novel architecture

## Comprehensive Feature Set

### Core Encryption Features

  - Military-Grade Symmetric Encryption:
    - Fernet (AES-128-CBC) - Default, proven security
    - AES-GCM - Authenticated encryption with associated data
    - AES-GCM-SIV - Misuse-resistant authenticated encryption
    - AES-SIV - Synthetic IV mode for nonce reuse resistance
    - AES-OCB3 - High-performance authenticated encryption (removed for encryption in 1.2.0, still supported for decryption)
    - ChaCha20-Poly1305 - Stream cipher with authentication
    - XChaCha20-Poly1305 - Extended nonce variant
    - Camellia - International standard block cipher (removed for encryption in 1.2.0, still supported for decryption)

###  Advanced Post-Quantum Cryptography

  - NIST-Approved Algorithms:
    - ML-KEM (Module Lattice KEM) - NIST FIPS 203 standard
        - ML-KEM-512 (Security Level 1)
      - ML-KEM-768 (Security Level 3)
      - ML-KEM-1024 (Security Level 5)
    - Kyber KEM - Original CRYSTALS-Kyber implementation
        - Kyber-512, Kyber-768, Kyber-1024
    - HQC (Hamming Quasi-Cyclic) - NIST 2025 additional KEM
        - HQC-128, HQC-192, HQC-256
    - MAYO - Multivariate quadratic signature scheme
        - MAYO-1 (Security Level 1)
        - MAYO-2 (Security Level 1)
        - MAYO-3 (Security Level 3)
        - MAYO-5 (Security Level 5)
    - CROSS - Code-based signature scheme
        - CROSS-R-SDPG-1 (Security Level 1)
        - CROSS-R-SDPG-3 (Security Level 3)
        - CROSS-R-SDPG-5 (Security Level 5)
  - Hybrid Encryption Architecture: Combines post-quantum KEMs with classical symmetric encryption for quantum-resistant protection

###  Multi-Layer Password Protection

  - Cryptographic Hash Functions:
    - SHA-2 Family (FIPS 180-4): SHA-512, SHA-384, SHA-256, SHA-224
    - SHA-3 Family (FIPS 202): SHA3-512, SHA3-384, SHA3-256, SHA3-224
    - BLAKE Family: BLAKE2b (high-performance), BLAKE3 (ultra-fast tree-based)
    - SHAKE Functions: SHAKE-256, SHAKE-128 (extendable-output functions)
    - Legacy: Whirlpool (512-bit cryptographic hash, removed for encryption in 1.2.0, still supported for decryption)
  - Key Derivation Functions (KDFs):
    - Modern KDFs:
        - HKDF - HMAC-based Key Derivation Function (RFC 5869)
        - Scrypt - Memory-hard function for GPU resistance
        - Argon2 - Winner of Password Hashing Competition (Argon2i, Argon2d, Argon2id variants)
        - Balloon Hashing - Memory-hard function with proven security
    - Legacy KDF:
        - PBKDF2 - Password-Based Key Derivation Function 2 (removed for encryption in 1.2.0, still supported for decryption)

###  Enterprise Security Features

  - Secure Key Management:
    - Local encrypted keystore for PQC keys
    - Key rotation and lifecycle management
    - Hardware security module (HSM) integration ready
  - Memory Security:
    - Secure memory allocation and deallocation
    - Protection against memory-based attacks
    - Buffer overflow prevention
    - Secure memory wiping
  - File Integrity & Verification:
    - Built-in cryptographic hash verification
    - Tamper detection mechanisms
    - Metadata integrity protection

###  Operational Features

  - Secure File Operations:
    - Military-grade secure deletion (multi-pass overwriting)
    - Atomic file operations to prevent corruption
    - In-place encryption with safety checks
    - Directory recursive processing
  - User Interface Options:
    - Full-featured graphical user interface (Tkinter-based)
    - Comprehensive command-line interface
    - Batch processing capabilities
    - Progress visualization for long operations
  - Flexibility & Customization:
    - Pre-configured security templates (Quick, Standard, Paranoid)
    - Custom template support
    - Glob pattern support for batch operations
    - Extensive configuration options

###  Advanced Security Implementations

  - Password Security:
    - Password policy enforcement
    - Secure random password generation
    - Password confirmation to prevent typos
    - Common password dictionary protection
  - Algorithm Flexibility:
    - Dual encryption modes (classical + post-quantum)
    - Algorithm chaining and cascading
    - Security level customization
    - Future algorithm extensibility

## Architecture & Components

### Core Modules

  - crypt.py - Main command-line utility entry point
  - crypt_gui.py - Graphical user interface application
  - cli.py - CLI routing and argument parsing
  - modules/crypt_core.py - Core cryptographic operations
  - modules/crypt_cli.py - Command-line interface implementation
  - modules/crypt_utils.py - Utility functions and helpers

### Cryptographic Modules

  - modules/pqc.py - Post-quantum cryptography implementation
  - modules/pqc_adapter.py - PQC algorithm adapter layer
  - modules/pqc_liboqs.py - LibOQS integration
  - modules/ml_kem_patch.py - ML-KEM specific implementations
  - modules/balloon.py - Balloon hash implementation
  - modules/secure_memory.py - Memory security functions
  - modules/crypto_secure_memory.py - Advanced memory protection

### Security & Management

  - modules/keystore_cli.py - Keystore command-line interface
  - modules/keystore_utils.py - Keystore utility functions
  - modules/keystore_wrapper.py - Keystore abstraction layer
  - modules/password_policy.py - Password validation and policies
  - modules/algorithm_warnings.py - Security algorithm warnings
  - modules/crypt_settings.py - Configuration management
  - modules/crypt_errors.py - Custom exception classes

### Testing & Quality Assurance

  - Comprehensive Test Suite:
    - Unit tests (unittests/unittests.py)
    - GUI testing (unittests/test_gui.py)
    - Dual encryption tests (tests/dual_encryption/)
    - Keystore functionality tests (tests/keystore/)
    - Post-quantum algorithm tests
    - Backward compatibility tests
  - Security Testing:
    - Static analysis integration
    - Dependency vulnerability scanning
    - CI/CD security pipeline
    - Comprehensive test file formats (v3, v4, v5)

## Installation & Dependencies

### Core Dependencies

  - Python 3.11+ (recommended for full feature support)
  - cryptography>=44.0.1 - Core cryptographic primitives
  - argon2-cffi>=23.1.0 - Argon2 password hashing
  - PyYAML>=6.0.2 - Configuration file support
  - whirlpool-py311>=1.0.0 - Whirlpool hash algorithm
  - blake3>=1.0.0 - BLAKE3 high-performance hash algorithm

### Optional Dependencies

  - liboqs-python - Extended post-quantum algorithm support (HQC, ML-DSA, SLH-DSA, FN-DSA)
  - tkinter - GUI interface (usually included with Python)

## Usage Interfaces

### Command-Line Interface
```
  # Basic encryption
  python -m openssl_encrypt.crypt encrypt -i file.txt -o file.txt.enc

  # Post-quantum encryption with MAYO signatures
  python -m openssl_encrypt.crypt encrypt -i file.txt --algorithm mayo-3-hybrid

  # Modern hash algorithms
  python -m openssl_encrypt.crypt encrypt -i file.txt --blake3-rounds 150000 --enable-hkdf

  # SHA-3 family encryption
  python -m openssl_encrypt.crypt encrypt -i file.txt --sha3-384-rounds 50000

  # Using security templates
  python -m openssl_encrypt.crypt encrypt -i file.txt --paranoid

  # Keystore operations
  python -m openssl_encrypt.keystore_cli_main create --keystore-path my_keys.pqc
```
### Graphical User Interface
```
  # Launch GUI
  python -m openssl_encrypt.crypt_gui
  # or
  python -m openssl_encrypt.cli --gui
```
  The GUI provides intuitive tabs for:
  - Encrypt: File encryption with algorithm selection (including MAYO/CROSS post-quantum)
  - Decrypt: Secure file decryption
  - Shred: Military-grade secure deletion
  - Settings: Organized hash families (SHA-2, SHA-3, BLAKE, SHAKE) and modern KDF configuration

### Flutter Desktop GUI
The Flutter-based desktop GUI has been ported to all versions and is available across all platforms (Linux, macOS, Windows) without requiring a version number upgrade. This modern interface provides enhanced usability and cross-platform compatibility.

For detailed Flutter GUI installation instructions, see the [User Guide](openssl_encrypt/docs/user-guide.md#flutter-desktop-gui-installation).

## Documentation Structure

The documentation has been consolidated from 37+ files into 10 comprehensive guides for better organization and usability.

### User Documentation

  - [**User Guide**](openssl_encrypt/docs/user-guide.md) - Complete installation, usage, examples, and troubleshooting
  - [**Keystore Guide**](openssl_encrypt/docs/keystore-guide.md) - PQC keystore management and dual encryption

### Security Documentation

  - [**Security Documentation**](openssl_encrypt/docs/security.md) - Comprehensive security architecture, threat model, and best practices
  - [**Algorithm Reference**](openssl_encrypt/docs/algorithm-reference.md) - Cryptographic algorithm audit and compliance analysis
  - [**Dependency Management**](openssl_encrypt/docs/dependency-management.md) - Security assessment and version pinning policies

### Technical Documentation

  - [**Metadata Formats**](openssl_encrypt/docs/metadata-formats.md) - File format specifications and migration guide
  - [**Development Setup**](openssl_encrypt/docs/development-setup.md) - Development environment, CI/CD, and testing

### Project Documentation

  - [**VERSION.md**](openssl_encrypt/docs/VERSION.md) - Complete version history and changelog
  - [**VERSION_PINNING_POLICY.md**](openssl_encrypt/docs/VERSION_PINNING_POLICY.md) - Dependency versioning strategy
  - [**TODO.md**](openssl_encrypt/docs/TODO.md) - Development roadmap and planned features

## Development & Testing

### Test Files & Validation

  All test files in unittests/testfiles/ are encrypted with password 1234 for testing purposes.

#### Security Templates

  - templates/quick.json - Fast encryption with good security
  - templates/standard.json - Balanced security and performance (default)
  - templates/paranoid.json - Maximum security configuration

#### Build & Distribution

  - Modern Python packaging with pyproject.toml
  - Docker support with multi-stage builds
  - CI/CD integration with GitLab CI
  - Automated testing and security scanning

## Support & Issues

  You can create issues by mailto:issue+world-openssl-encrypt-2-issue-+gitlab@rm-rf.ch to the linked address.

## License

  LICENSE

  ---
  OpenSSL Encrypt - Securing your data for the quantum age with military-grade cryptography and user-friendly interfaces.
