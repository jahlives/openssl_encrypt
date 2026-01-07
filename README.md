# OpenSSL Encrypt

A Python-based file encryption tool with modern ciphers, post-quantum algorithms, and defense-in-depth key derivation.

## History

The project is historically named `openssl-encrypt` because it once was a Python script wrapper around OpenSSL. That approach stopped working with recent Python versions, so I did a complete rewrite in pure Python using modern ciphers and hashes. The project name is a “homage” to its roots

---
## Installation

To install follow the [guide](https://github.com/jahlives/openssl_encrypt/wiki/INSTALLATION)

---

## Ethical Commitment & Usage Restrictions

This project is committed to the protection of human rights and the prevention of mass surveillance. To reflect these values, it is licensed under the **Hippocratic License 2.1**.

While the source code is public, usage is subject to strict ethical conditions. We prioritize human rights over traditional "neutral" open-source definitions.

### Prohibited Use Cases
By using this software, you agree that it shall **not** be used for:

* **Violations of Human Rights:** Usage by any entity that undermines the [UN Universal Declaration of Human Rights](https://github.com/jahlives/openssl_encrypt/blob/main/LICENSE#L51) is strictly prohibited (See [License Section 2.1](https://github.com/jahlives/openssl_encrypt/blob/main/LICENSE#L51)).
* **Mass Surveillance:** The software may not be used for bulk, warrantless monitoring or data collection (See [License Section 2.2.a](https://github.com/jahlives/openssl_encrypt/blob/main/LICENSE#L58)).
* **Government Intelligence Agencies:** Usage by agencies (such as NSA, GCHQ, etc.) or their contractors for offensive cyber operations or domestic spying is not permitted under this license.
* **Military & Weapons:** Usage by or for the defense industry, specifically for the development of lethal weaponry, targeting systems, or military-grade surveillance equipment (See [License Section 2.2](https://github.com/jahlives/openssl_encrypt/blob/main/LICENSE#L58)).


### Why this License?
Technological tools are not neutral. We believe that encryption should empower individuals, not oppressive systems. The **Hippocratic License** creates a legal barrier that prevents the integration of this code into software stacks used for surveillance and harm.

> **Note:** Because of these ethical protections, this project is considered **Ethical Source**, not "Open Source" according to the OSI definition, as we intentionally restrict usage for harmful purposes.

> "The Software shall be used for Good, not Evil." — *Inspired by the JSON License & HL 2.1*
---

## Documentation & Security Architecture

For deep-dives into the cryptographic design and security policies of this project, please refer to the specialized documentation in the `docs/` folder:

* **[Technical Architecture](openssl_encrypt/docs/architecture.md)**: Detailed explanation of the Hybrid PQC-flow, the Hardened KDF Chain (Argon2id + RandomX), and the AEAD Metadata Binding.
* **[Security Policy](openssl_encrypt/docs/security.md)**: Information on our "Defense in Depth" strategy, anti-oracle policies, and how to responsibly disclose vulnerabilities.

### Key Security Features at a Glance:
* **Post-Quantum Ready**: Hybrid encryption using NIST-standardized KEMs (HQC, CROSS, MAYO).
* **Deterministic AEAD**: AES-SIV support for maximum protection against nonce-misuse.
* **Metadata Integrity**: Cryptographic binding of headers to prevent tampering (on AEAD-supported ciphers).
* **Hardware-Resistant KDF**: Sequential Argon2id and RandomX hashing to neutralize ASIC/GPU brute-force clusters.
---
## What's New in v1.4.0

### 🚨 CRITICAL SECURITY UPDATE - Format Version 9

**SECURITY ADVISORY 2026-01** - This release contains a critical security fix for multi-round KDF configurations.

**Vulnerability**: Format versions ≤8 used predictable salt derivation that allowed attackers to precompute all round salts from plaintext metadata, enabling optimized rainbow table attacks against multi-round KDF configurations (CVSSv3 Score: 8.1 - High).

**Fix**: Format Version 9 implements secure chained salt derivation where each round uses the previous round's output as salt, forcing sequential computation and preventing precomputation attacks.

**Action Required**:
- ✅ **New encryptions automatically use v9** (secure)
- ⚠️ **Re-encrypt ALL files encrypted with format version < v9 OR code version < 1.4.0**
- ✅ **Backward compatible** - v8 and below files can still be decrypted

**Affected**: All files encrypted with metadata format versions v3-v8 or openssl_encrypt versions < 1.4.0, especially files with multi-round KDF (rounds > 1) or weak/medium passwords.

See [docs/security.md](openssl_encrypt/docs/security.md) and [docs/metadata-formats.md](openssl_encrypt/docs/metadata-formats.md) for complete details.

---

### Format Version 9: Secure Chained Salt Derivation

**Critical security fix** addressing CVE-2026-01 vulnerability in multi-round KDF implementations.

- **Security Impact**: Prevents precomputation attacks on multi-round KDF configurations
- **Implementation**: Chained salt derivation using previous round's output as next round's salt
- **Backward Compatible**: v8 and below files decrypt correctly with automatic format detection
- **Affected Components**: All multi-round KDF/hash functions (Argon2, PBKDF2, Scrypt, Balloon, HKDF, BLAKE3, BLAKE2b, SHAKE-256)
- **Mitigation**: Automatic upgrade for new encryptions; **re-encryption recommended for ALL files with format version < v9 or encrypted with code version < 1.4.0**
- **Format Versions v3-v8**: Deprecated immediately (read-only support maintained)

**Technical Details**:
```python
# VULNERABLE (v8): Predictable salt derivation
round_salt = SHA256(base_salt + str(round_num)).digest()[:16]

# SECURE (v9): Chained salt derivation
round_salt = previous_round_output[:16]
```

**References**:
- Security Advisory: [docs/security.md](openssl_encrypt/docs/security.md#advisory-2026-01)
- Technical Specification: [docs/metadata-formats.md](openssl_encrypt/docs/metadata-formats.md#version-9-specification)
- Test Coverage: `openssl_encrypt/unittests/test_salt_derivation_versions.py`

---

### Cascade Encryption (Multi-Layer Defense)

Sequential encryption using multiple cipher algorithms with chained HKDF key derivation.

- Attacker must break all ciphers to decrypt data
- Minimum 2 ciphers required, supports unlimited cascade depth
- Each layer adds entropy to the next layer's key derivation
- CLI support: `--cascade "aes-256-gcm,chacha20-poly1305,xcha-poly1305"`
- Automatic cipher diversity validation
- New metadata format V8

**Example:**
```bash
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --cascade "aes-256-gcm,chacha20-poly1305,xcha-poly1305"
```

### Threefish Post-Quantum Ciphers

Rust-based implementation of Threefish AEAD ciphers with memory-hard construction resistant to quantum attacks.

- Threefish-512: 256-bit post-quantum security level
- Threefish-1024: 512-bit post-quantum security level
- Native AEAD mode with embedded nonce
- Maturin-based Rust/Python integration

### Post-Quantum Keyserver

FastAPI-based keyserver for public key distribution with PostgreSQL backend.

- ML-DSA signature verification for uploaded keys
- Public key upload, search, and revocation endpoints
- Bearer token authentication, rate limiting, CORS protection
- Docker deployment with liboqs 0.12.0
- Available at: https://keyserver.rm-rf.ch

### Privacy-Preserving Telemetry

Opt-in anonymous telemetry infrastructure with user consent and data minimization.

- Anonymous client identifiers
- Configurable data collection scopes
- PostgreSQL backend with FastAPI REST API
- Docker deployment with automated migrations
- Available at: https://telemetry.rm-rf.ch

### Pepper Storage Plugin

Client plugin for secure pepper storage with password hardening and mTLS authentication.

- Client-side encrypted pepper storage (server never sees plaintext)
- TOTP 2FA with QR code generation for destructive operations
- Deadman switch with configurable check-in intervals and grace periods
- Panic wipe for emergency pepper deletion (all or single pepper)
- mTLS authentication with self-signed CA (client certificates required)
- Profile management with access tracking
- OPT-IN by default (disabled until explicitly enabled)
- Configuration: `~/.openssl_encrypt/plugins/pepper.json`

### Integrity Verification Plugin

Client plugin for encrypted file metadata hash verification with mTLS authentication.

- Store SHA-256 hashes of encrypted file metadata on remote server
- Verify file integrity before decryption (detect tampering)
- Batch verification support (up to 100 files per request)
- Tamper detection with comprehensive audit logging
- mTLS authentication with self-signed CA (client certificates required)
- Profile management and verification statistics
- OPT-IN by default (disabled until explicitly enabled)
- Configuration: `~/.openssl_encrypt/plugins/integrity.json`

### Identity-Based Asymmetric Encryption

Enhanced asymmetric key handling with improved format and HSM integration.

- Updated asymmetric encryption format (Format V7)
- KEM-based password wrapping using ML-KEM for post-quantum security
- Identity management system for recipient-based encryption
- Seamless integration with HSM-protected identities
- Skip interactive prompts in non-TTY environments

### Algorithm Registry System

Centralized cryptographic algorithm registration and validation framework.

- Cipher Registry: 12+ symmetric encryption algorithms
- Hash Registry: 15+ cryptographic hash functions
- KDF Registry: 8 key derivation functions
- KEM Registry: 9 Key Encapsulation Mechanisms (Kyber, ML-KEM, HQC)
- Signature Registry: 15 post-quantum signature algorithms
- CLI command: `crypt list-algorithms`
- Security level indicators and validation

### HSM Integration Improvements

- CLI arguments for HSM-protected identity creation: `--hsm`, `--hsm-slot`, `--hsm-pin`
- HSM_ONLY identities skip password prompts during encryption/decryption
- Automatic HSM identity detection with `--with-key`
- Save/load HSM identities without password requirements

### Security Enhancements

- SecureBytes implementation across all cryptographic registries (KDF, Cipher, Signature, KEM)
- Automatic zeroing of sensitive data after use
- Thread-safe secure memory operations
- SECURITY.md policy added to all 20 branches with vulnerability reporting guidelines
- PGP key: C8E4 C58E 83AB B314 74C0 E108 0271 3C63 792B 8986
- 48-hour initial response commitment for security issues

### Performance & Testing

- Modularized test suite with domain-specific organization
- Parallel test execution with high-CPU runner tags
- Optimized KDF parameters for faster CI/CD
- Test duration diagnostics

### Infrastructure

- Rust extension integration via Maturin build system
- Docker multi-stage builds with liboqs 0.12.0
- Enhanced Flatpak build with Threefish wheel handling
- CI/CD pipeline improvements

### Unified Server Architecture

Modular FastAPI server with dual authentication system supporting both public and private modules.

**Public Modules (JWT Authentication):**
- Keyserver: Post-quantum public key distribution
- Telemetry: Privacy-preserving usage statistics

**Private Modules (mTLS Authentication with Self-Signed CA):**
- **Pepper Module**: Secure pepper storage for password hardening
  - Client-side encrypted pepper storage (20 endpoints)
  - TOTP 2FA with QR code generation
  - Deadman switch with configurable check-in intervals
  - Panic wipe for emergency pepper deletion
  - Auto-registration on first mTLS connection
  - Database: 5 tables (clients, peppers, deadman, panic log, TOTP backup codes)

- **Integrity Module**: Encrypted file metadata hash verification
  - SHA-256 hash storage for encrypted file metadata (12 endpoints)
  - Integrity violation detection with audit logging
  - Batch verification support (up to 100 files)
  - Statistics tracking (success rate, verification counts)
  - Auto-registration on first mTLS connection
  - Database: 3 tables (clients, hashes, verification log)

**Security Features:**
- Self-signed CA requirement (public CAs rejected)
- Certificate fingerprint authentication (SHA-256)
- Trusted proxy IP validation
- Comprehensive audit logging
- Automated certificate management scripts

**Deployment:**
- Docker Compose with PostgreSQL backend
- Nginx reverse proxy support (recommended)
- Direct mTLS mode available
- Helper scripts: `setup_ca.sh`, `create_client_cert.sh`
- Full documentation: `openssl_encrypt_server/docs/MTLS_SETUP.md`

### Flutter GUI Enhancements

Complete overhaul of the desktop GUI with advanced cryptographic features and improved user experience.

**Cascade Encryption UI:**
- Multi-cipher selection interface with diversity validation
- Sub-group organization for algorithm categories
- Visual chain preview showing encryption layers
- Integrated into File Crypto, Text Crypto, and Batch Operations tabs

**Asymmetric Encryption UI:**
- Identity Management screen with create/import/export functionality
- Recipient selection for multi-recipient encryption
- HSM integration (YubiKey Challenge-Response, FIDO2/WebAuthn)
- Real-time YubiKey touch prompt display
- ML-KEM/ML-DSA key pair generation and management

**Network Plugin Configuration:**
- Remote Pepper Plugin settings with mTLS certificate management
- Integrity Plugin configuration with verification options
- Keyserver Plugin setup with bearer token authentication
- Visual feedback for plugin status and connectivity

**Algorithm Enhancements:**
- Enhanced algorithm picker with grouped display (Classical Symmetric, Post-Quantum, AEAD)
- PQC algorithms displayed in Information Tab
- Support for Threefish-512 and Threefish-1024 ciphers
- Format version 7 and 8 support in metadata viewer

**User Experience:**
- Steganography configuration panel in encryption tab
- Force password option for workflow automation
- Default input type set to file mode
- Improved status messages and error handling
- Progress indicators for long-running operations

**Flatpak Distribution:**
- Complete CI/CD pipeline with automated builds
- Incremental caching for faster compilation
- OSTree repository integration
- Available on Flathub (pending approval)

### Backward Compatibility

- Compatible with v3, v4, v5, v6, v7, and v8 encrypted files
- Automatic format detection and migration
- V3-V8 metadata formats deprecated due to security vulnerability (read-only support maintained)
- V9 metadata format (current) with secure chained salt derivation
- **Re-encryption strongly recommended for ALL files with format version < v9 or encrypted with code version < 1.4.0**
---
## Known Issues
### HQC Support in v1.2.x

**Note:** HQC (Hamming Quasi-Cyclic) post-quantum cryptography is not functional in v1.2.x releases due to fork-safety issues in liboqs on certain AMD64 systems. Files encrypted with HQC algorithms (hqc-128, hqc-192, hqc-256) cannot be decrypted reliably in these versions.

- ✅ **Other PQC algorithms work correctly**: Kyber/ML-KEM, Dilithium, Falcon, SPHINCS+, and all other supported post-quantum algorithms function as expected in v1.2.x
- ✅ **HQC fully supported in v1.3.0+**: The issue has been resolved in version 1.3.0 and later through improved multiprocessing handling

**Recommendation:** If you need to encrypt or decrypt files using HQC algorithms, please upgrade to version 1.3.0 or later.

**For v1.2.x users:** If you have files encrypted with HQC, you can:
1. Upgrade to v1.3.0+ to decrypt them
2. Use a different system where the fork-safety issue doesn't occur
3. Re-encrypt important files using Kyber/ML-KEM instead (recommended for long-term compatibility)
### Incomplete AEAD Metadata Binding (Versions < 1.3.0)

  **Issue**: In versions prior to 1.3.0, AEAD algorithms (AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, AES-SIV, AES-OCB3, XChaCha20-Poly1305, and all PQC hybrid variants) pass `None` for the Additional Authenticated Data (AAD) parameter, despite documentation indicating metadata is cryptographically bound to the ciphertext.

  **Security Impact**: Low - The encryption itself remains secure. Metadata is already cryptographically bound through the key derivation chain, meaning any tampering causes decryption failure. However, without AAD, tampering detection is delayed until after both KDF operations and decryption attempts complete.

  **Attack Scenarios**:
  - An attacker with write access to encrypted files can tamper with metadata
  - Modified metadata will cause decryption to fail, but only after processing
  - No data confidentiality breach is possible
  - Potential DoS vector: modifying the `rounds` parameter forces expensive KDF operations before failure is detected

  **Recommendation**: Upgrade to version 1.3.0 or later, which implements proper AAD binding for earlier tampering detection. Note that AAD does not eliminate the DoS risk, as metadata parsing and KDF execution occur before AAD validation.

  **Workaround**: No workaround needed for data security. To mitigate DoS risks, ensure file permissions prevent unauthorized write access to encrypted files.
---
## Security Architecture

### Chained Key Derivation

This tool uses a chained hash/KDF architecture where each round’s output determines the next round’s salt:

```
Password + Salt₀ → KDF₁ → Result₁ → Salt₁ = f(Result₁) → KDF₂ → Result₂ → ... → Final Key
```

**Design Properties:**

- **Sequential Dependency**: Each round requires the previous round’s result
- **Dynamic Salting**: Salts are derived from previous outputs, not predictable in advance
- **Memory-Hard Functions**: Argon2 and Balloon hashing require significant memory per attempt

### Attack Resistance

The chained architecture provides several security properties:

|Attack Vector           |Mitigation                                              |
|------------------------|--------------------------------------------------------|
|GPU/ASIC parallelization|Sequential dependency forces single-threaded computation|
|Rainbow tables          |Dynamic per-round salts prevent precomputation          |
|Time-memory trade-offs  |Cannot cache intermediate results across attempts       |
|Quantum key recovery    |Hybrid PQC modes (ML-KEM, HQC) for key encapsulation    |

### Computational Cost Estimates

|Password Entropy         |KDF Configuration|Time/Attempt|Brute-Force Estimate*|
|-------------------------|-----------------|------------|---------------------|
|50 bits (8 random chars) |Balloon ×5       |~40s        |~10²² years          |
|60 bits (10 random chars)|Balloon ×5       |~40s        |~10²⁵ years          |
|80 bits (13 random chars)|Balloon ×5       |~40s        |~10³¹ years          |

*Estimates assume: 95-character set, uniformly random password, single-threaded attack, no implementation flaws. Actual security depends on password quality and operational security.

### Security Considerations

- Strong passwords (12+ random characters) make brute-force computationally infeasible
- Sequential chaining prevents parallelization of key derivation
- Post-quantum algorithms provide resistance against quantum key-recovery attacks
- **Limitations**: Implementation bugs, side-channel attacks, weak passwords, or compromised systems remain potential risks. No cryptographic system provides absolute guarantees.

### Security Review

The v1.3.0 codebase received an independent security review:

- **Score**: 8.8/10
- **Critical/High findings**: 0
- **Medium findings**: 3 (defense-in-depth improvements, not blocking)
- **Dependencies**: pip-audit clean, zero known vulnerabilities

See <SECURITY_REVIEW_v1.3.0.md> for the full report.
---
## Features

### Symmetric Encryption

Modern AEAD (Authenticated Encryption with Associated Data) ciphers:

|Algorithm         |Status        |Notes                              |
|------------------|--------------|-----------------------------------|
|AES-GCM           |✅ Recommended |NIST standard, hardware-accelerated|
|AES-GCM-SIV       |✅ Recommended |Nonce-misuse resistant             |
|ChaCha20-Poly1305 |✅ Recommended |Software-optimized, constant-time  |
|XChaCha20-Poly1305|✅ Recommended |Extended nonce (192-bit)           |
|AES-SIV           |✅ Supported   |Deterministic encryption           |
|Fernet            |✅ Default     |AES-128-CBC + HMAC, simple API     |
|AES-OCB3          |⚠ Decrypt only|Deprecated in v1.2.0               |
|Camellia          |⚠ Decrypt only|Deprecated in v1.2.0               |

### Post-Quantum Cryptography

Hybrid encryption combining classical symmetric ciphers with post-quantum KEMs:

**NIST Standardized:**

- **ML-KEM** (FIPS 203): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **Kyber**: Kyber-512, Kyber-768, Kyber-1024 (original implementation)

**NIST Selected (2025):**

- **HQC**: HQC-128, HQC-192, HQC-256

**Signature Schemes (for authenticated encryption):**

- **MAYO**: MAYO-1, MAYO-2, MAYO-3, MAYO-5
- **CROSS**: CROSS-R-SDPG-1, CROSS-R-SDPG-3, CROSS-R-SDPG-5

### Key Derivation Functions

|KDF     |Type              |Status        |Use Case                    |
|--------|------------------|--------------|----------------------------|
|Argon2id|Memory-hard       |✅ Recommended |Default for password hashing|
|Balloon |Memory-hard       |✅ Recommended |Alternative to Argon2       |
|Scrypt  |Memory-hard       |✅ Supported   |GPU-resistant               |
|HKDF    |Extract-and-expand|✅ Supported   |Key expansion               |
|RandomX |CPU-hard          |✅ Supported   |Anti-ASIC (from Monero)     |
|PBKDF2  |Iterative         |⚠ Decrypt only|Deprecated in v1.2.0        |

### Hash Functions

For key derivation chaining:

- **SHA-2 Family** (FIPS 180-4): SHA-512, SHA-384, SHA-256, SHA-224
- **SHA-3 Family** (FIPS 202): SHA3-512, SHA3-384, SHA3-256, SHA3-224
- **BLAKE Family**: BLAKE2b, BLAKE3
- **SHAKE** (XOF): SHAKE-256, SHAKE-128
- **Legacy**: Whirlpool (decrypt only in v1.2.0+)

### Additional Security Features

**Memory Protection:**

- Secure memory allocation with mlock/VirtualLock
- Multi-pass memory wiping (random, 0xFF, 0xAA, 0x55, 0x00)
- Constant-time operations for timing attack resistance

**File Operations:**

- Multi-pass secure deletion (configurable passes)
- Atomic file operations
- Symlink attack protection (O_NOFOLLOW in D-Bus service)

**Key Management:**

- Encrypted keystore for PQC keys
- Key rotation support
- Dual encryption (password + keystore)

**Operational:**

- Password policy enforcement
- Common password dictionary check
- Audit logging
---
## Installation

### Flatpak (Recommended)

The easiest way to install with all dependencies included (Python, liboqs, liboqs-python, Flutter GUI):

```bash
# Add the repository
flatpak remote-add --if-not-exists openssl-encrypt https://flatpak.rm-rf.ch/openssl-encrypt.flatpakrepo

# Install latest stable version
flatpak install openssl-encrypt com.opensslencrypt.OpenSSLEncrypt

# Run the application
flatpak run com.opensslencrypt.OpenSSLEncrypt --help
```

**Benefits:**
- All dependencies pre-installed (including liboqs and Python bindings)
- Flutter Desktop GUI included
- Sandboxed environment
- Automatic updates
- Works on any Linux distribution

**Build Flatpak locally (alternative to using the repository):**

```bash
# Clone the repository
git clone https://github.com/jahlives/openssl_encrypt.git
cd openssl_encrypt/flatpak

# Build and install locally (includes Flutter GUI)
./build-flatpak.sh --build-flutter --local-install

# Or install as development branch (recommended for testing, runs parallel to stable)
./build-flatpak.sh --build-flutter --dev-install

# Run the locally installed flatpak
flatpak run com.opensslencrypt.OpenSSLEncrypt
```

**Build options:**
- `--build-flutter` - Build Flutter Desktop GUI before packaging
- `--local-install` - Install as stable branch (overwrites production)
- `--dev-install` - Install as development branch (parallel to production, recommended)
- `-f, --force` - Force clean build cache

See `flatpak/README.md` for detailed build instructions.

### PyPI / Source Installation

**Requirements:**
- Python 3.11+ (3.12 or 3.13 recommended)

**Core Dependencies:**
```
cryptography>=44.0.1
argon2-cffi>=23.1.0
PyYAML>=6.0.2
blake3>=1.0.0
```

**Optional Dependencies:**
```
liboqs-python          # Extended PQC support (HQC, ML-DSA, etc.)
                       # Requires liboqs (https://github.com/open-quantum-safe/liboqs)
tkinter                # GUI (usually included with Python)
```

**Install:**

```bash
# From PyPI (when available)
pip install openssl-encrypt

# From source
git clone https://github.com/jahlives/openssl_encrypt.git
cd openssl_encrypt
pip install -e .
```

**Note:** For full post-quantum support (HQC, ML-DSA), you need to manually install liboqs and liboqs-python. The Flatpak version includes these by default.
---
## Usage

### Command-Line Interface

```bash
# Basic encryption (Fernet, default settings)
python -m openssl_encrypt.crypt encrypt -i file.txt -o file.txt.enc

# AES-GCM with Argon2
python -m openssl_encrypt.crypt encrypt -i file.txt -o file.txt.enc \
    --algorithm aes-gcm \
    --enable-argon2 --argon2-rounds 3

# Post-quantum hybrid encryption
python -m openssl_encrypt.crypt encrypt -i file.txt -o file.txt.enc \
    --algorithm ml-kem-768-hybrid

# Using security templates
python -m openssl_encrypt.crypt encrypt -i file.txt --quick      # Fast, good security
python -m openssl_encrypt.crypt encrypt -i file.txt --standard   # Balanced (default)
python -m openssl_encrypt.crypt encrypt -i file.txt --paranoid   # Maximum security

# Decryption (algorithm auto-detected from metadata)
python -m openssl_encrypt.crypt decrypt -i file.txt.enc -o file.txt

# Secure file deletion
python -m openssl_encrypt.crypt shred -i sensitive.txt --passes 3

# Generate random password
python -m openssl_encrypt.crypt generate --length 20
```

### Graphical User Interface

```bash
python -m openssl_encrypt.crypt_gui
# or
python -m openssl_encrypt.cli --gui
```

### Flutter Desktop GUI

Cross-platform GUI available for Linux, macOS, and Windows. See the [User Guide](openssl_encrypt/docs/user-guide.md#flutter-desktop-gui-installation) for installation.

### Keystore Operations

```bash
# Create keystore
python -m openssl_encrypt.keystore_cli_main create --keystore-path keys.pqc

# Generate PQC keypair
python -m openssl_encrypt.keystore_cli_main generate --keystore-path keys.pqc \
    --algorithm ml-kem-768

# Encrypt with keystore
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --keystore keys.pqc --key-id my-key
```
---
## Configuration Templates

Pre-configured security profiles in `templates/`:

|Template       |Use Case                      |KDF                    |Rounds|Time |
|---------------|------------------------------|-----------------------|------|-----|
|`quick.json`   |Fast encryption, good security|Argon2                 |1     |~1s  |
|`standard.json`|Balanced (default)            |Argon2 + SHA3          |3     |~5s  |
|`paranoid.json`|Maximum security              |Argon2 + Balloon + SHA3|10+   |~60s+|
---
## Project Structure

```
openssl_encrypt/
├── crypt.py                 # CLI entry point
├── crypt_gui.py             # Tkinter GUI
├── modules/
│   ├── crypt_core.py        # Core encryption/decryption
│   ├── crypt_cli.py         # CLI implementation
│   ├── crypt_utils.py       # Utilities (shred, password gen)
│   ├── crypt_errors.py      # Exception classes
│   ├── secure_memory.py     # Memory protection
│   ├── secure_ops.py        # Constant-time operations
│   ├── balloon.py           # Balloon hashing
│   ├── randomx.py           # RandomX KDF
│   ├── pqc.py               # Post-quantum crypto
│   ├── pqc_adapter.py       # PQC algorithm adapter
│   ├── keystore_cli.py      # Keystore management
│   ├── password_policy.py   # Password validation
│   ├── dbus_service.py      # D-Bus integration (Linux)
│   └── plugin_system/       # Plugin sandbox
├── unittests/
│   ├── unittests.py         # Main test suite (950+ tests)
│   └── testfiles/           # Test vectors (password: 1234)
├── templates/               # Security profiles
└── docs/                    # Documentation
```
---
## Documentation

|Document                                                          |Description                                   |
|------------------------------------------------------------------|----------------------------------------------|
|[User Guide](openssl_encrypt/docs/user-guide.md)                  |Installation, usage, examples, troubleshooting|
|[Keystore Guide](openssl_encrypt/docs/keystore-guide.md)          |PQC key management, dual encryption           |
|[Security Documentation](openssl_encrypt/docs/security.md)        |Architecture, threat model, best practices    |
|[Algorithm Reference](openssl_encrypt/docs/algorithm-reference.md)|Cipher and KDF specifications                 |
|[Metadata Formats](openssl_encrypt/docs/metadata-formats.md)      |File format specs (v3, v4, v5)                |
|[Development Setup](openssl_encrypt/docs/development-setup.md)    |Contributing, CI/CD, testing                  |
---
## Testing

```bash
# Run all tests
pytest openssl_encrypt/unittests/

# Run with coverage
pytest --cov=openssl_encrypt openssl_encrypt/unittests/

# Run specific test class
pytest openssl_encrypt/unittests/unittests.py::TestCryptCore
```

Test files in `unittests/testfiles/` are encrypted with password `1234`.
---
## Support

- **Issues**: [GitHub Issues](https://github.com/jahlives/openssl_encrypt/issues)
- **Email**: issue+world-openssl-encrypt-2-issue-@gitlab.rm-rf.ch
- **Security vulnerabilities**: Email only (not public issues)
---
## License

See <LICENSE> file.

-----

*OpenSSL Encrypt – File encryption with modern ciphers, post-quantum algorithms, and defense-in-depth key derivation.*
