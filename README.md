# OpenSSL Encrypt

A Python-based file encryption tool with modern ciphers, post-quantum algorithms, and defense-in-depth key derivation.

## History

The project is historically named `openssl-encrypt` because it once was a Python script wrapper around OpenSSL. That approach stopped working with recent Python versions, so I did a complete rewrite in pure Python using modern ciphers and hashes. The project name is a “homage” to its ---

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
## What's New in v1.3.0

   Version 1.3.0 delivers security fixes and enterprise-grade hardware security:

  **SECURITY FIX: AEAD Additional Authenticated Data (AAD) Implementation**

  - **Fixed documentation discrepancy**: AEAD algorithms (AES-GCM, ChaCha20-Poly1305, etc.) were passing `None` for the AAD parameter despite documentation claiming metadata was cryptographically bound
  - **Actual impact**: Limited - metadata tampering would fail decryption regardless due to key derivation chain dependency. Without AAD, detection only occurred after both expensive KDF operations and decryption attempts
  - **Resolution**: Proper AAD implementation now binds metadata to ciphertext, enabling detection of tampering through authentication failure
  - **Limitation**: AAD does not prevent DoS attacks - metadata parsing and KDF chain execution (the expensive operations) occur before AAD validation during decryption. An attacker with write access can still modify the `rounds` parameter to trigger resource exhaustion
  - **Affects**: AES-GCM, AES-GCM-SIV, AES-SIV, AES-OCB3, ChaCha20-Poly1305, XChaCha20-Poly1305, and all PQC hybrid variants (24 algorithms total)

  **Key Point**: This fixes an implementation gap where documented behavior didn't match actual behavior. The encryption itself was never vulnerable - the metadata is cryptographically bound through the key derivation chain, ensuring any tampering causes decryption failure. AAD provides better integrity guarantees but cannot prevent DoS via metadata manipulation since the expensive KDF chain executes before AAD validation.

  ### Hardware Security Module (HSM) Support

  - **YubiKey HSM Plugin**: Native support for YubiKey 5 series hardware security modules
  - **PKCS#11 Integration**: Generic HSM support via PKCS#11 interface for enterprise HSMs
  - **Pepper Protection**: Cryptographic peppers stored in tamper-resistant hardware with PIN protection
  - **Plugin Architecture**: Extensible system for additional HSM vendors (Nitrokey, SoftHSM, etc.)
  - **Metadata Format v6**: Enhanced metadata structure with HSM validation and auto-detection

  ### Testing & Quality Assurance

  - Comprehensive test suite (`crypt test`) with fuzzing, side-channel analysis, and benchmarking
  - 960+ tests passing with 8.8/10 security score (independent review)
  - Zero vulnerable dependencies

  ### Security Hardening

  - O_NOFOLLOW symlink attack prevention in D-Bus service
  - Audit logging and debug mode warnings
  - Enhanced validation and tamper detection

  ### Advanced Features

  - Steganography support for covert data transport
  - Enhanced plugin system with process isolation
  - Improved RandomX KDF performance
  - Dual encryption support for PQC keys (keystore + file password)

  ### Backward Compatibility

  - Fully compatible with v3, v4, and v5 encrypted files
  - Automatic format detection and migration
  - **Warning**: Files encrypted with v1.3.0 AEAD algorithms cannot be decrypted by older versions (forward-breaking due to security fix)
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
