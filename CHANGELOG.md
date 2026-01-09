# Changelog

All notable changes to the openssl_encrypt project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-01-07

### 🚨 CRITICAL SECURITY FIX

#### Format Version 9: Secure Chained Salt Derivation
**SECURITY ADVISORY 2026-01** - Addresses critical vulnerability in multi-round KDF salt derivation

- **Vulnerability (CVSSv3 8.1 - High)**: Format versions ≤8 used predictable salt derivation allowing attackers to precompute all round salts from plaintext metadata, enabling optimized rainbow table attacks
- **Fix**: Implemented secure chained salt derivation where each round uses previous round's output as salt
  - **Security Impact**: Forces sequential computation, prevents precomputation attacks
  - **Backward Compatible**: v8 and below files can still be decrypted
  - **Auto-Upgrade**: New encryptions automatically use v9
- **Affected Components**: All multi-round KDF configurations (Argon2, PBKDF2, Scrypt, Balloon, HKDF) and multi-round hash functions (BLAKE3, BLAKE2b, SHAKE-256)
- **Affected Users**: Files with multi-round KDF (rounds > 1), especially with weak/medium passwords
- **Mitigation**: Upgrade to v1.4.0+ and re-encrypt sensitive files
- **References**: See `docs/security.md` and `docs/metadata-formats.md` for complete security advisory

#### Format Version 7 and 9 Unification
**CRITICAL UPDATE** - Unified v7 (from v1.3.4 branch) and v9 (from v1.4.0 branch) implementations

- **Background**: The security fix was independently implemented in two branches:
  - **Version 7**: Introduced in v1.3.4 (releases/1.3.4 branch) with focus on asymmetric encryption
  - **Version 9**: Introduced in v1.4.0 (feature/v1.4.0-development) with multi-feature release
- **Unification**: Both versions now use identical secure chained salt derivation
  - Pattern: `if format_version >= 7 and format_version != 8:`
  - v7 and v9 produce cryptographically identical keys
  - v8 deliberately excluded for backward compatibility
- **Compatibility**: v1.4.0+ correctly decrypts both v7 and v9 files
- **Security**: Both v7 and v9 provide the same security improvements over v8 and below
- **Implementation**: Updated 9 salt derivation locations, 11 keystore integration points
- **Testing**: Comprehensive v7/v9 compatibility tests verify cryptographic equivalence

### Added

#### Flutter GUI Enhancements
- **Cascade Encryption UI**: Complete cascade encryption configuration interface across all crypto tabs
  - Sub-group headers and algorithm organization
  - Multiple cipher selection with diversity validation
  - Integrated into File Crypto, Text Crypto, and Batch Operations tabs
- **Asymmetric Encryption UI**: Full asymmetric encryption interface
  - Identity management screen with create/import/export
  - Recipient selection for multi-recipient encryption
  - HSM integration (YubiKey Challenge-Response)
  - Integrated into all crypto tabs
- **Remote Plugin Integration**: Network plugin configuration in Settings
  - **Remote Pepper Plugin**: mTLS authentication, TOTP 2FA, deadman switch, panic wipe
  - **Integrity Plugin**: File verification with batch support and audit logging
  - **Keyserver Plugin**: Public key distribution with local caching
- **FIDO2/WebAuthn Support**: HSM credential management with YubiKey touch prompts
  - Real-time touch prompt display (PYTHONUNBUFFERED)
  - Credential management screen
  - Integration across encryption/decryption tabs
- **Algorithm Support Additions**:
  - Threefish-512 and Threefish-1024 post-quantum ciphers
  - Enhanced algorithm picker with grouped display
  - PQC algorithms in Information Tab
  - Support for file format versions 7 and 8

#### CLI & Core Features
- **Integrity Verification Flags**: `--integrity` and `--verify-integrity` for remote metadata hash verification
  - Automatic file_id computation from input file path
  - 409 Conflict handling for re-encryption scenarios
  - Integration with remote integrity module via mTLS
- **Pepper Plugin Integration**: Full CLI integration for remote pepper storage
  - Command-line flags for pepper operations
  - TOTP 2FA support for sensitive operations
  - mTLS certificate-based authentication
- **Steganography Options**: Comprehensive steganography configuration in GUI encryption tab
- **Force Password Option**: Added to encryption and decryption tabs for password override scenarios

### Fixed

#### Critical Bug Fixes
- **Threefish Algorithm Support**: Complete implementation of Threefish-512 and Threefish-1024
  - Added key length support (64 bytes for TF-512, 128 bytes for TF-1024)
  - Implemented HKDF key expansion to derive required key lengths
  - Added proper nonce sizes (32 bytes for TF-512, 64 bytes for TF-1024)
  - Added encryption and decryption logic with AAD support
  - Fixed nonce size mapping in `get_nonce_size()` function
- **Pepper Plugin Scoping Errors**: Fixed critical scoping bugs causing 100+ test failures
  - Resolved variable scope issues in pepper client plugin
  - Fixed authentication and storage operations
- **Integrity Plugin Issues**:
  - Fixed 409 Conflict when re-encrypting files with `--integrity` flag
  - Corrected file_id computation to use input file path instead of output
  - Fixed integrity verification hang in Flutter GUI
- **YubiKey Integration**:
  - Fixed YubiKey notification display in GUI
  - Enabled real-time touch prompt display via PYTHONUNBUFFERED
  - Fixed status message overwrites that hid touch prompts
- **HSM Plugin Loading**: Fixed dependency management and plugin initialization

#### Flatpak Improvements
- **CI/CD Pipeline**: Complete Flatpak build and publish automation
  - Automated flatpak-builder with incremental caching
  - Branch-based flatpak branch naming (from setup.py version)
  - OSTree repository caching to avoid 413 errors
  - Restricted jobs to releases branches and tags only
- **Build System Enhancements**:
  - Proper FLATPAK_BRANCH environment variable respect
  - VERSION extraction from setup.py without setuptools import
  - Python dependencies properly declared in manifest
  - Flutter SDK and build dependencies (which, unzip, patchelf)
  - Docker compatibility flags (--disable-rofiles-fuse)
- **Binary Naming**: Corrected desktop binary from openssl_encrypt_mobile to openssl_encrypt
- **Dependency Fixes**: Added certifi and all missing Python dependencies from requirements-prod.txt

#### GUI Fixes
- **Information Tab**:
  - Fixed hash algorithm display (sha224, sha3-224, sha384 filters)
  - Added PQC algorithms to encryption display
- **Algorithm Picker**:
  - Restored missing hash algorithms
  - Fixed Classical Symmetric consolidation
  - Set PQC and other groups to collapsed by default
- **Settings**:
  - Updated Homepage URL to releases/1.4.0 branch
  - Corrected Documentation and Source Code links
  - Default input type changed to file mode

#### Documentation & Infrastructure
- **Security Documentation**: Added comprehensive SECURITY.md with vulnerability reporting policy
- **Installation Guide**: Complete rewrite of INSTALLATION.md with Flatpak integration
- **README Updates**: Installation section and project URL corrections
- **Markdown Fixes**: Corrected formatting in Flatpak documentation sections
- **Command Syntax**: Fixed to use `-i` flag consistently in all examples

### Changed

#### Infrastructure
- **liboqs Upgrade**: Upgraded to liboqs-python 0.12.0 built from source for HQC algorithm support
- **Project URLs**: Updated to GitHub repository in setup.py
- **Version Management**: Bump to 1.4.0 with PEP 440 / PyPI conformant version strings
- **License**: Explicit Hippocratic-3.0 license declaration in setup.py and Flatpak metadata

#### Development & Testing
- **Test Organization**: Consolidated asymmetric test files into main unittests.py
- **Plugin Security**: Refined AST-based plugin validation to allow legitimate file/network operations
- **Coverage**: Added missing CLI arguments to test coverage
- **Code Formatting**: Applied automated Black formatting fixes

### Deprecated

- **Format Version 8**: Deprecated due to security vulnerability (see SECURITY ADVISORY 2026-01)
  - Read support maintained for backward compatibility
  - Write support disabled (encryption creates v9 files only)
  - Deprecation warning issued when decrypting v8 files

### Security

- **Input Validation**: Added salt, key size, and hash iteration validation in `create_key_from_password`
- **Secure Memory**: Enhanced error handling in secure memory operations
- **Test Coverage**: Added comprehensive tests for salt derivation versions (v8 vs v9)
  - Multi-round KDF behavior tests (PBKDF2, Argon2, Scrypt)
  - Hash function multi-round tests (BLAKE3, BLAKE2b, SHAKE-256)
  - Backward compatibility verification
  - Full encryption/decryption roundtrip tests

## [1.4.0-alpha.1] - 2025-12-31

### Added

#### Infrastructure & Deployment
- **Post-Quantum Keyserver System**: FastAPI-based keyserver for public key distribution with ML-DSA signature verification, bearer token authentication, PostgreSQL backend, and Docker deployment support
  - Public key upload/search/revocation endpoints with authenticated operations
  - CORS configuration and rate limiting for production deployment
  - Plugin architecture supporting HSM integration and custom storage backends
  - Docker support with liboqs 0.12.0 including HQC algorithm support
  - Health check and monitoring endpoints
  - Deployed at: https://keyserver.rm-rf.ch

- **Privacy-Preserving Telemetry System**: Opt-in anonymous telemetry infrastructure with comprehensive privacy controls
  - Plugin-based architecture with configurable data collection
  - Client registration and anonymous usage metrics
  - PostgreSQL backend with FastAPI REST API
  - Docker deployment with automated database migrations
  - Privacy-first design with user consent and data minimization
  - Deployed at: https://telemetry.rm-rf.ch

- **Unified Server Architecture**: Modular FastAPI server with dual authentication system supporting both public and private modules
  - JWT authentication for public modules (keyserver, telemetry)
  - mTLS authentication with self-signed CA for private modules (pepper, integrity)
  - Module isolation with independent enable flags and configuration
  - Docker Compose deployment with PostgreSQL backend
  - Nginx reverse proxy support for production deployments

- **Pepper Module (mTLS-Protected)**: Secure pepper storage system for password hardening with TOTP 2FA
  - 20 REST API endpoints for pepper management
  - Client-side encrypted pepper storage (server stores encrypted blobs)
  - TOTP 2FA with QR code generation (pyotp integration)
  - Deadman switch with configurable check-in intervals and grace periods
  - Panic wipe for emergency pepper deletion (all or single pepper)
  - Auto-registration on first mTLS connection
  - 5 database tables: clients, peppers, deadman, panic_log, totp_backup_codes
  - Access tracking (last_accessed_at, access_count)
  - Fernet encryption for TOTP secrets at rest
  - Argon2 hashing for backup codes

- **Integrity Module (mTLS-Protected)**: Encrypted file metadata hash verification system
  - 12 REST API endpoints for hash management and verification
  - SHA-256 hash storage for encrypted file metadata
  - Integrity violation detection with comprehensive audit logging
  - Batch verification support (up to 100 files per request)
  - Statistics tracking (success rate, verification counts, last verification)
  - Auto-registration on first mTLS connection
  - 3 database tables: clients, metadata_hashes, verification_log
  - Tamper detection with detailed mismatch warnings
  - Support for multiple algorithm types (symmetric, hybrid, PQC)

- **mTLS Authentication Infrastructure**: Certificate-based authentication for pepper and integrity modules
  - Self-signed CA requirement (public CAs explicitly rejected)
  - Certificate fingerprint authentication (SHA-256)
  - Proxy mode: Nginx terminates mTLS, passes X-Client-Cert-Fingerprint header
  - Direct mTLS mode: Server terminates TLS on dedicated ports (8444, 8445)
  - Trusted proxy IP validation with configurable network ranges
  - Reusable auth handlers: ProxyAuth and MTLSAuth classes
  - Certificate DN extraction for client identification
  - Automatic certificate fingerprint normalization

- **Certificate Management Tools**: Automated scripts for self-signed CA and client certificate generation
  - `setup_ca.sh`: Create self-signed CA with passphrase-protected private key
  - `create_client_cert.sh`: Generate client certificates signed by CA
  - Certificate validity: 825 days (~2 years, Apple/Google recommended max)
  - Automated certificate bundle creation for distribution
  - SHA-256 fingerprint calculation and normalization
  - Comprehensive documentation in docs/MTLS_SETUP.md
  - Security best practices and troubleshooting guides
  - Scripts in openssl_encrypt_server/scripts/ directory

#### Client Plugins
- **Pepper Storage Plugin**: Client plugin for secure pepper storage with mTLS authentication
  - Client-side encrypted pepper storage (server never sees plaintext peppers)
  - mTLS authentication with client certificates
  - TOTP 2FA integration for destructive operations
  - Deadman switch with configurable check-in intervals
  - Panic wipe functionality (all or single pepper)
  - Profile management with access tracking
  - Configuration: `~/.openssl_encrypt/plugins/pepper.json`
  - OPT-IN by default (enabled=false)
  - Python API: `from openssl_encrypt.plugins.pepper import PepperPlugin, PepperConfig`

- **Integrity Verification Plugin**: Client plugin for encrypted file metadata hash verification
  - Store SHA-256 hashes of encrypted file metadata on remote server
  - Verify file integrity before decryption (tamper detection)
  - Batch verification support (up to 100 files per request)
  - Comprehensive audit logging and statistics tracking
  - mTLS authentication with client certificates
  - Profile management and verification history
  - Utility methods: `compute_metadata_hash()`, `compute_file_id()`
  - Configuration: `~/.openssl_encrypt/plugins/integrity.json`
  - OPT-IN by default (enabled=false)
  - Python API: `from openssl_encrypt.plugins.integrity import IntegrityPlugin, IntegrityConfig`

- **Keyserver Plugin**: Client plugin for post-quantum public key distribution
  - Public key upload, search, and retrieval
  - Local SQLite caching with configurable TTL
  - Bearer token authentication for write operations
  - HTTPS-only connections with timeout configuration
  - Configuration: `~/.openssl_encrypt/plugins/keyserver.json`
  - OPT-IN by default (enabled=false)

- **Telemetry Plugin**: Client plugin for anonymous usage metrics collection
  - Anonymous client identifiers (no personal data)
  - Local SQLite buffering before upload
  - Configurable data collection scopes
  - Background upload with batch processing
  - Full opt-out with data deletion
  - Activation: `--telemetry` flag, `OPENSSL_ENCRYPT_TELEMETRY=1` env, or config
  - OPT-IN by default (disabled)

#### Cryptographic Features
- **Cascade Encryption (Multi-Layer Defense)**: Sequential encryption using multiple cipher algorithms with chained HKDF key derivation
  - Minimum 2 ciphers required, supports unlimited layers
  - Each layer adds entropy to next layer's key derivation
  - Attacker must break ALL ciphers to decrypt data
  - CLI support: `--cascade "aes-256-gcm,chacha20-poly1305,xcha-poly1305"`
  - Automatic cipher diversity validation
  - New metadata format V8 for cascade encryption support

- **Threefish Post-Quantum Ciphers**: Rust-based implementation of Threefish AEAD ciphers
  - Threefish-512 (256-bit post-quantum security level)
  - Threefish-1024 (512-bit post-quantum security level)
  - Memory-hard construction resistant to quantum attacks
  - Native AEAD mode with embedded nonce in ciphertext
  - Maturin-based Rust/Python integration

- **Algorithm Registry System**: Comprehensive cryptographic algorithm registration and validation framework
  - Cipher Registry: 12+ symmetric encryption algorithms with metadata
  - Hash Registry: 15+ cryptographic hash functions
  - KDF Registry: 8 key derivation functions (Argon2, Scrypt, Balloon, HKDF, PBKDF2, RandomX, bcrypt, Fernet)
  - KEM Registry: 9 Key Encapsulation Mechanisms (Kyber, ML-KEM, HQC)
  - Signature Registry: 15 post-quantum signature algorithms (ML-DSA, MAYO, CROSS, Falcon, Dilithium, SPHINCS+)
  - Automatic algorithm validation with security level indicators
  - `crypt list-algorithms` command for browsing available algorithms
  - Integration with configuration wizard and CLI help system

- **HSM-Protected Identity Creation**: Hardware Security Module integration for asymmetric key operations
  - CLI arguments for HSM-protected identity creation: `--hsm`, `--hsm-slot`, `--hsm-pin`
  - HSM_ONLY identities skip password prompts during encryption/decryption
  - Seamless auto-detection when `--with-key` provided
  - Save/load HSM identities without password requirements

#### Testing & Quality Assurance
- **Modularized Test Suite**: Domain-specific test file organization for better parallelization
  - Split CLI tests into 3+ parallel-friendly subclasses
  - Optimized KDF parameters for faster test execution
  - High-CPU GitLab runner tags for improved CI performance
  - Worksteal distribution for dynamic load balancing
  - Comprehensive cascade encryption test coverage

- **Performance Optimizations**: Test suite execution time improvements
  - Reduced KDF rounds in CLI tests (faster execution)
  - Reduced Balloon time_cost in derivation tests
  - Test-only Kyber file optimization
  - Test duration diagnostics for performance monitoring

#### Documentation & Security
- **SECURITY.md Policy**: Comprehensive vulnerability reporting documentation
  - GitHub Security Advisory as preferred reporting method
  - PGP-encrypted email alternative (PGP Key: C8E4 C58E 83AB B314 74C0 E108 0271 3C63 792B 8986)
  - 48-hour initial response commitment
  - Coordinated disclosure practices
  - CVE assignment for critical vulnerabilities
  - Security Hall of Fame for responsible disclosure
  - Added to ALL branches (including EOL releases)

- **Documentation Reorganization**: Cleaned up root directory and organized documentation
  - Moved analysis/audit files to `openssl_encrypt/docs/`
  - Moved test runner scripts to `tests/` directory
  - Removed implementation plan files from repository
  - Consolidated security documentation structure

- **Pre-Commit Hook**: Branch-specific plan file enforcement
  - Auto-remove plan files on main branch
  - Configurable per-branch rules
  - Prevents accidental plan file commits

### Changed

#### Core Features
- **Cascade Encryption Integration**: Full CLI and core module integration
  - Added `--cascade` parameter to encryption commands
  - Support for custom cipher chains with validation
  - JSON schema validation for V7 and V8 metadata formats
  - Cascade variables initialized for all format versions

- **Algorithm Registry Integration**: Replaced hardcoded algorithm lists with registry system
  - CLI helper utilities for registry-based operations
  - Registry-based algorithm validation
  - Improved help text with security level recommendations
  - Configuration wizard integration

- **Identity Management**: Enhanced asymmetric key handling
  - Updated asymmetric encryption format
  - Missing KDF arguments added to subparser for feature parity
  - Skip interactive KDF security prompts in non-TTY environments
  - Improved HSM option handling in identity CLI

#### Build & Dependencies
- **Rust Extension Build**: Integrated Threefish Rust extension into build process
  - Maturin build system for Python/Rust integration
  - Added patchelf for wheel building compatibility
  - CI build step for Threefish extension
  - Flatpak build with proper Threefish wheel handling

- **Docker Infrastructure**: Enhanced Docker builds for server components
  - liboqs 0.12.0 built from source for HQC support
  - Added pkg-config and python3-dev build dependencies
  - Multi-stage Docker builds for optimized images
  - PostgreSQL database integration for both servers

#### Code Quality
- **Security Enhancement**: SecureBytes implementation across all registries
  - KDF registry uses SecureBytes for sensitive data
  - Cipher registry uses SecureBytes for keys (comprehensive implementation)
  - Signature registry uses SecureBytes for secret keys
  - KEM registry uses SecureBytes for sensitive data
  - Comprehensive security audit updates

- **CI/CD Improvements**: Multiple CI pipeline enhancements
  - Docker-based CI support for server components
  - Parallel test execution with loadscope distribution
  - High-CPU runner allocation for faster execution
  - Test duration tracking and diagnostics

### Fixed

#### Critical Issues
- **Stdin Reading Bug**: Resolved decryption failures when reading from stdin
- **CLI Test Failures**: Fixed 2+ CLI test failures related to HSM mocking and argument handling
- **Asymmetric Encryption Tests**: Updated tests for new format compatibility
- **Identity CLI**: Fixed HSM mock issues in identity CLI tests
- **NoneType Comparison**: Removed debug statements causing NoneType comparison errors (fixed 15 tests)

#### Security Fixes
- **RandomX SIGILL Crash**: Prevented RandomX SIGILL crash during test collection in CI
- **Cipher Registry**: Complete SecureBytes implementation across all cipher operations
- **Algorithm Validation**: Fixed auto-detection logic when `--with-key` provided

#### Build System
- **Threefish AEAD Mode**: Fixed Threefish ciphers to embed nonce in ciphertext (like AES-GCM)
- **Flatpak Build**: Cleaned old wheels before Threefish build to prevent conflicts
- **Test Collection**: Use relative paths for test files to prevent CI collection failures

#### Compatibility
- **Metadata V7 Format**: Added quiet and verbose parameters to create_metadata_v7
- **RandomX KDF**: Updated to use correct package structure
- **KDF Arguments**: Fixed missing arguments for proper format compatibility

#### Server Infrastructure
- **SQLAlchemy Reserved Name**: Fixed integrity module INClient model using reserved 'metadata' column name
  - Renamed to 'client_metadata' to avoid SQLAlchemy DeclarativeAPI conflicts
  - Prevents "Attribute name 'metadata' is reserved" error during table creation
- **Environment Protection**: Added .gitignore to openssl_encrypt_server/ to protect sensitive files
  - Excludes .env files from version control
  - Excludes private keys (*.key, *.pem, *.p12, *.pfx)
  - Prevents accidental exposure of credentials and certificates
- **Server Info Endpoint**: Updated /info endpoint to include pepper and integrity module status
  - Shows enabled/disabled status for all four modules (keyserver, telemetry, pepper, integrity)
  - Displays endpoint paths for each module

### Security

#### Security Enhancements
- **Comprehensive SecureBytes Implementation**: All cryptographic registries now use secure memory handling
  - KDF, Cipher, Signature, and KEM registries fully secured
  - Automatic zeroing of sensitive data after use
  - Thread-safe secure memory operations
  - Complete security audit resolution

- **Algorithm Registry Security**: Enhanced cryptographic algorithm security
  - Validation framework prevents unsafe algorithm combinations
  - Security level indicators for all algorithms
  - Deprecated algorithm warnings integrated
  - Comprehensive algorithm metadata tracking

- **Keyserver Security**: Production-grade security for key distribution
  - ML-DSA signature verification for all uploaded keys
  - Bearer token authentication for write operations
  - Rate limiting and CORS protection
  - PostgreSQL backend with parameterized queries

- **Telemetry Privacy**: Privacy-first telemetry implementation
  - Opt-in by design with explicit user consent
  - Anonymous client identifiers
  - Minimal data collection with configurable scopes
  - Transparent data usage policies

- **Pepper Module Security**: Hardened pepper storage with multiple layers of protection
  - mTLS certificate authentication (self-signed CA only, public CAs rejected)
  - TOTP 2FA for destructive operations (panic wipe, account deletion)
  - Client-side encryption (server never sees plaintext peppers)
  - Fernet encryption for TOTP secrets at rest
  - Argon2 hashing for backup codes
  - Deadman switch with grace periods to prevent accidents
  - Comprehensive audit logging (panic events, access tracking)
  - Opt-in by design (disabled by default)

- **Integrity Module Security**: Tamper detection for encrypted file metadata
  - mTLS certificate authentication (self-signed CA only, public CAs rejected)
  - SHA-256 hash verification with integrity violation detection
  - Comprehensive audit logging (all verification attempts tracked)
  - Batch verification with result aggregation
  - Statistics tracking for security monitoring
  - Support for detecting metadata tampering before decryption
  - Opt-in by design (disabled by default)

- **mTLS Authentication Security**: Certificate-based authentication for private modules
  - Self-signed CA requirement prevents unauthorized certificate issuance
  - Public CAs explicitly rejected (Let's Encrypt, DigiCert, etc.)
  - Certificate fingerprint (SHA-256) as unique client identifier
  - Trusted proxy IP validation prevents header injection attacks
  - Certificate DN extraction for client identification
  - Automatic certificate fingerprint normalization
  - No pre-registration required (auto-register on first connection)

#### Security Metrics
- **All Critical Registry Issues Resolved**: Complete SecureBytes implementation across all registries
- **Comprehensive Security Documentation**: SECURITY.md added to all 20 branches
- **Zero Known HIGH/MEDIUM Vulnerabilities**: Security audit completion
- **Enhanced Secure Memory Handling**: Registry-wide secure memory practices

### Removed
- **Plan Files**: Removed implementation plan files from repository
  - asymetric.md, hsm_asymmetric.md, mobile.md
  - keyserver_plan.md, telemetry_plan.md
  - TELEMETRY_IMPLEMENTATION_SUMMARY.md
- **Root Convenience Wrapper**: Removed build-flatpak.sh from root directory
- **Test Artifacts**: Cleaned up test files for plan file hook validation

### Dependencies
- **liboqs**: Updated to 0.12.0 (built from source) for HQC algorithm support
- **FastAPI**: Added for keyserver and telemetry server REST APIs
- **PostgreSQL**: Added psycopg2-binary for server database backends
- **Maturin**: Added for Rust/Python integration (Threefish cipher)
- **All existing dependencies**: Maintained at current secure versions

### Infrastructure
- **Production Servers Deployed**:
  - Keyserver: https://keyserver.rm-rf.ch (FastAPI + PostgreSQL)
  - Telemetry: https://telemetry.rm-rf.ch (FastAPI + PostgreSQL)
- **Docker Support**: Complete Docker infrastructure for both servers
- **Plugin Architecture**: Extensible plugin system for both keyserver and telemetry

### Testing
- **127+ commits** of new functionality and improvements
- Comprehensive cascade encryption test suite
- Threefish cipher integration tests
- Algorithm registry validation tests
- HSM-protected identity tests
- Server endpoint integration tests
- Optimized test execution performance

### Breaking Changes
**None** - Version 1.4.0-alpha.1 maintains backward compatibility with all existing encrypted files and configurations. New features (cascade encryption, Threefish ciphers) use new metadata formats (V8) but existing files remain fully compatible.

### Migration Guide
This is an **alpha release** for testing purposes. While backward compatible, new features should be tested thoroughly before production use:
- **Cascade Encryption**: Test with `--cascade "cipher1,cipher2"` flag
- **Threefish Ciphers**: Available as `threefish-512` and `threefish-1024`
- **Keyserver**: Deploy using Docker or test at https://keyserver.rm-rf.ch
- **Telemetry**: Opt-in system, review privacy policy before enabling

**Alpha Testing Notes**:
- This is a pre-release version intended for testing and feedback
- Production deployment recommended only for non-critical workloads
- Report issues via GitHub Security Advisory or encrypted email
- Final 1.4.0 release planned for Q1 2026

### Contributors
- **Tobi** - Lead developer, cascade encryption, keyserver, telemetry, algorithm registry
- **Claude (Sonnet 4.5)** - Architecture design, security review, testing framework, documentation

---

## [1.3.0] - 2025-12-15

### Added

#### Cryptographic Features
- **RandomX Proof-of-Work KDF**: CPU-optimized key derivation function with light mode (256MB memory) and fast mode (2GB memory) for enhanced security against GPU/ASIC attacks
- **Implicit RandomX Activation**: Automatically enable RandomX when parameters are specified with intelligent default round configuration
- **Steganography Support in Flutter GUI**: Complete integration of data hiding capabilities in desktop GUI
- **Flexible Argument Parsing**: Global flags now support flexible argument parsing for improved CLI usability

#### Testing & Quality Assurance
- **Comprehensive Test Suite**: New `crypt test` command with fuzzing, side-channel analysis, Known-Answer Tests (KAT), performance benchmarking, and memory safety testing
- **Security Audit Logging**: Comprehensive logging system for security events with security_logger and security_report modules
- **Configuration Analysis Tool**: Smart recommendations system with security scoring and configuration validation

#### Infrastructure & Deployment
- **D-Bus Client Examples**: Python, Rust, and Shell client examples demonstrating cross-language compatibility
- **Docker Build Infrastructure**: Local Docker/Podman build scripts with optimized 140MB runtime images
- **QR Code Key Distribution**: Air-gapped keystore operations via portable media
- **Portable USB Encryption**: Unified portable media encryption script with automated integrity verification
- **CI/CD Updates**: Docker-based CI pipeline support with GitLab CI integration

#### Documentation
- **Security Review Documentation**: Comprehensive SECURITY_REVIEW_v1.3.0.md with detailed security audit
- **Docker Build Documentation**: Complete Docker setup guide in docker/README.md
- **D-Bus Integration Guide**: Comprehensive D-Bus service documentation
- **Mobile Implementation Guides**: PQC mobile requirements and chained hash implementation docs

### Changed

#### Core Features
- **RandomX KDF Integration**: Full integration with intelligent implicit enable when parameters detected
- **Default Configuration Behavior**: Enhanced security requiring hash configuration for new encryptions
- **Error Handling**: Improved error messages with comprehensive debug logging replacing print statements

#### Plugin System
- **Thread Safety**: Refactored threading resource management preventing global state pollution
- **Timeout Implementation**: Replaced simple timeout with reliable multiprocessing-based mechanism
- **Queue Handling**: Fixed multiprocessing queue deadlock through improved process management

#### Build & Dependencies
- **Flatpak Dependencies**: Updated manifest dependencies matching requirements-prod.txt
- **Pillow Version**: Relaxed to allow 11.x releases (updated to 11.3.0)
- **NumPy Compatibility**: Upgraded to 2.x for Alpine Linux compatibility

#### Code Quality
- **Path Canonicalization**: Fixed handling for special device files (/dev/stdin, /dev/null, /dev/stdout)
- **Python 3.13 Compatibility**: Replaced datetime.UTC with timezone.utc
- **String Formatting**: Fixed f-strings without placeholders and removed unnecessary imports
- **CI Configuration**: Added amd64 runner tags preventing ARM64 execution

### Fixed

#### Critical Issues
- **Default Configuration Decryption**: Resolved metadata generation inconsistency causing decryption failures
- **PQC Dual Encryption Tests**: Fixed test failures through improved binary prefix handling
- **Multiprocessing Segfaults**: Implemented proper 'spawn' method instead of default fork method
- **Plugin Sandbox Deadlock**: Resolved multiprocessing queue deadlock preventing proper termination

#### Test Infrastructure
- **Import Path Corrections**: Fixed duplicate module imports in pytest
- **Mock Patch Paths**: Corrected mock.patch module paths in test_generate_password_cli
- **Flaky Tests**: Fixed two intermittent test failures
- **API Compatibility**: Updated Advanced Testing Framework encrypt_file API calls

#### Build System
- **Docker Image Sizing**: Optimized build reducing image to 140MB with proper runtime dependencies
- **Build Tool Dependencies**: Added necessary build tools for Python package compilation
- **YAML Parsing**: Fixed YAML syntax errors and f-string issues in CI configuration

#### Compatibility
- **Keystore Schema**: Made schema more flexible for version compatibility
- **Backward Compatibility**: Fixed v1.3.0 decryption compatibility without prior hashing
- **PQC Validation**: Added missing PQC algorithms to metadata v5 schema
- **Legacy Algorithms**: Added legacy algorithm names for keystore compatibility

### Security

#### Vulnerability Resolutions
- **MED-2: D-Bus Symlink Attack Prevention (RESOLVED)**
  - Implemented O_NOFOLLOW protection in safe_open_file() utility for atomic TOCTOU protection
  - Added secure_mode parameter to encryption/decryption functions for D-Bus service security
  - Created comprehensive symlink attack tests with 100% pass rate
  - Eliminates symlink-based directory traversal attacks in D-Bus service
  - Maintains CLI behavior compatibility (secure_mode=False allows symlinks)

- **LOW-5: Debug Mode Security Warning (RESOLVED)**
  - Added prominent security warning box when --debug flag is enabled
  - Clear "DO NOT use with production data" messaging
  - Updated --debug help text across crypt_cli.py, crypt_cli_subparser.py, and crypt.py
  - Warning displayed before any sensitive logging occurs

#### Security Enhancements
- **Comprehensive Security Review**: SECURITY_REVIEW_v1.3.0.md with 0 CRITICAL, 0 HIGH, 3 MEDIUM, 4 LOW findings
- **Security Audit Logging**: Comprehensive audit logging for security events throughout codebase
- **D-Bus Path Validation**: Enhanced directory whitelisting for D-Bus file operations
- **Plugin Validation**: Added strict mode with configurable bypass options
- **Subprocess Safety**: Removed shell=True from subprocess calls with proper list-based arguments

#### Security Metrics
- **Overall Security Score**: 8.8/10 (improved from 8.5/10)
- **Input Validation**: 9.5/10 (improved with O_NOFOLLOW protection)
- **Cryptography**: 9.5/10
- **Authentication**: 9.0/10
- **Memory Safety**: 9.0/10
- **Dependency Security**: 10/10 (zero vulnerable dependencies via pip-audit)
- **Status**: APPROVED FOR PRODUCTION

### Removed
- **Video Steganography**: Removed implementation due to fundamental reliability issues
- **Video Dependencies**: Removed video steganography dependencies from requirements
- **Test Artifacts**: Cleaned up steganography test images and debug files

### Dependencies
- **Pillow**: Updated to 11.3.0 (relaxed constraint to allow 11.x releases)
- **NumPy**: Upgraded to 2.x for Alpine Linux compatibility
- **Cryptography**: Maintained at 44.0.3+
- **Argon2-cffi**: Maintained at 23.1.0+
- **pip-audit**: All dependencies verified with zero vulnerable packages

### Documentation
- Added SECURITY_REVIEW_v1.3.0.md with comprehensive security audit
- Added docker/README.md for Docker build and deployment
- Added examples/dbus_clients/ with Python, Rust, and Shell examples
- Enhanced plugin development guides with security architecture details

### Testing
- 128+ encryption-related unit tests passing
- Comprehensive plugin system tests with proper isolation
- Full D-Bus service tests with symlink attack scenarios
- Docker build tests with optimized 140MB image
- RandomX integration tests with fallback handling
- Post-quantum cryptography dual encryption tests

### Breaking Changes
**None** - Version 1.3.0 maintains full backward compatibility with all existing encrypted files and configurations.

### Migration Guide
No migration required. v1.3.0 is a drop-in replacement for v1.2.x installations.

**Note**: Debug mode (--debug) now displays a prominent security warning. This is intentional to remind users that debug output contains sensitive information.

### Contributors
- **Tobi** - Lead developer, security enhancements, comprehensive testing
- **Claude (Sonnet 4.5)** - Security review, documentation, testing framework

## [1.2.0] - 2025-08-16

### Added
- **Flutter Desktop GUI**: Professional desktop GUI application built with Flutter providing native Wayland and X11 support
- **Advanced CLI Integration**: Complete Flutter-to-CLI bridge service with real-time progress monitoring and error handling
- **Comprehensive Settings System**: Professional settings interface with theme switching, cryptographic defaults, and debug features
- **Desktop UX Excellence**: Professional menu bar, keyboard shortcuts (Ctrl+O, Ctrl+S, F1), drag & drop file operations
- **Algorithm Configuration UI**: Advanced parameter tuning interface for all KDFs (Argon2, Scrypt, Balloon, HKDF)
- **Post-Quantum Algorithm UI**: Complete interface for ML-KEM, Kyber, HQC, MAYO, and CROSS algorithms
- **Flatpak Desktop Integration**: Complete Flatpak packaging with desktop file, icons, and system integration

### Changed
- **GUI Architecture**: Migrated from tkinter to Flutter for superior desktop experience and cross-platform compatibility
- **Flatpak Launcher**: Simplified launcher focusing on Flutter GUI with tkinter support removed from release branches
- **User Interface**: Desktop-optimized layout with NavigationRail, tabbed interface, and professional visual design
- **File Operations**: Native desktop file dialogs with drag & drop support replacing basic file selection
- **Algorithm Selection**: Interactive algorithm picker with security level recommendations and performance guidance

### Removed
- **PBKDF2 Support**: Removed legacy PBKDF2 key derivation function from encryption operations due to security concerns
- **Whirlpool Hash**: Removed deprecated Whirlpool hash algorithm from encryption operations for security hardening

### Fixed
- **Wayland Compatibility**: Native Wayland support through Flutter eliminating X11 authorization issues
- **Display Server Support**: Robust support for both Wayland and X11 environments without manual configuration
- **Desktop Integration**: Proper desktop environment integration with system theming and accessibility support
- **Performance**: Significant UI responsiveness improvements through native Flutter rendering

### Security
- **Reduced Attack Surface**: Elimination of complex X11/XWayland compatibility layers in Flatpak environment
- **Native Desktop Security**: Flutter's native platform integration provides better sandboxing than X11-based solutions
- **Streamlined Permissions**: Simplified Flatpak permissions removing unnecessary X11 fallback mechanisms
- **Algorithm Hardening**: Removed deprecated PBKDF2 and Whirlpool algorithms to eliminate weak cryptographic options

## [1.1.0] - 2025-06-26

### Added
- Segregated CLI help system with two-tier structure (global + command-specific)
- Context-aware help display showing only relevant options per command
- Improved command discovery with comprehensive overview in global help
- Command-specific argument parsing for better user experience

### Changed
- Enhanced CLI help output for better usability and reduced cognitive load
- Global help now provides clear command overview and navigation guidance
- Encrypt command help shows only encryption-relevant options and algorithms
- Decrypt command help shows only decryption-relevant options (no algorithm selection)
- Generate-password, shred, and utility commands show focused option sets

### Technical
- Added crypt_cli_subparser.py module for command-specific argument handling
- Implemented version-aware algorithm filtering (excludes 1.1.0-only MAYO/CROSS algorithms)
- Maintained full backward compatibility with all existing CLI usage patterns
- No changes to core cryptographic functionality or file formats

## [1.0.0] - 2025-06-21

### Added
- Official production release milestone
- Enterprise-grade quantum-resistant cryptographic capabilities
- Complete post-quantum cryptography support (Kyber, ML-KEM, HQC algorithms)
- Production-grade type safety and runtime stability
- Enterprise-ready keystore management for PQC keys
- Industry-leading code quality standards with comprehensive static analysis

### Changed
- Status updated to Production Release / Stable
- Full backward compatibility maintained with all previous file formats
- Production deployment readiness achieved

### Security
- Comprehensive security hardening with constant-time operations
- Final security audit completion with zero HIGH/MEDIUM severity issues
- Production-ready security posture established

## [1.0.0-rc3] - 2025-06-16

### Documentation
- Major documentation consolidation from 37+ files to 10 comprehensive guides (73% reduction)
- Updated README.md Documentation Structure section with clickable links
- Added June 2025 documentation restructuring to RELEASE_NOTES.md
- Consolidated user documentation into user-guide.md and keystore-guide.md
- Consolidated security documentation into security.md, algorithm-reference.md, and dependency-management.md
- Consolidated technical documentation into metadata-formats.md and development-setup.md
- Integrated ML-KEM CLI support documentation into algorithm-reference.md
- Integrated HQC algorithm completion status from NEXT.md into TODO.md

### Security

- Updated `cryptography` dependency from `>=42.0.0,<43.0.0` to `>=44.0.1,<45.0.0` to address CVE-2024-12797
- Added specific version constraints to all dependencies to prevent unexpected breaking changes
- Implemented proper version pinning with both lower and upper bounds for all dependencies
- Added `bcrypt~=4.3.0` with compatible release specifier
- Added pre-commit hooks for security scanning
- Integrated Bandit for Python security code analysis
- Added pip-audit for dependency vulnerability scanning (replacing Safety)
- Created custom gitlab_dependency_scan.py script for reliable CI security scanning
- Added security scanning to CI pipeline
- Implemented Software Bill of Materials (SBOM) generation
- Added GitLab security dashboard integration

### Build System

- Added pyproject.toml for properly specifying build dependencies
- Implemented lock files using pip-tools for reproducible builds
- Created requirements-prod.txt and requirements-dev.txt lock files
- Added dependency update script (scripts/update_dependencies.sh)
- Updated setup.py to use lock files for dependencies
- Added setup_hooks.sh script for easy pre-commit installation

## [1.0.0-rc2] - 2025-06-16

### Fixed
- Resolved all critical MyPy type errors that could cause runtime failures in post-quantum cryptography operations
- Fixed variable naming conflicts between AESGCM and PQCipher classes
- Corrected string/bytes type mismatches in password handling
- Removed invalid function parameters causing TypeErrors
- 90%+ critical runtime issues resolved (type errors reduced from 529 to ~480)

### Added
- HQC algorithm support fully implemented (hqc-128/192/256-hybrid) with comprehensive testing
- **HQC Production Readiness**: Complete HQC algorithm implementation with 15 test files covering all symmetric encryption combinations
- **HQC Security Validation**: Comprehensive error handling tests for invalid keys, corrupted data, wrong passwords, and algorithm mismatches
- **HQC Integration**: Full keystore integration, dual-encryption support, and file format v5 compatibility
- Complete post-quantum cryptography support (Kyber, ML-KEM, HQC)
- Industry-leading code quality standards
- Production-grade stability and reliability

### Security
- Security analysis confirmed 0 HIGH/MEDIUM severity issues
- All core encryption functionality verified working
- HQC algorithms pass all security validation tests and attack vector analysis

## [1.0.0-rc1] - 2025-05-16

### Added
- Comprehensive multi-layered static code analysis with 7 GitLab CI jobs
- 18+ pre-commit hooks for immediate development feedback
- Legacy algorithm warning system for deprecated cryptographic algorithms
- Comprehensive code formatting via Black and isort
- Enhanced CI pipeline with Docker improvements and job isolation

### Changed
- Repository cleanup removing unnecessary development artifacts

### Security
- Industry-leading code quality standards implementation
- Comprehensive static analysis integration
- Enhanced security scanning capabilities

## [0.9.2] - 2025-05-15

### Added
- CRYPT_PASSWORD environment variable support for CLI with secure multi-pass clearing
- Comprehensive GUI password security with SecurePasswordVar class
- Extensive unit test suite with 11 tests covering environment variable password handling

### Security
- Enhanced password handling security across all interfaces
- Secure clearing verification for environment variables

## [0.9.1] - 2025-05-14

### Added
- ML-KEM algorithms (ML-KEM-512/768/1024)
- HQC algorithms re-enabled with comprehensive testing (HQC-128/192/256)
- Enhanced keystore integration for all PQC algorithms
- Improved concurrent test execution safety

### Removed
- bcrypt dependency due to incompatible salt handling

### Security
- Extended quantum-resistant algorithm support
- Comprehensive post-quantum testing infrastructure
- Enhanced keystore security features

## [0.9.0] - 2025-04-16

### Added
- Constant-time cryptographic operations implementation
- Secure memory allocator for cryptographic data
- Standardized error handling to prevent information leakage
- Python 3.13 compatibility
- Enhanced CI pipeline with pip-audit scanning
- SBOM generation (Software Bill of Materials)
- Thread safety improvements with thread-local timing jitter

### Security
- Comprehensive dependency security with version pinning
- Major security hardening release
- Backward compatibility maintained across all enhancements

## [0.8.2] - 2025-04-15

### Fixed
- Python version compatibility fixes for versions < 3.12
- More resilient Whirlpool implementation during package build
- Enhanced build system reliability
- Cross-platform compatibility improvements

## [0.8.1] - 2025-04-14

### Added
- New metadata structure v5 with backward compatibility
- User-defined data encryption when using PQC
- Enhanced PQC flexibility with configurable symmetric algorithms
- Comprehensive testing and documentation updates

## [0.7.2] - 2025-03-16

### Added
- New metadata structure with backward compatibility
- Improved data organization and structure
- Enhanced file format versioning
- All tests passing with updated documentation

## [0.7.1] - 2025-03-15

### Added
- Complete keystore implementation for post-quantum keys
- Comprehensive testing - all tests passing
- Updated documentation for keystore functionality

### Breaking Changes
- Breaking release for keystore feature of PQC keys

## [0.7.0-rc1] - 2025-03-14

### Added
- PQC key management system
- Local encrypted keystore for post-quantum keys
- Last major feature for release candidate phase

### Breaking Changes
- Breaking release introducing keystore feature

## [0.6.0-rc1] - 2025-02-16

### Added
- Feature-complete post-quantum cryptography implementation
- Hybrid post-quantum encryption architecture
- Complete post-quantum algorithm support

### Breaking Changes
- Breaking release for post-quantum cryptography

## [0.5.3] - 2025-02-15

### Added
- Additional buffer overflow protection
- Enhanced secure memory handling
- Improved memory safety

### Security
- Security-focused bug fixes
- Enhanced memory protection

## [0.5.2] - 2025-02-14

### Added
- Post-quantum resistant encryption via hybrid approach
- Kyber KEM integration for quantum resistance
- Hybrid encryption architecture combining classical and post-quantum
- Future-proof cryptographic foundation

## [0.5.1] - 2025-02-13

### Fixed
- More reliable commit SHA integration into version.py
- Enhanced build process reliability
- Improved version tracking

## [0.5.0] - 2025-01-16

### Added
- BLAKE2b and SHAKE-256 hash algorithms
- XChaCha20-Poly1305 encryption support
- Expanded cryptographic algorithm portfolio
- Enhanced security options

## [0.4.4] - 2025-01-15

### Added
- Scrypt support
- Additional hash algorithms implementation
- Enhanced key derivation options
- Improved password security

## [0.4.0] - 2025-01-14

### Added
- Secure memory handling implementation
- Improved password strength validation
- Memory security enhancements
- Enhanced data protection

## [0.3.0] - 2025-01-13

### Added
- Argon2 key derivation support
- Memory-hard key derivation function
- Enhanced password-based security
- Industry-standard KDF implementation

## [0.2.0] - 2025-01-12

### Added
- AES-GCM support
- ChaCha20-Poly1305 encryption
- Multiple encryption algorithm support
- Cryptographic algorithm flexibility

## [0.1.0] - 2025-01-11

### Added
- Initial public release
- Basic file encryption/decryption
- Fernet encryption (AES-128-CBC)
- Secure password-based encryption
- Foundation cryptographic features
