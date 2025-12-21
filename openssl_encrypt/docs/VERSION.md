# Version History - OpenSSL Encrypt

## Overview

OpenSSL Encrypt follows [Semantic Versioning (SemVer)](https://semver.org/) for version numbering and maintains comprehensive version history to track the evolution of cryptographic security features, post-quantum implementations, and security enhancements.

**Current Version:** `1.3.0` (Production Release)

**Development Status:** Production/Stable

## Version Numbering Scheme

- **MAJOR.MINOR.PATCH** for stable releases
- **MAJOR.MINOR.PATCH-rcN** for release candidates
- Git commit hashes are automatically embedded during build process
- Version information is programmatically accessible via `openssl_encrypt.version`

## Release History

### 1.3.0 (Current) - RandomX PoW & Advanced Testing Release
**Release Date:** December 2025
**Status:** Production Release

**Cryptographic Features:**
- ✅ **RandomX Proof-of-Work KDF** with CPU-optimized key derivation
  - Light mode (256MB memory) and fast mode (2GB memory)
  - Enhanced security against GPU/ASIC attacks
  - Implicit RandomX activation with intelligent default configuration
- ✅ **Steganography Support in Flutter GUI** - Complete integration of data hiding capabilities
- ✅ **Flexible Argument Parsing** - Global flags with improved CLI usability

**Testing & Quality Assurance:**
- ✅ **Comprehensive Test Suite** - New `crypt test` command with:
  - Fuzzing tests for input boundary conditions
  - Side-channel analysis
  - Known-Answer Tests (KAT)
  - Performance benchmarking
  - Memory safety testing
- ✅ **Security Audit Logging** - Comprehensive logging system for security events
- ✅ **Configuration Analysis Tool** - Smart recommendations with security scoring

**Infrastructure & Deployment:**
- ✅ **D-Bus Client Examples** - Python, Rust, and Shell demonstrating cross-language compatibility
- ✅ **Docker Build Infrastructure** - Optimized 140MB runtime images
- ✅ **QR Code Key Distribution** - Air-gapped keystore operations
- ✅ **Portable USB Encryption** - Unified portable media encryption script

**Security:**
- MED-2 resolved: D-Bus symlink attack prevention with O_NOFOLLOW protection
- LOW-5 resolved: Debug mode security warning
- Overall security score: 8.8/10 (improved from 8.5/10)

### 1.2.1 - CI/CD & Configuration Improvements
**Release Date:** December 2025
**Status:** Production Release

**Infrastructure:**
- ✅ **GitLab CI Enhancements** - Fixed Alpine/Debian compatibility for liboqs builds
- ✅ **Documentation Quality** - Removed marketing language, improved technical accuracy
- ✅ **DOCS_ONLY Pipeline** - Enable documentation-only CI runs

**Improvements:**
- ✅ **Sane CLI Defaults** - Applied when no hash/KDF arguments provided
- ✅ **Reduced Default KDF Rounds** - From 100 to 5 for better UX
- ✅ **Enhanced Flutter GUI** - Backported improvements from feature branch

### 1.2.0 - Professional Flutter Desktop GUI
**Release Date:** August 2025
**Status:** Production Release

**Desktop GUI Excellence:**
- ✅ **Flutter Desktop Application** - Professional GUI with native Wayland and X11 support
- ✅ **Advanced CLI Integration** - Complete Flutter-to-CLI bridge with real-time monitoring
- ✅ **Desktop UX Standards** - Menu bar, keyboard shortcuts (Ctrl+O, Ctrl+S, F1), drag & drop
- ✅ **Responsive Design** - NavigationRail sidebar, tabbed interface, professional visual hierarchy

**Configuration System:**
- ✅ **Professional Settings Interface** - Theme switching (Light/Dark/System), cryptographic defaults
- ✅ **Advanced Algorithm Configuration** - Interactive parameter tuning for all KDFs
- ✅ **Post-Quantum Algorithm UI** - Complete interface for ML-KEM, Kyber, HQC, MAYO, CROSS
- ✅ **Algorithm Recommendation Engine** - Intelligent selection with security guidance

**Security Hardening:**
- ✅ **Removed PBKDF2 Support** - Eliminated legacy key derivation function
- ✅ **Removed Whirlpool Hash** - Eliminated deprecated hash algorithm
- ✅ **Reduced Attack Surface** - Simplified Flatpak permissions, eliminated X11 compatibility layers

### 1.1.0 - Extended Cryptographic Portfolio
**Release Date:** June 2025
**Status:** Production Release

**Extended Hash Support:**
- ✅ **Complete SHA-2 Family** - Added SHA-224 and SHA-384
- ✅ **Complete SHA-3 Family** - Added SHA3-224 and SHA3-384
- ✅ **BLAKE3 Ultra-Fast Hash** - Tree-based parallelism for maximum performance
- ✅ **SHAKE-128 Function** - Additional extendable-output function

**Modern Key Derivation:**
- ✅ **HKDF Implementation** - RFC 5869 HMAC-based KDF with configurable hash algorithms
- ✅ **Flexible Configuration** - Support for chained KDF rounds
- ✅ **Legacy Categorization** - PBKDF2 properly categorized as legacy (disabled by default)

**Post-Quantum Signatures:**
- ✅ **MAYO Algorithm Support** - MAYO-1/3/5 multivariate signature algorithms
- ✅ **CROSS Algorithm Integration** - CROSS-128/192/256 code-based signatures
- ✅ **Hybrid Signature Architecture** - Combining classical and post-quantum schemes

**CLI Enhancements:**
- ✅ **Segregated CLI Help System** - Two-tier structure (global + command-specific)
- ✅ **Context-Aware Help** - Reduced cognitive load, improved discoverability

### 1.0.3 - Documentation & GUI Maintenance
**Release Date:** June 2025
**Status:** Maintenance Release

**Improvements:**
- ✅ **Enhanced Flutter GUI** - Backported improvements from feature branch
- ✅ **Documentation Updates** - Comprehensive version history and guides
- ✅ **CI/CD Updates** - Improved GitLab CI configuration for releases

### 1.0.2 - GUI Integration & Deprecations
**Release Date:** June 2025
**Status:** Maintenance Release

**Features:**
- ✅ **Enhanced Flutter GUI** - Backported from feature branch
- ✅ **AES-OCB3 Deprecation** - Blocked for new encryption, added deprecation notices
- ✅ **GitLab CI Updates** - Added releases/* branch support

### 1.0.1 - Security Fixes & GUI Integration
**Release Date:** June 2025
**Status:** Maintenance Release

**Security Fixes:**
- ✅ **HIGH-1**: Fixed timing side-channel vulnerability in MAC verification
- ✅ **HIGH-2**: Fixed path traversal in template loading
- ✅ **HIGH-5**: Increased PBKDF2 iterations to 100,000
- ✅ **MED-1**: Fixed insecure temporary file creation (CVSS 5.5)
- ✅ **MED-2**: Fixed missing path canonicalization (CVSS 6.1)

**Features:**
- ✅ **Segregated CLI Help System** - Improved user experience
- ✅ **Flutter Desktop GUI** - Complete integration with Flatpak support
- ✅ **AES-OCB3 Block** - Prevented use for new encryption
- ✅ **Enhanced Password Generator** - Cryptographically secure implementation

### 1.0.0 - Official Production Release
**Release Date:** June 2025
**Status:** Production Release

**Production Readiness:**
- ✅ **Complete Post-Quantum Cryptography** - Kyber, ML-KEM, HQC algorithms ready for production
- ✅ **Production-Grade Type Safety** - Comprehensive runtime stability
- ✅ **Security Hardening** - Constant-time operations, secure memory handling
- ✅ **Keystore Management** - PQC key management suitable for production
- ✅ **Full Backward Compatibility** - All previous file formats supported
- ✅ **Code Quality Standards** - Multiple static analysis tools

### 1.0.0-rc2 - Production Readiness Release
**Release Date:** June 2025
**Status:** Production Ready Release Candidate

**Critical Production-Readiness Fixes:**
- ✅ **Resolved all critical MyPy type errors** that could cause runtime failures in post-quantum cryptography operations
- ✅ **Fixed variable naming conflicts** between AESGCM and PQCipher classes
- ✅ **Corrected string/bytes type mismatches** in password handling
- ✅ **Removed invalid function parameters** causing TypeErrors
- ✅ **HQC algorithm support fully implemented** (hqc-128/192/256-hybrid) with comprehensive testing
- ✅ **Security analysis confirmed 0 HIGH/MEDIUM severity issues**
- ✅ **90%+ critical runtime issues resolved** (type errors reduced from 529 to ~480)
- ✅ **All core encryption functionality verified working**

**Features:**
- Complete post-quantum cryptography support (Kyber, ML-KEM, HQC)
- Comprehensive security hardening implementation
- Industry-leading code quality standards
- Production-grade stability and reliability

### 1.0.0-rc1 - Quality & Security Overhaul
**Release Date:** May 2025

**Major Quality Improvements:**
- **Comprehensive multi-layered static code analysis** with 7 GitLab CI jobs
  - Bandit security analysis
  - Semgrep code quality scanning
  - Pylint code analysis
  - MyPy type checking
  - Code complexity analysis
- **18+ pre-commit hooks** for immediate development feedback
- **Legacy algorithm warning system** for deprecated cryptographic algorithms
- **Comprehensive code formatting** via Black and isort
- **Enhanced CI pipeline** with Docker improvements and job isolation
- **Repository cleanup** removing unnecessary development artifacts

**Security Enhancements:**
- Industry-leading code quality standards implementation
- Comprehensive static analysis integration
- Enhanced security scanning capabilities

### 0.9.2 - Password Security Enhancement
**Release Date:** May 2025

**Password Security Features:**
- **CRYPT_PASSWORD environment variable support** for CLI with secure multi-pass clearing
- **Comprehensive GUI password security** with SecurePasswordVar class
- **Extensive unit test suite** with 11 tests covering:
  - Environment variable password handling
  - Secure clearing verification
  - Edge case coverage
- **Enhanced password handling security** across all interfaces

### 0.9.1 - Extended Post-Quantum Cryptography
**Release Date:** May 2025

**Post-Quantum Algorithm Expansion:**
- **ML-KEM algorithms added** (ML-KEM-512/768/1024)
- **HQC algorithms re-enabled** with comprehensive testing (HQC-128/192/256)
- **Enhanced keystore integration** for all PQC algorithms
- **Improved concurrent test execution** safety
- **Removed bcrypt dependency** due to incompatible salt handling

**Security Improvements:**
- Extended quantum-resistant algorithm support
- Comprehensive post-quantum testing infrastructure
- Enhanced keystore security features

### 0.9.0 - Major Security Hardening Release
**Release Date:** April 2025

**Security Hardening:**
- **Constant-time cryptographic operations** implementation
- **Secure memory allocator** for cryptographic data
- **Standardized error handling** to prevent information leakage
- **Python 3.13 compatibility** added
- **Comprehensive dependency security** with version pinning

**Infrastructure Improvements:**
- **Enhanced CI pipeline** with pip-audit scanning
- **SBOM generation** (Software Bill of Materials)
- **Thread safety improvements** with thread-local timing jitter
- **Backward compatibility maintained** across all enhancements

### 0.8.2 - Compatibility & Build Improvements
**Release Date:** April 2025

**Improvements:**
- **Python version compatibility** fixes for versions < 3.12
- **More resilient Whirlpool implementation** during package build
- **Enhanced build system reliability**
- **Cross-platform compatibility improvements**

### 0.8.1 - Configurable Data Encryption
**Release Date:** April 2025

**Features:**
- **New metadata structure v5** with backward compatibility
- **User-defined data encryption** when using PQC
- **Enhanced PQC flexibility** with configurable symmetric algorithms
- **Comprehensive testing** and documentation updates

### 0.7.2 - Metadata Structure Enhancement
**Release Date:** March 2025

**Features:**
- **New metadata structure** with backward compatibility
- **Improved data organization** and structure
- **Enhanced file format versioning**
- **All tests passing** with updated documentation

### 0.7.1 - Keystore Feature Completion
**Release Date:** March 2025

**Features:**
- **Breaking release** for keystore feature of PQC keys
- **Complete keystore implementation** for post-quantum keys
- **Comprehensive testing** - all tests passing
- **Updated documentation** for keystore functionality

### 0.7.0rc1 - Keystore Feature Introduction
**Release Date:** March 2025

**Features:**
- **Breaking release** introducing keystore feature
- **PQC key management** system
- **Local encrypted keystore** for post-quantum keys
- **Last major feature** for release candidate phase

### 0.6.0rc1 - Post-Quantum Breaking Release
**Release Date:** February 2025

**Features:**
- **Breaking release** for post-quantum cryptography
- **Feature-complete** implementation
- **Hybrid post-quantum encryption** architecture
- **Complete post-quantum algorithm support**

### 0.5.3 - Security Release
**Release Date:** February 2025

**Security Improvements:**
- **Additional buffer overflow protection**
- **Enhanced secure memory handling**
- **Security-focused bug fixes**
- **Improved memory safety**

### 0.5.2 - Post-Quantum Resistance Introduction
**Release Date:** February 2025

**Features:**
- **Post-quantum resistant encryption** via hybrid approach
- **Kyber KEM integration** for quantum resistance
- **Hybrid encryption architecture** combining classical and post-quantum
- **Future-proof cryptographic foundation**

### 0.5.1 - Build System Improvements
**Release Date:** February 2025

**Improvements:**
- **More reliable commit SHA** integration into version.py
- **Enhanced build process** reliability
- **Improved version tracking**

### 0.5.0 - Algorithm Expansion
**Release Date:** January 2025

**Features:**
- **BLAKE2b and SHAKE-256** hash algorithms added
- **XChaCha20-Poly1305** encryption support
- **Expanded cryptographic algorithm portfolio**
- **Enhanced security options**

### 0.4.4 - Enhanced Key Derivation
**Release Date:** January 2025

**Features:**
- **Scrypt support** added
- **Additional hash algorithms** implementation
- **Enhanced key derivation options**
- **Improved password security**

### 0.4.0 - Secure Memory & Password Strength
**Release Date:** January 2025

**Features:**
- **Secure memory handling** implementation
- **Improved password strength** validation
- **Memory security enhancements**
- **Enhanced data protection**

### 0.3.0 - Argon2 Integration
**Release Date:** January 2025

**Features:**
- **Argon2 key derivation** support
- **Memory-hard key derivation** function
- **Enhanced password-based security**
- **Industry-standard KDF implementation**

### 0.2.0 - Algorithm Diversification
**Release Date:** January 2025

**Features:**
- **AES-GCM support** added
- **ChaCha20-Poly1305** encryption
- **Multiple encryption algorithm** support
- **Cryptographic algorithm flexibility**

### 0.1.0 - Initial Release
**Release Date:** January 2025

**Features:**
- **Initial public release**
- **Basic file encryption/decryption**
- **Fernet encryption** (AES-128-CBC)
- **Secure password-based encryption**
- **Foundation cryptographic features**

## Version Lifecycle

### Development Branches
- **`main`** - Stable production code
- **`release`** - Release preparation and staging
- **`nightly`** - Latest development features
- **`testing`** - Pre-release testing and validation
- **`dev`** - Active development branch

### Release Process

1. **Development** → `dev` branch
2. **Testing** → `testing` branch with comprehensive test suite
3. **Release Candidate** → `release` branch with version tagging
4. **Production** → `main` branch merge after validation
5. **Distribution** → PyPI publication and documentation updates

## Technical Version Information

### Version Detection
```python
from openssl_encrypt.version import get_version_info

info = get_version_info()
print(f"Version: {info['version']}")
print(f"Git Commit: {info['git_commit']}")
print(f"Build Date: {info.get('build_date', 'Unknown')}")
```

### Compatibility Matrix

| Version | Python | Status | Support Level |
|---------|--------|--------|---------------|
| 1.3.x | 3.9+ | Current | Full Support |
| 1.2.x | 3.9+ | Maintenance | Security Fixes |
| 1.1.x | 3.9+ | Maintenance | Security Fixes |
| 1.0.x | 3.9+ | Maintenance | Security Fixes |
| 0.9.x | 3.9+ | EOL | No Support |
| < 0.9.0 | 3.8+ | EOL | No Support |

## Security & Updates

### Critical Security Releases
- **1.3.0**: D-Bus symlink attack prevention (MED-2), debug mode security warnings
- **1.2.0**: Removed PBKDF2 and Whirlpool deprecated algorithms
- **1.0.1**: Multiple HIGH/MED severity fixes (timing attacks, path traversal, PBKDF2 iterations)
- **1.0.0**: Production release with comprehensive security hardening
- **0.9.0**: Major security hardening with constant-time operations
- **0.5.3**: Buffer overflow protection and memory security
- **Dependencies**: Regular updates for CVE mitigation

### Update Recommendations
- **Production environments**: Use stable releases (1.0.0+)
- **Development**: Use latest release candidates for new features
- **Security**: Monitor security advisories and update promptly
- **Dependencies**: Follow semantic versioning constraints

## Future Roadmap

### Planned Releases
- **1.4.0** - Extended mobile platform support and performance optimizations
- **1.5.0** - Hardware security module (HSM) integration
- **2.0.0** - Next-generation post-quantum algorithms (NIST Round 4+)
- **2.1.0** - Cloud key management and enterprise features

### Development Focus
- **Performance optimization** for large file processing
- **Extended post-quantum algorithms** (Falcon, SPHINCS+, etc.)
- **Hardware security integration** (TPM, HSM support)
- **Enhanced GUI** with advanced configuration options
- **API standardization** for programmatic usage

---

**Maintainer:** Tobi <jahlives@gmx.ch>
**License:** Hippocratic License 3.0 (https://firstdonoharm.dev)
**Repository:** https://gitlab.rm-rf.ch/world/openssl_encrypt
**Documentation:** https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs
