# Changelog

All notable changes to the openssl_encrypt project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Extended Cryptographic Hash Support**: Complete SHA-2 family (SHA-224, SHA-384), SHA-3 family (SHA3-224, SHA3-384), BLAKE3 ultra-fast hash, SHAKE-128 extendable-output function
- **HKDF Key Derivation**: RFC 5869 HMAC-based Key Derivation Function with configurable rounds and hash algorithms
- **MAYO Post-Quantum Signatures**: MAYO-1/3/5 multivariate signature algorithms for quantum-resistant authentication
- **CROSS Post-Quantum Signatures**: CROSS-128/192/256 code-based signature algorithms
- **Reorganized GUI Settings**: Professional hash family groupings (SHA-2, SHA-3, BLAKE, SHAKE, Legacy) and KDF Algorithm Settings section
- **Complete CLI Coverage**: All new hash algorithms and HKDF available via command-line interface with comprehensive help documentation
- **PBKDF2 Categorization**: Moved PBKDF2 to Legacy KDF section with default disabled (0 iterations)

### Changed
- **GUI Organization**: Restructured settings tab with logical algorithm families and modern vs. legacy categorization
- **Algorithm Defaults**: PBKDF2 iterations default changed from 100,000 to 0 (disabled by default)
- **CLI Interface**: Enhanced subparser help consistency with main CLI for all hash and KDF options
- **Documentation Updates**: Updated README.md with comprehensive hash families and new CLI examples

### Fixed
- **Unit Test Coverage**: Comprehensive CLI argument testing ensuring all 93+ CLI parameters are validated to prevent regressions
- **Test Infrastructure**: Enhanced unit test system to check both main CLI and subparser implementations for complete coverage
- **Code Quality**: Removed legacy pqc-allow-mixed-operations parameter and cleaned up 63 development artifacts from repository
- **Repository Maintenance**: Systematic cleanup of test/debug/fix scripts while preserving production code and proper unit tests

### Security
- **Modern Algorithm Promotion**: Clear separation of modern (HKDF, Argon2, Scrypt, Balloon) vs. legacy (PBKDF2) KDFs
- **Enhanced Hash Portfolio**: Industry-leading cryptographic hash coverage including latest BLAKE3 and complete SHA-3 family
- **Future-Proof Signatures**: Additional post-quantum signature algorithms (MAYO, CROSS) for comprehensive quantum resistance
- **Secure Defaults**: Disabled legacy PBKDF2 by default while maintaining backward compatibility

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
