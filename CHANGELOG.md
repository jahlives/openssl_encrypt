# Changelog

All notable changes to the openssl_encrypt project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
