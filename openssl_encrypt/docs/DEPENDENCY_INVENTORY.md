# Dependency Inventory for openssl_encrypt

This document provides a comprehensive inventory of all dependencies used in the openssl_encrypt project, including their purpose, version constraints, license information, and security considerations.

## Core Dependencies

| Dependency | Purpose | Version Constraint | License | Notes |
|------------|---------|-------------------|---------|-------|
| cryptography | Provides cryptographic primitives and algorithms | >=42.0.0,<43.0.0 | Apache-2.0 | Critical for encryption/decryption operations |
| argon2-cffi | Implements the Argon2 password hashing algorithm | >=23.1.0,<24.0.0 | MIT | Used for secure key derivation |
| PyYAML | YAML parser and emitter | Not pinned | MIT | Used for configuration file handling |
| whirlpool-py311 | Whirlpool hash algorithm implementation for Python 3.11+ | Not pinned | Public Domain | Used for additional hash algorithm |
| bcrypt | Modern password hashing library | ~=4.3.0 | Apache-2.0 | Used for password hashing |

## Platform-Specific Dependencies

| Dependency | Purpose | Version Constraint | License | Notes |
|------------|---------|-------------------|---------|-------|
| pywin32 | Python extensions for Windows | >=306,<307 (Windows only) | PSF | Used for Windows-specific features |

## Optional Dependencies

| Dependency | Purpose | Version Constraint | License | Notes |
|------------|---------|-------------------|---------|-------|
| liboqs-python | Python bindings for liboqs | Not pinned (optional) | MIT | For post-quantum cryptography support |

## Development Dependencies

| Dependency | Purpose | Version Constraint | License | Notes |
|------------|---------|-------------------|---------|-------|
| pytest | Testing framework | >=8.0.0 | MIT | For running unit tests |
| pytest-cov | Test coverage plugin for pytest | >=4.1.0 | MIT | For measuring test coverage |
| black | Code formatter | >=24.1.0 | MIT | For consistent code formatting |
| pylint | Static code analyzer | >=3.0.0 | GPL-2.0 | For code quality checks |

## Transitive Dependencies

This section will list significant indirect dependencies that are pulled in by our direct dependencies. This helps identify potential security concerns in the dependency tree.

| Dependency | Purpose | Direct Parent | License | Notes |
|------------|---------|--------------|---------|-------|
| cffi | C Foreign Function Interface for Python | cryptography, argon2-cffi | MIT | Used for C binding |
| pycparser | C parser in Python | cffi | BSD-3-Clause | Used by cffi |
| setuptools | Build system | Multiple | MIT | Used for package installation |
| ... | ... | ... | ... | ... |

## Security Audit

### Security Critical Dependencies

The following dependencies are considered security-critical as they directly impact the cryptographic operations of the library:

1. **cryptography** - Core cryptographic operations
2. **argon2-cffi** - Key derivation and password hashing
3. **liboqs-python** (optional) - Post-quantum cryptography
4. **whirlpool-py311** - Additional hash algorithm
5. **bcrypt** - Password hashing

### Known Vulnerabilities

Based on our security scan, the following vulnerabilities were identified in the project's dependencies:

| Dependency | Version | Vulnerability | Severity | Notes |
|------------|---------|---------------|----------|-------|
| cryptography | 42.0.8 | CVE-2024-12797 | Medium | Affects OpenSSL bundled in cryptography wheels. Fixed in version 44.0.1 |

### Dependency Maintenance Status

| Dependency | Current Version | Latest Version | Last Updated | Activity Level | Notes |
|------------|----------------|----------------|--------------|----------------|-------|
| cryptography | 42.0.8 | 44.0.1 | May 2025 | High | Actively maintained by Python Cryptographic Authority |
| argon2-cffi | 23.1.0 | 23.1.0 | August 2023 | Medium | Stable, less frequent updates |
| PyYAML | 6.0.2 | 6.0.2 | August 2024 | Medium | Mature library |
| bcrypt | 4.3.0 | 4.3.0 | April 2023 | Medium | Maintained by Python Cryptographic Authority |
| whirlpool-py311 | 1 | 1 | July 2022 | Low | Specialized library with less frequent updates |

### Transitive Dependencies Analysis

Important transitive dependencies include:

| Dependency | Purpose | Direct Parent | License | Notes |
|------------|---------|--------------|---------|-------|
| cffi | C Foreign Function Interface | cryptography, argon2-cffi | MIT | Critical for crypto operations |
| argon2-cffi-bindings | C bindings for Argon2 | argon2-cffi | MIT | Critical for Argon2 functionality |
| pycparser | C parser in Python | cffi | BSD-3-Clause | Used by cffi |

### Version Pinning Status

- **Tightly pinned**: Dependencies with exact version or very narrow range
- **Loosely pinned**: Dependencies with minimum version but no maximum
- **Unpinned**: Dependencies with no version constraints

| Pinning Level | Dependencies |
|---------------|-------------|
| Tightly pinned | cryptography, argon2-cffi, pywin32, bcrypt |
| Loosely pinned | pytest, pytest-cov, black, pylint |
| Unpinned | PyYAML, whirlpool-py311, liboqs-python |

## Security Risk Assessment

### High-Risk Dependencies

1. **cryptography (42.0.8)**
   - Contains known vulnerability CVE-2024-12797
   - Critical for core cryptographic operations
   - Recommendation: Update to version 44.0.1 or newer

### Medium-Risk Dependencies

1. **PyYAML (6.0.2)**
   - No known vulnerabilities in current version
   - Not strictly pinned in requirements
   - Used for configuration handling
   - Recommendation: Add version constraints

2. **whirlpool-py311 (1)**
   - Low maintenance activity
   - Used for hash algorithm
   - Recommendation: Monitor for updates and consider alternatives

### Low-Risk Dependencies

1. **argon2-cffi (23.1.0)**
   - No known vulnerabilities
   - Well-maintained by reputable author
   - Used for password hashing
   - Recommendation: Keep current pinning

2. **bcrypt (4.3.0)**
   - No known vulnerabilities
   - Maintained by Python Cryptographic Authority
   - Used for password hashing
   - Recommendation: Keep current pinning

## Recommended Actions

Based on the dependency audit, the following actions are recommended:

1. **Critical Updates**
   - Update cryptography to version 44.0.1 or newer to address CVE-2024-12797

2. **Version Pinning Improvements**
   - Add upper version bounds to PyYAML
   - Add version constraints to whirlpool-py311

3. **Dependency Documentation**
   - Document the purpose and security considerations for each dependency
   - Create a policy for dependency updates and security scanning

4. **Continuous Monitoring**
   - Implement regular security scanning for dependencies
   - Monitor security mailing lists for the critical dependencies
   - Set up automated alerts for new security advisories
