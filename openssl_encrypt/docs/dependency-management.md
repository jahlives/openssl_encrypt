# Dependency Management - OpenSSL Encrypt

## Table of Contents

1. [Dependency Structure](#dependency-structure)
2. [Core Dependencies Inventory](#core-dependencies-inventory)
3. [Critical Dependencies Assessment](#critical-dependencies-assessment)
4. [Security Implementation Plan](#security-implementation-plan)
5. [Version Pinning Policy](#version-pinning-policy)
6. [Dependency Updates](#dependency-updates)
7. [Security Monitoring](#security-monitoring)
8. [Risk Assessment](#risk-assessment)

## Dependency Structure

The project uses a structured approach to dependency management with lock files for reproducible builds:

### File Organization

1. **Source `.in` Files**:
   - `requirements-prod.in`: Contains production dependencies with version constraints
   - `requirements-dev.in`: Contains development dependencies, includes production dependencies

2. **Lock `.txt` Files**:
   - `requirements-prod.txt`: Precisely pinned production dependencies
   - `requirements-dev.txt`: Precisely pinned development dependencies

3. **Build Configuration**:
   - `pyproject.toml`: Contains build dependencies
   - `setup.py`: Contains installation dependencies

### Usage

#### For Development
```bash
# Install all development dependencies
pip install -r requirements-dev.txt
```

#### For Production
```bash
# Install only production dependencies
pip install -r requirements-prod.txt
```

## Core Dependencies Inventory

### Critical Security Dependencies

| Dependency | Purpose | Version Constraint | License | Security Level |
|------------|---------|-------------------|---------|----------------|
| **cryptography** | Core cryptographic primitives and algorithms | >=44.0.1,<45.0.0 | Apache-2.0 | **CRITICAL** |
| **argon2-cffi** | Argon2 password hashing algorithm | >=23.1.0,<24.0.0 | MIT | **HIGH** |
| **PyYAML** | YAML parser for configuration files | >=6.0.2,<7.0.0 | MIT | **MEDIUM** |
| **whirlpool-py311** | Whirlpool hash algorithm for Python 3.11+ | >=1.0.0,<2.0.0 | Public Domain | **LOW** |

### Platform-Specific Dependencies

| Dependency | Purpose | Version Constraint | Platform | Notes |
|------------|---------|-------------------|----------|-------|
| **pywin32** | Windows-specific functionality | >=306,<307 | Windows only | System integration |

### Optional Dependencies

| Dependency | Purpose | Version Constraint | License | Notes |
|------------|---------|-------------------|---------|-------|
| **liboqs-python** | Post-quantum cryptography support | Not pinned | MIT | **Optional PQC** |

### Development Dependencies

| Dependency | Purpose | Version Constraint | License | Notes |
|------------|---------|-------------------|---------|-------|
| **pytest** | Testing framework | >=8.0.0,<9.0.0 | MIT | Unit testing |
| **pytest-cov** | Test coverage plugin | >=4.1.0,<5.0.0 | MIT | Coverage measurement |
| **black** | Code formatter | >=24.1.0,<25.0.0 | MIT | Code formatting |
| **pylint** | Static code analyzer | >=3.0.0,<4.0.0 | GPL-2.0 | Code quality |
| **bandit** | Security vulnerability scanner | >=1.7.0,<2.0.0 | Apache-2.0 | Security scanning |
| **mypy** | Static type checker | >=1.0.0,<2.0.0 | MIT | Type checking |

### Transitive Dependencies (Security-Relevant)

| Dependency | Purpose | Direct Parent | License | Security Notes |
|------------|---------|---------------|---------|----------------|
| **cffi** | C Foreign Function Interface | cryptography, argon2-cffi | MIT | Critical for crypto bindings |
| **pycparser** | C parser in Python | cffi | BSD-3-Clause | Used by cffi |
| **setuptools** | Build system | Multiple | MIT | Package installation |

## Critical Dependencies Assessment

### 1. cryptography (>=44.0.1,<45.0.0)

#### Usage in the Project
The `cryptography` package is the cornerstone of cryptographic operations:

- **Symmetric Encryption Algorithms**:
  - Fernet (authenticated encryption)
  - AES-GCM, AES-GCM-SIV, AES-OCB3 (AEAD modes)
  - ChaCha20-Poly1305, XChaCha20-Poly1305
  - AES-SIV

- **Hashing and Key Derivation**:
  - HKDF (Hash-based Key Derivation Function)
  - SHA-256, SHA-512, SHA3 variants
  - BLAKE2b hashing

- **Core Cryptographic Primitives**:
  - Secure random number generation
  - Message authentication codes
  - Digital signatures

#### Security Analysis
- **Current Requirement**: >=44.0.1,<45.0.0
- **Maintenance**: Actively maintained by the Python Cryptographic Authority
- **Vulnerabilities**: CVE-2024-12797 addressed in version 44.0.1
- **Risk Level**: **CRITICAL** - Any vulnerability directly compromises encryption security

### 2. argon2-cffi (>=23.1.0,<24.0.0)

#### Usage in the Project
- **Password-Based Key Derivation**: Converting user passwords into cryptographic keys
- **Memory-Hard Function**: Making brute-force attacks resource-intensive
- **Configurable Parameters**: Memory cost, time cost, and parallelism

#### Security Analysis
- **Current Requirement**: >=23.1.0,<24.0.0
- **Algorithm**: Implements Argon2id (winner of Password Hashing Competition)
- **Risk Level**: **HIGH** - Critical for password security

### 3. PyYAML (>=6.0.2,<7.0.0)

#### Usage in the Project
- **Configuration Files**: Parsing YAML configuration templates
- **Security Templates**: Loading paranoid, standard, and quick templates

#### Security Analysis
- **Security Considerations**: YAML parsing can be vulnerable to code injection
- **Mitigation**: Use safe loading methods only (`yaml.safe_load`)
- **Risk Level**: **MEDIUM** - Limited attack surface with safe usage

## Security Implementation Plan

### Phase 1: Immediate Security Updates ✅ COMPLETED

#### 1.1 Critical Dependency Updates
- **✅ Updated cryptography** from `>=42.0.0,<43.0.0` to `>=44.0.1,<45.0.0`
  - Addresses CVE-2024-12797 (AES-OCB mode key reuse vulnerability)
  - Prevents potential nonce-reuse attacks

#### 1.2 Version Constraint Improvements
- **✅ Added upper bounds** to all critical dependencies:
  - `PyYAML>=6.0.2,<7.0.0`
  - `whirlpool-py311>=1.0.0,<2.0.0`
  - `argon2-cffi>=23.1.0,<24.0.0`

#### 1.3 Development Dependencies
- **✅ Pinned development tools** with security implications:
  - `pytest>=8.0.0,<9.0.0`
  - `black>=24.1.0,<25.0.0`
  - `pylint>=3.0.0,<4.0.0`
  - `bandit>=1.7.0,<2.0.0`

### Phase 2: Enhanced Security Monitoring

#### 2.1 Automated Vulnerability Scanning
- **pip-audit integration** for continuous vulnerability monitoring
- **CI/CD pipeline** security scanning
- **GitLab security dashboard** integration

#### 2.2 Dependency Tracking
- **Lock file maintenance** with pip-tools
- **Regular security updates** following semantic versioning
- **Change documentation** for all security-related updates

## Version Pinning Policy

### Pinning Strategy

1. **Security-Critical Dependencies** (cryptography, argon2-cffi):
   - **Lower bound**: Minimum version with required security fixes
   - **Upper bound**: Next major version to prevent breaking changes
   - **Example**: `cryptography>=44.0.1,<45.0.0`

2. **Functional Dependencies** (PyYAML, pytest):
   - **Lower bound**: Minimum version with required features
   - **Upper bound**: Next major version for stability
   - **Example**: `PyYAML>=6.0.2,<7.0.0`

3. **Development Tools**:
   - **Compatible release**: Allow patch and minor updates
   - **Major version pinning**: Prevent breaking changes in tooling
   - **Example**: `black>=24.1.0,<25.0.0`

### Rationale

- **Security**: Allow patch updates containing security fixes
- **Stability**: Prevent unexpected breaking changes from major versions
- **Maintenance**: Balance between security and development velocity
- **Reproducibility**: Ensure consistent builds across environments

## Dependency Updates

### Update Process

#### Automated Updates
```bash
# Use the provided update script
scripts/update_dependencies.sh
```

#### Manual Updates
1. **Edit source files**:
   ```bash
   # Edit requirements-prod.in and requirements-dev.in
   vim requirements-prod.in
   ```

2. **Compile lock files**:
   ```bash
   pip-compile requirements-prod.in
   pip-compile requirements-dev.in
   ```

3. **Test changes**:
   ```bash
   # Install updated dependencies
   pip install -r requirements-dev.txt

   # Run test suite
   pytest

   # Run security scans
   bandit -r openssl_encrypt/
   ```

4. **Update setup.py**:
   ```bash
   # Ensure setup.py matches lock file constraints
   vim setup.py
   ```

### Update Schedule

- **Security Updates**: Immediate (within 24 hours of CVE disclosure)
- **Regular Updates**: Monthly review and update cycle
- **Major Version Updates**: Quarterly evaluation with thorough testing

## Security Monitoring

### Vulnerability Scanning

#### Tools Integration
1. **pip-audit**: Primary vulnerability scanner for Python packages
2. **Bandit**: Security vulnerability scanner for code
3. **GitLab Security Scanner**: Integrated CI/CD security scanning
4. **SBOM Generation**: Software Bill of Materials for compliance

#### Scanning Schedule
- **CI/CD Pipeline**: Every commit and merge request
- **Daily Scans**: Automated vulnerability scanning
- **Weekly Reports**: Comprehensive security assessment
- **Emergency Scans**: Upon CVE disclosure for used packages

#### Response Procedures
1. **High/Critical Vulnerabilities**:
   - Immediate assessment (within 4 hours)
   - Emergency update if patch available
   - Risk mitigation if no patch available

2. **Medium Vulnerabilities**:
   - Assessment within 24 hours
   - Scheduled update in next release cycle
   - Documentation of risk acceptance if needed

3. **Low Vulnerabilities**:
   - Assessment within 1 week
   - Update in regular maintenance cycle

### Monitoring Tools Configuration

#### pip-audit
```bash
# Scan for vulnerabilities
pip-audit --requirement requirements-prod.txt --format json

# Generate SBOM
pip-audit --requirement requirements-prod.txt --format cyclonedx-json --output sbom.json
```

#### Bandit
```bash
# Security code analysis
bandit -r openssl_encrypt/ -f json -o security-report.json
```

## Risk Assessment

### Dependency Risk Matrix

| Risk Level | Dependencies | Impact | Mitigation |
|------------|-------------|---------|------------|
| **CRITICAL** | cryptography | Complete compromise of encryption | Immediate updates, security monitoring |
| **HIGH** | argon2-cffi | Password security compromise | Regular updates, vulnerability scanning |
| **MEDIUM** | PyYAML, pytest | Limited attack surface | Safe usage patterns, version pinning |
| **LOW** | whirlpool-py311, black | Minimal security impact | Standard update procedures |

### Risk Mitigation Strategies

1. **Supply Chain Security**:
   - Verify package signatures when available
   - Use package index mirrors for reliability
   - Monitor for typosquatting attacks

2. **Dependency Isolation**:
   - Virtual environments for development
   - Container-based deployments
   - Minimal dependency surface

3. **Security Hardening**:
   - Regular security audits
   - Automated vulnerability scanning
   - Incident response procedures

### Compliance Considerations

- **FIPS Compliance**: cryptography package provides FIPS-validated algorithms
- **Industry Standards**: Dependencies align with NIST recommendations
- **License Compliance**: All dependencies use OSI-approved licenses
- **Export Controls**: Consider encryption export regulations

---

This dependency management documentation ensures secure, reliable, and maintainable dependency handling for the OpenSSL Encrypt project. Regular review and updates of this documentation are essential as the dependency landscape evolves.

**Last updated**: June 16, 2025
