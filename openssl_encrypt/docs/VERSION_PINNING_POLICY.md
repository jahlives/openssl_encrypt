# Version Pinning Policy

This document outlines the policy for specifying version constraints on dependencies in the openssl_encrypt project. Following these guidelines ensures a balance between stability, security, and maintainability.

## Core Principles

Our version pinning strategy is guided by the following principles:

1. **Security**: Ensure timely updates for security patches
2. **Stability**: Prevent unexpected breaking changes
3. **Reproducibility**: Enable reproducible builds
4. **Flexibility**: Allow compatible updates without manual intervention
5. **Clarity**: Make dependency requirements clear and explicit

## Semantic Versioning

We follow the [Semantic Versioning](https://semver.org/) (SemVer) principles where:

- **MAJOR** version changes (`X.y.z`) indicate incompatible API changes
- **MINOR** version changes (`x.Y.z`) add functionality in a backward-compatible manner
- **PATCH** version changes (`x.y.Z`) indicate backward-compatible bug fixes

## Version Specifier Guidelines

### Security-Critical Dependencies

For dependencies that directly affect cryptographic operations or security:

```python
cryptography>=44.0.1,<45.0.0
```

**Guidelines**:
- **Always specify both lower and upper bounds**
- Set lower bound to a specific secure version
- Limit upper bound to prevent automatic major version upgrades
- Always include in the critical security review process

**Examples**:
- `cryptography>=44.0.1,<45.0.0` (Allows patch updates but not major/minor)
- `argon2-cffi>=23.1.0,<24.0.0` (Same approach for password hashing library)

### Standard Dependencies

For regular dependencies that are stable and well-maintained:

```python
bcrypt~=4.3.0
```

**Guidelines**:
- Use the compatible release operator (`~=`) for stable libraries
- Allows patch-level updates automatically
- Prevents minor version updates that might introduce subtle changes

**Examples**:
- `bcrypt~=4.3.0` (Allows 4.3.x but not 4.4.0 or higher)
- `PyYAML>=6.0.2,<7.0.0` (Alternative approach, allows minor updates within a major version)

### Development Dependencies

For tools used in the development process but not in production:

```python
pytest>=8.0.0,<9.0.0
```

**Guidelines**:
- Specify a minimum version with a major version cap
- More flexible than production dependencies
- Still prevents major version jumps that might break CI pipelines

**Examples**:
- `pytest>=8.0.0,<9.0.0`
- `black>=24.1.0,<25.0.0`

### Platform-Specific Dependencies

For dependencies that only apply to specific platforms:

```python
pywin32>=306,<307; sys_platform == 'win32'
```

**Guidelines**:
- Include environment markers for platform specificity
- Follow version pinning rules based on the dependency's category above
- Document the platform requirement clearly

### Optional Dependencies

For functionality that is not required for core operations:

```python
# liboqs-python>=0.7.0,<0.8.0  # Uncomment to enable post-quantum cryptography
```

**Guidelines**:
- Comment out optional dependencies in requirements files
- Document how to enable them
- Still use appropriate version pins when they are enabled

## Version Specifiers Reference

| Specifier | Example | Meaning |
|-----------|---------|---------|
| `==` | `==1.2.3` | Exact version only |
| `>=` | `>=1.2.3` | Minimum version (inclusive) |
| `<=` | `<=1.2.3` | Maximum version (inclusive) |
| `<` | `<2.0.0` | Less than version (exclusive) |
| `>` | `>1.0.0` | Greater than version (exclusive) |
| `~=` | `~=1.2.3` | Compatible release (≥1.2.3, <1.3.0) |
| `>=X.Y.Z,<X+1.0.0` | `>=3.1.2,<4.0.0` | Allow minor and patch updates within a major version |
| `>=X.Y.Z,<X.Y+1.0` | `>=3.1.2,<3.2.0` | Allow only patch updates within a minor version |

## When to Use Each Specifier

### Exact Pinning (`==`)

**When to use**:
- In lock files (requirements-prod.txt, requirements-dev.txt)
- For dependencies with known compatibility issues
- In CI/CD environments where reproducibility is critical

**Example**: `cryptography==44.0.1`

### Compatible Release (`~=`)

**When to use**:
- For stable, well-maintained libraries
- When you want automatic security updates
- When the dependency follows semantic versioning strictly

**Example**: `bcrypt~=4.3.0` (allows 4.3.1, 4.3.2, but not 4.4.0)

### Range with Upper Bound (`>=X.Y.Z,<X+1.0.0`)

**When to use**:
- For dependencies that you want to keep updated
- When minor releases are generally safe
- For security-related dependencies where updates are important

**Example**: `PyYAML>=6.0.2,<7.0.0`

### Range with Strict Upper Bound (`>=X.Y.Z,<X.Y+1.0`)

**When to use**:
- For critical dependencies where even minor updates need review
- For dependencies with a history of breaking changes in minor releases
- In sensitive security contexts

**Example**: `cryptography>=44.0.1,<45.0.0`

## Exception Handling

While this policy provides general guidelines, exceptions may be necessary in specific cases.

### Criteria for Exceptions

1. **Dependency Behavior**: Some libraries don't follow SemVer strictly
2. **Security Requirements**: Critical security fixes might override normal pinning
3. **Technical Constraints**: Some dependencies may have complex interdependencies

### Exception Process

1. **Documentation**: Clearly document the reason for the exception
2. **Risk Assessment**: Evaluate and document the risks
3. **Approval**: Require review by a second developer
4. **Testing**: Implement comprehensive tests for the specific dependency

## Dependency Update Workflow

1. **Regular Updates**:
   - Run `scripts/update_dependencies.sh` to update all dependencies
   - Review changes in the lock files
   - Test thoroughly before merging

2. **Security Updates**:
   - Update the source `.in` files with new constraints
   - Regenerate lock files
   - Create priority pull request with security tag

3. **Breaking Changes**:
   - Document the breaking change in CHANGELOG.md
   - Adjust code to accommodate the new API
   - Update version constraints in requirements-*.in files
   - Regenerate lock files

## Compliance Verification

- CI pipeline should verify that all dependencies comply with this policy
- Reviews should check for appropriate version constraints
- Lock files should be updated when source requirements change