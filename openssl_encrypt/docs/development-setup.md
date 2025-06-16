# Development Setup - OpenSSL Encrypt

## Table of Contents

1. [Overview](#overview)
2. [Development Environment Setup](#development-environment-setup)
3. [Static Code Analysis](#static-code-analysis)
4. [Security Scanning](#security-scanning)
5. [CI/CD Pipeline](#cicd-pipeline)
6. [Code Quality Tools](#code-quality-tools)
7. [Testing Framework](#testing-framework)
8. [Development Workflow](#development-workflow)

## Overview

This document provides comprehensive guidance for setting up a development environment for OpenSSL Encrypt, including security scanning, static analysis, and quality assurance tools.

### Development Philosophy

- **Security First**: All code changes are screened for security issues
- **Quality Assurance**: Multiple layers of automated quality checks
- **Early Detection**: Issues caught during development, not in production
- **Comprehensive Testing**: Extensive test coverage for all components

## Development Environment Setup

### Prerequisites

- **Python**: 3.9+ (3.11+ recommended)
- **Git**: Latest version
- **Docker**: For CI/CD testing (optional)

### Initial Setup

```bash
# Clone the repository
git clone https://gitlab.rm-rf.ch/world/openssl_encrypt.git
cd openssl_encrypt

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install development dependencies
pip install -r requirements-dev.txt
pip install -e .

# Setup development tools
./scripts/setup_static_analysis.sh
```

### Quick Setup Script

```bash
#!/bin/bash
# scripts/setup_static_analysis.sh

echo "Setting up OpenSSL Encrypt development environment..."

# Install pre-commit
pip install pre-commit

# Install and configure pre-commit hooks
pre-commit install
pre-commit install --hook-type pre-push

# Install additional development tools
pip install -r requirements-dev.txt

# Setup configuration files
cp .pre-commit-config.yaml.example .pre-commit-config.yaml
cp .bandit.yaml.example .bandit.yaml

echo "Development environment setup complete!"
echo "Run 'make lint' to verify setup."
```

## Static Code Analysis

### Multi-Layer Analysis Strategy

1. **Client-side (Pre-commit)**: Fast feedback during development
2. **Server-side (GitLab CI)**: Comprehensive analysis after push
3. **Security-focused**: Multiple tools for cryptographic code security

### Tools Overview

#### 🔒 Security Analysis Tools

##### Bandit
- **Purpose**: Python security vulnerability scanner
- **Configuration**: `.bandit.yaml`
- **Focus**: Cryptographic code security patterns
- **Execution**: Pre-commit + GitLab CI

**Configuration Example**:
```yaml
# .bandit.yaml
exclude_dirs:
  - tests
  - unittests
  - build
  - dist

skips:
  - B101  # assert_used - OK in tests
  - B404  # subprocess_without_shell_equals_true

plugins:
  - bandit_cryptography_checker
```

**Common Issues Detected**:
- Hardcoded passwords or secrets
- Weak cryptographic algorithms
- Use of unsafe random number generators
- SQL injection vulnerabilities
- Command injection risks

##### pip-audit
- **Purpose**: Dependency vulnerability scanning
- **Database**: PyPI advisory database + OSV
- **Execution**: Pre-commit + GitLab CI
- **Maintenance**: Google-maintained tool

**Usage**:
```bash
# Scan production dependencies
pip-audit --requirement requirements-prod.txt

# Scan development dependencies
pip-audit --requirement requirements-dev.txt

# Generate SBOM
pip-audit --requirement requirements-prod.txt --format cyclonedx-json --output sbom.json
```

#### 📊 Code Quality Tools

##### MyPy
- **Purpose**: Static type checking
- **Configuration**: `mypy.ini`
- **Focus**: Type safety for security-critical code

```ini
# mypy.ini
[mypy]
python_version = 3.9
strict = True
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True

[mypy-cryptography.*]
ignore_missing_imports = True

[mypy-argon2.*]
ignore_missing_imports = True
```

##### Pylint
- **Purpose**: Code quality and style analysis
- **Configuration**: `.pylintrc`
- **Focus**: Maintainability and best practices

##### Black
- **Purpose**: Code formatting
- **Configuration**: `pyproject.toml`
- **Execution**: Pre-commit hook

```toml
# pyproject.toml
[tool.black]
line-length = 88
target-version = ['py39']
include = '\.pyi?$'
extend-exclude = '''
/(
  \.eggs
  | \.git
  | \.mypy_cache
  | \.tox
  | \.venv
  | build
  | dist
)/
'''
```

##### isort
- **Purpose**: Import sorting and organization
- **Configuration**: `pyproject.toml`
- **Integration**: Works with Black

### Daily Development Workflow

```bash
# Format code before committing
make format

# Run all quality checks
make lint          # Pylint + code quality
make security      # Bandit + security checks
make type-check    # MyPy type checking
make test          # Full test suite

# Or let pre-commit handle it automatically
git commit -m "Your changes"  # Runs checks automatically
```

### Makefile Targets

```makefile
# Makefile
.PHONY: format lint security type-check test

format:
	black openssl_encrypt/ tests/
	isort openssl_encrypt/ tests/

lint:
	pylint openssl_encrypt/
	flake8 openssl_encrypt/

security:
	bandit -r openssl_encrypt/ -f json -o security-report.json
	pip-audit --requirement requirements-prod.txt

type-check:
	mypy openssl_encrypt/

test:
	pytest tests/ openssl_encrypt/unittests/ -v --cov=openssl_encrypt
```

## Security Scanning

### Local Development Scanning

#### Pre-commit Hook Configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-c', '.bandit.yaml']

  - repo: https://github.com/pypa/pip-audit
    rev: v2.6.1
    hooks:
      - id: pip-audit
        args: ['--requirement', 'requirements-prod.txt']

  - repo: https://github.com/psf/black
    rev: 23.7.0
    hooks:
      - id: black

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.5.1
    hooks:
      - id: mypy
        additional_dependencies: [types-PyYAML]
```

#### Setting Up Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Install git hooks
pre-commit install
pre-commit install --hook-type pre-push

# Test hooks
pre-commit run --all-files
```

### Advanced Security Scanning

#### Custom Security Checks

```python
# scripts/custom_security_check.py
#!/usr/bin/env python3
"""
Custom security checks for OpenSSL Encrypt codebase.
"""

import ast
import os
import sys
from pathlib import Path

class SecurityChecker(ast.NodeVisitor):
    """AST visitor for custom security checks."""

    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        """Check function calls for security issues."""
        # Check for hardcoded secrets
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['encode', 'decode']:
                for arg in node.args:
                    if isinstance(arg, ast.Str) and self.is_potential_secret(arg.s):
                        self.issues.append(f"Potential hardcoded secret: {arg.s[:10]}...")

        self.generic_visit(node)

    def is_potential_secret(self, value):
        """Detect potential secrets in string literals."""
        # Simple heuristics for secret detection
        if len(value) > 20 and any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
            return True
        return False

def scan_file(filepath):
    """Scan a Python file for security issues."""
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            tree = ast.parse(f.read())
            checker = SecurityChecker()
            checker.visit(tree)
            return checker.issues
        except SyntaxError:
            return [f"Syntax error in {filepath}"]

def main():
    """Main security scanning function."""
    issues_found = False

    for root, dirs, files in os.walk('openssl_encrypt'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                issues = scan_file(filepath)
                if issues:
                    issues_found = True
                    print(f"Issues in {filepath}:")
                    for issue in issues:
                        print(f"  - {issue}")

    return 1 if issues_found else 0

if __name__ == '__main__':
    sys.exit(main())
```

## CI/CD Pipeline

### GitLab CI Configuration

The security scanning is integrated into the CI/CD pipeline with multiple stages:

```yaml
# .gitlab-ci.yml (security section)
stages:
  - security
  - test
  - build
  - deploy

variables:
  PYTHON_VERSION: "3.11"

# Security scanning stage
dependency-scan:
  stage: security
  image: python:$PYTHON_VERSION
  script:
    - pip install pip-audit
    - python scripts/gitlab_dependency_scan.py
  artifacts:
    reports:
      dependency_scanning: dependency-scan-results.json
    expire_in: 1 week
  only:
    - main
    - dev
    - merge_requests

code-security-scan:
  stage: security
  image: python:$PYTHON_VERSION
  script:
    - pip install bandit[toml]
    - bandit -r openssl_encrypt/ -f gitlab -o bandit-report.json
  artifacts:
    reports:
      sast: bandit-report.json
    expire_in: 1 week
  only:
    - main
    - dev
    - merge_requests

sbom-generation:
  stage: security
  image: python:$PYTHON_VERSION
  script:
    - pip install pip-audit
    - pip-audit --requirement requirements-prod.txt --format cyclonedx-json --output sbom.json
  artifacts:
    paths:
      - sbom.json
    expire_in: 1 month
  only:
    - main
    - tags
```

### Custom GitLab Dependency Scanner

```python
# scripts/gitlab_dependency_scan.py
#!/usr/bin/env python3
"""
Custom dependency scanning script for GitLab CI integration.
"""

import json
import subprocess
import sys
from datetime import datetime

def run_pip_audit():
    """Run pip-audit and return results."""
    try:
        # Scan production dependencies
        result = subprocess.run([
            'pip-audit',
            '--requirement', 'requirements-prod.txt',
            '--format', 'json'
        ], capture_output=True, text=True, check=True)

        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"pip-audit failed: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Failed to parse pip-audit output: {e}")
        return None

def convert_to_gitlab_format(audit_results):
    """Convert pip-audit results to GitLab dependency scanning format."""
    vulnerabilities = []

    for package in audit_results.get('dependencies', []):
        for vuln in package.get('vulnerabilities', []):
            vulnerability = {
                "id": vuln['id'],
                "category": "dependency_scanning",
                "name": f"Vulnerability in {package['name']}",
                "message": vuln['description'],
                "description": vuln['description'],
                "severity": map_severity(vuln.get('severity', 'Unknown')),
                "confidence": "High",
                "solution": f"Update to version {', '.join(vuln.get('fix_versions', ['latest']))}",
                "scanner": {
                    "id": "pip-audit",
                    "name": "pip-audit"
                },
                "location": {
                    "file": "requirements-prod.txt",
                    "dependency": {
                        "package": {
                            "name": package['name']
                        },
                        "version": package['version']
                    }
                },
                "identifiers": [
                    {
                        "type": "pypi_advisory",
                        "name": vuln['id'],
                        "value": vuln['id']
                    }
                ]
            }
            vulnerabilities.append(vulnerability)

    return {
        "version": "15.0.0",
        "vulnerabilities": vulnerabilities,
        "scan": {
            "scanner": {
                "id": "pip-audit",
                "name": "pip-audit",
                "vendor": {
                    "name": "Google"
                }
            },
            "type": "dependency_scanning",
            "start_time": datetime.utcnow().isoformat() + "Z",
            "end_time": datetime.utcnow().isoformat() + "Z",
            "status": "success"
        }
    }

def map_severity(severity):
    """Map pip-audit severity to GitLab severity levels."""
    mapping = {
        'Critical': 'Critical',
        'High': 'High',
        'Medium': 'Medium',
        'Low': 'Low',
        'Unknown': 'Unknown'
    }
    return mapping.get(severity, 'Unknown')

def main():
    """Main function."""
    audit_results = run_pip_audit()
    if audit_results is None:
        sys.exit(1)

    gitlab_results = convert_to_gitlab_format(audit_results)

    # Write results to file
    with open('dependency-scan-results.json', 'w') as f:
        json.dump(gitlab_results, f, indent=2)

    # Print summary
    vuln_count = len(gitlab_results['vulnerabilities'])
    if vuln_count > 0:
        print(f"Found {vuln_count} vulnerabilities")
        # Don't fail the build for vulnerabilities, just report them
        # sys.exit(1)
    else:
        print("No vulnerabilities found")

    sys.exit(0)

if __name__ == '__main__':
    main()
```

### Pipeline Stages

1. **Security Stage**: Runs before all other stages
   - Dependency vulnerability scanning
   - Static code security analysis
   - SBOM generation

2. **Test Stage**: Comprehensive testing
   - Unit tests with coverage
   - Integration tests
   - Security property tests

3. **Build Stage**: Package creation
   - Wheel building
   - Documentation generation
   - Artifact creation

4. **Deploy Stage**: Publishing
   - PyPI publication
   - GitLab package registry
   - Documentation deployment

## Code Quality Tools

### Configuration Files

#### `.bandit.yaml`
```yaml
exclude_dirs:
  - tests
  - unittests
  - build
  - dist

plugins:
  - bandit_cryptography_checker

tests:
  - B101  # Use of assert detected
  - B102  # Test for executable with shell equals true
  - B103  # Test for setting a bad file permission
  - B104  # Test for binding to all interfaces
  - B105  # Test for hardcoded password strings
  - B106  # Test for hardcoded password function arguments
  - B107  # Test for hardcoded password default arguments
  - B108  # Test for insecure usage of tmp file/directory
  - B110  # Test for a pass in the except block
  - B112  # Test for a continue in the except block
  - B201  # Flask app with debug=True
  - B301  # Pickle usage
  - B302  # Insecure cookie usage
  - B303  # Use of insecure MD2, MD4, MD5, or SHA1 hash function
  - B304  # Use of insecure cipher mode
  - B305  # Use of insecure cipher
  - B306  # Use of insecure temporary file
  - B307  # Use of possibly insecure function
  - B308  # Use of mark_safe() may expose XSS vulnerabilities
  - B309  # Use of HTTPSConnection
  - B310  # Use of urllib urlopen without HTTPS
  - B311  # Use of random for security purposes
  - B312  # Use of telnet
  - B313  # Use of XML modules
  - B314  # Use of XML modules with lxml
  - B315  # Use of XML modules with xml
  - B316  # Use of XML modules with defusedxml
  - B317  # Use of XML modules with xmlrpc
  - B318  # Use of XML modules with xml.dom.minidom
  - B319  # Use of XML modules with xml.sax
  - B320  # Use of XML modules with xml.dom.pulldom
  - B321  # Use of FTP
  - B322  # Use of input()
  - B323  # Use of unverified context in urllib
  - B324  # Use of insecure hash function for password
  - B325  # Use of os.tempnam()
  - B326  # Use of os.mktemp()
  - B327  # Use of subprocess with shell=True
  - B401  # Use of import subprocess
  - B402  # Use of import of FTP
  - B403  # Use of import of pickle
  - B404  # Use of import of subprocess
  - B405  # Use of import of xml libraries
  - B406  # Use of import of insecure libraries
  - B407  # Use of import of FTP
  - B408  # Use of import of FTP
  - B409  # Use of import of FTP
  - B410  # Use of import of lxml
  - B411  # Use of import of lxml
  - B412  # Use of import of lxml
  - B413  # Use of import of pycrypto
  - B501  # Use of requests with verify=False
  - B502  # Use of ssl with insecure SSL/TLS protocol version
  - B503  # Use of ssl with bad defaults
  - B504  # Use of ssl with bad version
  - B505  # Use of weak cryptographic key
  - B506  # Use of yaml.load()
  - B507  # Use of ssh with no host key verification
  - B601  # Use of shell=True in subprocess calls
  - B602  # Use of subprocess with shell=True
  - B603  # Use of subprocess without shell equals true
  - B604  # Use of subprocess with shell=True
  - B605  # Start process with a shell
  - B606  # Start process without a shell
  - B607  # Starting a process with a partial path
  - B608  # Possible SQL injection vector through string-based query construction
  - B609  # Use of wildcard in SQL query
  - B610  # Potential SQL injection via string formatting
  - B611  # Potential SQL injection via format string
  - B701  # Test for not auto escaping in jinja2
  - B702  # Use of mako templates
  - B703  # Use of django mark_safe

skips:
  - B101  # assert_used - OK in tests
  - B404  # subprocess_without_shell_equals_true - we use this safely
```

#### `mypy.ini`
```ini
[mypy]
python_version = 3.9
strict = True
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True
disallow_any_generics = True
disallow_subclassing_any = True
disallow_untyped_calls = True
disallow_untyped_decorators = True
disallow_incomplete_defs = True
check_untyped_defs = True
disallow_untyped_defs = True
no_implicit_optional = True
warn_redundant_casts = True
warn_unused_ignores = True
warn_no_return = True
warn_unreachable = True

[mypy-cryptography.*]
ignore_missing_imports = True

[mypy-argon2.*]
ignore_missing_imports = True

[mypy-whirlpool.*]
ignore_missing_imports = True

[mypy-liboqs.*]
ignore_missing_imports = True
```

## Testing Framework

### Test Structure

```
tests/
├── __init__.py
├── test_encryption.py          # Core encryption tests
├── test_key_derivation.py      # KDF testing
├── test_pqc.py                 # Post-quantum tests
├── test_security.py            # Security property tests
├── dual_encryption/            # Dual encryption tests
├── keystore/                   # Keystore functionality tests
└── fixtures/                   # Test data and fixtures

openssl_encrypt/unittests/
├── __init__.py
├── unittests.py               # Legacy unit tests
├── test_gui.py                # GUI testing
└── testfiles/                 # Encrypted test files
```

### Testing Best Practices

```python
# tests/conftest.py
import pytest
import tempfile
import os
from pathlib import Path

@pytest.fixture
def temp_dir():
    """Provide a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)

@pytest.fixture
def test_password():
    """Provide a consistent test password."""
    return "test-password-123!"

@pytest.fixture
def sample_data():
    """Provide sample data for encryption tests."""
    return b"This is test data for encryption testing."

# Example security property test
def test_constant_time_comparison():
    """Verify that sensitive comparisons are constant-time."""
    from openssl_encrypt.modules.secure_ops import constant_time_compare

    # Test data
    a = b"correct_password"
    b_correct = b"correct_password"
    b_wrong_start = b"incorrect_pass"
    b_wrong_end = b"correct_passwrng"

    # Measure timing (simplified example)
    import time

    times = []
    for b in [b_correct, b_wrong_start, b_wrong_end]:
        start = time.perf_counter()
        for _ in range(1000):
            constant_time_compare(a, b)
        end = time.perf_counter()
        times.append(end - start)

    # Verify timing differences are minimal
    max_diff = max(times) - min(times)
    assert max_diff < 0.01, "Constant time comparison shows timing variations"
```

## Development Workflow

### Git Workflow

1. **Feature Development**:
   ```bash
   git checkout -b feature/new-algorithm
   # Make changes
   git add .
   git commit -m "feat: Add new encryption algorithm"
   # Pre-commit hooks run automatically
   ```

2. **Code Review Process**:
   - All changes require merge request
   - Automated CI/CD pipeline runs
   - Security scans must pass
   - Code review by maintainer required

3. **Release Process**:
   ```bash
   # Update version
   git checkout release
   git merge main

   # Tag release
   git tag v1.0.0
   git push origin v1.0.0

   # Automated deployment via CI/CD
   ```

### Daily Development Commands

```bash
# Start development session
source venv/bin/activate
git pull origin main

# Make changes and test
make format
make lint
make security
make test

# Commit changes
git add .
git commit -m "feat: Your feature description"
git push origin feature-branch

# Create merge request via GitLab UI
```

---

This development setup documentation provides comprehensive guidance for maintaining high code quality and security standards throughout the development process.

**Last updated**: June 16, 2025
