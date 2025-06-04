# Static Code Analysis for openssl_encrypt

This document describes the comprehensive static code analysis setup for the openssl_encrypt project, focusing on security, code quality, and maintainability.

## Overview

Our static analysis strategy uses a multi-layered approach:

1. **Client-side (Pre-commit)**: Fast feedback during development
2. **Server-side (GitLab CI)**: Comprehensive analysis after push
3. **Security-focused**: Multiple tools specifically for cryptographic code security

## Quick Start

### Setup (One-time)

```bash
# Install and configure all static analysis tools
./scripts/setup_static_analysis.sh

# Or install pre-commit manually
pip install pre-commit
pre-commit install
```

### Daily Usage

```bash
# Format code before committing
make format

# Run all checks
make lint
make security
make type-check

# Or let pre-commit do it automatically
git commit -m "Your changes"  # Runs checks automatically
```

## Tools Overview

### 🔒 Security Analysis

#### Bandit
- **Purpose**: Python security vulnerability scanner
- **Configuration**: `.bandit.yaml`
- **Focus**: Cryptographic code security patterns
- **Runs**: Pre-commit + GitLab CI

```bash
# Manual run
bandit -r openssl_encrypt/ -c .bandit.yaml
```

#### Semgrep
- **Purpose**: Advanced static analysis for security patterns
- **Rulesets**: `security-audit`, `python`, `auto`
- **Runs**: GitLab CI only
- **Coverage**: OWASP Top 10, CWE patterns

```bash
# Manual run  
semgrep --config=p/security-audit openssl_encrypt/
```

#### pip-audit
- **Purpose**: Dependency vulnerability scanning
- **Scope**: Production and development dependencies
- **Runs**: Pre-commit + GitLab CI

```bash
# Manual run
pip-audit --requirement requirements-prod.txt
```

### 🎨 Code Quality

#### Black
- **Purpose**: Code formatting
- **Configuration**: Line length 100, aggressive formatting
- **Runs**: Pre-commit
- **Auto-fix**: Yes

```bash
# Manual run
black openssl_encrypt/ --line-length=100
```

#### isort
- **Purpose**: Import sorting and organization
- **Configuration**: Compatible with Black
- **Runs**: Pre-commit
- **Auto-fix**: Yes

```bash
# Manual run
isort openssl_encrypt/ --profile black
```

#### Flake8
- **Purpose**: Linting and style checking
- **Plugins**: 
  - `flake8-bugbear`: Additional bug checks
  - `flake8-security`: Security-focused linting
  - `flake8-docstrings`: Documentation checks
- **Runs**: Pre-commit

```bash
# Manual run
flake8 openssl_encrypt/ --max-line-length=100
```

#### Pylint
- **Purpose**: Comprehensive code quality analysis
- **Configuration**: `.pylintrc`
- **Scoring**: Minimum 8.0/10 for release branches
- **Runs**: GitLab CI

```bash
# Manual run
pylint openssl_encrypt/
```

### 🔍 Type Checking

#### MyPy
- **Purpose**: Static type checking
- **Configuration**: `mypy.ini`
- **Coverage**: Gradual typing with security modules prioritized
- **Runs**: Pre-commit + GitLab CI

```bash
# Manual run
mypy openssl_encrypt/ --config-file mypy.ini
```

### 📊 Complexity Analysis

#### Radon
- **Purpose**: Code complexity metrics
- **Metrics**:
  - Cyclomatic complexity
  - Maintainability index
  - Halstead complexity
  - Raw metrics (LOC, etc.)
- **Runs**: GitLab CI

```bash
# Manual run
radon cc openssl_encrypt/  # Complexity
radon mi openssl_encrypt/  # Maintainability
```

## Configuration Files

### Pre-commit Configuration (`.pre-commit-config.yaml`)
Defines all client-side checks that run before commits:
- Code formatting (Black, isort)
- Security scanning (Bandit, GitGuardian)
- Type checking (MyPy)
- Linting (Flake8, pydocstyle)
- File validation (YAML, JSON, etc.)

### Bandit Configuration (`.bandit.yaml`)
Security-focused configuration for cryptographic code:
- Excludes test directories
- Focuses on crypto-specific security patterns
- Custom rules for weak randomness and hardcoded keys
- JSON output for CI integration

### Pylint Configuration (`.pylintrc`)
Comprehensive code quality configuration:
- Crypto-friendly naming conventions (`iv`, `pk`, `sk`, etc.)
- Security-focused enabled checks
- Appropriate thresholds for crypto code complexity
- Module-specific configuration

### MyPy Configuration (`mypy.ini`)
Type checking configuration:
- Gradual typing approach
- Stricter typing for security modules
- Third-party library stubs
- Platform-specific settings

## GitLab CI Integration

### Security Stage Jobs

1. **dependency-scan**: Vulnerability scanning of dependencies
2. **code-security-scan**: Bandit security analysis
3. **code-quality-scan**: Pylint code quality analysis
4. **type-checking**: MyPy type checking
5. **semgrep-security-scan**: Advanced security pattern detection
6. **code-complexity-scan**: Complexity and maintainability analysis
7. **sbom-generation**: Software Bill of Materials

### Artifacts and Reports

All analysis results are saved as artifacts:
- **GitLab Security Dashboard**: SAST and dependency scanning
- **JSON Reports**: Machine-readable results for automation
- **HTML Reports**: Human-readable visualizations
- **Text Reports**: Terminal-friendly output

### Branch Protection

- **Release branches**: All checks must pass
- **Development branches**: Checks run but don't block
- **Merge requests**: All checks run for review

## Best Practices

### For Developers

1. **Run checks locally**: Use `make` commands before pushing
2. **Address pre-commit issues**: Fix formatting and basic issues locally
3. **Review CI reports**: Check GitLab CI artifacts for detailed analysis
4. **Prioritize security issues**: Address Bandit and Semgrep findings first

### For Cryptographic Code

1. **Use `secrets` module**: Never use `random` for cryptographic purposes
2. **Avoid hardcoded keys**: Use configuration or environment variables
3. **Document complex functions**: High complexity is acceptable if documented
4. **Type hint security functions**: Use strict typing for security-critical code

### For CI/CD

1. **Monitor trends**: Track complexity and quality metrics over time
2. **Set quality gates**: Enforce minimum standards for releases
3. **Regular updates**: Keep analysis tools updated
4. **Baseline management**: Use Bandit baselines for false positives

## Makefile Commands

```bash
make format          # Format code with black and isort
make lint            # Run all linting tools  
make security        # Run security analysis
make type-check      # Run type checking with mypy
make complexity      # Analyze code complexity
make test-all        # Run all tests
make clean           # Clean analysis reports
make install-dev     # Install development dependencies
make setup-analysis  # Setup static analysis tools
```

## Troubleshooting

### Common Issues

#### Pre-commit fails with formatting issues
```bash
# Fix automatically
make format
git add .
git commit -m "Your message"
```

#### Bandit false positives
```bash
# Add to .bandit.yaml skips section or use inline comments
# nosec comment for specific lines
password = "test_password"  # nosec B105
```

#### MyPy import errors
```bash
# Install type stubs
pip install types-PyYAML types-requests

# Or add to mypy.ini ignore list
[mypy-problematic_module.*]
ignore_missing_imports = True
```

#### Pylint too strict
```bash
# Disable specific checks in .pylintrc
disable=C0103,R0913

# Or use inline comments
def complex_crypto_function():  # pylint: disable=too-many-locals
```

### Performance Tips

1. **Use pre-commit**: Faster feedback than waiting for CI
2. **Incremental checks**: Many tools support checking only changed files
3. **Parallel execution**: Most tools support multi-core processing
4. **Smart exclusions**: Exclude test and build directories

## Integration with IDEs

### VS Code
Install extensions:
- Python
- Pylint  
- MyPy
- Black Formatter
- Bandit

### PyCharm
Configure external tools:
- Black formatter
- Pylint inspection
- MyPy checking
- Bandit security

### Vim/Neovim
Use plugins:
- `ale` for async linting
- `black` for formatting
- `mypy` for type checking

## Metrics and Monitoring

### Quality Metrics Tracked

- **Security**: Number of Bandit/Semgrep findings
- **Code Quality**: Pylint score and violation counts
- **Type Coverage**: MyPy type checking coverage
- **Complexity**: Cyclomatic complexity and maintainability index
- **Dependencies**: Known vulnerabilities in dependencies

### Trends to Monitor

- Increasing complexity over time
- Declining code quality scores
- Growing number of security findings
- Type coverage regression
- Dependency vulnerability accumulation

## Security Considerations

### Tool Selection Rationale

- **Bandit**: Industry standard for Python security
- **Semgrep**: Advanced pattern matching for complex security issues
- **pip-audit**: Official Python vulnerability database
- **GitGuardian**: Secret detection and credential scanning

### Cryptographic Code Specific

- **Constant-time operations**: Custom rules for timing attack prevention
- **Key material handling**: Detection of hardcoded keys and weak randomness
- **Algorithm validation**: Checks for deprecated cryptographic algorithms
- **Side-channel resistance**: Analysis for potential information leakage

### Compliance

This static analysis setup helps ensure compliance with:
- **OWASP**: Top 10 security vulnerabilities
- **CWE**: Common Weakness Enumeration
- **NIST**: Cryptographic standards and recommendations
- **PCI DSS**: Payment card industry standards (where applicable)

## Maintenance

### Regular Tasks

- **Monthly**: Update tool versions and rulesets
- **Quarterly**: Review and tune configuration files
- **Per Release**: Generate comprehensive analysis reports
- **Annually**: Evaluate new tools and methodologies

### Configuration Updates

When updating configurations:
1. Test changes locally first
2. Update documentation
3. Communicate changes to team
4. Monitor for new false positives
5. Adjust baselines as needed

---

For questions or improvements to this static analysis setup, please open an issue or submit a merge request.