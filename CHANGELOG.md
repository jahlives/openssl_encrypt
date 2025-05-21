# Changelog

All notable changes to the openssl_encrypt project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Documentation

- Added comprehensive dependency inventory and security assessment
- Created dependency security plan with implementation timeline
- Added DEPENDENCY_MANAGEMENT.md with dependency handling guidelines
- Created VERSION_PINNING_POLICY.md with detailed versioning guidelines
- Added SECURITY_SCANNING_GUIDE.md for security tools usage
- Added CI_SECURITY_SCANNING.md for CI pipeline security integration
- Added this CHANGELOG file to track notable changes

## [0.8.2] - Previous Release

_Note: Previous release information will be added retrospectively_