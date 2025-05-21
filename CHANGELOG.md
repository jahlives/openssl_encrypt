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

### Documentation

- Added comprehensive dependency inventory and security assessment
- Created dependency security plan with implementation timeline
- Added this CHANGELOG file to track notable changes

## [0.8.2] - Previous Release

_Note: Previous release information will be added retrospectively_