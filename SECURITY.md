# Security Policy

## Supported Versions

We take security seriously and provide security updates for the following versions:

| Version | Supported          | End of Life    |
| ------- | ------------------ | -------------- |
| 1.4.x   | :white_check_mark: | TBD            |
| 1.3.x   | :white_check_mark: | June 2026      |
| 1.2.x   | :x:                | December 2024  |
| < 1.2   | :x:                | -              |

**Note:** We maintain security support for the current major version (1.4.x) and the previous major version (1.3.x) for 6 months after a new major release.

## Reporting a Vulnerability

We appreciate responsible disclosure of security vulnerabilities. If you discover a security issue, please follow these steps:

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Send an email to: **tobster@brain-force.ch**
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Affected versions
   - Potential impact
   - Any proof-of-concept code (if applicable)

### What to Expect

- **Initial Response:** Within 48 hours, we'll acknowledge receipt of your report
- **Status Updates:** We'll provide updates every 7 days on our progress
- **Resolution Timeline:** We aim to resolve critical issues within 30 days
- **Disclosure:** We follow coordinated disclosure practices

### Vulnerability Handling Process

1. **Triage:** We'll verify and assess the severity of the vulnerability
2. **Fix Development:** We'll develop and test a fix
3. **Release:** We'll release a security patch for supported versions
4. **Announcement:** We'll publish a security advisory with proper credit
5. **CVE Assignment:** Critical vulnerabilities will receive CVE identifiers

### Security Advisory

Accepted vulnerabilities will be:
- Fixed in the next security release
- Documented in our security advisories
- Credited to the reporter (unless you prefer to remain anonymous)

Declined reports will receive:
- A detailed explanation of why it was declined
- Guidance if it's a configuration issue rather than a vulnerability

## Security Hall of Fame

We recognize and thank the following security researchers for their responsible disclosure:

<!-- Add entries here as they occur -->
*No vulnerabilities reported yet. Be the first!*

---

## Best Practices

When using OpenSSL Encrypt, please follow these security best practices:

- Keep your installation up to date
- Use strong passwords and passphrases
- Enable post-quantum encryption for long-term data protection
- Verify signatures when using the keyserver
- Review telemetry settings if privacy is a concern
- Use HSM plugins for production key management
- Regular security audits of your encryption workflows

## Security Features

OpenSSL Encrypt includes multiple security layers:

- **Post-Quantum Cryptography:** ML-KEM and ML-DSA algorithms
- **Cascade Encryption:** Multiple cipher layers for defense in depth
- **Key Derivation:** Argon2 for password-based keys
- **Signature Verification:** Authenticated key distribution
- **Format Versioning:** Forward-compatible security improvements
- **HSM Support:** Hardware security module integration

---

For general security questions (not vulnerabilities), please open a discussion on GitHub or contact us at tobster@brain-force.ch.
