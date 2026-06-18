# Security Policy

## Supported Versions

We take security seriously and provide security updates for the following versions:

| Version | Supported          | End of Life    |
| ------- | ------------------ | -------------- |
| 1.4.x   | :white_check_mark: | TBD            |
| 1.3.x   | :white_check_mark: | TBD            |
| 1.2.x   | :x:                | December 2025  |
| < 1.2   | :x:                | -              |

**Note:** We provide extended security support for both the current major version (1.4.x) and the previous major version (1.3.x). End of life dates will be announced well in advance.

## Source-Code Integrity Verification

Core cryptographic/security source files are covered by a PGP-signed integrity
manifest so tampering can be detected. The manifest is signed by a **dedicated
source-integrity key**:

- **Source-integrity signing key fingerprint:** `D269D6A5 D6D7CE52 CE1FC71D C2DF2905 9ED65043`
- Key type: Ed25519 (sign-only)

This fingerprint is published here as an **out-of-band reference**. To verify the
source independently, confirm this fingerprint through a channel other than the
repository, then follow `docs/SOURCE_INTEGRITY.md`:

```bash
gpg --verify openssl_encrypt/integrity/manifest.json.asc \
             openssl_encrypt/integrity/manifest.json
```

> The built-in `openssl-encrypt verify-integrity` command is a convenience tripwire,
> not cryptographic proof — the verifier ships in the same package it checks. Only
> manual `gpg` verification against an out-of-band fingerprint is authoritative.
>
> **Production signing-key fingerprint** — confirm this through an independent channel
> (this repo, the GitLab project page, the maintainer's web-of-trust) before trusting
> any verification result:
>
> ```
> D269D6A5D6D7CE52CE1FC71DC2DF29059ED65043
> ```

## Reporting a Vulnerability

We appreciate responsible disclosure of security vulnerabilities. If you discover a security issue, please follow these steps:

### How to Report

**Preferred Method:** Use GitHub's private security advisory feature
- Go to the repository's **Security** tab
- Click **"Report a vulnerability"**
- Fill out the private advisory form

**Alternative Method:** Send an encrypted email
- Email: **tobster@brain-force.ch**
- **Strongly recommended:** Use PGP encryption for sensitive details
- PGP Key Fingerprint: `C8E4 C58E 83AB B314 74C0  E108 0271 3C63 792B 8986`
- Key Type: RSA 4096-bit (expires 2029-09-08)
- Download from: `keys.openpgp.org` or `gpg --recv-keys C8E4C58E83ABB31474C0E10802713C63792B8986`

**Important:**
1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Include the following information in your report:
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

## Resolved Security Vulnerabilities

### CVSSv3 8.1 (High): Predictable Salt Derivation in Multi-Round KDF - Fixed in v1.3.4 (2026-01-07)

**Vulnerability ID:** CWE-330 - Use of Insufficiently Random Values
**Severity:** High (CVSSv3 Base Score: 8.1)
**Affected Versions:** All versions prior to v1.3.4 (Format Versions 3-6)
**Fixed In:** v1.3.4 (Format Version 7)

**Description:**
Multi-round KDF operations in versions prior to v1.3.4 used predictable salt derivation. Each round's salt was computed as `sha256(base_salt + round_number)`, making all round salts predictable from the plaintext metadata's base salt. This allowed adversaries with access to encrypted file metadata to precompute all intermediate salts, undermining the security benefits of multi-round key derivation against precomputation attacks.

**Affected Components:**
- Hash Algorithms: BLAKE2b, BLAKE3, SHAKE-256 (multi-round modes)
- KDF Algorithms: Argon2, Scrypt, Balloon, PBKDF2, HKDF (multi-round modes)

**Impact:**
The vulnerability weakened the defense-in-depth provided by multi-round KDF. While the encryption itself remained cryptographically sound, the predictable salt generation allowed attackers to perform precomputation attacks against the key derivation chain, partially defeating the time-cost benefits of multi-round operations.

**Resolution:**
Version 1.3.4 implements Format Version 7 with **secure chained salt derivation**. Each round now uses the previous round's output as the salt input for the next round, creating an unpredictable chain that requires executing all prior rounds.

**Mitigation:**
- **Immediate Action:** Upgrade to v1.3.4 or later
- **Re-encryption Recommended:** Files encrypted with multi-round KDF settings in Format Versions 3-6 should be re-encrypted with v1.3.4 for maximum security
- **Backward Compatibility:** Maintained - v1.3.4 can decrypt all previous format versions (v3-v6)

**Credit:** Internal security review

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
