# Security Policy

## 1. Security Philosophy
`openssl_encrypt` is designed with a **Defense in Depth** approach. Our security model doesn't just focus on data confidentiality but emphasizes **Metadata Integrity** and **Quantum Resistance**.

We believe in transparency; therefore, our cryptographic choices are documented to allow for public audit and verification.

---

## 2. Security Advisories

### 🚨 ADVISORY 2026-01: Multi-Round KDF Salt Derivation Vulnerability (CRITICAL)

**Published**: January 7, 2026
**Severity**: **CRITICAL**
**CVSSv3 Score**: 8.1 (High)
**Affected Versions**: All versions prior to v1.4.1 using multi-round KDF configurations
**Fixed In**: v1.4.1 (Format Version 9)

#### Summary

A critical security vulnerability was discovered in the multi-round KDF (Key Derivation Function) salt derivation implementation used in format versions 8 and below. The vulnerability allows attackers to precompute all round salts from the base salt stored in plaintext metadata, significantly reducing the effective security of multi-round KDF configurations.

#### Vulnerability Details

**CWE Classification**: CWE-330 (Use of Insufficiently Random Values)

**Attack Vector**: In format versions ≤8, round salts for multi-round KDFs were derived predictably:

```python
# VULNERABLE (v8 and below)
round_salt = SHA256(base_salt + str(round_number).encode()).digest()[:16]
```

Since `base_salt` is stored in plaintext metadata, attackers can:
1. Extract `base_salt` from the encrypted file
2. Precompute all round salts for each round
3. Build optimized rainbow tables for each round independently
4. Parallelize password cracking across all rounds

**Impact**:
- Multi-round KDF configurations provide **significantly reduced security** compared to intended design
- Attackers can precompute round-specific rainbow tables
- Parallel attacks possible across all rounds
- Effective security does **not** increase with additional rounds as intended

#### Technical Analysis

**Affected Components**:
- Argon2 (Argon2id, Argon2i, Argon2d) multi-round configurations
- PBKDF2 multi-round configurations
- Scrypt multi-round configurations
- Balloon hashing multi-round configurations
- HKDF multi-round configurations
- BLAKE3, BLAKE2b, SHAKE-256 multi-round hashing

**Exploitation Requirements**:
- Access to encrypted file (to extract base_salt from metadata)
- Multi-round KDF configuration (rounds > 1)
- Offline attack scenario

**Exploitation Complexity**: LOW
- No special tools required
- Standard cryptanalysis techniques
- Can be automated

#### Security Fix (Format Version 9)

Version 9 introduces **secure chained salt derivation**:

```python
# SECURE (v9)
if round_num == 0:
    round_salt = base_salt
else:
    round_salt = previous_output[:16]  # Use previous round's output
```

**Security Properties**:
- ✅ **Sequential Dependency**: Each round depends on previous output
- ✅ **Precomputation Impossible**: Cannot compute round N salt without computing rounds 0 through N-1
- ✅ **Parallel Attack Prevention**: Forces sequential computation for each password guess
- ✅ **Increased Work Factor**: Effective security multiplies by number of rounds

#### Affected Users

**HIGH RISK** - Immediate action recommended:
- Files encrypted with multi-round KDF configurations (rounds > 1)
- Files containing sensitive data
- Files with weak or medium-strength passwords
- Files stored in publicly accessible locations

**MEDIUM RISK** - Re-encryption recommended when convenient:
- Files with strong passwords (>20 characters, high entropy)
- Files with additional encryption layers
- Files in secure storage

**LOW RISK** - Minimal concern:
- Files with single-round KDF (rounds = 1) - vulnerability does not apply
- Files already using strong security practices

#### Mitigation

**Immediate Actions** (Required):
1. **Upgrade** to openssl_encrypt v1.4.1 or later
2. **Re-encrypt** sensitive files to use format version 9:
   ```bash
   # Decrypt old file
   python -m openssl_encrypt.crypt decrypt -i sensitive.enc -o temp.txt

   # Re-encrypt with v9 (automatic)
   python -m openssl_encrypt.crypt encrypt -i temp.txt -o sensitive.enc

   # Securely delete temporary file
   shred -u temp.txt
   ```
3. **Verify** format version:
   ```bash
   python -m openssl_encrypt.crypt info -i sensitive.enc | grep format_version
   # Should show: "format_version": 9
   ```

**Long-Term Actions** (Recommended):
- Audit all encrypted files for format version
- Prioritize re-encryption of files with multi-round KDF configurations
- Update documentation and procedures to use v1.4.1+
- Consider password rotation for affected files

#### Backward Compatibility

- ✅ Files encrypted with v8 and below can still be decrypted
- ✅ No data loss or breaking changes
- ✅ Automatic format detection during decryption
- ⚠️ v8 write support disabled (encryption only creates v9 files)
- ⚠️ Deprecation warning issued when decrypting v8 files

#### Detection

Check if your files are affected:

```bash
# Check format version of encrypted file
python -m openssl_encrypt.crypt info -i yourfile.enc

# If format_version <= 8 AND you use multi-round KDF:
# - Check for "rounds" > 1 in metadata
# - Re-encrypt to v9 immediately
```

#### Timeline

- **December 2025**: Vulnerability discovered during internal security audit
- **January 7, 2026**: Fix released in v1.4.1 (Format Version 9)
- **January 7, 2026**: Public advisory published
- **Responsible Disclosure**: No third-party disclosure prior to fix

#### References

- [Format Version 9 Specification](metadata-formats.md#version-9-specification)
- [Migration Guide](metadata-formats.md#migration-guide)
- [Security Analysis](metadata-formats.md#security-analysis)

#### Credits

Discovered by the openssl_encrypt development team during routine security audit.

---

## 3. Cryptographic Standards & AEAD
A core requirement of this tool is the cryptographic binding of file metadata (the JSON header) to the encrypted payload. This is achieved through **Authenticated Encryption with Associated Data (AEAD)**.

### 3.1 Metadata Binding (AAD)

#### AEAD Algorithms (Full AAD Binding)
The following ciphers implement true AEAD, where the Base64-encoded metadata header is cryptographically bound to the ciphertext via Associated Data (AAD):

**Pure AEAD Algorithms:**
* **AES-256-GCM**: Standard hardware-accelerated AEAD with AAD binding
* **ChaCha20-Poly1305**: Software-efficient AEAD with AAD binding
* **XChaCha20-Poly1305**: Extended-nonce AEAD with AAD binding
* **AES-256-SIV**: Deterministic AEAD with AAD binding (nonce-misuse resistant)
* **AES-GCM-SIV**: Misuse-resistant AEAD with AAD binding
* **AES-OCB3**: OCB mode AEAD with AAD binding

**Post-Quantum Hybrid Algorithms (18 total):**
All PQC hybrid algorithms use AEAD ciphers for their symmetric encryption layer:
* **ML-KEM** variants (512, 768, 1024, with AES-GCM or ChaCha20-Poly1305)
* **HQC** variants (128, 192, 256)
* **MAYO** variants (1, 3, 5)
* **CROSS** variants (128, 192, 256)
* **Kyber** variants (512, 768, 1024) - deprecated

For these algorithms:
- Metadata is created BEFORE encryption
- Metadata is passed as AAD to the cipher
- Any modification to metadata causes authentication failure
- No `encrypted_hash` is stored (redundant with AAD protection)

#### Non-AEAD Algorithms (Hash-Based Verification)
The following algorithms use hash-based integrity verification:

* **Fernet**: Uses internal HMAC (no AAD support per specification)
* **Camellia**: Uses HMAC-SHA256 for authentication

For these algorithms:
- Metadata is created AFTER encryption
- `encrypted_hash` is included in metadata
- Verification via hash comparison (not AAD)

### 3.2 Note on Fernet
Fernet is included for compatibility with the Python `cryptography` ecosystem.
* **Limitation:** The Fernet specification does not natively support Associated Data (AAD).
* **Security Bound:** While the payload integrity is guaranteed, the metadata header is not cryptographically bound to the Fernet token via AAD. Hash-based verification is used instead.

---

## 4. Post-Quantum Cryptography (PQC)
To protect against the future threat of Cryptographically Relevant Quantum Computers (CRQC), this tool utilizes a hybrid KEM (Key Encapsulation Mechanism) layer.
* **Supported Algorithms:** HQC, CROSS, and MAYO.
* **Mechanism:** The PQC secret is fused with a hardened KDF output (Argon2id/RandomX) to derive the final session key.

---

## 5. Reporting a Vulnerability
We welcome security researchers and users to report any potential vulnerabilities. To protect our users, we ask you to follow a responsible disclosure process.

### How to report:
1.  **Do not open a public issue.**
2.  Please use the **[GitHub Security Advisory](https://github.com/jahlives/openssl_encrypt/security/advisories/new)** feature to report vulnerabilities privately.
3.  Include a detailed description, steps to reproduce, and a Proof of Concept (PoC) if possible.

### What to report:
We are particularly interested in reports concerning:
* Bypassing the AEAD metadata binding.
* Flaws in the KDF chain (Argon2id + RandomX fusion).
* Implementation errors in the PQC wrappers.

---

## 6. Anti-Oracle Policy
To mitigate side-channel and padding oracle attacks, `openssl_encrypt` implements a strict **generic error policy**.
* Any failure (KDF mismatch, Header corruption, or Tag verification failure) returns an identical `Decryption Failed` error.
* We will not provide granular error messages that could leak information about the internal state of the cryptographic stack.
