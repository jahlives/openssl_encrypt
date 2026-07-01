# OpenSSL Encrypt

A Python-based file encryption tool with modern ciphers, post-quantum algorithms, and defense-in-depth key derivation.

Built to encrypt anything from grandma's pie recipe to the nuclear launch codes — with parameters to satisfy every paranoia level in between. Sensible, secure defaults out of the box; fully tunable KDF chains and cipher choices when you want to crank the cost to match the threat.

> **Looking for the stable release?** The latest stable version is [v1.4.7](https://github.com/jahlives/openssl_encrypt/releases/tag/v1.4.7) on the releases/1.4.x branch.

## History

The project is historically named `openssl-encrypt` because it once was a Python script wrapper around OpenSSL. That approach stopped working with recent Python versions, so I did a complete rewrite in pure Python using modern ciphers and hashes. The project name is a “homage” to its roots

---
## Installation

To install follow the [guide](https://github.com/jahlives/openssl_encrypt/wiki/INSTALLATION)

---

## Ethical Commitment & Usage Restrictions

This project is committed to the protection of human rights and the prevention of mass surveillance. To reflect these values, it is licensed under the **Hippocratic License 3.0**.

While the source code is public, usage is subject to strict ethical conditions. We prioritize human rights over traditional "neutral" open-source definitions.

### Prohibited Use Cases
By using this software, you agree that it shall **not** be used for:

* **Violations of Human Rights:** Usage by any entity that undermines the [UN Universal Declaration of Human Rights](https://github.com/jahlives/openssl_encrypt/blob/main/LICENSE#L51) is strictly prohibited (See [License Section 2.1](https://github.com/jahlives/openssl_encrypt/blob/main/LICENSE#L51)).
* **Mass Surveillance:** The software may not be used for bulk, warrantless monitoring or data collection (See [License Section 2.2.a](https://github.com/jahlives/openssl_encrypt/blob/main/LICENSE#L58)).
* **Government Intelligence Agencies:** Usage by agencies (such as NSA, GCHQ, etc.) or their contractors for offensive cyber operations or domestic spying is not permitted under this license.
* **Military & Weapons:** Usage by or for the defense industry, specifically for the development of lethal weaponry, targeting systems, or military-grade surveillance equipment (See [License Section 2.2](https://github.com/jahlives/openssl_encrypt/blob/main/LICENSE#L58)).


### Why this License?
Technological tools are not neutral. We believe that encryption should empower individuals, not oppressive systems. The **Hippocratic License** creates a legal barrier that prevents the integration of this code into software stacks used for surveillance and harm.

> **Note:** Because of these ethical protections, this project is considered **Ethical Source**, not "Open Source" according to the OSI definition, as we intentionally restrict usage for harmful purposes.

> "The Software shall be used for Good, not Evil." — *Inspired by the JSON License & HL 3.0*
---

## Documentation & Security Architecture

For deep-dives into the cryptographic design and security policies of this project, please refer to the specialized documentation in the `docs/` folder:

* **[Technical Architecture](openssl_encrypt/docs/architecture.md)**: Detailed explanation of the Hybrid PQC-flow, the memory-hard KDF chain (Argon2id-anchored, with optional RandomX), and the AEAD Metadata Binding.
* **[On-Disk Format Specification](openssl_encrypt/docs/FORMAT.md)**: The authoritative, implementer-facing description of the bytes written to disk — container layouts, metadata schema, AAD binding, key derivation, and the format-version history. (Reviewed; every claim code-verified.)
* **[Security Policy](SECURITY.md)**: Threat model and non-goals, supported versions, cryptographic standards, anti-oracle policy, source-code integrity, and how to responsibly disclose vulnerabilities.

### Key Security Features at a Glance:
* **Post-Quantum Ready**: Hybrid encryption using NIST-standardized KEMs (HQC, CROSS, MAYO).
* **Deterministic AEAD**: AES-SIV support for maximum protection against nonce-misuse.
* **Metadata Integrity**: Cryptographic binding of headers to prevent tampering (on AEAD-supported ciphers).
* **Memory-Hard KDF + RandomX**: Argon2id (and Balloon) memory-hardness bounds an attacker's guess rate — the primary, load-bearing defense against ASIC/GPU brute-force clusters. The STANDARD template also chains **RandomX** (10 rounds) as genuine **defense-in-depth**: it is *not* a memory-hard KDF and does not replace Argon2id's per-guess cost, but it earns its anti-ASIC value a different way — RandomX is heavily optimized for commodity CPUs (it is Monero's anti-ASIC proof-of-work), so a general-purpose CPU is already near-optimal and custom silicon is highly unlikely to beat it. Net: Argon2id memory remains the primary cost lever; RandomX makes specialized hardware an even worse bet on top of it.
* **Hardware Token Binding (HSM)**: YubiKey/OnlyKey HMAC-SHA1 challenge-response, FIDO2, and PIV/PKCS#11 smart-card support — the hardware-derived pepper is never stored, so decryption requires the physical token. YubiKey and OnlyKey are interchangeable within a same-secret fleet.
* **Cascade Multi-Layer Encryption**: Independent AES-256-GCM + ChaCha20-Poly1305 layers (default in the STANDARD template) for defense-in-depth.
* **Threefish-512/1024**: Native AEAD ciphers with 256/512-bit post-quantum security margins.
* **Streaming Chunked Encryption**: Constant-memory authenticated encryption for multi-gigabyte files (format v12).
---
## 🚀 What's New in v1.4.7

**Current Release:** v1.4.7 | **Status:** Stable | **Tests:** 2900+ passing

Everything that landed since v1.4.1:

- **Documentation & packaging (1.4.7)**: README and PyPI project-page updates reflecting the 1.4.6 feature set; no functional or on-disk changes.
- **PIV / PKCS#11 hardware tokens (1.4.6)**: signature-based HSM backend (`--hsm piv`) that derives the KDF pepper from a PIV private key on a PKCS#11 token (YubiKey Bio MPE, Token2 PIN+, or any compliant PIV smart card); deterministic across devices, across Ed25519 and RSA-2048/3072/4096.
- **Source-code integrity verification (1.4.6)**: `verify-integrity` checks the core cryptographic/security modules against a PGP-signed SHA-512 manifest; the authoritative check is a manual `gpg` against the out-of-band fingerprint published in SECURITY.md.
- **Envelope encryption & O(header) rekey (1.4.6)**: `--envelope` encrypts data under a random DEK and wraps it with the password-derived KEK through the full KDF chain, so changing the password rewrites only the metadata header instead of re-encrypting the payload.
- **Detached signing & ASCII armor (1.4.6)**: `sign` / `verify-signature` produce and verify a detached ML-DSA-65 signature over any file (closing the symmetric-AEAD authenticity gap, where anyone who knows the password can forge a valid file); `encrypt --armor` emits paste-safe Base64 with a CRC-24 truncation guard.
- **Independent XOR v13 default & sequential-XOR KDF-cost fix (1.4.6, ADVISORY 2026-02)**: Independent XOR now derives per-component domain-separated salts (format v13) and is the STANDARD/PARANOID default; the sequential `--xor` mode no longer cancels its last KDF stage out of the key. Existing files remain decryptable.
- **Security dependency update (1.4.5)**: urllib3 2.7.0, cryptography 46.0.7, pillow 12.2.0, idna 3.15 — fixes for CVE-2026-44431/44432, CVE-2026-39892, a PSD decoder out-of-bounds write, and an idna DoS. A new CI check keeps flatpak dependency pins aligned with the package requirements.
- **Security hardening batch (1.4.4)**: Authenticated v2 keystore format (HMAC-SHA256, fails closed on tampering), D-Bus per-caller authorization with polkit, fail-closed PQC algorithm resolution, plugin sandbox enforcement (file/network/process restrictions), unique per-drive salts for portable USB drives, TOFU key-change detection in the identity layer
- **OnlyKey HSM plugin & cross-device fleet decryption (1.4.4)**: Hardware-bound key derivation via OnlyKey challenge-response; YubiKey and OnlyKey provisioned with the same HMAC-SHA1 secret decrypt each other's files (`--hsm onlykey` / `--hsm yubikey`, `--hsm-slot` overrides the stored slot)
- **CLI tooling (1.4.4)**: `info` reconstructs the full `encrypt` command from file metadata; `derive-password` gains HSM-aware deterministic derivation and `--confirm`; Diceware passphrase generation (`generate-password --dice`, bundled EFF wordlist)
- **Modernized defaults (1.4.2)**: STANDARD template upgraded to cascade encryption (AES-256-GCM + ChaCha20-Poly1305), RandomX + Argon2 KDFs, and Independent XOR (v11) key derivation by default
- **Simple/Pro GUI modes (1.4.2)**: Default Simple mode shows only Encrypt/Decrypt/Settings; Pro mode restores the full crypto UI
- **Platform support**: Python 3.11+ required; Python 3.14 fully supported including the Threefish native extension (PyO3 0.26)

**Release History:**
- **v1.4.7** (Current) - Documentation/packaging release: README and PyPI project page updated for the 1.4.6 feature set (no functional changes)
- **v1.4.6** - PIV/PKCS#11 HSM backend, source-code integrity manifest, envelope encryption with O(header) rekey, detached ML-DSA-65 signing, ASCII armor, Independent XOR v13 default, sequential-XOR KDF-cost fix (ADVISORY 2026-02), streaming decrypt fix
- **v1.4.5** - Security dependency update (CVE fixes) and flatpak pin CI guard
- **v1.4.4** - Security hardening batch, OnlyKey HSM plugin with cross-device fleet decryption, `info` CLI reconstruction, Diceware passphrases, Python 3.14 support
- **v1.4.3** - Flatpak GUI launcher fix
- **v1.4.2** - Simple/Pro GUI modes, modernized STANDARD template (cascade by default, Independent XOR v11)
- **v1.4.1** - Stable release
- **v1.4.0** - Stable release with in-memory encryption and security-hardened rekey
- **v1.4.0rc2** - Relax SAST rules for built-in plugins
- **v1.4.0rc1** - First release candidate: security hardening and dependency updates
- **v1.4.0b10** - Format Version 11: Independent XOR & Parallel Processing
- **v1.4.0b9** - Test infrastructure improvements, Threefish cipher support, cross-version compatibility fixes
- **v1.4.0b8** - Critical security fix: Format Version 9 with secure chained salt derivation
- See [version.py.template](openssl_encrypt/version.py.template) for complete release history

### Cascade Encryption (Multi-Layer Defense)

Sequential encryption using multiple cipher algorithms with chained HKDF key derivation.

- Attacker must break all ciphers to decrypt data
- Minimum 2 ciphers required, supports unlimited cascade depth
- Each layer adds entropy to the next layer's key derivation
- CLI support: `--cascade "aes-256-gcm,chacha20-poly1305,xcha-poly1305"`
- Automatic cipher diversity validation
- New metadata format V8

**Example:**
```bash
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --cascade "aes-256-gcm,chacha20-poly1305,xcha-poly1305"
```

### Threefish Post-Quantum Ciphers

Rust-based implementation of Threefish AEAD ciphers with memory-hard construction resistant to quantum attacks.

- Threefish-512: 256-bit post-quantum security level
- Threefish-1024: 512-bit post-quantum security level
- Native AEAD mode with embedded nonce
- Maturin-based Rust/Python integration

### Post-Quantum Keyserver

FastAPI-based keyserver for public key distribution with PostgreSQL backend.

- ML-DSA signature verification for uploaded keys
- Public key upload, search, and revocation endpoints
- Bearer token authentication, rate limiting, CORS protection
- Docker deployment with liboqs 0.12.0
- Available at: https://keyserver.rm-rf.ch

### Privacy-Preserving Telemetry

Opt-in anonymous telemetry infrastructure with user consent and data minimization.

- Anonymous client identifiers
- Configurable data collection scopes
- PostgreSQL backend with FastAPI REST API
- Docker deployment with automated migrations
- Available at: https://telemetry.rm-rf.ch

### Pepper Storage Plugin

Client plugin for secure pepper storage with password hardening and mTLS authentication.

- Client-side encrypted pepper storage (server never sees plaintext)
- TOTP 2FA with QR code generation for destructive operations
- Deadman switch with configurable check-in intervals and grace periods
- Panic wipe for emergency pepper deletion (all or single pepper)
- mTLS authentication with self-signed CA (client certificates required)
- Profile management with access tracking
- OPT-IN by default (disabled until explicitly enabled)
- Configuration: `~/.openssl_encrypt/plugins/pepper.json`

### Integrity Verification Plugin

Client plugin for encrypted file metadata hash verification with mTLS authentication.

- Store SHA-256 hashes of encrypted file metadata on remote server
- Verify file integrity before decryption (detect tampering)
- Batch verification support (up to 100 files per request)
- Tamper detection with comprehensive audit logging
- mTLS authentication with self-signed CA (client certificates required)
- Profile management and verification statistics
- OPT-IN by default (disabled until explicitly enabled)
- Configuration: `~/.openssl_encrypt/plugins/integrity.json`

### Identity-Based Asymmetric Encryption

Enhanced asymmetric key handling with improved format and HSM integration.

- Updated asymmetric encryption format (Format V7)
- KEM-based password wrapping using ML-KEM for post-quantum security
- Identity management system for recipient-based encryption
- Seamless integration with HSM-protected identities
- Skip interactive prompts in non-TTY environments

### Algorithm Registry System

Centralized cryptographic algorithm registration and validation framework.

- Cipher Registry: 12+ symmetric encryption algorithms
- Hash Registry: 15+ cryptographic hash functions
- KDF Registry: 8 key derivation functions
- KEM Registry: 9 Key Encapsulation Mechanisms (Kyber, ML-KEM, HQC)
- Signature Registry: 15 post-quantum signature algorithms
- CLI command: `crypt list-algorithms`
- Security level indicators and validation

### HSM Integration Improvements

- CLI arguments for HSM-protected identity creation: `--hsm`, `--hsm-slot`, `--hsm-pin`
- HSM_ONLY identities skip password prompts during encryption/decryption
- Automatic HSM identity detection with `--with-key`
- Save/load HSM identities without password requirements
- **PIV / PKCS#11 HSM backend** (`--hsm piv`): hardware-bound key
  derivation backed by a PIV private key on a PKCS#11 token (YubiKey Bio
  MPE, Token2 PIN+ R3.3+, or any compliant PIV smart card). The key signs
  a deterministic challenge derived from the salt; the signature is
  normalized into a pepper via HKDF-SHA256, so the same key on multiple
  devices always yields identical peppers. Algorithm-agnostic across
  Ed25519 and RSA-2048/3072/4096; non-deterministic schemes (ECDSA,
  RSA-PSS) are rejected. New flags: `--hsm-pkcs11-lib PATH` (required),
  `--hsm-piv-slot {9a,9c,9d,9e}`, `--hsm-biometric`. Requires
  `python-pkcs11` (`pip install -r requirements-hsm.txt`). See
  [docs/PIV_BACKEND.md](docs/PIV_BACKEND.md) for setup.
- **OnlyKey support** (`--hsm onlykey` / `--hsm onlykey-only`, slots 1..12)
  alongside YubiKey. Same HMAC-SHA1 wire protocol — fleets mixing
  YubiKey and OnlyKey devices loaded with the same 20-byte secret are
  deterministic across either backend. See
  [docs/hardware-tokens.md](docs/hardware-tokens.md) for setup and
  [docs/migration-from-yubikey-only.md](docs/migration-from-yubikey-only.md)
  for adding OnlyKey to an existing YubiKey fleet.

### `info` action — encrypted file inspection with CLI reconstruction

`openssl_encrypt info <file>` reads the metadata of an encrypted file
without decrypting it. In addition to the human-readable summary, the
output now ends with a "Reconstructed CLI" section showing the
`openssl_encrypt encrypt` command that would produce equivalent
encryption settings on a fresh file. Salt and per-file random values
are deliberately NOT reconstructed (only the deterministic
configuration: cipher / cascade chain, KDFs, hash rounds, HSM binding,
pepper).

```bash
$ openssl_encrypt info myfile.enc
File Information:
  Format Version:    9
  ...

  Reconstructed CLI:
    openssl_encrypt encrypt \
      --algorithm aes-gcm \
      --enable-argon2 \
      --argon2-rounds 10 \
      --argon2-time 3 \
      --argon2-memory 65536 \
      ...
```

JSON mode (`--json`) is unchanged — the JSON payload remains the raw
metadata dict so scripts piping into `jq` continue working.

### `derive-password` — HSM-aware deterministic derivation

The `derive-password` action runs a user-supplied password through the
full KDF cascade (Argon2id, scrypt, Balloon, RandomX, HKDF, hashes)
and prints the derived bytes. Useful for generating a strong,
reproducible password for third-party tools (password managers, disk
encryption, encrypted archives) from a memorable input.

```bash
# Basic: derive a 32-byte key from a password (auto-generated salt
# echoed to stderr so you can reproduce)
openssl_encrypt derive-password --enable-argon2 --argon2-rounds 10

# Reproducible (specify the salt)
openssl_encrypt derive-password --salt 0123456789abcdef0123456789abcdef \
    --enable-argon2 --argon2-rounds 10

# Confirm the password twice — guards against typos that would
# silently produce a wrong-but-valid-looking output
openssl_encrypt derive-password --confirm --enable-argon2 --argon2-rounds 10

# Mix in a hardware token: same password + same salt + same hardware
# secret = same output. Re-provisioning the token changes the output
# (a stderr reminder fires when --hsm is used without --salt).
openssl_encrypt derive-password --hsm yubikey --salt 0123...abcdef \
    --enable-argon2 --argon2-rounds 10
openssl_encrypt derive-password --hsm onlykey --hsm-slot 3 --salt 0123...abcdef \
    --enable-argon2 --argon2-rounds 10
```

### Diceware Passphrase Generation

`generate-password --dice` produces Diceware-style passphrases as an
alternative to character-based generation:

```bash
# Default: 10 words from the bundled EFF Large Wordlist (~129 bits of entropy)
openssl_encrypt generate-password --dice

# Customize word count and separator
openssl_encrypt generate-password --dice --dice-count 7 --dice-sep -

# Bring your own wordlist (EFF format or plain text)
openssl_encrypt generate-password --dice --dice-list ~/my-wordlist.txt
```

The bundled wordlist is the [EFF Large Wordlist for Passphrases](https://www.eff.org/dice)
(7,776 words), redistributed under
[Creative Commons Attribution 3.0 US](https://creativecommons.org/licenses/by/3.0/us/)
with attribution in
[`openssl_encrypt/data/EFF_WORDLIST_LICENSE.txt`](openssl_encrypt/data/EFF_WORDLIST_LICENSE.txt).

### Password Strength Checking

`check-password` reports the strength of a password without encrypting anything.
It detects predictable structure (dictionary words, l33t substitutions, keyboard
walks, sequences, repeats, dates) rather than relying on raw character-space
entropy alone. The password is read from `CRYPT_PASSWORD`, a piped stdin, or an
interactive prompt — never from the command line.

```bash
# Interactive prompt; human-readable report on stderr
openssl_encrypt check-password

# From an environment variable, JSON report on stdout
CRYPT_PASSWORD='correct horse battery staple' openssl_encrypt check-password --json

# Use as a scriptable gate: non-zero exit if it fails the policy
echo -n "$pw" | openssl_encrypt check-password --password-policy paranoid --strict-strength
```

Pattern-aware detection uses the optional `zxcvbn` package when installed and a
built-in heuristic fallback otherwise.

### Security Enhancements

- SecureBytes implementation across all cryptographic registries (KDF, Cipher, Signature, KEM)
- Automatic zeroing of sensitive data after use
- Thread-safe secure memory operations
- SECURITY.md policy added to all 20 branches with vulnerability reporting guidelines
- PGP key: C8E4 C58E 83AB B314 74C0 E108 0271 3C63 792B 8986
- 48-hour initial response commitment for security issues

### Performance & Testing

- Modularized test suite with domain-specific organization
- Parallel test execution with high-CPU runner tags
- Optimized KDF parameters for faster CI/CD
- Test duration diagnostics

### Infrastructure

- Rust extension integration via Maturin build system
- Docker multi-stage builds with liboqs 0.12.0
- Enhanced Flatpak build with Threefish wheel handling
- CI/CD pipeline improvements

### Unified Server Architecture

Modular FastAPI server with dual authentication system supporting both public and private modules.

**Public Modules (JWT Authentication):**
- Keyserver: Post-quantum public key distribution
- Telemetry: Privacy-preserving usage statistics

**Private Modules (mTLS Authentication with Self-Signed CA):**
- **Pepper Module**: Secure pepper storage for password hardening
  - Client-side encrypted pepper storage (20 endpoints)
  - TOTP 2FA with QR code generation
  - Deadman switch with configurable check-in intervals
  - Panic wipe for emergency pepper deletion
  - Auto-registration on first mTLS connection
  - Database: 5 tables (clients, peppers, deadman, panic log, TOTP backup codes)

- **Integrity Module**: Encrypted file metadata hash verification
  - SHA-256 hash storage for encrypted file metadata (12 endpoints)
  - Integrity violation detection with audit logging
  - Batch verification support (up to 100 files)
  - Statistics tracking (success rate, verification counts)
  - Auto-registration on first mTLS connection
  - Database: 3 tables (clients, hashes, verification log)

**Security Features:**
- Self-signed CA requirement (public CAs rejected)
- Certificate fingerprint authentication (SHA-256)
- Trusted proxy IP validation
- Comprehensive audit logging
- Automated certificate management scripts

**Deployment:**
- Docker Compose with PostgreSQL backend
- Nginx reverse proxy support (recommended)
- Direct mTLS mode available
- Helper scripts: `setup_ca.sh`, `create_client_cert.sh`
- Full documentation: `openssl_encrypt_server/docs/MTLS_SETUP.md`

### Flutter GUI Enhancements

Complete overhaul of the desktop GUI with advanced cryptographic features and improved user experience.

**Cascade Encryption UI:**
- Multi-cipher selection interface with diversity validation
- Sub-group organization for algorithm categories
- Visual chain preview showing encryption layers
- Integrated into File Crypto, Text Crypto, and Batch Operations tabs

**Asymmetric Encryption UI:**
- Identity Management screen with create/import/export functionality
- Recipient selection for multi-recipient encryption
- HSM integration (YubiKey Challenge-Response, FIDO2/WebAuthn)
- Real-time YubiKey touch prompt display
- ML-KEM/ML-DSA key pair generation and management

**Network Plugin Configuration:**
- Remote Pepper Plugin settings with mTLS certificate management
- Integrity Plugin configuration with verification options
- Keyserver Plugin setup with bearer token authentication
- Visual feedback for plugin status and connectivity

**Algorithm Enhancements:**
- Enhanced algorithm picker with grouped display (Classical Symmetric, Post-Quantum, AEAD)
- PQC algorithms displayed in Information Tab
- Support for Threefish-512 and Threefish-1024 ciphers
- Format version 7 and 8 support in metadata viewer

**User Experience:**
- Steganography configuration panel in encryption tab
- Force password option for workflow automation
- Default input type set to file mode
- Improved status messages and error handling
- Progress indicators for long-running operations

**Flatpak Distribution:**
- Complete CI/CD pipeline with automated builds
- Incremental caching for faster compilation
- OSTree repository integration
- Available on Flathub (pending approval)

### Backward Compatibility

- Compatible with v3, v4, v5, v6, v7, and v8 encrypted files
- Automatic format detection and migration
- V3-V8 metadata formats deprecated due to security vulnerability (read-only support maintained)
- V9 metadata format (current) with secure chained salt derivation
- **Re-encryption strongly recommended for ALL files with format version < v9 or encrypted with code version < 1.4.0**
---
## Known Issues
### HQC Support in v1.2.x

**Note:** HQC (Hamming Quasi-Cyclic) post-quantum cryptography is not functional in v1.2.x releases due to fork-safety issues in liboqs on certain AMD64 systems. Files encrypted with HQC algorithms (hqc-128, hqc-192, hqc-256) cannot be decrypted reliably in these versions.

- ✅ **Other PQC algorithms work correctly**: Kyber/ML-KEM, Dilithium, Falcon, SPHINCS+, and all other supported post-quantum algorithms function as expected in v1.2.x
- ✅ **HQC fully supported in v1.3.0+**: The issue has been resolved in version 1.3.0 and later through improved multiprocessing handling

**Recommendation:** If you need to encrypt or decrypt files using HQC algorithms, please upgrade to version 1.3.0 or later.

**For v1.2.x users:** If you have files encrypted with HQC, you can:
1. Upgrade to v1.3.0+ to decrypt them
2. Use a different system where the fork-safety issue doesn't occur
3. Re-encrypt important files using Kyber/ML-KEM instead (recommended for long-term compatibility)
### Incomplete AEAD Metadata Binding (Versions < 1.3.0)

  **Issue**: In versions prior to 1.3.0, AEAD algorithms (AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, AES-SIV, AES-OCB3, XChaCha20-Poly1305, and all PQC hybrid variants) pass `None` for the Additional Authenticated Data (AAD) parameter, despite documentation indicating metadata is cryptographically bound to the ciphertext.

  **Security Impact**: Low - The encryption itself remains secure. Metadata is already cryptographically bound through the key derivation chain, meaning any tampering causes decryption failure. However, without AAD, tampering detection is delayed until after both KDF operations and decryption attempts complete.

  **Attack Scenarios**:
  - An attacker with write access to encrypted files can tamper with metadata
  - Modified metadata will cause decryption to fail, but only after processing
  - No data confidentiality breach is possible
  - Potential DoS vector: modifying the `rounds` parameter forces expensive KDF operations before failure is detected

  **Recommendation**: Upgrade to version 1.3.0 or later, which implements proper AAD binding for earlier tampering detection. Note that AAD does not eliminate the DoS risk, as metadata parsing and KDF execution occur before AAD validation.

  **Workaround**: No workaround needed for data security. To mitigate DoS risks, ensure file permissions prevent unauthorized write access to encrypted files.
---
## Security Architecture

### Chained Key Derivation

This tool uses a chained hash/KDF architecture where each round’s output determines the next round’s salt:

```
Password + Salt₀ → KDF₁ → Result₁ → Salt₁ = f(Result₁) → KDF₂ → Result₂ → ... → Final Key
```

**Design Properties:**

- **Memory-Hard Functions**: Argon2id and Balloon hashing require significant memory per guess — this is what bounds an attacker's parallelism (RAM bandwidth/capacity per lane caps how many guesses run at once), and is therefore the actual source of GPU/ASIC resistance.
- **Dynamic Salting**: Per-round salts are derived from previous outputs, not predictable in advance, which prevents cross-guess precomputation.
- **Sequential Dependency**: Each round requires the previous round’s result. This blocks *intra-guess* parallelism only; it does **not** stop *guess-level* parallelism (an attacker simply runs many independent guesses in parallel), which is the attack that matters.

**Why chaining / multiple KDFs?** The value of chaining is **defense-in-depth**: if one KDF turns out to be buggy or broken, the others still stand. It is **not** a source of added GPU/ASIC resistance. An attacker's total cost is the **sum of the stage costs** (dominated by the strongest stage) — exactly what a single, well-parametrized memory-hard KDF also achieves. The most effective single lever for ASIC/GPU resistance is **Argon2id memory size**, because memory (not the function's identity) is what bounds purpose-built hardware. (Scrypt-based ASICs exist for Litecoin precisely because its 128 KB memory parameter is small enough to fit on-die.)

### KDF Composition Modes (Independent vs Sequential XOR)

When several hash/KDF algorithms are combined, the tool supports two composition
modes with **different security guarantees**. Pick deliberately:

- **Independent XOR** (format v13, the STANDARD/PARANOID default; v11 still readable) — every algorithm
  derives from the **same** `(password + salt)` input and the outputs are XOR'd:
  `K = H₁(x) ⊕ H₂(x) ⊕ … ⊕ Hₙ(x)`. This is a **robust XOR-combiner** for PRFs
  (Herzberg; Harnik–Kilian–Naor–Reingold–Rosen): for **output / PRF
  indistinguishability**, the result is **as strong as the strongest component** —
  it stays secure as long as **at least one** component is unbroken. Use this mode
  when you want the strongest-link guarantee.
- **Sequential XOR** (format v10, or v13 with `xor_mode: sequential`) — each round
  feeds the previous round's output forward. The robust-combiner guarantee does
  **not** hold here: a broken or entropy-collapsing **early** round propagates into
  every later round (XOR can't rescue what already collapsed), so security is bounded
  by the **weakest early link**. Its only gain over independent mode is intra-guess
  sequentiality (thread-binding).

**Scope of the "strongest component" claim.** It is precisely about **output
indistinguishability**, and it bites only against a **broken / entropy-collapsing**
component. It does **not** cover *cost*: total work is the **sum of all components**
in *both* modes (a merely cheap-but-full-entropy component is harmless and is not
what the guarantee is about). So don't read "strongest link" as buying extra
memory-hardness or ASIC resistance — that comes from each component's own cost
parameters (see above).

**Cancellation caveat (independent XOR) — fixed in format v13.** Because all
components share the same `(password + salt)`, the strongest-link property holds
only while no two components are the **same function with identical parameters** —
XOR of two identical outputs is zero. The robust fix is per-component domain
separation, and **format version 13 (1.4.6) implements exactly this**: every
component gets a distinct `HKDF-SHA256(salt₀, info="…indep-xor.v13.salt:" + name)`
salt, retiring the footgun, and v13 is now the Independent XOR default. The same
release also fixed a **sequential-XOR** defect in which the chain's last KDF stage
cancelled out of the key (single-KDF/no-prior-hash configs bypassed the KDF cost) —
see ADVISORY 2026-02 in [SECURITY.md](SECURITY.md). Files written by older versions
remain decryptable; re-encrypt to adopt v13.

### Attack Resistance

The architecture provides several security properties:

|Attack Vector           |Mitigation                                                       |
|------------------------|-----------------------------------------------------------------|
|GPU/ASIC parallelization|Memory-hardness of Argon2id/Balloon caps guesses-per-second; raise Argon2id memory to harden further|
|Rainbow tables          |Dynamic per-round salts prevent precomputation                   |
|Time-memory trade-offs  |Memory-hard KDFs penalize trading memory for computation         |
|Quantum key recovery    |Hybrid PQC modes (ML-KEM, HQC) for key encapsulation             |

> **Note:** sequential chaining is *not* listed as the anti-parallelization defense. Chaining only serializes the work *within* a single guess; it cannot prevent an attacker from evaluating many guesses concurrently. Per-guess cost (memory-hardness), not the chaining, is what bounds attacker throughput.

### Computational Cost Estimates

|Password Entropy         |KDF Configuration|Time/Attempt|Brute-Force Estimate*|
|-------------------------|-----------------|------------|---------------------|
|50 bits (8 random chars) |Balloon ×5       |~40s        |~10²² years          |
|60 bits (10 random chars)|Balloon ×5       |~40s        |~10²⁵ years          |
|80 bits (13 random chars)|Balloon ×5       |~40s        |~10³¹ years          |

*These figures are an **idealized upper bound** computed as (search space × time-per-guess) for a single evaluator. A massively parallel attacker undercuts them by their parallelism factor (commonly 10⁴–10⁶+ across a GPU/ASIC cluster), so treat the numbers as a ceiling, not a guarantee. What actually bounds a real attacker is the **per-guess memory-hard cost** (raise Argon2id memory to push it up), not the round chaining. Estimates further assume a 95-character set, a uniformly random password, and no implementation flaws; actual security depends on password quality and operational security.

### Security Considerations

- Strong passwords (12+ random characters) make brute-force computationally infeasible
- Memory-hard KDFs (Argon2id/Balloon) bound how fast an attacker can guess; sequential chaining only serializes work *within* a guess and does not prevent guess-level parallelism
- Post-quantum algorithms provide resistance against quantum key-recovery attacks
- **Limitations**: Implementation bugs, side-channel attacks, weak passwords, or compromised systems remain potential risks. No cryptographic system provides absolute guarantees.

### Security Review

The v1.3.0 codebase received an independent security review:

- **Score**: 8.8/10
- **Critical/High findings**: 0
- **Medium findings**: 3 (defense-in-depth improvements, not blocking)
- **Dependencies**: pip-audit clean, zero known vulnerabilities

See <SECURITY_REVIEW_v1.3.0.md> for the full report.

### Source-Code Integrity

Core cryptographic/security source files are covered by a PGP-signed integrity
manifest. Verify with `openssl-encrypt verify-integrity` (a convenience tripwire) or,
authoritatively, with `gpg` against the out-of-band fingerprint published in
[SECURITY.md](SECURITY.md). Full runbook: [docs/SOURCE_INTEGRITY.md](docs/SOURCE_INTEGRITY.md).

---
## Features

### Symmetric Encryption

Modern AEAD (Authenticated Encryption with Associated Data) ciphers:

|Algorithm         |Status        |Notes                              |
|------------------|--------------|-----------------------------------|
|AES-GCM           |✅ Recommended |NIST standard, hardware-accelerated|
|AES-GCM-SIV       |✅ Recommended |Nonce-misuse resistant             |
|ChaCha20-Poly1305 |✅ Recommended |Software-optimized, constant-time  |
|XChaCha20-Poly1305|✅ Recommended |Extended nonce (192-bit)           |
|AES-SIV           |✅ Supported   |Deterministic encryption           |
|Fernet            |✅ Default     |AES-128-CBC + HMAC, simple API     |
|AES-OCB3          |⚠ Decrypt only|Deprecated in v1.2.0               |
|Camellia          |⚠ Decrypt only|Deprecated in v1.2.0               |

### Post-Quantum Cryptography

Hybrid encryption combining classical symmetric ciphers with post-quantum KEMs:

**NIST Standardized:**

- **ML-KEM** (FIPS 203): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **Kyber**: Kyber-512, Kyber-768, Kyber-1024 (original implementation)

**NIST Selected (2025):**

- **HQC**: HQC-128, HQC-192, HQC-256

**Signature Schemes (for authenticated encryption):**

- **MAYO**: MAYO-1, MAYO-2, MAYO-3, MAYO-5
- **CROSS**: CROSS-R-SDPG-1, CROSS-R-SDPG-3, CROSS-R-SDPG-5

### Key Derivation Functions

|KDF     |Type              |Status        |Use Case                    |
|--------|------------------|--------------|----------------------------|
|Argon2id|Memory-hard       |✅ Recommended |Default for password hashing|
|Balloon |Memory-hard       |✅ Recommended |Alternative to Argon2       |
|Scrypt  |Memory-hard       |✅ Supported   |GPU-resistant               |
|HKDF    |Extract-and-expand|✅ Supported   |Key expansion               |
|RandomX |CPU-hard          |✅ Supported   |Anti-ASIC (from Monero)     |
|PBKDF2  |Iterative         |⚠ Decrypt only|Deprecated in v1.2.0        |

### Hash Functions

For key derivation chaining:

- **SHA-2 Family** (FIPS 180-4): SHA-512, SHA-384, SHA-256, SHA-224
- **SHA-3 Family** (FIPS 202): SHA3-512, SHA3-384, SHA3-256, SHA3-224
- **BLAKE Family**: BLAKE2b, BLAKE3
- **SHAKE** (XOF): SHAKE-256, SHAKE-128
- **Legacy**: Whirlpool (decrypt only in v1.2.0+)

### Additional Security Features

**Memory Protection:**

- Secure memory allocation with mlock/VirtualLock
- Multi-pass memory wiping (random, 0xFF, 0xAA, 0x55, 0x00)
- Constant-time operations for timing attack resistance

**File Operations:**

- Multi-pass secure deletion (configurable passes)
- Atomic file operations
- Symlink attack protection (O_NOFOLLOW in D-Bus service)

**Key Management:**

- Encrypted keystore for PQC keys
- Key rotation support
- Dual encryption (password + keystore)

**Operational:**

- Password policy enforcement
- Common password dictionary check
- Audit logging
---
## Installation

### Flatpak (Recommended)

The easiest way to install with all dependencies included (Python, liboqs, liboqs-python, Flutter GUI):

```bash
# Add the repository
flatpak remote-add --if-not-exists openssl-encrypt https://flatpak.rm-rf.ch/openssl-encrypt.flatpakrepo

# Install latest stable version
flatpak install openssl-encrypt com.opensslencrypt.OpenSSLEncrypt

# Run the application
flatpak run com.opensslencrypt.OpenSSLEncrypt --help
```

**Benefits:**
- All dependencies pre-installed (including liboqs and Python bindings)
- Flutter Desktop GUI included
- Sandboxed environment
- Automatic updates
- Works on any Linux distribution

**Build Flatpak locally (alternative to using the repository):**

```bash
# Clone the repository
git clone https://github.com/jahlives/openssl_encrypt.git
cd openssl_encrypt/flatpak

# Build and install locally (includes Flutter GUI)
./build-flatpak.sh --build-flutter --local-install

# Or install as development branch (recommended for testing, runs parallel to stable)
./build-flatpak.sh --build-flutter --dev-install

# Run the locally installed flatpak
flatpak run com.opensslencrypt.OpenSSLEncrypt
```

**Build options:**
- `--build-flutter` - Build Flutter Desktop GUI before packaging
- `--local-install` - Install as stable branch (overwrites production)
- `--dev-install` - Install as development branch (parallel to production, recommended)
- `-f, --force` - Force clean build cache

See `flatpak/README.md` for detailed build instructions.

### PyPI / Source Installation

**Requirements:**
- Python 3.11+ (3.12 or 3.13 recommended)

**Core Dependencies:**
```
cryptography>=44.0.1
argon2-cffi>=23.1.0
PyYAML>=6.0.2
blake3>=1.0.0
```

**Optional Dependencies:**
```
liboqs-python          # Extended PQC support (HQC, ML-DSA, etc.)
                       # Requires liboqs (https://github.com/open-quantum-safe/liboqs)
tkinter                # GUI (usually included with Python)
zxcvbn                 # Pattern-aware password strength estimation
                       # (falls back to a built-in heuristic when absent)
```

**Install:**

```bash
# From PyPI (when available)
pip install openssl-encrypt

# From source
git clone https://github.com/jahlives/openssl_encrypt.git
cd openssl_encrypt
pip install -e .
```

**Note:** For full post-quantum support (HQC, ML-DSA), you need to manually install liboqs and liboqs-python. The Flatpak version includes these by default.
---
## Usage

### Command-Line Interface

```bash
# Basic encryption (Fernet, default settings)
python -m openssl_encrypt.crypt encrypt -i file.txt -o file.txt.enc

# AES-GCM with Argon2
python -m openssl_encrypt.crypt encrypt -i file.txt -o file.txt.enc \
    --algorithm aes-gcm \
    --enable-argon2 --argon2-rounds 3

# Post-quantum hybrid encryption
python -m openssl_encrypt.crypt encrypt -i file.txt -o file.txt.enc \
    --algorithm ml-kem-768-hybrid

# Using security templates
python -m openssl_encrypt.crypt encrypt -i file.txt --quick      # Fast, good security
python -m openssl_encrypt.crypt encrypt -i file.txt --standard   # Balanced (default)
python -m openssl_encrypt.crypt encrypt -i file.txt --paranoid   # Maximum security

# Decryption (algorithm auto-detected from metadata)
python -m openssl_encrypt.crypt decrypt -i file.txt.enc -o file.txt

# Secure file deletion
python -m openssl_encrypt.crypt shred -i sensitive.txt --passes 3

# Generate random password
python -m openssl_encrypt.crypt generate --length 20
```

### Graphical User Interface

```bash
python -m openssl_encrypt.crypt_gui
# or
python -m openssl_encrypt.cli --gui
```

### Flutter Desktop GUI

Cross-platform GUI available for Linux, macOS, and Windows. See the [User Guide](openssl_encrypt/docs/user-guide.md#flutter-desktop-gui-installation) for installation.

### Keystore Operations

```bash
# Create keystore
python -m openssl_encrypt.keystore_cli_main create --keystore-path keys.pqc

# Generate PQC keypair
python -m openssl_encrypt.keystore_cli_main generate --keystore-path keys.pqc \
    --algorithm ml-kem-768

# Encrypt with keystore
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --keystore keys.pqc --key-id my-key
```
---
## Configuration Templates

Pre-configured security profiles in `templates/`:

|Template       |Use Case                      |KDF                    |Rounds|Time |
|---------------|------------------------------|-----------------------|------|-----|
|`quick.json`   |Fast encryption, good security|Argon2                 |1     |~1s  |
|`standard.json`|Balanced (default)            |Argon2 + SHA3          |3     |~5s  |
|`paranoid.json`|Maximum security              |Argon2 + Balloon + SHA3|10+   |~60s+|
---
## Project Structure

```
openssl_encrypt/
├── crypt.py                 # CLI entry point
├── crypt_gui.py             # Tkinter GUI
├── modules/
│   ├── crypt_core.py        # Core encryption/decryption
│   ├── crypt_cli.py         # CLI implementation
│   ├── crypt_utils.py       # Utilities (shred, password gen)
│   ├── crypt_errors.py      # Exception classes
│   ├── secure_memory.py     # Memory protection
│   ├── secure_ops.py        # Constant-time operations
│   ├── balloon.py           # Balloon hashing
│   ├── randomx.py           # RandomX KDF
│   ├── pqc.py               # Post-quantum crypto
│   ├── pqc_adapter.py       # PQC algorithm adapter
│   ├── keystore_cli.py      # Keystore management
│   ├── password_policy.py   # Password validation
│   ├── dbus_service.py      # D-Bus integration (Linux)
│   └── plugin_system/       # Plugin sandbox
├── unittests/
│   ├── unittests.py         # Main test suite (950+ tests)
│   └── testfiles/           # Test vectors (password: 1234)
├── templates/               # Security profiles
└── docs/                    # Documentation
```
---
## Documentation

|Document                                                          |Description                                   |
|------------------------------------------------------------------|----------------------------------------------|
|[User Guide](openssl_encrypt/docs/user-guide.md)                  |Installation, usage, examples, troubleshooting|
|[Keystore Guide](openssl_encrypt/docs/keystore-guide.md)          |PQC key management, dual encryption           |
|[Security Documentation](openssl_encrypt/docs/security.md)        |Architecture, threat model, best practices    |
|[Algorithm Reference](openssl_encrypt/docs/algorithm-reference.md)|Cipher and KDF specifications                 |
|[Metadata Formats](openssl_encrypt/docs/metadata-formats.md)      |File format specs (v3, v4, v5)                |
|[Development Setup](openssl_encrypt/docs/development-setup.md)    |Contributing, CI/CD, testing                  |
---
## Testing

```bash
# Run all tests
pytest openssl_encrypt/unittests/

# Run with coverage
pytest --cov=openssl_encrypt openssl_encrypt/unittests/

# Run specific test class
pytest openssl_encrypt/unittests/unittests.py::TestCryptCore
```

Test files in `unittests/testfiles/` are encrypted with password `1234`.
---
## Support

- **Issues**: [GitHub Issues](https://github.com/jahlives/openssl_encrypt/issues)
- **Email**: issue+world-openssl-encrypt-2-issue-@gitlab.rm-rf.ch
- **Security vulnerabilities**: Email only (not public issues)
---
## License

See <LICENSE> file.

-----

*OpenSSL Encrypt – File encryption with modern ciphers, post-quantum algorithms, and defense-in-depth key derivation.*
