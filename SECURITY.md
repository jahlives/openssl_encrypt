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
with a warning instead of silently weakening the policy. This complements
ADVISORY 2026-03, which closed signature *verification* gaps but left the default
policy permissive.

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
