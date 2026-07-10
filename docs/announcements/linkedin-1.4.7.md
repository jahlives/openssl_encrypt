# openssl_encrypt 1.4.6 / 1.4.7 — a KDF-cost bypass fixed, plus whitened headers, recovery slots and more

## The fix that matters most

The headline of this release is a security fix. In the Sequential XOR key-derivation
mode (`--xor`, on-disk format versions 8/10), the chain's final value was XOR'd into
the key in addition to the last stage's own snapshot — and since those two values are
equal, they cancelled. The result: the last KDF stage silently dropped out of the key.
In an Argon2-only configuration this collapsed the derived key down to the cheap initial
`SHA256(password+salt)` computed before the chain ran, bypassing the configured Argon2
cost entirely.

**Who is affected — read this before worrying:** this is only reachable with a
non-default configuration. Two conditions must both hold: (1) you explicitly enabled
Sequential XOR mode (`--xor`), and (2) your key derivation used a single KDF with no
other KDFs and no hashing chained around it. The default profile — multiple chained KDFs
combined with chained hashes — was never affected, because any additional KDF or hash
stage prevents the cancellation. If you use the defaults, your files were never weakened
by this.

- Tracked as ADVISORY 2026-02 / CWE-916, CVSS 6.2 (Medium).
- The fix: `--xor` now writes format version 13 with the redundant append removed, so
  every stage contributes to the key. Existing v8/v10 files still decrypt, but a
  single-KDF `--xor` file should be re-encrypted to regain full KDF cost.

Full disclosure and details — GitHub Security Advisory GHSA-vxf9-vwp6-2w43:
https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-vxf9-vwp6-2w43

## What else is new in 1.4.6

- **Format version 13 — domain-separated salts for Independent XOR (now default).**
  Previously every component received the same `salt_0`, so two identical components
  could XOR to zero. v13 derives a distinct per-component salt via HKDF, retiring the
  cancellation footgun while keeping the strongest-link combiner guarantee. Non-breaking;
  older files decrypt unchanged.

- **Hidden ("whitened") file format (`--hidden-header`, opt-in).** Wraps output so the
  whole file is indistinguishable from random bytes, removing the identifiable header
  that fingerprinted a file as ours and leaked its derivation profile. Two byte-identical
  modes — keyless (anti-fingerprinting) and keyed second-password (real metadata
  confidentiality, no decryption oracle). Streaming-safe and fully backward-compatible.

- **Recovery slots (envelope add-on).** An envelope's Data Encryption Key can now be
  wrapped under independent recovery credentials — a high-entropy recovery code, a
  memorable recovery passphrase, or a post-quantum (ML-KEM) escrow recipient — so a lost
  password no longer means lost data. The slot set is bound by a DEK-keyed MAC and fails
  closed against tampering.

- **And more:** real spec-compliant 192-bit XChaCha20-Poly1305 nonces, envelope
  encryption (DEK/KEK), detached post-quantum signing (`sign` / `verify-signature`),
  ASCII armor output, encrypt-to-self, a PIV / PKCS#11 HSM backend (`--hsm piv`), and
  source-code integrity verification.

(1.4.7 is a docs/packaging follow-up over 1.4.6 — it refreshes the PyPI project page and
documentation; no functional or on-disk format changes.)

## Get it

- GitHub release: https://github.com/jahlives/openssl_encrypt/releases/tag/v1.4.7
- PyPI: `pip install openssl-encrypt` — https://pypi.org/project/openssl-encrypt/
- Flatpak:
  ```
  flatpak remote-add --if-not-exists openssl-encrypt https://flatpak.rm-rf.ch/openssl-encrypt.flatpakrepo
  flatpak install openssl-encrypt com.opensslencrypt.OpenSSLEncrypt
  ```
