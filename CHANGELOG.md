# Changelog

All notable changes to the openssl_encrypt project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - TBD

### Added

- **Format-version fixture corpus** (v14 implementation plan Phase 5):
  pre-encrypted fixtures under `unittests/testfiles/format_versions/` pin
  the decrypt path of every supported write topology — v9 plain, v11/v13
  independent-XOR, v13 sequential-XOR, v12/v14 streaming, v13/v14 PQC with
  HKDF and transcript-bound KEM keys, and a pre-1.4.8 legacy-KDF PQC file
  that permanently pins the bare-SHA256 decrypt fallback. A failure in this
  suite means reading existing files broke.


- **`check-password` command**: a read-only subcommand that reports the strength
  of a password without encrypting anything. Prints the pattern-aware strength
  category, entropy (pattern-aware and raw), detected-weakness warnings, and
  pass/fail against a chosen `--password-policy` (with `--strict-strength`
  supported). The password is read from `CRYPT_PASSWORD`, a piped stdin, an
  interactive prompt, or (discouraged, with a warning) the `-p`/`--password`
  flag. Human output goes to stderr; `--json` emits a machine-readable report on
  stdout. Exits non-zero when a policy is applied and the password fails it, so
  it can be used as a scriptable gate.
- **Pattern-aware password strength estimation**: password strength feedback now
  detects predictable structure (dictionary words, l33t substitutions, keyboard
  walks, ascending/descending sequences, repeats, dates) instead of relying on
  the raw character-space entropy alone, which over-rated structured passwords
  (e.g. `Password1!`). Uses the optional [`zxcvbn`](https://pypi.org/project/zxcvbn/)
  package when installed, and a built-in heuristic fallback otherwise — `zxcvbn`
  is **not** a production dependency. Behaviour is **advisory by default**: the
  displayed strength label and new "Password weakness" warnings reflect the
  pattern-aware estimate, but the `--min-password-entropy` gate still uses the
  raw measure, so passwords accepted before remain accepted. The new
  `--strict-strength` flag (enabled automatically by the `paranoid` policy) makes
  the gate reject passwords whose pattern-aware strength is too low. This only
  affects password validation when encrypting; it never affects decryption.
- **Hidden ("whitened") file format** (**now the DEFAULT output on 1.5.x**; opt
  out with `--legacy-format`): wraps the
  encrypted output in an outer layer so the whole file is indistinguishable
  from random bytes, hiding the identifiable `base64(metadata):base64(body)`
  header that otherwise fingerprints a file as ours and leaks the derivation
  profile. Only the small metadata header is whitened; the body is kept raw
  (no double-encryption), so streaming and bounded memory are preserved. Two
  modes share one byte-identical layout (`salt | nonce | whitened_len |
  header_region | auth | body`) so the presence of a second password is not
  observable:
  - **Keyless** (default when `--hidden-header` is given without a second
    password): the outer key is derived cheaply from the *public* salt. This is
    **anti-fingerprinting only** — a party who has the tool can reverse the
    public transform; it defeats bulk/passive fingerprinting, not a targeted
    analyst.
  - **Keyed** (`--second-password`/`--second-password-fd`/
    `--second-password-prompt`): the outer key is derived from a *second*
    password through a fixed heavy chain (100k×SHA3-512 → 5×Argon2id → scrypt →
    HKDF), giving real **metadata confidentiality** even against an adversary
    who has the tool. The length field is whitened with a password-derived key,
    so a keyed file has no length-based distinguisher and a wrong second
    password fails as an authentication error. Keyed mode authenticates the
    header (XChaCha20-Poly1305, AAD = `salt|nonce|whitened_len`); keyless mode
    is deliberately tagless (no free "this is our file" oracle).
  Supported on the symmetric, keystore-wrapped, and asymmetric (PQC) paths,
  for both buffered and streaming files. Decryption auto-detects legacy vs
  hidden (no magic bytes); `--legacy-format` forces the legacy path. On 1.5.x
  new CLI encryptions default to keyless-hidden (the `encrypt_file` library API
  still defaults to legacy); the 1.4.x line keeps the legacy default and offers
  the hidden format only via `--hidden-header` (flipping a stable line's default
  would break older readers). The outer KDF profile is fixed and pinned to
  a version (it cannot be stored without re-leaking the fingerprint). On
  decrypt, a keyed file with a missing/wrong second password fails with the same
  generic error as any wrong/corrupt input (no oracle); an **interactive,
  TTY-gated second-password prompt** offers it before failing (suppressible with
  `--no-second-password-prompt`, never fires in scripts). See
  `docs/HIDDEN_HEADER.md`.

- **Recovery slots** (envelope add-on): an envelope file's Data Encryption Key
  can be wrapped under one or more *independent* recovery credentials in
  addition to the password, so losing the password no longer means losing the
  data. Four credential types: a generated high-entropy **recovery code**
  (HKDF), a memorable **recovery passphrase** (Argon2id), a **Shamir k-of-n**
  split recovery secret (reuses the secret-sharing module), and a **PQC escrow
  recipient** (ML-KEM public key). Decryption succeeds with the password *or*
  any recovery credential. The recovery-slot SET is bound by a DEK-keyed MAC
  (`encryption.dek_slots_mac`), verified on every decryption path, so
  stripping, injecting, modifying, or swapping slots fails closed; the slot
  fields are excluded from the bulk AEAD AAD so slots can be added/removed
  post-hoc without re-encrypting the bulk. **Purely additive and fully
  backward-compatible**: files without recovery slots are byte-identical and
  the primary `wrapped_dek` stays canonical. CLI: `add-recovery`,
  `remove-recovery`, `list-recovery`, and `recover` (decrypt via a recovery
  credential). On-disk format pinned by committed golden fixtures
  (`testfiles/recovery_slots/`). See `docs/RECOVERY_SLOTS.md`.

- **Envelope encryption (DEK/KEK)** (`--envelope`, opt-in): bulk data is
  encrypted under a random **Data Encryption Key (DEK)**, and the DEK is wrapped
  by a **Key Encryption Key** derived from the password through the full,
  unchanged KDF chain. Decryption auto-detects envelope files (no flag needed).
  - **O(header) credential rekey**: changing the password rewraps the small DEK
    and rewrites only the metadata header — the bulk ciphertext is retained
    verbatim instead of being re-encrypted. This rotates the *access credential*,
    not the data key; for true data-key rotation, re-encrypt under a fresh DEK.
  - **Stable-subset AEAD binding**: the bulk is bound to a canonical subset of
    the metadata that excludes only the KEK-gating fields a rekey changes (the
    KDF salt/config and the wrapped DEK); every other field stays authenticated,
    so a rekey keeps the ciphertext valid while tampering still fails closed.
  - **Never the weak link**: for a `cascade` chain the DEK is wrapped under the
    *same* chain (not single AES-256-GCM), preserving the cascade's
    strongest-component guarantee. Single-cipher files use AES-256-GCM.
  - Opt-in only and **fully backward-compatible**: files written without
    `--envelope` are byte-for-byte unchanged and keep full-metadata AEAD binding.
    DEK and KEK are zeroed on every path and never logged. Foundation for future
    multi-password / multi-recipient wrapping.

- **Foreign-format interop — decrypt `age` and OpenPGP files**
  (`decrypt --from age|pgp`): read-only decryption of files produced by other
  ecosystems, to ease migration. Implemented directly on `cryptography` — **no
  new dependency**.
  - **age** (`--from age`): X25519 recipients (`--age-identity keys.txt`,
    repeatable) and scrypt passphrase files (`age -p`, via `--password`); binary
    and ASCII-armored; unknown/GREASE stanzas skipped. Validated against the
    `age` reference implementation's known-answer vectors.
  - **OpenPGP** (`--from pgp`): both passphrase-based (`gpg -c`) and
    **public-key** messages. Symmetric: SKESK + S2K, SEIPD v1 (CFB + SHA-1 MDC),
    inner ZIP/ZLIB/BZIP2 compression, ciphers 3DES/CAST5/AES-128/192/256/Camellia.
    Public-key (`--pgp-key FILE`, key passphrase via `--password`): parses an
    exported secret key and unwraps the session key for **RSA** (PKCS#1 v1.5) and
    **ECDH** (RFC 6637 + RFC 3394) over Curve25519 and NIST P-256/384/521. All
    validated against real GnuPG output.
  - Untrusted-input hardening across both: integrity (age MAC/AEAD; OpenPGP MDC)
    is verified before any plaintext is returned, unauthenticated OpenPGP data
    (SED) is refused, decompression and packet/work-factor sizes are bounded,
    and unsupported constructions fail closed. New package
    `openssl_encrypt/modules/interop/`.

- **Detached file signing** (`sign` / `verify-signature`): post-quantum
  (ML-DSA-65) detached signatures over **arbitrary files**, closing the
  authenticity gap of symmetric AEAD (which gives confidentiality + integrity
  but lets anyone who knows the password forge a valid file).
  `sign --input F --sign-with IDENTITY` writes a `.sig` JSON sidecar
  (ASCII-armored by default; `--no-armor` for raw) that binds the file's
  SHA-512 digest to the signer over a domain-separated payload (distinct from
  the encrypted-file metadata signature). `verify-signature` resolves the
  signer's public key from your identity store **and contacts** by the embedded
  fingerprint, **fails closed on an unknown signer** (`--signer` to pin),
  reports which signature component(s) verified, and supports `--json`. The
  sidecar's `signatures` list is forward-compatible with a future classical
  (e.g. Ed25519) hybrid component. New module
  `openssl_encrypt/modules/file_signature.py` (covered by the signed manifest).

- **ASCII armor** (`encrypt --armor` / `-a`): write PEM-style Base64 output that
  is safe to paste into email, chat, YAML or a clipboard. The whole encrypted
  blob is wrapped in a `-----BEGIN/END OPENSSL-ENCRYPT MESSAGE-----` envelope
  with an OpenPGP-style CRC-24 checksum that detects paste truncation/corruption
  (fails closed on malformed armor). `decrypt`, `info` and `verify` auto-detect
  armored input by content — no flag required — and the round-trip is byte-exact.
  Works across the symmetric, `stdin`→`stdout` streaming, and recipient
  (asymmetric) output paths. New module `openssl_encrypt/modules/armor.py`
  (covered by the signed integrity manifest).

- **Encrypt-to-self** (`encrypt --for-identity …`, on by default): when
  encrypting *for* recipients, the sender's own identity (`--sign-with`) is now
  added as an additional recipient so the sender can later decrypt their own
  outbound file — removing a common data-loss footgun. The sender slot reuses
  the existing multi-recipient ML-KEM wrapping and is de-duplicated by
  fingerprint. Opt out with `--no-encrypt-to-self`.

- **PIV / PKCS#11 HSM backend** (`--hsm piv`): hardware-bound key derivation
  backed by a PIV private key on a PKCS#11 token (YubiKey Bio MPE, Token2 PIN+
  R3.3+, or any compliant PIV smart card). The key signs a deterministic
  challenge derived from the salt and the signature is normalized into a pepper
  via HKDF-SHA256. Algorithm-agnostic across Ed25519 and RSA-2048/3072/4096;
  non-deterministic schemes (ECDSA, RSA-PSS) are explicitly rejected so the
  same key on multiple devices always yields identical peppers.
  - New flags: `--hsm-pkcs11-lib PATH` (required), `--hsm-piv-slot {9a,9c,9d,9e}`,
    `--hsm-biometric`; `--hsm-slot` selects the PKCS#11 slot index for PIV.
  - PIN is read via `getpass` (never via CLI args/logs/exceptions), held in a
    `bytearray`, and wiped with `secure_memzero` after login; a final-try guard
    refuses lock-risking attempts without confirmation; sessions are closed on
    every exit path.
  - New dependency: `python-pkcs11` (in `requirements-hsm.txt`).
  - Setup guide: `openssl_encrypt/docs/PIV_BACKEND.md`.

- **Cross-device HSM decryption (YubiKey ↔ OnlyKey)**: files encrypted with
  one HMAC-SHA1 challenge-response device can now be decrypted with the
  other by selecting it explicitly via `--hsm`, provided both devices hold
  the same 20-byte secret (`yubikey_hsm` / `onlykey_hsm` form a
  protocol-compatible plugin family; unrelated plugins are still rejected).
  `--hsm-slot` on `decrypt` / rekey now takes precedence over the slot
  stored in file metadata — previously it was printed but silently
  ignored — so fleet devices may hold the secret in different slots.
- **OnlyKey setup guide** (`docs/ONLYKEY_SETUP.md`, linked from the docs
  sidebar): installation, udev rules for VID/PID 1d50:60fc, the
  unlock-then-touch hardware flow, the challenge-code-mode caveat,
  cross-device provisioning with YubiKey, and troubleshooting for every
  real-hardware failure mode.
- **Real 192-bit XChaCha20-Poly1305 nonces** (spec-compliant per
  draft-irtf-cfrg-xchacha-03), replacing the previous behavior where a
  24-byte nonce was stored but only the first 12 bytes affected the
  keystream (96-bit effective, not a vulnerability thanks to per-file
  keys, but not real XChaCha and not interoperable):
  - New module `modules/xchacha.py` implements HChaCha20 on top of the
    `cryptography` library's ChaCha20 (keystream feed-forward
    subtraction) — no new runtime dependency. Pinned against the
    official §2.2.1 and §A.3 test vectors and an independent
    pure-Python reference (`test_xchacha_primitives.py`).
  - New files carry `encryption.xchacha_nonce_format: 2` in their
    metadata (AAD-protected when `aead_binding` is set). Decryption
    auto-detects: files without the flag use the legacy derivations
    (one-shot/streaming: first-12-bytes; cascade: HKDF nonce funnel).
  - Applies to one-shot, streaming (24-byte per-chunk nonces), and
    cascade XChaCha layers. The PQC hybrid data layer intentionally
    keeps 12-byte nonces under per-encryption KEM-derived keys.
  - Backward compatibility is pinned by immutable fixtures generated
    with the pre-1.5 code (`testfiles/xchacha_legacy/`); the new format
    is pinned by `testfiles/xchacha_v2/`.
  - The `XChaCha20Poly1305` wrapper now rejects nonce lengths other
    than 24 (real) and 12 (legacy/PQC); the unreachable HKDF nonce
    branches were removed.

- **`info` action now reconstructs the `encrypt` CLI** from file metadata:
  - The human-readable output of `openssl_encrypt info <file>` now ends
    with a "Reconstructed CLI" section showing the full
    `openssl_encrypt encrypt ...` command that would produce equivalent
    encryption settings on a fresh file.
  - Salt and per-file random values are NOT reconstructed — only the
    deterministic configuration (cipher / cascade chain, all five KDFs
    Argon2id/scrypt/Balloon/HKDF/RandomX, the 12 hash-rounds flags,
    legacy PBKDF2 / Whirlpool flags, HSM binding via `--hsm` +
    `--hsm-slot`, remote-pepper plugin via `--pepper` + `--pepper-name`).
  - JSON output mode (`info --json`) is unchanged — the JSON payload
    remains the raw metadata dict, so scripts piping into `jq` continue
    to work without modification.
  - Round-trip property covered by automated test
    (`test_info_reconstruction.py::TestReconstructionRoundTrip`):
    encrypting a fresh file with parameters X, extracting metadata, and
    running the reconstructor yields a CLI flag string containing
    every parameter value from X.
  - Argon2's `type` field is auto-converted from the on-disk integer
    representation (0/1/2) back to the CLI form (`d`/`i`/`id`).
  - SHA-3 hash names use the metadata form (`sha3_512`) translated to
    the CLI flag form (`--sha3-512-rounds`).
- **`derive-password` gains HSM-aware deterministic derivation**:
  - `--hsm yubikey` / `--hsm onlykey` (+ optional `--hsm-slot`) plumb
    the hardware token's HMAC-SHA1 response into the KDF cascade. Same
    password + same salt + same device-loaded secret = same output;
    re-provisioning the device silently changes the output.
  - When `--hsm` is set without explicit `--salt` (random-salt mode), a
    stderr reminder fires explaining the three reproducibility inputs
    (password, salt, hardware secret) so users don't get surprised when
    re-running fails.
  - `--confirm` prompts for the password twice and rejects on mismatch
    — guards against typos that would silently produce a wrong derived
    value. No-op when password comes from `--password` / `--password-file`
    / `--password-fd` / `OPENSSL_ENCRYPT_PASSWORD` / `--keyring-load`.
- **Diceware passphrase generation** for `generate-password`:
  - `--dice` switches `generate-password` from character-based generation
    to a Diceware-style passphrase (mutually exclusive with the
    `--use-lowercase/uppercase/digits/special` flags).
  - `--dice-count N` (default 10) — number of words. Defaults to 10 for a
    conservative ~129 bits of entropy with the bundled EFF list.
  - `--dice-sep SEP` (default `""`) — separator between words. Defaults to
    empty for maximum compatibility with password fields that strip
    whitespace.
  - `--dice-list PATH` — custom wordlist; auto-detects EFF format
    (`<dice>\t<word>`) vs plain one-word-per-line.
  - `--force-wordlist` — override the 1024-word (10 bits/word) minimum
    for custom wordlists. Default rejects undersized lists outright;
    forcing emits a UserWarning but proceeds.
  - The bundled
    [EFF Large Wordlist](https://www.eff.org/dice) (7,776 words) ships
    at `openssl_encrypt/data/eff_large_wordlist.txt` under
    [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/);
    attribution lives in `openssl_encrypt/data/EFF_WORDLIST_LICENSE.txt`.
  - Diceware mode prints `Passphrase entropy: X bits (N words)` to
    stderr, then the passphrase via the existing display helper.
  - Wordlist loader strict-validates: rejects duplicate words and
    words containing whitespace (both would silently corrupt entropy
    or boundary semantics).
  - Policy interaction: in `--dice` mode only entropy- and length-based
    policy checks apply; character-class and common-password checks are
    skipped (they are orthogonal to passphrase security).
- **OnlyKey Challenge-Response HSM plugin**: New `OnlykeyHSMPlugin`
  (`openssl_encrypt/plugins/hsm/onlykey_challenge_response/`) adds
  hardware-bound pepper derivation via OnlyKey devices (USB VID/PID
  `0x1d50:0x60fc`) using the same HMAC-SHA1 wire protocol as YubiKey.
  CLI: `--hsm onlykey` for encrypt/decrypt, slots 1..12 via `--hsm-slot`,
  auto-detected if omitted. Two new HSM management subcommands:
  `openssl_encrypt hsm onlykey-list` and `openssl_encrypt hsm onlykey-test`.
- **OnlyKey identity protection**: `openssl_encrypt identity create`
  now accepts `--hsm onlykey` and `--hsm onlykey-only` alongside the
  existing yubikey options. `IdentityKeyProtectionService` selects the
  plugin via a new `hsm_type` constructor argument; the type is
  serialised into the identity protection metadata so decrypt routes
  to the correct plugin.
- **Cross-device deterministic pepper guarantee**: A YubiKey and an
  OnlyKey loaded with the same 20-byte HMAC-SHA1 secret produce
  identical responses for identical challenges, allowing mixed fleets.
  Verified by a new RFC 2202 parameterised determinism test
  (`test_cr_cross_backend_determinism.py`).
- **Documentation**: `docs/hardware-tokens.md` (combined YubiKey +
  OnlyKey setup guide, fleet provisioning workflow, troubleshooting)
  and `docs/migration-from-yubikey-only.md` (step-by-step for existing
  users adding OnlyKey to their fleet).
- **Regression test baseline for YubikeyHSMPlugin**
  (`test_yubikey_plugin.py`, 24 tests) — locks in existing behaviour
  prior to the OnlyKey work.

### Fixed

- **README: broken CLI examples and stale version references**
  (gitlab#126 / github#52, 2026-07-13): the password-generation example
  used a non-existent `generate --length` invocation (the subcommand is
  `generate-password` with a positional length), the shred example used
  `--passes` instead of `--shred-passes`, and the keystore examples
  invoked a non-existent `openssl_encrypt.keystore_cli_main` module with
  flags the CLIs don't have — replaced with the real
  `openssl_encrypt.modules.keystore_cli` workflow (`create`, encrypt
  with `--keystore-path` auto-generating the keypair, `list-keys`).
  The cascade example (follow-up, same day) used both a wrong syntax
  and a non-existent algorithm name: `--cascade` takes a preset
  (`standard`/`paranoia`) or combines with `--algorithm` for a custom
  chain, and the cipher is `xchacha20-poly1305`, not `xcha-poly1305`.
  Also updated the stale "latest stable is v1.4.0" pointer to v1.4.8
  and removed the leftover v1.4.0-beta framing ("v1.4.0 Development
  Series", "currently in beta testing", stale test counts).
  Documentation only; no code changes.

- **Test: `test_fallback_notice_respects_quiet` is now deterministic
  against the environment** (gitlab#122, 2026-07-12, ported from
  1.4.x): the CI test job exports `PQC_QUIET=true`, and
  `PQCipher.__init__` computes `self.quiet = quiet or PQC_QUIET` — so
  the test's `quiet=False` reader was forcibly quiet in CI, the
  legacy-KEM-derivation notice never appeared, and the assertion failed
  on release-branch/tag pipelines (the only pipelines that run the test
  job). The test now patches the module-level `PQC_QUIET` constant to
  `False` so it exercises the `quiet` parameter itself. Product
  behavior is unchanged.

- **Legacy-KDF retry classification is now structural and covers every
  PQC data cipher** (v14 follow-up review LOW-4, gitlab#116, 2026-07-11):
  three classification gaps in the v12/v13 legacy-KEM-key retry — all
  fail-closed, none attacker-usable. (1) Native Threefish authentication
  failures propagated as the binding's raw `RuntimeError` before the
  `PQCAuthenticationError` classifier, so legacy (bare-SHA256-keyed)
  v12/v13 threefish files never got the one-shot retry built for exactly
  that population — the tag failure is now classified structurally
  (threefish_native raises `RuntimeError` for tag failures, `ValueError`
  for structural errors). (2) The adapter retry caught only
  `cryptography.exceptions.InvalidTag`, but the custom XChaCha20Poly1305
  wrapper converts that into the project's `AuthenticationError`, so
  adapter-path xchacha legacy files skipped the retry — it now catches
  both. (3) The native classifier was over-broad (`except Exception`),
  converting structural errors (e.g. "Ciphertext too short") into
  "authentication failure" and triggering a pointless retry,
  contradicting the `decrypt()` docstring — it is now narrowed to
  `(InvalidTag, AuthenticationError)`. The retry remains scoped to
  v12/v13 and AEAD-gated; v14+ still never retries.

- **Pointed migration error for removed-PBKDF2-chain files**: decrypting a
  1.4.x sequential file whose key-derivation chain used `pbkdf2_iterations`
  (the PBKDF2 chain stage removed in 1.5.0) previously failed with a generic
  authentication error indistinguishable from a wrong password. Decrypt now
  refuses up front — before burning KDF time on a derivation that cannot
  succeed — with guidance naming the breaking change and the migration path
  (decrypt with openssl-encrypt 1.4.x, re-encrypt). Scoped to
  sequential-routed files only: independent-XOR files carry the same
  (public) `pbkdf2` metadata entry but never consumed it and keep
  decrypting; wrong-password errors on readable files are unchanged. Also
  enforced on the envelope rekey fast-path and the asymmetric decryption
  path (both bypass the main decrypt dispatch); crypto-review confirmed the
  refusal is based only on public cleartext metadata (no oracle).


- **Keystore dual-encryption metadata gates excluded v11-v14 files**
  (pre-existing, surfaced by the v14 default flip): `keystore_wrapper` and
  `keystore_utils` checked `format_version in [4..10]` before looking up
  embedded PQC keys, key IDs, and the dual-encryption flag in the v4+
  hierarchical metadata — files at v11-v13 fell into the legacy root-level
  branch and keystore dual-encryption failed. All gates generalized to
  `>= 4`, matching the crypt_core fix.

- **RandomX component crashed independent-XOR derivation for wide-key
  algorithms** (pre-existing): the RandomX KDF natively yields 32 bytes, so
  with AES-SIV or Threefish-512/1024 (64/128-byte keys) the independent-XOR
  combiner refused to XOR mismatched lengths and key derivation crashed.
  The component output is now HKDF-normalized to the target key length
  (byte-identical pass-through for 32-byte keys; mismatched configs never
  produced a file, so nothing existing is affected). The KDF-without-
  prior-hashing interactive warning and the HKDF-only rejection (#99) are
  also enforced on the independent-XOR path now that it is the default.

- **Sequential XOR + streaming silently produced undecryptable files** (found
  while wiring the v14 default flip): requesting `--use-xor-composition` on
  a file above the streaming threshold derived the key sequentially but
  wrote a v12 streaming file, which the decrypt router always routes down
  the independent-XOR path — every such file failed chunk authentication
  (data loss). The combination is now refused with a clear error pointing
  to `--no-streaming` (which round-trips correctly at v13-sequential)
  instead of writing a file that cannot be decrypted.

- **Embedded encrypted PQC private keys in v11-v13 files were undecryptable**
  ("Missing PQC key salt"): the decrypt-side `pqc_key_salt` lookup was gated
  on `format_version in [4..10]`, so files that embed a password-encrypted
  post-quantum private key (`pqc_store_private_key`) at format versions 11-13
  always fell into the v3 legacy branch and failed. Every v4+ metadata writer
  stores the salt under `encryption.pqc_key_salt`; the gate is now `>= 4`,
  with v13/v14 regression round-trips. Found while wiring format_version 14.


- **Asymmetric recipient files written by 1.4.x now decrypt on 1.5.x**: the
  per-recipient password-wrap key derivation was upgraded from bare SHA-256 to
  HKDF-SHA256 (`password_wrap.v2`) on the 1.4.x line, but the change was never
  forward-ported, so 1.5.x derived a different wrap key and failed to decrypt
  recipient files produced by 1.4.x. Forward-ported the HKDF derivation;
  `unwrap_password` now tries HKDF/v2 first and falls back to the legacy
  bare-SHA256 (`v1`) derivation, so both lines write v2 and read v2+v1 and
  recipient files are cross-line interoperable (with a regression test pinning
  it). The bare-SHA256 derivation was itself cryptographically sound — an ML-KEM
  shared secret is already a uniform 32-byte key — so this is an interop /
  robustness fix, not a confidentiality fix.
- **OnlyKey plugin now works with real hardware**: device construction no
  longer fails with "24828 is not a valid PID" — the plugin masquerades as
  an OTP-only YubiKey (`PID.YKS_OTP`), since yubikit's PID enum only
  contains Yubico product IDs and the PID is used solely for USB interface
  bookkeeping. `open_connection` is now called with `OtpConnection`
  instead of `None` (ykman asserts on non-type arguments). A device that
  actively rejects a challenge now produces an actionable error naming the
  two real-world causes (empty slot / challenge-code mode) instead of the
  bare "No data".
- **threefish_native builds on Python 3.14**: PyO3 upgraded 0.24.1 → 0.26
  (3.14 support), with the `PyBytes::new_bound` → `PyBytes::new` API
  rename.
- **Streaming encryption data-loss bug**: streaming files always record
  `format_version: 12` in their metadata, but the encryption key, pepper
  derivation, and cascade setup were built with the *caller's*
  format_version (library default 10; the CLI passes 9/10/11 depending
  on XOR flags). Decryption re-derives everything from the metadata
  version, so freshly encrypted streaming files failed authentication
  and could not be decrypted. format_version=11 worked for plain
  ciphers only by coincidence (its key derivation matches v12), which
  is why the integration tests — pinned to fv=11 — never caught it;
  cascade + streaming was broken for every version except an explicit
  12. The streaming decision now happens before any version-dependent
  derivation and forces format_version=12 for the whole streaming
  encrypt path. One-shot files keep the caller's version unchanged.
  Regression-tested across fv 9/10/11/12/default, plain and cascade
  (`test_streaming_format_version.py`).
- **Cross-version envelope + cascade + XChaCha decryption**: a file written by
  1.4.x with `--envelope`, a `cascade` chain containing `xchacha20-poly1305`,
  could not be decrypted after upgrading to 1.5.x. 1.4.x wraps the DEK with the
  legacy 12-byte XChaCha nonce and writes no `xchacha_nonce_format` flag, but the
  envelope DEK-unwrap (`unwrap_dek_cascade`) hardcoded the new 192-bit format
  (`xchacha_nonce_format=2`), so the DEK never authenticated and the file was
  permanently unreadable. The break was unique to envelope + xchacha — the bulk
  cascade path already defaulted an absent flag to legacy (1), so plain
  cascade+xchacha and single xchacha files always interoperated. The DEK
  wrap/unwrap now honor the file's `xchacha_nonce_format` (absent ⇒ legacy 1) at
  both the decrypt and rekey paths; newly written 1.5.x files are unchanged and
  still use the real 192-bit construction. Regression-tested against a committed
  genuine 1.4.x vector (`testfiles/envelope_xchacha_v14/`,
  `test_envelope_encryption.py`).

### Changed

- **Visible notices for legacy-format writes** (post-v14 review
  INFO-1/INFO-2, 2026-07-11, warn-only — never an error): requesting an
  explicit `format_version` below the current default for a NEW encryption
  now prints a warning (the file lacks the v14 `#100`/`#83` protections;
  explicit versions remain honored for API compatibility), and the
  streaming path's silent version upgrade is now announced with a visible
  note instead of a debug-only log line (streaming can only write v12 or
  v14; the upgrade itself is unchanged). Also corrected a misleading
  comment that claimed streaming PQC files exist (no PQC hybrid algorithm
  can stream), so future binding-coverage audits aren't misled (INFO-3).

- **Dead shadowed `_derive_symmetric_key` definition removed** (2026-07-10):
  `PQCipher` in `modules/pqc.py` carried two definitions of
  `_derive_symmetric_key`; the first (the pre-#83 v12/legacy-only variant)
  was silently shadowed by the second, live definition in the class body
  and was never executed. The dead first definition is removed — the live
  transcript-binding-aware implementation is unchanged, so no derivation
  path is affected. Removes the risk of someone editing the dead copy and
  seeing no effect.

- **Documentation: `docs/PBKDF2_CHAIN_ERROR_PLAN.md` added** (2026-07-10):
  plan for replacing the generic authentication error with a pointed
  migration error when decrypting 1.4.x sequential files that used the
  PBKDF2 chain stage removed in 1.5.0 — scoped to sequential-routed files
  only (independent-XOR files carry the same metadata entry but never used
  PBKDF2 and keep decrypting). Plan only — no code change.

- **1.5.x adaptations for the v14 rollout**: `verify` accepts format version
  14 (and validates the streaming structure only for actually-streaming v14
  files); the v14 metadata schema carries this line's streaming block
  (including the optional `cascade_nonce_scheme` from the cascade-streaming
  nonce fix); the fixture corpus pins that 1.4.x sequential files using the
  removed PBKDF2 chain fail cleanly here (documented 1.5.0 breaking change —
  decrypt those with 1.4.x) while all independent-XOR, streaming and PQC
  fixtures decrypt byte-identically; the PQC adapter's Threefish decrypt
  path now wipes both derived keys deterministically before returning.

- **format_version 14 scaffolding** (v14 implementation plan Phase 1, no
  default/behavior change for existing writes): registered
  `metadata_v14_schema.json` (independent-XOR only — `xor_mode` enum is
  `["independent"]`; optional v12-style `streaming` block), added
  `LATEST_STABLE_FORMAT_VERSION = 14`, extended explicit `xor_mode` stamping
  from `== 13` to `>= 13`, added a fail-closed guard refusing any
  `format_version >= 14` write with sequential XOR (sequential stays pinned
  at v13 per the M2 decision), and generalized hardcoded decrypt-side
  version lists (`[4..13]` → `>= 4`, `[8..13]` → `>= 8`) so future versions
  cannot silently fall into legacy branches. Per crypto-review of the phase:
  the sequential-refusal fires before the streaming force rewrites the
  version (size-independent invariant), the no-validator JSON fallback now
  fail-closes on unknown/future format versions instead of relying solely on
  schema validation, the v14 schema requires `xor_mode`, and the decrypt
  router treats `format_version >= 14` as independent-XOR explicitly. v14
  files round-trip; nothing writes v14 by default yet.


- **`--debug` warning is now proportional to what it leaks**: the loud
  "SENSITIVE DATA LOGGING ACTIVE" banner and the "do not use on production data"
  notice now fire only for `--debug --unsafe-show-secrets` (the path that prints
  secrets in cleartext). Plain `--debug`, which redacts every secret to length +
  a keyed SHA-256 fingerprint, now shows a calm, accurate note instead — stating
  that secrets are redacted, that secret lengths and public values (nonces,
  salts, ciphertext) are still written to stderr and may persist in logs or
  shell history, and that `--unsafe-show-secrets` reveals cleartext. The old
  always-on alarming banner both overstated the risk of the redacted path and
  desensitised users to the real cleartext warning. Message-only change; no
  redaction logic was altered.
- **Declared Python floor raised to `>=3.11`** in `setup.py` and
  `threefish_native/pyproject.toml`, aligning the metadata with the
  documented requirement (README: "Python 3.11+") and with the 1.4.x
  line (where numpy forces it; the 1.5 pins alone would allow 3.10).
  Stale 3.9/3.10 classifiers dropped, 3.14 added. Guarded by
  `test_python_floor_metadata.py`.
- `--hsm-slot` no longer hard-restricted to `choices=[1, 2]` at the
  argparse layer. YubiKey validates 1..2 inside its plugin; OnlyKey
  validates 1..12. This is purely an internal validation move — no
  user-visible behaviour change for existing YubiKey users; OnlyKey
  users can now select any slot in 1..12.
- `handle_hsm_command` no longer imports / requires FIDO2 unconditionally.
  The fido2 availability gate is now scoped to `fido2-*` actions only,
  so `onlykey-list` / `onlykey-test` work on machines without fido2.

### Removed

**Code-surface reduction** (~28,000 lines, -23% of production code). None of
these affect the ability to decrypt existing files — every decrypt path is
preserved. Exception: steganography *extraction* (see below).

- **Steganography subsystem** (`plugins/steganography/`, ~8.7k lines): all
  LSB/JPEG/DCT hiding methods for PNG, BMP, JPEG, TIFF, WEBP, WAV, FLAC,
  MP3 and MP4, and all `--stego-*` CLI flags. ⚠️ Data hidden with
  `--stego-hide` can no longer be extracted with v1.5.0 — extract it with
  v1.4.x first (the embedded encrypted payload itself remains decryptable
  by v1.5.0 once extracted). Drops the `numpy` production dependency
  (Pillow is retained for QR key distribution).
- **D-Bus service and client** (`dbus_service.py`, `dbus_client.py`, bus
  policies, systemd units, client examples). The service had no production
  importers; a privileged system service is unnecessary attack surface.
- **In-package security testing framework** (`modules/testing/`, ~4.4k
  lines: fuzzing, side-channel, KAT, benchmark and memory suites) and the
  `test` CLI command — development tooling no longer ships in the
  production package.
- **Advisory configuration tooling**: `config-wizard`, `analyze-config`,
  `analyze-security`, the `template` management subcommand and the
  `smart-recommendations` engine (`config_analyzer.py`, `config_wizard.py`,
  `template_manager.py`, `smart_recommendations.py`, `security_scorer.py`).
  Encryption templates are unaffected: `-t/--template`,
  `--quick/--standard/--paranoid`, the security aliases and custom
  JSON/YAML templates in `templates/` work unchanged.
- **`security_report.py`** — dead code, imported by nothing.

Deliberately kept after re-evaluation: the decryption cost estimator
(`decryption_estimator.py`) — it is DoS protection against maliciously
inflated KDF metadata parameters, not cosmetic output.

### Security

- **Balloon KDF fails closed on v14+ metadata missing `space_cost`**
  (security review 2026-07-13 INFO-2, gitlab#125): the decrypt-side
  derivation fell back to the historically weak `space_cost=16` whenever
  the field was absent from balloon metadata. That fallback is load-bearing
  for v11 files written by released v1.4.0–v1.4.3 (pre-M3, guarded by
  `test_balloon_defaults_m3.py`) and is kept for v11–13 — but v14 postdates
  the M3 fix, so every released v14+ writer persists the field; a missing
  `space_cost` at v14+ can only be crafted or corrupted metadata and now
  raises a clear `ValueError` instead of silently deriving with ~512 bytes
  of memory hardness. The parallel KDF path needs no gate of its own (v13+
  parallel dispatch delegates to the sequential, gated path — invariant now
  pinned by a test). No legitimately written file changes behavior.

- **The legacy no-hash-iterations KDF seed is now wipeable and wiped**
  (security review 2026-07-13 INFO-1, gitlab#124): with no hash iterations
  configured, `generate_key` built its seed as the immutable concatenation
  `password + salt + hsm_pepper`, which the existing wipe at the return
  site silently refused (M10 — immutable input). The seed is now written
  into one exact-size `bytearray` through a memoryview and is effectively
  zeroized in the `finally`, including when a KDF rebinds the working
  variable. Legacy sequential formats only; derived keys are byte-identical
  (pinned by golden-value regression tests).

- **`derive-password` no longer leaves the HSM pepper and derived-key
  copies unwiped** (security review 2026-07-13 LOW-1, gitlab#123): the
  handler held the hardware pepper as immutable bytes that were never
  zeroized, and "cleaned up" the derived key by wiping a throwaway
  `bytearray(key)` copy while the printed output slice stayed resident.
  The pepper is now held in a wipeable buffer from acquisition (a mutable
  plugin buffer is wiped in place), the truncated output is copied into a
  `bytearray` via a memoryview (no intermediate immutable slice), and both
  are zeroized in a `finally` on all exit paths. The immutable `bytes`
  returned by `generate_key` remains a documented accepted residual (M10
  design, common to all callers). Derived outputs are unchanged.

- **The live `hsm fido2-test`/`onlykey-test` handlers no longer print the
  derived hardware pepper** (H1 [HSM-1] residual, gitlab#121, 2026-07-12,
  ported from 1.4.x): the 2026-07-07 H1 fix removed the pepper hex dump
  from `modules/hsm_cli.py`, but that click-based frontend is not wired
  into the `openssl-encrypt` entry point — the `hsm` subcommand dispatches
  to `handle_hsm_command` in `crypt_cli.py`, whose `fido2-test` and
  `onlykey-test` handlers still hex-dumped the full pepper. Both now
  report only the pepper length. Mitigating: the printed pepper was
  derived from a random per-invocation test salt, so it unlocks no real
  file — but it is hardware-derived key material and must never reach
  output. Fixed in the same sweep: the FIDO2 pepper plugin interpolated
  the raw prf/hmac-secret output (the pepper's source material) into a
  `logger.debug` line and into a `PluginResult` error message that reaches
  the user via `eprint(result.message)` — both now render structure only
  (type/keys); and the `asymmetric_core` `__main__` self-test printed 32
  bytes of its (random, throwaway) roundtrip password as hex on failure —
  now lengths only. The H1 regression test now scans the live
  `crypt_cli.py`, the OnlyKey/YubiKey challenge-response plugins, and
  every `prf_data` sink (logs, prints, plugin error messages), not just
  `hsm_cli.py`.

- **SECURITY.md advisories recorded for this release's security batch**:
  new ADVISORY 2026-03 (plugin signature verification gaps — unverified
  package siblings H2 [PLUGIN-1], verify/execute byte mismatch M1
  [PLUGIN-2]) and ADVISORY 2026-04 (cleartext secret material in
  diagnostic/debug output — HSM test-command pepper prints incl. the
  gitlab#121 live-path residual / GHSA-p9g8-wvh4-2jmx, per-round KDF
  debug intermediate, plugin prf_data sinks, self-test print); the
  ADVISORY 2026-02 mitigation now notes the v8/v10 write refusal, the
  rekey upgrade path, and this line's PBKDF2-chain migration caveat.

- **The native PQC Threefish paths now zeroize the expanded
  data-encryption key** (v14 follow-up review LOW-3, gitlab#115,
  2026-07-11): in `PQCipher.encrypt`/`_decrypt_impl` the Threefish branch
  derived the actual 64/128-byte Threefish key via HKDF as plain immutable
  `bytes`, never wiped it, and returned before the AEAD block's
  SecureBytes handling; the adapter *encrypt* threefish branch had the
  same gap. All three sites now mirror the adapter decrypt pattern that
  landed with the v14 series: the expanded key is held in `SecureBytes`
  and zeroized in a `finally` on success and exception paths (HKDF's
  immutable output remains the documented M10 accepted residual). No
  derived keys or ciphertexts change; pure memory-hygiene hardening.

- **`encrypt_file` now refuses format_version values above the latest
  stable format** (v14 follow-up review LOW-2, gitlab#114, 2026-07-11):
  the write path bounded explicit `format_version` requests from below
  (the v8/v10 sequential-XOR refusal) but not from above — an explicit
  `format_version=15` passed every `>= 14` gate, derived a real key, and
  stamped the unknown version into the metadata; the decrypt side then
  failed closed on it, leaving a permanently unreadable file (data-loss
  footgun for API callers) carrying an on-disk version whose semantics
  were never specified. New writes now raise a clear `ValueError` for
  `format_version > LATEST_STABLE_FORMAT_VERSION`, before any archiving
  or temp files, mirroring the decrypt-side bound. Not attacker-
  exploitable; no change for any valid version.

- **Remote and combined KDF pepper are now zeroized after use** (v14
  follow-up review LOW-1, gitlab#113, 2026-07-11): the v14 work wipes the
  TLV KDF seed in a `finally` block, but the pepper material feeding it
  outlived that wipe — the remote pepper (AES-GCM decrypt output) and the
  combined `hsm_pepper + remote_pepper` concatenation were immutable
  `bytes` that were never zeroized, and the existing `hsm_pepper` wipe was
  a no-op copy-zero on plugin-supplied `bytes` (M10). All three are now
  held in wipeable `bytearray` buffers from creation — the combined pepper
  is built by a new `_combine_peppers` helper in one exact-size allocation
  (no intermediate concatenation copies, same M2 [MEM-1] standard as the
  seed encoder) — and zeroized in the `encrypt_file`/`decrypt_file`
  `finally` blocks on all paths. Unavoidable immutable transients from
  library/plugin APIs (`AESGCM.decrypt` output, the plugin result dict)
  remain documented accepted residuals. No derived keys or file formats
  change; pure memory-hygiene hardening.

- **Recipient password wrap now binds the KEM ciphertext and algorithm
  into the key derivation (wrap_version 3)** (post-v14 review LOW-3,
  gitlab#112, 2026-07-11): `PasswordWrapper` derived the per-recipient
  AES-256-GCM wrap key from the ML-KEM shared secret with a static HKDF
  info — the finding-#83 transcript binding covered only the main PQC data
  path. New asymmetric files wrap with
  `info = "openssl_encrypt.password_wrap.v3|" + kem_algorithm + "|ct=" +
  SHA256(encapsulated_key)` and record `wrap_version: 3` in the recipient
  entry (inside the signed metadata). Defense-in-depth: ML-KEM implicit
  rejection plus the GCM tag already defeat ciphertext substitution in
  practice. Fail-closed by construction — a marked entry never falls back
  to weaker derivations, stripping the marker derives the wrong key and
  fails the tag, and unknown marker values are rejected. **Every existing
  file keeps decrypting** (entries without the marker take the previous
  v2→v1 chain byte-for-byte, pinned by a pre-fix fixture file); note that
  asymmetric files written from this version on cannot be opened by older
  releases (clean unwrap error — same trade as the v14 default flip).

- **Keystore metadata version gates are now type-safe** (post-v14 review
  LOW-2, gitlab#111, 2026-07-11): the keystore integration read
  `format_version` from raw parsed JSON and compared it with `>=`, so a
  crafted file carrying a non-int value (`"4"`, `true`, `[]`) crashed the
  operation with an unhandled TypeError. Fail-closed either way (no
  bypass, key material never touched), but a crash is a one-operation DoS
  and an ugly failure mode. All six affected ingestion points in
  `keystore_wrapper.py`/`keystore_utils.py` now validate the type once via
  a shared helper and reject malformed metadata with the project's clean
  `ValidationError`. Legitimately written files always store an int —
  behavior for every valid file is unchanged.

- **v14 TLV KDF seed is built in a single allocation** (post-v14 review
  LOW-1, gitlab#110, 2026-07-11): `_v14_seed_encode` previously grew its
  buffer with incremental `bytearray +=`, so CPython reallocations could
  leave partial copies of the length-prefixed cleartext password in freed,
  unwiped heap memory — the caller's `secure_memzero` wipes only the final
  allocation — and its `bytes()` field conversion would materialize an
  unwipeable immutable copy of a mutable (bytearray/SecureBytes) secret.
  The seed is now written into one exact-size preallocated bytearray
  through memoryviews: no reallocation, no immutable copies (M2 [MEM-1]
  hygiene). Not exploitable on its own — hardening only; derived keys and
  the on-disk format are byte-identical, pinned by the cross-line golden
  vectors plus a new byte-identity test matrix covering mutable inputs.

- **format_version 14 is now the default write format — independent-XOR
  topology by default** (finding M2 Option A / M1, v14 implementation plan
  Phase 4, 2026-07-10): new encryptions without an explicit format version
  (CLI and library) now write `format_version 14` with independent-XOR key
  derivation — the parallel robust-combiner topology that stays as strong as
  its strongest component even if another KDF stage is broken — replacing
  the plain sequential cascade default (weakest-link floor per the KDF-chain
  research). Explicit sequential XOR (`--use-xor-composition`) stays a
  supported opt-in pinned at format_version 13; explicit format-version
  requests are honored unchanged. Streaming now writes v14 too (so streaming
  PQC files carry the #83 transcript binding); explicit v12 requests keep
  writing v12 and all v12 files keep decrypting. M1 is closed by
  construction: the independent scrypt component derives the full key length
  (64/128-byte keys for AES-SIV/Threefish are no longer funneled through a
  256-bit sequential intermediate on any v14 write path) — pinned by golden
  vectors, with a legacy vector guarding that the `< 14` sequential scrypt
  stage stays byte-identical. Rekey with `--independent-xor` targets v14;
  a plain rekey inherits the file's format version and normalizes the
  topology to independent-XOR (the recommended mode — the rekeyed file is
  self-consistent and gets a fresh key, so nothing breaks). All existing
  files decrypt unchanged (decrypt is metadata-driven).

- **format_version 14: KEM ciphertext transcript binding** (finding #83,
  v14 implementation plan Phase 3, 2026-07-10): for v12/v13 the PQC KEM
  symmetric key is HKDF(shared_secret) with only the algorithm name as
  domain separation — nothing binds the derived key to the KEM encapsulation
  ciphertext or the AEAD choice. At `format_version >= 14` the derivation
  binds the full transcript:
  `HKDF-SHA256(info = "openssl_encrypt.kem.v14|" + algorithm + "|" +
  encryption_data + "|ct=" + sha256(kem_ciphertext))` (info layout pinned
  for cross-line byte-identity). A missing ciphertext at v14 raises — no
  silent fallback. The legacy bare-SHA256 decrypt retry is scoped to
  v12/v13 only (no v14 file can carry a legacy key, so v14 fails after a
  single authenticated attempt). v12/v13 derivations are byte-identical to
  before.

- **format_version 14: length-prefixed (TLV) KDF seed** (finding #100,
  v14 implementation plan Phase 2, 2026-07-10): below v14 the
  independent-XOR key derivation seeds every component from
  `sha256(password || pepper || salt)` with the hardware pepper mixed by raw
  concatenation — so different (password, pepper, salt) splits of the same
  byte string derive the same key (boundary ambiguity; rated impractical to
  exploit since tool-generated salts have fixed length, but structurally
  unsound). Files at `format_version >= 14` seed from
  `sha256(LP(password) || LP(salt) || LP(pepper))` with
  `LP(x) = uint32_be(len(x)) || x` and an always-present pepper field
  (`_v14_seed_encode`, pinned for cross-line byte-identity). Everything
  below v14 derives byte-identically to before; nothing writes v14 by
  default yet.

- **v14 TLV seed hashed without an immutable copy** (crypto-reviewer v14
  series pass 2026-07-10, Low): the v14 TLV seed is now hashed through a
  `memoryview` of the seed `bytearray` instead of an immutable `bytes()`
  copy, so no unwipeable copy of the cleartext password+salt+pepper is
  materialized (M2 [MEM-1] hygiene; derived keys are byte-identical —
  pinned by the cross-line golden vectors).

- **v14 KEM transcript binding: detection mechanism documented**
  (crypto-reviewer v14 series pass 2026-07-10, Low): `_derive_symmetric_key`
  now documents that the #83 transcript binding detects ciphertext/metadata
  substitution *via AEAD authentication* (wrong key → tag failure), not an
  explicit compare — so the binding requires the symmetric layer to remain
  an AEAD (all reachable PQC data ciphers are AEADs, incl. Threefish via
  CTR+Poly1305), guarding against a future non-authenticated data cipher
  silently voiding it.

- **Legacy KEM key-derivation decrypt retry — reads pre-1.4.8 PQC files**
  (finding #83 backport counterpart, v14 plan Phase 0, 2026-07-10): 1.4.x
  releases up to 1.4.7 derived every PQC KEM symmetric key as bare
  `sha256(shared_secret)`, while this line uses HKDF-SHA256 for
  `format_version >= 12` — so v12 (streaming) and v13 (Independent-XOR) PQC
  files written by those releases could not be decrypted here (confirmed
  empirically: InvalidTag). When HKDF-key authentication fails on a v12/v13
  PQC file, decryption now retries once with the legacy key (safe — the
  AEAD tag rejects wrong keys, and the legacy file population legitimately
  exists, so no new downgrade surface) and prints a re-encryption
  recommendation. Scoped structurally via the new `PQCAuthenticationError`
  (no error-string matching). Files below v12 and all non-PQC files derive
  byte-identically to before.


Follow-up security review (2026-07-07) — findings fixed with regression tests
and crypto-reviewer sign-off:

- **FIDO2/HSM pepper no longer printed in cleartext** (follow-up review #H1
  [HSM-1]): the `hsm fido2-test` command printed the full 32-byte derived
  hardware pepper as hex to stdout unconditionally — outside the
  `debug_secret()` redaction chokepoint, so it landed in scrollback/`script`/CI
  logs. The hex dump is removed (the length is still reported); the FIDO2 plugin
  already routed the pepper through `debug_secret()`, so this only closed a CLI
  inconsistency. *Note: this fix landed in `modules/hsm_cli.py`, which turned
  out not to be the frontend the `hsm` subcommand actually dispatches to — the
  reachable handlers were fixed under gitlab#121 (see the Security section
  above), so both frontends are clean as of this release.*
- **Plugin signature now covers the exact bytes that execute** (follow-up review
  #M1 [PLUGIN-2]): the loader verified a plugin's signature over one read while
  AST-scanning and executing others (verify-A / execute-B), and `exec_module`
  could run a cached `.pyc` never covered by the signature. `_validate_plugin_file`
  now reads the plugin once as raw bytes and threads that same buffer through the
  signature gate, the `sha256(raw)` pin, and `ast.parse(raw)`; `load_plugin`
  re-reads once, compares to the pin, and executes via `compile(raw)+exec` —
  killing the CRLF/BOM and `.pyc`-shadow discrepancies. Fail-closed on a missing
  pin for non-built-ins.
- **Signed per-package plugin manifest closes the sibling-coverage gap**
  (follow-up review #H2 [PLUGIN-1]): a package plugin's signed `__init__.py`
  transitively imported sibling modules that were never signature/AST/hash-checked,
  so a benign signed `__init__.py` plus a malicious unsigned `helper.py` executed
  unchecked. A signed `PLUGIN.manifest` now covers **every** importable module
  under the package (source `.py`, bytecode `.pyc`, native `.so`/`.pyd`,
  recursively incl. underscore/nested) with one detached `.asc`; under `enforce`
  a tampered/unlisted/native-swapped/impostor-signed sibling is refused, `warn`
  warns and loads, built-in packages keep the trust shortcut. `plugin sign`
  auto-detects a package and writes the manifest. (A runtime import-hook for the
  validation→import TOCTOU window remains a documented follow-on.)
- **Key material is now actually wiped at plugin/KDF call sites** (follow-up
  review #M2 [MEM-1]): several callers wrapped an immutable `bytes` secret in
  `bytearray(...)` and called `secure_memzero` on the throwaway copy — zeroing a
  copy while the real secret lingered in unlocked heap (the exact M10 anti-pattern,
  reintroduced at callers in `parallel_kdf.py`, `asymmetric_core.py`, `pqc.py`,
  `crypt_core.py`). Each secret is now held in a `bytearray`/`SecureBytes` from
  creation and that object is wiped.
- **Parallel and sequential Independent-XOR now derive the same key** (follow-up
  review #M3 [KDF-1]): for Argon2 with `rounds > 1` the parallel KDF path and the
  sequential path produced different keys, so a file encrypted under one and
  decrypted under the other failed to authenticate. The parallel worker now
  matches the sequential derivation exactly.
- **RandomX now fails closed in the parallel Independent-XOR path** (follow-up
  review #R1 [KDF-2b]): a RandomX failure in the parallel path was swallowed and
  the derivation continued (fail-open), unlike the sequential path which fails
  closed. Both paths now fail closed.
- **Streaming per-chunk AEAD auth failures classified structurally** (follow-up
  review #M4 [STREAM-1]): a per-chunk authentication failure during streaming
  decryption was detected by substring-matching the exception text, which could
  misclassify an integrity failure. Classification is now structural.

- **Debug logs no longer leak a KDF key intermediate** (audit 2026-07-06 #2):
  the per-round Argon2/Balloon/Scrypt debug lines printed `round_salt` as raw
  hex, and for `format_version >= 7` rounds ≥ 1 that "salt" is the first 128 bits
  of the live derived-key chain. Under plain `--debug` this leaked key material
  outside the `debug_secret()` redaction chokepoint; it is now redacted by
  default (cleartext only under `--debug --unsafe-show-secrets`).
- **New files are no longer written in the cost-bypassing v8/v10 format** (audit
  2026-07-06 #3): the v8/v10 sequential-XOR derivation appended the chain's final
  value twice, cancelling the last KDF stage so an Argon2-only config collapsed
  to ~`SHA256(password‖salt)`. `encrypt_file` now defaults to `format_version=9`
  (the secure chained-salt format) and **refuses to encrypt** new v8/v10 files —
  the refusal is raised before any directory archiving or temp file is created,
  so a refused request leaves no cleartext artifact on disk. Decryption of
  existing v8/v10 files is unaffected; a library-only `allow_insecure_legacy_xor`
  escape hatch exists for legacy-fixture tests. `rekey` transparently upgrades an
  inherited v8/v10 file to v9 — including the envelope fast-path, which no longer
  re-emits a legacy file verbatim — so rekey is a real migration off the weak
  derivation. The envelope rekey fast-path now accepts every version envelope
  writes (v9/v11/v12/v13). The unsafe version set lives in a single shared
  constant so the refusal, the rekey upgrade, and the fast-path exclusion cannot
  drift apart.
- **Format version 13 — Independent XOR with per-component domain-separated
  salts** (now the **default** for Independent XOR; non-breaking): the Independent
  XOR key derivation (v11) fed every hash/KDF component the *same* `salt_0`, so two
  components that were the same function with identical parameters could XOR to
  zero (cancellation). v13 derives a distinct
  `HKDF-SHA256(salt_0, info="openssl_encrypt.indep-xor.v13.salt:" + name)` salt per
  component, retiring the footgun while keeping the robust-combiner (strongest-link)
  guarantee. **`--independent-xor`, the STANDARD/PARANOID templates, and rekey now
  write v13**; v11 remains fully supported for **decryption** (append-only). Files
  `< 13` decrypt unchanged; v13 is byte-identical across the 1.4.x and 1.5.x lines
  (pinned by a cross-line golden vector). v13 uses the sequential derivation, so
  `--parallel-kdf` falls back to sequential for v13 (with a notice).
- **Sequential XOR last-stage cancellation fixed (KDF cost bypass)** — ADVISORY
  2026-02: in sequential XOR (`--xor`, `format_version 8`/`10`) the chain's final
  value was XOR'd into the key *in addition to* the last stage's own snapshot,
  which are equal — so they cancelled and the **last stage dropped out of the
  key**. For Argon2-only (Argon2 is last) the key reduced to the cheap **initial**
  `SHA256(pw+salt)` computed before the chain (the original password/salt, not the
  derived values), bypassing the configured Argon2 cost. `--xor` now writes
  **format_version 13** (`xor_mode: "sequential"`) with the redundant append
  removed, so every stage contributes. Existing v8/v10 files still decrypt
  (derivation preserved) but are weak until re-encrypted. v13 routes XOR mode by
  the on-disk `xor_mode` field (independent vs sequential), not the version.
- **Cascade + streaming per-chunk nonce reuse fixed**: streaming encryption of
  a `cascade` chain reused a single cascade salt for every chunk. Because each
  cascade layer derives its key *and* AEAD nonce from `(master_key, salt)`, this
  reused the per-layer nonce across all chunks — catastrophic AEAD nonce reuse
  (a confidentiality/integrity break) for multi-chunk cascade streaming files
  (format v12). Each chunk now derives a unique cascade salt via HKDF
  (`oesc-cascade-chunk-salt`), recorded as `streaming.cascade_nonce_scheme = 2`
  in metadata. Files written before the fix lack the flag, are read as the
  legacy scheme (1) for backward compatibility, and emit a security warning
  urging re-encryption (rekey). Non-cascade streaming was unaffected (it already
  derived a unique per-chunk nonce). Covered by new adversarial and legacy-read
  tests in `test_streaming.py`.

Security-review findings (SECURITY_REVIEW_FINDINGS.md) fixed and ported to
the 1.5 branch:

- **Keystore integrity — authenticated v2 keystore format (H4)**: the
  keystore previously stored everything except wrapped private keys as
  cleartext, unauthenticated JSON, so anyone with write access could swap
  a stored public key, repoint per-algorithm defaults or delete entries
  undetected. v2 authenticates the entire structure with HMAC-SHA256 over
  canonical JSON, keyed by a domain-separated subkey of the master key;
  any mismatch fails closed with `KeystoreIntegrityError`. Legacy v1
  keystores load with a warning and auto-upgrade to v2 on the next save.
  A regression test proves the store-level MAC also neutralizes the
  blob-move attack (M6).
- **PQC algorithm resolution fails closed (H3)**: `PQCipher` no longer
  silently falls back to the weakest available KEM when a requested
  algorithm cannot be resolved (e.g. ML-KEM-1024 on a build lacking it, or
  a typo) — it raises `ValueError` listing the available algorithms.
  Legacy Kyber names still normalize to ML-KEM at the *same* security
  level.
- **Portable USB drives use a unique per-drive KDF salt (H5)**: master-key
  derivation previously used one global hardcoded salt for every drive,
  enabling a single precomputed dictionary against all drives. New drives
  generate a random 32-byte salt (`config/salt.bin`); pre-existing drives
  transparently fall back to the legacy salt and remain verifiable.
- **Plugin sandbox hardening (H8)**: file/network/process restrictions are
  now enforced on the default process-isolation path (previously only in
  legacy threading mode — a plugin without file capability could still
  read arbitrary files); the AST denylist closes the
  frame/traceback escape chain (`__traceback__` → `f_back` → `f_globals`);
  plugins in group/world-writable files or directories are rejected.
- **Balloon KDF memory-hard default (M3)**: on the v11 independent-XOR
  path an enabled Balloon with no explicit `space_cost` silently fell back
  to a ~512-byte buffer (GPU-trivial) and the value was not persisted.
  A memory-hard default is now applied and persisted at encrypt time;
  explicitly low values trigger a warning. Legacy files stay decryptable.
- **Weak dual-encryption password verifier removed (M7)**: dual-encrypted
  files no longer store a 10,000-iteration PBKDF2 hash of the file
  password in cleartext metadata (an offline brute-force oracle). The
  AES-GCM tag already authenticates the password; legacy files carrying
  the verifier are still honoured.
- **Identity TOFU key-change detection (M8)**: re-importing a contact
  whose key fingerprint changed now raises `IdentityKeyChangedError` even
  with `overwrite=True` (replacing a pinned key requires the explicit
  `allow_key_change=True`); fingerprint lookup now requires a full match
  instead of `startswith()` (an empty prefix used to resolve to the first
  stored identity).
- **Honest secure-memory contract (M10/M10a)**: `secure_memzero` no longer
  falsely reports success after zeroing a *copy* of immutable input — it
  returns `False` for `bytes`/`str` (new `strict=True` raises), and wipes
  in place for mutable buffers. The KDF registry password wipe, which
  never actually ran due to an always-false condition, is now effective
  and copy-free across all backends.
- **Metadata schema validation fails closed (M11)**: unknown
  `format_version` values are now rejected instead of skipping
  per-version schema validation; schemas are registered dynamically from
  disk (the shipped v9/v12 schemas were never registered and silently
  unused). The `encryption.algorithm` field in v9/v12 schemas was relaxed
  to a string — the cipher registry is the fail-closed boundary for
  algorithm names (H3), the schema's role is structural/DoS validation.
- D-Bus per-caller authorization (H7+L8) also landed during this cycle
  and was subsequently superseded by the removal of the entire D-Bus
  subsystem (see Removed).
- OnlyKey plugin: no changes to the cryptographic core. It reuses
  yubikit's `YubiOtpSession.calculate_hmac_sha1`; the only difference
  vs the YubiKey plugin is USB device enumeration (additional VID/PID
  filter). Existing YubiKey-encrypted files and YubiKey-protected
  identities are bit-identical and unaffected.

### Internal

- **Completed plan documents removed from `docs/`** (plan-tracker
  verification 2026-07-13): `XCHACHA_192BIT_PLAN.md`,
  `PBKDF2_CHAIN_ERROR_PLAN.md`, `V14_REVIEW_LOW_FIX_PLAN.md`,
  `SECURITY_REVIEW_RESIDUALS_2026-07-13_PLAN.md`, and the two v14 format
  documents `FORMAT_V14_PLAN.md` / `FORMAT_V14_IMPLEMENTATION_PLAN.md`
  (v14 fully rolled out on both lines; the spec and scope-correction
  rationale stay recoverable via git history) — all steps verified
  implemented in code before removal. Also removed `docs/announcements/`
  (the published 1.4.7 LinkedIn announcement text).

- **`KDF_CHAIN_SECURITY_RESEARCH.md` ported from the 1.4.x line** into the
  package documentation (`openssl_encrypt/docs/`, byte-identical): the
  literature review behind the independent-XOR-by-default design decision
  was previously missing from this branch entirely.

- **Test-collection regression fixed**: `pytest.ini` (added 2025-12-30)
  silently stopped collecting `unittests/unittests.py` — 91 tests across
  12 classes had not run in any suite invocation since. Collection is
  restored and everything that surfaced was repaired, including a
  module-level `warnings.warn` monkeypatch that leaked into co-resident
  workers and broke later `pytest.warns()` assertions.
- No new Python dependencies. The `onlykey` PyPI package is **not**
  required — HMAC-SHA1 is performed via yubikit (already pulled in
  via `yubikey-manager`).
- ~200 new unit tests across `test_onlykey_plugin.py`,
  `test_onlykey_cli.py`, `test_onlykey_identity_protection.py`,
  `test_cr_cross_backend_determinism.py`, and `test_yubikey_plugin.py`;
  new security-fix suites `test_keystore_integrity.py`,
  `test_plugin_sandbox_h8.py`, `test_identity_tofu_m8.py`,
  `test_balloon_defaults_m3.py`, `test_kdf_wipe_m10a.py`,
  `test_secure_memzero_m10.py`, `test_metadata_schema_m11.py` and
  `test_portable_media.py` additions.
- **Envelope + cascade + XChaCha regression test**: `test_envelope_encryption.py`
  pins the three-feature combination — envelope mode over a `cascade` chain
  containing `xchacha20-poly1305` round-trips, the `wrapped_dek` is present, and
  the cascade layer uses real 192-bit nonces (`xchacha_nonce_format == 2`).
  Existing cascade coverage exercised `chacha20-poly1305` only, so this guards
  against either feature silently degrading when xchacha is combined with the
  envelope DEK-wrap.

## [1.4.3] - 2026-03-30

### Fixed

- **Flutter GUI launcher in Flatpak**: Corrected binary name in wrapper script (`openssl_encrypt_mobile` → `openssl_encrypt`) so `--gui` flag works correctly
- **GTK window title**: Changed window title from `openssl_encrypt_mobile` to `OpenSSL Encrypt`

## [1.4.2] - 2026-03-29

### Added

- **Simple/Pro mode for desktop GUI**: New default "Simple" mode hides all advanced crypto options, showing only Encrypt, Decrypt, and Settings tabs. Uses CLI `--standard` template automatically. Pro mode toggle in Settings restores full UI with all algorithms, KDFs, cascade, steganography, and identity management
- **Independent XOR (v11) as default key derivation**: STANDARD and PARANOID templates now automatically enable Independent XOR composition (a robust XOR-combiner) for stronger key derivation security guarantees
- **RandomX support in independent XOR path**: RandomX KDF now works correctly in both parallel and non-parallel v11 key derivation paths
- **Progress bars for Argon2 and RandomX in XOR mode**: Multi-round KDF operations now display progress bars when using `--progress` flag in independent XOR (v11) mode

### Changed

- **STANDARD template modernized**: Hashes changed from sha3-256+sha3-512 to sha3-512+blake3 (10k rounds each). KDFs changed from scrypt+argon2 to randomx (10 rounds)+argon2 (10 rounds). Encryption upgraded from single-layer aes-gcm to cascade (aes-256-gcm + chacha20-poly1305)
- **Cascade encryption enabled by default**: STANDARD template now uses 2-layer cascade encryption (AES-256-GCM + ChaCha20-Poly1305) for defense-in-depth

### Security

- **Dependency bumps**: cryptography 46.0.5→46.0.6, requests 2.32.5→2.33.0, black 24.10.0→26.3.1, nltk 3.9.3→3.9.4

## [1.4.1rc2] - 2026-03-22

### Security

- **Dependency bump: nltk to 3.9.3**: Resolves CVE-2026-33236, CVE-2026-33231, CVE-2026-33230, GHSA-rf74-v2fm-23pw

## [1.4.1rc1] - 2026-03-21

### Added

- **Streaming chunked encryption (format v12)**: Large files now encrypted in authenticated chunks with configurable chunk size, enabling constant-memory operation, per-chunk integrity verification, and efficient handling of multi-gigabyte files
- **`--info` CLI action**: Display metadata about an encrypted file (format version, algorithms, `encrypted_at` timestamp) without decrypting
- **`encrypted_at` timestamp**: Metadata now records encryption time for auditing purposes
- **Windows compatibility**: Full Windows support backported from v1.5.x including NTFS ACL-based file permissions, UTF-8 encoding fixes across all file I/O, and an automated Whirlpool build step for Windows
- **Cross-platform `tty_write`/`tty_clear_line` helpers**: Interactive terminal prompts (YubiKey touch, password clear) now bypass stdout/stderr redirection by writing directly to `/dev/tty` on Unix or `msvcrt` on Windows, with emoji-safe fallback for Windows consoles
- **Stderr output separation**: All status, progress, and diagnostic output now goes to stderr via `eprint()`. Redirecting with `2>/dev/null` correctly suppresses all non-data output without affecting the decrypted content on stdout

### Security

- **Key zeroization in streaming/cascade/crypt_core**: All derived intermediate keys zeroed via `SecureBytes`/`secure_memzero` immediately after use
- **HKDF for keystore password wrap key**: Replaced bare SHA-256 with HKDF for deriving the keystore password wrap key
- **HKDF for streaming HMAC key** (v12+): Per-encryption HMAC key derived via HKDF rather than direct KDF output
- **Per-layer salt and AAD for cascade** (v12+): Each cascade layer receives an independently derived salt; all layers bound to the ciphertext via AAD (H6/H7/M12)
- **HKDF for pepper and PQC signature keys** (v12+): Pepper and PQC signature keys derived via HKDF with `format_version` wired through the derivation context (M15/M18/C2)
- **PQC signature HKDF salt pre-bound**: Salt generated before AEAD metadata construction, binding it into the ciphertext and preventing post-encryption metadata modification attacks
- **Per-chunk nonce bound into cascade**: Streaming chunk nonces passed to each cascade layer, preventing cross-chunk nonce reuse
- **Chunk count validation**: Streaming decryptor validates `chunk_count` from metadata against actual payload size, preventing truncation attacks
- **Format version integer validation**: `decrypt_file()` now rejects non-integer `format_version` values in metadata
- **Keystore Argon2id fallback warning**: User is warned when keystore falls back from Argon2id to PBKDF2
- **Plugin sandbox hardening**: Blocked `marshal` and `codecs` modules; blocked `__dict__`, `__func__`, `__self__` attribute access; added detection of string concatenation building dangerous names; added TOCTOU mitigation for plugin file validation; fixed TOCTOU race in symlink check; hardened AST analyzer against additional bypass vectors (PL-4/PL-5/PL-6/H8/H9/H10)
- **Plugin execution serialization**: Threading-mode plugins execute under a lock, preventing race conditions in concurrent usage
- **Algorithm registries frozen after init**: Algorithm registries are made immutable after initialization, preventing runtime tampering (M9/M13)
- **HSM pepper cache as bytearray**: Cached pepper stored as `bytearray` to allow effective memory zeroing
- **PQCKeystore context manager**: Added `close()` and `__exit__` to zero keys on teardown
- **Identity private key AAD binding**: Identity private key encryption now includes AAD for ciphertext binding
- **Identity import fingerprint verification**: Fingerprint verified on identity import to detect tampering; identity names validated against path traversal (M5/H1/H2)
- **Restrictive file permissions**: Keystore files set to `0o600`; pepper config directory `0o700`, pepper config file `0o600`; keystore dual encryption now includes AAD (M1/M20)
- **KeyStretch state reset**: Mutable class-level state reset at the start of each encrypt/decrypt operation to prevent cross-call state leakage
- **PluginResult sensitive key filtering**: Sensitive keys stripped in `PluginResult` constructor (M10)
- **PluginSecurityContext immutable capabilities**: `capabilities` stored as `frozenset` to prevent runtime mutation
- **HTTPS enforcement in keyserver**: `register()` enforces HTTPS for keyserver URL (PL-8)
- **Server secrets hardening**: Removed insecure default token secrets from server config (SV-2)
- **Dependency security**: Bumped `authlib` to 1.6.9, `python-jose` to 3.4.0, `cryptography` to ≥46.0.5

### Performance

- **Incremental metadata reads for v12**: `_read_metadata_only()` uses 8KB incremental reads to locate the metadata separator, avoiding loading the full file into memory before decryption begins
- **Bounded streaming decrypt**: `decrypt_file()` in streaming.py uses bounded reads instead of a single `fin.read()`, keeping memory usage proportional to chunk size regardless of file size

### Changed

- **`eprint()` replaces `print()` for all non-data output**: ~1,500 call sites across all modules now route to stderr by default, making it safe to capture stdout for scripting and automation

## [1.4.0] - 2026-03-03

### Security

- **Plaintext never touches disk during rekey**: `rekey_file()` no longer writes decrypted plaintext to a temporary file. Plaintext is passed directly as bytes to `encrypt_file()`, eliminating the filesystem race window where plaintext was briefly visible (even with 0o600 permissions) and potentially recoverable on journaling filesystems or SSDs with wear leveling.

### Added

- **In-memory encryption API**: `encrypt_file()` now accepts `bytes`/`bytearray` as `input_file` and `None` as `output_file`, mirroring the pattern `decrypt_file()` already uses. When `output_file=None`, returns encrypted data as bytes instead of writing to disk.
- **Input validation for bytes mode**: Clear `ValidationError` when auto-generated pepper is used with bytes input (requires `--pepper-name`). Integrity plugin gracefully skipped with warning when input is bytes.
- **New test file**: `test_encrypt_bytes.py` with 15 tests covering bytes input, bytes output, full in-memory roundtrip, and input validation.
- **Rekey no-temp-plaintext tests**: 4 new tests in `test_rekey.py` verifying no `.rekey_plain_*` files are created during rekey operations.

### Changed

- **`encrypt_file()` signature**: `input_file` now accepts `Union[str, bytes, bytearray]`, `output_file` accepts `Optional[str]`, returns `Union[bool, bytes]`.
- **`rekey_file()` simplified**: Removed temp plaintext file creation (`mkstemp`/`fchmod`/`write`/`close` block), secure zero-fill cleanup, and `temp_plaintext_path` variable. Memory cleanup of plaintext data now happens after `encrypt_file()` returns.
- **Post-processing plugins**: Skipped when `output_file is None` (no file to post-process).
- **Test coverage**: 1636+ tests passing.

## [1.4.0rc2] - 2026-02-27

### Added

- **Rekey action**: Added `--rekey` CLI action to re-encrypt files with a new password

### Fixed

- **SAST rules**: Relaxed AST security scan for built-in plugins (GHSA-9pgj-v69p-q586 follow-up)

## [1.4.0rc1] - 2026-02-26

### Security

- **CSPRNG for Steganography**: Replaced non-cryptographic random with HMAC-SHA256 CSPRNG (GHSA-vfgx-5q85-58q3)
- **HKDF Salt Parameter**: Added salt parameter to HKDF key derivation (GHSA-j9mh-57cc-665x)
- **Standard PBKDF2 Fallback**: Use standard PBKDF2 for new encryptions in fallback path (GHSA-743f-89fg-x288)
- **Sandbox Bypass Prevention**: Block pathlib/io sandbox bypass for file operations (GHSA-mcjj-qw7m-j3cp)
- **Import Guard Sync**: Synchronized import guard and AST analyzer blocked module lists (GHSA-9pgj-v69p-q586)
- **Path Traversal Sanitization**: Sanitize plugin_id to prevent path traversal (GHSA-8jpj-w975-rwv5)
- **Thread-Safe Module Hiding**: Fixed restore_hidden_modules() logging and thread safety (GHSA-43r4-3hf9-m84q)
- **CORS Default Hardening**: Changed CORS default from wildcard to empty list (GHSA-c65f-x25w-62jv)
- **Trusted Proxy Restriction**: Restricted default trusted proxies to localhost (GHSA-2592-7m3g-7fq6)
- **DB Error Masking**: Stopped leaking DB errors in readiness endpoint (GHSA-2vhw-q7vh-7xv2)
- **Refresh Token Security**: Moved refresh token from query params to POST body (GHSA-4rh7-jwg9-m28m)
- **Key Bundle Verification**: Verify key bundle signature on deserialization (GHSA-8h88-gxp3-j7pg)
- **TOTP Rate Limiter**: Added pluggable backend for TOTP rate limiter (GHSA-h45m-mgcp-q388)
- **SO Path Validation**: Validated .so file paths before loading (GHSA-j48q-4c78-rhf9)
- **Password File Support**: Added --password-file/--password-fd, deprecated --password (GHSA-h3m5-p59h-x88p)
- **Schema Validation**: Raise error when jsonschema unavailable instead of silently passing (GHSA-425g-fjhq-5h92)

### Changed

- Bumped dependencies to fix 8 Dependabot alerts

## [1.4.0b10] - 2026-01-11

### Added

- **Format Version 11: Independent XOR Key Derivation (robust XOR-combiner)**
  - **New Cryptographic Approach**: Implements Independent XOR composition (robust XOR-combiner; Herzberg, HKNRR) where each hash/KDF algorithm processes the same original input (password + salt), and outputs are XOR'd together
  - **Security Guarantee**: Provides "strongest component" security - the derived key is at least as secure as the strongest constituent algorithm, even if all others are compromised
  - **CLI Flag**: New `--independent-xor` flag enables v11 format with Independent XOR composition
  - **Distinction from v10**: Unlike v10 sequential XOR (chains algorithms for anti-parallelization), v11 processes all algorithms independently for maximum cryptographic assurance
  - **Use Cases**: Ideal for scenarios requiring maximum cryptographic confidence and resistance against future algorithm breaks
  - **Initial Normalization**: Adds initial SHA-256 hash of input for defense-in-depth and consistent input normalization
  - **Backward Compatibility**: Files encrypted with v11 format require openssl_encrypt 1.4.0b10+ to decrypt
  - **Cross-Branch Compatibility**: v11 format is compatible with v9 format in the 1.3.x branch

- **Parallel KDF Processing for Performance Optimization**
  - **Multiprocessing Support**: Optional parallel execution of hash algorithms and KDFs using ProcessPoolExecutor
  - **Performance Improvement**: ~2.7x speedup with 8 algorithms on 8-core CPU (sequential: ~8.5s → parallel: ~3.1s)
  - **CLI Flags**:
    - `--parallel-kdf`: Enable parallel processing for key derivation (requires `--independent-xor`)
    - `--kdf-workers N`: Specify number of parallel workers (default: auto-detect based on CPU count)
  - **Progress Reporting**: Queue-based progress aggregation with unified display showing active workers and completion percentage
  - **GUI Integration**: Added parallel KDF progress regex pattern for GUI progress bar support
  - **Key Consistency**: Parallel and sequential modes produce identical keys through deterministic XOR ordering
  - **GIL Bypass**: Uses multiprocessing instead of threading for true CPU parallelism on compute-bound operations

- **New Metadata Schema**: `metadata_v11_schema.json` with `xor_mode` field to distinguish Independent XOR (v11) from Sequential XOR (v10)

- **Comprehensive Test Coverage**:
  - 7 new v11 Independent XOR tests covering basic operations, cross-compatibility, and various encryption algorithms
  - 11 new parallel KDF tests for key consistency, round-trip encryption, worker configuration, and error handling
  - Total: 1573 tests passing (up from 1535)

### Changed

- **Key Derivation Architecture**: v11 format bypasses `generate_key()` function, directly calling `generate_key_independent_xor()` or `generate_key_independent_xor_parallel()` in `encrypt_file()` and `decrypt_file()`
- **Hash Config Handling**: Added automatic flattening of nested hash config structures for v11 metadata creation
- **Format Version Support**: Updated decrypt path to recognize format version 11 in 5 key locations for proper metadata extraction and key derivation

### Performance

- **Sequential v11**: Baseline performance equivalent to v10 (~8.5s for 8 algorithms)
- **Parallel v11**: ~2.7x faster than sequential on 8-core systems (~3.1s for 8 algorithms)
- **Scalability**: Performance scales with CPU core count and number of enabled algorithms
- **Bottleneck**: Slowest algorithm determines parallel mode completion time

## [1.4.0b9] - 2026-01-09

### Fixed

- **Test Infrastructure**: Fixed 6 salt derivation test failures by correcting test suite to use `generate_key()` instead of `multi_hash_password()` for KDF operations
  - **Root Cause**: Tests were calling `multi_hash_password()` with KDF configs (Scrypt, Argon2, PBKDF2, Balloon), but that function only handles regular hash algorithms (SHA-512, BLAKE2b, etc.). KDFs are processed in `generate_key()`
  - **Resolution**: Updated all test calls to use `generate_key()` with proper algorithm parameter
  - **Impact**: All 1535 tests now passing, 0 failures (up from 1532 passed, 6 failed)
  - **Validation**: Format Version 9 security model validated across all KDF algorithms

- **Threefish Cipher Support**: Completed Threefish-512/1024 cipher implementation with HKDF key expansion and proper AEAD integration
  - Added Threefish to `AEAD_ALGORITHMS` list for proper AAD support
  - Fixed nonce size handling in `get_nonce_size()` function
  - Resolved AAD variable handling in Threefish decryption

- **BLAKE3 Buffer Compatibility**: Fixed BLAKE3 buffer sizing for backward compatibility with pre-BLAKE3 encrypted files
  - Enhanced buffer allocation logic to handle files encrypted before BLAKE3 support
  - Zero-initialization for deterministic BLAKE3 keyed hashing

- **Metadata Schema Compatibility**: Made 'mode' field optional in metadata v7 schema for v1.3.4 backward compatibility

- **Type Conversions**:
  - Fixed Scrypt bytearray to bytes conversion in salt derivation
  - Resolved SecureBytes slice handling in XChaCha20 nonce operations

### Changed

- **Test Suite Quality**: Improved test infrastructure and validation
  - 1535 tests passing, 0 failures
  - Format Version 9 validated across PBKDF2, Argon2, Scrypt, Balloon
  - Enhanced cross-version compatibility testing

- **Debug Logging**: Enhanced debug logging for version-aware salt derivation decisions
  - Added logging at KDF function entry points
  - Salt derivation branch logging (SECURE vs PREDICTABLE)

## [1.4.0b8] - 2026-01-08

### 🚨 CRITICAL SECURITY FIX

- **Format Version 9 Implementation**: Implemented secure chained salt derivation for v1.4.x branch
  - **Vulnerability**: Same as v1.3.4 fix (CVSSv3 8.1 HIGH) - predictable salt derivation in multi-round KDF
  - **Resolution**: Unified security model where v7 and v9 use secure chained derivation, v8 uses predictable (backward compatibility only)
  - **Implementation**: Each round uses previous round's output as salt, preventing precomputation attacks
  - **Affected**: All multi-round KDF/hash operations (BLAKE2b, BLAKE3, SHAKE-256, Argon2, Scrypt, Balloon, PBKDF2, HKDF)

### Fixed

- **Pepper Plugin**: Fixed critical scoping errors causing 100+ test failures
  - Resolved variable scoping issues in pepper plugin implementation
  - Fixed HSM plugin loading and dependency management

### Added

- **Flatpak CI/CD**: Added comprehensive Flatpak CI/CD pipeline
  - `flatpak-build`: Regular cached build job
  - `flatpak-build:clean`: Manual clean build without cache
  - `flatpak-publish`: Publish to Flatpak repository
  - `flatpak-publish:clean`: Clean publish from scratch
  - Build and publish stages integrated into GitLab CI

- **Flutter GUI Enhancements**:
  - Remote pepper plugin integration
  - Integrity verification UI
  - Cascade encryption configuration UI
  - Asymmetric encryption configuration
  - YubiKey touch prompt improvements

## [1.3.5] - 2026-01-09

### Fixed

- **BLAKE3 Keyed Hashing Integration**: Fixed BLAKE3 hash algorithm support with proper 32-byte key handling for Format Version 7
  - **Issue**: BLAKE3 was not properly integrated for keyed hashing operations
  - **Resolution**: Implemented BLAKE3-aware buffer sizing with 64-byte minimum allocation
  - **Impact**: BLAKE3 now fully functional. No regression with existing files as BLAKE3 was not used before this bugfix
  - **Compatibility**: Files encrypted with v1.3.5 using BLAKE3 maintain forward compatibility with v1.4.x

- **Metadata Schema Compatibility**: Made 'mode' field optional in metadata v7 schema for v1.3.4 backward compatibility
- **Scrypt Salt Handling**: Fixed bytearray to bytes conversion in Scrypt salt derivation
- **XChaCha20 Nonce Processing**: Resolved SecureBytes slice handling in XChaCha20 nonce operations

### Added

- **Build Tooling**: Comprehensive build scripts for liboqs dependencies
  - `scripts/build_local_deps.sh`: Automated dependency building with version verification
  - `scripts/cleanup_liboqs.sh`: Clean removal of locally built dependencies
  - Environment variable support for custom installation paths

- **CI/CD Infrastructure**: Backported Flatpak build and publish jobs from v1.4.x
  - Automated Flatpak packaging on release branches
  - Clean build jobs for testing without cache

- **Debug Logging**: Enhanced BLAKE3 operation logging for troubleshooting

### Changed

- **Cross-Version Compatibility**: Files encrypted with v1.3.5 are fully compatible with v1.4.x
- **Format Version 7**: Maintains secure chained salt derivation from v1.3.4

## [1.3.4] - 2026-01-07

### Security

- **CRITICAL: Fixed Predictable Salt Derivation in Multi-Round KDF (CVSSv3 8.1 - High)**
  - **CWE-330: Use of Insufficiently Random Values**
  - **Vulnerability**: Multi-round KDF used predictable salt derivation allowing precomputation attacks
  - **Resolution**: Implemented Format Version 7 with secure chained salt derivation
  - **Affected**: BLAKE2b, BLAKE3, SHAKE-256, Argon2, Scrypt, Balloon, PBKDF2, HKDF (multi-round)
  - **Backward Compatibility**: Full backward compatibility maintained (Format Versions 3-6)
  - **Forward Compatibility**: Files encrypted with Format Version 7 require v1.3.4+

### Fixed

- **Test Infrastructure**: Fixed pytest-xdist enum serialization issues
- **Keystore Integration**: Updated keystore to recognize Format Version 7

## [1.3.3] - 2026-01-06

### Changed

- **License Compliance**: Updated license from MIT to Hippocratic License 3.0
  - Fixed Flatpak metainfo.xml project_license field
  - Added explicit license field to setup.py
  - Repository-wide license standardization
  - No functional changes to cryptographic operations

## [1.3.2] - 2025-12-20

### Added

- **Decryption Cost Estimation**: Comprehensive time/memory estimation to prevent DoS attacks
  - Static benchmark data for all hash and KDF algorithms
  - Pre-decryption cost display with 2-second cancellation window
  - `--no-estimate` CLI flag for trusted files

### Fixed

- **CLI Argument Parsing**: Fixed `--no-estimate` flag compatibility with `--progress`
  - Enhanced subcommand detection after global flag preprocessing

## [1.3.1] - 2025-12-18

### Security

- **HSM Security Fix**: Removed `--device=all` from Flatpak manifest
  - Requires explicit USB device opt-in for hardware security modules
  - Enhanced Flatpak permissions with explicit YubiKey/smart card access

### Fixed

- **PQC Key Storage**: Fixed post-quantum private key storage for AEAD algorithms
- **Flatpak Permissions**: Cleaned up invalid filesystem permissions

## [1.4.0] - 2026-03-03 (additional security-fix notes; see the consolidated [1.4.0] entry above)

### 🚨 CRITICAL SECURITY FIX

#### Format Version 9: Secure Chained Salt Derivation
**SECURITY ADVISORY 2026-01** - Addresses critical vulnerability in multi-round KDF salt derivation

- **Vulnerability (CVSSv3 8.1 - High)**: Format versions ≤8 used predictable salt derivation allowing attackers to precompute all round salts from plaintext metadata, enabling optimized rainbow table attacks
- **Fix**: Implemented secure chained salt derivation where each round uses previous round's output as salt
  - **Security Impact**: Forces sequential computation, prevents precomputation attacks
  - **Backward Compatible**: v8 and below files can still be decrypted
  - **Auto-Upgrade**: New encryptions automatically use v9
- **Affected Components**: All multi-round KDF configurations (Argon2, PBKDF2, Scrypt, Balloon, HKDF) and multi-round hash functions (BLAKE3, BLAKE2b, SHAKE-256)
- **Affected Users**: Files with multi-round KDF (rounds > 1), especially with weak/medium passwords
- **Mitigation**: Upgrade to v1.4.0+ and re-encrypt sensitive files
- **References**: See `docs/security.md` and `docs/metadata-formats.md` for complete security advisory

#### Format Version 7 and 9 Unification
**CRITICAL UPDATE** - Unified v7 (from v1.3.4 branch) and v9 (from v1.4.0 branch) implementations

- **Background**: The security fix was independently implemented in two branches:
  - **Version 7**: Introduced in v1.3.4 (releases/1.3.4 branch) with focus on asymmetric encryption
  - **Version 9**: Introduced in v1.4.0 (feature/v1.4.0-development) with multi-feature release
- **Unification**: Both versions now use identical secure chained salt derivation
  - Pattern: `if format_version >= 7 and format_version != 8:`
  - v7 and v9 produce cryptographically identical keys
  - v8 deliberately excluded for backward compatibility
- **Compatibility**: v1.4.0+ correctly decrypts both v7 and v9 files
- **Security**: Both v7 and v9 provide the same security improvements over v8 and below
- **Implementation**: Updated 9 salt derivation locations, 11 keystore integration points
- **Testing**: Comprehensive v7/v9 compatibility tests verify cryptographic equivalence

### Added

#### Flutter GUI Enhancements
- **Cascade Encryption UI**: Complete cascade encryption configuration interface across all crypto tabs
  - Sub-group headers and algorithm organization
  - Multiple cipher selection with diversity validation
  - Integrated into File Crypto, Text Crypto, and Batch Operations tabs
- **Asymmetric Encryption UI**: Full asymmetric encryption interface
  - Identity management screen with create/import/export
  - Recipient selection for multi-recipient encryption
  - HSM integration (YubiKey Challenge-Response)
  - Integrated into all crypto tabs
- **Remote Plugin Integration**: Network plugin configuration in Settings
  - **Remote Pepper Plugin**: mTLS authentication, TOTP 2FA, deadman switch, panic wipe
  - **Integrity Plugin**: File verification with batch support and audit logging
  - **Keyserver Plugin**: Public key distribution with local caching
- **FIDO2/WebAuthn Support**: HSM credential management with YubiKey touch prompts
  - Real-time touch prompt display (PYTHONUNBUFFERED)
  - Credential management screen
  - Integration across encryption/decryption tabs
- **Algorithm Support Additions**:
  - Threefish-512 and Threefish-1024 post-quantum ciphers
  - Enhanced algorithm picker with grouped display
  - PQC algorithms in Information Tab
  - Support for file format versions 7 and 8

#### CLI & Core Features
- **Integrity Verification Flags**: `--integrity` and `--verify-integrity` for remote metadata hash verification
  - Automatic file_id computation from input file path
  - 409 Conflict handling for re-encryption scenarios
  - Integration with remote integrity module via mTLS
- **Pepper Plugin Integration**: Full CLI integration for remote pepper storage
  - Command-line flags for pepper operations
  - TOTP 2FA support for sensitive operations
  - mTLS certificate-based authentication
- **Steganography Options**: Comprehensive steganography configuration in GUI encryption tab
- **Force Password Option**: Added to encryption and decryption tabs for password override scenarios

### Fixed

#### Critical Bug Fixes
- **Threefish Algorithm Support**: Complete implementation of Threefish-512 and Threefish-1024
  - Added key length support (64 bytes for TF-512, 128 bytes for TF-1024)
  - Implemented HKDF key expansion to derive required key lengths
  - Added proper nonce sizes (32 bytes for TF-512, 64 bytes for TF-1024)
  - Added encryption and decryption logic with AAD support
  - Fixed nonce size mapping in `get_nonce_size()` function
- **Pepper Plugin Scoping Errors**: Fixed critical scoping bugs causing 100+ test failures
  - Resolved variable scope issues in pepper client plugin
  - Fixed authentication and storage operations
- **Integrity Plugin Issues**:
  - Fixed 409 Conflict when re-encrypting files with `--integrity` flag
  - Corrected file_id computation to use input file path instead of output
  - Fixed integrity verification hang in Flutter GUI
- **YubiKey Integration**:
  - Fixed YubiKey notification display in GUI
  - Enabled real-time touch prompt display via PYTHONUNBUFFERED
  - Fixed status message overwrites that hid touch prompts
- **HSM Plugin Loading**: Fixed dependency management and plugin initialization

#### Flatpak Improvements
- **CI/CD Pipeline**: Complete Flatpak build and publish automation
  - Automated flatpak-builder with incremental caching
  - Branch-based flatpak branch naming (from setup.py version)
  - OSTree repository caching to avoid 413 errors
  - Restricted jobs to releases branches and tags only
- **Build System Enhancements**:
  - Proper FLATPAK_BRANCH environment variable respect
  - VERSION extraction from setup.py without setuptools import
  - Python dependencies properly declared in manifest
  - Flutter SDK and build dependencies (which, unzip, patchelf)
  - Docker compatibility flags (--disable-rofiles-fuse)
- **Binary Naming**: Corrected desktop binary from openssl_encrypt_mobile to openssl_encrypt
- **Dependency Fixes**: Added certifi and all missing Python dependencies from requirements-prod.txt

#### GUI Fixes
- **Information Tab**:
  - Fixed hash algorithm display (sha224, sha3-224, sha384 filters)
  - Added PQC algorithms to encryption display
- **Algorithm Picker**:
  - Restored missing hash algorithms
  - Fixed Classical Symmetric consolidation
  - Set PQC and other groups to collapsed by default
- **Settings**:
  - Updated Homepage URL to releases/1.4.0 branch
  - Corrected Documentation and Source Code links
  - Default input type changed to file mode

#### Documentation & Infrastructure
- **Security Documentation**: Added comprehensive SECURITY.md with vulnerability reporting policy
- **Installation Guide**: Complete rewrite of INSTALLATION.md with Flatpak integration
- **README Updates**: Installation section and project URL corrections
- **Markdown Fixes**: Corrected formatting in Flatpak documentation sections
- **Command Syntax**: Fixed to use `-i` flag consistently in all examples

### Changed

#### Infrastructure
- **liboqs Upgrade**: Upgraded to liboqs-python 0.12.0 built from source for HQC algorithm support
- **Project URLs**: Updated to GitHub repository in setup.py
- **Version Management**: Bump to 1.4.0 with PEP 440 / PyPI conformant version strings
- **License**: Explicit Hippocratic-3.0 license declaration in setup.py and Flatpak metadata

#### Development & Testing
- **Test Organization**: Consolidated asymmetric test files into main unittests.py
- **Plugin Security**: Refined AST-based plugin validation to allow legitimate file/network operations
- **Coverage**: Added missing CLI arguments to test coverage
- **Code Formatting**: Applied automated Black formatting fixes

### Deprecated

- **Format Version 8**: Deprecated due to security vulnerability (see SECURITY ADVISORY 2026-01)
  - Read support maintained for backward compatibility
  - Write support disabled (encryption creates v9 files only)
  - Deprecation warning issued when decrypting v8 files

### Security

- **Input Validation**: Added salt, key size, and hash iteration validation in `create_key_from_password`
- **Secure Memory**: Enhanced error handling in secure memory operations
- **Test Coverage**: Added comprehensive tests for salt derivation versions (v8 vs v9)
  - Multi-round KDF behavior tests (PBKDF2, Argon2, Scrypt)
  - Hash function multi-round tests (BLAKE3, BLAKE2b, SHAKE-256)
  - Backward compatibility verification
  - Full encryption/decryption roundtrip tests

## [1.4.0-alpha.1] - 2025-12-31

### Added

#### Infrastructure & Deployment
- **Post-Quantum Keyserver System**: FastAPI-based keyserver for public key distribution with ML-DSA signature verification, bearer token authentication, PostgreSQL backend, and Docker deployment support
  - Public key upload/search/revocation endpoints with authenticated operations
  - CORS configuration and rate limiting for production deployment
  - Plugin architecture supporting HSM integration and custom storage backends
  - Docker support with liboqs 0.12.0 including HQC algorithm support
  - Health check and monitoring endpoints
  - Deployed at: https://keyserver.rm-rf.ch

- **Privacy-Preserving Telemetry System**: Opt-in anonymous telemetry infrastructure with comprehensive privacy controls
  - Plugin-based architecture with configurable data collection
  - Client registration and anonymous usage metrics
  - PostgreSQL backend with FastAPI REST API
  - Docker deployment with automated database migrations
  - Privacy-first design with user consent and data minimization
  - Deployed at: https://telemetry.rm-rf.ch

- **Unified Server Architecture**: Modular FastAPI server with dual authentication system supporting both public and private modules
  - JWT authentication for public modules (keyserver, telemetry)
  - mTLS authentication with self-signed CA for private modules (pepper, integrity)
  - Module isolation with independent enable flags and configuration
  - Docker Compose deployment with PostgreSQL backend
  - Nginx reverse proxy support for production deployments

- **Pepper Module (mTLS-Protected)**: Secure pepper storage system for password hardening with TOTP 2FA
  - 20 REST API endpoints for pepper management
  - Client-side encrypted pepper storage (server stores encrypted blobs)
  - TOTP 2FA with QR code generation (pyotp integration)
  - Deadman switch with configurable check-in intervals and grace periods
  - Panic wipe for emergency pepper deletion (all or single pepper)
  - Auto-registration on first mTLS connection
  - 5 database tables: clients, peppers, deadman, panic_log, totp_backup_codes
  - Access tracking (last_accessed_at, access_count)
  - Fernet encryption for TOTP secrets at rest
  - Argon2 hashing for backup codes

- **Integrity Module (mTLS-Protected)**: Encrypted file metadata hash verification system
  - 12 REST API endpoints for hash management and verification
  - SHA-256 hash storage for encrypted file metadata
  - Integrity violation detection with comprehensive audit logging
  - Batch verification support (up to 100 files per request)
  - Statistics tracking (success rate, verification counts, last verification)
  - Auto-registration on first mTLS connection
  - 3 database tables: clients, metadata_hashes, verification_log
  - Tamper detection with detailed mismatch warnings
  - Support for multiple algorithm types (symmetric, hybrid, PQC)

- **mTLS Authentication Infrastructure**: Certificate-based authentication for pepper and integrity modules
  - Self-signed CA requirement (public CAs explicitly rejected)
  - Certificate fingerprint authentication (SHA-256)
  - Proxy mode: Nginx terminates mTLS, passes X-Client-Cert-Fingerprint header
  - Direct mTLS mode: Server terminates TLS on dedicated ports (8444, 8445)
  - Trusted proxy IP validation with configurable network ranges
  - Reusable auth handlers: ProxyAuth and MTLSAuth classes
  - Certificate DN extraction for client identification
  - Automatic certificate fingerprint normalization

- **Certificate Management Tools**: Automated scripts for self-signed CA and client certificate generation
  - `setup_ca.sh`: Create self-signed CA with passphrase-protected private key
  - `create_client_cert.sh`: Generate client certificates signed by CA
  - Certificate validity: 825 days (~2 years, Apple/Google recommended max)
  - Automated certificate bundle creation for distribution
  - SHA-256 fingerprint calculation and normalization
  - Comprehensive documentation in docs/MTLS_SETUP.md
  - Security best practices and troubleshooting guides
  - Scripts in openssl_encrypt_server/scripts/ directory

#### Client Plugins
- **Pepper Storage Plugin**: Client plugin for secure pepper storage with mTLS authentication
  - Client-side encrypted pepper storage (server never sees plaintext peppers)
  - mTLS authentication with client certificates
  - TOTP 2FA integration for destructive operations
  - Deadman switch with configurable check-in intervals
  - Panic wipe functionality (all or single pepper)
  - Profile management with access tracking
  - Configuration: `~/.openssl_encrypt/plugins/pepper.json`
  - OPT-IN by default (enabled=false)
  - Python API: `from openssl_encrypt.plugins.pepper import PepperPlugin, PepperConfig`

- **Integrity Verification Plugin**: Client plugin for encrypted file metadata hash verification
  - Store SHA-256 hashes of encrypted file metadata on remote server
  - Verify file integrity before decryption (tamper detection)
  - Batch verification support (up to 100 files per request)
  - Comprehensive audit logging and statistics tracking
  - mTLS authentication with client certificates
  - Profile management and verification history
  - Utility methods: `compute_metadata_hash()`, `compute_file_id()`
  - Configuration: `~/.openssl_encrypt/plugins/integrity.json`
  - OPT-IN by default (enabled=false)
  - Python API: `from openssl_encrypt.plugins.integrity import IntegrityPlugin, IntegrityConfig`

- **Keyserver Plugin**: Client plugin for post-quantum public key distribution
  - Public key upload, search, and retrieval
  - Local SQLite caching with configurable TTL
  - Bearer token authentication for write operations
  - HTTPS-only connections with timeout configuration
  - Configuration: `~/.openssl_encrypt/plugins/keyserver.json`
  - OPT-IN by default (enabled=false)

- **Telemetry Plugin**: Client plugin for anonymous usage metrics collection
  - Anonymous client identifiers (no personal data)
  - Local SQLite buffering before upload
  - Configurable data collection scopes
  - Background upload with batch processing
  - Full opt-out with data deletion
  - Activation: `--telemetry` flag, `OPENSSL_ENCRYPT_TELEMETRY=1` env, or config
  - OPT-IN by default (disabled)

#### Cryptographic Features
- **Cascade Encryption (Multi-Layer Defense)**: Sequential encryption using multiple cipher algorithms with chained HKDF key derivation
  - Minimum 2 ciphers required, supports unlimited layers
  - Each layer adds entropy to next layer's key derivation
  - Attacker must break ALL ciphers to decrypt data
  - CLI support: `--cascade "aes-256-gcm,chacha20-poly1305,xcha-poly1305"`
  - Automatic cipher diversity validation
  - New metadata format V8 for cascade encryption support

- **Threefish Post-Quantum Ciphers**: Rust-based implementation of Threefish AEAD ciphers
  - Threefish-512 (256-bit post-quantum security level)
  - Threefish-1024 (512-bit post-quantum security level)
  - Memory-hard construction resistant to quantum attacks
  - Native AEAD mode with embedded nonce in ciphertext
  - Maturin-based Rust/Python integration

- **Algorithm Registry System**: Comprehensive cryptographic algorithm registration and validation framework
  - Cipher Registry: 12+ symmetric encryption algorithms with metadata
  - Hash Registry: 15+ cryptographic hash functions
  - KDF Registry: 8 key derivation functions (Argon2, Scrypt, Balloon, HKDF, PBKDF2, RandomX, bcrypt, Fernet)
  - KEM Registry: 9 Key Encapsulation Mechanisms (Kyber, ML-KEM, HQC)
  - Signature Registry: 15 post-quantum signature algorithms (ML-DSA, MAYO, CROSS, Falcon, Dilithium, SPHINCS+)
  - Automatic algorithm validation with security level indicators
  - `crypt list-algorithms` command for browsing available algorithms
  - Integration with configuration wizard and CLI help system

- **HSM-Protected Identity Creation**: Hardware Security Module integration for asymmetric key operations
  - CLI arguments for HSM-protected identity creation: `--hsm`, `--hsm-slot`, `--hsm-pin`
  - HSM_ONLY identities skip password prompts during encryption/decryption
  - Seamless auto-detection when `--with-key` provided
  - Save/load HSM identities without password requirements

#### Testing & Quality Assurance
- **Modularized Test Suite**: Domain-specific test file organization for better parallelization
  - Split CLI tests into 3+ parallel-friendly subclasses
  - Optimized KDF parameters for faster test execution
  - High-CPU GitLab runner tags for improved CI performance
  - Worksteal distribution for dynamic load balancing
  - Comprehensive cascade encryption test coverage

- **Performance Optimizations**: Test suite execution time improvements
  - Reduced KDF rounds in CLI tests (faster execution)
  - Reduced Balloon time_cost in derivation tests
  - Test-only Kyber file optimization
  - Test duration diagnostics for performance monitoring

#### Documentation & Security
- **SECURITY.md Policy**: Comprehensive vulnerability reporting documentation
  - GitHub Security Advisory as preferred reporting method
  - PGP-encrypted email alternative (PGP Key: C8E4 C58E 83AB B314 74C0 E108 0271 3C63 792B 8986)
  - 48-hour initial response commitment
  - Coordinated disclosure practices
  - CVE assignment for critical vulnerabilities
  - Security Hall of Fame for responsible disclosure
  - Added to ALL branches (including EOL releases)

- **Documentation Reorganization**: Cleaned up root directory and organized documentation
  - Moved analysis/audit files to `openssl_encrypt/docs/`
  - Moved test runner scripts to `tests/` directory
  - Removed implementation plan files from repository
  - Consolidated security documentation structure

- **Pre-Commit Hook**: Branch-specific plan file enforcement
  - Auto-remove plan files on main branch
  - Configurable per-branch rules
  - Prevents accidental plan file commits

### Changed

#### Core Features
- **Cascade Encryption Integration**: Full CLI and core module integration
  - Added `--cascade` parameter to encryption commands
  - Support for custom cipher chains with validation
  - JSON schema validation for V7 and V8 metadata formats
  - Cascade variables initialized for all format versions

- **Algorithm Registry Integration**: Replaced hardcoded algorithm lists with registry system
  - CLI helper utilities for registry-based operations
  - Registry-based algorithm validation
  - Improved help text with security level recommendations
  - Configuration wizard integration

- **Identity Management**: Enhanced asymmetric key handling
  - Updated asymmetric encryption format
  - Missing KDF arguments added to subparser for feature parity
  - Skip interactive KDF security prompts in non-TTY environments
  - Improved HSM option handling in identity CLI

#### Build & Dependencies
- **Rust Extension Build**: Integrated Threefish Rust extension into build process
  - Maturin build system for Python/Rust integration
  - Added patchelf for wheel building compatibility
  - CI build step for Threefish extension
  - Flatpak build with proper Threefish wheel handling

- **Docker Infrastructure**: Enhanced Docker builds for server components
  - liboqs 0.12.0 built from source for HQC support
  - Added pkg-config and python3-dev build dependencies
  - Multi-stage Docker builds for optimized images
  - PostgreSQL database integration for both servers

#### Code Quality
- **Security Enhancement**: SecureBytes implementation across all registries
  - KDF registry uses SecureBytes for sensitive data
  - Cipher registry uses SecureBytes for keys (comprehensive implementation)
  - Signature registry uses SecureBytes for secret keys
  - KEM registry uses SecureBytes for sensitive data
  - Comprehensive security audit updates

- **CI/CD Improvements**: Multiple CI pipeline enhancements
  - Docker-based CI support for server components
  - Parallel test execution with loadscope distribution
  - High-CPU runner allocation for faster execution
  - Test duration tracking and diagnostics

### Fixed

#### Critical Issues
- **Stdin Reading Bug**: Resolved decryption failures when reading from stdin
- **CLI Test Failures**: Fixed 2+ CLI test failures related to HSM mocking and argument handling
- **Asymmetric Encryption Tests**: Updated tests for new format compatibility
- **Identity CLI**: Fixed HSM mock issues in identity CLI tests
- **NoneType Comparison**: Removed debug statements causing NoneType comparison errors (fixed 15 tests)

#### Security Fixes
- **RandomX SIGILL Crash**: Prevented RandomX SIGILL crash during test collection in CI
- **Cipher Registry**: Complete SecureBytes implementation across all cipher operations
- **Algorithm Validation**: Fixed auto-detection logic when `--with-key` provided

#### Build System
- **Threefish AEAD Mode**: Fixed Threefish ciphers to embed nonce in ciphertext (like AES-GCM)
- **Flatpak Build**: Cleaned old wheels before Threefish build to prevent conflicts
- **Test Collection**: Use relative paths for test files to prevent CI collection failures

#### Compatibility
- **Metadata V7 Format**: Added quiet and verbose parameters to create_metadata_v7
- **RandomX KDF**: Updated to use correct package structure
- **KDF Arguments**: Fixed missing arguments for proper format compatibility

#### Server Infrastructure
- **SQLAlchemy Reserved Name**: Fixed integrity module INClient model using reserved 'metadata' column name
  - Renamed to 'client_metadata' to avoid SQLAlchemy DeclarativeAPI conflicts
  - Prevents "Attribute name 'metadata' is reserved" error during table creation
- **Environment Protection**: Added .gitignore to openssl_encrypt_server/ to protect sensitive files
  - Excludes .env files from version control
  - Excludes private keys (*.key, *.pem, *.p12, *.pfx)
  - Prevents accidental exposure of credentials and certificates
- **Server Info Endpoint**: Updated /info endpoint to include pepper and integrity module status
  - Shows enabled/disabled status for all four modules (keyserver, telemetry, pepper, integrity)
  - Displays endpoint paths for each module

### Security

#### Security Enhancements
- **Comprehensive SecureBytes Implementation**: All cryptographic registries now use secure memory handling
  - KDF, Cipher, Signature, and KEM registries fully secured
  - Automatic zeroing of sensitive data after use
  - Thread-safe secure memory operations
  - Complete security audit resolution

- **Algorithm Registry Security**: Enhanced cryptographic algorithm security
  - Validation framework prevents unsafe algorithm combinations
  - Security level indicators for all algorithms
  - Deprecated algorithm warnings integrated
  - Comprehensive algorithm metadata tracking

- **Keyserver Security**: Production-grade security for key distribution
  - ML-DSA signature verification for all uploaded keys
  - Bearer token authentication for write operations
  - Rate limiting and CORS protection
  - PostgreSQL backend with parameterized queries

- **Telemetry Privacy**: Privacy-first telemetry implementation
  - Opt-in by design with explicit user consent
  - Anonymous client identifiers
  - Minimal data collection with configurable scopes
  - Transparent data usage policies

- **Pepper Module Security**: Hardened pepper storage with multiple layers of protection
  - mTLS certificate authentication (self-signed CA only, public CAs rejected)
  - TOTP 2FA for destructive operations (panic wipe, account deletion)
  - Client-side encryption (server never sees plaintext peppers)
  - Fernet encryption for TOTP secrets at rest
  - Argon2 hashing for backup codes
  - Deadman switch with grace periods to prevent accidents
  - Comprehensive audit logging (panic events, access tracking)
  - Opt-in by design (disabled by default)

- **Integrity Module Security**: Tamper detection for encrypted file metadata
  - mTLS certificate authentication (self-signed CA only, public CAs rejected)
  - SHA-256 hash verification with integrity violation detection
  - Comprehensive audit logging (all verification attempts tracked)
  - Batch verification with result aggregation
  - Statistics tracking for security monitoring
  - Support for detecting metadata tampering before decryption
  - Opt-in by design (disabled by default)

- **mTLS Authentication Security**: Certificate-based authentication for private modules
  - Self-signed CA requirement prevents unauthorized certificate issuance
  - Public CAs explicitly rejected (Let's Encrypt, DigiCert, etc.)
  - Certificate fingerprint (SHA-256) as unique client identifier
  - Trusted proxy IP validation prevents header injection attacks
  - Certificate DN extraction for client identification
  - Automatic certificate fingerprint normalization
  - No pre-registration required (auto-register on first connection)

#### Security Metrics
- **All Critical Registry Issues Resolved**: Complete SecureBytes implementation across all registries
- **Comprehensive Security Documentation**: SECURITY.md added to all 20 branches
- **Zero Known HIGH/MEDIUM Vulnerabilities**: Security audit completion
- **Enhanced Secure Memory Handling**: Registry-wide secure memory practices

### Removed
- **Plan Files**: Removed implementation plan files from repository
  - asymetric.md, hsm_asymmetric.md, mobile.md
  - keyserver_plan.md, telemetry_plan.md
  - TELEMETRY_IMPLEMENTATION_SUMMARY.md
- **Root Convenience Wrapper**: Removed build-flatpak.sh from root directory
- **Test Artifacts**: Cleaned up test files for plan file hook validation

### Dependencies
- **liboqs**: Updated to 0.12.0 (built from source) for HQC algorithm support
- **FastAPI**: Added for keyserver and telemetry server REST APIs
- **PostgreSQL**: Added psycopg2-binary for server database backends
- **Maturin**: Added for Rust/Python integration (Threefish cipher)
- **All existing dependencies**: Maintained at current secure versions

### Infrastructure
- **Production Servers Deployed**:
  - Keyserver: https://keyserver.rm-rf.ch (FastAPI + PostgreSQL)
  - Telemetry: https://telemetry.rm-rf.ch (FastAPI + PostgreSQL)
- **Docker Support**: Complete Docker infrastructure for both servers
- **Plugin Architecture**: Extensible plugin system for both keyserver and telemetry

### Testing
- **127+ commits** of new functionality and improvements
- Comprehensive cascade encryption test suite
- Threefish cipher integration tests
- Algorithm registry validation tests
- HSM-protected identity tests
- Server endpoint integration tests
- Optimized test execution performance

### Breaking Changes
**None** - Version 1.4.0-alpha.1 maintains backward compatibility with all existing encrypted files and configurations. New features (cascade encryption, Threefish ciphers) use new metadata formats (V8) but existing files remain fully compatible.

### Migration Guide
This is an **alpha release** for testing purposes. While backward compatible, new features should be tested thoroughly before production use:
- **Cascade Encryption**: Test with `--cascade "cipher1,cipher2"` flag
- **Threefish Ciphers**: Available as `threefish-512` and `threefish-1024`
- **Keyserver**: Deploy using Docker or test at https://keyserver.rm-rf.ch
- **Telemetry**: Opt-in system, review privacy policy before enabling

**Alpha Testing Notes**:
- This is a pre-release version intended for testing and feedback
- Production deployment recommended only for non-critical workloads
- Report issues via GitHub Security Advisory or encrypted email
- Final 1.4.0 release planned for Q1 2026

### Contributors
- **Tobi** - Lead developer, cascade encryption, keyserver, telemetry, algorithm registry
- **Claude (Sonnet 4.5)** - Architecture design, security review, testing framework, documentation

---

## [1.3.0] - 2025-12-15

### Added

#### Cryptographic Features
- **RandomX Proof-of-Work KDF**: CPU-optimized key derivation function with light mode (256MB memory) and fast mode (2GB memory) for enhanced security against GPU/ASIC attacks
- **Implicit RandomX Activation**: Automatically enable RandomX when parameters are specified with intelligent default round configuration
- **Steganography Support in Flutter GUI**: Complete integration of data hiding capabilities in desktop GUI
- **Flexible Argument Parsing**: Global flags now support flexible argument parsing for improved CLI usability

#### Testing & Quality Assurance
- **Comprehensive Test Suite**: New `crypt test` command with fuzzing, side-channel analysis, Known-Answer Tests (KAT), performance benchmarking, and memory safety testing
- **Security Audit Logging**: Comprehensive logging system for security events with security_logger and security_report modules
- **Configuration Analysis Tool**: Smart recommendations system with security scoring and configuration validation

#### Infrastructure & Deployment
- **D-Bus Client Examples**: Python, Rust, and Shell client examples demonstrating cross-language compatibility
- **Docker Build Infrastructure**: Local Docker/Podman build scripts with optimized 140MB runtime images
- **QR Code Key Distribution**: Air-gapped keystore operations via portable media
- **Portable USB Encryption**: Unified portable media encryption script with automated integrity verification
- **CI/CD Updates**: Docker-based CI pipeline support with GitLab CI integration

#### Documentation
- **Security Review Documentation**: Comprehensive SECURITY_REVIEW_v1.3.0.md with detailed security audit
- **Docker Build Documentation**: Complete Docker setup guide in docker/README.md
- **D-Bus Integration Guide**: Comprehensive D-Bus service documentation
- **Mobile Implementation Guides**: PQC mobile requirements and chained hash implementation docs

### Changed

#### Core Features
- **RandomX KDF Integration**: Full integration with intelligent implicit enable when parameters detected
- **Default Configuration Behavior**: Enhanced security requiring hash configuration for new encryptions
- **Error Handling**: Improved error messages with comprehensive debug logging replacing print statements

#### Plugin System
- **Thread Safety**: Refactored threading resource management preventing global state pollution
- **Timeout Implementation**: Replaced simple timeout with reliable multiprocessing-based mechanism
- **Queue Handling**: Fixed multiprocessing queue deadlock through improved process management

#### Build & Dependencies
- **Flatpak Dependencies**: Updated manifest dependencies matching requirements-prod.txt
- **Pillow Version**: Relaxed to allow 11.x releases (updated to 11.3.0)
- **NumPy Compatibility**: Upgraded to 2.x for Alpine Linux compatibility

#### Code Quality
- **Path Canonicalization**: Fixed handling for special device files (/dev/stdin, /dev/null, /dev/stdout)
- **Python 3.13 Compatibility**: Replaced datetime.UTC with timezone.utc
- **String Formatting**: Fixed f-strings without placeholders and removed unnecessary imports
- **CI Configuration**: Added amd64 runner tags preventing ARM64 execution

### Fixed

#### Critical Issues
- **Default Configuration Decryption**: Resolved metadata generation inconsistency causing decryption failures
- **PQC Dual Encryption Tests**: Fixed test failures through improved binary prefix handling
- **Multiprocessing Segfaults**: Implemented proper 'spawn' method instead of default fork method
- **Plugin Sandbox Deadlock**: Resolved multiprocessing queue deadlock preventing proper termination

#### Test Infrastructure
- **Import Path Corrections**: Fixed duplicate module imports in pytest
- **Mock Patch Paths**: Corrected mock.patch module paths in test_generate_password_cli
- **Flaky Tests**: Fixed two intermittent test failures
- **API Compatibility**: Updated Advanced Testing Framework encrypt_file API calls

#### Build System
- **Docker Image Sizing**: Optimized build reducing image to 140MB with proper runtime dependencies
- **Build Tool Dependencies**: Added necessary build tools for Python package compilation
- **YAML Parsing**: Fixed YAML syntax errors and f-string issues in CI configuration

#### Compatibility
- **Keystore Schema**: Made schema more flexible for version compatibility
- **Backward Compatibility**: Fixed v1.3.0 decryption compatibility without prior hashing
- **PQC Validation**: Added missing PQC algorithms to metadata v5 schema
- **Legacy Algorithms**: Added legacy algorithm names for keystore compatibility

### Security

#### Vulnerability Resolutions
- **MED-2: D-Bus Symlink Attack Prevention (RESOLVED)**
  - Implemented O_NOFOLLOW protection in safe_open_file() utility for atomic TOCTOU protection
  - Added secure_mode parameter to encryption/decryption functions for D-Bus service security
  - Created comprehensive symlink attack tests with 100% pass rate
  - Eliminates symlink-based directory traversal attacks in D-Bus service
  - Maintains CLI behavior compatibility (secure_mode=False allows symlinks)

- **LOW-5: Debug Mode Security Warning (RESOLVED)**
  - Added prominent security warning box when --debug flag is enabled
  - Clear "DO NOT use with production data" messaging
  - Updated --debug help text across crypt_cli.py, crypt_cli_subparser.py, and crypt.py
  - Warning displayed before any sensitive logging occurs

#### Security Enhancements
- **Comprehensive Security Review**: SECURITY_REVIEW_v1.3.0.md with 0 CRITICAL, 0 HIGH, 3 MEDIUM, 4 LOW findings
- **Security Audit Logging**: Comprehensive audit logging for security events throughout codebase
- **D-Bus Path Validation**: Enhanced directory whitelisting for D-Bus file operations
- **Plugin Validation**: Added strict mode with configurable bypass options
- **Subprocess Safety**: Removed shell=True from subprocess calls with proper list-based arguments

#### Security Metrics
- **Overall Security Score**: 8.8/10 (improved from 8.5/10)
- **Input Validation**: 9.5/10 (improved with O_NOFOLLOW protection)
- **Cryptography**: 9.5/10
- **Authentication**: 9.0/10
- **Memory Safety**: 9.0/10
- **Dependency Security**: 10/10 (zero vulnerable dependencies via pip-audit)
- **Status**: APPROVED FOR PRODUCTION

### Removed
- **Video Steganography**: Removed implementation due to fundamental reliability issues
- **Video Dependencies**: Removed video steganography dependencies from requirements
- **Test Artifacts**: Cleaned up steganography test images and debug files

### Dependencies
- **Pillow**: Updated to 11.3.0 (relaxed constraint to allow 11.x releases)
- **NumPy**: Upgraded to 2.x for Alpine Linux compatibility
- **Cryptography**: Maintained at 44.0.3+
- **Argon2-cffi**: Maintained at 23.1.0+
- **pip-audit**: All dependencies verified with zero vulnerable packages

### Documentation
- Added SECURITY_REVIEW_v1.3.0.md with comprehensive security audit
- Added docker/README.md for Docker build and deployment
- Added examples/dbus_clients/ with Python, Rust, and Shell examples
- Enhanced plugin development guides with security architecture details

### Testing
- 128+ encryption-related unit tests passing
- Comprehensive plugin system tests with proper isolation
- Full D-Bus service tests with symlink attack scenarios
- Docker build tests with optimized 140MB image
- RandomX integration tests with fallback handling
- Post-quantum cryptography dual encryption tests

### Breaking Changes
**None** - Version 1.3.0 maintains full backward compatibility with all existing encrypted files and configurations.

### Migration Guide
No migration required. v1.3.0 is a drop-in replacement for v1.2.x installations.

**Note**: Debug mode (--debug) now displays a prominent security warning. This is intentional to remind users that debug output contains sensitive information.

### Contributors
- **Tobi** - Lead developer, security enhancements, comprehensive testing
- **Claude (Sonnet 4.5)** - Security review, documentation, testing framework

## [1.2.0] - 2025-08-16

### Added
- **Flutter Desktop GUI**: Professional desktop GUI application built with Flutter providing native Wayland and X11 support
- **Advanced CLI Integration**: Complete Flutter-to-CLI bridge service with real-time progress monitoring and error handling
- **Comprehensive Settings System**: Professional settings interface with theme switching, cryptographic defaults, and debug features
- **Desktop UX Excellence**: Professional menu bar, keyboard shortcuts (Ctrl+O, Ctrl+S, F1), drag & drop file operations
- **Algorithm Configuration UI**: Advanced parameter tuning interface for all KDFs (Argon2, Scrypt, Balloon, HKDF)
- **Post-Quantum Algorithm UI**: Complete interface for ML-KEM, Kyber, HQC, MAYO, and CROSS algorithms
- **Flatpak Desktop Integration**: Complete Flatpak packaging with desktop file, icons, and system integration

### Changed
- **GUI Architecture**: Migrated from tkinter to Flutter for superior desktop experience and cross-platform compatibility
- **Flatpak Launcher**: Simplified launcher focusing on Flutter GUI with tkinter support removed from release branches
- **User Interface**: Desktop-optimized layout with NavigationRail, tabbed interface, and professional visual design
- **File Operations**: Native desktop file dialogs with drag & drop support replacing basic file selection
- **Algorithm Selection**: Interactive algorithm picker with security level recommendations and performance guidance

### Removed
- **PBKDF2 Support**: Removed legacy PBKDF2 key derivation function from encryption operations due to security concerns
- **Whirlpool Hash**: Removed deprecated Whirlpool hash algorithm from encryption operations for security hardening

### Fixed
- **Wayland Compatibility**: Native Wayland support through Flutter eliminating X11 authorization issues
- **Display Server Support**: Robust support for both Wayland and X11 environments without manual configuration
- **Desktop Integration**: Proper desktop environment integration with system theming and accessibility support
- **Performance**: Significant UI responsiveness improvements through native Flutter rendering

### Security
- **Reduced Attack Surface**: Elimination of complex X11/XWayland compatibility layers in Flatpak environment
- **Native Desktop Security**: Flutter's native platform integration provides better sandboxing than X11-based solutions
- **Streamlined Permissions**: Simplified Flatpak permissions removing unnecessary X11 fallback mechanisms
- **Algorithm Hardening**: Removed deprecated PBKDF2 and Whirlpool algorithms to eliminate weak cryptographic options

## [1.1.0] - 2025-06-26

### Added
- Segregated CLI help system with two-tier structure (global + command-specific)
- Context-aware help display showing only relevant options per command
- Improved command discovery with comprehensive overview in global help
- Command-specific argument parsing for better user experience

### Changed
- Enhanced CLI help output for better usability and reduced cognitive load
- Global help now provides clear command overview and navigation guidance
- Encrypt command help shows only encryption-relevant options and algorithms
- Decrypt command help shows only decryption-relevant options (no algorithm selection)
- Generate-password, shred, and utility commands show focused option sets

### Technical
- Added crypt_cli_subparser.py module for command-specific argument handling
- Implemented version-aware algorithm filtering (excludes 1.1.0-only MAYO/CROSS algorithms)
- Maintained full backward compatibility with all existing CLI usage patterns
- No changes to core cryptographic functionality or file formats

## [1.0.0] - 2025-06-21

### Added
- Official production release milestone
- Enterprise-grade quantum-resistant cryptographic capabilities
- Complete post-quantum cryptography support (Kyber, ML-KEM, HQC algorithms)
- Production-grade type safety and runtime stability
- Enterprise-ready keystore management for PQC keys
- Industry-leading code quality standards with comprehensive static analysis

### Changed
- Status updated to Production Release / Stable
- Full backward compatibility maintained with all previous file formats
- Production deployment readiness achieved

### Security
- Comprehensive security hardening with constant-time operations
- Final security audit completion with zero HIGH/MEDIUM severity issues
- Production-ready security posture established

## [1.0.0-rc3] - 2025-06-16

### Documentation
- Major documentation consolidation from 37+ files to 10 comprehensive guides (73% reduction)
- Updated README.md Documentation Structure section with clickable links
- Added June 2025 documentation restructuring to RELEASE_NOTES.md
- Consolidated user documentation into user-guide.md and keystore-guide.md
- Consolidated security documentation into security.md, algorithm-reference.md, and dependency-management.md
- Consolidated technical documentation into metadata-formats.md and development-setup.md
- Integrated ML-KEM CLI support documentation into algorithm-reference.md
- Integrated HQC algorithm completion status from NEXT.md into TODO.md

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

## [1.0.0-rc2] - 2025-06-16

### Fixed
- Resolved all critical MyPy type errors that could cause runtime failures in post-quantum cryptography operations
- Fixed variable naming conflicts between AESGCM and PQCipher classes
- Corrected string/bytes type mismatches in password handling
- Removed invalid function parameters causing TypeErrors
- 90%+ critical runtime issues resolved (type errors reduced from 529 to ~480)

### Added
- HQC algorithm support fully implemented (hqc-128/192/256-hybrid) with comprehensive testing
- **HQC Production Readiness**: Complete HQC algorithm implementation with 15 test files covering all symmetric encryption combinations
- **HQC Security Validation**: Comprehensive error handling tests for invalid keys, corrupted data, wrong passwords, and algorithm mismatches
- **HQC Integration**: Full keystore integration, dual-encryption support, and file format v5 compatibility
- Complete post-quantum cryptography support (Kyber, ML-KEM, HQC)
- Industry-leading code quality standards
- Production-grade stability and reliability

### Security
- Security analysis confirmed 0 HIGH/MEDIUM severity issues
- All core encryption functionality verified working
- HQC algorithms pass all security validation tests and attack vector analysis

## [1.0.0-rc1] - 2025-05-16

### Added
- Comprehensive multi-layered static code analysis with 7 GitLab CI jobs
- 18+ pre-commit hooks for immediate development feedback
- Legacy algorithm warning system for deprecated cryptographic algorithms
- Comprehensive code formatting via Black and isort
- Enhanced CI pipeline with Docker improvements and job isolation

### Changed
- Repository cleanup removing unnecessary development artifacts

### Security
- Industry-leading code quality standards implementation
- Comprehensive static analysis integration
- Enhanced security scanning capabilities

## [0.9.2] - 2025-05-15

### Added
- CRYPT_PASSWORD environment variable support for CLI with secure multi-pass clearing
- Comprehensive GUI password security with SecurePasswordVar class
- Extensive unit test suite with 11 tests covering environment variable password handling

### Security
- Enhanced password handling security across all interfaces
- Secure clearing verification for environment variables

## [0.9.1] - 2025-05-14

### Added
- ML-KEM algorithms (ML-KEM-512/768/1024)
- HQC algorithms re-enabled with comprehensive testing (HQC-128/192/256)
- Enhanced keystore integration for all PQC algorithms
- Improved concurrent test execution safety

### Removed
- bcrypt dependency due to incompatible salt handling

### Security
- Extended quantum-resistant algorithm support
- Comprehensive post-quantum testing infrastructure
- Enhanced keystore security features

## [0.9.0] - 2025-04-16

### Added
- Constant-time cryptographic operations implementation
- Secure memory allocator for cryptographic data
- Standardized error handling to prevent information leakage
- Python 3.13 compatibility
- Enhanced CI pipeline with pip-audit scanning
- SBOM generation (Software Bill of Materials)
- Thread safety improvements with thread-local timing jitter

### Security
- Comprehensive dependency security with version pinning
- Major security hardening release
- Backward compatibility maintained across all enhancements

## [0.8.2] - 2025-04-15

### Fixed
- Python version compatibility fixes for versions < 3.12
- More resilient Whirlpool implementation during package build
- Enhanced build system reliability
- Cross-platform compatibility improvements

## [0.8.1] - 2025-04-14

### Added
- New metadata structure v5 with backward compatibility
- User-defined data encryption when using PQC
- Enhanced PQC flexibility with configurable symmetric algorithms
- Comprehensive testing and documentation updates

## [0.7.2] - 2025-03-16

### Added
- New metadata structure with backward compatibility
- Improved data organization and structure
- Enhanced file format versioning
- All tests passing with updated documentation

## [0.7.1] - 2025-03-15

### Added
- Complete keystore implementation for post-quantum keys
- Comprehensive testing - all tests passing
- Updated documentation for keystore functionality

### Breaking Changes
- Breaking release for keystore feature of PQC keys

## [0.7.0-rc1] - 2025-03-14

### Added
- PQC key management system
- Local encrypted keystore for post-quantum keys
- Last major feature for release candidate phase

### Breaking Changes
- Breaking release introducing keystore feature

## [0.6.0-rc1] - 2025-02-16

### Added
- Feature-complete post-quantum cryptography implementation
- Hybrid post-quantum encryption architecture
- Complete post-quantum algorithm support

### Breaking Changes
- Breaking release for post-quantum cryptography

## [0.5.3] - 2025-02-15

### Added
- Additional buffer overflow protection
- Enhanced secure memory handling
- Improved memory safety

### Security
- Security-focused bug fixes
- Enhanced memory protection

## [0.5.2] - 2025-02-14

### Added
- Post-quantum resistant encryption via hybrid approach
- Kyber KEM integration for quantum resistance
- Hybrid encryption architecture combining classical and post-quantum
- Future-proof cryptographic foundation

## [0.5.1] - 2025-02-13

### Fixed
- More reliable commit SHA integration into version.py
- Enhanced build process reliability
- Improved version tracking

## [0.5.0] - 2025-01-16

### Added
- BLAKE2b and SHAKE-256 hash algorithms
- XChaCha20-Poly1305 encryption support
- Expanded cryptographic algorithm portfolio
- Enhanced security options

## [0.4.4] - 2025-01-15

### Added
- Scrypt support
- Additional hash algorithms implementation
- Enhanced key derivation options
- Improved password security

## [0.4.0] - 2025-01-14

### Added
- Secure memory handling implementation
- Improved password strength validation
- Memory security enhancements
- Enhanced data protection

## [0.3.0] - 2025-01-13

### Added
- Argon2 key derivation support
- Memory-hard key derivation function
- Enhanced password-based security
- Industry-standard KDF implementation

## [0.2.0] - 2025-01-12

### Added
- AES-GCM support
- ChaCha20-Poly1305 encryption
- Multiple encryption algorithm support
- Cryptographic algorithm flexibility

## [0.1.0] - 2025-01-11

### Added
- Initial public release
- Basic file encryption/decryption
- Fernet encryption (AES-128-CBC)
- Secure password-based encryption
- Foundation cryptographic features
