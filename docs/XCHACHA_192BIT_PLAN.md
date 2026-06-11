# Real 192-bit XChaCha20-Poly1305 Nonce Support — Implementation Plan

Target release: **1.5** (branch `feature/xchacha-192bit-nonce`, based on
`feature/v1.5.x-development`).

**Status: implemented** — see CHANGELOG 1.5.0 and `test_xchacha_primitives.py`,
`test_xchacha_wrapper.py`, `test_xchacha_192bit_format.py`.

## 1. Problem Statement

The current "XChaCha20-Poly1305" implementation stores a 24-byte nonce in the
file format but only the first 12 bytes ever affect the keystream. The cipher
is therefore effectively ChaCha20-Poly1305 with a 96-bit nonce (2^48 random
collision bound), not real XChaCha20 with a 192-bit nonce (2^96 bound).

This is **not a vulnerability** in existing releases: encryption keys are
derived per file from unique random salts, so a nonce is never reused under
the same key. But the algorithm does not provide what its name promises, and
files are not interoperable with spec-compliant XChaCha20-Poly1305
implementations (libsodium et al.).

### Current state per code path (audit of `feature/v1.5.x-development`)

| Path | Stored nonce | Effective derivation | Effective strength |
|------|-------------|----------------------|--------------------|
| One-shot file (`crypt_core.py` encrypt ~6229 / decrypt ~9268) | 24 bytes | first 12 bytes used raw (`nonce[:nonce_size]`, `nonce_size=12`) | 96-bit |
| Streaming (`streaming.py`, `_get_nonce_size` → 12) | 12-byte per-chunk HKDF nonce | used raw | 96-bit (per chunk) |
| Cascade (registry `cipher_registry.py:604`) | 24 bytes (HKDF-derived per layer) | `HKDF(ikm=key, salt=nonce[:16], info=nonce[16:]) → 12 bytes` | 96-bit (funnel; key-dependent) |
| PQC hybrid (`pqc.py`, `pqc_adapter.py`) | 12 bytes | used raw | 96-bit |
| `crypt_core.XChaCha20Poly1305._process_nonce` 24-byte HKDF branch | — | dead code on file paths (call sites always slice to 12) | — |

Note: a naive fix that just "passes the full 24 bytes" so the existing HKDF
branch runs gains nothing — HKDF funnels 24 bytes into a 96-bit nonce under
the same key, staying at the 2^48 collision bound. Real 192-bit security
requires genuine HChaCha20 subkey derivation: the per-message *key* must
depend on the first 16 nonce bytes.

## 2. Design Decisions

### D1 — HChaCha20 in-repo, no new dependency

`cryptography` 46.0.6 does not expose XChaCha20-Poly1305 or HChaCha20, and
PyNaCl is not a project dependency. We implement HChaCha20 on top of
`cryptography`'s C-backed `ChaCha20` stream cipher using the keystream
feed-forward subtraction identity:

```
keystream_block = chacha20_rounds(state) + state          (per-word, mod 2^32)
⇒ chacha20_rounds(state)[i] = keystream_block[i] - state[i]
```

All initial state words are known (constants, key, 16-byte HChaCha input in
the counter+nonce positions), so HChaCha20's output (words 0–3 and 12–15 of
the round output, *without* feed-forward) is recovered by subtracting the
known initial words from one 64-byte keystream block. This is a standard
technique for building XChaCha on ChaCha20-only APIs.

**Already validated**: prototype output matches an independent pure-Python
HChaCha20 implementation; both verified against the
draft-irtf-cfrg-xchacha-03 §2.2.1 test vector
(`82413b42 27b27bfe d30e4250 8a877d73 a0f9e4d5 8a74a853 c12ec413 26d3ecdc`).

Real XChaCha20-Poly1305 then is, per the draft:

```
subkey  = HChaCha20(key, nonce[0:16])
chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:24]
XChaCha20Poly1305(key).seal(nonce24, pt, aad)
    = ChaCha20Poly1305(subkey).seal(chacha_nonce, pt, aad)
```

New module: `openssl_encrypt/modules/xchacha.py` with `hchacha20()` and
`xchacha20poly1305_encrypt/decrypt()` helpers — single source of truth for
all paths. Unit tests pin the §2.2.1 HChaCha20 vector and the §A.3 full AEAD
test vector (interop-grade proof).

### D2 — Format signaling: metadata field, not a format_version bump

`format_version` is entangled with KDF/XOR semantics: the CLI writes 9/10/11
depending on XOR flags and streaming always writes 12. A v13 bump would have
to fan out across every hardcoded version list, schema dispatch, rekey logic,
and the XOR-mode selection — high blast radius for an orthogonal concern.

Instead, new-format files carry an explicit marker in the metadata
`encryption` section:

```json
"encryption": { "algorithm": "xchacha20-poly1305", "xchacha_nonce_format": 2, ... }
```

- `xchacha_nonce_format: 2` → real 192-bit XChaCha (this feature).
- Field absent (or `1`) → legacy behavior (pre-1.5 files).
- Schemas v10/v11/v12 already allow `additionalProperties`; the field is
  added explicitly to the schemas anyway for documentation/validation.

**Downgrade analysis**: when metadata is AEAD-bound (`aead_binding: true`),
the field is covered by the AAD and cannot be stripped. Even without AAD
binding, stripping the field only switches the decryptor to the legacy
derivation, which produces a *different* keystream/subkey under the same key
— the Poly1305 tag check fails. There is no path where an attacker downgrades
a new file to weaker decryption that succeeds.

### D3 — Nonce-length dispatch in `crypt_core.XChaCha20Poly1305`

The wrapper class becomes mode-explicit by nonce length:

- 24-byte nonce → **real XChaCha** (D1 construction).
- 12-byte nonce → legacy direct `ChaCha20Poly1305` (what every existing file
  path effectively does today).
- Any other length → `ValidationError` (the HKDF fallback branches are dead
  code on file paths and are removed; stricter input validation).

Call-site compatibility: legacy decrypt sites already slice to 12 bytes
before calling the class, so legacy files are untouched. New-format sites
pass the full 24 bytes.

### D4 — One-shot encrypt/decrypt gating

- `get_algorithm_nonce()` (encrypt): for XChaCha return
  `(secrets.token_bytes(24), 24)` — full nonce passed to the cipher; metadata
  gets `xchacha_nonce_format: 2`. The pytest-only "12-byte nonce in test
  mode" special case is removed for XChaCha so tests exercise the real
  format.
- `get_nonce_size()` (decrypt): candidates become
  - flag == 2 → `[(24, 24)]`
  - flag absent → `[(24, 12), (12, 12)]` (existing legacy trial order)
  The existing trial loop structure is reused unchanged.

### D5 — Cascade / registry cipher

The registry `XChaCha20Poly1305(CipherBase)` gains a real-nonce mode. Its
current HKDF `_process_nonce` is **live** legacy behavior for existing
cascade files and must be preserved for them:

- mode `legacy` (default): HKDF(salt=nonce[:16], info=nonce[16:]) → 12 bytes
  (decrypts pre-1.5 cascade layers).
- mode `xchacha2`: real HChaCha20 construction.

`CascadeEncryptor`/`CascadeDecryptor` already receive `format_version`; they
additionally receive the nonce-format flag plumbed from `crypt_core` (writer
sets 2; reader takes it from metadata). Layer nonce sizes stay 24 bytes —
only the cipher-internal derivation changes.

### D6 — Streaming

- Writer: `_get_nonce_size("xchacha20-poly1305")` → 24 for new files;
  `derive_chunk_nonce(..., nonce_size=24)` (HKDF output length change only);
  metadata `encryption` section carries `xchacha_nonce_format: 2`.
- Reader: nonce size selected from the metadata flag (12 for legacy streaming
  files, 24 for new).

### D7 — PQC hybrid path: explicitly out of scope

`pqc.py` / `pqc_adapter.py` generate 12-byte nonces under a fresh
KEM-derived symmetric key per encryption — there is no nonce-reuse risk and
the construction is effectively ChaCha20-Poly1305. Changing it would alter
the PQC container layout for no security gain. Documented as-is; the
crypt_core class keeps accepting 12-byte nonces for exactly this path.

### D8 — GUI/CLI

No new flags. New encryptions silently produce the real format; decryption
auto-detects via metadata. The "WARNING: Using legacy 12-byte nonce" decrypt
message is kept for legacy files.

## 3. Test Plan (TDD — tests written first per step)

1. **Primitive vectors** (`test_xchacha_primitives.py`, new):
   - HChaCha20 §2.2.1 vector; XChaCha20-Poly1305 §A.3 AEAD vector
     (key/nonce/AAD/ciphertext/tag from draft-irtf-cfrg-xchacha-03).
   - Cross-check against pure-Python HChaCha20 reference for random inputs.
   - Input validation (key/nonce lengths, None, empty).
2. **Wrapper class**: 24-byte → real (matches §A.3), 12-byte → legacy direct
   ChaCha20Poly1305 equivalence, other lengths rejected, tamper → 
   `AuthenticationError`.
3. **192-bit effectiveness regression test** (the proof the bug is fixed):
   same key, two 24-byte nonces identical in the first 12 bytes, differing
   only in bytes 12–23 → ciphertexts must differ (fails on legacy slicing,
   passes on real XChaCha).
4. **One-shot round-trip** new format; metadata contains the flag; decrypt of
   freshly-written file works; tamper detection.
5. **Legacy compatibility**: all existing `unittests/testfiles/v12/*xchacha*`
   fixtures (plain + `cascade~…~xchacha20-poly1305`) must still decrypt — they
   are committed pre-change artifacts and serve as the regression corpus.
6. **Streaming round-trip** new format (multi-chunk), legacy streaming file
   decrypt.
7. **Cascade round-trip** new format; legacy cascade fixtures decrypt.
8. **Cross-mode negative tests**: new-format file forced through legacy path
   (and vice versa) must fail authentication, not silently succeed.
9. **New-format fixtures**: add freshly-generated real-XChaCha test files to
   `testfiles/` so future changes can't regress the new format either.

## 4. Implementation Steps & Commit Plan

Workflow per global guidelines: full-suite baseline before any change; one
feature-step = one commit after its targeted tests pass; full suite again at
the feature boundary and diffed against the baseline.

1. `docs:` this plan document.
2. `feat:` `modules/xchacha.py` + primitive vector tests (TDD).
3. `feat:` rework `crypt_core.XChaCha20Poly1305` (nonce-length dispatch) +
   class tests.
4. `feat:` one-shot path: metadata flag, `get_algorithm_nonce`/
   `get_nonce_size` gating, schema updates + round-trip/legacy/effectiveness
   tests.
5. `feat:` streaming path + tests.
6. `feat:` cascade/registry path + tests.
7. `test:` new-format fixture corpus; `docs:` CHANGELOG, format docs,
   SECURITY.md note on legacy nonce semantics.
8. Full suite, baseline diff, fix any regressions before each commit.

## 5. Risks / Notes

- The HChaCha20-via-ChaCha20 trick depends on `cryptography`'s ChaCha20
  16-byte-nonce convention (4-byte LE counter ‖ 12-byte nonce). The §2.2.1
  vector test pins this; if a future backend changed conventions the test
  fails loudly.
- Old (≤1.4) software cannot decrypt new-format XChaCha files (expected for
  a 1.5 format feature; error is an authentication failure rather than a
  friendly message — acceptable, matches existing cross-version behavior).
- `secure_memzero` hygiene: the derived subkey is key material and must be
  zeroized after use in `xchacha.py` helpers.
