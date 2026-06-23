# Implementation Plan & Progress — Cascade Chunk-Nonce Fix (#1) + Envelope Encryption (#2)

> Living document. Pick up here. Checkboxes reflect actual completion state.
> Last updated: 2026-06-23 (initial draft, baseline running).

## Decisions (locked, from user)

| Topic | Decision |
|---|---|
| Branch targets | **#1 → both** `feature/v1.4.x-development` **and** `feature/v1.5.x-development`; **#2 → `feature/v1.5.x-development` only** |
| #1 old-file compat | **Read-compat + warn**: new writes use fixed scheme; old (weak) cascade-streamed files still decrypt via legacy path + one-time security warning urging rekey |
| #2 rollout | **Opt-in flag, default off** (decrypt auto-detects via metadata) |
| Work order | **#1 first, fully shipped & committed, then #2** |
| Process | Strict TDD (Red→Green→Refactor), one commit per cycle; security-first; reuse `secure_memzero` / `SecureBytes` / `CryptoKey`; `constant_time_*` for compares; no keys in logs/exceptions |

## Test / baseline discipline
- Full suite (`pytest -n auto --dist=worksteal openssl_encrypt/unittests/ | tee test-logs/<name>.log`) at each **feature boundary**; targeted-file pytest per cycle.
- Post-change suite log of #1 becomes the baseline for #2 (chained baselines).
- Sandbox: run black/isort/bandit manually, commit with `--no-verify` (sandbox only); black `--line-length=100`, match pinned rev in `.pre-commit-config.yaml`.

## Definition of Done (BOTH features) — release artifacts
Every feature is incomplete until ALL FIVE changelog/version touchpoints are updated together:
- [ ] `CHANGELOG.md` (repo root)
- [ ] `openssl_encrypt/version.py.template` (**source of truth**: `${VERSION}` + `VERSION_HISTORY`)
- [ ] `openssl_encrypt/version.py` (generated but committed — keep in sync)
- [ ] `flatpak/com.opensslencrypt.OpenSSLEncrypt.metainfo.xml` (`<releases>`)
- [ ] `flatpak/flathub/apps/openssl-encrypt/changelog.html`
- (NOTE: `versions.py` plural is the liboqs dep-check module — NOT a changelog. Leave alone.)

---

# Feature #1 — Cascade chunk-nonce reuse fix (SECURITY FIX)

**Branch:** `feature/streaming-cascade-nonce-fix` (off `feature/v1.5.x-development`), then port to `feature/v1.4.x-development`.

## Root cause (confirmed in code)
`openssl_encrypt/modules/streaming.py:509-512` — the cascade branch passes the constant
`self.cascade_salt` to `cascade_encryptor.encrypt(...)` for **every chunk** and ignores the
per-chunk `nonce` derived at line 503. `cascade.py` derives each layer's key+nonce from
`(master_key, salt)`; constant salt ⇒ **same per-layer nonce reused across all chunks**
(catastrophic AEAD nonce reuse). Non-cascade path (line 514) is sound: per-chunk
`derive_chunk_nonce(prefix, chunk_index)`.

## Fix design
- Add helper `derive_chunk_cascade_salt(cascade_salt, chunk_index)` next to `derive_chunk_nonce`
  (`streaming.py:110`): `HKDF(salt=cascade_salt, info=b"oesc-cascade-chunk-salt:"+u32be(idx), len=32)`.
- Pass the per-chunk salt in the cascade branch of **both** `StreamingEncryptor.encrypt_file`
  and `StreamingDecryptor` (mirror). `cascade.py` stays untouched (still salt-based).
- Mark new scheme via metadata `streaming.cascade_nonce_scheme: 2`.
  Decrypt: absent/`1` → legacy reused-salt path **+ one-time security warning urging rekey**;
  `2` → fixed per-chunk derivation.
  (Chosen over a global format_version bump as the lower-risk, surgical option consistent with
  "read-compat + warn". Revisit if a global bump is preferred.)

## Key files
- `openssl_encrypt/modules/streaming.py` (encryptor `:456-547`, decryptor `:563+`, helpers `:110-163`)
- `openssl_encrypt/modules/cascade.py` (derive_layer_keys — read-only, confirm derivation)
- `openssl_encrypt/modules/crypt_core.py` (streaming wiring `~5806-5882`, `~8970-9046`; metadata builders)
- Tests: `openssl_encrypt/unittests/test_streaming.py`,
  `test_streaming_format_version.py`, `test_xchacha_192bit_format.py`

## TDD cycles — tasks
- [x] **0. Baseline** full suite captured to `test-logs/baseline_cascade_nonce_fix.log` (clean: 4988 passed, 25 skipped, 4 xfailed, 0 failed — 2026-06-23)
- [x] **1. [Red]** white-box test `test_cascade_per_chunk_salt_is_unique` (mock cascade, capture
      per-chunk salts, assert distinct) — confirmed RED (1 != 4). Integration guard
      `test_end_to_end_cascade_streaming_records_scheme_2` added. (Black-box body-compare dropped:
      fragile for cascade — inner per-layer tags differ regardless; white-box test is definitive.)
- [x] **2. [Green]** added `derive_chunk_cascade_salt` (streaming.py); used in encryptor + decryptor
      (scheme-switched); `cascade_nonce_scheme` written by crypt_core (cascade only) + read on decrypt
      with legacy default; added field to `metadata_v12_schema.json`.
- [x] **3. [Refactor]** helper + `CASCADE_NONCE_SCHEME_LEGACY/PER_CHUNK` constants + docstrings (clean).
- [x] **4. [Red→Green]** legacy-read test `test_legacy_scheme1_file_decrypts_and_warns`: scheme-1 file
      decrypts AND emits `logger.warning` urging rekey. (Warning added in StreamingDecryptor.decrypt_file.)
- [x] **5. [Green]** regression: test_streaming + test_streaming_format_version + test_cascade +
      test_xchacha_192bit_format = 192 passed, 1 skipped. No regressions.
- [x] **6. Release artifacts**: CHANGELOG.md (### Security), version.py.template (1.5.0 entry),
      version.py (local sync; note: git-IGNORED/generated), flatpak metainfo.xml (1.5.0 alpha block).
      NOTE: flathub changelog.html NOT updated — it lags at 1.4.2 and tracks no 1.5.0 content at all;
      it is regenerated at release time. **Release-time TODO: add 1.5.0 section to changelog.html.**
- [x] **7. Post-change full suite** → `test-logs/postfix_cascade_nonce_fix.log`: 4991 passed, 25
      skipped, 4 xfailed, 0 failed (baseline 4988 + 3 new tests). No regressions.
- [x] **8. Commit** on `feature/streaming-cascade-nonce-fix` — `38be75b0` (amended `08cc2052`).
- [x] **9. Port to v1.4.x** — DONE, but as a **regression guard only**. KEY FINDING: v1.4.x is
      **NOT vulnerable** — its `CascadeEncryption.encrypt/decrypt` take a per-chunk `chunk_nonce`
      folded into the salt (`effective_salt = salt + chunk_nonce`, cascade.py:316/365), passed by
      both StreamingEncryptor and StreamingDecryptor. The bug was a v1.5.x-only refactor regression.
      Per user decision: added 2 white-box regression-guard tests (encryptor + decryptor side) that
      fail if `chunk_nonce` is ever dropped. No code fix, no changelog/version bump.
      v1.4.x baseline 2617 → post-change 2619 passed, 0 failed. Commit `6470b1e6` on
      `feature/v1.4.x-development`.
      SEPARATE PRE-EXISTING v1.4.x ISSUE (out of scope, flagged to user): the high-level
      `encrypt_file`→`decrypt_file` streaming roundtrip fails on v1.4.x (streaming-format_version
      fix exists on v1.5.x only). Not pursued.

### Notes / deviations
- `version.py` is **git-ignored** (generated from `version.py.template` by setup.py); only the
  template is committed. The 5-file checklist is effectively 4 committed files + 1 release-time HTML.
- Backward-compat realized via a `streaming.cascade_nonce_scheme` metadata field (default=1 legacy on
  read) rather than a global format_version bump — surgical, matches the existing `xchacha_nonce_format`
  pattern.

---

# Feature #2 — Envelope encryption (DEK/KEK), opt-in

**Branch:** `feature/envelope-encryption` (off `feature/v1.5.x-development`). v1.5.x ONLY.

## Design (reuse the tested v7 asymmetric envelope pattern)
- Random 32-byte **DEK** in `CryptoKey`/`SecureBytes`.
- **KEK** derived from password via existing `generate_key()` KDF chain.
- Wrap DEK with KEK using `PasswordWrapper.wrap_password(DEK, KEK)` (AES-256-GCM, nonce‖ct‖tag).
- **DECISION (user, 2026-06-23): additive `encryption.wrapped_dek` field, NOT a new format_version.**
  Existing format_version is preserved; presence of `wrapped_dek` triggers envelope mode and is
  auto-detected on decrypt. Rationale: `format_version in [...]` is checked in many places + M11
  fails closed on unknown versions → a v13 would be high blast-radius. Mirrors `cascade_nonce_scheme`.
- KEK = today's password-derived key (`generate_key`). Bulk encrypt uses DEK instead of KEK.
- Decrypt: derive KEK as today; if `encryption.wrapped_dek` present → DEK = unwrap_password(...),
  use DEK for bulk; else use KEK directly (unchanged legacy path).
- Bulk data AND streaming chunks encrypt under the DEK.
- `secure_memzero` DEK+KEK on every exit path; never logged / never in exceptions.
- **`rekey` fast path:** envelope file ⇒ unwrap DEK with old KEK, rewrap with new KEK, copy
  ciphertext verbatim (O(header)). Non-envelope ⇒ today's full re-encrypt.
- **Opt-in CLI flag** (e.g. `--envelope`), default off; decrypt auto-detects via `wrapped_dek`.

## Key files (to confirm at start)
- `openssl_encrypt/modules/crypt_core.py` (`encrypt_file` `:5190`, `decrypt_file` `:7984`,
  `rekey_file` `:7720`, metadata builders `create_metadata_v6/_v8` `:3917/:4114`, `generate_key` `:2490`)
- `openssl_encrypt/modules/asymmetric_core.py` (`PasswordWrapper`)
- `openssl_encrypt/modules/secure_memory.py` / `crypto_secure_memory.py` (`CryptoKey`, `SecureBytes`)
- CLI subparser for the new flag
- Tests: new `test_envelope_encryption.py`; touch `test_rekey.py`

## TDD cycles — tasks
- [~] **0. Baseline** on `feature/envelope-encryption` (off v1.5.x-dev) → `test-logs/baseline_envelope.log` (RUNNING).
- [x] **1. [Red→Green]** DEK wrap/unwrap primitive — `modules/envelope.py` (`generate_dek`,
      `wrap_dek`, `unwrap_dek`; AES-256-GCM, HKDF-domain-separated wrap key, `secure_memzero`).
      9 tests in `test_envelope_encryption.py` (roundtrip, wrong-KEK, tamper, sizes, short-KEK). GREEN.
      Standalone module (no PQ KEM dependency). Commit pending.
- [ ] **2. [Red→Green]** flag plumbing (`--envelope`) parsed & threaded to encrypt_file.
- [ ] **3. [Red→Green]** bulk encrypt/decrypt under DEK via additive `encryption.wrapped_dek`
      (existing format_version preserved); non-envelope still works; decrypt auto-detects.
- [ ] **4. [Red→Green]** streaming under DEK.
- [ ] **5. [Red→Green]** `rekey` fast path: assert ciphertext bytes unchanged, only header rewrapped.
- [ ] **6. [Green]** backward-compat: pre-envelope files decrypt unchanged.
- [ ] **7. Security tests:** DEK/KEK zeroed on all paths; absent from logs & exception messages.
- [ ] **8. Release artifacts** (CHANGELOG.md ### Added, version.py.template + version.py, flatpak
      metainfo.xml; changelog.html release-time) + bump `__version__` if cutting a version.
- [ ] **9. Post-change full suite** → `test-logs/postfix_envelope.log`; diff vs baseline; zero regressions.
- [ ] **10. Commit** on `feature/envelope-encryption`.

---

## Progress log (newest first)
- 2026-06-23: Plan drafted. Branch `feature/streaming-cascade-nonce-fix` created off v1.5.x.
  Root cause confirmed (streaming.py:509-512). Baseline full suite running
  (`test-logs/baseline_cascade_nonce_fix.log`). Memory updated with the 5 changelog locations.
