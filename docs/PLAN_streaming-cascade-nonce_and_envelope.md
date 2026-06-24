# Implementation Plan & Progress — Cascade Chunk-Nonce Fix (#1) + Envelope Encryption (#2)

> Living document. Pick up here. Checkboxes reflect actual completion state.
> Last updated: 2026-06-23 (initial draft, baseline running).

## Decisions (locked, from user)

| Topic | Decision |
|---|---|
| Branch targets | **#1 → both** `feature/v1.4.x-development` **and** `feature/v1.5.x-development`; **#2 → both** (REVISED 2026-06-24, was 1.5.x-only): build+harden on `feature/v1.5.x-development` FIRST, then port the frozen impl to `feature/v1.4.x-development`. **`v13` envelope format MUST be byte-identical across both lines** (shared known-answer vectors) so v13 files interop across 1.4.x↔1.5.x. |
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
- [x] **0. Baseline** on `feature/envelope-encryption` (off v1.5.x-dev) → `test-logs/baseline_envelope.log`: 4988 passed, 25 skipped, 4 xfailed, 0 failed.
- [x] **1. [Red→Green]** DEK wrap/unwrap primitive — `modules/envelope.py` (`generate_dek`,
      `wrap_dek`, `unwrap_dek`; AES-256-GCM, HKDF-domain-separated wrap key, `secure_memzero`).
      9 tests in `test_envelope_encryption.py` (roundtrip, wrong-KEK, tamper, sizes, short-KEK). GREEN.
      Standalone module (no PQ KEM dependency). Commit pending.
- [x] **2. [Red→Green]** `--envelope` flag added to encrypt subparser, threaded to all 3
      `encrypt_file(` CLI call sites (`envelope=getattr(args,"envelope",False)`).
- [x] **3. [Red→Green]** bulk encrypt/decrypt under DEK via additive `encryption.wrapped_dek`
      (existing format_version preserved). encrypt_file: DEK swap after KEK finalized (crypt_core
      ~5807), wrapped_dek injected before each `json.dumps(metadata)` (3 sites). decrypt_file: unwrap
      after KEK derived (~8829). No schema change needed (encryption.additionalProperties=true).
      Non-envelope unchanged; decrypt auto-detects. Tests: aes-gcm/chacha/cascade roundtrip,
      wrapped_dek present+base64+size, wrong-password fails, non-envelope has no wrapped_dek.
- [x] **4. [Red→Green]** streaming under DEK — `test_envelope_streaming_roundtrip` (key=DEK flows
      into StreamingEncryptor/Decryptor). 16 envelope tests green; cascade regression 78 green.
- [ ] **5. [Red→Green]** `rekey` fast path — **BLOCKED: OPEN DESIGN DECISION (see below).** Deferred.
- [ ] **6. [Green]** backward-compat: pre-envelope files decrypt unchanged.
- [ ] **7. Security tests:** DEK/KEK zeroed on all paths; absent from logs & exception messages.
- [ ] **8. Release artifacts** (CHANGELOG.md ### Added, version.py.template + version.py, flatpak
      metainfo.xml; changelog.html release-time) + bump `__version__` if cutting a version.
- [ ] **9. Post-change full suite** → `test-logs/postfix_envelope.log`; diff vs baseline; zero regressions.
- [ ] **10. Commit** on `feature/envelope-encryption`.

---

## ⚠️ OPEN DESIGN DECISION FOR TOMORROW — envelope rekey fast-path vs AEAD binding

**Status:** Cycles 1–4 of Feature #2 are DONE and committed (envelope works end-to-end;
`--envelope` opt-in; one-shot/cascade/streaming round-trip). Cycle 5 (the O(1) rekey fast-path —
envelope's headline benefit) is **BLOCKED** on the decision below. Decide tomorrow, then implement.

### The conflict (verified in code)
- Bulk ciphertext is AEAD-bound to the FULL metadata: `aad = metadata_b64` (one-shot:
  `aad_for_decrypt = metadata_b64` at decrypt; streaming: `build_chunk_aad(metadata_b64, ...)`).
- `metadata_b64` includes the KDF **salt**, **kdf_config**, AND the new **`encryption.wrapped_dek`**.
- A rekey with a new password MUST change salt → new KEK → new `wrapped_dek`. That changes the AAD,
  so the OLD bulk ciphertext would fail authentication. ⇒ "keep ciphertext, only rewrap the DEK"
  (true O(1) rekey) is **incompatible** with the current full-metadata AEAD binding.

### The sound fix (standard envelope construction)
Make the envelope bulk AEAD bind only a **stable subset** of metadata — algorithm, format_version,
cascade chain (cipher_chain/layer_info), streaming params (chunk_size/chunk_count/nonce_prefix/
cascade_nonce_scheme), encryption_data — and EXCLUDE the KEK-derivation fields
(`derivation_config.salt`, `derivation_config.kdf_config`/`hash_config`, `encryption.wrapped_dek`).
- **Why safe:** `wrapped_dek` is itself AES-GCM authenticated, so tampering with salt/kdf/wrapped_dek
  just makes `unwrap_dek` fail closed; the DEK (actual bulk key) is unchanged by a rekey. Everything
  that affects *interpretation* of the bulk ciphertext stays in the AAD; only the *access-gating*
  KEK material is excluded. This is the conventional KEM/DEK envelope AAD split.
- **Cost/risk:** security-sensitive change to AAD computation in BOTH encrypt and decrypt, across
  one-shot + cascade + streaming. Needs a canonical stable-subset serializer (deterministic key
  order) used identically on both sides, plus adversarial tests (tamper each excluded field ⇒
  unwrap fails; tamper each included field ⇒ auth fails; cross-file wrapped_dek swap ⇒ fails).

### Options (pick one tomorrow)
- **A. Implement stable-subset AAD** (recommended) → enables true O(1) rekey (rewrap DEK + rewrite
  metadata, copy bulk ciphertext verbatim). Most value; most care required.
- **B. Ship envelope WITHOUT fast-path** → keep full-metadata binding; rekey stays full re-encrypt
  even for envelope files. Envelope is then only DEK indirection (foundation for multi-recipient),
  with little immediate user benefit. Low risk.
- **C. Revert Feature #2** if the fast-path isn't worth the AAD change (cycles 1–4 are isolated on
  `feature/envelope-encryption`, easy to shelve).

## ✅ DECISION LOCKED (2026-06-24) — Option A, opt-in only

**Chosen: Option A** (stable-subset bulk AAD enabling O(1) credential rekey + future
multi-password/multi-KEK), subject to TWO HARD CONSTRAINTS and a fixed wrap construction.

### Hard constraints (non-negotiable)
1. **Must NEVER affect existing encryptions.** Every file without an envelope marker keeps
   FULL-metadata AAD binding (`aad = metadata_b64`), byte-for-byte the current code. The
   subset-AAD path is entered ONLY when `encryption.wrapped_dek` is present / `format_version`
   is the envelope version (v13). The change is strictly additive + branched:
   `if envelope: aad = envelope_aad(metadata) else: aad = metadata_b64`. No previously written
   ciphertext is ever reinterpreted under the subset AAD.
2. **Never the default.** Strictly opt-in via `--envelope` (already `envelope=False` default in
   cycles 2-4). Option A only alters behavior *inside* the already-opt-in envelope branch.

### Why the constraints hold (mode-confusion is fail-closed)
The mode selector is itself authenticated: **`format_version` is in the stable-subset AAD and
envelope uses its own version (v13).** Therefore:
- Strip `wrapped_dek` to force the legacy/full-AAD (password-is-bulk-key) path ⇒ wrong bulk key ⇒
  fails closed.
- Bolt a `wrapped_dek` onto a legacy file to force the subset path ⇒ unwrap yields a bogus DEK,
  bulk was never under a DEK ⇒ fails closed.
Neither silently downgrades an existing file. REQUIRED adversarial tests: add/remove `wrapped_dek`
and flip `format_version` ⇒ each fails closed.

### DEK-wrap cipher — FIXED, not user-configurable
The AES-256-GCM that wraps the DEK (`wrapped_dek`) is **pinned, not a user choice.** Rationale:
- It encrypts **32 bytes** — no perf/throughput/capability difference exists between AEADs at this
  size, so a cipher menu buys nothing here.
- A selectable wrap-algorithm identifier is a downgrade/confusion attack surface (the JWT `alg`
  failure class). Fewer choices = smaller surface.
- One wrap construction = one code path, one test matrix, auditable.
- AES-256-GCM is FIPS, AES-NI-accelerated, exhaustively analyzed, and nonce-safe here (each wrap
  key = `HKDF(KEK)` wraps exactly one DEK once with a fresh random nonce; rekey rolls the KEK).

**One automatic refinement (NOT a knob):** the wrap must never be the weak link. When the **bulk is
a cascade**, wrap the DEK under that **same cascade chain** (keyed from the KEK) so envelope
preserves the cascade's strongest-surviving-component guarantee instead of collapsing the file's
security to single AES-256. Driven by the file's `encryption.algorithm`/cascade-chain, which is
already in the authenticated AAD subset ⇒ no new downgrade surface, nothing for the user to set.
- Non-cascade bulk → AES-256-GCM wrap (fixed).
- Cascade bulk → same cascade chain wraps the DEK.
(RFC 3394 AES-KW is the purpose-built nonce-free alternative if ever wanted; GCM-random-nonce is
sound and matches existing AEAD usage — staying with GCM.)

### Rekey is CREDENTIAL rotation, not data-key rotation
The fast-path rewraps the SAME DEK under a new KEK; the DEK never changes. This rotates *access*
(old password can no longer unwrap) but NOT the bulk key. If the DEK may itself be compromised,
that requires a full re-encrypt under a fresh DEK. ⇒ Keep a `--rotate-dek` / full-reencrypt option
for true data-key rotation; document the distinction in CLI help + CHANGELOG so users don't assume
fast rekey gives more than it does. (For small files the rekey speedup is ~nil anyway — the 2x KDF
floor dominates — so the headline value of A here is the multi-password foundation, not speed.)

### GATE before any code
Grep every reader of `derivation_config.salt` and confirm it feeds ONLY the KEK, never the
bulk/DEK path. If anything bulk-side consumes the salt, that field MUST move into the authenticated
subset. This gate decides the safety of the entire included/excluded partition.

### If A is chosen — implementation sketch
1. Add `envelope_aad(metadata) -> bytes`: canonical JSON of the stable subset (sorted keys).
2. encrypt_file + StreamingEncryptor + cascade: when envelope, use `envelope_aad` instead of
   `metadata_b64` for the bulk AEAD AAD (a flag/param threaded down). Non-envelope unchanged.
3. decrypt_file mirror: when `wrapped_dek` present, recompute `envelope_aad` for bulk decryption.
4. rekey_file: envelope fast-path — read file, derive old KEK, unwrap DEK; derive new KEK (new
   salt/kdf from new password/config), rewrap DEK; rewrite metadata (new salt/kdf/wrapped_dek),
   keep payload bytes; recompute nothing on the bulk side because `envelope_aad` is unchanged.
   Add test: bulk ciphertext bytes identical before/after rekey; new password decrypts; old fails.
5. Full adversarial test pass (above).

### Remaining Feature #2 cycles after the decision
6 backward-compat (mostly green) · 7 security/wipe tests (DEK/KEK zeroed, never logged) ·
8 release artifacts (CHANGELOG ### Added, version.py.template+version.py, flatpak metainfo.xml) ·
9 post-change full suite → test-logs/postfix_envelope.log · 10 final commit.

## Progress log (newest first)
- 2026-06-24 (later): REVISED branch target — Feature #2 now ships to BOTH 1.5.x and 1.4.x (was
  1.5.x-only). Feasibility confirmed: v13 is free on both branches (both cap at v12, identical
  schema sets v3-v12); 1.4.x already has aead_binding/streaming.py/cascade.py, only envelope.py is
  missing. Approach: build+harden on 1.5.x first, then port the frozen impl to 1.4.x (same pattern
  as #1). HARD CONSTRAINT: v13 envelope format byte-identical across both lines (shared KAT vectors)
  so files interop 1.4.x↔1.5.x. Rationale: 1.5.x is alpha, 1.4.x is the stable/production line where
  users actually are; multi-password only reaches users via 1.4.x.
- 2026-06-24: DECISION LOCKED — Option A approved, opt-in only, two hard constraints (never affect
  existing files; never default). DEK-wrap cipher fixed to AES-256-GCM (NOT user-configurable),
  with automatic cascade-match when bulk is cascade. Keep `--rotate-dek`/full-reencrypt for true
  data-key rotation. NEXT: run the salt-only-feeds-KEK gate, then implement cycles 5-10. Feature #1
  (cascade nonce fix) merged to v1.5.x (d1f6f9dc) + signed (2e8ecb7c) + pushed to origin.
- 2026-06-23 (later): Feature #1 committed on feature/streaming-cascade-nonce-fix (08cc2052).
  v1.4.x regression-guard committed (6470b1e6) — v1.4.x was already protected via chunk_nonce.
  Feature #2 cycles 1-4 committed on feature/envelope-encryption (cycle1 7e4a89cb; cycles2-4
  17055935): envelope.py primitive + --envelope opt-in + encrypt/decrypt integration + streaming.
  16 envelope tests green. Cycle 5 (rekey fast-path) BLOCKED on the AEAD-binding design decision
  above — left for tomorrow. STOP POINT: resume by deciding A/B/C above.
- 2026-06-23: Plan drafted. Branch `feature/streaming-cascade-nonce-fix` created off v1.5.x.
  Root cause confirmed (streaming.py:509-512). Baseline full suite running
  (`test-logs/baseline_cascade_nonce_fix.log`). Memory updated with the 5 changelog locations.
