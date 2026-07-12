# v14 Series Review Fixes (2026-07-10) — 1.4.x Port Check

> **STATUS: DONE (2026-07-11).** Ported to `feature/v1.4.x-development` as
> `e1b8950a` (LOW-2 memoryview) and `490014eb` (LOW-1 SECURITY NOTE, cipher
> list adapted to 1.4.x: AES-GCM/-GCM-SIV/-SIV/-OCB3 + (X)ChaCha20-Poly1305,
> no Threefish in the 1.4.x PQC dispatch). Fix 3 confirmed N/A. crypto-reviewer
> re-review on 1.4.x: clean. Full suite before/after identical (3241 passed,
> 29 skipped, 0 failures). Not pushed.

Working note for tomorrow: three changes landed on `feature/v1.5.x-development`
after the crypto-reviewer pass over the format_version-14 series (commits
`900023e8..671df1ce`). The reviewer reported **no Critical/High findings**;
two Low findings were fixed and confirmed RESOLVED on re-review, plus one
dead-code cleanup the review surfaced. Since the v14 series exists on both
lines, check whether `feature/v1.4.x-development` needs the same fixes.

Pre-check already done today against `origin/feature/v1.4.x-development`
(state as of 2026-07-10 — re-verify tomorrow if the branch moved).

Reminder (CLAUDE.md): when porting, keep the shared changelog text
byte-identical across branches.

---

## 1. LOW-2 — v14 TLV KDF seed hashed via memoryview (code fix)

- **1.5.x commit:** `824d7b2e` — `security: hash v14 TLV KDF seed via
  memoryview (review LOW-2)`
- **What:** in `generate_key_independent_xor` (crypt_core.py), the v14 seed
  was hashed as `hashlib.sha256(bytes(_v14_seed))`, materializing an
  immutable, unwipeable copy of the cleartext password+salt+pepper (M2
  [MEM-1] class). Fixed to `hashlib.sha256(memoryview(_v14_seed))` —
  zero-copy, byte-identical digest, `finally: secure_memzero(_v14_seed)`
  unchanged and still wipes in place (secure_memzero uses same-length slice
  assignment, no resize, and the inline memoryview is released before the
  `finally` runs).
- **1.4.x status: NEEDED.** Confirmed present:
  `origin/feature/v1.4.x-development` crypt_core.py:2894 still has
  `SecureBytes(hashlib.sha256(bytes(_v14_seed)).digest())`.
- **Port action:** cherry-pick / apply the one-line change + comment.
  Regression net: the cross-line golden vectors in
  `test_format_v14_seed_lengthsep.py` (GOLDEN_V14_KEY_HEX /
  GOLDEN_V14_PEPPER_KEY_HEX) must still pass — the change is
  behavior-preserving by construction.

## 2. LOW-1 — v14 KEM transcript binding: detection mechanism documented (docstring only)

- **1.5.x commit:** `06de2b24` — `docs(security): state AEAD-based detection
  for v14 KEM transcript binding (review LOW-1)`
- **What:** added a SECURITY NOTE to the live `_derive_symmetric_key`
  docstring in pqc.py: the #83 transcript binding detects
  ciphertext/metadata substitution *via AEAD authentication* (tampered
  transcript → different HKDF key → tag failure), not an explicit compare —
  so the PQC symmetric layer must remain an AEAD. All reachable data
  ciphers are AEADs, including Threefish (CTR+Poly1305, verified in
  `threefish_native/src/threefish_aead.rs`). Guards against a future
  non-authenticated data cipher silently voiding the binding.
- **1.4.x status: NEEDED.** The SECURITY NOTE is absent on
  `origin/feature/v1.4.x-development` (its `_derive_symmetric_key` is at
  pqc.py:529). Verify the 1.4.x PQC cipher dispatch is AEAD-only too before
  copying the note verbatim.
- **Port action:** copy the docstring block. No behavioral change, no test
  impact.

## 3. Dead shadowed `_derive_symmetric_key` removal (cleanup)

- **1.5.x commit:** `56a163b6` — `refactor: remove dead shadowed
  _derive_symmetric_key definition`
- **What:** 1.5.x pqc.py carried TWO defs of `_derive_symmetric_key`; the
  first (pre-#83, v12/legacy-only) was silently shadowed by the second,
  live definition and never executed. Removed the dead copy.
- **1.4.x status: NOT NEEDED.** `origin/feature/v1.4.x-development` has
  exactly one definition (pqc.py:529, the kem_ciphertext-aware one) — the
  duplication was a 1.5.x-only artifact of the v14 rollout port.
- **Port action:** none. Just re-confirm with
  `git grep -c "def _derive_symmetric_key" <1.4.x> -- openssl_encrypt/modules/pqc.py`
  (expect 1).

---

## Verification recipe for tomorrow (on the 1.4.x checkout)

1. `git grep -n "bytes(_v14_seed)" -- openssl_encrypt/modules/crypt_core.py`
   → any hit means fix 1 is still unported.
2. `git grep -n "SECURITY NOTE (detection mechanism)" -- openssl_encrypt/modules/pqc.py`
   → no hit means fix 2 is still unported.
3. After porting: run `test_format_v14_seed_lengthsep.py`,
   `test_format_v14_kem_binding.py`, `test_pqc_kem_hkdf.py` targeted, full
   suite at the boundary per the tiered test policy; changelog entries in
   CHANGELOG.md (+ version.py.template Security clause) byte-identical to
   the 1.5.x wording (commits `824d7b2e`/`06de2b24` carry the exact text).
