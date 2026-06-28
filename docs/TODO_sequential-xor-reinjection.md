# TODO — KDF re-injection robustness for the sequential / XOR composition

> **⚠️ SUPERSEDED (2026-06-28).** After analysis we did **not** build the
> sequential re-injection construction below. Its only unique benefit is
> intra-guess *thread-binding*, which is **not** the load-bearing defense
> (per-guess memory-hardness is — see DOC_FIXES §1), while its provable wins
> (cancellation-kill, broken-link robustness) come more cheaply — and *with* the
> strongest-link proof — from **independent XOR with distinct domain-separated
> per-component salts**. That was implemented instead as **`format_version 13`**
> (`_indep_xor_component_salt`; `test_format_v13_xor_domsep.py`), opt-in,
> byte-identical on both lines. The construction below is **declined / archived**
> for reference; revisit only if a hard *thread-binding* requirement appears.

> **Status:** SUPERSEDED by format_version 13 (independent-XOR per-component salts)
> **Owner:** Tobias
> **Branches:** must land on **both** `feature/v1.4.x-development` **and**
> `feature/v1.5.x-development` (see gating).
> **Origin:** follow-up to the independent-vs-sequential XOR analysis. Goal is to
> make the sequential composition robust against (a) a broken/entropy-collapsing
> link and (b) XOR cancellation, by re-injecting the **original password** and
> the **original salt** into every round.

---

## ⚠️ 0. GATING — read first (non-negotiable)

This changes the derived key for the same inputs, so it **MUST be gated behind a
new format version**. Without gating it is a **breaking change** — existing
ciphertexts would no longer decrypt.

- [ ] Allocate **one new `format_version` N** for the re-injection derivation.
  - [ ] Confirm the highest `format_version` currently allocated **across both
    lines** first (1.4.x and 1.5.x diverge; 12 = streaming, 13 = ⚠️ confirm), then
    take the next free number.
  - [ ] **The version number MUST be identical on 1.4.x and 1.5.x.** Same integer,
    same meaning, same derivation. Do not let the two lines drift to different
    numbers for the same change.
- [ ] **Append-only decryption.** The new derivation applies **only** to files
  written at version N. Files at version `< N` MUST continue to decrypt via the
  existing (legacy) derivation path, unchanged. → no breaking change for existing
  files.
- [ ] **Cross-line byte-identity.** A file written at version N by 1.4.x must
  decrypt identically on 1.5.x and vice versa. The derivation must be
  byte-for-byte identical across branches — pin every detail (§2) and add a
  cross-line golden-vector test (§4).
- [ ] **Default write version:** keep N **opt-in** until impl + tests are green on
  both lines; flip the default to N in a separate, later step (own checkbox /
  own commit).

---

## 1. The construction (target derivation for version N)

Per round `i` (1…n) over the cross-KDF sequence:

```
salt_i = H( salt_0 || r_{i-1} || LE(i) )      # r_0 := "" (empty) for i = 1
r_i    = KDF_i( pw, salt_i )
key    = ⊕_i r_i           # XOR mode
       |  r_n              # pure-sequential mode (no XOR)
```

Where:

- `pw` = the **original password** (post-HSM-pepper mix, if any) — fed to **every**
  round, never replaced by the previous round's output.
- `salt_0` = the **original random file salt** — bound into **every** round's salt
  (every iteration, not just round 1).
- `r_{i-1}` = previous round's output — carries the **sequential / thread-bound**
  dependency.
- `LE(i)` = round index as domain separation (fixed-width, see §2).

What this buys (vs. the current `current_input = result; round_salt = result[:32]`
chaining, where pw and salt_0 only enter round 1):

- **Robustness:** a broken early link can no longer sever the pw dependency — the
  next round still sees `pw` directly, so distinct passwords → distinct `r_i` and
  the key keeps full entropy. Degrades gracefully, not catastrophically.
- **Salt survives a break:** because `salt_0` is in every `salt_i`, a collapsed
  early round no longer discards the per-file salt → multi-target / rainbow /
  identical-key protection stays intact on later rounds.
- **Cancellation killed (bonus):** every round now gets a **distinct** `salt_i`,
  so two identical KDFs can no longer produce identical outputs that XOR to `0`.
  This also retires the shared-`(pw+salt)` cancellation footgun in the
  independent-XOR mode.

---

## 2. Determinism details to PIN (load-bearing for cross-line identity)

- [ ] **`H`** = ⚠️ decide and pin (recommend SHA-256). Document it.
- [ ] **Concatenation encoding** of `salt_0 || r_{i-1} || LE(i)`: fix field
  widths / length-prefixing so there is no ambiguity (e.g. fixed 32-byte `salt_0`,
  fixed `r_{i-1}` length, **index as fixed-width little-endian**, pick the width).
  Avoid any variable-length concat that could alias.
- [ ] **Round 1 convention:** define `r_0` (empty string vs. a fixed constant) and
  document it.
- [ ] **Ordering** of the cross-KDF sequence and which stages participate must be
  derived deterministically from metadata (same rule on both lines).
- [ ] **`key_length` normalization** of each `r_i` before XOR (reuse
  `normalize_to_key_length_secure`) — confirm identical on both lines.

---

## 3. Code touch-points

- [ ] `compute_kdf_independent` / `compute_hash_independent` — add the version-N
  salt-derivation + pw re-injection path (gated on `format_version == N`).
- [ ] `generate_key_independent_xor` — wire the new path; update the docstring
  ("strongest component" scope + the new per-round salt).
- [ ] `generate_key` — version dispatch so `< N` → legacy, `== N` → new.
- [ ] `xor_bytes_secure` — unchanged, but the cancellation note no longer applies
  at version N (distinct salts). Update comment.
- [ ] **Pure-sequential mode caveat:** document that without XOR the **final link
  is still a single point of failure** (its output *is* the key; no XOR term to
  absorb a broken final round). XOR mode closes this; pure-sequential does not.
  Decide whether to (a) keep pure-sequential as-is with the caveat documented, or
  (b) recommend XOR mode as the default for the multi-KDF case.
- [ ] **Intra-KDF rounds (separate, lower priority):** the internal `rounds` loop
  of a single KDF (e.g. Argon2's `current_input = result`) gains little from
  external round-wrapping — a repeated strong function won't entropy-collapse.
  Prefer raising **native** cost params (`time_cost` / `memory_cost`) over
  external wrapping. Track as its own item; do **not** bundle into version N.

---

## 4. Tests (both lines)

- [ ] **Regression / no-break:** a corpus of files at every existing
  `format_version` still decrypts unchanged after the change. (Enforces §0
  append-only.)
- [ ] **Round-trip** at version N (encrypt → decrypt) for single-KDF, multi-KDF
  XOR, and pure-sequential.
- [ ] **Cross-line golden vector:** a version-N file + fixed `{pw, salt_0, params}`
  → fixed key/ciphertext, asserted **identical on 1.4.x and 1.5.x**. (Enforces §0
  byte-identity.) Commit the vector.
- [ ] **Broken-link simulation:** stub one KDF to a constant; assert distinct
  passwords still yield distinct keys at version N (robustness), and that the
  *legacy* path would have collapsed (documents the fix).
- [ ] **Cancellation:** configure two identical KDFs; assert the key is **not**
  zero / not degraded at version N (distinct `salt_i`).
- [ ] **Salt-survival:** with a collapsed early link, assert the key still depends
  on `salt_0` at version N (different `salt_0` → different key).

---

## 5. Docs to update (after impl)

- [ ] `FORMAT.md` §15 version table — add row for version N (introduced in
  1.4.x **and** 1.5.x, same number); §7 — document the re-injection derivation
  and pin `H` / encoding.
- [ ] `DOC_FIXES_TODO.md` §2 — mark the sequential-XOR robustness + cancellation
  items as addressed by version N; keep the "no clean combiner proof for
  sequential" caveat.
- [ ] `CHANGELOG.md` (both lines) — note the new format version and that it is
  **opt-in, non-breaking** (legacy files unaffected).

---

## 6. Open decisions for tomorrow

- [ ] `H` choice (SHA-256?) and the exact concat encoding / index width.
- [ ] Pure-sequential: keep with documented final-link SPOF, or steer to XOR mode?
- [ ] When to flip the **default** write version to N (separate step).
- [ ] Honest framing to carry over: this is **empirically robust on both axes**,
  but the correlated per-round salts mean it is **still not a clean XOR-combiner
  proof** — the *proof* remains only with independent XOR (now with distinct,
  domain-separated salts against cancellation). Keep both modes; lean on
  independent for the formal claim, on this construction when thread-binding is
  wanted.
