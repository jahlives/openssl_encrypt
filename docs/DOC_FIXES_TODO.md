# Documentation TODO — Fixes & Clarifications

> **Status:** open / actionable
> **Created:** YYYY-MM-DD
> **Context:** Corrections arising from a review of the KDF attack-resistance
> claims and the independent-vs-sequential XOR composition modes, plus
> structural gaps in SECURITY.md and cross-doc consistency.
> Items 1–2 are the substantive factual corrections (highest priority);
> 3–4 are structural.

---

## 1. README — KDF attack-resistance claims (factual fixes)

- [x] **`Attack Resistance` table** — the row *"GPU/ASIC parallelization →
  sequential dependency forces single-threaded computation"* misattributes the
  defense. Re-attribute anti-GPU/ASIC to the **memory-hardness** of
  Argon2id/Balloon (RAM bandwidth/capacity per lane bounds how many guesses run
  in parallel). Note that sequential dependency only blocks *intra-guess*
  parallelism, which does **not** stop *guess-level* parallelism — the attack
  that matters.
- [x] **`Computational Cost Estimates` table** — the "~10²²–10³¹ years" figures
  assume a **single-threaded attacker**. Drop that assumption or relabel the
  numbers as an idealized upper bound a massively parallel attacker undercuts by
  the parallelism factor (10⁴–10⁶+). Make clear the per-guess *cost*
  (memory-hardness), not the chaining, is what bounds throughput.
- [x] **`Chained Key Derivation` section** — reframe the value of chaining /
  multiple KDFs as **defense-in-depth** (robustness if one KDF is buggy/broken)
  plus prevention of cross-guess precomputation via per-round salts — **not**
  added ASIC/GPU resistance. State that total attacker cost is the *sum* of stage
  costs (dominated by the strongest), which a single well-parametrized KDF also
  achieves.
- [x] Add: the most effective lever for ASIC/GPU resistance is **Argon2id memory
  size**, because memory (not function identity) drives ASIC-resistance.
  Optional justification: Litecoin-scrypt ASICs exist only because of its 128 KB
  parameter.
- [x] Reconcile any text presenting **RandomX** as a security feature.
  **NOTE / correction:** RandomX is **not** disabled by default — the STANDARD
  (default) template sets `randomx.enabled = True` (10 rounds), asserted by
  `test_standard_template.py`. Only the bare `--enable-randomx` CLI flag defaults
  off. Per maintainer decision (2026-06-28) this is a **docs-only** fix: we
  document the *reality* (RandomX is on in STANDARD) but reframe it honestly as an
  exotic PoW / defense-in-depth, not the load-bearing anti-ASIC defense
  (Argon2id memory-hardness is). The template default was **not** changed.

## 2. KDF composition modes (independent vs sequential XOR)

- [ ] Document the **two modes and their different guarantees** explicitly:
  - *Independent XOR* — provably **as strong as the strongest component** for
    **output/PRF security** (robust XOR-combiner: secure if ≥1 component is).
    This is the mode to lean on for the strongest-link claim.
  - *Sequential XOR* — the strongest-link guarantee does **not** hold; a
    broken/entropy-collapsing *early* round propagates through later rounds
    (XOR can't rescue), so it's bounded by the **weakest early link**. Its only
    gain is intra-guess sequentiality.
- [ ] **Scope the "strongest component" claim precisely** (in the
  `generate_key_independent_xor` docstring + docs): it concerns **output
  indistinguishability** and bites only against a **broken/entropy-collapsing**
  link. A merely *cheap* (low-cost but full-entropy) link is harmless in either
  mode and is not what the guarantee covers — so don't present "strongest link"
  as covering cost/memory-hardness (cost is sum-of-components in both modes).
- [ ] Document the **cancellation caveat** for independent XOR: components share
  the same `(pw+salt)`, so the property holds only while no two are the *same
  function with identical params* (XOR of identical outputs = 0). Recommend
  per-component domain separation, e.g. `HKDF(salt, info=algo_name)`.
  *(Track the matching impl + test as a separate hardening item.)*
- [ ] If sequential XOR stays an option, document the recommended hardening:
  **re-inject the original password (or a stable commitment) into every round**
  so no early link can sever the pw dependency — and note it still lacks a clean
  combiner proof.
- [ ] Replace any **"Massey XOR"** naming with the correct literature term:
  **robust combiner** / XOR-combiner for PRFs (Herzberg;
  Harnik–Kilian–Naor–Reingold–Rosen).

## 3. SECURITY.md — threat model & scope

- [ ] Add an explicit, written **threat model / non-goals** section: adversary
  capabilities, protected assets, and what is *not* defended (compromised
  endpoint, traffic analysis, CPython timing/side-channels, plaintext-length
  leakage). This anchors the cost-claim corrections above.
- [ ] Document that **plaintext length is not hidden** by the standard container
  (size leaks); note optional padding as a future consideration
  *(cross-ref FORMAT.md §17)*.
- [ ] Re-scope the **Source-Code Integrity** wording: keep the honest
  "convenience tripwire" framing, but state it does not substitute for
  supply-chain measures (signed/attested releases, reproducible builds), and
  acknowledge the maintenance cost.

## 4. Cross-references & consistency

- [ ] Link the new **FORMAT.md** from README and SECURITY.md; finish its §18
  index — especially **§6 AAD canonicalization** and the **§15 version table
  (identify v11 and v13)**.
- [ ] Mirror the **v1.5.0 removals / migration notes** consistently across
  README, CHANGELOG, SECURITY.md, and FORMAT.md §13 (decrypt-only exception);
  confirm steganography removal is documented as **1.5.x-only** (retained in
  1.4.x).

---

### Suggested sequencing

1. **§1 + §2** — the factual KDF corrections (highest leverage; they fix claims
   that are currently misleading).
2. **§3 threat model** — anchors and justifies the §1 cost-claim rewrites.
3. **§4 cross-references** — once FORMAT.md and the above settle.
