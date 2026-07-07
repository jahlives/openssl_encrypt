# Security Review v1.4.7 — Remaining Open Issues

_Generated 2026-07-02 from GitLab `sec-review::1.4.7` (project `world/openssl_encrypt`)._

> **Reconciled 2026-07-07 against git history.** Everything Critical/High/Medium is
> resolved, including **#66** (plugin signature-gating, merged `055036b1`). Of the
> original 19 LOW items, **18 are fixed**; the last one (#100) is deferred to a possible
> format-version bump (see below). **Nothing remains that is fixable in place.** See the
> **Resolved** section for per-issue commit refs.
>
> **Update 2026-07-07 (#95).** On feasibility investigation #95 proved **not**
> format-breaking — the per-chunk nonce is HKDF-derived from a metadata-stored prefix, so
> widening it 8→16 bytes is backward compatible. Fixed on both branches (v1.4.x `a0a5357d`,
> v1.5.x `5f0a8b02`), not a format bump.
>
> **Update 2026-07-07 (deferred hardening batch).** #79/#80 and #74 fixed on both
> branches (v1.4.x `997a6c00` / `48a3e207`; v1.5.x `ebb34c44` / `e6c8a54b`); #59
> marked superseded by M3 (no code change, by decision).
>
> **Update 2026-07-07 (#100/#83 format-bump design).** Design review concluded a new
> `format_version 14` is **not warranted on its own**: #100 is non-exploitable and was
> deliberately left by v13's domain-separation work; #83 is already HKDF for
> `format_version >= 12` (only default-v9 files + a ciphertext-binding nicety remain), with
> no exploitable gain. Both are kept as accepted LOW residuals with a **ready-to-implement
> spec pre-staged in [`docs/FORMAT_V14_PLAN.md`](docs/FORMAT_V14_PLAN.md)** — land it
> opportunistically at the next format bump. **4 deferred items** (#81, #82 inherent; #83,
> #100 pre-staged v14); **none open in place**.

Each issue links to its GitLab entry (which has the full finding + verification notes).
Fixes land on BOTH `feature/v1.4.x-development` and `feature/v1.5.x-development`, each
with a regression test and full-suite check, per the project workflow.


## Deferred / reclassified-LOW (future hardening) (4)

_Nothing here is fixable in place. #81/#82 are inherent-limitation / large-rewrite; #83 and
#100 are format-breaking and pre-staged for a possible `format_version 14`
([`docs/FORMAT_V14_PLAN.md`](docs/FORMAT_V14_PLAN.md)). None exploitable._

### #81 — [MEM-8] Key material leaked into immutable objects that cannot be wiped
- **severity:** low · [GitLab #81](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/81)
- Reclassified LOW; inherent Python limitation. `get_bytes`/`get_as_str` and KDF `.derive()` returns produce immutable bytes/str that can't be zeroed. Mitigation: steer callers to `get_bytearray()`. A true fix needs a C-extension / bytearray-only end-to-end. Defer.

### #82 — [MEM-9] 'Guard pages' are in-band canaries only, checked lazily
- **severity:** low · [GitLab #82](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/82)
- Reclassified LOW; partly mitigated by #60/#63. Canaries are software/in-band (no real mprotect guard pages), but the block is now mlock'd + madvise(MADV_DONTDUMP) with key material inside it. Remaining: 'software canaries, not hardware guard pages'. Real guard pages = large rewrite, low marginal benefit.

### #83 — [PQC-3] KEM shared secret keyed through bare SHA-256 (no KDF, no domain separation, no transcript binding)
- **severity:** low · [GitLab #83](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/83)
- **Already partly fixed.** `PQCipher._derive_symmetric_key` (`pqc.py:426-453`) uses
  **HKDF-SHA256 with algorithm-name domain separation for `format_version >= 12`**; only
  **default-v9** non-streaming PQC files still use bare `sha256(shared_secret)`, and no
  version yet binds the KEM ciphertext. The derivation is sound regardless (uniform ML-KEM
  output; ciphertext implicitly bound via AEAD failure) — no exploitable gain. Remaining
  hygiene (default-v9 → HKDF, + ciphertext-transcript binding) is format-breaking; pre-staged
  for `format_version 14` — see [`docs/FORMAT_V14_PLAN.md`](docs/FORMAT_V14_PLAN.md) §3.3.

### #100 — [KDF-8] Missing length separation in seed/hash inputs (canonicalization ambiguity)
- **severity:** low · [GitLab #100](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/100)
- The KDF seed is a raw concat `password + salt (+ hsm_pepper)` (`crypt_core.py:1206`/`1208`,
  sized at `1163-1164`), plus per-round `sha256(salt + str(i))`. Canonicalization-ambiguous
  but **non-exploitable** (tool-generated fixed-length salt → boundary not attacker-controllable).
  v13's domain-separation work **deliberately left this input unchanged** (`crypt_core.py:1739-1740`:
  "cannot duplicate"). Length-prefixing is format-breaking (changes every derived key) and the
  highest-cost change in the codebase for zero exploitable gain — pre-staged for
  `format_version 14`, see [`docs/FORMAT_V14_PLAN.md`](docs/FORMAT_V14_PLAN.md) §3.2. Do it
  opportunistically at the next format bump.


## Resolved (23)

_Single-ref rows show the `feature/v1.4.x-development` commit; each such fix was also
forward-ported to `feature/v1.5.x-development` per the project workflow. Rows with both
refs listed name the commit on each branch explicitly. This tracker is maintained on both
branches._

| # | Code / title | Fix commit (v1.4.x) |
|---|---|---|
| [#59](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/59) | [KDF-1] Balloon negligible memory-hardness at default params | **superseded by M3** (`_apply_balloon_security_defaults`, crypt_core.py): encrypt-time unset `space_cost`→65536, persisted; explicit sub-floor warned. Residual 16s are dead convenience fns / GUI presets (M3 warns) — left by decision 2026-07-07 |
| [#66](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/66) | [CLI-3] Plugin top-level code exec'd in main process, gated only by an AST blocklist | `055036b1` (merge `feature/plugin-signing-14x`: signature-gated plugin loading) |
| [#74](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/74) | [IO-4] os.umask() process-global race in file/dir creation | v1.4.x `48a3e207`, v1.5.x `e6c8a54b` — explicit per-component mkdir+chmod / os.open+fchmod, no global umask |
| [#79](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/79) | [MEM-6] Multi-pass / explicit_bzero wiping is dead code | v1.4.x `997a6c00`, v1.5.x `ebb34c44` — remove dead cold-boot copy path from secure_memzero |
| [#80](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/80) | [MEM-7] secure_memzero reports success while zeroing only a copy | v1.4.x `997a6c00`, v1.5.x `ebb34c44` — non-in-place types return False (honest), mirror M10 |
| [#88](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/88) | [CLI-5] Subprocess children inherit the full environment | `b5070e3a` scrub RandomX probe subprocess env, absolute interpreter |
| [#90](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/90) | [CORE-10] constant_time_pkcs7_unpad has data-dependent branches | `1d3b57b6` branchless unpad; reject padding > data length |
| [#91](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/91) | [CORE-7] Cascade auth-failure classification leaks layer info | `9151135a` type-based cascade auth classification, layer-agnostic errors |
| [#92](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/92) | [CORE-8] verify_mac `associated_data` parameter is a no-op | `d695d78f` remove no-op associated_data parameter from verify_mac |
| [#93](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/93) | [CORE-9] Legacy XChaCha nonce_format=1 advertises 192-bit but funnels to 96 | `4139915d` stop describing nonce_format=1 as 192-bit/spec-compliant |
| [#94](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/94) | [IO-5] JSON nesting-depth limit enforced only after json.loads | `1751f11c` enforce JSON nesting depth before parse, map RecursionError |
| [#95](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/95) | [IO-6] 64-bit per-file streaming nonce prefix | v1.4.x `a0a5357d`, v1.5.x `5f0a8b02` — widen 8→16 bytes; **not** format-breaking (HKDF-derived, metadata-stored prefix), older files still decrypt |
| [#96](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/96) | [IO-7] Streaming decrypt writes plaintext before trailer HMAC verifies | `07509df1` stage streaming decrypt output, rename after trailer HMAC |
| [#97](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/97) | [KDF-10] CommonPasswordChecker custom-path branch does not set loaded flag | `dcd81033` make custom+embedded password-list semantics explicit |
| [#98](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/98) | [KDF-6] Key fingerprint lacks domain separation / algorithm binding | `090f71c2` v2 identity fingerprint with domain separation + algorithm binding |
| [#99](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/99) | [KDF-7] Config can select only non-stretching KDFs (HKDF-only) | `73be3409` reject HKDF-only key-derivation configs at encryption time |
| [#103](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/103) | [MEM-11] supports_madv_dontdump set True without a real check | `487e642f` really probe MADV_DONTDUMP, page-align madvise, check returns |
| [#104](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/104) | [MEM-12] Irreversible global RLIMIT_CORE hard-limit drop on allocation | `5fad6116` stop dropping RLIMIT_CORE hard limit on every allocation |
| [#105](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/105) | [MEM-13] Debugger 'detection' is security theater | `eb96f093` mark debugger detection advisory-only, drop countermeasure theater |
| [#106](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/106) | [MEM-14] secure_erase_system_memory writes /proc/sys/vm/drop_caches | `79115dc4` remove misleading drop_caches write |
| [#107](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/107) | [PQC-10] KEM/DSA keys/ciphertexts used without length pre-validation | `1048ee47` pre-validate KEM/DSA input lengths before liboqs |
| [#109](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/109) | [PQC-9] check_pqc_support fabricates a 'supported' list on error | `9510b75a` report true mechanism list, no fabrication |

### #89 — [CLI-6] In-memory 'secure clear' of password strings is a no-op — **RESOLVED 2026-07-07**
- **severity:** low · [GitLab #89](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/89)
- The CLI pseudo-wipe (`pwd = "\x00"*len(pwd)`) was already removed from `crypt_cli.py` and guarded by `test_cli_password_wipe.py`. On follow-up the **same bug-class was found in `keystore_utils.py`** (`store_pqc_key_in_keystore` cleanup): a fallback `encrypted_private_key = b"\x00" * len(...)` that rebinds a fresh zero-filled bytes object and never overwrites the original immutable buffer (also dead code — `secure_memzero` handles immutable bytes without raising). Removed the misleading rebind; `encrypted_private_key` is always `None`/immutable bytes (base64.b64decode output) so dropping the reference is all that's possible. Broadened the regression test to scan **all** modules (comparison-safe regex so the all-zero pepper `==` checks in `crypt_core.py` are not flagged). crypto-reviewer: approved (no wiping guarantee weakened, no mutable-buffer path missed).
- **Fixed on both branches:** `feature/v1.4.x-development` `d014fd1f`, `feature/v1.5.x-development` `f1b529ba`. Full suites green (v1.4.x 3131 passed; v1.5.x 5472 passed). Both pushed to origin.

---

## Suggested next steps

**No findings remain that are fixable in place.** The review is effectively closed; what
remains is optional, non-exploitable, and format-gated.

1. **#100 + #83** — the only remaining actionable findings, both format-breaking with no
   exploitable gain. Do **not** cut a format bump solely for them. Land the pre-staged
   [`docs/FORMAT_V14_PLAN.md`](docs/FORMAT_V14_PLAN.md) opportunistically the next time a
   `format_version` bump is required for a functional reason (fold them in as free hygiene).
   If a clean bill is ever forced, ship **#83-only** (cheap, self-contained).
2. Leave the inherent-limitation items (**#81**, **#82**) unless a C-extension/bytearray-only
   rework is on the table.

_(Non-breaking hardening done — #79/#80, #74, and #95 (found not to be format-breaking after
all); #59 superseded by M3. See Resolved.)_
