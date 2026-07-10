# Pre-staged spec — `format_version 14` (findings #100 KDF-8 and #83 PQC-3, plus KDF-cascade audit M1/M2)

**Status: DEFERRED / pre-staged. Not scheduled.** This is a ready-to-implement
spec, not committed work. Per the 2026-07-07 design review, a v14 bump is **not
warranted on its own** — both findings are non-exploitable, #83 is already fixed
for `format_version >= 12`, and v13 deliberately left #100's line unchanged. Land
this opportunistically the next time a format bump is required for an independent
functional reason (fold #100 + #83 in as free hygiene and pay the format tax once).
If a "clean bill" is ever forced, ship **#83-only** (cheap, self-contained).

**Addendum 2026-07-09:** the KDF-cascade audit (crypto-reviewer, against
`docs/KDF_CHAIN_SECURITY_RESEARCH.md`) added two format-affecting findings —
**M1** (scrypt 256-bit intermediate truncation) and **M2** (default v9 path is a
pure sequential cascade, weakest-link floor). Both ride the same v14 bump; see
**section 6**. They strengthen the case for v14 but still do not force it on
their own (M1's floor is still 2^256; M2 is defense-in-depth, not an active
break). If v14 proceeds, M1 and M2 are **in scope alongside #100 + #83**.

**Decision 2026-07-10:** M2 is **decided — Option A**: independent-XOR becomes
the default topology for v14 writes. Sequential-XOR (`--use-xor-composition`)
remains a supported opt-in but stays **pinned at format_version 13**; the
whole-chain HKDF-finalization fallback is **rejected**. Under this topology no
v14 write path uses the sequential scrypt stage, so **M1 is closed for v14
writes by construction** (the independent scrypt component already derives
`dklen=key_length`). See sections 6.2/6.3 for the updated specs.

_Line references are against `feature/v1.5.x-development` as of 2026-07-07; v14 would
land on the development line. Re-verify before implementing — line numbers drift._

---

## 1. Verified current state

**Format-version selection (no single "current version" constant).**
- `encrypt_file(..., format_version=9)` default — `crypt_core.py:5395`.
- CLI selects per invocation (`crypt_cli.py:7064-7071`, dup at `7298-7304`, `7939-7945`):
  `--independent-xor` / `--use-xor-composition` → **13**, else → **9**. Rekey forces 13
  (`crypt_cli.py:9261-9263`).
- Streaming forces **12** (`crypt_core.py:5822`, `6102`, `6137`).
- Unsafe cancelling XOR versions (8/10) refused for new writes (`crypt_core.py:5457-5461`).
- Net: a plain non-streaming non-XOR file — including a **default PQC/hybrid file** —
  is written as **v9**.
- Decrypt reads `metadata.get("format_version", …)` (`crypt_core.py:8211`, `9167`, `4752`,
  `7545`) and threads it into every derivation function, so a gate inside a derivation
  function is automatically backward-compatible.

**#100 — KDF seed.** `multi_hash_password` (`crypt_core.py:1056`, already receives
`format_version`):
- buffer sized to exact concat: `initial_size = len(password)+len(salt)+pepper_len`
  (`crypt_core.py:1163-1164`);
- raw concat: `secure_memcpy(hashed, password + salt + hsm_pepper)` / `password + salt`
  (`crypt_core.py:1206`, `1208`);
- per-round salt `sha256(salt + str(i).encode())` at `crypt_core.py:1403,1413,1460,1471,
  1521,1556,1566` (hash stages) and `3017,3152,3274,3390` (Argon2/Balloon/Scrypt/PBKDF2);
- shared XOR input `sha256(password + salt)` at `crypt_core.py:2787` (sequential) and
  `2245-2254` (independent). `generate_key` (`2591`) and `generate_key_independent_xor`
  (`2128`) both receive/forward `format_version`.
- v13's `_indep_xor_component_salt` (`crypt_core.py:1732-1759`) fixed per-component
  cancellation; its docstring (`1739-1740`) records that the shared `SHA256(pw||salt)`
  and initial-hash inputs were **intentionally left unchanged** — exactly #100's residual.

**#83 — KEM symmetric key (already partly fixed).** Consolidated into
`PQCipher._derive_symmetric_key` (`pqc.py:426-453`):
- `format_version >= 12` → **HKDF-SHA256**, `length=key_length`, `salt=None`,
  `info=b"openssl_encrypt-kem-key-" + algorithm_name` (`pqc.py:442-451`);
- else → `hashlib.sha256(shared_secret).digest()` (`pqc.py:453`).
- Call sites: `pqc.py:610`, `796`; `pqc_adapter.py:286`, `421`. `format_version` threaded
  via `PQCipher(...)` on encrypt (`crypt_core.py:6524,6536,6542`) and decrypt
  (`crypt_core.py:6715,6725,10378`).
- So v12/v13 PQC files already use HKDF; only **default-v9** PQC files use bare SHA-256,
  and **no version binds the KEM ciphertext**. The password-wrap path
  (`asymmetric_core.py:216`) is separate and already fixed — out of scope.

## 2. Recommendation (why deferred)

- **#100:** non-exploitable (fixed-length tool-generated salt → boundary not
  attacker-controllable; finding rates it "impractical"), already partly addressed and
  consciously left by v13. A v14 seed change is the **highest-cost** change in the
  codebase (core stretch loop, all four memory-hard salt sites, both XOR inputs, every
  per-round salt; full algorithm × KDF golden re-pin; cross-line byte-identity).
- **#83:** sound already (uniform ML-KEM output; ciphertext implicitly bound via AEAD
  failure). HKDF+domain-separation already shipped for v12/v13; only default-v9 + a
  ciphertext-binding nicety remain. Small surface, but still "no exploitable gain."
- **Verdict:** keep both as accepted LOW residuals; pre-stage this spec. If forced,
  #83-only as v14.

## 3. v14 specification (only if the bump proceeds)

### 3.1 Version selection & stamping
- Add `LATEST_STABLE_FORMAT_VERSION = 14`. Make the CLI default-selection blocks
  (`crypt_cli.py:7064-7071` + clones `7298-7304`, `7939-7945`) emit **14** where they emit
  **9** (plain) and **14** where they emit **13** (XOR; v14 carries `xor_mode` like v13).
  Bump streaming's forced value to **14** (`crypt_core.py:5822,6102,6137`) so streaming PQC
  also gets #83.
- Stamp `metadata["format_version"]=14`; extend the `== 13` `xor_mode` stamping
  (`crypt_core.py:6177,6982,7276`) to `>= 13`.
- Register 14 in the version allow-list / schema registry (unregistered versions are now
  rejected — verify `crypt_cli.py:341` and the registry module).

### 3.2 #100 — length-prefixed KDF seed (gate `format_version >= 14`)
Canonical TLV seed, replacing the raw concat at `crypt_core.py:1206`/`1208` (and the
size calc at `1163-1164`):
```
seed  = LP(password) || LP(salt) || LP(hsm_pepper)
LP(x) = uint32_be(len(x)) || x          # 4-byte BE length prefix, then bytes
pepper absent -> LP(b"") = 00 00 00 00  # always emit the field, never omit
```
- Fixed field order password, salt, pepper; every field length-prefixed (incl. empty
  pepper) so no field-set concatenation can alias another. Endianness pinned (BE).
- v14 buffer size: `initial_size = 12 + len(password) + len(salt) + pepper_len`; keep the
  BLAKE3-64 min-size logic (`crypt_core.py:1187-1198`) otherwise unchanged.
- **Per-round salt** (the 11 sites above): under v14 replace `sha256(salt + str(i))` with
  `HKDF-SHA256(ikm=salt, salt=None, length=32,
  info=b"openssl_encrypt.kdf.v14.round:" + algo_name + b":" + uint32_be(i))`.
  Keep the `< 14` branch returning the exact current bytes.
- **Shared XOR input** (`crypt_core.py:2787`, `2245-2254`): under v14 hash the LP seed —
  `sha256(LP(password) || LP(salt))` — closing the residual v13 left open.
- Shape: add `_v14_seed_encode(password, salt, hsm_pepper) -> bytes` next to
  `_indep_xor_component_salt` (`crypt_core.py:1732`); branch on `format_version >= 14` at
  each site. No signature changes (functions already receive `format_version`).

### 3.3 #83 — HKDF with KEM-ciphertext transcript binding (gate `format_version >= 14`)
Add a `kem_ciphertext: bytes = None` param to `PQCipher._derive_symmetric_key`
(`pqc.py:426-453`) and pass the encapsulation ciphertext from the four call sites
(available: `pqc_adapter.py:279` encrypt / `415` decrypt input; native `pqc.py:605-610` /
`726`). New branch:
```
if fv >= 14:
    HKDF(SHA256, length=key_length, salt=None,
         info = b"openssl_encrypt.kem.v14|" + algorithm_name
                + b"|" + encryption_data                       # bind the AEAD choice
                + b"|ct=" + sha256(kem_ciphertext).digest())   # bind the KEM transcript
elif fv >= 12: ...   # unchanged v12/v13 HKDF
else: ...            # unchanged bare-SHA256 for < 12
```
- Bind the ciphertext via `sha256(ct)` inside `info` (keeps `info` bounded; ML-KEM ct is
  ~1–1.5 KB). `info`-binding ≡ AAD-binding here since the AEAD already authenticates the
  payload — simpler than threading AAD through every cipher branch.
- Fold `encryption_data` (AEAD name) into `info`. Leave `salt=None`. Do NOT touch the
  `asymmetric_core.py` password-wrap path.
- For `fv >= 14`, a missing `kem_ciphertext` must **raise**, not silently fall back.

### 3.4 Backward-compatible decrypt
No new dispatch code: files `< 14` hit existing `else`/`>= 12`/`< 12` branches unchanged;
version already flows into `multi_hash_password`, `generate_key*`, and `PQCipher`. Add
explicit `< 14` fixtures (v9/v11/v12/v13, plain + PQC) proving byte-identical legacy
derivation.

### 3.5 Golden-vector / cross-line strategy
Mirror v13 exactly (`test_format_v13_xor_domsep.py:48`, `100-109`):
- `test_format_v14_seed_lengthsep.py`: pin `GOLDEN_KEY_HEX` for a minimal deterministic
  config (one hash stage + Argon2, fixed 16-byte salt); assert distinct from v13,
  deterministic, `< 14` no-op, full round-trip; include an independent `_ref_v14_seed(...)`
  spec cross-check.
- `test_format_v14_kem_binding.py`: pin the derived key for fixed shared-secret + fixed
  ciphertext; assert differs from v12/v13 HKDF and bare-SHA256; wrong-ct → different key.
- Cross-line byte-identity: generate golden hex once, assert identically on both branches;
  pin `info` strings and field widths as named constants with a "do not change" comment
  (as `_indep_xor_component_salt` does at `crypt_core.py:1745-1746`).
- Extend matrix suites (`test_salt_derivation_versions.py`, `test_streaming_format_version.py`,
  `test_pqc.py`, `test_format_v13_*`) with a v14 row per algorithm × KDF.

### 3.6 Branch strategy
- **#83 half:** v12 HKDF ancestor exists on both lines → cross-line cheaply; land on both
  if 1.4.x still maintained.
- **#100 half:** prefer **1.5.x-only writes** (1.4.x is maintenance; #100 non-exploitable)
  to avoid doubling golden-vector maintenance — unless strict cross-line write-compat is
  wanted.
- Coupling: if 1.5.x **writes** v14, 1.4.x must at least **read** it — so land the
  decrypt-side `>= 14` gates on both lines even if writing stays 1.5.x-only.

## 4. Risks / migration
- Golden-vector blast radius (#100): the seed change alters every derived key; an off-by-one
  in field width/order silently changes all vectors. Guard with the independent-reimpl spec
  test and full-matrix pinning before wiring the CLI default.
- Cross-line drift: any `info`/endianness divergence between branches breaks the other line's
  files. Pin as named constants; forbid edits in comments.
- Default-version flip (9→14): update downstream hard-coded version asserts (tests, GUI,
  mobile `mobile_crypto_core.py`, `check_file_format.py`). Grep first.
- `_derive_symmetric_key` signature change: apply `kem_ciphertext` to all four call sites and
  any native override; missed site must raise for `fv >= 14`.
- Streaming forces the version — move the forced value and CLI default together (avoid the
  documented v11/v12 mismatch class).

## 5. TDD sequence
1. Failing spec tests: `_v14_seed_encode` (TLV layout, empty pepper, ambiguity pairs now
   distinct); `_derive_symmetric_key` v14 (ciphertext binding, distinct from v12).
2. Implement `_v14_seed_encode` + `>= 14` at seed sites (`1163-1164`, `1206`/`1208`) and
   shared-input sites (`2787`, `2245-2254`); HKDF-based round salts under v14.
3. Implement `_derive_symmetric_key` v14 branch + thread `kem_ciphertext` through 4 sites.
4. `< 14` legacy no-op tests; v9/v11/v12/v13 fixtures decrypt byte-identically (regression).
5. Round-trip tests (plain, cascade, PQC-KEM, streaming) at v14.
6. Pin `GOLDEN_KEY_HEX` for #100 and #83; add cross-line assertion note.
7. Flip CLI default-selection + clones, streaming force value, `xor_mode` stamping, schema
   registration.
8. Update matrix suites + hard-coded version asserts.
9. CHANGELOG under `[1.5.0] - TBD`; update `SECURITY_REVIEW_REMAINING.md` (#100, #83 resolved).
10. Full suite on 1.5.x (and 1.4.x if cross-lined); verify golden vectors match across branches.

## 6. Addendum (2026-07-09) — KDF-cascade audit findings M1 & M2

Source: crypto-reviewer audit of the KDF cascade against
`docs/KDF_CHAIN_SECURITY_RESEARCH.md` (sequential-chain robustness literature).
_Line references in this section are against `feature/v1.4.x-development` as of
2026-07-09, spot-corrected 2026-07-10 by the follow-up M2 review — re-verify on
the line that lands v14; line numbers drift._

### 6.1 Verified current state

**M1 — scrypt sequential stage truncates the intermediate to 256 bits (Medium).**
- `crypt_core.py:3807` hardcodes `length=32` for scrypt in the sequential path;
  every other KDF stage there derives `hash_len = key_length` (argon2 `3485`,
  balloon `3654`, HKDF/PBKDF2 `key_length`).
- If scrypt is the last enabled KDF before an AES-SIV (64-byte) or
  Threefish-512/1024 (64/128-byte) key, all key entropy funnels through a
  256-bit intermediate; the downstream HKDF expansion (`4379-4402`) / AES-SIV
  `sha512` (`4359`) cannot restore entropy above 2^256.
- Exactly the "narrow intermediate state" failure mode of the research doc
  (entropy preservation per stage); floor remains 2^256, so Medium, not High.

**M2 — default encrypt path (v9) is a pure sequential cascade, weakest-link
floor (Medium).**
- `use_xor_composition = format_version >= 10 or == 8` (`crypt_core.py:3250`);
  dispatch at `crypt_core.py:6703-6716` routes only `xor_mode="independent"` /
  `fv >= 11` to `generate_key_independent_xor`. Default v9
  (`crypt_cli.py:8324`, `8607`, `9267`) gets the plain chain: the final stage's
  raw output **is** the key (`crypt_core.py:4351-4402`).
- Per Herzberg (ePrint 2002/135; research doc findings #1/#3): the sequential
  chain's cryptographic floor is the weakest link — a break in the final stage
  (usually PBKDF2-SHA256) bounds output quality regardless of a strong
  Argon2/scrypt earlier. The provably robust remedy already exists in-tree
  (`generate_key_independent_xor`, `crypt_core.py:2610`, correct per audit) but
  is opt-in only (`--independent-xor` / v13).
- **Blast-radius correction (verified 2026-07-10):** a bare invocation (no
  KDF/hash args) loads the STANDARD template, which forces
  `independent_xor=True` (`crypt_cli.py:7020-7032`); the `--standard` /
  `--paranoid` templates do the same (`crypt_cli.py:6981-6982`). The v9
  sequential cascade is therefore the default only for **user-supplied custom
  KDF/hash configs** (else-branch at `crypt_cli.py:7033`), not for the
  out-of-box default or the security templates. M2 stands, with a narrower
  blast radius than "all default writes".

**Sequential-XOR mode (`--use-xor-composition`, `xor_mode="sequential"`) —
verified 2026-07-10.** It is a **hybrid**, not an independent combiner: stages
still chain (`password = SecureBytes(result)` at
`crypt_core.py:3579/3716/3842/3956/4057/4135`) while a
`normalize_to_key_length_secure` snapshot of each stage is appended to an XOR
accumulator (`crypt_core.py:3313/3628/3757/3858/3972/4074/4152`) and folded at
the end (`4282-4308`). It flows through the **same** scrypt `length=32` site
(`3807`) — **M1 applies to sequential-XOR writes too**. Its v13 fix was only
the last-stage self-cancellation guard (`crypt_core.py:4295`;
`test_format_v13_sequential_xor.py`); `_indep_xor_component_salt` is called
only from `generate_key_independent_xor` — zero call sites in the sequential
path. Security floor: better than the plain chain (a break confined to the
final stage no longer bounds the key alone, since every stage's snapshot is
mixed in) but **not** the strongest-link robust-combiner guarantee — stages
still chain, so an entropy-collapsing stage starves all later snapshots.
Document it as "opt-in hybrid mode; independent-XOR is the
recommended/strongest topology". By contrast, the independent-XOR scrypt
component derives `dklen=key_length` (`crypt_core.py:2458`, via
`compute_kdf_independent`) — no M1 truncation; argon2/balloon/HKDF components
are likewise full-length (`2420`, `2505-2512`, `2532`).

### 6.2 M1 specification (resolved by the M2 topology decision, 2026-07-10)
Under the decided M2 option (6.3) **no v14 write path uses the sequential
scrypt stage**: plain defaults become v14 independent-XOR, and sequential /
sequential-XOR writes stay pinned `< 14`. M1 is therefore closed for v14
writes by construction:
- The independent-XOR scrypt component already derives `dklen=key_length`
  (`crypt_core.py:2458`, verified 2026-07-10) — no code change needed; the
  other components are likewise full-length (argon2 `hash_len=key_length`
  `2420`, balloon normalized via HKDF `2505-2512`, HKDF `length=key_length`
  `2532`).
- The sequential scrypt `length=32` (`crypt_core.py:3807`) stays byte-identical
  for all `< 14` writes and legacy decrypt — do **NOT** change it.
- The previously specified `>= 14` gate in the sequential stage is **dropped**
  (dead code under the decided topology). If a future version ever reopens
  sequential writes at `>= 14`, this gate must be re-introduced first.
- Golden vectors: extend the v14 matrix (section 3.5) with an independent-XOR
  scrypt-final × {AES-SIV, Threefish-512, Threefish-1024} row asserting
  full-length derivation; pin one `< 14` sequential scrypt-final legacy vector
  proving byte-identity (guards against an accidental "fix" of `3807`).

### 6.3 M2 specification — DECIDED 2026-07-10: Option A
**Decision: make independent-XOR the default topology for v14 writes**, with
sequential-XOR retained as a v13-pinned opt-in.

- The CLI default-selection blocks (section 3.1) emit 14 with
  `xor_mode="independent"` where they previously defaulted to plain v9
  (current mapping: `crypt_cli.py:8317-8324`, clones `8600-8607`/`9260-9267`
  on 1.4.x). Rekey already forces the XOR path (`crypt_cli.py:9261-9263` on
  1.5.x), so this aligns defaults with the recommended mode; total KDF work is
  unchanged (same components, run independently instead of chained). The
  attacker's per-guess cost is the sum of component costs in both topologies —
  no work-factor regression.
- **Sequential-XOR stays a supported write mode, pinned at v13:**
  `--use-xor-composition` continues to emit `format_version=13` +
  `xor_mode="sequential"` exactly as today; v14 carries `xor_mode="independent"`
  only. Consequences: no M1 fix, no section-3.2 seed gates, and no new golden
  vectors for the sequential path (the sequential path's initial hash at
  `crypt_core.py:3311` is a *separate* site from the independent one at `2737`
  and stays untouched); the existing v13 sequential golden
  (`test_format_v13_sequential_xor.py`) remains the pin and must stay
  byte-identical cross-line.
- Any new write-version gate (e.g. a `LATEST_STABLE_FORMAT_VERSION` check)
  must **not** refuse fv-13 sequential-XOR writes; only the unsafe cancelling
  versions 8/10 stay refused (`crypt_core.py:5457-5461`).
- **Rejected fallback (recorded 2026-07-10):** whole-chain HKDF finalization
  (`HKDF-SHA256(ikm=chain_output, info=b"openssl_encrypt.kdf.v14.finalize:" +
  algo_name, length=key_length)` at the key-formatting sites
  `crypt_core.py:4351-4402`). Rejected because it is a deterministic function
  of the same chain output: it cannot add entropy or robustness, leaves the
  weakest-link floor and the non-injective-stage failure mode fully intact,
  and leaves M1 in the live default write path. It would have been raw-output
  hygiene only.
- **Decrypt side (verified 2026-07-10):** dispatch is fully metadata-driven —
  `xor_mode = metadata.get("xor_mode", "sequential")` at
  `crypt_core.py:10493`, routing at `10505`/`10540-10542`; rekey/streaming at
  `8914`/`8992`/`9142`; no read path consults an encrypt-side default. All
  v8–v13 files of all three topologies (plain chain, sequential-XOR,
  independent-XOR) decrypt byte-identically regardless of the default flip.
- Changelog/docs framing: describe Option A as a robust combiner for the
  PRF-type property a KDF needs, explicitly noting the XOR concrete-security
  caveats (research doc findings #6/#7) — do not overstate the guarantee. The
  shared-component-seed residual #100 (`sha256(password+salt)`,
  `crypt_core.py:2737` on 1.4.x) is either folded in via the section-3.2 seed
  change or explicitly re-accepted in the same bump.

### 6.4 Additions to the TDD sequence (section 5)
- Failing tests first: v14 default writes carry `format_version=14` +
  `xor_mode="independent"`; v14 independent-XOR scrypt-final derives full
  `key_length` bytes (M1); `--use-xor-composition` still stamps
  `format_version=13` + `xor_mode="sequential"` after the default flip;
  `< 14` regression fixtures byte-identical (incl. one sequential
  scrypt-final legacy vector).
- Fold into steps 5-8 of section 5 (round-trips, golden pinning, CLI default
  flip, matrix suites). CHANGELOG: M1 and M2 are **Security** entries → all
  four changelog files per changelog discipline.

### 6.5 Added risks
- M1: with the sequential stage deliberately left untouched, the risk inverts —
  an accidental "fix" of `crypt_core.py:3807` would change derived keys for
  every existing sequential scrypt file; the pinned `< 14` sequential legacy
  vector (6.2) is the guard.
- M2 flips the default topology: downstream tools/tests that assert `xor_mode`
  absence, plain-v9 metadata, or "any XOR opt-in ⇒ v13" will break — grep
  tests/GUI/`mobile_crypto_core.py`/`check_file_format.py` before flipping
  (same class as the 9→14 default-flip risk in section 4).
- A v14 sequential(-XOR) file must never exist: assert no CLI/API path can
  emit `format_version >= 14` with `xor_mode="sequential"` (or the plain
  chain) — otherwise the dropped M1/seed gates for the sequential path are
  silently missing.
- Sequential-XOR degeneracy residual (Low, recorded 2026-07-10): only the
  single-stage self-cancellation case (`crypt_core.py:4295`) is test-covered;
  there is no proof that no adversarial hash_config can make two accumulator
  snapshots coincide. Acceptable for an opt-in mode; note in docs, not a
  blocker.

## Critical files
- `openssl_encrypt/modules/crypt_core.py` — seed build 1163-1208, per-round salts, shared XOR
  inputs 2787/2245, `_indep_xor_component_salt` 1732-1759, version stamping 6177/6982/7276,
  PQCipher construction 6524-6542/10378; **M1/M2 (1.4.x refs, re-verified 2026-07-10):**
  scrypt length 3807, independent scrypt component dklen 2458, XOR-composition flag 3250,
  encrypt dispatch 6699-6767, decrypt dispatch 10493-10542, key formatting 4351-4402,
  `generate_key_independent_xor` 2610, `_indep_xor_component_salt` 2180-2207,
  sequential-XOR accumulator 4282-4308 (v13 self-cancel guard 4295)
- `openssl_encrypt/modules/pqc.py` — `_derive_symmetric_key` 426-453, KEM sites 610/796
- `openssl_encrypt/modules/pqc_adapter.py` — shared-secret + ciphertext sites 279/286/415/421
- `openssl_encrypt/modules/crypt_cli.py` — version selection 7064-7071/7298-7304/7939-7945/
  9261-9263; allow-list 341; **M2 (1.4.x refs, re-verified 2026-07-10):** XOR/version
  mapping 8317-8324 (clones 8600-8607/9260-9267), template forcing 6981-6982/7020-7032
- `openssl_encrypt/unittests/test_format_v13_xor_domsep.py` — golden-vector / cross-line pattern
- `openssl_encrypt/unittests/test_format_v13_sequential_xor.py` — sequential-XOR golden +
  self-cancellation regression (must stay green and byte-identical)
