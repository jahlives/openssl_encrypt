# Pre-staged spec — `format_version 14` (findings #100 KDF-8 and #83 PQC-3)

**Status: DEFERRED / pre-staged. Not scheduled.** This is a ready-to-implement
spec, not committed work. Per the 2026-07-07 design review, a v14 bump is **not
warranted on its own** — both findings are non-exploitable, #83 is already fixed
for `format_version >= 12`, and v13 deliberately left #100's line unchanged. Land
this opportunistically the next time a format bump is required for an independent
functional reason (fold #100 + #83 in as free hygiene and pay the format tax once).
If a "clean bill" is ever forced, ship **#83-only** (cheap, self-contained).

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

## Critical files
- `openssl_encrypt/modules/crypt_core.py` — seed build 1163-1208, per-round salts, shared XOR
  inputs 2787/2245, `_indep_xor_component_salt` 1732-1759, version stamping 6177/6982/7276,
  PQCipher construction 6524-6542/10378
- `openssl_encrypt/modules/pqc.py` — `_derive_symmetric_key` 426-453, KEM sites 610/796
- `openssl_encrypt/modules/pqc_adapter.py` — shared-secret + ciphertext sites 279/286/415/421
- `openssl_encrypt/modules/crypt_cli.py` — version selection 7064-7071/7298-7304/7939-7945/
  9261-9263; allow-list 341
- `openssl_encrypt/unittests/test_format_v13_xor_domsep.py` — golden-vector / cross-line pattern
