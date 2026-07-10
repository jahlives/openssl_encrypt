# Implementation plan — `format_version 14` on `feature/v1.4.x-development`

**Status: SCHEDULED 2026-07-10.** Execution plan for the pre-staged spec in
`docs/FORMAT_V14_PLAN.md` (referred to below as "the spec"). Scope decisions
(2026-07-10):

- **Scope: FULL v14** — #100 (TLV length-prefixed KDF seed), #83 (KEM HKDF +
  ciphertext transcript binding), M2 (independent-XOR default topology, Option
  A as decided in the spec §6.3) and M1 (resolved by the M2 topology, spec
  §6.2).
- **Branch strategy: 1.4.x first, full 1.5.x port after.** Both lines write
  and read v14; golden vectors must be byte-identical cross-line (v13
  pattern). This supersedes the spec §3.6 preference for 1.5.x-only #100
  writes.
- **Deliverable per phase:** TDD (failing tests first), crypto-reviewer gate
  before each feature commit, changelog per change, one feature per
  commit-boundary.

_All line references below were verified on `feature/v1.4.x-development` on
2026-07-10 (files: `openssl_encrypt/modules/crypt_core.py` = "core",
`openssl_encrypt/modules/crypt_cli.py` = "cli", `openssl_encrypt/modules/pqc.py`,
`openssl_encrypt/modules/pqc_adapter.py`). Line numbers drift — re-verify at
implementation time._

---

## 0. Critical deviation found during planning (2026-07-10)

**The spec §3.6 claim "#83: v12 HKDF ancestor exists on both lines" is WRONG
for 1.4.x.** Verified:

- 1.5.x has `PQCipher._derive_symmetric_key` with a `format_version >= 12`
  HKDF-SHA256 branch (`info=b"openssl_encrypt-kem-key-" + algorithm_name`)
  — confirmed via `git show origin/feature/v1.5.x-development:...pqc.py`
  (def at 426, gate at 442-446, call sites 614/800).
- 1.4.x derives the KEM symmetric key as **bare `sha256(shared_secret)`
  unconditionally**: `pqc.py:674` (encrypt), `pqc.py:944` (decrypt),
  `pqc_adapter.py:299` / `405`. There is **no** `_derive_symmetric_key`, no
  HKDF branch, and **no `format_version` threading into `pqc.py` /
  `pqc_adapter.py` at all** (grep returns zero hits).

**Suspected live cross-line incompatibility (pre-existing, independent of
v14):** 1.4.x can write v13 PQC files today (`--independent-xor` +
kyber/ml-kem → v13; nothing gates PQC out of the XOR opt-ins), and its
streaming path writes v12 (core:6691-6697). 1.5.x decrypting any v12/v13 PQC
file applies HKDF; 1.4.x wrote the key with bare SHA-256 → key mismatch →
decrypt failure (and vice versa for 1.5.x-written v12/v13 PQC files read by
1.4.x). **Phase 0 must confirm this empirically and fix it by backporting the
1.5.x consolidation.** If confirmed, it is a Security bug fix in its own
right, independent of v14.

---

## 1. Verified 1.4.x current state (implementation sites)

### crypt_core.py
| Item | Site(s) |
|---|---|
| `multi_hash_password(...)` (has `format_version=9` param) | def 1419-1427 |
| Seed buffer size `initial_size = len(password)+len(salt)+pepper_len` | 1528 |
| Raw seed concat `secure_memcpy(hashed, password + salt [+ hsm_pepper])` | 1567 (pepper) / 1569 (no pepper) |
| BLAKE3 min-64-byte buffer logic (keep unchanged) | 1524-1559 (esp. 1551-1553) |
| Per-round salt `sha256(salt + str(i).encode())` — hash stages (7 sites) | 1764, 1774, 1820, 1831, 1881, 1916, 1926 |
| Per-round salt — KDF stages (4 sites, `base_salt`) | 3544, 3679, 3801, 3940 |
| Shared XOR input `sha256(password+salt)` — independent path | 2737 |
| Shared XOR input — sequential path (**do not touch**, stays < 14) | 3311 |
| `generate_key` def (has `format_version=9`) | 3101-3112 |
| `generate_key_independent_xor` def (has `format_version=11`) | 2610-2622 |
| Independent scrypt component `dklen=key_length` (M1-safe already) | 2458 |
| Sequential scrypt `length=32` (**do not touch**, legacy bytes) | 3807 |
| `_indep_xor_component_salt` (v13 domain sep; pattern for new constants) | 2180-2207 |
| `encrypt_file(..., format_version=9)` default | def 6150-6175 |
| Streaming forces v12 on encrypt | 6691-6697; hardcoded again 6860, 6872, 6911 |
| Streaming decrypt gates **hardcode `== 12`** | 9868 (`_temp_format_version == 12 and ... streaming`), 10815 |
| `xor_mode` stamping | 4858-4861 (v11+/v8+10), `== 13` gates at 6947-6948, 7805-7808, 8095-8098 |
| Unsafe-version refusal (8/10) | `_UNSAFE_SEQUENTIAL_XOR_VERSIONS = (8, 10)` at 112; gate 6236-6241 |
| PQCipher construction (encrypt) — **no format_version passed today** | 7306-7311, 7317-7323 |
| PQC decrypt calls | 11147-11152, 11157-11159 |
| Encrypt/decrypt XOR dispatch (metadata-driven) | 6699-6767 / 10493-10542 |
| `LATEST_STABLE_FORMAT_VERSION` | **does not exist** on 1.4.x — introduce in Phase 1 |

### crypt_cli.py
| Item | Site(s) |
|---|---|
| Version selection `13 if independent else (13 if xor else 9)` (3 blocks) | 8318-8324, 8600-8607, 9260-9267 |
| Legacy-version branch in metadata extraction | 336 (`if format_version in [4, 5, 6, 7, 9]:`) |
| Registry imports (validation module `.registry`) | 988, 1048, 1056, 1082 |
| Template forcing `independent_xor=True` (STANDARD/PARANOID + bare default) | 6982, 7032 |
| Rekey version selection | 10660-10665 (`13 if independent else (13 if xor else None)`) |

### pqc.py / pqc_adapter.py (1.4.x)
Bare `sha256(shared_secret)`: `pqc.py:674` (encrypt), `pqc.py:944` (decrypt),
`pqc_adapter.py:299` / `405`. Encapsulation ciphertext is in scope at the
encrypt sites (`kem.encap_secret` at `pqc.py:576`, `668`) and at decrypt
(`kem.decap_secret(encapsulated_key)` at `pqc.py:622`) — thread it to the
derivation in Phase 3.

### Known breakage on default flip (grep-verified; re-grep in Phase 4)
- `unittests/test_format_v10.py:514-518` — `test_default_format_version_is_9_not_10`
  asserts `format_version == 9`.
- `unittests/test_salt_derivation_versions.py:84, 309` — assert new files are v9.
- `mobile_app/mobile_crypto_core.py:434` hardcodes `"format_version": 5` on its
  own write path — unaffected by the CLI flip, but confirm mobile can *read*
  v14 or document that it cannot.

### Existing test assets
- Golden-vector pattern: `unittests/test_format_v13_xor_domsep.py`
  (`GOLDEN_KEY_HEX` at line 48), `unittests/test_format_v13_sequential_xor.py`
  (golden at line 43 — must stay byte-identical).
- Matrix/legacy suites: `test_salt_derivation_versions.py`, `test_streaming.py`,
  `test_pqc.py`, `test_format_v10.py`, `test_format_v11_independent_xor.py`,
  `test_cross_version_v8_v10.py`.
- Fixture dirs exist only for v3/v4/v5 (+ special sets) under
  `unittests/testfiles/` — **no v9/v11/v12/v13 pre-encrypted fixtures**; they
  must be created (Phase 5).
- Current in-dev version: `[1.4.8] - Unreleased` (CHANGELOG.md:8;
  `version.py.template` VERSION_HISTORY last key `1.4.8`).

---

## 2. Phase plan

Ordering rationale: Phase 0 is a prerequisite for #83 and a standalone bug
fix; Phase 1 creates the version plumbing every later phase gates on; #100
(Phase 2) and #83 (Phase 3) are independent of each other; the default flip
(Phase 4) goes last so every v14 mechanism exists before anything writes v14
by default.

Every phase follows the unittest workflow: full-suite baseline to
`test_baseline.log` before the phase, full suite to `test_after.log` at the
phase boundary, diff for regressions (tiered policy: targeted-file pytest on
intermediate commits). Every phase ends with a crypto-reviewer run on the
diff before its feature commit. Before editing any site, check it is not
inside a `# START DO NOT CHANGE` block.

### Phase 0 — Backport #83's v12 HKDF consolidation from 1.5.x (bug fix)

1. **Reproduce first** (TDD for a bug fix): test that derives the KEM
   symmetric key for a v12/v13 PQC file the way 1.5.x does (HKDF-SHA256,
   `info=b"openssl_encrypt-kem-key-" + algorithm_name`) and asserts 1.4.x
   produces the same key — expected to FAIL against bare sha256. Plus an
   encrypt-on-1.4.x → decrypt-with-1.5.x-derivation round-trip equivalent.
2. Port from `origin/feature/v1.5.x-development:openssl_encrypt/modules/pqc.py`:
   `PQCipher._derive_symmetric_key` (fv ≥ 12 → HKDF; else bare sha256,
   byte-identical), `format_version` param on `PQCipher.__init__`, and the
   HKDF expansion helper if the port needs it (1.5.x lines 426-453, 612-614,
   800, 878+). Replace the four bare-sha256 sites (`pqc.py:674`, `944`,
   `pqc_adapter.py:299`, `405`) with `_derive_symmetric_key` calls.
3. Thread `format_version` into every `PQCipher(...)` construction:
   encrypt core:7306-7311, 7317-7323; find/instrument the decrypt-side
   constructions feeding core:11147-11159 (metadata `format_version` is in
   scope there). Mirror the 1.5.x call signatures exactly so the Phase 6 port
   is a no-op diff.
4. Regression tests: `< 12` files keep bare sha256 byte-identically (golden);
   v12 streaming PQC and v13 XOR PQC round-trip on 1.4.x; derived-key golden
   pinned to the 1.5.x value (cross-line byte-identity).
5. Changelog: **Security** (cross-line v12/v13 PQC compatibility fix) → all
   four changelog files. crypto-reviewer gate. **Commit** (this is a
   self-contained fix — commit before any v14 work; it must be
   cherry-pickable independently).

### Phase 1 — v14 version scaffolding (no behavior change for defaults)

1. Failing tests: registry/validation accepts `format_version=14`; a
   hand-stamped v14 metadata blob passes validation; `xor_mode` stamping
   fires for fv 14.
2. Add `LATEST_STABLE_FORMAT_VERSION = 14` in core (new constant — does not
   exist on 1.4.x; place near `_UNSAFE_SEQUENTIAL_XOR_VERSIONS`, core:112).
   Use it in the new selection code (Phase 4) instead of a literal.
3. Register 14 wherever 13 is registered: the `.registry` module (imported at
   cli:988/1048/1056/1082 — locate the version list/schema there), and audit
   the legacy branch at cli:336 for whether v14 needs a case.
4. Extend `xor_mode` stamping gates `== 13` → `>= 13` at core:6947-6948,
   7805-7808, 8095-8098 (leave 4858-4861 v8/10/11 logic untouched).
5. Confirm decrypt dispatch needs no change (metadata-driven,
   core:10493-10542) with a test: synthetic v14 + `xor_mode="independent"`
   metadata routes to `generate_key_independent_xor`.
6. Changelog (`### Changed`, CHANGELOG.md only — internal plumbing).
   crypto-reviewer gate. **Commit.**

### Phase 2 — #100: length-prefixed TLV seed (gate `fv >= 14`)

Spec §3.2 semantics; 1.4.x sites:

1. Failing spec tests first (`test_format_v14_seed_lengthsep.py`, mirroring
   `test_format_v13_xor_domsep.py`): `_v14_seed_encode` TLV layout
   (`LP(x) = uint32_be(len(x)) || x`; field order password, salt, pepper;
   empty pepper emits `00 00 00 00`); ambiguity pairs (e.g.
   `pw="ab", salt="c"` vs `pw="a", salt="bc"`) now derive distinct keys;
   independent `_ref_v14_seed(...)` reimplementation cross-check;
   `GOLDEN_KEY_HEX` for one minimal deterministic config (one hash stage +
   Argon2, fixed 16-byte salt); `< 14` byte-identical no-op; round-trip.
2. Implement `_v14_seed_encode(password, salt, hsm_pepper) -> bytes` next to
   `_indep_xor_component_salt` (core:2180); pin the `info`/width constants
   with do-not-change comments (v13 pattern, core:2193-2194).
3. Gate the seed sites on `format_version >= 14`: buffer size core:1528
   (v14: `12 + len(password) + len(salt) + pepper_len`), concat core:1567/1569
   → `_v14_seed_encode`. Keep BLAKE3 min-size logic (1551-1553) unchanged.
4. Per-round salts under v14 → `HKDF-SHA256(ikm=salt, salt=None, length=32,
   info=b"openssl_encrypt.kdf.v14.round:" + algo_name + b":" + uint32_be(i))`
   at the 7 hash-stage sites (1764, 1774, 1820, 1831, 1881, 1916, 1926) and
   4 KDF-stage sites (3544, 3679, 3801, 3940). `< 14` branches return the
   exact current bytes.
5. Shared XOR input, **independent path only** (core:2737): v14 →
   `sha256(LP(password) || LP(salt))`. The sequential site (core:3311) is NOT
   gated — add the guard test that no v14 write can reach the sequential path
   (spec §6.5).
6. Full-matrix golden pinning per algorithm × KDF (extend
   `test_salt_derivation_versions.py` with a v14 row) BEFORE any CLI default
   change. Changelog: **Security** → all four files. crypto-reviewer gate.
   **Commit** (split "seed encode + sites" / "round salts" into two commits if
   review size demands; feature boundary = both landed).

### Phase 3 — #83: v14 KEM ciphertext transcript binding (gate `fv >= 14`)

1. Failing tests first (`test_format_v14_kem_binding.py`): pinned derived key
   for fixed shared-secret + fixed ciphertext; differs from the v12/v13 HKDF
   and bare-SHA256 outputs; wrong ciphertext → different key; `fv >= 14` with
   missing `kem_ciphertext` → raises.
2. Extend the Phase-0 `_derive_symmetric_key` with
   `kem_ciphertext: bytes = None`; v14 branch per spec §3.3:
   `HKDF(SHA256, length=key_length, salt=None,
   info=b"openssl_encrypt.kem.v14|" + algorithm_name + b"|" +
   encryption_data + b"|ct=" + sha256(kem_ciphertext).digest())`.
   `fv >= 12` and `< 12` branches unchanged.
3. Thread the encapsulation ciphertext at all 1.4.x call sites: encrypt
   `pqc.py:668-674` (ct from `kem.encap_secret`, 668), decrypt `pqc.py:944`
   (ct = `encapsulated_key` input, 622), `pqc_adapter.py:299`/`405`.
   Do NOT touch the password-wrap path in `asymmetric_core.py`.
4. Round-trip v14 PQC (native + adapter + streaming-off), plus `< 14`
   regression. Changelog: **Security** → all four files. crypto-reviewer
   gate. **Commit.**

### Phase 4 — M2 default flip + M1 golden matrix + streaming bump

1. Failing tests first: default CLI write (custom KDF config, no XOR flags)
   stamps `format_version=14` + `xor_mode="independent"`;
   `--use-xor-composition` still stamps 13 + `"sequential"`;
   `--independent-xor` stamps 14 + `"independent"`; rekey writes 14
   independent; streaming writes 14; v14 independent scrypt-final derives
   full `key_length` (M1) for AES-SIV/Threefish-512/1024.
2. Flip the three CLI selection blocks (8318-8324, 8600-8607, 9260-9267) to
   `14 if independent else (13 if use_xor else 14)` with
   `xor_mode="independent"` for both 14 cases; rekey 10660-10665 → same rule.
   Use `LATEST_STABLE_FORMAT_VERSION`.
3. Streaming: bump the forced version (core:6691-6697) and the hardcoded 12s
   (6860, 6872, 6911) to 14, **and generalize the decrypt gates that
   hardcode `== 12`** (core:9868, 10815) to accept both 12 and 14 —
   1.4.x-specific trap, not in the spec. Extend `test_streaming.py`
   with v14 rows; keep a v12 streaming fixture decrypting unchanged.
4. Fix flagged assertions: `test_format_v10.py:514-518` (default is now 14),
   `test_salt_derivation_versions.py:84/309`; then re-grep the whole tree
   (`grep -rn "format_version.*9" unittests/ tools/ *.py`) for stragglers,
   plus any test asserting `xor_mode` absence on default writes.
5. M1 golden rows (spec §6.2): independent-XOR scrypt-final ×
   {AES-SIV, Threefish-512, Threefish-1024} full-length vectors; one `< 14`
   sequential scrypt-final legacy vector guarding core:3807.
6. Changelog: **Security** (M2 + M1) → all four files. crypto-reviewer gate.
   **Commit.**

### Phase 5 — legacy fixtures, full regression, release-notes hygiene

1. Create the missing pre-encrypted fixture set under `unittests/testfiles/`:
   v9 plain, v11/v13 independent-XOR, v13 sequential-XOR, v12 streaming,
   v12/v13 PQC (post-Phase-0 semantics), one v14 of each new kind — with a
   decrypt-byte-identity test module. (Password/config documented inside the
   fixture dir.)
2. Full suite → `test_after.log`; diff vs baseline; zero regressions
   (CLAUDE.md rule: no commit with regressions on this branch).
3. Final crypto-reviewer audit over the whole v14 diff
   (`git diff <pre-phase-0>..HEAD`). Address findings, re-run.
4. Verify all four changelog files carry every Security entry; confirm no
   `__version__` bump (release finalization only). **Commit** (fixtures +
   residual fixes).

### Phase 6 — full port to `feature/v1.5.x-development`

1. Fresh baseline on 1.5.x. Port in the same phase order. Phase 0 is a no-op
   there (1.5.x already has `_derive_symmetric_key`) — only verify the
   backport produced identical code, then port Phases 1-5. The spec §§1-5
   line refs apply to 1.5.x.
2. Cross-line byte-identity: every `GOLDEN_KEY_HEX` and fixture must assert
   the same hex on both branches; shared changelog text byte-identical
   (changelog discipline).
3. 1.5.x-specific deltas: its CLI blocks live at 7064-7071/7298-7304/7939-7945,
   rekey at 9261-9263, streaming force at 5822/6102/6137, registry allow-list
   at cli:341 (verify the 1.5.x streaming decrypt gates for the `== 12`
   pattern too). Full suite; crypto-reviewer; commits mirroring Phases 1-5.

---

## 3. Risks & mitigations (1.4.x-specific, beyond spec §4/§6.5)

- **Phase 0 is on the critical path and touches live decrypt behavior** for
  v12/v13 PQC files. If empirical testing shows 1.4.x-written v12/v13 PQC
  files exist in the wild with bare-sha256 keys, the backport makes 1.4.x
  *unable to read its own* old v12/v13 PQC files. Mitigation: measure first
  (Phase 0 step 1); if both derivations must coexist, decide a fallback
  policy (try-HKDF-then-legacy is a security anti-pattern — prefer an
  explicit metadata marker) — **STOP and consult before implementing a
  fallback.**
  - **RESOLVED 2026-07-10:** measurement confirmed the risk is real — v13
    shipped in released 1.4.6/1.4.7 (Independent-XOR is even the
    STANDARD/PARANOID default there), so legacy-keyed v12/v13 PQC files exist
    in the wild. Per the user's explicit constraint ("no breaking changes for
    existing encryptions"), Phase 0 implements a **decrypt-side one-shot
    legacy retry**: v12+ KEM decryption tries HKDF first and, on
    authentication failure, retries once with the legacy bare-SHA256 key,
    printing a re-encryption notice. This is safe (the AEAD tag rejects wrong
    keys; the legacy population legitimately exists, so no attacker-usable
    downgrade is added). A metadata marker was rejected because 1.5.x neither
    writes nor reads one, so it cannot restore cross-line reading. Port the
    same retry to 1.5.x in Phase 6 — 1.5.x currently cannot read old 1.4.x
    v12/v13 PQC files either.
- **Streaming decrypt gates hardcode `== 12`** (core:9868, 10815) — missing
  them yields v14 streaming files that encrypt fine and fail to decrypt.
  Covered by Phase 4 step 3 tests.
- **No pre-existing v9-v13 fixture corpus** — regressions in legacy
  derivation would otherwise only surface via golden unit vectors. Phase 5
  step 1 closes this; consider generating the fixtures BEFORE Phase 2 as an
  additional safety net (cheap: they can be created any time before the seed
  change lands, from the pre-change working tree).
- **Golden blast radius (#100)**: the seed change alters every v14-derived
  key; the independent `_ref_v14_seed` reimplementation test plus full-matrix
  pinning before the CLI flip (Phase 2 step 6 ordered before Phase 4) is the
  guard.
- **Registry/validation unknowns**: the `.registry` module's version
  registration and the cli:336 legacy branch were located but not audited;
  Phase 1 step 3 must read them before adding 14.
- **`_UNSAFE_SEQUENTIAL_XOR_VERSIONS` untouched**: only 8/10 stay refused;
  the fv-13 sequential-XOR opt-in must keep writing (spec §6.3) — Phase 4
  test asserts it.

## 4. Estimated effort (rough, for scheduling)

| Phase | Size |
|---|---|
| 0 (#83 backport) | M — port + 4 call sites + threading + goldens |
| 1 (scaffolding) | S |
| 2 (#100 seed) | L — 2 seed sites + 11 round-salt sites + matrix re-pin |
| 3 (#83 binding) | S-M |
| 4 (default flip) | M — 3 CLI blocks + rekey + streaming + test fallout |
| 5 (fixtures/regression) | M |
| 6 (1.5.x port) | M — mostly mechanical if goldens are cross-line pinned |
