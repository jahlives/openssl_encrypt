# Fix Plan: Post-v14 Security Review Findings (LOW-1/2/3 + INFO)

Status: PLANNED (nothing implemented yet)
Review basis: crypto-reviewer run 2026-07-11 (Fable 5) over the v14 series
`5e552693..bc5c13df` on `feature/v1.4.x-development`.

## Non-negotiable constraint

**Every existing encrypted file must remain decryptable by the fixed code.**
Each fix below states its backward-compatibility argument explicitly and pins
it with regression tests/fixtures. Forward compatibility (old releases reading
files written AFTER the fix) is called out separately where it changes.

## Verified facts the plan rests on

(All verified in the current working tree on 2026-07-11; line numbers are
`feature/v1.4.x-development`.)

- `_v14_seed_encode` (crypt_core.py:2216-2246) builds the TLV seed with
  repeated `bytearray +=`; encoding is pinned by golden vectors in
  `unittests/test_format_v14_seed_lengthsep.py` (`GOLDEN_V14_KEY_HEX`,
  layout/boundary tests). The identical function exists on
  `feature/v1.5.x-development` (crypt_core.py:1773).
- Keystore modules read `format_version` from raw `json.loads` output and
  compare with `>=` at: keystore_wrapper.py:147/151, 178-180, 519/532,
  568/570, 639/643; keystore_utils.py:44, 222, 342/351, 392/394, 645.
  Same gates exist on 1.5.x (offsets differ: wrapper 160/164, 417/430,
  472/474, 549/553; utils 52, 237, 357/366, 414/416, 667).
- Asymmetric-mode files are **pinned to `format_version: 7`**
  (crypt_core.py:5970, 6020) — they never carry v14, so the reviewer's
  "gate on v14+" suggestion does NOT apply; a per-recipient marker is needed
  instead.
- `PasswordWrapper.wrap_password/unwrap_password`
  (asymmetric_core.py:175-345) derive the AES-256-GCM wrap key via HKDF with
  static info `b"openssl_encrypt.password_wrap.v2"`; the unwrap path already
  implements a try-v2-then-v1 fallback chain — the established non-breaking
  upgrade mechanism this plan extends.
- Recipient entries are written at crypt_core.py:6000-6007
  (`key_id`, `kem_algorithm`, `encapsulated_key`, `encrypted_password`) and
  read at crypt_core.py:5751-5769. No wrap-version field exists today.
- `metadata_v7_schema.json` sets `additionalProperties: true` on recipient
  items (and everywhere relevant), so a new recipient key passes validation
  on old AND new readers. `MetadataCanonicalizer.canonicalize`
  (asymmetric_core.py:345+) serializes all keys sorted — a new key is
  automatically covered by the existing metadata signature (tamper-evident).
- `recovery_slots.py` also uses `PasswordWrapper` (lines 406-466) but ONLY
  `encapsulate`/`decapsulate`; its KEK comes from its own `_pqc_kek`
  (line 377, per-slot random salt, static `_PQC_INFO`). Any change to
  `wrap_password`'s signature must keep defaults so this caller is untouched.
- asymmetric_core.py is byte-equivalent between 1.4.x and 1.5.x except import
  order/formatting (verified via `git diff` between branches).

---

## Fix 1 — LOW-1: `_v14_seed_encode` heap hygiene

**Problem.** `seed += ...` grows the bytearray incrementally; CPython
reallocations free earlier buffers (already containing `LP(password)`)
unwiped — the caller's `secure_memzero` (crypt_core.py:2899) only wipes the
final allocation. `bytes(field)` would additionally materialize an unwipeable
copy for mutable (bytearray/SecureBytes) inputs.

**Fix.** Single exact-size preallocation, fill in place, no `bytes()`
conversion:

```python
fields = [memoryview(f) if f else memoryview(b"") for f in (password, salt, hsm_pepper)]
seed = bytearray(sum(4 + len(f) for f in fields))
pos = 0
for f in fields:
    seed[pos:pos + 4] = len(f).to_bytes(4, "big")   # keeps OverflowError >= 2**32
    pos += 4
    seed[pos:pos + len(f)] = f
    pos += len(f)
return seed
```

Docstring: keep the pinned-encoding warning; add a note that the single
allocation is part of the M2 [MEM-1] wipe guarantee (do not reintroduce
incremental growth).

**Backward compatibility.** Output bytes are identical by construction —
same field order, same 4-byte BE length prefixes, same None/`b""` aliasing.
Pinned by the existing golden vectors (`test_v14_golden_vector_cross_line`,
`test_v14_pepper_golden_vector_cross_line`) and the format fixture corpus
(v14 fixture files must still decrypt). Zero on-disk change. **Risk: none**
if goldens stay green.

**TDD (write first, watch fail where applicable).**
- Byte-identity matrix vs. a reference re-implementation of the OLD encoder
  inside the test: inputs covering empty/None pepper, empty salt/password,
  1-byte and multi-KiB fields, and mutable types (`bytearray`, `memoryview`)
  for every field. (New behavior: mutable inputs must work without copies —
  the old `bytes(field)` path accepted them too, so identity must hold.)
- Assert return type stays `bytearray` (wipeable) — extend existing
  `test_seed_encoder_returns_wipeable_type`.
- Existing golden/layout/boundary tests remain untouched and green.

**Files.** `openssl_encrypt/modules/crypt_core.py`,
`openssl_encrypt/unittests/test_format_v14_seed_lengthsep.py`.

---

## Fix 2 — LOW-2: type-safe `format_version` in keystore modules

**Problem.** The v14 series converted `format_version in [4..10]` gates to
`format_version >= 4`. On crafted metadata carrying a non-int
(`"format_version": "4"`, `[]`, `{}`), `>=` raises `TypeError` — an unhandled
traceback (fail-closed, but a crash-DoS and an ugly failure mode). The main
decrypt path already validates (crypt_core.py:10141-10144); keystore paths do
not.

**Fix.** One tiny helper (place in `keystore_utils.py`, import into
`keystore_wrapper.py` — or duplicate 4 lines if the import direction is
awkward; decide at implementation after checking the import graph, both
modules already cross-import):

```python
def _coerce_format_version(container: dict, default: int) -> int:
    fv = container.get("format_version", default)
    if not isinstance(fv, int) or isinstance(fv, bool):
        raise ValidationError(f"Invalid format_version type: {type(fv).__name__}")
    return fv
```

Apply at every metadata/header ingestion point listed in "Verified facts"
(wrapper: 147, 519, 568, 639; utils: 44, 222, 342, 392, 645). Downstream
`>=`/`==` comparisons then operate on a guaranteed int. Use the project's
existing `ValidationError` (crypt_errors) so callers that already catch
project errors keep working; verify at implementation which exception the
surrounding callers translate (keystore_wrapper wraps extraction in
try/except in several places — confirm the new error surfaces as a clean
"invalid metadata" message, not a traceback).

**Backward compatibility.** Every legitimately written file stores
`format_version` as a JSON int (verified in the writers: crypt_core writes
int literals/ints throughout; asymmetric writer crypt_core.py:6020). Bool is
excluded deliberately (`True >= 4` is valid Python but nonsense metadata).
Behavior change exists ONLY for malformed/crafted metadata: TypeError-crash →
clean fail-closed error. **Decryptability of valid files: unchanged.**
As an extra guard, the format fixture corpus (v3→v14 files) must pass through
the keystore extraction helpers untouched.

**TDD.**
- Regression tests per ingestion function: metadata with
  `"format_version": "4"`, `null` handled-as-default vs present-null
  (decide: `None` present → invalid, absent → default; match main-path
  semantics at crypt_core.py:10141), `true`, `[]` — assert clean
  ValidationError (or documented fallback), never TypeError.
- Positive tests: int 3/4/5/6/14 route to the same branches as before
  (pin current routing with tests BEFORE refactoring, then swap in helper).

**Files.** `openssl_encrypt/modules/keystore_utils.py`,
`openssl_encrypt/modules/keystore_wrapper.py`, new
`openssl_encrypt/unittests/test_keystore_format_version_typesafety.py`.

---

## Fix 3 — LOW-3: KEM-ciphertext binding for the recipient password wrap

**Problem.** `PasswordWrapper` derives the wrap key from the KEM shared
secret with static info — the #83 transcript-binding hardening was applied
only to the main PQC data path. Defense-in-depth gap; practical
exploitability low (ML-KEM implicit rejection + GCM tag).

**Design (marker-based, NOT format_version-based).** Asymmetric files are
pinned at format_version 7, so the binding is versioned per recipient entry:

1. **New wrap derivation ("v3"):**
   `info = b"openssl_encrypt.password_wrap.v3|" + kem_algorithm.encode("ascii") + b"|ct=" + hashlib.sha256(encapsulated_key).digest()`
   Binds both the KEM ciphertext and the algorithm identity into the key.
2. **API — backward-compatible signature extension:**
   - `wrap_password(password, shared_secret, *, encapsulated_key=None)` —
     `None` → v2 behavior byte-for-byte (protects `recovery_slots.py` and any
     external caller); provided → v3 info.
   - `unwrap_password(encrypted_password, shared_secret, *, encapsulated_key=None, wrap_version=None)`:
     - `wrap_version == 3`: v3 derivation ONLY, **no fallback** (fail closed;
       requires `encapsulated_key`, raise if absent).
     - `wrap_version` absent/None: existing v2→v1 fallback chain, unchanged.
     - Any other value (incl. non-int): clean PasswordWrapperError
       (fail closed; apply the Fix-2 type lesson here from the start).
3. **Writer** (crypt_core.py:5996-6007): pass `encapsulated_key` into
   `wrap_password`, add `"wrap_version": 3` to the recipient entry.
   The field lands inside the signed metadata (canonicalizer covers all keys)
   → stripping/altering it is signature-detectable when signatures are used;
   when unsigned, stripping it merely downgrades to the v2 *attempt*, which
   fails the GCM tag because the key differs (fail closed, same argument as
   the v14 downgrade analysis).
4. **Reader** (crypt_core.py:5751-5769): read
   `recipient_entry.get("wrap_version")` (type-checked), thread it plus the
   already-decoded `encapsulated_key` into `unwrap_password`.

**Compatibility matrix (the non-negotiable, spelled out).**

| File | Old reader (≤ current release) | New reader (with fix) |
|---|---|---|
| Existing file (no `wrap_version`) | v2→v1 chain (unchanged) | v2→v1 chain (unchanged) → **decrypts** ✓ |
| New file (`wrap_version: 3`) | unknown key ignored by schema (`additionalProperties: true` verified); tries v2 → GCM tag fails → clean unwrap error | v3 → decrypts ✓ |

Backward direction (the constraint) is fully preserved: the no-marker path is
byte-identical to today. Forward direction changes: **asymmetric files
written after this fix will not open on older releases** (clean error, not a
crash). This is the same trade already accepted for the v14 default flip.
Two mitigations considered:
- (a) Ship v3-by-default with a release-note entry (RECOMMENDED — consistent
  with the v14 flip; asymmetric mode is a niche path and failure is clean).
- (b) Add an opt-in flag for one release before flipping. Rejected as
  default: doubles the matrix and delays the hardening; revisit only if the
  user wants old-reader interop.

`recovery_slots._pqc_kek` has the same theoretical gap (static `_PQC_INFO`,
salt does not bind the KEM ciphertext). It is NOT in this fix's scope (the
reviewer scoped LOW-3 to `PasswordWrapper`'s wrap path; slot compat has its
own marker mechanics inside envelope metadata). Record as a follow-up
candidate for the next review round on BOTH branches — do not silently
change it here.

**TDD.**
- Roundtrip: wrap with `encapsulated_key` → unwrap with `wrap_version=3` ✓.
- **The security property:** substitute a different (valid-length) KEM
  ciphertext → unwrap with the SAME shared secret fails (info differs →
  key differs → GCM tag failure). Also: different `kem_algorithm` string →
  fails.
- Fail-closed: `wrap_version=3` without `encapsulated_key` → raises;
  `wrap_version="3"`/`true`/`2` → clean error, no fallback to v2.
- Marker-strip downgrade: v3-wrapped blob unwrapped via the no-marker path
  → GCM failure (never silently succeeds).
- Legacy: v2-wrapped and v1-wrapped blobs (construct both in-test with the
  old derivations) unwrap via the no-marker path — pins the fallback chain.
- End-to-end: a pre-fix asymmetric `.enc` fixture file (generate with the
  CURRENT code BEFORE implementing, commit under
  `unittests/testfiles/format_versions/` with its test recipient keypair)
  must decrypt after the fix — permanent backward-compat pin, mirroring the
  v14 fixture-corpus pattern.
- Regression: recovery-slot wrap/unlock tests stay green (unchanged
  defaults), full existing asymmetric test module green.

**Files.** `openssl_encrypt/modules/asymmetric_core.py`,
`openssl_encrypt/modules/crypt_core.py` (writer/reader threading), new
`openssl_encrypt/unittests/test_password_wrap_ct_binding.py`, new fixture(s).

---

## INFO items

- **INFO-3 (do it):** fix the misleading comment at crypt_core.py:6889-6891
  (claims streaming PQC files exist; all PQC hybrids are in
  `STREAMING_UNSUPPORTED_ALGORITHMS`). Docs-only, ride along with the LOW-1
  commit's issue or the tracker-update commit.
- **INFO-1/INFO-2 (recommend, small separate feature):** emit a
  non-debug warning when an explicit `format_version < LATEST_STABLE_FORMAT_VERSION`
  is requested for a NEW encryption, and elevate the streaming
  silent-upgrade message from `logger.debug` to a visible (non-fatal)
  notice. MUST warn only — never raise (API compat). Skip if the user
  prefers zero behavior-adjacent changes this round.

---

## Process / workflow (per CLAUDE.md)

1. **Issues first** (assessed as non-exploitable hardening → PUBLIC, no
   advisory; decided 2026-07-11):
   - 3 public GitLab issues (`glab issue create --repo
     world/openssl_encrypt`), one per LOW finding, each describing
     finding + fix design + compat argument.
   - 3 public GitHub mirror issues referencing the GitLab issue numbers.
   - **No GHSA** — none of the findings is an exploitable vulnerability;
     an advisory would create noise/implied urgency.
2. **Baseline:** reuse the existing clean suite log as `test_baseline.log`
   per the chained-baseline policy if it is current for this branch tip;
   otherwise run a fresh full baseline
   (`pytest -n auto --dist=worksteal openssl_encrypt/unittests/ | tee test_baseline.log`).
3. **Implementation order & commits** (one fix = one commit, tests-first):
   1. LOW-1 seed encoder (`security: ...  Refs gitlab#<n1>`)
   2. LOW-2 keystore type safety (`security: ... Refs gitlab#<n2>`)
   3. LOW-3 wrap binding — commit the pre-fix fixture generation together
      with the fix commit or as a preparatory `test:` commit
      (`security: ... Refs gitlab#<n3>`)
   4. INFO-3 comment (+ optional INFO-1/2 warnings as `feat:`/`chore:`)
   Targeted test runs per commit (tiered policy); after the last fix run the
   FULL suite `| tee test_after.log`, diff against baseline — zero
   regressions or no commit/push.
4. **Per-commit tracker comments:** GitLab issue note + draft-advisory
   comment with commit hash + step description.
5. **Changelog (Security section → ALL FOUR files):** `CHANGELOG.md`,
   `openssl_encrypt/version.py.template` (source of truth; never commit
   generated `version.py`), `flatpak/...metainfo.xml`, flathub
   `changelog.html` — before each commit, current unreleased version entry,
   byte-identical text across both branches.
6. **Re-run crypto-reviewer** (default Opus — the Fable 5 override was
   one-invocation-only) over the three fixes before pushing; address any
   findings, re-run to confirm.
7. **Push to origin (GitLab), not github; verify the remote ref advanced.**

## Port to 1.5.x

All three fixes port 1:1 — verified surface parity:

- **LOW-1:** `_v14_seed_encode` body is byte-identical on 1.5.x
  (crypt_core.py:1773/1798-1803). Same golden-vector suite exists (the v14
  series landed on both lines). Cherry-pick applies with offset only.
- **LOW-2:** identical `>= 4` gates on 1.5.x at wrapper 160/164, 417/430,
  472/474, 549/553 and utils 52, 237, 357/366, 414/416, 667. Same helper +
  same tests; expect clean cherry-picks with small offsets (keystore modules
  diverged ~284 lines between branches — verify each hunk lands at the right
  gate, do not force-apply).
- **LOW-3:** asymmetric_core.py differs only in import order/formatting
  between branches; the crypt_core writer/reader sites exist on both (line
  offsets differ — 1.5.x crypt_core diverged heavily, locate by symbol not
  line). New fixture files are branch-independent (format_version 7 is read
  by both) — copy them, keep test text identical.
- **Changelog:** same four files on 1.5.x, byte-identical Security entries.
- **Process:** separate full baseline/after run on 1.5.x; same per-commit
  tracker comments (same issues/advisory cover both branches — note the
  per-branch commit hashes, as done for the v14 series).
- **1.5.x-only surfaces checked:** `envelope.py` KEK wrap has no KEM
  ciphertext (password-derived) → LOW-3 N/A; `recovery_slots.py` PQC slots
  exist on both branches → same follow-up note applies to both.

## Decision points for the user (defaults chosen, flag if you disagree)

1. **LOW-3 forward compatibility:** new asymmetric files won't open on older
   releases (clean error). Default: accept + release note (matches v14-flip
   precedent). Alternative: opt-in flag for one release.
2. **Advisory granularity:** one consolidated draft GHSA for all three LOWs
   (default) vs. one per finding.
3. **INFO-1/2 warnings:** include as a small extra feature commit (default:
   include) or defer.
4. **recovery_slots `_pqc_kek` ct-binding:** deliberately out of scope;
   queue for the next review round (default) or fold into LOW-3 now.
