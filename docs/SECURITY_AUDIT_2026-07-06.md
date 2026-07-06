# Security Audit — Full Branch Review

- **Branch:** `feature/v1.4.x-development`
- **HEAD at audit:** `aa23f4b0`
- **Date:** 2026-07-06
- **Scope:** Full-codebase crypto review (not just latest changes), across four
  focus areas: sensitive-data handling / zeroization, KDF implementations, hash
  & MAC usage, and symmetric/asymmetric encryption implementation issues.
- **Method:** Five parallel `crypto-reviewer` passes, one per dimension. Findings
  below are review **input** and must be independently confirmed before being
  treated as definitively exploitable. Items marked **✓ verified** were confirmed
  against source in the main session during the audit.

> Line numbers are as of `aa23f4b0` and will drift as the file changes. Re-anchor
> by symbol name (e.g. `generate_key`, `encrypt_file`) when acting on a finding.

## Remediation status

- **#2 — FIXED** in `66257a28`: per-round KDF salt now redacted via `debug_secret()`.
- **#3 — FIXED** in `e1b6731f`: `encrypt_file` defaults to v9 and refuses to encrypt
  v8/v10; rekey upgrades legacy files; ripple fixes to the envelope fast-path and
  the v9 metadata schema. Full suite green (3131 passed / 0 failed).
- All other findings remain **open** (see below).

---

## Severity summary

| # | Sev | Area | Finding | Anchor |
|---|-----|------|---------|--------|
| 1 | HIGH | Sensitive data | Secret wiping is a systemic no-op (immutable `bytes`) | `secure_memory.py:206`, `crypt_core.py:4380` |
| 2 | HIGH ✓ | Sensitive data / KDF | Live KDF intermediate logged in cleartext under `--debug` | `crypt_core.py:3532,3669,3799` |
| 3 | HIGH ✓ | KDF | `encrypt_file` defaults to cancelling `format_version=10` | `crypt_core.py:6148,4262` |
| 4 | HIGH | KDF | Parallel independent-XOR drops Whirlpool component | `parallel_kdf.py:606` vs `crypt_core.py:2735` |
| 5 | HIGH | KDF | Sequential `generate_key` fails *open* on KDF errors | `crypt_core.py:4053,3949,3612,4175` |
| 6 | HIGH | Hash | Unkeyed SHA-256 of plaintext stored in cleartext metadata | `crypt_core.py:6991→5466` |
| 7 | HIGH | PQC / identity | Recipient public key not bound to pinned fingerprint | `identity.py:281,818,951` |
| 8 | MED | PQC | KEM shared secret through bare SHA-256, not HKDF | `pqc.py:671,941`; `pqc_adapter.py:299,405` |
| 9 | MED | PQC | Silent v1 (SHA-256) wrap-key downgrade on unwrap | `asymmetric_core.py:299` |
| 10 | MED | Hash | `encrypted_hash` unkeyed but presented as integrity control | `crypt_core.py:7863,10178` |
| 11 | MED | KDF | No cost floors for Argon2/scrypt/PBKDF2; inconsistent defaults | `crypt_core.py:3460`; `parallel_kdf.py:236` |
| 12 | MED | Sensitive data | Per-round secret copies / `.hex()` string never wiped | `crypt_core.py:3526,2026,2473` |
| 13 | LOW | AEAD | 64-bit streaming nonce prefix (latent footgun) | `streaming.py:425,111` |
| 14 | LOW | AEAD | AES-SIV `len==32` test hack in production decrypt | `crypt_core.py:11131` |
| 15 | LOW | KDF | RandomX output not normalized → 64/128-byte key derive failure | `crypt_core.py:2554`; `randomx.py:367` |
| 16 | LOW | KDF | Balloon salt passed as `str()` repr | `crypt_core.py:3677` |
| 17 | LOW | Hash | Two post-auth `==` comparisons not constant-time | `streaming.py:933`; `crypt_core.py:5644` |
| 18 | LOW | PQC | "hybrid" algorithm names have no classical KEM leg | `pqc_adapter.py:69` |
| 19 | LOW | PQC | Keystore per-key blob doesn't bind `key_id`/pubkey | `pqc_keystore.py:1445` |
| 20 | LOW | PQC | `--no-verify` asymmetric decrypt drops KDF DoS cap | `crypt_core.py:5510` |
| 21 | LOW | Sensitive data | `secure_memzero(salt)` on a returned object (latent corruption) | `crypt_core.py:4396` |

---

## HIGH

### 1. Secret wiping is a systemic no-op
**Area:** sensitive-data handling · **Files:** `secure_memory.py:206`, `crypt_core.py:4380, 6978, 8196, 11532`

A hardening change made `secure_memzero()` refuse to wipe immutable `bytes`/`str`
and return `False` — correct in isolation, but **no caller checks the return
value**, and the crown-jewel secrets are held in immutable `bytes`:
- `generate_key()` returns `bytes(password)` (`:4380`), so every downstream
  `secure_memzero(key)` (`encrypt_file` `:8196`, `decrypt_file` `:11532`) is a no-op.
- Plaintext is read as `bytes` (`:6978`), so `secure_memzero(data)` is a no-op.

The mlock / secure-allocator / multi-pattern-overwrite machinery protects scratch
buffers that mostly do **not** hold the final secrets; the derived file key and
full plaintext stay resident (unlocked, swappable, core-dumpable) until GC.

**Impact:** the primary purpose of the secure-memory module is defeated for the
highest-value secrets; the code *appears* to zero them but does not.

**Fix:** keep the key/plaintext in `bytearray`/`SecureBytes` end-to-end (have
`generate_key` return `SecureBytes`, read plaintext into `bytearray`), so the
existing cleanup calls become effective. Add a test-only guard that fails when
`secure_memzero()` returns `False` on a value the code believes it is wiping —
this would catch the whole class.

### 2. ✓ Live KDF intermediate logged in cleartext under `--debug`
**Area:** sensitive-data / KDF · **Files:** `crypt_core.py:3532, 3669, 3799`

The Argon2/Balloon/Scrypt debug blocks log the per-round salt with raw `.hex()`:

```python
logger.debug(f"ARGON2:SALT Round {i+1}/{argon2_rounds}: {round_salt.hex()}")
```

For `format_version >= 7` and rounds ≥ 1, `round_salt = bytes(password)[:16]`
(`:3514, 3647, 3767`) — i.e. the first 128 bits of the **live evolving key
material**. These lines bypass the `debug_secret()` chokepoint and fire under
plain `--debug` (not gated by `--unsafe-show-secrets`).

**Impact:** 128 bits of KDF intermediate leaks to any debug log/file, directly
undermining the debug-redaction design (commits `aa23f4b0` / `93d33990`).

**Fix:** route these through `debug_secret("ARGON2:SALT ...", round_salt)`. Round 0
is the public file salt and is harmless, but the same call is safe there too.

### 3. ✓ `encrypt_file` defaults to the cancelling `format_version=10`
**Area:** KDF · **Files:** `crypt_core.py:6148` (default), `4262` (append), `6667`

In the sequential-XOR path, for `format_version < 13` the chain's final value is
appended to the XOR accumulator a second time; since `normalize()` is
deterministic it XORs the last stage with itself → 0, so the last stage cancels
out. With a single memory-hard KDF placed last (e.g. Argon2-only), the key
collapses to `normalize(SHA256(password+salt))`, bypassing the KDF cost. The code
comment at `:4262` documents this for v8/v10.

The CLI is safe (uses v9 / v13), **but `encrypt_file(..., format_version=10)` is
the default parameter value**, so any direct library/API caller using defaults
produces vulnerable v10 files.

**Impact:** library callers silently produce files whose key is a single cheap
SHA-256 of `password+salt`.

**Fix:** change the `encrypt_file` default to a non-cancelling version (9 or 13),
and refuse to *encrypt* new v8/v10 files (keep them decrypt-only), e.g. raise
unless the config came from decryption metadata.

### 4. Parallel independent-XOR drops the Whirlpool component
**Area:** KDF · **Files:** `parallel_kdf.py:606` vs `crypt_core.py:2735`

The sequential independent-XOR builder folds a Whirlpool component when Whirlpool
rounds > 0; the parallel builder's `hash_algorithms` list **excludes** Whirlpool.
`parallel_kdf` is a runtime flag not recorded in metadata, and both encrypt and
decrypt route on it.

**Impact:** (a) encrypt with `--parallel-kdf`, decrypt without → different XOR
component set → different key → **undecryptable file** (data loss); (b) both
parallel → decryptable but the configured Whirlpool component is silently missing,
so the combiner is weaker than the metadata advertises.

**Fix:** make the two paths derive identically — either include Whirlpool in the
parallel worker set, or hard-fail the parallel path when Whirlpool rounds > 0 and
fall back to sequential (as already done for v13 at `parallel_kdf.py:545`).

### 5. Sequential `generate_key` fails *open* on KDF errors
**Area:** KDF · **Files:** `crypt_core.py:4053, 3949, 3612, 3739, 3838` (swallow), `4175` (backstop guard)

In the sequential path a KDF exception is swallowed and the stage skipped
(`use_randomx=False`, etc.). The PBKDF2 "requested-but-none-succeeded" backstop is
disabled for XOR composition (`and not use_xor_composition` at `:4175`). So a
v8/v10 file whose only stretch stage is RandomX/HKDF/Argon2 and it throws performs
no stretching at all — the key reduces to ~`SHA256(password+salt)`. The #71 fix was
applied only to the independent path (`:2930`, fails closed with `ValidationError`).

**Impact:** silent downgrade to a cheap key on KDF failure, same class as #71 but
still live on the sequential path.

**Fix:** mirror the #71 fail-closed behavior in `generate_key`; at minimum remove
the `and not use_xor_composition` guard so the PBKDF2 backstop still fires for
v8/v10, and do not swallow exceptions for a KDF that is the only configured stretch.

### 6. Unkeyed SHA-256 of plaintext stored in cleartext metadata
**Area:** hash · **Files:** `crypt_core.py:6991` (`original_hash = calculate_hash(data)`), `6803`, `5770`; stored at `4652/4815/5035/5259`; header written cleartext at `5466`

`original_hash` is an **unkeyed** SHA-256 of the *plaintext*, emitted in the
cleartext metadata header of every file. An attacker holding only the ciphertext
can confirm a guessed plaintext by computing `SHA-256(guess)` — no password
needed. It is also redundant: every cipher is authenticated (AEAD tag, Camellia
encrypt-then-HMAC, or the streaming trailer HMAC), so it adds no integrity an
attacker can't forge, only the oracle.

**Impact:** plaintext confirmation/recovery for guessable or known-set content
directly from the ciphertext file.

**Fix:** stop storing an unkeyed plaintext hash; rely on the cipher's
authentication. If a redundant integrity value is still wanted, make it a **keyed**
MAC over an HKDF-separated subkey of the derived key, never an unkeyed digest.

### 7. Recipient public key not bound to its pinned fingerprint
**Area:** PQC / identity · **Files:** `identity.py:281` (`Identity.load`), `818` (TOFU), `951` (private-key AAD)

`Identity.load()` reads public keys from `*_public.pem` and takes `fingerprint`
verbatim from `identity.json`; it never calls `check_fingerprint_consistency()`
(unlike `from_dict()` at `:553`). The TOFU pin compares the fingerprint from
`identity.json`, not the actual PEM bytes. The private-key at-rest AEAD binds only
`identity:{name}:purpose:{...}` — not the public key.

**Impact:** an attacker with local write access to a contact's identity directory
replaces `encryption_public.pem` with their own ML-KEM key, leaving `identity.json`
untouched. TOFU sees no change; the sender then encapsulates the file password to
the attacker's key (KEYSTORE-DOWNGRADE class). Local-tamper / store-integrity break.

**Fix:** in `Identity.load()`, call `check_fingerprint_consistency()` and refuse to
load/use on mismatch. Additionally bind the public-key bytes (or fingerprint) into
the private-key encryption AAD so the keypair halves are cryptographically tied.

---

## MEDIUM

### 8. KEM shared secret run through bare SHA-256, not HKDF
**Files:** `pqc.py:671` (enc), `941` (dec); `pqc_adapter.py:299, 405`

AEAD key = `hashlib.sha256(shared_secret).digest()` — no HKDF, salt, `info`, or
binding to the encapsulated ciphertext / algorithm name. Inconsistent with the rest
of the codebase (which uses HKDF with domain-separated `info`). The ML-KEM shared
secret is uniform so this is not a direct break, but it removes domain separation
and lets different algorithms of equal shared-secret length become interchangeable
at the symmetric layer.

**Fix:** derive with HKDF-SHA256, `info` binding the algorithm name and the
encapsulated ciphertext, matching `PasswordWrapper`.

### 9. Silent v1 (SHA-256) wrap-key downgrade on unwrap
**Files:** `asymmetric_core.py:299`

`unwrap_password` tries the HKDF-v2 key and, on any failure, silently falls back to
a legacy `SHA-256("...v1" + shared_secret)` wrap key. No version field exists, so
the weaker derivation is accepted indefinitely and chosen by trial decryption. Not
directly exploitable (AES-GCM authenticates), but keeps a deprecated derivation
alive with no sunset.

**Fix:** record the wrap version explicitly in the (already-signed) recipient
metadata and select the derivation from it; gate v1 behind explicit legacy opt-in.

### 10. `encrypted_hash` unkeyed but presented as an integrity control
**Files:** `crypt_core.py:7863` (compute), `10178` (verify)

`encrypted_hash` = unkeyed SHA-256 over `nonce+ciphertext`, stored in cleartext,
unauthenticated metadata. An active attacker who alters ciphertext simply
recomputes it, so it provides **zero** tamper protection — only accidental-corruption
detection. The real integrity is the AEAD tag. Messaging presents it as "content
integrity verification," risking a future caller trusting it as an auth gate.

**Fix:** drop it and rely on the AEAD/HMAC tag, or relabel as corruption-detection
only and never treat a match as an authenticity decision.

### 11. No cost-factor floors for Argon2/scrypt/PBKDF2; inconsistent defaults
**Files:** `crypt_core.py:3460, 2378`; `parallel_kdf.py:236, 262`

Only Balloon has a warn-floor (`_apply_balloon_security_defaults`). Argon2
(memory/time/parallelism), scrypt (n/r/p), and PBKDF2 iterations are taken from
config with no minimum, so e.g. `argon2.memory_cost=8` is accepted silently. The
three derivation paths also disagree on read-defaults (`generate_key`:
time=3/mem=65536/par=4; the independent + parallel workers: time=2/mem=102400/par=8),
so a config missing a field derives different strength depending on version/flag.

**Fix:** add an encrypt-time floor+warning for Argon2/scrypt/PBKDF2 mirroring the
Balloon defaults, and unify read-defaults across the three paths.

### 12. Per-round secret copies / `.hex()` string never wiped
**Files:** `crypt_core.py:3526, 3660, 3790` (per-round `bytes(password)`), `2026` (`copy_from`), `2473` (`.hex()`)

Each memory-hard round snapshots the evolving secret into immutable `bytes` before
calling the KDF; the subsequent `secure_memzero` on those `bytes` is a no-op (see
#1). `multi_hash_password` hash-round digests and `SecureBytes.copy_from`
materialize immutable copies. `compute_hash_independent` does
`password_str = password_bytes.hex()` — an immutable `str` holding the full secret
that can never be wiped and may be interned.

**Fix:** hold intermediates in mutable buffers; avoid `bytes()` snapshots and the
`.hex()` string (adapt the Balloon wrapper to accept bytes).

---

## LOW

- **13. 64-bit streaming nonce prefix** (`streaming.py:425, 111`) — per-chunk nonces
  derive from an 8-byte random prefix. Safe today (streaming key is always per-file),
  but a high-blast-radius footgun if a reused key is ever fed to `StreamingEncryptor`.
  **Fix:** widen to 16 bytes and mix the file key/salt into `derive_chunk_nonce`.
- **14. AES-SIV `len==32` test hack** (`crypt_core.py:11131`) — production decrypt
  branches on a magic ciphertext length "for unit tests." Not a crypto break, but
  length-conditioned control flow in a decrypt routine is oracle-shaped. **Fix:**
  drive SIV framing from metadata/format version; move the expectation to the test.
- **15. RandomX output not normalized** (`crypt_core.py:2554`; `randomx.py:367`) —
  RandomX returns 32 bytes; `compute_kdf_independent` doesn't normalize, so a
  64/128-byte key (AES-SIV, Threefish) + RandomX raises "All values must be same
  length." **Fix:** normalize the RandomX result like the hash components.
- **16. Balloon salt passed as `str(round_salt)`** (`crypt_core.py:3677`) — stringifies
  to the bytes repr rather than using salt bytes. Deterministic (not a break) but
  inconsistent with the independent path. **Fix:** pass salt bytes consistently.
- **17. Two post-auth `==` hash comparisons** (`streaming.py:933`; `crypt_core.py:5644`)
  — not `hmac.compare_digest`. Run only after AEAD/HMAC auth, so not practically
  exploitable, but inconsistent with the main paths. **Fix:** use `compare_digest`.
- **18. "hybrid" names have no classical KEM leg** (`pqc_adapter.py:69`) — every
  `*-hybrid` maps to a pure-PQC algorithm; no X25519/ECDH backstop. Naming/expectation
  risk. **Fix:** add a real classical leg + combiner, or rename.
- **19. Keystore per-key blob doesn't bind `key_id`/pubkey** (`pqc_keystore.py:1445`)
  — per-key AAD omits `public_key`/`key_id`; only the outer whole-file AEAD protects
  them. Defense-in-depth gap. **Fix:** add `key_id` + a hash of `public_key` to the AAD.
- **20. `--no-verify` asymmetric decrypt drops KDF DoS cap** (`crypt_core.py:5510`) —
  with `skip_verification=True`, `generate_key()` runs with unauthenticated KDF params
  and no upper bound (unlike the recovery-slot path). A hostile file + `--no-verify`
  forces an unbounded memory-hard KDF. **Fix:** apply the same param caps regardless
  of the verification flag.
- **21. `secure_memzero(salt)` on a returned object** (`crypt_core.py:4396`) — `salt`
  is also referenced by the returned tuple and written to file metadata; if it were
  ever mutable this would corrupt the output. Works only because `salt` is immutable
  `bytes` (which also means the wipe does nothing). **Fix:** never wipe an object you
  are returning.

---

## Confirmed sound (no action)

- Cascade streaming chunk-nonce reuse fix holds — per-chunk nonce mixed into the
  HKDF salt (`cascade.py:335, 384`); no residual (key, nonce) reuse.
- Streaming per-chunk nonce uniqueness; reorder/truncation/extension detection
  (`streaming.py:111, 146, 778, 821, 905, 919`).
- AEAD tag verified before plaintext release everywhere; streaming stages to a temp
  file and only `os.replace`s after all checks pass.
- Metadata / format-version / cipher / xchacha-flag bound as AEAD AAD (incl. the
  envelope path, which only strips `derivation_config` + `wrapped_dek`).
- Camellia legacy padding-oracle fix correct (length pre-check → constant-time
  `verify_mac` → padding check); full 32-byte tag; HKDF-separated MAC key.
- Real XChaCha 192-bit construction correct (`xchacha.py`); legacy format-1 is a
  deliberate 96-bit funnel for pre-1.5 compat (no reuse — per-file keys).
- ML-DSA-65 file signatures: domain-separated, canonical payload, fail-closed on
  unknown signer (`file_signature.py`).
- Integrity manifest: SHA-512 per-file digests over public content, signature
  verified separately, unsupported algorithm + symlink/outside-root fail closed.
- Recovery-slot set MAC-bound to the DEK and verified fail-closed; untrusted Argon2
  params range-capped (#73). liboqs absence fails closed on the V7/`PasswordWrapper`
  path. Signature-before-KDF ordering correct on the asymmetric path.

---

## Recommended remediation order

1. **#2** — route the three `*:SALT` debug lines through `debug_secret()` (closes a
   direct hole in the debug-redaction feature; ~3 lines + a test).
2. **#3** — change `encrypt_file` default off `format_version=10`; refuse to encrypt
   new v8/v10 (keep decrypt-only).
3. **#6** — remove/replace the cleartext unkeyed plaintext-hash oracle.
4. **#4 / #5** — KDF fail-open + parallel Whirlpool divergence (correctness + data-loss).
5. **#1 / #12** — make secret wiping real (larger refactor: `SecureBytes` end-to-end).
6. **#7** — bind recipient public key to its pinned fingerprint.
7. Medium/Low items as capacity allows.

Each fix should be its own TDD commit per commit discipline, with a `crypto-reviewer`
re-check before committing. HIGH #1 and #6 are format/behavior-affecting and should
be coordinated with the 1.5.x line.
