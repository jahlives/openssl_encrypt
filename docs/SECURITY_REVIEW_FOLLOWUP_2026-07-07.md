# Security Review — Follow-up (v1.5.x, 2026-07-07)

_Fresh audit of `feature/v1.5.x-development` (`821309e3`), performed after `sec-review::1.4.7`
was closed. Method: five parallel `crypto-reviewer` passes across distinct domains — KDF/key
handling; cipher cascade/streaming/AEAD; PQC/KEM/signatures; secure memory/side-channels;
hardware-token/plugin/keystore/IO. Findings below are **new** (not in the closed 1.4.7 set)
and each was verified against the code by the reviewer._

**Overall:** the crypto core is well-engineered. The v8/v10 XOR-cancellation fix, v13
per-component domain separation, cascade/streaming nonce management, KEM/DEK/AEAD binding,
slot-set MAC, and constant-time/redaction machinery all verified sound. The recurring theme
worth attention is **no-op `secure_memzero` at call sites** (the M10/#79/#80 honesty work made
the function honest, but several callers still wrap immutable `bytes` in `bytearray(...)` and
"wipe" a throwaway copy) and two **plugin-signing coverage gaps**.

Counts: **2 High · 4 Medium · 8 Low · 6 Info** (20 findings). A 21st (RandomX
parallel fail-open) was surfaced by crypto-reviewer during remediation — see **R1** below.

> **Remediation status (2026-07-07).** Fixed on **both branches** (each with a regression
> test + crypto-reviewer sign-off), v1.4.x / v1.5.x commits:
> **H1** (`35c4dd5c` / `2d646c4b`), **M4** (`c2ac14be` / `65bcf52e`),
> **M2** (`cc833442` / `23646ac1`+`4eb40e54`), **M3** & **R1** (`ec2cfbe8` / `4eb40e54`),
> **M1** (plugin read-once) (`08870363` / `6b45aadf`), **H2** (signed per-package manifest +
> CLI) (v1.5.x `b26c46de`+`1fc7378d`; v1.4.x port pending). A runtime import-hook
> (sibling-swap TOCTOU defense-in-depth) remains a follow-on per
> [`PLUGIN_TRUSTBOUNDARY_H2_M1_PLAN.md`](PLUGIN_TRUSTBOUNDARY_H2_M1_PLAN.md). Low/Info items open.

---

## High

### H1 — [HSM-1] FIDO2/HSM pepper printed in cleartext, bypassing the redaction chokepoint — **RESOLVED** (v1.4.x `35c4dd5c` / v1.5.x `2d646c4b`)
- `hsm_cli.py:228` — `click.echo(f"Pepper (hex): {pepper.hex()}")`.
- The `hsm fido2-test` command prints the full 32-byte derived hardware pepper (key material /
  KDF intermediate) to stdout **unconditionally** — no `--debug`, no `--unsafe-show-secrets`,
  not via `debug_secret()`. Lands in scrollback / `script` / CI logs. The FIDO2 plugin itself
  routes the pepper through `debug_secret()` (`fido2_pepper/__init__.py:529`), so this is a CLI
  inconsistency, not intent. (`test_salt.hex()` at :208 is fine — salt is public.)
- **Fix:** remove the hex dump (the length is already printed at :227), or gate the value behind
  `debug_secret("pepper", pepper)`.

### H2 — [PLUGIN-1] Package plugins: only `__init__.py` is signature/AST/hash-verified; sibling modules execute unverified — **RESOLVED** (v1.5.x `b26c46de`+`1fc7378d`; v1.4.x port pending)
- Signed per-package manifest (`plugin_manifest.py`): `PLUGIN.manifest` covers **every importable
  module** (source `.py`, bytecode `.pyc`, native `.so`/`.pyd` — recursively, incl. underscore/
  nested), signed once as `PLUGIN.manifest.asc`. For a package `__init__.py`, `_validate_plugin_file`
  verifies the manifest (signature via the existing trust anchors + exact tree match) instead of only
  `__init__.py`'s own `.asc`, hash-pins every module, and AST-scans every source module. Under ENFORCE
  a tampered/unlisted/native-swapped/impostor-signed sibling is refused; WARN warns+loads; built-in
  packages keep the trust shortcut. Fail-closed enumeration rejects symlinked/escaping/newline/dup
  module files. Operator CLI: `plugin sign` auto-detects a package and writes the signed manifest.
  crypto-reviewer approved (after native/bytecode coverage + fail-closed symlink fixes).
- **Remaining follow-on (defense-in-depth, not the finding):** a runtime `sys.meta_path` import hook to
  re-verify siblings at import time (closes the validation→import TOCTOU sibling-swap window, currently
  bounded by the H8 owner-only-writable check). Tracked in the plan doc.
- `plugin_manager.py:150-161` (discovery registers `subdir/__init__.py`), `:970-1042`
  (`_validate_plugin_file` gates only that file), `:880-916` (signature policy).
- When `exec_module` runs a package plugin's `__init__.py`, it transitively imports sibling
  modules (`from .helper import ...`) that are **not** signature-checked, AST-scanned, or
  hash-pinned. **All shipped token plugins are packages** (`yubikey_challenge_response`,
  `onlykey_challenge_response`, `fido2_pepper`, `pepper`, `keyserver`, `telemetry`). Under
  `ENFORCE`, a third-party author can ship a benign signed `__init__.py` plus a malicious
  unsigned `helper.py` and it runs with zero scrutiny — defeating the signing guarantee's core
  promise for package plugins.
- **Fix:** validate (signature + AST + TOCTOU hash) every `*.py` under the package before
  `exec_module`, or sign a manifest/tree-hash of the whole package. At minimum refuse package
  plugins under `ENFORCE` unless all contained modules are covered.

---

## Medium

### M1 — [PLUGIN-2] Signature is verified over bytes read separately from the AST-scanned/executed bytes (verify-A / execute-B) — **RESOLVED** (v1.4.x `08870363` / v1.5.x `6b45aadf`)
- Read-once binding: `_validate_plugin_file` reads the plugin ONCE as raw bytes and threads that
  exact buffer through the signature gate, the `sha256(raw)` pin, and `analyze_plugin_code(raw)`
  (`ast.parse(raw)`); `load_plugin` re-reads once, compares to the pin, and executes via
  `compile(raw_now)+exec` instead of `spec.loader.exec_module` — killing the CRLF/BOM verify-A/
  execute-B discrepancy and the `.pyc`-shadow vector. Fail-closed on a missing pin for
  non-built-ins; sys.modules cleaned on exec failure. crypto-reviewer approved. (H2 — package
  sibling coverage — remains deferred; see the plan doc.)

### M2 — [MEM-1] Key material not actually wiped — no-op `secure_memzero(bytearray(immutable_bytes))` at multiple call sites — **RESOLVED** (v1.4.x `cc833442`+`ec2cfbe8` / v1.5.x `23646ac1`+`4eb40e54`)
- Same root cause across several files: an HKDF/hash output is immutable `bytes`; wrapping it in
  `bytearray(...)` and calling `secure_memzero` zeros a **copy** and returns success while the
  original secret lingers in unlocked heap (swap/core-dump exposure). This is the exact
  M10/#79/#80 anti-pattern the function itself was fixed for, reintroduced at callers.
  - `parallel_kdf.py:820-830` — `initial_hash` and each `results[...]` value are **direct XOR
    components of the final key** (used at `:709-710,720,728`); the "CRITICAL: zero all
    intermediate components" block wipes copies only.
  - `asymmetric_core.py:216`/`:246` (`wrap_password` wrap key), `:297`/`:305`/`:309`/`:334`
    (`unwrap_password`; note `:305` wipes a copy then `:309` orphans the real key — dead code).
  - `pqc.py:610`/`:680` (`PQCipher.encrypt` symmetric key — the `decrypt` path at `:795` is
    correct: it holds the key in `SecureBytes`).
  - `crypt_core.py:2239` + cleanup `:2566-2587` — `generate_key_independent_xor` never wipes the
    pepper-mixed `password` (and `bytes(password)` at `:2247` makes an un-wiped copy), unlike the
    sequential `generate_key` which does `secure_memzero(password)` at `:3727`.
- **Fix:** hold each secret in a `bytearray`/`SecureBytes` **from creation** and wipe that object;
  for pickled worker outputs (immutable `bytes`), drop references + `del`/`gc.collect()` rather
  than calling `secure_memzero(bytearray(...))` (which is a no-op and gives false assurance).
  Consider `strict=True` in these finally blocks so a future immutable-input regression fails loud.

### M3 — [KDF-1] Parallel vs sequential Independent-XOR derive different keys for Argon2 `rounds > 1` — **RESOLVED** (v1.4.x `ec2cfbe8` / v1.5.x `4eb40e54`)
- `parallel_kdf.py:216-242` (`_kdf_worker` Argon2 branch runs `hash_secret_raw` **once**, ignoring
  `rounds`) vs `crypt_core.py:1955-1980` (sequential loops `rounds` with `round_salt = result[:32]`
  chaining). `--parallel-kdf` is a runtime flag **not persisted in metadata** (`crypt_core.py:5977`,
  `9756`), so encrypting with it (Argon2 `rounds>1`) and decrypting without it → different key →
  permanent silent failure to decrypt. The parallel path also does strictly less KDF work than the
  recorded config implies. (RandomX in the same worker *does* loop rounds — this is Argon2-specific;
  fv>=13 delegates to sequential, so it bites v11/v12 independent-XOR.)
- **Fix:** make the worker's Argon2 branch loop `rounds` with the same salt-chaining, or reject
  `rounds != 1` for parallel dispatch. Add a parallel-vs-sequential key-equivalence test for
  Argon2 `rounds>1` (and Balloon — see L1).

### M4 — [STREAM-1] Streaming per-chunk AEAD auth failures misclassified via substring matching — **RESOLVED** (v1.4.x `c2ac14be` / v1.5.x `65bcf52e`)
- `streaming.py:360-366` (`decrypt_chunk`): tag failures for the library-direct ciphers
  (`aes-gcm`, `chacha20-poly1305`, `aes-ocb3`, `aes-gcm-siv`, `aes-siv`) raise
  `cryptography.exceptions.InvalidTag`, whose `str(e)` is **empty** → matches neither `"tag"` nor
  `"authentication"` → surfaced as `DecryptionError` instead of `AuthenticationError`. XChaCha /
  Threefish surface correctly. This is exactly the substring anti-pattern that #91 replaced with
  type-based classification in `cascade.py:389-395`, not applied here. Fails closed (no plaintext
  released), but the exception *type* an attacker observes now depends on which AEAD the file uses
  — an integrity-vs-decryption classification signal, plus a correctness defect.
- **Fix:** classify by exception type (catch `InvalidTag` + `crypt_errors.AuthenticationError`),
  re-raise a uniform layer-agnostic `AuthenticationError` with a fixed message; don't interpolate
  `{e}`.

### R1 — [KDF-2b] RandomX fails OPEN in the parallel Independent-XOR path — **RESOLVED** (v1.4.x `ec2cfbe8` / v1.5.x `4eb40e54`)
- Surfaced by crypto-reviewer during M2/M3 remediation. `parallel_kdf.py` (dispatcher) skipped
  RandomX with a warning when it was enabled but unavailable, whereas the sequential path fails
  closed (#71). With RandomX enabled alongside another KDF, the parallel path silently dropped a
  KDF component — deriving a weaker key that also diverges from the sequential result
  (undecryptable). Fixed to raise (fail closed), mirroring #71; regression test added.

---

## Low

### L1 — [KDF-2] Parallel Independent-XOR Balloon branch references a non-existent module
- `parallel_kdf.py:261-287` — `find_spec("openssl_encrypt.modules.balloon_hash")` (no such module;
  code is in `balloon.py`) and calls `balloon_hash(..., hash_len=...)` (the real
  `balloon.balloon_hash` takes only `(password, salt)`). Parallel + Balloon always raises →
  **fails closed** (availability bug, not a key-strength vuln), but sequential/parallel are not
  interchangeable for Balloon configs. **Fix:** use `balloon._balloon`/`balloon_m`, mirror the
  sequential `compute_kdf_independent` Balloon logic incl. HKDF length-normalization; add an
  equivalence test.

### L2 — [SIG-1] Detached-signature verify trusts the sidecar-declared algorithm and can crash on a bad one
- `file_signature.py:247,262,270` — `verify_signature` reads `algorithm` from the untrusted `.sig`
  sidecar and never checks it equals the resolved identity's `signing_algorithm`; and
  `PQCSigner(algorithm)` at `:262` is outside the `try`, so an unsupported algorithm raises an
  uncaught `ValueError` (crash instead of "BAD signature"). Not forgeable (algorithm is inside the
  signed payload; pubkey is fixed), but an unnecessary algorithm-confusion + DoS surface. **Fix:**
  assert `sig["algorithm"] == identity.signing_algorithm`; construct the verifier defensively.

### L3 — [SIG-2] Asymmetric (V7) verify doesn't bind the chosen sender key to the file's declared sender
- `crypt_core.py:4795-4805` — the metadata signature is verified against the caller-supplied
  `--verify-from` key, but never checks that key's fingerprint equals
  `metadata["asymmetric"]["sender"]["key_id"]`. The signature does cover the whole metadata, so
  this is an authenticity/UX gap (user told "verified" against a non-declared identity), not a
  forgery. **Fix:** verify the resolved sender key's fingerprint matches the signed
  `asymmetric.sender.key_id`.

### L4 — [MEM-2] KDF key components cross the process boundary via spawn+pickle into unlocked memory
- `parallel_kdf.py:639-681,689` — with `spawn`, `initial_hash` (a direct final-key component) is
  pickled to every worker and each component is pickled back as plain `bytes`, living in multiple
  address spaces + OS pipe buffers, never wiped and outside the mlock'd region. The raw password is
  **not** sent (only its salted SHA-256), limiting blast radius. **Fix:** minimize lifetime
  (`del`+`gc` each `results` entry right after it's folded into the accumulator); consider not
  shipping a raw key component.

### L5 — [MEM-3] Divergent, weaker `secure_memzero` in `secure_ops.py`
- `secure_ops.py:148-174` — a second `secure_memzero` (distinct from the hardened
  `secure_memory` one): no verification, returns `None`, no M10 immutable-input contract (passing
  `bytes` raises mid-loop). Contained today (only `SecureContainer`, always a bytearray) but a
  same-named foot-gun. **Fix:** delegate to `secure_memory.secure_memzero` and return its bool.

### L6 — [MEM-4] Non-constant-time canary comparison
- `secure_allocator.py:205,211,218` — `check_canaries()` compares secret canaries with `!=`
  (variable-time). Very low risk (canaries are integrity tokens; timing attacker already has local
  execution), but `hmac.compare_digest` matches the module's own posture. **Fix:** constant-time
  compare.

### L7 — [IO-1] SHA-256 of the full plaintext stored in cleartext v12 metadata
- `crypt_core.py:6112` (→ `create_metadata_v8(original_hash=...)`) — the streaming header stores
  `SHA-256(plaintext)` in cleartext (also bound as per-chunk AAD). For low-entropy/known-candidate
  inputs this is an offline confirmation/known-plaintext verifier. Streaming files are usually
  high-entropy (mitigation); **may be pre-existing** (confirm it wasn't already accepted under
  1.4.7). **Fix (if in scope):** use a keyed MAC over the plaintext (key via HKDF from the file
  key) instead of a bare hash.

### L8 — [AUDIT-1] Audit-chain anchor pubkey pinning is optional and defaults to unpinned
- `audit_verifier.py:83-84,286-305`; `audit_cli.py:85-90,142-148` — `verify_chain` only pins the
  anchor pubkey when `--anchor-pubkey` is passed; otherwise anchors are verified against the pubkey
  **embedded in the anchor itself**. The ML-DSA anchor signature exists to survive compromise of
  the forward-secure MAC seed, but that protection is void without pinning (an attacker with the
  seed re-signs anchors with their own keypair + embedded pubkey; unpinned verify passes). **Fix:**
  persist the trusted anchor pubkey at chain-init and pin by default; missing/mismatched pin =
  verification failure.

---

## Informational

- **I1 — [SSS-1]** `secret_sharing.py:72-74` — GF(256) `mul` has a data-dependent early-return on
  zero operands (small timing variation over secret share bytes). Very low risk for local
  split/combine of a static high-entropy secret; a fully table-driven `mul` removes it. Coefficients
  use CSPRNG (good).
- **I2 — [KDF-3]** `crypt_core.py:5963-5971` — selecting `--xor-mode independent` while leaving the
  default `format_version=9` yields independent-XOR **without** v13 per-component domain separation.
  Safe for the current distinct-algorithm set but silently forgoes the v13 hardening; consider
  auto-selecting `format_version=13` when `xor_mode="independent"` is explicitly requested.
- **I3 — [MEM-5]** `telemetry_filter.py:236-281` — hash *rounds* are dropped as "identifying" yet
  exact Argon2/scrypt cost tuples (`time_cost`, `memory_cost`, `parallelism`, `n/r/p`) are forwarded
  to telemetry plugins — equally fingerprinting. No key leak (numeric allow-list). Coarsen to
  buckets for parity if plugins are untrusted.
- **I4 — [PQC-1]** `crypt_core.py:9840-9864` — a DEK unlocked from a recovery slot is trusted after
  only the DEK-keyed slot-set MAC; not cross-checked against the primary `wrapped_dek` (safe because
  bulk AEAD fails closed, but an explicit consistency check fails earlier/clearer). The `except` at
  `:9853` catches everything, which can mask programming errors.
- **I5 — [PLUGIN-3]** Default signature policy is `WARN` (`plugin_manager.py:121`) — unsigned
  third-party plugins still load+execute after a log line. Documented decision (D1); combined with
  H2/M1 it means signing provides no hard guarantee unless the operator sets `ENFORCE`. Consider
  defaulting third-party dirs to `ENFORCE`.
- **I6 — [IO-2]** `hidden_header.py:417-420,462-463` — keyless hidden-header mode provides no header
  integrity (16 random decoy `auth` bytes, XOR-whitening only). Documented anti-fingerprinting-only;
  callers feed it back through the authenticated inner pipeline, so acceptable as-is.

---

## Assessed sound (no action)
v8/v10 cancellation fix + rekey upgrade; `_indep_xor_component_salt` v13 domain separation;
RandomX/HKDF-only fail-closed; recovery-slots (clamped Argon2 params, DEK-keyed slot MAC,
constant-time compare, wiped KEKs); Shamir secret sharing (CSPRNG, range/dup checks); per-chunk
nonce uniqueness + cascade scheme-2 per-chunk salts + AAD truncation/reorder binding + temp-file
staging before trailer HMAC; cascade layer independence + type-based auth-error; XChaCha 192-bit
format-2 construction; KEM ciphertext binding (IND-CCA2) + no decap simulation/unauth fallback;
envelope AAD deny-list + fail-closed rekey; identity fingerprint v2 + TOFU refusal;
`constant_time_pkcs7_unpad` branchless; `debug_secret` keyed + redaction-default + dual-gated CLI;
`SECRET_VALUE_CLI_OPTIONS` complete; audit-chain forward-secure key evolution + Merkle domain
separation + atomic 0600 writes; JSON validator pre-parse depth scan + fail-closed on unknown
versions; keystore C6/M7 fixes; PIV backend (deterministic-only, PIN zeroized, HKDF domain
separation); YubiKey/OnlyKey (per-file random challenge, length-only logging); AST analyzer
(frame/traceback + getattr/subscript bypass coverage).
