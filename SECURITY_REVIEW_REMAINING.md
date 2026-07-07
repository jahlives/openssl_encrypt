# Security Review v1.4.7 — Remaining Open Issues

_Generated 2026-07-02 from GitLab `sec-review::1.4.7` (project `world/openssl_encrypt`). 26 issues open; everything Critical/High/Medium is resolved except #66._

> **Update 2026-07-07:** #89 [CLI-6] resolved — see the Resolved section below.

Each issue links to its GitLab entry (which has the full finding + verification notes). Fixes land on BOTH `feature/v1.4.x-development` and `feature/v1.5.x-development`, each with a regression test and full-suite check, per the project workflow.


## Actionable — Medium (1)

### #66 — [CLI-3] Plugin top-level code is exec'd in the main process, gated only by an AST blocklist
- **severity:** medium · **priority:** soon · [GitLab #66](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/66)
- **FIX (design task) — the only actionable item above LOW.** Plugin top-level code runs via `spec.loader.exec_module` in the main process (plugin_manager.py:233), gated only by an AST denylist. Existing mitigations: writable-location refusal, TOCTOU re-hash before exec, strict mode, built-in containment — so it's 'user loads untrusted code from their own owner-only dir that also evades the denylist', not remote/drop-in RCE. **Recommended fix:** require non-built-in plugins to carry a detached signature verified against a trusted key before exec, reusing the existing source-integrity signing infra (keep AST as defense-in-depth). Large/architectural — touches plugin loading, distribution, and the built-in-plugin flow; needs design + cross-plugin testing. Alt: run plugin load in a spawned, privilege-dropped subprocess (larger, risks HSM/FIDO2/stego flows).


## Deferred / reclassified-LOW (future hardening) (7)

_Downgraded from higher tiers after verification; kept open as future/optional hardening. None exploitable._

### #59 — [KDF-1] Balloon KDF provides negligible memory-hardness at default parameters
- **severity:** low · [GitLab #59](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/59)
- Reclassified LOW. Balloon defaults (`space_cost=16`) are function fallbacks; real encryption uses `space_cost=65536` (CLI/templates), and Balloon is stacked behind Argon2id. Optional: raise the fallback constants to the 65536 default as defense-in-depth. Not exploitable.

### #74 — [IO-4] os.umask() process-global race in file/dir creation
- **severity:** low · [GitLab #74](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/74)
- Reclassified LOW; mostly moot. `create_secure_file` now `fchmod`s post-open (#58) and `create_secure_directory` post-`chmod`s, and the umask is set MORE restrictive (fails safe). Optional cleanup: mkdir-then-chmod to drop the global-umask side effect. No exploitable weakening.

### #79 — [MEM-6] Multi-pass / explicit_bzero wiping is dead code
- **severity:** low · [GitLab #79](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/79)
- Reclassified LOW. An early return in `secure_memzero` makes the multi-pass/explicit_bzero/msync block dead code for bytearray/memoryview; the single slice-assignment still zeroes correctly. Dead defense-in-depth, not a remanence hole. Fix: delete the unreachable code or route through it.

### #80 — [MEM-7] secure_memzero zeroes a copy for non-bytearray buffer types but reports success
- **severity:** low · [GitLab #80](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/80)
- Reclassified LOW; unreachable. `secure_memzero` wipes a COPY (returns True) for non-bytearray writable types, but no caller passes array.array/ctypes (all pass bytearray/SecureBytes/bytes/str). Cheap to make honest (return False for non-in-place types).

### #81 — [MEM-8] Key material leaked into immutable objects that cannot be wiped
- **severity:** low · [GitLab #81](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/81)
- Reclassified LOW; inherent Python limitation. `get_bytes`/`get_as_str` and KDF `.derive()` returns produce immutable bytes/str that can't be zeroed. Mitigation: steer callers to `get_bytearray()`. A true fix needs a C-extension / bytearray-only end-to-end. Defer.

### #82 — [MEM-9] 'Guard pages' are in-band canaries only, checked lazily
- **severity:** low · [GitLab #82](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/82)
- Reclassified LOW; partly mitigated by #60/#63. Canaries are software/in-band (no real mprotect guard pages), but the block is now mlock'd + madvise(MADV_DONTDUMP) with key material inside it. Remaining: 'software canaries, not hardware guard pages'. Real guard pages = large rewrite, low marginal benefit.

### #83 — [PQC-3] KEM shared secret keyed through bare SHA-256 (no KDF, no domain separation, no transcript binding)
- **severity:** low · [GitLab #83](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/83)
- Reclassified LOW; deferred to a future format bump. `sha256(shared_secret)` KEM key derivation is sound (ML-KEM output is uniform, IND-CCA2) and the KEM ciphertext is implicitly bound (wrong ct -> wrong key -> AEAD fail). HKDF + explicit ciphertext-AAD is cleaner but FORMAT-BREAKING for no exploitable gain — do it at a future format-version bump.


## LOW — cosmetic / inherent / marginal (informational) (18)

_Assessed as not worth churning: cosmetic, inherent Python limits, already-conditional, behavior-sensitive, or marginal defense-in-depth where liboqs already validates. None exploitable. Listed for completeness; pick any if desired._

| # | Code / title | Disposition |
|---|---|---|
| [#88](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/88) | [CLI-5] Subprocess children inherit the full environment (incl. password env vars); python3 via PATH; PYTHONPATH from sys.path | Subprocess (RandomX probe) inherits full env incl. password env vars; `python3` via PATH; PYTHONPATH from sys.path. Low: requires a writable sys.path entry / hostile PATH. Fix: pass a scrubbed minimal env, absolute interpreter, avoid CWD-relative sys.path. |
| [#90](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/90) | [CORE-10] constant_time_pkcs7_unpad has data-dependent branches | `constant_time_pkcs7_unpad` has data-dependent branches despite its name. Only reachable post-MAC (and the #53 Camellia fix enforces MAC-first). Fix: rewrite branchless over a fixed block size. Low; non-trivial. |
| [#91](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/91) | [CORE-7] Cascade auth-failure classification by exception-string matching leaks layer info | Cascade auth-failure is classified by substring-matching the underlying error text, and discloses which layer failed. Fix: catch concrete InvalidTag/AuthenticationError types; uniform layer-agnostic error. Low. |
| [#92](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/92) | [CORE-8] verify_mac `associated_data` parameter is a no-op (misleading API) | Cosmetic/footgun. `verify_mac(associated_data=...)` is a no-op (never incorporated); the Camellia caller already binds AAD in hmac_data. Safe fix: remove the misleading param + update the 2 crypt_core callers (no behavior change). Do NOT make it bind (would double-count -> break files). |
| [#93](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/93) | [CORE-9] Legacy XChaCha nonce_format=1 advertises 192-bit nonce but funnels to 96 bits | Docs/clarity. Legacy XChaCha nonce_format=1 HKDF-funnels a 24-byte nonce to 96-bit effective; the '192-bit' naming is illusory for format 1 (format 2 is the real construction). Correct comments/docs. |
| [#94](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/94) | [IO-5] JSON nesting-depth limit enforced only after json.loads; RecursionError uncaught | `validate_json_structure` depth cap (20) runs AFTER `json.loads` parses fully; RecursionError not caught. Guard is cosmetic. Fix: enforce depth during parse + catch RecursionError. Low (CPython recursion fails safe). |
| [#95](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/95) | [IO-6] 64-bit per-file nonce prefix for streaming AEAD (thin margin if a key is ever reused) | 64-bit per-file nonce prefix for streaming AEAD. Safe in practice (per-file random key), only thin if a caller reuses a fixed DEK across files. Optional: widen to 16 bytes. |
| [#96](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/96) | [IO-7] Streaming decrypt writes per-chunk-authenticated plaintext before the trailer HMAC verification | Streaming decrypt writes per-chunk-authenticated plaintext before the trailer HMAC verifies (output removed on failure). No unauthenticated plaintext released; a concurrent reader could observe a partial file later deleted. Optional: stage to temp + rename after trailer verifies. |
| [#97](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/97) | [KDF-10] CommonPasswordChecker custom-path branch does not set loaded flag | INFO/behavior quirk. CommonPasswordChecker custom-path branch doesn't set `loaded_at_least_one`, so the embedded list is also loaded (custom + embedded). One-line fix, but changes custom-only vs custom+embedded behavior — confirm intent first. |
| [#98](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/98) | [KDF-6] Key fingerprint lacks domain separation / algorithm binding | Key fingerprint concatenates enc+sign pubkeys without length prefix and excludes algorithm ids. Ambiguous; algorithm-substitution not reflected. Low (fixed-length keys). Fix: length-prefix + algorithm-tag the fingerprinted encoding. |
| [#99](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/99) | [KDF-7] Config can select only non-stretching KDFs (e.g. HKDF-only) | Config can select HKDF-only (non-stretching) + zero hash rounds -> weak file key. XOR combiner is strongest-component so harmless if a strong component is also enabled. Fix: require >=1 memory-hard/iterated component; reject HKDF-only. |
| [#100](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/100) | [KDF-8] Missing length separation in seed/hash inputs (canonicalization ambiguity) | Length-separation hygiene: `sha256(password + salt)` / balloon hash_func concatenate without delimiters. Canonicalization-ambiguous but impractical (fixed/known salt). Fix: length-prefix fields. |
| [#103](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/103) | [MEM-11] supports_madv_dontdump set True without a real check; madvise/msync return ignored | `supports_madv_dontdump` — verify the runtime probe (secure_memory.py:458) actually checks support vs hardcoding; madvise/msync return values ignored. Low hygiene. |
| [#104](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/104) | [MEM-12] Irreversible global RLIMIT_CORE hard-limit drop as a side effect of allocation | `setrlimit(RLIMIT_CORE, (0,0))` sets the HARD limit to 0 (irreversible, process-global) on every allocation, across secure_memory (2) + secure_allocator (1). Fix: set soft limit only, restore, do it once. Behavior-sensitive (core-dump prevention) — care needed. |
| [#105](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/105) | [MEM-13] Debugger 'detection' is security theater | Security theater. `_detect_debugger`/`_anti_debug_check` only warn (TracerPid trips under any ptrace); no protective action. Remove or clearly mark advisory-only. |
| [#106](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/106) | [MEM-14] secure_erase_system_memory writes /proc/sys/vm/drop_caches with misleading intent | `secure_erase_system_memory` writes /proc/sys/vm/drop_caches (needs root, silently fails; misleading comment). Cosmetic — remove/correct. |
| [#107](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/107) | [PQC-10] KEM/DSA public keys and ciphertexts used without length/structure pre-validation | KEM/DSA public keys + ciphertexts passed to liboqs without length/structure pre-validation (relies on liboqs internal checks); HQC path hardcodes+slices ciphertext sizes. Defense-in-depth: validate against `length_public_key`/`length_ciphertext` before use. Low (liboqs already validates). |
| [#109](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/109) | [PQC-9] check_pqc_support fabricates a 'supported' algorithm list on error | `check_pqc_support` fabricates a 'supported' ML-KEM/Kyber list on exception, masking a non-functional backend. Fix: return the true (possibly empty) enabled-mechanism list. Some downstream risk if callers rely on the fabricated list — verify before changing. |


## Resolved (1)

### #89 — [CLI-6] In-memory 'secure clear' of password strings is a no-op — **RESOLVED 2026-07-07**
- **severity:** low · [GitLab #89](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/work_items/89)
- The CLI pseudo-wipe (`pwd = "\x00"*len(pwd)`) was already removed from `crypt_cli.py` and guarded by `test_cli_password_wipe.py`. On follow-up the **same bug-class was found in `keystore_utils.py`** (`store_pqc_key_in_keystore` cleanup): a fallback `encrypted_private_key = b"\x00" * len(...)` that rebinds a fresh zero-filled bytes object and never overwrites the original immutable buffer (also dead code — `secure_memzero` handles immutable bytes without raising). Removed the misleading rebind; `encrypted_private_key` is always `None`/immutable bytes (base64.b64decode output) so dropping the reference is all that's possible. Broadened the regression test to scan **all** modules (comparison-safe regex so the all-zero pepper `==` checks in `crypt_core.py` are not flagged). crypto-reviewer: approved (no wiping guarantee weakened, no mutable-buffer path missed).
- **Fixed on both branches:** `feature/v1.4.x-development` `d014fd1f`, `feature/v1.5.x-development` `f1b529ba`. Full suites green (v1.4.x 3131 passed; v1.5.x 5472 passed). Both pushed to origin.

---

## Suggested order for tomorrow

1. **#66** — draft the signed-manifest plugin-loader design, then implement (largest item).
2. Optional quick LOW wins if desired: **#92** (remove no-op `verify_mac` param), **#104** (RLIMIT_CORE soft-limit-only, with care), **#99**/**#59** (reject/strengthen weak-KDF configs). (**#89** done — see Resolved.)
3. Leave the purely cosmetic/inherent items (#81, #90, #91, #93, #94, #105, #106) unless convenient.

