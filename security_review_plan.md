# Security Audit Report: `feature/v1.5.x-development` Branch

**Scope:** Full branch diff vs `main` — ~102K lines changed across 1364 files
**Date:** 2026-03-06
**Reviewer:** Automated deep review (6 parallel security agents)

---

## Executive Summary

| Severity | Count |
|----------|-------|
| **CRITICAL** | 7 |
| **HIGH** | 14 |
| **MEDIUM** | 24 |
| **LOW** | 17 |

The branch introduces significant new functionality (PQC, cascade encryption, plugin system, identity management, secret sharing, streaming encryption, archive support) with several serious security issues that should be addressed before release.

---

## CRITICAL Findings

### C1. Bare SHA-256 for KEM Shared Secret to Symmetric Key Derivation

**Files:** `pqc.py:595`, `pqc_adapter.py:278`

```python
symmetric_key = hashlib.sha256(shared_secret).digest()
```

All PQC encryption derives symmetric keys via a single `SHA-256(shared_secret)` instead of HKDF with domain separation, violating NIST SP 800-56C. This truncates larger KEM shared secrets (e.g., HQC's 512-bit output) and lacks extract-then-expand processing needed for non-uniform KEM outputs.

**Recommendation:** Replace with `HKDF-SHA256(ikm=shared_secret, salt=random, info=domain_label)`.

---

### C2. Weak KDF in Asymmetric Password Wrapping

**File:** `asymmetric_core.py:206-209`

```python
h = hashlib.sha256()
h.update(b"openssl_encrypt.password_wrap.v1")
h.update(shared_secret)
wrap_key_bytes = h.digest()
```

The AES-256-GCM password wrapping key uses `SHA-256(domain || shared_secret)` instead of HKDF. If the KEM shared secret is not uniformly distributed, SHA-256 alone may not extract a uniform key.

**Recommendation:** Use HKDF-SHA256 with the domain label as `info`.

---

### C3. Plugin Sandbox Escape via `exec()` Without Guards

**File:** `plugin_sandbox.py:1028-1058`

`IsolatedPluginExecutor.execute_in_process()` calls `exec(plugin_code)` with restricted builtins but **no AST validation and no import guard**. The restriction is trivially escapable via `().__class__.__bases__[0].__subclasses__()` to access `os.system`, `subprocess.Popen`, etc.

**Recommendation:** Run AST validation before `exec()`, install the import guard, or use a proper sandboxing mechanism (seccomp, namespace isolation).

---

### C4. AST Analysis Only Inspects Plugin Class, Not Module-Level Code

**File:** `plugin_sandbox.py:38-69`

`_validate_plugin_source()` uses `inspect.getsource(type(plugin))` which only returns the **class definition**. Module-level malicious code executes at import time before any validation.

**Recommendation:** Validate the full module source file, not just the class.

---

### C5. Silent AST Validation Skip When Source Unavailable

**File:** `plugin_sandbox.py:52-55`

When `inspect.getsource()` raises `OSError`/`TypeError` (e.g., dynamically-created classes), validation is **silently skipped**. A malicious plugin can use `type()` to create a class dynamically and bypass all AST analysis.

**Recommendation:** Fail closed -- reject plugins whose source cannot be analyzed.

---

### C6. Post-Encryption Metadata Modification Breaks AEAD

**File:** `keystore_wrapper.py:275-281`

After encryption with AEAD ciphers (AES-GCM), the code rewrites the metadata section (removing private key fields). If metadata was bound as AAD during encryption, this **invalidates the authentication tag**, silently removing integrity protection.

**Recommendation:** Strip metadata before encryption, not after.

---

### C7. Streaming Decryptor Reads Entire File Into Memory

**File:** `streaming.py:591-596`

```python
file_content = fin.read()  # Reads entire file!
```

The streaming decryptor defeats its own purpose by reading the entire file at once. A crafted file can cause memory exhaustion.

**Recommendation:** Refactor to process chunks from the file handle incrementally.

---

## HIGH Findings

### H1. Path Traversal in Identity Name Leading to Arbitrary File Delete

**Files:** `identity.py:577-586, 636, 655`

Identity names are used directly in path construction with no sanitization. `delete_identity("../../important_data")` calls `shutil.rmtree()` on arbitrary directories. Combined with `--force`, no confirmation is shown.

**Recommendation:** Validate names with `re.match(r'^[a-zA-Z0-9_.-]+$', name)`.

---

### H2. Untrusted Identity Name from Imported JSON

**Files:** `identity.py:436`, `identity_cli.py:426`

When importing a public identity, the `name` field from untrusted JSON is used for directory creation. Combined with H1, a crafted export triggers path traversal.

**Recommendation:** Apply the same name validation as H1 during import.

---

### H3. Ineffective `secure_memzero()` on Immutable `bytes` Objects

**Files:** `crypt_core.py` (throughout), `crypto_secure_memory.py`, `parallel_kdf.py:758-768`

`secure_memzero(bytearray(some_bytes))` creates and zeros a **copy**; the original immutable `bytes` persists in memory. Setting variables to `None` (crypto_secure_memory.py:196-197, 230, 236) is equally ineffective.

**Recommendation:** Use `bytearray` from the start for all sensitive data, or document the limitation. Consider ctypes-based wiping for critical paths.

---

### H4. PQC Integrity Check Bypass in Production

**File:** `crypt_core.py:8847-8866`

For ML-KEM algorithms in non-test environments, integrity check failures return `b""` instead of raising an error, silently discarding tampered/corrupted data.

**Recommendation:** Fail hard on integrity check failure regardless of algorithm.

---

### H5. Algorithm Downgrade via Fuzzy Matching Fallback

**File:** `pqc.py:374-411`

If a requested KEM algorithm isn't found, the code silently falls back to the first available algorithm instead of raising an error.

**Recommendation:** Fail with an explicit error when the exact algorithm is unavailable.

---

### H6. HKDF Salt Reuse Across Cascade Layers

**File:** `cascade.py:181-198`

All cascade layers derive keys and nonces from the same `(master_key, salt)`, differentiated only by the `info` parameter. If cipher names collide or are manipulated, keys could collide.

**Recommendation:** Use per-layer salt derivation (e.g., `HKDF(salt || layer_index)`).

---

### H7. Deterministic Nonces in Cascade (Catastrophic if Salt Reused)

**File:** `cascade.py:191-198`

Nonces are derived deterministically via HKDF. If the same `(master_key, salt)` is ever reused (e.g., by a caller providing their own salt), all nonces repeat -- catastrophic for AES-GCM.

**Recommendation:** Document salt uniqueness requirement; consider adding a random component per layer.

---

### H8. AST Analysis Bypass Vectors

**File:** `plugin_ast_analyzer.py`

Multiple bypass routes: `vars()`, `dir()`, `globals()`, `locals()` not blocked; `getattr` with dynamic strings evades detection; `__class__` not blocked (entry point for subclass traversal); `type()` not blocked.

**Recommendation:** Block `vars`, `dir`, `globals`, `locals`, `type` builtins; detect `__class__` attribute access.

---

### H9. `os` Module Functions Incompletely Blocked

**Files:** `plugin_ast_analyzer.py`, `plugin_sandbox.py`

`os.execv/execve/execvp/execvpe`, `os.environ`, `os.remove`, `os.chmod`, `os.symlink` are not in `DANGEROUS_OS_FUNCTIONS`. In threading mode, `os.exec*` family is not monkey-patched.

**Recommendation:** Expand `DANGEROUS_OS_FUNCTIONS` and monkey-patch coverage.

---

### H10. Built-in Plugin Root Bypasses All Security Validation

**File:** `plugin_manager.py:686-691`

Files under `builtin_plugin_root` skip ALL security validation. If an attacker can write to that directory, plugins are fully trusted.

**Recommendation:** Validate built-in plugins too, or ensure the directory has restrictive permissions.

---

### H11. No File Permission Enforcement on Keystore Files

**Files:** `keystore_utils.py`, `keystore_wrapper.py`

Keystore files containing encrypted private key material are created with default umask (typically world-readable 0644).

**Recommendation:** Set `os.chmod(path, 0o600)` after creating keystore files.

---

### H12. Temporary Files Without Restrictive Permissions

**File:** `crypt_cli.py:7033-7036, 8578-8582, 8909-8913`

Several `NamedTemporaryFile(delete=False)` calls don't set `0o600` permissions, unlike the stdin temp file which correctly does so.

**Recommendation:** Add `os.chmod(temp_file.name, 0o600)` after creation consistently.

---

### H13. Streaming HMAC Key Uses `SHA-256(key || constant)` Instead of HKDF

**File:** `streaming.py:508, 675`

```python
hmac_key = hashlib.sha256(self.key + b"oesc-trailer-hmac").digest()
```

The trailer HMAC key derivation uses concatenation-then-hash instead of proper HKDF key derivation.

**Recommendation:** Replace with `HKDF-SHA256(ikm=key, info=b"oesc-trailer-hmac")`.

---

### H14. No Maximum Chunk Size Validation in Streaming Decryptor

**File:** `streaming.py:629-641`

The `ciphertext_len` field is read from the file without any sanity check against a maximum expected size, enabling memory exhaustion with crafted files.

**Recommendation:** Enforce `ciphertext_len <= chunk_size + AEAD_tag_overhead` with a reasonable maximum.

---

## MEDIUM Findings

### M1. Share Files Written World-Readable (0644)

**File:** `secret_sharing.py:226`

Share files contain secret-derived data but are written using default umask.

**Recommendation:** Write with `0o600` permissions.

---

### M2. `share_index` Not Validated in [1,255] Range

**File:** `secret_sharing.py:316-363`

`combine_shares` never validates that `share_index` values are in [1, 255]. A crafted share with `share_index=0` causes incorrect reconstruction; `share_index>=256` causes `IndexError` in `LOG_TABLE`.

**Recommendation:** Validate range in `combine_shares`.

---

### M3. Threshold Not Cross-Validated Across Shares

**File:** `secret_sharing.py:337-339`

The threshold is read from the first share's metadata and trusted. A modified threshold value allows reconstruction with fewer shares than intended.

**Recommendation:** Verify all shares agree on `threshold` and `total_shares`.

---

### M4. AES-GCM Without AAD in Identity Key Encryption

**Files:** `identity.py:759,839`, `identity_protection.py:450,516`

```python
ciphertext = cipher.encrypt(nonce, private_key, None)
```

Without AAD, encrypted private keys are not bound to context (identity name, key type). An attacker with disk access could swap encrypted keys between identities.

**Recommendation:** Bind AAD to identity name and key purpose.

---

### M5. Fingerprint Not Verified on Identity Import

**File:** `identity_cli.py:421-429`

When importing a public identity, the fingerprint from JSON is stored but never recomputed and verified against the actual public keys.

**Recommendation:** Call `identity.verify_fingerprint()` during import.

---

### M6. Pepper Cache Not Auto-Wiped on Destruction

**File:** `identity_protection.py:210,347-351`

`IdentityKeyProtectionService` caches the HSM pepper but `clear_pepper_cache()` is never called automatically. The wiping at line 350 creates a new `bytearray` from immutable `bytes` and wipes the copy.

**Recommendation:** Add `__del__` and context manager support.

---

### M7. HSM Plugins Disable Process Isolation

**File:** `plugin_manager.py:582`

`execute_hsm_plugin` always uses `use_process_isolation=False`, giving HSM plugins weaker sandboxing.

**Recommendation:** Document this risk or enable process isolation for HSM plugins.

---

### M8. Incomplete File Access Restriction in Plugin Sandbox

**File:** `plugin_sandbox.py:525-585`

File restrictions don't cover `os.open()`, `os.fdopen()`, `mmap.mmap()`, `codecs.open()`, `tempfile` functions.

**Recommendation:** Block or patch these additional file access vectors.

---

### M9. TOCTOU in `_is_safe_path` Symlink Check

**File:** `plugin_sandbox.py:766-790`

Race between `islink` check and `realpath` resolution. An attacker could replace a regular file with a symlink between checks.

**Recommendation:** Use `O_NOFOLLOW` or operate only on resolved paths.

---

### M10. `PluginResult.__init__` Bypasses Sensitive Key Filtering

**File:** `plugin_base.py:195-208`

Only `add_data()` filters sensitive keys. A plugin can bypass filtering via the constructor: `PluginResult(data={"password": "stolen"})`.

**Recommendation:** Apply filtering in `__init__` as well.

---

### M11. `ignore_integrity_checks` Defaults to `True`

**File:** `pqc.py:438`

The PQCipher constructor disables integrity checks by default, undermining authenticated encryption guarantees.

**Recommendation:** Default to `False`; override explicitly for legacy compatibility.

---

### M12. AAD Only Applied to First Cascade Layer

**File:** `cascade.py:285`

```python
aad = associated_data if i == 0 else None
```

Only the innermost layer authenticates the AAD. Outer layers can be stripped/re-wrapped without detection until the inner layer fails.

**Recommendation:** Bind AAD (including layer index and cipher chain) at each layer.

---

### M13. Mutable Registry Singletons Allow Algorithm Injection

**Files:** `registry/*.py`

After initialization, `register()` is publicly accessible, allowing any code to add or replace algorithms.

**Recommendation:** Freeze registries after initialization.

---

### M14. Threefish HKDF Key Expansion Uses `salt=None`

**Files:** `pqc.py:623-628`, `pqc_adapter.py:307-312`

HKDF with `salt=None` uses a zero-filled salt, reducing the strength of the extract phase.

**Recommendation:** Use a random salt stored alongside the ciphertext.

---

### M15. Static HKDF Salt for PQC Signature-Hybrid Algorithms

**File:** `crypt_core.py:5924-5936`

```python
salt = b"OpenSSL-Encrypt-PQ-Signature-Hybrid"
```

This shadows the random salt from line 5276, meaning every encryption with the same private key produces the same AES-GCM key.

**Recommendation:** Use the random salt generated earlier or generate a new one.

---

### M16. KeyStretch Mutable Class-Level State (Concurrency Risk)

**File:** `crypt_core.py:719-722`

`KeyStretch` uses mutable class-level attributes shared across all instances and threads. `decrypt_file` only partially resets state.

**Recommendation:** Use instance-level state or pass state explicitly.

---

### M17. Silent KDF Failure Continues with Weakened Key

**File:** `crypt_core.py:2939-2943`

When Argon2/Balloon/Scrypt fails, encryption proceeds with a potentially much weaker key derivation. No error is raised.

**Recommendation:** Raise an error on KDF failure rather than continuing with degraded security.

---

### M18. Pepper Key Derived from Raw SHA-256(password)

**File:** `crypt_core.py:5382`

```python
pepper_key = hashlib.sha256(password).digest()
```

No salt, no iteration count. An attacker with the encrypted pepper can brute-force the password with one SHA-256 per guess, bypassing the expensive KDF chain.

**Recommendation:** Use a proper KDF (e.g., HKDF or Argon2) for pepper key derivation.

---

### M19. Key Material Serialized via Pickle to Child Processes

**File:** `parallel_kdf.py:596-619`

Worker functions receive key-derived bytes via pickle serialization through OS pipes. Serialized data may persist in pipe buffers and kernel memory.

**Recommendation:** Document the limitation; consider using shared memory with explicit wiping.

---

### M20. 8192-Byte Metadata Read Limit May Truncate Large PQC Keys

**File:** `keystore_wrapper.py:328`

For PQC algorithms with large keys (e.g., HQC-256 ~7.6KB), the read limit may not capture the entire metadata.

**Recommendation:** Increase the limit or read until the delimiter is found.

---

### M21. TOCTOU Race in Keystore File Rewrite

**File:** `keystore_wrapper.py:434-439`

File is read, closed, then reopened for writing. Another process could modify it between operations.

**Recommendation:** Use atomic file operations (write to temp, then rename).

---

### M22. Regex UUID Fallback May Select Wrong Key ID

**File:** `keystore_utils.py:158-177`

When JSON parsing fails, regex extracts the first UUID found in metadata, which may not be the key ID.

**Recommendation:** Fail rather than guessing; or validate the UUID against expected context.

---

### M23. Debug Mode Controlled by Environment Variable

**File:** `crypt_errors.py:150,283`

`DEBUG=1` or `PYTEST_CURRENT_TEST` environment variables enable detailed error messages. An attacker who can set env vars gets debug output in production.

**Recommendation:** Use a configuration file or CLI flag rather than environment variables for debug mode.

---

### M24. Environment Variable Password Clearing is Ineffective

**File:** `crypt_cli.py:351-379`

Python strings are immutable; overwriting `os.environ["CRYPT_PASSWORD"]` creates new string objects. The original password string remains in memory.

**Recommendation:** Document the limitation; consider using `ctypes` for C-level string wiping.

---

## LOW Findings

### L1. Share Data as Plaintext Integers in JSON

**File:** `secret_sharing.py:183`

Share bytes stored as `[42, 195, 13, ...]` without encryption or encoding.

**Recommendation:** Consider base64 encoding for defense in depth.

---

### L2. Python Int Wiping is Inherently Ineffective

**File:** `secret_sharing.py:299-301`

Python integers are immutable objects; `coeffs[j] = 0` replaces the reference, not the memory.

**Recommendation:** Document the limitation.

---

### L3. Logger f-string Injection via Identity Names

**File:** `identity.py:159,204,245,310,338,400,546,556,658`

Identity names with special characters or newlines could corrupt log files.

**Recommendation:** Sanitize names before logging.

---

### L4. Private Key Bytes Copies Not Wiped After Use

**File:** `identity.py:384`

`.get_bytes()` returns a copy that is never wiped after being passed to `_encrypt_private_key`.

**Recommendation:** Wipe the copy in a `finally` block.

---

### L5. `bytes` Immutability Defeats Pepper Cache Wiping

**File:** `identity_protection.py:350`

`secure_memzero(bytearray(self._cached_pepper))` wipes a copy, not the original `bytes`.

**Recommendation:** Store pepper as `bytearray` instead of `bytes`.

---

### L6. Audit Log Has No Integrity Protection

**File:** `plugin_manager.py:882-893`

In-memory list truncated at 1000 entries. An attacker could flood the log to evict evidence.

**Recommendation:** Add log integrity checks or write to append-only storage.

---

### L7. Resource Monitoring Ineffective in Threading Mode

**File:** `plugin_sandbox.py:846-858`

Exceptions raised in the monitoring thread don't propagate to the execution thread.

**Recommendation:** Use a shared cancellation flag or `threading.Event`.

---

### L8. Plugin Config Warns But Doesn't Block Sensitive Keys

**File:** `plugin_config.py:538-578`

Validation logs warnings for sensitive-looking keys but doesn't reject them.

**Recommendation:** Reject or redact sensitive keys in plugin configs.

---

### L9. `PQSigner.sign()` Mutates Shared State (Thread-Unsafe)

**File:** `pqc_liboqs.py:364-368`

`sign()` imports the secret key into the shared `self.sig` instance, creating a race condition.

**Recommendation:** Create per-call signer instances or add locking.

---

### L10. `check_pqc_support()` Returns Hardcoded Algorithms on Exception

**File:** `pqc.py:190-196`

Falls back to hardcoded algorithm names rather than failing, potentially reporting unavailable algorithms as available.

**Recommendation:** Return empty list on exception or propagate the error.

---

### L11. Signature Verification Swallows All Exceptions

**File:** `pqc_signing.py:238-241`

All exceptions (including `MemoryError`, `TypeError`) are caught and converted to `False`.

**Recommendation:** Only catch cryptographic exceptions; re-raise system errors.

---

### L12. TOCTOU in `set_secure_permissions`

**File:** `crypt_core.py:887-898`

Gap between `realpath()`/`samefile()` and `chmod()` allows symlink substitution.

**Recommendation:** Use `O_NOFOLLOW` with `fchmod` on the open file descriptor.

---

### L13. `PYTEST_CURRENT_TEST` Env Var Alters Security Behavior

**File:** `crypt_core.py:5097` and others

Test environment detection changes error messages, nonce sizes, and exception types.

**Recommendation:** Remove production behavior changes based on test env vars.

---

### L14. Timing Jitter Degrades to Constant Under Rapid Calls

**File:** `crypt_errors.py:207-208`

After 5+ rapid calls, jitter falls to `min_ms`, becoming predictable.

**Recommendation:** Use cryptographic randomness for jitter instead of adaptive decay.

---

### L15. Missing Schema for Format Version 9

**File:** `json_validator.py:86-88`

Format version 9 falls through to "unknown version" and bypasses schema validation entirely.

**Recommendation:** Add a v9 schema or explicitly handle v9 in validation.

---

### L16. FIDO2 Credential File TOCTOU on Permissions

**File:** `fido2_pepper/__init__.py:288-297`

Temp file created with default permissions, then `chmod` to 0o600. Brief window of exposure.

**Recommendation:** Use `os.open()` with `O_CREAT | O_WRONLY` and mode `0o600`.

---

### L17. XChaCha20 Naming/Spec Mismatch

**Files:** `crypt_core.py:306-343`, `cipher_registry.py:640-665`

The implementation uses HKDF-based nonce derivation instead of the standard HChaCha20 subkey construction. In `crypt_core.py`, the HKDF branch is dead code (only first 12 bytes of the 24-byte nonce are ever passed). The HKDF construction in `cipher_registry.py` is cryptographically sound but non-standard and does not provide XChaCha20's 2^96 nonce collision bound. No security weakness, but naming is misleading.

**Recommendation:** Rename to reflect the actual construction, or implement standard HChaCha20.

---

## Top Priority Recommendations

1. **Replace all bare SHA-256 key derivations with HKDF** (C1, C2, H13, M18) -- This is the single highest-impact class of issues, affecting PQC, asymmetric, streaming, and pepper key derivation paths.

2. **Sanitize identity names against path traversal** (H1, H2) -- Add strict name validation (`[a-zA-Z0-9_.-]+`) at all entry points. This is the most directly exploitable finding.

3. **Harden the plugin sandbox** (C3, C4, C5, H8-H10) -- The current sandbox provides minimal protection against a motivated attacker. Consider using OS-level isolation (seccomp, namespaces) rather than Python-level restrictions.

4. **Fix AEAD metadata handling** (C6) -- Strip metadata before encryption, not after, to avoid breaking authentication tags.

5. **Make streaming decryption actually stream** (C7) -- Process chunks incrementally.

6. **Fail hard on integrity/KDF failures** (H4, M17) -- Never silently degrade security.

7. **Use `bytearray` for all sensitive data paths** (H3) -- Accept the Python limitation but use mutable types where possible.

8. **Set restrictive file permissions (0o600)** on all security-sensitive files (H11, H12, M1).

9. **Validate streaming chunk sizes** (H14) -- Enforce maximum `ciphertext_len` based on expected chunk size + AEAD overhead.

10. **Remove silent algorithm downgrade** (H5) -- Fail explicitly when a requested algorithm is unavailable.
