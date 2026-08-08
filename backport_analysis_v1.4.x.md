# Security Backport Analysis: v1.5.x → v1.4.x

## Overview

This document analyzes which security fixes from `feature/v1.5.x-development` can be safely backported to `feature/v1.4.x-development` without introducing breaking changes.

**Analysis date:** 2026-03-06
**Source branch:** `feature/v1.5.x-development`
**Target branch:** `feature/v1.4.x-development`

---

## Branch Comparison

The v1.4.x branch diverged from v1.5.x approximately 85 commits ago. Key differences:
- v1.5.x has `secret_sharing.py` and `dir_archive.py` — v1.4.x does NOT
- Plugin system, registry, cascade, streaming, identity, keystore modules exist on BOTH branches with nearly identical structure
- `crypt_core.py` has diverged but core structure (encrypt_file/decrypt_file, metadata handling) is the same

---

## Detailed Fix-by-Fix Analysis

### H6/H7: Cascade Per-Layer Salt Derivation — BACKPORTABLE (gated)

**Problem:** All cascade layers share the same HKDF salt, meaning layers with same cipher get identical (master_key, salt) pairs.
**Fix:** Derive per-layer salts via HKDF with domain separation (`cascade:salt:<index>`).
**v1.4.x status:** `cascade.py` exists, identical structure. `CascadeKeyDerivation` class present.
**Backport approach:** Add `format_version` parameter to `CascadeKeyDerivation.__init__()` and `CascadeEncryption.__init__()`. Add `_derive_layer_salt()` method. Gate behind `format_version >= 12`.
**Risk:** Low-medium. No existing tests break because legacy path is unchanged.

### H8/H9: AST-Based Plugin Security Hardening — BACKPORTABLE (direct)

**Problem:** Plugin sandbox doesn't check for dangerous imports (os, subprocess, shutil, etc.) or dangerous dunder attributes (__import__, __subclasses__).
**Fix:** Add AST analysis to `PluginSandbox` that scans plugin source for blocked imports and dunder access.
**v1.4.x status:** `plugin_system/sandbox.py` exists with identical structure.
**Backport approach:** Direct port of AST analysis code and blocked module/dunder lists.
**Risk:** Low. Additive change, no existing behavior modified.

### H10: Plugin Sandbox TOCTOU Fix — BACKPORTABLE (direct)

**Problem:** Source file could be modified between security analysis and execution.
**Fix:** Re-read source at load time and compare hash to analyzed version.
**v1.4.x status:** Same sandbox code.
**Backport approach:** Direct port.
**Risk:** Low.

### H13: Streaming HMAC Key via HKDF — BACKPORTABLE (gated)

**Problem:** HMAC key derived via bare `SHA-256(key || constant)` instead of proper HKDF.
**Fix:** Use HKDF for HMAC key derivation when `format_version >= 12`.
**v1.4.x status:** `streaming.py` exists with identical `StreamingEncryptor`/`StreamingDecryptor` classes.
**Backport approach:** Add `format_version` parameter and `_derive_hmac_key()` method to both classes. Gate HKDF path behind v12+.
**Risk:** Low-medium. Streaming always writes v12 metadata, so new encryptions use HKDF. Old files decrypt via legacy path.

### M5: Identity Key File Permissions — BACKPORTABLE (direct)

**Problem:** Identity key files created with default permissions instead of 0o600.
**Fix:** Set `os.chmod(path, 0o600)` after writing key files.
**v1.4.x status:** `identity.py` exists with same key generation code.
**Backport approach:** Direct port.
**Risk:** Very low.

### M9: Algorithm Registry Freeze — BACKPORTABLE (direct)

**Problem:** Registry allows modification after initialization, enabling runtime algorithm injection.
**Fix:** Add `freeze()`/`is_frozen` to registry, freeze after init, reject modifications when frozen.
**v1.4.x status:** `registry.py` exists with same structure.
**Backport approach:** Direct port of freeze mechanism.
**Risk:** Low. May need to ensure freeze is called at the right point in v1.4.x initialization.

### M10: Plugin Capability Restriction — BACKPORTABLE (direct)

**Problem:** Plugins could declare `CRYPTO_PROVIDER` capability, potentially overriding core crypto.
**Fix:** Reject plugins with `CRYPTO_PROVIDER` capability during sandbox validation.
**v1.4.x status:** Same plugin system.
**Backport approach:** Direct port.
**Risk:** Very low.

### M12: Cascade AAD on All Layers — BACKPORTABLE (gated)

**Problem:** AAD only applied to first cascade layer; inner layers have no authenticity binding.
**Fix:** Apply AAD to all layers when `format_version >= 12`.
**v1.4.x status:** Same cascade code structure.
**Backport approach:** Part of the H6/H7 cascade backport. Same `format_version` gating.
**Risk:** Low. Gated behind v12+, legacy unchanged.

### M13: Registry Input Validation — BACKPORTABLE (direct)

**Problem:** `get_cipher()` doesn't validate input type/format, could raise confusing errors.
**Fix:** Add type checking and format validation before lookup.
**v1.4.x status:** Same registry code.
**Backport approach:** Direct port.
**Risk:** Very low.

### M15: PQC Signature HKDF with Random Salt — BACKPORTABLE (gated)

**Problem:** PQC signature-hybrid key derivation uses static salt string.
**Fix:** Generate random 32-byte salt for each encryption, store in metadata, use in HKDF.
**v1.4.x status:** PQC module exists. Need to verify `_derive_pqc_sig_key()` helper can be added.
**Backport approach:** Add helper function to `crypt_core.py`, store `sig_hkdf_salt` in metadata. Gate behind format_version check.
**Risk:** Medium. Touches metadata serialization which must be verified carefully.

### M18: Pepper Key Derivation via HKDF — BACKPORTABLE (gated)

**Problem:** Pepper key derived via bare `SHA-256(password)` instead of HKDF.
**Fix:** Use HKDF with domain separation for v12+.
**v1.4.x status:** Pepper key derivation exists in `crypt_core.py`.
**Backport approach:** Add `_derive_pepper_key()` helper, gate behind `format_version >= 12`.
**Risk:** Medium. Pepper is used in key stretching; must ensure legacy decryption path unchanged.

### M20: Keystore Path Traversal Prevention — BACKPORTABLE (direct)

**Problem:** Keystore doesn't validate key names for path traversal (e.g., `../../etc/passwd`).
**Fix:** Validate key names, reject paths with `..`, `/`, or other traversal patterns.
**v1.4.x status:** `keystore.py` exists with same structure.
**Backport approach:** Direct port.
**Risk:** Very low.

### C2: crypt_core.py Format Version Wiring — BACKPORTABLE (complex)

**Problem:** `format_version` not threaded through to cascade, streaming, and PQC modules.
**Fix:** Pass `format_version` from `encrypt_file()`/`decrypt_file()` to all sub-modules.
**v1.4.x status:** `crypt_core.py` has diverged but same core structure.
**Backport approach:** This is the wiring that enables all Category B fixes. Must be ported carefully with attention to v1.4.x-specific code differences.
**Risk:** Medium-high. `crypt_core.py` is the most complex file and has diverged between branches. Each wiring point must be verified against v1.4.x code.

---

## NOT Backportable

### M2/M3: Secret Sharing Timing/Validation

**Reason:** `secret_sharing.py` does not exist on v1.4.x. This module was added in v1.5.x.

### C1: PQC MAYO/CROSS Signature Fixes

**Reason:** These PQC algorithms may not be present on v1.4.x. The PQC module has likely diverged significantly. Needs further investigation if backport is desired.

### M11: PQC Verify with Multiple Algorithms

**Reason:** Depends on PQC module structure that may differ on v1.4.x. Needs investigation.

### M4: AES-GCM Without AAD in Identity

**Reason:** Deferred on v1.5.x as well — requires identity format migration strategy.

---

## Recommended Priority

1. **Highest priority (direct, low risk):** H8/H9, H10, M9, M10 — plugin/registry hardening
2. **High priority (direct, low risk):** M5, M13, M20 — defense-in-depth
3. **Medium priority (gated, medium risk):** H6/H7, M12, H13 — cryptographic improvements
4. **Lower priority (gated, higher complexity):** M15, M18, C2 — requires careful crypt_core.py work

---

## Notes

- All format-gated fixes (Category B) use the same `format_version >= 12` pattern as v1.5.x
- Legacy encryption/decryption paths remain byte-identical — no backward compatibility impact
- Each fix should be committed separately per project commit discipline
- Full test suite must pass after each commit
