# OpenSSL Encrypt - Work Status & Next Steps

**Date**: 2026-01-08
**Branch**: `feature/v1.4.0-development`
**Last Commit**: `d23084a` - Schema compatibility fix

---

## Current Situation

### 80+ Test Failures - NOT A REGRESSION
**Important**: The test failures in `/tmp/test.log` are **pre-existing issues**, not caused by recent work.

- Tests were added in commit `ccb49da` and **never passed**
- Verified by checking out `ccb49da` - same failures occur
- Tests are related to salt derivation differences between format versions v7, v8, and v9
- Main issue: Tests call `multi_hash_password()` directly but it only processes hash iterations, not KDFs

### v1.3.4 to v1.4.0 Compatibility Issue

**Problem**: Files encrypted with v1.3.4 (format_version=7) cannot decrypt in v1.4.0

**Test Files**:
- `/tmp/test.txt` - 100K SHA3-512 + 100K BLAKE3 rounds (fails)
- `/tmp/test_combined.txt` - 100 SHA3-512 + 100 BLAKE3 rounds (works)
- `/tmp/test_blake3_v13.txt` - Only 10 BLAKE3 rounds (fails even in v1.3.0!)
- `/tmp/fresh_test_v13.txt` - Freshly created with v1.3.0 (works in v1.4.0 after schema fix)

---

## What Was Fixed Today

### ✅ Schema Validation Issue
**Commit**: `d23084a`

**Problem**: v1.4.0 required 'mode' field in metadata_v7_schema.json, but v1.3.4 files don't have it

**Solution**: Removed 'mode' from required fields in schema
- File: `openssl_encrypt/schemas/metadata_v7_schema.json`
- Line 7: Changed from `["format_version", "mode", "derivation_config", "encryption"]` to `["format_version", "derivation_config", "encryption"]`
- Code already handles missing mode via `.get('mode', 'symmetric')`

**Result**: v1.4.0 can now validate v1.3.4 metadata

---

## Outstanding Issues

### 1. BLAKE3/Hash Buffer Issue (High Priority)

**Symptoms**:
- Files with high BLAKE3 rounds fail: "expected a 32-byte key, found 20"
- Some v1.3.4 files decrypt successfully, others don't

**Root Cause Investigation**:
The issue is complex and affects the hash iteration chain:

1. **Initial Investigation**: Buffer sized for short passwords (4 bytes for "1234") too small for 64-byte hash outputs
2. **Attempted Fix #1**: Increased buffer to 64 bytes minimum
   - **Result**: Broke ALL hash operations - hash functions were hashing padded zeros
   - **Why**: `hashlib.sha512(hashed)` hashed the full 64-byte buffer including garbage
3. **Attempted Fix #2**: Added `current_size` tracking variable
   - **Result**: Changed all hash operations to use `hashed[:current_size]`
   - **Problem**: Extremely invasive, affects every hash algorithm
   - **Reverted**: Too risky, changes key derivation behavior
4. **Attempted Fix #3**: Pad BLAKE3/BLAKE2b keys to 32 bytes
   - **Result**: Changes key derivation, breaks backwards compatibility
   - **Reverted**: Can't decrypt existing files

**Current Theory**:
- The BLAKE3 keyed mode issue only manifests with very specific conditions
- `/tmp/test_blake3_v13.txt` fails even in v1.3.0, suggesting it's corrupted or was never valid
- `/tmp/test_combined.txt` and `/tmp/fresh_test_v13.txt` work fine
- `/tmp/test.txt` might be hitting a specific edge case

**Key Files**:
- `openssl_encrypt/modules/crypt_core.py` lines 1460-1810: `multi_hash_password()` function

### 2. Salt Derivation Test Failures (80+ tests)

**Failed Test Examples**:
```
test_v7_uses_secure_chained_derivation
test_v8_remains_backward_compatible
test_multi_round_scrypt_v8_v9
```

**Problem**:
Tests expect format v7 and v8 to produce different keys (secure vs predictable salt derivation), but they produce identical keys:
```
AssertionError: b'test_password_123v7_test_salt_val' == b'test_password_123v7_test_salt_val'
```

**Analysis**:
- `multi_hash_password()` returns the literal concatenation of password + format_version + salt
- No hashing or KDF operations are being performed
- Tests call `multi_hash_password()` directly with only Scrypt config
- But `multi_hash_password()` only handles hash iterations, not KDFs
- This suggests either:
  1. Tests are calling the wrong function
  2. `multi_hash_password()` should handle KDFs but doesn't
  3. There's a missing integration between hash and KDF processing

**Test File**: `openssl_encrypt/unittests/test_salt_derivation_versions.py`

---

## Git History Context

### Recent Commits (working backwards)
```
d23084a - fix: Make 'mode' field optional in metadata_v7_schema (TODAY)
a72a342 - fix: Convert bytearray to bytes in Scrypt salt
7f7a41e - fix: Convert SecureBytes slices to bytes in XChaCha20
b2c76b0 - fix: Use correct AAD variable in Threefish decryption
ccb49da - test: Add v7/v9 compatibility and security tests (TESTS ADDED HERE - NEVER PASSED)
fe4b845 - security: Implement Format Version 9 with secure chained salt derivation
```

### Backported to v1.3.0
```
8347580 - fix: Increase hash buffer size to minimum 64 bytes (v1.3.0)
23d5c85 - fix: Convert bytearray to bytes in Scrypt and XChaCha20 (v1.3.0)
```

---

## Next Steps / TODO

### Immediate Priority

1. **Investigate BLAKE3 issue without changing key derivation**
   - [ ] Test `/tmp/test.txt` decryption in v1.3.4 (switch branches)
   - [ ] If it works in v1.3.4, binary compare the key derivation outputs
   - [ ] Check if the issue is in encryption or decryption path
   - [ ] Verify: Does the file actually have valid ciphertext?

2. **Verify test file validity**
   - [ ] Check if `/tmp/test_blake3_v13.txt` was ever valid
   - [ ] Try decrypting it with the exact v1.3.0 that created it
   - [ ] If corrupt, discard and focus on other test files

3. **Understand multi_hash_password behavior**
   - [ ] Read the full function to understand expected flow
   - [ ] Determine if KDFs should be in `multi_hash_password()` or called separately
   - [ ] Check where KDFs are actually invoked during encryption/decryption
   - [ ] Look at `generate_key()` function - is that what calls KDFs?

### Secondary Priority

4. **Fix salt derivation tests (if they're valid)**
   - [ ] Determine if tests are calling correct functions
   - [ ] Check if `generate_key()` should be called instead of `multi_hash_password()`
   - [ ] Review the security design doc for v7/v8/v9 differences
   - [ ] Fix or rewrite tests as needed

5. **Run full test suite**
   - [ ] After fixing, run: `pytest openssl_encrypt/unittests/ -x`
   - [ ] Focus on PQC tests that are failing
   - [ ] Many PQC failures seem to be missing private keys - might be test data issue

---

## Important Code Locations

### Hash Processing
- **Function**: `multi_hash_password()`
- **File**: `openssl_encrypt/modules/crypt_core.py`
- **Lines**: 1373-1810
- **Purpose**: Processes hash iterations (SHA-512, SHA-256, SHA3-512, BLAKE3, BLAKE2b, etc.)

### KDF Processing
- **Scrypt**: Lines ~2230-2260
- **Argon2**: Lines ~2100-2180
- **RandomX**: Separate module
- **Balloon**: Lines ~2260+

### Key Generation
- **Function**: `generate_key()`
- **File**: `openssl_encrypt/modules/crypt_core.py`
- **Lines**: 1837+ (after `multi_hash_password()`)
- **Purpose**: Main entry point for key generation - likely calls both hash and KDF functions

### Schemas
- **v7 Schema**: `openssl_encrypt/schemas/metadata_v7_schema.json`
- **Modified**: Line 7 - removed 'mode' from required fields

---

## Key Insights

### Format Versions
- **v1-v6, v8**: Use predictable salt derivation (vulnerable to precomputation)
- **v7, v9+**: Use secure chained salt derivation
- **v7 & v9**: Cryptographically equivalent (both secure chained)
- **v8**: Deliberately kept vulnerable for backward compatibility

### Encryption Modes
- **v1.3.4**: Only symmetric encryption (no 'mode' field)
- **v1.4.0**: Added asymmetric encryption support (requires 'mode' field)

### SecureBytes Issues
- SecureBytes slicing returns bytearray, not bytes
- Many crypto libraries require bytes, not bytearray
- Fixed in: Scrypt salt (a72a342), XChaCha20 nonce (7f7a41e)

---

## Commands for Tomorrow

### Test individual file decryption
```bash
python3 -m openssl_encrypt decrypt -i /tmp/test.txt -p 1234 --force-password --no-estimate --debug 2>&1 | tee /tmp/decrypt_debug.log
```

### Test with v1.3.0
```bash
git checkout feature/v1.3.0-development
python3 -m openssl_encrypt decrypt -i /tmp/test.txt -p 1234 --force-password 2>&1
```

### Run specific failing test
```bash
pytest openssl_encrypt/unittests/test_salt_derivation_versions.py::TestSaltDerivationVersions::test_v7_uses_secure_chained_derivation -xvs
```

### Check test history
```bash
git checkout ccb49da  # When tests were added
pytest openssl_encrypt/unittests/test_salt_derivation_versions.py -xvs
```

---

## Questions to Answer Tomorrow

1. **Does `/tmp/test.txt` decrypt successfully in v1.3.4?**
   - If YES: Need to find what changed between branches
   - If NO: File might be corrupt or created with incompatible settings

2. **What is the correct flow for key generation?**
   ```
   Option A: generate_key() → multi_hash_password() → KDFs
   Option B: generate_key() → multi_hash_password() + separate KDF calls
   Option C: Something else?
   ```

3. **Are the salt derivation tests correct?**
   - Do they test the right behavior?
   - Are they calling the right functions?
   - Should they test `generate_key()` instead?

4. **Why do some BLAKE3 files work and others don't?**
   - Is it round count related?
   - Is it password length related?
   - Is it format version related?

---

## Don't Forget

- The 80+ test failures are NOT a regression
- Schema fix is good and pushed
- Don't attempt buffer size changes without full understanding
- Any key derivation changes break backwards compatibility
- Test files in `/tmp/` are critical for validation

---

## Contact/References

- Test log: `/tmp/test.log`
- Plan from previous session: `/home/tobster/.claude/plans/purring-rolling-gray.md`
- Branch: `feature/v1.4.0-development`
- Remote: `origin/feature/v1.4.0-development` (in sync with d23084a)
