# Implementation Plan: Independent XOR Key Derivation (Massey-style)

## Executive Summary

**Goal**: Add a new "Independent XOR" mode based on Massey's paper where all hash/KDF algorithms receive the **same original input** (password + salt) and their outputs are XORed together. This provides the **strongest component guarantee** - the combined key is at least as secure as its strongest constituent algorithm.

**Key Distinction from Existing v8/v10**:
| Property | Existing v8/v10 (Sequential XOR) | New Independent XOR |
|----------|----------------------------------|---------------------|
| Input to each algorithm | Output of previous algorithm | Original password+salt |
| Dependencies | Sequential chain | None (parallel) |
| Anti-parallelization | Yes (attacker must run sequentially) | No (attacker can parallelize) |
| Security guarantee | Protection via chaining + XOR | "Strongest component" (Massey) |
| Use case | Maximum attacker cost | Maximum cryptographic assurance |

**Branches**:
- **1.4** (feature/v1.4.x-new-xor): Implement as metadata **v11** - START HERE
- **1.3** (feature/v1.3.x-new-xor): Backport as metadata **v9** (after 1.4 complete)

---

## Theoretical Background (Massey Paper)

From Maurer and Massey's work on cascade/combiner security:

**Independent XOR Composition**: `K = H1(x) ⊕ H2(x) ⊕ ... ⊕ Hn(x)`

Where each Hi receives the **same input x** (password + salt).

**Security Property**: The combined key K is at least as secure as the strongest individual Hi. Even if (n-1) algorithms are completely broken, the remaining secure algorithm protects the entire key.

**Trade-off**: Since algorithms don't depend on each other, an attacker with parallel hardware can compute all Hi simultaneously. This reduces the wall-clock time for brute-force attacks compared to sequential chaining.

**When to use**:
- When you want maximum cryptographic assurance against algorithm weaknesses
- When future algorithm breaks are a concern
- When parallel attack resistance is less important than algorithm diversity

---

## Design Approach

### New Functions (Not Modifying Existing)

Following the user's requirement to create new functions rather than modify existing ones:

1. **`generate_key_independent_xor()`** - New function for independent XOR mode
2. **`compute_hash_independent()`** - Compute single hash algorithm on original input
3. **`compute_kdf_independent()`** - Compute single KDF on original input

This approach:
- Minimizes regression risk to existing v8/v9/v10 code paths
- Allows side-by-side comparison during testing
- Makes the code path explicit and auditable

### New CLI Argument

```
--independent-xor    Enable independent XOR key derivation (format v11/v9).
                     Each algorithm processes the original password+salt independently.
                     Provides strongest-component security guarantee.
                     Note: Attackers can parallelize, but key is as strong as strongest algorithm.
```

**Mutually exclusive**: `--independent-xor` and `--use-xor-composition` cannot be used together.
- Error if both specified: "Cannot use both --independent-xor and --use-xor-composition. Choose one XOR mode."

### Algorithms Included

**All enabled algorithms** participate in the independent XOR:
- Hash algorithms: SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE3, SHAKE256, Whirlpool
- KDFs: Argon2, Scrypt, Balloon, HKDF, PBKDF2 (if enabled)

Each enabled algorithm computes on the same original input and contributes to the final XOR.

### Format Version Mapping

| Branch | Existing Sequential XOR | New Independent XOR |
|--------|------------------------|---------------------|
| 1.4    | v10 (--use-xor-composition) | v11 (--independent-xor) |
| 1.3    | v8 (--use-xor-composition) | v9 (--independent-xor) |

---

## Implementation Steps - Branch 1.4

### Step 1: Create feature branch
**Files**: N/A (git operation)
```bash
git checkout feature/v1.4.x-development
git checkout -b feature/v1.4.x-new-xor
```
**Commit**: `<pending>`

---

### Step 2: Add independent XOR helper functions
**File**: `openssl_encrypt/modules/crypt_core.py`

Add new functions (around line ~2100, after existing XOR helpers):

```python
def compute_hash_independent(
    password: bytes,
    salt: bytes,
    algorithm: str,
    rounds: int,
    key_length: int,
    debug: bool = False,
) -> "SecureBytes":
    """
    Compute a single hash algorithm on password+salt independently.

    For Independent XOR mode: each algorithm gets the SAME original input,
    providing "strongest component" security guarantee (Massey).

    Args:
        password: Original password bytes
        salt: Original salt bytes
        algorithm: Hash algorithm name (sha256, sha512, blake2b, etc.)
        rounds: Number of iterations
        key_length: Target output length
        debug: Enable debug logging

    Returns:
        SecureBytes of normalized hash output
    """
    # Implementation: hash(password+salt) for `rounds` iterations
    # Normalize to key_length using HKDF
    pass


def compute_kdf_independent(
    password: bytes,
    salt: bytes,
    kdf_type: str,
    kdf_config: dict,
    key_length: int,
    debug: bool = False,
) -> "SecureBytes":
    """
    Compute a single KDF on password+salt independently.

    For Independent XOR mode: each KDF gets the SAME original input.

    Args:
        password: Original password bytes
        salt: Original salt bytes
        kdf_type: KDF type (argon2, scrypt, balloon, etc.)
        kdf_config: KDF-specific configuration
        key_length: Target output length
        debug: Enable debug logging

    Returns:
        SecureBytes of KDF output
    """
    pass


def generate_key_independent_xor(
    password: bytes,
    salt: bytes,
    hash_config: dict,
    algorithm: str = "aes-256-gcm",
    quiet: bool = False,
    progress: bool = False,
    debug: bool = False,
    hsm_pepper: bytes = None,
    format_version: int = 11,
) -> Tuple[bytes, bytes, bytes]:
    """
    Generate encryption key using Independent XOR composition.

    Based on Massey's work: K = H1(x) ⊕ H2(x) ⊕ ... ⊕ Hn(x)

    Each algorithm receives the SAME input (password + salt).
    The XOR of all outputs provides "strongest component" security -
    the key is at least as secure as its strongest constituent algorithm.

    Trade-off: Attackers can parallelize computation of individual algorithms.

    Args:
        password: User password
        salt: Random salt
        hash_config: Configuration for enabled algorithms
        algorithm: Encryption algorithm (determines key length)
        quiet: Suppress output
        progress: Show progress
        debug: Enable debug logging
        hsm_pepper: Optional HSM pepper
        format_version: Metadata format version (11 for 1.4, 9 for 1.3)

    Returns:
        Tuple of (key, salt, iv)
    """
    pass
```

**Commit**: `[1.4] feat(kdf): Add independent XOR helper functions for Massey-style composition`

---

### Step 3: Implement `compute_hash_independent()`
**File**: `openssl_encrypt/modules/crypt_core.py`

Implementation details:
- Accept algorithm name and rounds
- Use original password+salt as input (NOT chained)
- Apply iterations on the hash itself (standard key stretching within single algorithm)
- Normalize output to key_length using existing `normalize_to_key_length_secure()`
- Return SecureBytes

**Commit**: `[1.4] feat(kdf): Implement compute_hash_independent for hash algorithms`

---

### Step 4: Implement `compute_kdf_independent()`
**File**: `openssl_encrypt/modules/crypt_core.py`

Implementation details:
- Handle each KDF type: Argon2, Scrypt, Balloon, HKDF, PBKDF2
- Use original password as input, original salt for KDF
- Return SecureBytes of specified key_length

**Commit**: `[1.4] feat(kdf): Implement compute_kdf_independent for KDF algorithms`

---

### Step 5: Implement `generate_key_independent_xor()`
**File**: `openssl_encrypt/modules/crypt_core.py`

Implementation details:
```python
def generate_key_independent_xor(...):
    # 1. Determine key_length based on algorithm
    key_length = _get_key_length_for_algorithm(algorithm)

    # 2. Collect all algorithm outputs independently
    xor_components = []  # List[SecureBytes]

    # 3. Process each enabled hash algorithm
    for algo in ['sha256', 'sha512', 'sha3_256', 'blake2b', 'blake3', ...]:
        rounds = get_hash_rounds(hash_config, algo)
        if rounds > 0:
            result = compute_hash_independent(password, salt, algo, rounds, key_length, debug)
            xor_components.append(result)

    # 4. Process each enabled KDF
    for kdf in ['argon2', 'scrypt', 'balloon', 'hkdf', 'pbkdf2']:
        if is_kdf_enabled(hash_config, kdf):
            result = compute_kdf_independent(password, salt, kdf, get_kdf_config(hash_config, kdf), key_length, debug)
            xor_components.append(result)

    # 5. XOR all components together
    try:
        if len(xor_components) == 0:
            raise ValueError("No algorithms enabled for key derivation")

        final_key = xor_bytes_secure(xor_components)

        # Generate IV
        iv = os.urandom(16)

        return bytes(final_key), salt, iv

    finally:
        # Zero all intermediate components
        for component in xor_components:
            secure_memzero(component)
```

**Commit**: `[1.4] feat(kdf): Implement generate_key_independent_xor main function`

---

### Step 6: Add CLI argument `--independent-xor`
**File**: `openssl_encrypt/modules/crypt_cli_subparser.py`

Add to format version options group (around line 741):
```python
format_group.add_argument(
    "--independent-xor",
    action="store_true",
    default=False,
    help="Enable independent XOR key derivation (format v11). "
         "Each algorithm processes the original password+salt independently. "
         "Provides strongest-component security guarantee (Massey). "
         "Note: Attackers can parallelize, but key is as strong as strongest algorithm. "
         "Files require openssl_encrypt 1.4.x+ to decrypt.",
)
```

**Commit**: `[1.4] feat(cli): Add --independent-xor CLI argument`

---

### Step 7: Wire CLI to new code path
**File**: `openssl_encrypt/modules/crypt_cli.py`

Modify encrypt command handler (around line 6698):
```python
# Determine format version and key derivation mode
if getattr(args, "independent_xor", False):
    format_version = 11
    use_independent_xor = True
elif getattr(args, "use_xor_composition", False):
    format_version = 10
    use_independent_xor = False
else:
    format_version = 9
    use_independent_xor = False
```

Modify key generation call:
```python
if use_independent_xor:
    key, salt, iv = generate_key_independent_xor(
        password=password_bytes,
        salt=salt,
        hash_config=hash_config,
        algorithm=algorithm,
        quiet=quiet,
        debug=debug,
        format_version=format_version,
    )
else:
    # Existing generate_key() call
    key, salt, iv = generate_key(...)
```

**Commit**: `[1.4] feat(cli): Wire --independent-xor to generate_key_independent_xor`

---

### Step 8: Update metadata schema for v11
**File**: `openssl_encrypt/modules/metadata_v9_schema.json`

Update format_version enum:
```json
"format_version": {
    "type": "integer",
    "enum": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    "description": "Format version. v11: Independent XOR (Massey). v10/v8: Sequential XOR. v9: Secure chained salt."
}
```

Add new field to distinguish XOR modes:
```json
"xor_mode": {
    "type": "string",
    "enum": ["sequential", "independent"],
    "description": "XOR composition mode. 'sequential': v8/v10 chained. 'independent': v11 parallel (Massey)."
}
```

**Commit**: `[1.4] feat(schema): Update metadata schema for v11 independent XOR`

---

### Step 9: Update metadata creation for v11
**File**: `openssl_encrypt/modules/crypt_core.py`

Add `xor_mode` field to metadata when format_version == 11:
```python
if format_version == 11:
    metadata["xor_mode"] = "independent"
elif format_version in [8, 10]:
    metadata["xor_mode"] = "sequential"
```

**Commit**: `[1.4] feat(metadata): Add xor_mode field for v11 format`

---

### Step 10: Update decryption to handle v11
**File**: `openssl_encrypt/modules/crypt_core.py`

In `decrypt_file()` or key regeneration logic:
```python
format_version = metadata.get("format_version", 1)
xor_mode = metadata.get("xor_mode", "sequential")

if format_version == 11 or xor_mode == "independent":
    key, _, _ = generate_key_independent_xor(
        password=password_bytes,
        salt=salt,
        hash_config=hash_config,
        algorithm=algorithm,
        format_version=format_version,
    )
else:
    # Existing generate_key() for v1-v10
    key, _, _ = generate_key(...)
```

**Commit**: `[1.4] feat(decrypt): Handle v11 independent XOR during decryption`

---

### Step 11: Add unit tests for independent XOR
**File**: `openssl_encrypt/unittests/test_format_v11_independent_xor.py` (NEW)

Test cases:
1. Basic round-trip encryption/decryption with v11
2. Verify v11 produces different keys than v10 (different mode)
3. Test with various algorithm combinations
4. Test all hash algorithms independently
5. Test all KDFs independently
6. Verify XOR component count matches enabled algorithms
7. Test backward compatibility (v9/v10 files still decrypt)
8. Secure memory cleanup verification

**Commit**: `[1.4] test: Add comprehensive tests for v11 independent XOR`

---

### Step 12: Run full test suite and fix regressions
**Command**: `pytest openssl_encrypt/unittests/ -v`

Verify all existing tests pass plus new v11 tests.

**Commit**: `[1.4] fix: Resolve any test regressions for v11`

---

### Step 13: Manual integration testing
**Commands**:
```bash
# Test v11 encryption/decryption
echo "Test data" > test.txt
python -m openssl_encrypt encrypt -i test.txt -o test.enc --independent-xor --debug
python -m openssl_encrypt decrypt -i test.enc -o test_dec.txt
diff test.txt test_dec.txt

# Verify v9/v10 backward compatibility
python -m openssl_encrypt encrypt -i test.txt -o test_v9.enc
python -m openssl_encrypt decrypt -i test_v9.enc -o test_v9_dec.txt
diff test.txt test_v9_dec.txt
```

**Commit**: `[1.4] docs: Update plan with v11 testing complete`

---

## Implementation Steps - Branch 1.3 (Backport)

After 1.4 implementation is complete and tested:

### Step 14: Create 1.3 feature branch
```bash
git checkout feature/v1.3.x-development
git checkout -b feature/v1.3.x-new-xor
```

### Step 15-22: Cherry-pick/adapt changes from 1.4
- Same new functions but format_version = 9 instead of 11
- Schema is in `openssl_encrypt/schemas/` not `modules/`
- Create `metadata_v9_schema.json` based on v8

**Commits**: Mirror 1.4 commits with `[1.3]` prefix

---

## Files to Modify Summary

### Branch 1.4 (feature/v1.4.x-new-xor)

| File | Changes |
|------|---------|
| `openssl_encrypt/modules/crypt_core.py` | Add 3 new functions, update decrypt logic |
| `openssl_encrypt/modules/crypt_cli_subparser.py` | Add `--independent-xor` argument |
| `openssl_encrypt/modules/crypt_cli.py` | Wire CLI to new code path |
| `openssl_encrypt/modules/metadata_v9_schema.json` | Add v11, add xor_mode field |
| `openssl_encrypt/unittests/test_format_v11_independent_xor.py` | NEW - comprehensive tests |

### Branch 1.3 (feature/v1.3.x-new-xor)

| File | Changes |
|------|---------|
| `openssl_encrypt/modules/crypt_core.py` | Same new functions |
| `openssl_encrypt/modules/crypt_cli_subparser.py` | Add `--independent-xor` argument |
| `openssl_encrypt/modules/crypt_cli.py` | Wire CLI to new code path |
| `openssl_encrypt/schemas/metadata_v9_schema.json` | NEW - v9 schema for independent XOR |
| `openssl_encrypt/unittests/test_format_v9_independent_xor.py` | NEW - tests |

---

## Security Considerations

### Secure Memory Handling (Non-negotiable)
- ALL intermediate values MUST use `SecureBytes`
- ALL intermediates MUST be zeroed in finally blocks
- Use `secure_memzero()` for cleanup
- Never use plain `bytes` for key material

### Algorithm Considerations
- Minimum 2 algorithms should be enabled for meaningful XOR protection
- Warn user if only 1 algorithm is enabled (no XOR benefit)
- HSM pepper integration must work with independent mode

---

## Verification Checklist

### Functional
- [ ] v11 encryption produces valid encrypted files
- [ ] v11 decryption correctly recovers original data
- [ ] Each algorithm receives same input (password+salt)
- [ ] XOR combines correct number of components
- [ ] v9/v10 backward compatibility maintained
- [ ] Debug output shows independent computation

### Security
- [ ] All intermediates use SecureBytes
- [ ] All intermediates zeroed after XOR
- [ ] Exception safety with try/finally
- [ ] No memory leaks

### Testing
- [ ] All existing tests pass (no regressions)
- [ ] New v11 tests pass
- [ ] Manual integration tests pass
- [ ] Cross-version compatibility verified

---

## Progress Tracking

### Branch 1.4 (feature/v1.4.x-new-xor)
- [ ] Step 1: Create feature branch - Commit: `<pending>`
- [ ] Step 2: Add helper function signatures - Commit: `<pending>`
- [ ] Step 3: Implement compute_hash_independent - Commit: `<pending>`
- [ ] Step 4: Implement compute_kdf_independent - Commit: `<pending>`
- [ ] Step 5: Implement generate_key_independent_xor - Commit: `<pending>`
- [ ] Step 6: Add CLI argument - Commit: `<pending>`
- [ ] Step 7: Wire CLI to new code path - Commit: `<pending>`
- [ ] Step 8: Update metadata schema - Commit: `<pending>`
- [ ] Step 9: Update metadata creation - Commit: `<pending>`
- [ ] Step 10: Update decryption - Commit: `<pending>`
- [ ] Step 11: Add unit tests - Commit: `<pending>`
- [ ] Step 12: Run test suite - Commit: `<pending>`
- [ ] Step 13: Manual testing - Commit: `<pending>`

### Branch 1.3 (feature/v1.3.x-new-xor)
- [ ] Step 14: Create feature branch - Commit: `<pending>`
- [ ] Steps 15-22: Backport from 1.4 - Commits: `<pending>`

**Last Updated**: 2026-01-11
**Current Status**: Plan complete - user confirmed: mutually exclusive flags, v9 for 1.3 backport, all algorithms included

---

## User Confirmations

- **CLI Flags**: Mutually exclusive (`--independent-xor` OR `--use-xor-composition`, not both)
- **1.3 Format Version**: v9 (next after v8 sequential XOR)
- **Algorithms**: All enabled hash algorithms AND KDFs participate in XOR
