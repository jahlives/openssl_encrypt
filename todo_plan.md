# Plan: Three New Features — SSS, Directory Archiving, Verify

## Context

Three new features for the openssl_encrypt project, implemented on `feature/v1.5.x-development`:

1. **Shamir's Secret Sharing (SSS)** — K-of-N threshold secret sharing for encryption keys
2. **Encrypted Directory Archiving** — `encrypt -i ./folder/` with tar streaming
3. **Integrity Verification** — `verify -i file.enc` structural checks without password

## Implementation Order

1. **Verify** (simplest, no deps, provides reusable metadata validation logic)
2. **SSS** (self-contained new module + CLI)
3. **Directory Archiving** (highest complexity, modifies encrypt_file/decrypt_file)

---

## Feature 1: Integrity Verification Without Decryption

### New Files

**`openssl_encrypt/modules/verify.py`** (~250 lines)
- `VerificationResult` dataclass: `check_name`, `passed`, `message`, `details`
- `FileVerifier` class with check methods:
  - `_check_file_readable()` — file exists and is readable
  - `_check_base64_metadata()` — split on first colon, decode base64
  - `_check_metadata_json()` — valid JSON
  - `_check_metadata_schema()` — required fields: `format_version`, `encryption`, `derivation_config`
  - `_check_format_version()` — version in supported range (3-12)
  - `_check_streaming_structure()` — for v12 streaming: OESC magic, payload version, sequential chunk indices, chunk sizes within bounds, chunk_count matches trailer, file size consistent
- `verify_file_integrity(input_file, json_output, verbose) -> (bool, list)` — public API

**`openssl_encrypt/unittests/test_verify.py`** (~350 lines)
- `TestVerifyValidFiles` — freshly encrypted files (fernet, aes-gcm, streaming v12)
- `TestVerifyInvalidFiles` — empty, random bytes, truncated, corrupted base64, invalid JSON, unsupported version
- `TestVerifyStreamingStructure` — missing OESC magic, wrong payload version, chunk count mismatch, truncated chunk
- `TestVerifyOutput` — json mode, verbose mode, exit codes

### Modified Files

**`crypt_cli.py`**
- Add `"verify"` to action choices (~line 3372)
- Add handler: `elif args.action == "verify":` calling `verify_file_integrity()`

**`crypt_cli_subparser.py`**
- Add `setup_verify_parser()`: `--input/-i` (required), `--json`, `--verbose`
- Register in `create_subparser_main()`

**`crypt_errors.py`**
- Add `VerificationError(SecureError)` (~8 lines)

---

## Feature 2: Shamir's Secret Sharing

### New Files

**`openssl_encrypt/modules/secret_sharing.py`** (~500 lines)

Core GF(256) implementation (no external deps):

- `GF256` class — constant-time table-lookup arithmetic:
  - Pre-computed `EXP_TABLE`/`LOG_TABLE` for irreducible polynomial x^8+x^4+x^3+x+1
  - `mul(a, b)`, `inv(a)`, `evaluate_polynomial(coeffs, x)`, `lagrange_interpolate(points)`
- `ShareMetadata` dataclass: `threshold`, `total_shares`, `share_index`, `key_id` (UUID), `algorithm` ("shamir-gf256"), `created_at`
- `Share` class: `metadata` + `data` (bytes), with `to_json()`/`from_json()`/`to_file()`/`from_file()` serialization
- `SHARE_FILE_HEADER = "ossl_encrypt_share"`
- `split_secret(secret: bytes, threshold: int, num_shares: int) -> List[Share]`
  - Per-byte: generate (k-1) random coefficients, evaluate polynomial at x=1..n
  - Validation: 2 <= k <= n <= 255
- `combine_shares(shares: List[Share]) -> bytes`
  - Per-byte: Lagrange interpolation at x=0
  - Validation: matching key_ids, sufficient shares, no duplicate indices

**`openssl_encrypt/unittests/test_secret_sharing.py`** (~500 lines)
- `TestGF256` — mul identity/zero/commutativity, inv correctness (a * inv(a) == 1 for all nonzero a)
- `TestSplitCombine` — 2-of-3, 3-of-5, 5-of-10, all k-subsets reconstruct, k-1 shares fail
- `TestShareSerialization` — JSON roundtrip, file roundtrip, metadata preserved
- `TestValidation` — threshold > shares, threshold < 2, shares > 255, mismatched key_ids, empty secret

**`openssl_encrypt/unittests/test_secret_sharing_integration.py`** (~300 lines)
- `TestSplitSecretCLI` — encrypt file, split key into shares, combine shares to decrypt
- `TestShareKeystoreIntegration` — store/retrieve shares in keystore
- `TestShareQRExport` — share to QR roundtrip (skip if no qrcode/PIL)

### Modified Files

**`crypt_cli.py`**
- Add `"split-secret"` and `"combine-secrets"` to action choices
- `split-secret` handler: prompt password → derive key → `split_secret(key)` → write share files (or store in keystore, or export QR)
- `combine-secrets` handler: read share files → `combine_shares()` → use reconstructed key to decrypt

**`crypt_cli_subparser.py`**
- `setup_split_secret_parser()`:
  - `--input/-i`: encrypted file
  - `--shares/-n` (int): total shares
  - `--threshold/-k` (int): minimum for recovery
  - `--output-dir/-d`: directory for share files
  - `--keystore`/`--keystore-path`: store in keystore
  - `--qr`: export as QR codes
  - Password args (reuse existing pattern)
- `setup_combine_secrets_parser()`:
  - `--input/-i`: encrypted file to decrypt
  - `--shares` (nargs='+'): share file paths
  - `--keystore`/`--keystore-path`/`--key-id`: load from keystore
  - `--output/-o`: decrypted output

**`keystore_cli.py`** — `PQCKeystore` class:
- Add `add_share(share, password)` convenience method (~30 lines) — stores with `algorithm: "shamir-share"`
- Add `get_shares_by_key_id(key_id) -> List[Share]` (~20 lines)

**`portable_media/qr_distribution.py`**
- Add `create_share_qr()` (~40 lines) — header `"ossl_encrypt_key_share"`, includes threshold/index/total/key_id
- Add `read_share_qr()` (~30 lines) — parse share from QR

**`crypt_errors.py`**
- Add `SecretSharingError(SecureError)` (~8 lines)

---

## Feature 3: Encrypted Directory Archiving

### New Files

**`openssl_encrypt/modules/archive.py`** (~350 lines)

- `DirectoryArchiver` class:
  - `__init__(preserve_permissions=True, follow_symlinks=False)`
  - `create_tar_to_file(dir_path) -> temp_tar_path` — tar to temp file (for two-pass hash+encrypt)
  - `get_manifest(dir_path) -> dict` — `{total_files, total_dirs, total_size_bytes, contains_symlinks, root_name}`
- `secure_tar_extract(tar_data_or_path, output_dir)` — security-hardened extraction:
  - Reject path traversal (`..` components, absolute paths)
  - Reject symlinks pointing outside output_dir
  - Validate member names before extraction
- `validate_directory_input(path)` — exists, readable, is directory

**Two-pass approach:** Create tar to temp file → `calculate_hash_streaming(temp_tar)` → `StreamingEncryptor.encrypt_file(temp_tar)` → securely shred temp tar. Reuses existing streaming infrastructure as-is.

**`openssl_encrypt/unittests/test_archive.py`** (~500 lines)
- `TestDirectoryArchiver` — tar creation, permissions, timestamps, symlinks, nested dirs, empty dir
- `TestTarExtraction` — roundtrip, path traversal rejection, absolute path rejection, symlink security
- `TestDirectoryEncryptDecrypt` — full encrypt/decrypt roundtrip, content verification, various algorithms
- `TestManifest` — file/dir counts, total size
- `TestEdgeCases` — nonexistent dir, file-not-dir, empty dir, special chars in names

### Modified Files

**`crypt_core.py`** — `encrypt_file()` (~40 lines added, before main encryption logic, outside protected blocks):
```python
is_directory = isinstance(input_file, str) and os.path.isdir(input_file)
if is_directory:
    from .archive import DirectoryArchiver, validate_directory_input
    validate_directory_input(input_file)
    archiver = DirectoryArchiver(...)
    manifest = archiver.get_manifest(input_file)
    temp_tar = archiver.create_tar_to_file(input_file)
    original_input = input_file
    input_file = temp_tar  # rest of function encrypts the tar file
```
- Add `metadata["archive"] = {"type": "tar", "manifest": manifest, "original_path": basename}` in metadata construction
- After encryption: securely shred temp tar

**`crypt_core.py`** — `decrypt_file()` (~30 lines added, after decryption completes):
```python
if metadata.get("archive"):
    from .archive import secure_tar_extract
    # Extract tar to output directory instead of writing raw tar
    secure_tar_extract(plaintext, output_dir)
```

**`crypt_cli.py`**
- Update encrypt handler: print "Encrypting directory..." when `os.path.isdir(args.input)`
- Update decrypt handler: detect archive, inform user of extraction

**`crypt_cli_subparser.py`**
- Update `--input/-i` help text: "Input file or directory to encrypt"
- Add `--follow-symlinks` flag to encrypt subparser
- Add `--no-archive-permissions` flag to encrypt subparser

---

## Verification

### Feature 1 (Verify)
```bash
# Encrypt a test file, then verify it
.venv/bin/python -m openssl_encrypt.crypt encrypt -i test.txt --algorithm aes-gcm -p testpass --force-password
.venv/bin/python -m openssl_encrypt.crypt verify -i test.txt.enc
.venv/bin/python -m openssl_encrypt.crypt verify -i test.txt.enc --json
# Corrupt the file and verify again (should fail)
echo "corrupt" >> test.txt.enc
.venv/bin/python -m openssl_encrypt.crypt verify -i test.txt.enc
# Run tests
.venv/bin/python -m pytest openssl_encrypt/unittests/test_verify.py -v
```

### Feature 2 (SSS)
```bash
# Encrypt, split into 3-of-5 shares, combine 3 to decrypt
.venv/bin/python -m openssl_encrypt.crypt encrypt -i secret.txt --algorithm aes-gcm -p testpass --force-password
.venv/bin/python -m openssl_encrypt.crypt split-secret -i secret.txt.enc -n 5 -k 3 -p testpass --force-password
.venv/bin/python -m openssl_encrypt.crypt combine-secrets -i secret.txt.enc --shares share_1.json share_2.json share_4.json -o recovered.txt
diff secret.txt recovered.txt
# Run tests
.venv/bin/python -m pytest openssl_encrypt/unittests/test_secret_sharing.py openssl_encrypt/unittests/test_secret_sharing_integration.py -v
```

### Feature 3 (Directory Archiving)
```bash
# Create test directory, encrypt, decrypt
mkdir -p testdir/sub && echo "hello" > testdir/file.txt && echo "world" > testdir/sub/nested.txt
.venv/bin/python -m openssl_encrypt.crypt encrypt -i testdir/ --algorithm aes-gcm -p testpass --force-password
.venv/bin/python -m openssl_encrypt.crypt decrypt -i testdir.enc -o restored/ -p testpass --force-password
diff -r testdir/ restored/testdir/
# Run tests
.venv/bin/python -m pytest openssl_encrypt/unittests/test_archive.py -v
```

### Full Test Suite
```bash
.venv/bin/python -m pytest openssl_encrypt/unittests/ -n auto --dist=worksteal -v --durations=20
```
