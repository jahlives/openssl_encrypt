# Security Review — Remaining Items

Items identified during the v1.4.x security review that have not yet been addressed.

## Deferred (Architectural)

### SC-3: Streaming decryptor reads entire file into memory

**Severity:** MEDIUM
**File:** `openssl_encrypt/modules/streaming.py`

The streaming decryptor reads the entire encrypted payload into memory before
processing chunks. For very large files this defeats the purpose of streaming.
A true streaming approach would read and decrypt chunks incrementally from disk.

This requires a significant refactor of the streaming decryption pipeline and
careful handling of the HMAC trailer verification (which currently needs the
full payload to validate before releasing plaintext).

### CC-10: TOCTOU race in set_secure_permissions

**Severity:** MEDIUM
**File:** `openssl_encrypt/modules/crypt_utils.py`

The `set_secure_permissions()` function has a time-of-check to time-of-use race
between file creation and `os.chmod()`. An attacker with local access could
potentially read the file in the window between creation and permission change.

Mitigation would require platform-specific approaches:
- Linux: use `os.open()` with mode flags (already done in keystore_cli.py and
  pepper config), or `os.fchmod()` on the file descriptor
- Audit all callers of `set_secure_permissions()` and replace with
  `os.open(..., 0o600)` pattern where possible

## Dismissed (By Design)

These were identified during review but determined to not require changes:

| ID | Description | Reason |
|----|-------------|--------|
| CC-2 | Debug logging may expose sensitive data | Intentional; requires explicit enable, big warning shown |
| CC-3 | Camellia uses shorter key than AES-256 | Decrypt-only in v1.4.x, fully removed in v1.5 |
| CC-4 | XChaCha20 nonce handling | Left out per maintainer decision |
| CC-5 | PBKDF2 weaker than Argon2id | Decrypt-only in v1.4.x, fully removed in v1.5 |
| CC-6 | Fernet metadata not independently authenticated | Self-protecting via Fernet's internal HMAC |
| CC-7/CC-8 | Format version <12 missing per-chunk nonce/AAD | Fixing would break backward compatibility |
| SV-3 | `--password` CLI arg visible in process list | Already deprecated with warning; `--password-file` and env var alternatives exist |
