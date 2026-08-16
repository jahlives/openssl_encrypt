# Recovery Slots

Recovery slots let you decrypt an **envelope** file with an *independent*
recovery credential when the primary password is unavailable — without weakening
the file or re-encrypting the bulk data.

## Model

An envelope file encrypts the bulk data under a random **Data Encryption Key
(DEK)**; the DEK is wrapped under your password (`encryption.wrapped_dek`). A
recovery slot is an *additional, independent* wrapping of the **same DEK** under
a recovery credential, stored in `encryption.dek_slots`. Any one credential
(password or a recovery slot) recovers the DEK and decrypts the file.

Recovery slots are **purely additive**: the primary `wrapped_dek` stays
canonical, and a file with no recovery slots is byte-identical to one written
without the feature (and still readable by older versions).

### Credential types

| Type | KEK derivation | Use case |
|------|----------------|----------|
| `recovery_code` | HKDF over a generated 256-bit code | Print/store a one-time recovery code |
| `passphrase` | Argon2id over a chosen passphrase | A memorable backup passphrase |
| `shamir` | HKDF over a k-of-n split secret | Shared custody / no single point |
| `pqc` | ML-KEM to an escrow public key | Offline/third-party escrow (API) |

### Integrity

The recovery-slot **set** is authenticated by a DEK-keyed MAC
(`encryption.dek_slots_mac` = HMAC over the canonical slot list, keyed by
`HKDF(DEK)`), verified after the DEK is recovered on **every** decryption path.
Stripping, injecting, modifying, or swapping slots fails closed. The slot fields
are deliberately excluded from the bulk AEAD AAD so slots can be added/removed
post-hoc without invalidating the retained bulk ciphertext.

## CLI

```bash
# Create an envelope file, then add a generated recovery code:
openssl-encrypt encrypt -i secret.txt -o secret.enc --envelope
openssl-encrypt add-recovery -i secret.enc -o secret.enc -p --add-code
#   -> prints a RECOVERY CODE; store it securely (shown once)

# Add a Shamir 2-of-3 recovery secret (writes share files):
openssl-encrypt add-recovery -i secret.enc -o secret.enc -p \
    --add-shares 2-of-3 --shares-dir ./shares

# Inspect / remove slots:
openssl-encrypt list-recovery   -i secret.enc
openssl-encrypt remove-recovery -i secret.enc -o secret.enc -p --slot-id recovery_code-ab12cd34

# Recover (decrypt WITHOUT the password):
openssl-encrypt recover -i secret.enc -o secret.txt --recovery-code ABCDE-FGHIJ-...
openssl-encrypt recover -i secret.enc -o secret.txt --recovery-passphrase
openssl-encrypt recover -i secret.enc -o secret.txt --recovery-share shares/recovery_share_1.json shares/recovery_share_3.json
```

> The PQC escrow type is available via the Python API
> (`recovery_credentials=[{"type": "pqc", "public_key": ..., "kem_algorithm": ...}]`
> and `decrypt_file(recovery_private_key=...)`); the CLI flags for it are a
> planned follow-up.

## Machine-readable output (`--json`, gitlab#277/#278)

All four commands emit one total-json envelope document on stdout
(`{"status": "ok", "data": ...}`; error envelope on failure). The
`list-recovery` slot schema:

```json
{"metadata_authenticated": false,
 "slots": [{"id": "...", "type": "...", "key_id": "...|null",
            "threshold": 2, "num_shares": 3}], "truncated": true}
```

- `metadata_authenticated` is always `false`: the listing is
  credential-free and everything in it comes from the unauthenticated
  plaintext header — a consumer must not take destructive advice (e.g.
  discarding surplus share files) from it (gitlab#280). All fields are
  declared in the capabilities manifest `json_fields`.

- `id`/`type`/`key_id` are always present (`null` when the header value is
  missing, non-string, or longer than 256 chars). For shamir slots,
  `key_id` is the share-set UUID stamped on the share files that
  `add-recovery --add-shares` writes, so multiple share sets stay
  distinguishable.
- `threshold`/`num_shares` are OPTIONAL and appear only for `type: "shamir"`
  slots whose header values validate as ints with `2 <= K <= N <= 255`;
  malformed values are omitted, never echoed.
- Everything `list-recovery` reports comes from the **unauthenticated**
  plaintext header: the slot set (including K-of-N) is MAC-bound to the DEK
  and verified only when the file is actually decrypted. Do not discard
  share files based on the listing alone — a tampered header could
  under-report N.
- `truncated` appears only when the file claims more than 32 slots (the
  format's `MAX_DEK_SLOTS` bound); the list is capped there.
- `add-recovery --json` reports `output`, `slot_type`, `credential_source`,
  plus `recovery_code_written_to` (with `--add-code`; requires
  `--recovery-code-out`) or `shares`/`threshold`/`num_shares` (with
  `--add-shares` — share file paths only, never share content).

## Python API

```python
from openssl_encrypt.modules.crypt_core import (
    encrypt_file, decrypt_file,
    add_recovery_slots, remove_recovery_slot, list_recovery_slots,
)
from openssl_encrypt.modules.recovery_slots import generate_recovery_code

code = generate_recovery_code()
encrypt_file("in.txt", "out.enc", password=b"pw",
             recovery_credentials=[{"type": "recovery_code", "code": code}])

decrypt_file("out.enc", "in2.txt", recovery_code=code)        # no password needed
add_recovery_slots("out.enc", "out.enc",
                   [{"type": "passphrase", "passphrase": b"backup"}], password=b"pw")
```

## Security notes

- A recovery slot can only be created or changed by someone who can already
  recover the DEK (has the password or an existing recovery credential).
- A recovery **code** is high-entropy and uses a fast KDF; a recovery
  **passphrase** is human-chosen and uses Argon2id. Store recovery material at
  least as securely as the password it backs up.
- Removing a slot revokes that recovery path on the rewritten file only;
  copies made earlier are unaffected.
