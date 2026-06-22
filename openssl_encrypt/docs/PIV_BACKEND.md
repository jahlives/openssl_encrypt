# PIV / PKCS#11 HSM Backend

The PIV backend binds your encryption to a hardware key that holds a **PIV
private key**. Instead of the HMAC-SHA1 challenge-response used by the YubiKey
and OnlyKey backends, a PIV key *signs* a deterministic challenge derived from
the file salt, and the signature is normalized into a fixed-length pepper with
HKDF-SHA256.

The pepper is **never stored** — the token must be present to decrypt.

## Why "deterministic" matters

The whole value of this backend is **multi-device redundancy**: import the same
private key onto two tokens and either one can decrypt your files, because the
same key produces the *same* signature for the same challenge.

This only holds for deterministic signature schemes. The backend therefore
supports and **requires** one of:

| Key type | Mechanism | Deterministic? | Supported |
|---|---|---|---|
| Ed25519 | EdDSA (RFC 8032) | Yes | ✅ |
| RSA-2048/3072/4096 | PKCS#1 v1.5 | Yes | ✅ |
| ECDSA (P-256/P-384) | ECDSA | **No** (random k) | ❌ rejected |
| RSA | PSS | **No** (random salt) | ❌ rejected |

If you point the backend at an ECDSA or RSA-PSS key it raises a clear error
rather than silently producing peppers that differ between devices. On every
signing operation the backend also signs the challenge twice and compares the
results (constant-time) as a determinism self-check.

## Supported hardware

| Device | PIV application | Key types | PKCS#11 module |
|---|---|---|---|
| YubiKey Bio MPE | Yes | Ed25519, RSA | `opensc-pkcs11.so` or `ykcs11.so` |
| YubiKey 5 series | Yes | Ed25519, RSA | `opensc-pkcs11.so` or `ykcs11.so` |
| Token2 PIN+ R3.3+ | Yes | RSA-2048/3072/4096 | `opensc-pkcs11.so` |
| Any PKCS#11 PIV token | Yes | Ed25519 or RSA | vendor module |

> ⚠️ **Not every YubiKey has PIV.** The PIV applet exists only on the
> **YubiKey 5 series**, **5 FIPS**, and the **YubiKey Bio — Multi-Protocol
> Edition (MPE)**. It is **absent** on the **Security Key Series** (FIDO-only)
> and, importantly, on the **YubiKey Bio — FIDO Edition** (note: *FIDO*
> Edition, not *MPE*). On those devices the PIV application simply does not
> exist, so the backend cannot be used and `ykman config usb -e piv` fails with
> `PIV not supported over USB on this YubiKey` — it is a missing applet, not a
> disabled interface. Check with `ykman info`: if the `PIV` row reads
> `Not available`, this backend is not an option for that key.

### If your key is FIDO-only

A FIDO-only key (Security Key Series, Bio FIDO Edition) can still bind
encryption via the **FIDO2 backend** (`--hsm fido2`, hmac-secret extension) —
see [FIDO2_HSM_GUIDE.md](FIDO2_HSM_GUIDE.md). Be aware of a significant
trade-off, though:

> ⚠️ **The FIDO2 backend has no true backup key.** A FIDO2 hmac-secret
> credential's secret (CredRandom) is generated inside the authenticator, is
> **non-exportable**, and is **unique per credential** — there is no way to
> provision a second physical key that derives the *same* pepper. Registering a
> "backup" credential (`fido2-register --backup`) only adds another credential
> that produces a *different* pepper; a backup key therefore **cannot decrypt
> files that were encrypted with the primary key**. If the registered key is
> lost or reset, data bound to it is **unrecoverable**.
>
> This is the key advantage of the PIV and HMAC-SHA1 CR backends: PIV lets you
> import the *same* private key onto several tokens, and the YubiKey/OnlyKey CR
> backends let you load the *same* 20-byte secret onto several devices — both
> give genuine multi-device redundancy. **If backup/recovery matters, prefer a
> PIV-capable token (5 series, 5 FIPS, Bio MPE) or the CR backends over FIDO2.**

## Requirements

```bash
pip install -r requirements-hsm.txt   # pulls in python-pkcs11
```

You also need a PKCS#11 module on the system (e.g. OpenSC's `opensc-pkcs11.so`
or Yubico's `ykcs11`). The path is **always supplied explicitly** via
`--hsm-pkcs11-lib`; it is never hardcoded.

## Importing a key into a PIV slot

> The tool does **not** generate or import keys for you — that is your
> responsibility. Generate the key once, store it securely (offline), and import
> the *same* key onto every device you want to use.

```bash
# Generate an Ed25519 key once, and keep piv_key.pem somewhere safe & offline.
openssl genpkey -algorithm ed25519 -out piv_key.pem

# Import into a YubiKey PIV slot 9a (Authentication).
ykman piv keys import 9a piv_key.pem

# Import the SAME key into a Token2 R3.3 via OpenSC.
pkcs15-init --store-private-key piv_key.pem --key-usage sign --auth-id 01

# Verify the key is present.
ykman piv info
```

Repeat the import on each backup device using the same `piv_key.pem`.

## PIV slots

| Slot | Hex | Purpose |
|---|---|---|
| 9a | `0x9A` | PIV Authentication (default) |
| 9c | `0x9C` | Digital Signature |
| 9d | `0x9D` | Key Management |
| 9e | `0x9E` | Card Authentication |

## Usage

```bash
# Encrypt with a PIN-protected PIV key in slot 9a (default).
openssl_encrypt encrypt -i secret.txt -o secret.enc \
    --hsm piv --hsm-pkcs11-lib /usr/lib/opensc-pkcs11.so

# Use a different PIV slot.
openssl_encrypt encrypt -i secret.txt -o secret.enc \
    --hsm piv --hsm-pkcs11-lib /usr/lib/opensc-pkcs11.so --hsm-piv-slot 9c

# Biometric (YubiKey Bio): no PIN prompt, touch the fingerprint sensor instead.
openssl_encrypt encrypt -i secret.txt -o secret.enc \
    --hsm piv --hsm-pkcs11-lib /usr/lib/opensc-pkcs11.so --hsm-biometric

# Select a specific PKCS#11 slot index when several tokens are connected.
openssl_encrypt encrypt -i secret.txt -o secret.enc \
    --hsm piv --hsm-pkcs11-lib /usr/lib/opensc-pkcs11.so --hsm-slot 1

# Decrypt: present the same flags (and the same key on the token).
openssl_encrypt decrypt -i secret.enc -o secret.txt \
    --hsm piv --hsm-pkcs11-lib /usr/lib/opensc-pkcs11.so
```

### CLI flags

| Flag | Meaning |
|---|---|
| `--hsm piv` | select the PIV/PKCS#11 backend |
| `--hsm-pkcs11-lib PATH` | path to the PKCS#11 module (**required** for PIV) |
| `--hsm-piv-slot {9a,9c,9d,9e}` | PIV key slot (default `9a`) |
| `--hsm-slot N` | PKCS#11 slot index when several tokens are present (default 0) |
| `--hsm-biometric` | Bio keys: skip the PIN prompt, authenticate by touch |

The **PIN is never a command-line argument**. For PIN-protected keys you are
prompted interactively (via `getpass`, so it never echoes). An empty entry falls
back to the no-PIN / biometric flow.

## Security notes

- **PIN handling.** The PIN is read with `getpass`, held in a `bytearray`, and
  zeroed with `ctypes.memset` immediately after login, on success or failure. It
  never appears in arguments, logs, exception messages, or tracebacks.
- **Final-try guard.** Before sending a non-empty PIN, the backend checks the
  token's final-try flag and refuses to attempt a login that could lock the
  token unless explicitly confirmed. (Skipped for the biometric flow.)
- **No fallback.** If authentication fails the operation aborts; it never falls
  back to another method.
- **Session cleanup.** The PKCS#11 session is closed on every exit path,
  including exceptions.

## Known limitations

- **PIN copies inside python-pkcs11.** The backend zeroes its own PIN buffer, but
  the `python-pkcs11` binding may hold a transient copy of the PIN during
  `C_Login` that is outside our control and cannot be wiped. This is inherent to
  the binding.
- **Login-state verification.** The backend confirms a USER_FUNCTIONS session
  state after login when the binding exposes session info; some versions do not,
  in which case it relies on `C_Login` raising on failure (it does) and on the
  subsequent login-gated signing operation.
- **`verify_hardware()` is a diagnostic.** It returns a per-check result dict
  (each value `True`, `"skipped"`, or an error string) rather than raising on a
  failed check, so you can inspect every step. The real `get_pepper()` path
  raises on any failure.
- **Out of scope:** on-device key generation, an interactive setup wizard, and
  the Windows PKCS#11 mini-driver path (documented as future work).
