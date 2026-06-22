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
| YubiKey 5 series | Yes | Ed25519, RSA | `opensc-pkcs11.so` or `ykcs11.so` |
| YubiKey 5 FIPS | Yes | Ed25519, RSA | `opensc-pkcs11.so` or `ykcs11.so` |
| YubiKey Bio — MPE (enterprise-only, see caveat) | Yes | Ed25519, RSA | `opensc-pkcs11.so` or `ykcs11.so` |
| Token2 PIN+ Release3.3+ "with PIV" (see caveat) | Yes | RSA-2048/3072/4096 | `opensc-pkcs11.so` |
| Any PKCS#11 PIV token | Yes | Ed25519 or RSA | vendor module |

> ⚠️ **Most YubiKeys you can buy do not have PIV — the YubiKey 5 series is the
> practical choice.** The PIV applet exists only on the **YubiKey 5 series**,
> **5 FIPS**, and the **YubiKey Bio — Multi-Protocol Edition (MPE)**. It is
> **absent** on the **Security Key Series** (FIDO-only) and on the **YubiKey Bio
> — FIDO Edition** — which is the *only* Bio you can buy off the shelf.
>
> Heads-up on the Bio MPE specifically:
> - It exists in both form factors (USB-A "YubiKey Bio – MPE" and USB-C "YubiKey
>   C Bio – MPE"), **but you cannot buy one in the store.** Yubico's own
>   consumer store sells only the **FIDO Edition** Bios; the MPE ships
>   **exclusively via "YubiKey as a Service"** (enterprise Compliance tier, or an
>   Advanced-tier add-on). There is no individual purchase path at any price.
> - For anyone not on a Yubico enterprise contract, the realistic PIV-capable
>   key is a **YubiKey 5**, not a Bio.
>
> On a FIDO-only key the PIV application simply does not exist, so the backend
> cannot be used and `ykman config usb -e piv` fails with `PIV not supported over
> USB on this YubiKey` — a missing applet, not a disabled interface. Check with
> `ykman info`: if the `PIV` row reads `Not available`, this backend is not an
> option for that key.

> ⚠️ **Token2: not every model has PIV.** Only the **PIN+ Release3.3** keys (sold
> explicitly as *"FIDO2.1 Key with PIV, OpenPGP and OTP"* — e.g. *PIN+ Dual
> Release3.3* and *PIN+ Release3.3 TypeC*) carry the PIV applet. The **Token2
> Bio3** ships with **OpenPGP, not PIV**, and `openssl_encrypt` has no
> OpenPGP-card backend — so a Bio3 cannot drive `--hsm piv` (its reader name
> shows "FIDO + PGP", and `pkcs15-init` fails with *"Invalid arguments"*).
> Confirm the applet first with `pkcs15-tool --dump` or
> `pkcs11-tool --module /usr/lib/opensc-pkcs11.so -O --login`.

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

## Cross-device backup & recovery

This is the backend's headline advantage over the FIDO2 backend (which has **no**
backup key — its credential secret is non-exportable). Because Ed25519 and
RSA PKCS#1 v1.5 are **deterministic**, the *same* private key on two different
tokens signs the salt-derived challenge identically, so both derive the **same
pepper** — and a file encrypted with one token decrypts with the other.

> ✅ **Verified on real hardware** (2026-06-22): a file encrypted with one
> YubiKey (Ed25519, slot 9a) decrypted cleanly with a second YubiKey holding the
> same imported key.

**Provision a backup device:**

```bash
# Import the SAME offline piv_key.pem onto a second token (YubiKey 5.7+ for
# Ed25519, or 5-series/Token2 R3.3 for RSA). Use the same slot you encrypt with.
ykman piv keys import --pin-policy ONCE --touch-policy ALWAYS 9a piv_key.pem
ykman piv certificates import 9a piv_cert.pem
```

**Prove recovery before you rely on it** — encrypt with key #1, then decrypt with
**only key #2** present:

```bash
echo "recovery test" > /tmp/rt.txt
# (key #1 inserted)
openssl_encrypt encrypt -i /tmp/rt.txt -o /tmp/rt.enc \
    --hsm piv --hsm-pkcs11-lib /usr/lib/opensc-pkcs11.so --hsm-piv-slot 9a
# swap to key #2, then:
openssl_encrypt decrypt -i /tmp/rt.enc -o /tmp/rt.out \
    --hsm piv --hsm-pkcs11-lib /usr/lib/opensc-pkcs11.so --hsm-piv-slot 9a
diff /tmp/rt.txt /tmp/rt.out && echo "cross-device PIV recovery OK"
```

Requirements and caveats:

- **Same key type on every device.** Ed25519 needs **YubiKey firmware ≥ 5.7**;
  to include an older YubiKey or a Token2 R3.3 in the fleet, standardize on
  **RSA-2048** (works everywhere) instead. Mixed key material does **not** produce
  matching peppers.
- **Same key, not a fresh one per device.** Generate `piv_key.pem` once and import
  that exact file onto each token — a key generated on-device would differ.
- **Keep `piv_key.pem` itself offline** (e.g. paper/USB in a safe). It is the
  master recovery secret: from it you can provision any replacement token. The
  per-device PIN/touch only gate *use* of the key, not its value.
- The PKCS#11 **slot index** (`--hsm-slot`) may differ between hosts/tokens; the
  **PIV slot** (`--hsm-piv-slot`, default `9a`) should match what you encrypted
  with. On `decrypt`/rekey, `--hsm-slot` overrides any stored value.

## PIV slots

| Slot | Hex | Purpose | PIN behavior | Works with this backend? |
|---|---|---|---|---|
| 9a | `0x9A` | PIV Authentication | PIN once per session (honors `--pin-policy`) | ✅ **recommended (default)** |
| 9c | `0x9C` | Digital Signature | **PIN required before *every* signature** (always-authenticate) | ❌ **not supported** — see warning |
| 9d | `0x9D` | Key Management | PIN once per session (honors `--pin-policy`) | ✅ works like 9a |
| 9e | `0x9E` | Card Authentication | **no PIN** (PIN-policy NEVER) | ⚠️ works, but no PIN factor |

> ⚠️ **Do not use slot 9c with this backend.** On YubiKey, slot 9c (Digital
> Signature) is **always-authenticate**: the PIV standard requires a fresh PIN
> verification immediately before *each* signature, which PKCS#11 exposes as a
> **context-specific login** (`CKA_ALWAYS_AUTHENTICATE`). This backend performs a
> single session login and then signs (twice, for the determinism self-check)
> **without** a per-signature context-specific re-login, so signing on a 9c key
> fails (`CKR_USER_NOT_LOGGED_IN`, after prompting for a second "context specific
> PIN"). Use **9a** (default) — or 9d — which honor `--pin-policy ONCE` so one
> session login covers the operation. Slot 9e works too but requires no PIN at
> all, dropping the PIN factor.

## Usage

```bash
# Encrypt with a PIN-protected PIV key in slot 9a (default).
openssl_encrypt encrypt -i secret.txt -o secret.enc \
    --hsm piv --hsm-pkcs11-lib /usr/lib/opensc-pkcs11.so

# Use a different PIV slot (9d behaves like 9a; avoid 9c — see "PIV slots").
openssl_encrypt encrypt -i secret.txt -o secret.enc \
    --hsm piv --hsm-pkcs11-lib /usr/lib/opensc-pkcs11.so --hsm-piv-slot 9d

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
| `--hsm-piv-slot {9a,9c,9d,9e}` | PIV key slot (default `9a`; use 9a or 9d — **not 9c**, see "PIV slots") |
| `--hsm-slot N` | PKCS#11 slot index when several tokens are present (default 0) |
| `--hsm-biometric` | Bio keys: skip the PIN prompt, authenticate by touch (see caveat) |

The **PIN is never a command-line argument**. For PIN-protected keys you are
prompted interactively (via `getpass`, so it never echoes). An empty entry falls
back to the no-PIN / biometric flow.

> ⚠️ **`--hsm-biometric` is effectively Windows-only for PIV.** On the YubiKey
> Bio MPE, fingerprint verification for the **PIV** applet requires Yubico's
> **Smart Card Minidriver (≥4.6.1), which exists only on Windows**. On Linux and
> macOS the PIV path uses the **PIN** instead (and on the MPE the PIN is *shared*
> between PIV and FIDO2). So on this project's primary platform (Linux),
> `--hsm-biometric` will generally not give you a true fingerprint-only flow —
> expect a PIN prompt. Also note the MPE's **PUK is blocked by default**: a
> blocked PIN can only be cleared by a full device reset (which destroys the key).

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
- **No context-specific (always-authenticate) login.** The backend does one
  session `C_Login` and then signs; it does not perform a per-signature
  context-specific login. Keys whose slot sets `CKA_ALWAYS_AUTHENTICATE` —
  notably **YubiKey PIV slot 9c** — therefore fail at signing. Use slot **9a**
  (default) or **9d**. See the warning under "PIV slots".
- **Out of scope:** on-device key generation, an interactive setup wizard, and
  the Windows PKCS#11 mini-driver path (documented as future work).
