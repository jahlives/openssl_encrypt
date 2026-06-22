# FIDO2 Hardware Security Module (HSM) Guide

## Overview

The FIDO2 HSM plugin adds hardware-bound key derivation to OpenSSL Encrypt using **FIDO2 authenticators**. It uses the `hmac-secret` extension to derive deterministic 32-byte pepper values that enhance encryption security by binding encrypted files to physical security keys.

**Key Features:**
- ✅ Hardware-bound encryption (requires physical security key)
- ✅ Works with any FIDO2-compliant authenticator (YubiKey 5, Nitrokey 3, SoloKey v2, etc.)
- ✅ PIN protection + touch requirement for each operation
- ⚠️ Per-credential peppers — **no true backup key** (see warning below)
- ✅ Deterministic pepper derivation (same salt + same credential → same pepper)
- ✅ Standard FIDO2 protocol (no vendor lock-in)

> ⚠️ **No true backup key with FIDO2.** A FIDO2 hmac-secret credential's secret
> (CredRandom) is generated inside the authenticator, is **non-exportable**, and
> is **unique per credential**. There is no way to provision a second physical
> key that derives the *same* pepper. Registering a backup credential
> (`fido2-register --backup`) only adds a credential that produces a *different*
> pepper, so a backup key **cannot decrypt files encrypted with the primary** —
> it is useful only for encrypting *new* files you also want that key to open.
> If the registered key is lost or reset, data bound to it is **unrecoverable**.
>
> For genuine multi-device redundancy use a backend whose secret can be
> replicated across devices: the **PIV / PKCS#11** backend (import the same
> private key onto several tokens — [PIV_BACKEND.md](PIV_BACKEND.md)) or the
> **YubiKey/OnlyKey HMAC-SHA1 CR** backends (load the same 20-byte secret onto
> several devices — [hardware-tokens.md](hardware-tokens.md)). Reach for FIDO2
> mainly when your key is FIDO-only (Security Key Series, YubiKey Bio FIDO
> Edition) and PIV/OTP applets are unavailable.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Usage Examples](#usage-examples)
5. [How It Works](#how-it-works)
6. [Security Properties](#security-properties)
7. [Credential Management](#credential-management)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

---

## Requirements

### Hardware Requirements

**Supported FIDO2 Authenticators:**
- YubiKey 5 Series (YubiKey 5 NFC, 5 Nano, 5C, 5Ci, 5C Nano)
- Nitrokey 3
- SoloKey v2
- Any FIDO2-compliant authenticator supporting `hmac-secret` extension

**To verify your device supports hmac-secret:**
```bash
openssl_encrypt hsm fido2-list
```

### Software Requirements

- Python 3.11+
- `fido2` library (python-fido2 by Yubico)

---

## Installation

### 1. Install FIDO2 Library

```bash
pip install fido2>=1.1.0
```

### 2. Verify Installation

```bash
# List connected FIDO2 devices
openssl_encrypt hsm fido2-list
```

Expected output:
```
🔐 Connected FIDO2 Devices
==================================================
Found 1 device(s):

Device #1: YubiKey 5 NFC
  Manufacturer: Yubico
  AAGUID: cb69481e-8ff7-4039-93ec-0a2729a154a8
  Versions: FIDO_2_0, FIDO_2_1
  Extensions: hmac-secret, credProtect
  hmac-secret: ✅ Supported
```

---

## Quick Start

### Step 1: Register Your Security Key

```bash
openssl_encrypt hsm fido2-register --description "YubiKey 5 NFC"
```

**What happens:**
1. You'll be prompted to insert your security key
2. You may need to enter your PIN
3. Touch your security key to complete registration
4. A credential is created and saved to `~/.openssl_encrypt/fido2/credentials.json`

### Step 2: Verify Registration

```bash
openssl_encrypt hsm fido2-status
```

### Step 3: Test Pepper Derivation

```bash
openssl_encrypt hsm fido2-test
```

### Step 4: Encrypt a File

```bash
openssl_encrypt encrypt --hsm fido2 secret.txt
```

**What happens:**
1. You'll be prompted to enter encryption password
2. You'll be prompted to touch your security key
3. File is encrypted with password + hardware-bound pepper
4. Output: `secret.txt.enc`

### Step 5: Decrypt the File

```bash
openssl_encrypt decrypt --hsm fido2 secret.txt.enc
```

**What happens:**
1. You'll be prompted to enter decryption password
2. You'll be prompted to touch your security key
3. File is decrypted and saved to `secret.txt`

---

## Usage Examples

### Basic Encryption/Decryption

```bash
# Encrypt with FIDO2 pepper
openssl_encrypt encrypt --hsm fido2 document.pdf

# Decrypt with FIDO2 pepper
openssl_encrypt decrypt --hsm fido2 document.pdf.enc
```

### Multiple Files

```bash
# Encrypt multiple files
openssl_encrypt encrypt --hsm fido2 file1.txt file2.txt file3.txt

# Decrypt multiple files
openssl_encrypt decrypt --hsm fido2 *.enc
```

### With Custom Algorithm

```bash
# Use AES-256-GCM with FIDO2 pepper
openssl_encrypt encrypt --hsm fido2 -a aes-256-gcm sensitive.txt

# Use post-quantum ML-KEM with FIDO2 pepper
openssl_encrypt encrypt --hsm fido2 -a ml-kem-768-hybrid classified.txt
```

### Backup Credential Registration

Register an additional credential:

```bash
openssl_encrypt hsm fido2-register --description "Backup Nitrokey 3" --backup
```

> ⚠️ **This does NOT give you a recovery key.** Each FIDO2 credential has its
> own non-exportable secret, so a "backup" credential derives a *different*
> pepper and **cannot decrypt files encrypted with the primary**. It only lets
> that second key open files you encrypt *after* registering it (the plugin
> peppers with whichever registered credential is present). To survive loss of
> the primary key you must keep the primary key itself safe, or re-encrypt your
> data under each key separately. For genuine recovery, use the PIV or
> YubiKey/OnlyKey CR backends instead — see the warning at the top of this guide.

---

## How It Works

### 1. Pepper Derivation Flow

```
┌──────────────────┐
│  Encryption      │
│  Password        │
└────────┬─────────┘
         │
         ▼
    ┌────────┐
    │  Salt  │ (16 bytes, random)
    └───┬────┘
        │
        ├─────────────────────────────┐
        │                             │
        ▼                             ▼
┌───────────────┐           ┌─────────────────┐
│   Password    │           │  FIDO2 Device   │
│   + Salt      │           │  hmac-secret    │
│   (Argon2)    │           │  (Hardware)     │
└───────┬───────┘           └────────┬────────┘
        │                            │
        │  Derived Key (32 bytes)    │  Pepper (32 bytes)
        │                            │
        └────────────┬───────────────┘
                     │
                     ▼
            ┌─────────────────┐
            │  Final Key      │
            │  (Key + Pepper) │
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │  Encrypt File   │
            └─────────────────┘
```

### 2. FIDO2 hmac-secret Extension

The plugin uses the FIDO2 `hmac-secret` extension:

```python
# Simplified flow
salt = random_bytes(16)                    # Random 16-byte salt
credential_id = load_from_config()         # Previously registered credential

# FIDO2 authenticator computes:
pepper = HMAC-SHA256(credential_secret, salt)  # 32-byte output

# credential_secret is:
# - Generated during registration
# - Stored securely in authenticator hardware
# - Never leaves the device
# - Unique per credential
```

**Key Properties:**
- ✅ **Deterministic**: Same salt + same credential → same pepper
- ✅ **Hardware-bound**: Pepper requires physical device
- ✅ **Never stored**: Computed on-demand each time
- ✅ **PIN protected**: User verification required

### 3. Credential Storage

Credentials are stored in `~/.openssl_encrypt/fido2/credentials.json`:

```json
{
  "version": 1,
  "rp_id": "openssl-encrypt.local",
  "credentials": [
    {
      "id": "primary",
      "credential_id": "<base64_encoded_id>",
      "created_at": "2026-01-02T12:00:00Z",
      "authenticator_aaguid": "cb69481e-8ff7-4039-93ec-0a2729a154a8",
      "description": "YubiKey 5 NFC (primary)",
      "is_backup": false
    }
  ]
}
```

**File Permissions:**
- Directory: `0o700` (drwx------)
- File: `0o600` (-rw-------)

**What's Stored:**
- ✅ Credential ID (public, needed to identify credential on device)
- ✅ Description (human-readable label)
- ✅ Creation timestamp
- ✅ Authenticator AAGUID (device identifier)

**What's NOT Stored:**
- ❌ No secret keys
- ❌ No private keys
- ❌ No pepper values
- ❌ No passwords

---

## Security Properties

### 1. Hardware-Bound Encryption

**Threat Model:**
- ❌ **Attacker steals encrypted file** → Cannot decrypt without physical security key
- ❌ **Attacker clones encrypted file** → Still requires original security key
- ❌ **Attacker extracts credential file** → Contains no secrets, useless alone

**Security Guarantee:**
Even if an attacker obtains:
- Encrypted file
- Password
- Credential configuration file

They **cannot decrypt** without physical access to the registered security key.

### 2. PIN Protection

Every pepper derivation requires:
1. **PIN entry** (something you know)
2. **Touch confirmation** (something you have)

This provides **two-factor authentication** for every encryption/decryption operation.

### 3. Deterministic Pepper Derivation

The pepper is **deterministic**:
- Same salt + same credential → same pepper (always)
- Required for decryption
- Never changes for a given salt and credential

This ensures:
- ✅ Encrypted files can always be decrypted **with the same credential** used to encrypt them
- ✅ No risk of pepper rotation breaking old files
- ⚠️ The pepper is **per-credential**: a different credential (e.g. a "backup" key) derives a *different* pepper and cannot decrypt the primary's files

### 4. No Secrets in Storage

The credential file contains **zero secrets**:
- No private keys
- No symmetric keys
- No pepper values
- Only public metadata

**Even if stolen, it's useless without the physical security key.**

### 5. Standard Protocol

Uses **FIDO2 hmac-secret extension** (standard):
- No proprietary protocols
- No vendor lock-in
- Works with any compliant authenticator
- Well-audited and trusted

---

## Credential Management

### Register Primary Credential

```bash
openssl_encrypt hsm fido2-register --description "YubiKey 5 NFC"
```

### Register Backup Credential

```bash
openssl_encrypt hsm fido2-register --description "Backup Nitrokey 3" --backup
```

> ⚠️ **Not a recovery key.** The two keys derive **different** peppers for the
> same salt (each credential's secret is unique and non-exportable), so the
> backup key **cannot** decrypt files made with the primary. Re-encryption under
> the backup key *is* required if you want that key to open existing files. See
> the "no true backup key" warning at the top of this guide.

### Check Registration Status

```bash
openssl_encrypt hsm fido2-status
```

Output:
```
🔐 FIDO2 Registration Status
==================================================
✅ 2 credential(s) registered
Configuration file: /home/user/.openssl_encrypt/fido2/credentials.json
Relying Party ID: openssl-encrypt.local

Credential #1:
  ID: primary
  Description: YubiKey 5 NFC (primary)
  Created: 2026-01-02T12:00:00Z
  AAGUID: cb69481e-8ff7-4039-93ec-0a2729a154a8
  Backup: No

Credential #2:
  ID: backup-1
  Description: Backup Nitrokey 3
  Created: 2026-01-03T10:00:00Z
  AAGUID: 11223344-5566-7788-99aa-bbccddeeff00
  Backup: Yes
```

### Test Pepper Derivation

```bash
openssl_encrypt hsm fido2-test
```

Verifies:
- Device is connected
- PIN is correct
- Pepper derivation works
- Returns 32-byte pepper

### Unregister Credential

```bash
# Remove primary credential
openssl_encrypt hsm fido2-unregister

# Remove specific backup credential
openssl_encrypt hsm fido2-unregister --credential-id backup-1

# Remove all credentials
openssl_encrypt hsm fido2-unregister --all
```

**WARNING:** This only removes the local registration. The credential remains on your security key. Use your authenticator's management tools to fully delete credentials.

---

## Troubleshooting

### No Device Found

**Error:**
```
❌ No FIDO2 device found. Please connect your security key.
```

**Solutions:**
1. Insert your FIDO2 security key
2. Try a different USB port
3. Verify device is recognized: `lsusb` (Linux) or check Device Manager (Windows)
4. Check udev rules (Linux): `/etc/udev/rules.d/70-u2f.rules`

### Device Not Supporting hmac-secret

**Error:**
```
❌ Connected device does not support hmac-secret extension
```

**Explanation:**
Your device doesn't support the `hmac-secret` extension required for pepper derivation.

**Supported Devices:**
- YubiKey 5 Series
- Nitrokey 3
- SoloKey v2
- Most modern FIDO2 authenticators

**Check Support:**
```bash
openssl_encrypt hsm fido2-list
```

### PIN Required but Not Set

**Error:**
```
❌ PIN required but not set on device
```

**Solution:**
Set a PIN on your FIDO2 authenticator:

**YubiKey:**
```bash
ykman fido access change-pin
```

**Nitrokey:**
```bash
nitropy fido2 set-pin
```

### Wrong PIN

**Error:**
```
❌ Failed to get assertion: PIN verification failed
```

**Solution:**
1. Enter correct PIN
2. If PIN is forgotten, reset your device (WARNING: deletes all credentials)

**YubiKey Reset:**
```bash
ykman fido reset
```

**Nitrokey Reset:**
```bash
nitropy fido2 reset
```

### Multiple Devices Connected

**Behavior:**
Plugin automatically uses the first detected device.

**Solution for Specific Device:**
Currently not supported. Disconnect other devices or use device selection (future feature).

### Permission Denied (Linux)

**Error:**
```
❌ Failed to access device: Permission denied
```

**Solution:**
Add udev rules for FIDO2 devices:

```bash
# Create udev rules file
sudo tee /etc/udev/rules.d/70-u2f.rules <<EOF
# YubiKey
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", MODE="0660", GROUP="plugdev", TAG+="uaccess"

# Nitrokey
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="20a0", MODE="0660", GROUP="plugdev", TAG+="uaccess"

# Generic FIDO
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="*", ATTRS{idProduct}=="*", MODE="0660", GROUP="plugdev", TAG+="uaccess", ENV{ID_FIDO_TOKEN}=="1"
EOF

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger
```

---

## FAQ

### Q: What happens if I lose my security key?

**A:** Your files are **permanently inaccessible** for anything that was
encrypted while that key was the present credential. FIDO2 has **no recovery
key**: a "backup" credential derives a different pepper and cannot decrypt the
lost key's files (see the warning at the top of this guide). A backup credential
only helps for files you *also* encrypted with that backup key present.

**Recommendation:** If you need to survive loss of the device, do **not** rely on
FIDO2 — use the PIV backend (same private key imported onto a spare token) or the
YubiKey/OnlyKey CR backends (same secret loaded onto a spare device), both of
which give a real recovery key.

---

### Q: Can I use the same security key across multiple computers?

**A:** Yes! The FIDO2 credential is stored on the security key itself.

**Setup:**
1. Register credential on Computer A
2. Copy `~/.openssl_encrypt/fido2/credentials.json` to Computer B
3. Use security key on Computer B

The credential configuration file contains **no secrets**, so it's safe to copy.

---

### Q: What if someone steals my encrypted files?

**A:** They **cannot decrypt** without:
1. Your password (something you know)
2. Your physical security key (something you have)
3. Your security key PIN (something else you know)

This provides **three factors of protection**.

---

### Q: Does the FIDO2 plugin work with password-protected keys?

**A:** Yes! The plugin adds an **additional layer** on top of password encryption:

```
Security = Password + FIDO2 Hardware + PIN
```

Even with the correct password, decryption fails without the physical security key.

---

### Q: How do backup credentials work?

**A:** They do **not** provide cross-key recovery. Each registered credential
derives a **different** pepper for the same salt.

**Why:**
- Each credential has a unique `CredRandom` secret generated inside the
  authenticator at registration; it is non-exportable and cannot be cloned.
- The FIDO2 hmac-secret output is `HMAC(CredRandom, salt)` — so different
  credentials produce **different** outputs, by design of the spec.
- Therefore a file encrypted with the primary credential **cannot** be decrypted
  with a backup credential. A "backup" only opens files that were encrypted
  while that backup credential was the one present.

---

### Q: Can I use multiple FIDO2 devices simultaneously?

**A:** You can **register** multiple devices, but only **one device is used** per
operation — and the pepper depends on *which* credential that device holds.

**During decryption:**
- The plugin presents all registered credential IDs; the connected device
  answers for whichever one it holds.
- Decryption only succeeds if the present credential is the **same** one used at
  encryption time — a different registered credential yields a different pepper
  and fails. Registered keys are **not** interchangeable for a given file.

---

### Q: What's stored on the FIDO2 device?

**On Device:**
- ✅ Credential private key (never leaves device)
- ✅ hmac-secret material

**NOT on Device:**
- ❌ Encrypted files
- ❌ Passwords
- ❌ File metadata

The security key only stores **cryptographic material** needed for pepper derivation.

---

### Q: Is this more secure than YubiKey Challenge-Response?

**Comparison:**

| Feature | FIDO2 hmac-secret | YubiKey Challenge-Response |
|---------|-------------------|---------------------------|
| **Pepper Size** | 32 bytes (SHA256) | 20 bytes (SHA1) |
| **Authentication** | PIN + Touch | Touch only (no PIN) |
| **Standard** | FIDO2 (industry standard) | Proprietary (Yubico) |
| **Device Support** | Any FIDO2 authenticator | YubiKey only |
| **Multi-device recovery** | ❌ None — per-credential secret, non-exportable | ✅ Same 20-byte secret can be loaded onto multiple devices |

**Recommendation:** FIDO2 hmac-secret offers a longer pepper and PIN+touch, but
has **no multi-device recovery**. If you need a backup/recovery key, prefer the
PIV backend or the YubiKey/OnlyKey Challenge-Response backends. Use FIDO2 when
your key is FIDO-only (e.g. Security Key Series, YubiKey Bio FIDO Edition).

---

### Q: Can I migrate from YubiKey Challenge-Response to FIDO2?

**A:** Not directly. Files encrypted with YubiKey CR cannot be decrypted with FIDO2.

**Migration Process:**
1. Keep YubiKey Challenge-Response enabled
2. Decrypt files with `--hsm yubikey`
3. Re-encrypt files with `--hsm fido2`

---

### Q: What happens if I factory reset my security key?

**A:**
- ❌ All credentials are **deleted** from the device, and their secrets are gone
  forever (non-exportable, unrecoverable).
- ❌ You **cannot** decrypt files encrypted with that key — a backup credential
  on another device does **not** help, because it derives a different pepper.

**Before Factory Reset — there is no shortcut:**
1. Decrypt **all** files that were bound to this key, while you still have it.
2. Re-encrypt them afterwards (under a new credential, or a recovery-capable
   backend like PIV / YubiKey-OnlyKey CR).

---

### Q: Can I share encrypted files with others?

**A:** Not with HSM-encrypted files. Each file is bound to **your specific security key**.

**Workaround:**
1. Decrypt file with your security key
2. Re-encrypt for recipient (without HSM, or with their key)

**For Sharing:** Use asymmetric encryption instead:
```bash
openssl_encrypt encrypt --for recipient@example.com file.txt
```

---

## Additional Resources

- **FIDO2 Specification:** https://fidoalliance.org/specs/
- **python-fido2 Library:** https://github.com/Yubico/python-fido2
- **OpenSSL Encrypt Documentation:** `openssl_encrypt/docs/`
- **Plugin Development Guide:** `openssl_encrypt/plugins/PLUGIN_DEVELOPMENT.md`

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/openssl_encrypt/issues
- Documentation: https://github.com/yourusername/openssl_encrypt/docs

---

*Last Updated: 2026-01-02*
*Plugin Version: 1.0.0*
