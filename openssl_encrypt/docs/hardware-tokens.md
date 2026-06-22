# Hardware Token Setup Guide

`openssl_encrypt` supports hardware-bound key derivation via HMAC-SHA1
Challenge-Response on two device families: **YubiKey** and **OnlyKey**. The
two backends produce identical output when loaded with the same 20-byte
secret, so a single fleet can mix devices freely.

> A third, signature-based backend is also available: the **PIV / PKCS#11**
> backend (`--hsm piv`) derives the pepper from a PIV private key on a
> PKCS#11 token (YubiKey Bio MPE, Token2 PIN+, any compliant PIV smart card)
> instead of HMAC-SHA1 CR. See [PIV / PKCS#11 backend](PIV_BACKEND.md) for setup.

This guide covers:

- [What hardware-bound CR provides](#what-hardware-bound-cr-provides)
- [YubiKey setup](#yubikey-setup)
- [OnlyKey setup](#onlykey-setup)
- [Fleet provisioning (same secret on multiple devices)](#fleet-provisioning)
- [Using the CLI](#using-the-cli)
- [Troubleshooting](#troubleshooting)

---

## What hardware-bound CR provides

When you encrypt with `--hsm <plugin>`, the tool:

1. Uses the file's salt as the **challenge** to the hardware token
2. Asks the token to compute `HMAC-SHA1(loaded_secret, challenge)`
3. Uses the 20-byte response as a **pepper** mixed into the KDF cascade
   (Argon2id, Balloon, scrypt, RandomX, …)

The pepper is never stored anywhere. Decryption requires the same secret on
the same (or an equivalent) hardware token. An attacker who steals the
encrypted file cannot brute-force it without physical access to the device.

Both plugins follow the same convention:

- Encryption: `openssl_encrypt encrypt --hsm <plugin> ...`
- Decryption: `openssl_encrypt decrypt --hsm <plugin> ...`
- Slot selection: `--hsm-slot N` (YubiKey: 1..2, OnlyKey: 1..12 accepted but
  only 1..2 verified on hardware; auto-detected if omitted)
- Plugin name in metadata is advisory — a file encrypted with
  `--hsm yubikey` can be decrypted with `--hsm onlykey` provided both
  devices hold the same 20-byte secret.

---

## YubiKey setup

### Requirements

- YubiKey 4, 5, or NEO with OTP applet enabled
- `yubikey-manager` (ykman) for configuration:
  `pip install yubikey-manager` or `pip install -r requirements-hsm.txt`

### Configure HMAC-SHA1 on slot 1 or 2

```bash
# Slot 1: requires touch every time (recommended for daily use)
ykman otp chalresp --touch 1

# Slot 2: no touch (recommended only for unattended scripting)
ykman otp chalresp 2

# Or load a specific 20-byte secret (hex) — for fleet provisioning
ykman otp chalresp --touch 1 1122334455667788991122334455667788991122
```

`ykman` prompts you to either generate a random key or supply one in hex.
For fleets, supply a hex key so you can load the same one onto every device.

### Verify the configuration

```bash
ykman otp chalresp 1 deadbeef
# Should print 20 bytes of hex (touch the YubiKey if required)
```

---

## OnlyKey setup

### Requirements

- OnlyKey (rev 2 or later) with HMAC-SHA1 Challenge-Response enabled
- The official OnlyKey App for slot configuration:
  https://docs.crp.to/quickstart
- `yubikey-manager` library (provides the yubikit OTP protocol that both
  backends share): `pip install -r requirements-hsm.txt`

> OnlyKey uses USB VID/PID `0x1d50:0x60fc`. The OnlyKey speaks the same
> HMAC-SHA1 wire protocol as the YubiKey — we just enumerate the
> different USB IDs. No separate Python package is needed.

### Enable Challenge-Response Mode

1. Open the OnlyKey App and enter your PIN on the device buttons
2. Go to **Preferences → HMAC Mode** and enable it
3. Select either **Slot 1 (HMAC1)** or **Slot 2 (HMAC2)** — these are the only
   slots verified on hardware; the plugin also accepts slots 3..12, but those
   are untested
4. Click **Configure HMAC** and load your 20-byte hex secret

### Verify the configuration

After loading a secret, you can test from the command line:

```bash
openssl_encrypt hsm onlykey-list
# Should report your OnlyKey device path

openssl_encrypt hsm onlykey-test --hsm-slot 1
# Performs a random-salt CR and prints the 20-byte response
# (If the OnlyKey is locked, enter your PIN on the device buttons.)
```

---

## Fleet provisioning

The deterministic-pepper property only works if **every device in the
fleet has the same 20-byte secret loaded**. Suggested workflow:

1. **Generate the secret once, offline.** Use a known-good RNG:

   ```bash
   openssl rand -hex 20
   # e.g. a1b2c3d4e5f6...  (40 hex chars = 20 bytes)
   ```

2. **Store the secret in a vault** (Bitwarden, 1Password, paper backup
   in a safe). You will need it to provision replacement devices later.

3. **Load it onto every YubiKey:**

   ```bash
   ykman otp chalresp --touch 1 <hex_secret>
   ```

4. **Load it onto every OnlyKey** via the OnlyKey App (same hex value).

5. **Verify cross-device determinism** before relying on it:

   ```bash
   # On YubiKey
   openssl_encrypt encrypt --hsm yubikey --hsm-slot 1 testfile testfile.enc
   # Unplug YubiKey, plug OnlyKey
   openssl_encrypt decrypt --hsm onlykey --hsm-slot 1 testfile.enc testfile.out
   diff testfile testfile.out  # should be identical
   ```

---

## Using the CLI

### Symmetric file encryption with HSM pepper

```bash
# YubiKey (auto-detects which slot is configured)
openssl_encrypt encrypt --hsm yubikey secret.txt secret.enc

# OnlyKey with explicit slot
openssl_encrypt encrypt --hsm onlykey --hsm-slot 2 secret.txt secret.enc

# Decryption — the device must hold the same secret used for encrypt
openssl_encrypt decrypt --hsm yubikey secret.enc secret.txt
openssl_encrypt decrypt --hsm onlykey secret.enc secret.txt
```

### Identity-protected private keys

The same hardware token can protect post-quantum private keys:

```bash
# Create identity with password + OnlyKey
openssl_encrypt identity create --name alice --hsm onlykey

# OnlyKey-only protection (no password)
openssl_encrypt identity create --name alice --hsm onlykey-only --hsm-slot 2

# Same options work for yubikey / yubikey-only
```

### Listing and testing devices

```bash
openssl_encrypt hsm onlykey-list           # enumerate connected OnlyKeys
openssl_encrypt hsm onlykey-test           # perform CR test with random salt
openssl_encrypt hsm fido2-list             # FIDO2 hmac-secret devices (separate)
```

---

## Troubleshooting

### "No OnlyKey device found"

- Confirm the device is plugged in: `lsusb | grep -i 1d50`
- Check udev rules permit non-root HID access (OnlyKey docs cover this:
  https://docs.crp.to/linux.html)
- Run `openssl_encrypt hsm onlykey-list` to see what the plugin sees

### "OnlyKey is locked. Enter your PIN on the OnlyKey buttons"

OnlyKey requires its PIN to be entered on the device's physical buttons
before any sensitive operation. The host-side CLI never receives or
transmits the PIN — enter it directly on the OnlyKey and retry.

### "No Challenge-Response slot configured"

The slot you specified (or auto-detect found none) does not have HMAC-SHA1
loaded. Re-run the device's setup tool (`ykman otp chalresp` or the
OnlyKey App) and load a secret.

### YubiKey worked, OnlyKey returns different pepper

The two devices hold different 20-byte secrets. They are deterministic
only when loaded with the **same** secret bytes. See
[Fleet provisioning](#fleet-provisioning) above.

### "Touch your YubiKey" prompt does not appear

The plugin writes touch prompts directly to `/dev/tty`, which survives
stdout/stderr redirection. If you're in an environment without a TTY
(systemd unit, CI runner), the touch step still happens — touch your
YubiKey blindly when the operation hangs. For unattended scripting,
configure the slot without touch (`ykman otp chalresp 2` — note: less
secure, no presence check).
