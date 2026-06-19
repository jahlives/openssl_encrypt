# Migrating from a YubiKey-only setup to a mixed YubiKey + OnlyKey fleet

This guide is for existing `openssl_encrypt` users who today protect files
or identities with `--hsm yubikey` and want to add OnlyKey devices to
their fleet without breaking any existing encrypted data.

**TL;DR:** The cryptographic operation is identical between the two
backends. As long as your OnlyKey is loaded with the same 20-byte
HMAC-SHA1 secret as your YubiKey, every file and identity you already
have continues to decrypt — with `--hsm yubikey` *or* `--hsm onlykey`.

---

## Before you start

You will need:

- All YubiKeys in your fleet, present, and you know which slot
  (1 or 2) is configured for HMAC-SHA1 Challenge-Response
- Either a record of the 20-byte hex secret loaded onto them, OR
  willingness to provision a fresh secret on every device (which
  invalidates any in-flight files that were encrypted with the old
  secret — see "If you don't have the original secret" below)
- One or more OnlyKey devices, unlocked (PIN entered on device buttons)
- The OnlyKey App (https://docs.crp.to/quickstart) for slot configuration
- `openssl_encrypt` v1.4.4 or later (this is the release that adds
  OnlyKey support)

---

## Migration scenarios

### Scenario A: You have the original 20-byte secret

This is the easy path.

1. **Provision the OnlyKey:**

   - Open the OnlyKey App, enter PIN on device buttons
   - Preferences → HMAC Mode → enable
   - Choose a slot (1..12) and click "Configure HMAC"
   - Paste the same 20-byte hex secret your YubiKey already holds

2. **Verify cross-device determinism with a throwaway file:**

   ```bash
   echo "test" > test.txt

   # Encrypt with YubiKey
   openssl_encrypt encrypt --hsm yubikey --hsm-slot 1 test.txt test.enc

   # Unplug YubiKey, plug OnlyKey
   openssl_encrypt decrypt --hsm onlykey --hsm-slot 1 test.enc test.out

   diff test.txt test.out   # must be identical
   ```

   If `diff` reports differences, the secrets don't match — see
   [Troubleshooting](#troubleshooting) below.

3. **You're done.** Existing encrypted files and identities work with
   either backend interchangeably. New encryptions can use whichever
   flag you prefer.

### Scenario B: You don't have the original 20-byte secret

If the secret was generated randomly by `ykman` and never recorded,
the OnlyKey cannot be loaded with the same value — they will produce
different peppers, and any file encrypted with the YubiKey will not
decrypt on the OnlyKey.

**You have two options:**

#### Option B1: Re-encrypt with a new shared secret

This requires temporarily decrypting every file/identity with the old
YubiKey, then re-encrypting with the new shared secret loaded on both
devices. Disruptive but clean.

1. Generate a new 20-byte secret and save it securely:

   ```bash
   openssl rand -hex 20 | tee ~/Documents/hsm-secret.hex
   # Move this file to a vault — paper backup, password manager, etc.
   ```

2. Decrypt all existing files with the old YubiKey:

   ```bash
   for f in *.enc; do
     openssl_encrypt decrypt --hsm yubikey "$f" "${f%.enc}.plain"
   done
   ```

3. Re-provision the YubiKey with the new secret:

   ```bash
   ykman otp chalresp --touch 1 $(cat ~/Documents/hsm-secret.hex)
   ```

4. Provision the OnlyKey with the same new secret via the OnlyKey App.

5. Re-encrypt with the new secret:

   ```bash
   for f in *.plain; do
     openssl_encrypt encrypt --hsm yubikey "$f" "${f}.enc"
     shred -u "$f"   # securely remove plaintext
   done
   ```

6. Run the verification step from Scenario A.

#### Option B2: Keep YubiKey-only files, OnlyKey for new files

Keep the YubiKey for legacy files; use OnlyKey (loaded with a separate
new secret) for all new encryptions. Both work independently.

This avoids the re-encryption disruption but means you must always
remember which device decrypts which file.

---

## Identity migration

Existing identities protected with `--hsm yubikey` or `--hsm yubikey-only`
will continue to work with the YubiKey — that's untouched. To create
**new** identities that are unlocked by either device family, choose the
appropriate flag at creation time:

```bash
# Password + OnlyKey
openssl_encrypt identity create --name new-alice --hsm onlykey

# OnlyKey only (no password)
openssl_encrypt identity create --name new-alice --hsm onlykey-only --hsm-slot 1
```

**Note:** Each identity is locked to one HSM type at creation time
(the `hsm_type` is stored in the identity's protection config). You
cannot decrypt a `yubikey`-protected identity with an OnlyKey *unless*
the OnlyKey is loaded with the same secret AND you re-create the
identity. The encrypt-side file path is interchangeable; the
identity-side is type-locked because the metadata's `hsm_type` field
drives plugin selection on unlock.

---

## Troubleshooting

### Verification step produces different ciphertext

The two devices have different 20-byte secrets. Possible causes:

- Hex typo when loading the OnlyKey App field — re-paste and try again
- Endianness assumption — secrets are exchanged as plain hex, no byte
  reversal needed
- One device was previously configured with a different secret you've
  forgotten about — wipe its slot and reload from the canonical hex

### YubiKey decrypts but OnlyKey reports "No OnlyKey device found"

Check `lsusb | grep -i 1d50` shows the device. If it does but
`openssl_encrypt hsm onlykey-list` returns empty, your user lacks HID
access — install OnlyKey's udev rules (see https://docs.crp.to/linux.html).

### "OnlyKey is locked. Enter your PIN on the OnlyKey buttons"

Normal behavior — the OnlyKey PIN is entered on the device, not the
host. Enter it on the physical buttons and rerun the command.

### My existing files still work with `--hsm yubikey` after upgrading

Yes, that's intentional. Adding OnlyKey support did not change any
YubiKey behavior. If something stopped working, please file an issue.
