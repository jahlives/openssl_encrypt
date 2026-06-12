# OnlyKey HSM Plugin Setup Guide

## Overview

The OnlyKey HSM plugin provides hardware-bound key derivation using OnlyKey's
HMAC-SHA1 Challenge-Response mode. OnlyKey speaks the same HMAC-SHA1 wire
protocol as YubiKey — only the USB VID/PID differs (`1d50:60fc` vs Yubico's
`1050`) — so the plugin reuses the same `yubikit` OTP machinery.

Because the protocol is identical, OnlyKey and YubiKey devices loaded with the
**same 20-byte secret** produce identical responses for identical challenges.
Files encrypted with one device can be decrypted with the other (see
[Cross-Device Compatibility](#cross-device-compatibility-with-yubikey)).

## Requirements

1. **Hardware**: OnlyKey with an HMAC-SHA1 Challenge-Response slot configured
   in **button-press** (or no-user-presence) mode — *not* challenge-code mode
2. **Software**: `yubikey-manager` Python library (provides `yubikit`)
3. **Permissions**: HID device access (see below)

## Installation

### 1. Install yubikey-manager

```bash
pip install -r requirements-hsm.txt
```

Or directly:
```bash
pip install yubikey-manager
```

No OnlyKey-specific Python package is needed — the plugin enumerates OnlyKey
devices itself and drives them over the YubiKey OTP protocol.

### 2. Configure OnlyKey Challenge-Response

Use the official [OnlyKey App](https://onlykey.io/pages/download) to load an
HMAC-SHA1 Challenge-Response secret:

1. Unlock the OnlyKey with your PIN.
2. In the OnlyKey App, open the Challenge-Response / Yubico OTP configuration.
3. Load a 20-byte HMAC-SHA1 secret into slot 1 or slot 2.
4. Set the slot's user-presence mode to **button press** (or none).

**⚠️ Challenge-code mode is not supported.** If the slot is configured to
require a 3-digit challenge code typed on the OnlyKey, the device rejects
challenges sent over the raw YubiKey wire protocol (only OnlyKey-aware host
applications can display the code). The plugin reports this as
*"OnlyKey rejected the challenge on slot N"*.

**Note on slots:** the OnlyKey hardware advertises many slots, but the YubiKey
wire protocol used by this plugin only defines two Challenge-Response slot
command codes. Use slot 1 or slot 2.

### 3. Set up HID Permissions

The OnlyKey hidraw node must be accessible to your user.

**For Debian/Ubuntu (uses `plugdev` group):**

```bash
# Create udev rules file
sudo tee /etc/udev/rules.d/49-onlykey.rules << 'EOF'
# OnlyKey (VID 1d50, PID 60fc)
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="60fc", MODE="0660", GROUP="plugdev", TAG+="uaccess"
EOF

# Add your user to plugdev group
sudo usermod -a -G plugdev $USER

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Unplug and replug your OnlyKey
# Log out and log back in for group changes to take effect
```

**For Fedora/RHEL/CentOS (uses systemd ACLs):**

```bash
sudo tee /etc/udev/rules.d/49-onlykey.rules << 'EOF'
# OnlyKey udev rules for Fedora/RHEL (systemd ACLs)
ACTION=="add|change", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="60fc", TAG+="uaccess"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger

# Unplug and replug your OnlyKey
# No need to log out - systemd ACLs apply immediately
```

The official OnlyKey udev rules from
[docs.onlykey.io](https://docs.onlykey.io) also work and cover additional
OnlyKey interfaces.

## Usage

### The Three-Step Hardware Flow

Every OnlyKey operation follows this sequence:

1. **Unlock first**: plug in the OnlyKey and enter your PIN on its buttons.
   The LED turns solid green. A locked OnlyKey rejects all challenges.
2. **Run the command** (see below).
3. **Touch to approve**: when the OnlyKey blinks, press the button. The
   response is computed and the operation completes.

### Encrypt with OnlyKey HSM

```bash
# Auto-detect Challenge-Response slot
openssl-encrypt encrypt --hsm onlykey -i input.txt -o output.enc

# Specify slot explicitly
openssl-encrypt encrypt --hsm onlykey --hsm-slot 1 -i input.txt -o output.enc
```

### Decrypt with OnlyKey HSM

```bash
# Slot is stored in metadata, used automatically on decrypt
openssl-encrypt decrypt --hsm onlykey -i output.enc -o decrypted.txt

# Or override the slot explicitly (takes precedence over metadata)
openssl-encrypt decrypt --hsm onlykey --hsm-slot 1 -i output.enc -o decrypted.txt
```

## Cross-Device Compatibility with YubiKey

`yubikey_hsm` and `onlykey_hsm` form a compatibility family: a file encrypted
with one may be decrypted with the other by passing `--hsm` explicitly,
provided both devices hold the **same 20-byte HMAC-SHA1 secret**. HMAC-SHA1 is
fully specified by RFC 2104, so identical secrets yield identical peppers.

```bash
# File was encrypted with a YubiKey (slot 2); decrypt with an OnlyKey
# that has the same secret in its slot 1:
openssl-encrypt decrypt --hsm onlykey --hsm-slot 1 -i file.enc -o file.txt

# And the reverse direction works the same way:
openssl-encrypt decrypt --hsm yubikey --hsm-slot 2 -i onlykey-file.enc -o file.txt
```

Notes:

- The slot override matters whenever the secret lives in different slot
  numbers on the two devices — `--hsm-slot` takes precedence over the slot
  recorded in the file's metadata.
- Without an explicit `--hsm`, decryption auto-loads the plugin recorded in
  the file metadata, as before.
- Provisioning: generate the secret once (e.g.
  `ykman otp chalresp --generate 2` prints it, or generate 20 random bytes
  yourself) and load the identical hex value on every fleet device. A secret
  generated *on-device* cannot be extracted and therefore cannot be shared.
- A device with a *different* secret produces a wrong pepper and decryption
  fails cleanly at authentication — no weaker result.

## Testing

### Test OnlyKey Access

```bash
# Verify the device node is visible and readable
ls -l /dev/hidraw*
for d in /sys/class/hidraw/hidraw*; do
  grep -H . "$d/device/uevent" | grep -i 1d50 && echo "OnlyKey: ${d##*/}"
done
```

### Round-Trip Test

```bash
echo "onlykey test" > /tmp/ok-test.txt
openssl-encrypt encrypt --hsm onlykey --hsm-slot 1 -i /tmp/ok-test.txt -o /tmp/ok-test.enc
openssl-encrypt decrypt --hsm onlykey --hsm-slot 1 -i /tmp/ok-test.enc -o /tmp/ok-test.dec
diff /tmp/ok-test.txt /tmp/ok-test.dec && echo "OK"

# The real security property: unplug the OnlyKey and confirm decryption fails.
```

## Troubleshooting

Run with `--debug` to see the underlying error instead of the generic
*"Security key derivation failed"*.

### Error: "No OnlyKey device found"

- udev rule missing or not applied — see
  [Set up HID Permissions](#3-set-up-hid-permissions); unplug/replug after
  installing the rule.
- Quick check: if the command works under `sudo`, it is a permissions issue.
- Note: device enumeration silently skips hidraw nodes it cannot open, so a
  permissions problem looks identical to an absent device.

### Error: "OnlyKey rejected the challenge on slot N"

The device returned to idle without computing a response and without
requesting a button press. Causes:

- The slot has no HMAC-SHA1 secret loaded (OnlyKey ships a factory random
  secret in slot 2 only).
- The slot is in **challenge-code mode**, which cannot be served over the
  YubiKey wire protocol — switch it to button-press mode in the OnlyKey App.

### Error: "OnlyKey is locked"

Enter your PIN on the OnlyKey buttons (LED turns solid green), then retry.
The unlock is never part of the challenge-response exchange — it must happen
before the command runs.

### Error: "Timed out waiting for touch"

The slot requires a button press and none arrived within the wait window
(~15 s). Re-run the command and press the OnlyKey button when it blinks.

### Error: "... is not a valid PID"

Fixed in current versions: the plugin masquerades as an OTP-only YubiKey when
constructing the device handle, because the OnlyKey's USB product ID is not in
yubikit's PID enum. If you see this, update openssl_encrypt.

## Security Considerations

### Benefits

- The HSM pepper is derived fresh from the device on every operation and is
  **never stored** — decryption requires physical possession of a fleet device.
- Button-press mode adds user-presence verification per operation.

### Limitations

- HMAC-SHA1 challenge-response is the protocol the hardware offers; its
  security here rests on HMAC (not on SHA-1 collision resistance), consistent
  with RFC 2104 usage.
- If **all** devices holding the secret are lost and the secret was never
  recorded, the encrypted data is unrecoverable.

### Best Practices

- Provision the same secret on at least two devices (e.g. one YubiKey, one
  OnlyKey) and store the hex secret itself in a sealed offline backup.
- Use button-press mode rather than no-user-presence mode.
- Test decryption with every fleet device after provisioning, before trusting
  it with real data.

## Architecture

### How It Works

1. The encryption salt (16 bytes) is sent to the OnlyKey as an HMAC-SHA1
   challenge on the chosen slot.
2. The device computes HMAC-SHA1(secret, challenge) after button approval.
3. The 20-byte response becomes the `hsm_pepper`, which is mixed with the
   password and salt during key derivation.
4. On decryption the same salt yields the same pepper — but only with a
   device holding the same secret.

### Implementation Notes

- Device enumeration uses ykman's per-platform HID primitives, filtered to
  OnlyKey's VID/PID (`1d50:60fc`).
- The device handle masquerades as an OTP-only YubiKey (`PID.YKS_OTP`)
  because yubikit's PID enum contains only Yubico product IDs; yubikit uses
  the PID solely for USB interface bookkeeping, and the OTP protocol version
  is read from the device status (OnlyKey reports its YubiKey emulation as
  v2.2.3).

## See Also

- [Yubikey Setup](YUBIKEY_SETUP.md) - YubiKey variant of the same plugin family
- [HSM Plugin Guide](HSM_PLUGIN_GUIDE.md) - Full HSM plugin system documentation
- [OnlyKey Documentation](https://docs.onlykey.io/) - Official OnlyKey docs
