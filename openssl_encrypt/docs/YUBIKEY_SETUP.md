# Yubikey HSM Plugin Setup Guide

## Overview

The Yubikey HSM plugin provides hardware-bound key derivation using Yubikey Challenge-Response (HMAC-SHA1). This requires proper system configuration for HID device access.

## Requirements

1. **Hardware**: Yubikey with Challenge-Response configured
2. **Software**: `yubikey-manager` Python library
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

### 2. Configure Yubikey Challenge-Response

If you haven't configured Challenge-Response on your Yubikey yet:

```bash
# Configure Challenge-Response on slot 2 with generated secret
ykman otp chalresp --generate 2

# Or on slot 1
ykman otp chalresp --generate 1
```

**Important:** Remember which slot you configured - you'll need to specify it when encrypting/decrypting (or use auto-detect).

### 3. Set up HID Permissions

The Yubikey OTP interface requires HID access. You have two options:

#### Option A: udev Rules (Recommended)

Create a udev rule to allow your user to access Yubikey HID devices.

**For Debian/Ubuntu (uses `plugdev` group):**

```bash
# Create udev rules file
sudo tee /etc/udev/rules.d/70-yubikey.rules << 'EOF'
# Yubikey 4/5 USB
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", MODE="0660", GROUP="plugdev", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="1050", MODE="0660", GROUP="plugdev", TAG+="uaccess"

# Yubikey NEO
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", ATTRS{idProduct}=="0010|0110|0111|0114|0116|0401|0403|0405|0407|0410", MODE="0660", GROUP="plugdev", TAG+="uaccess"
EOF

# Add your user to plugdev group
sudo usermod -a -G plugdev $USER

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Unplug and replug your Yubikey
# Log out and log back in for group changes to take effect
```

**For Fedora/RHEL/CentOS (uses systemd ACLs):**

```bash
# Create udev rules file
sudo tee /etc/udev/rules.d/70-yubikey.rules << 'EOF'
# Yubikey udev rules for Fedora/RHEL
# This allows non-root access to Yubikey devices via systemd ACLs

# Yubikey 4/5 series
ACTION=="add|change", SUBSYSTEM=="usb", ATTRS{idVendor}=="1050", TAG+="uaccess"
ACTION=="add|change", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"

# Yubikey NEO, 4, 5 - HID OTP interface (for Challenge-Response)
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"
EOF

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Unplug and replug your Yubikey
# No need to log out - systemd ACLs apply immediately
```

#### Option B: Run with sudo (Not Recommended)

You can run commands requiring Yubikey access with `sudo`:

```bash
sudo openssl-encrypt --hsm yubikey input.txt output.enc
```

**Warning:** Running encryption tools as root is not recommended for security reasons.

## Usage

### Encrypt with Yubikey HSM

```bash
# Auto-detect Challenge-Response slot
openssl-encrypt --hsm yubikey input.txt output.enc

# Specify slot explicitly
openssl-encrypt --hsm yubikey --hsm-slot 2 input.txt output.enc
```

### Decrypt with Yubikey HSM

```bash
# Slot is stored in metadata, auto-detected on decrypt
openssl-encrypt -d --hsm yubikey output.enc decrypted.txt

# Or specify slot explicitly
openssl-encrypt -d --hsm yubikey --hsm-slot 2 output.enc decrypted.txt
```

### Touch Prompt

If your Yubikey has "touch required" enabled for Challenge-Response:
1. The tool will display: **👆 Touch your Yubikey now**
2. Touch the metal contact on your Yubikey
3. The operation will complete

## Testing

### Test Yubikey Access

Run the diagnostic script:

```bash
python3 test_yubikey_direct.py
```

This will check:
- ykman installation
- Device detection
- Connection types (SmartCard, OTP)
- Challenge-Response functionality

### Run Integration Tests

```bash
# Skip by default (requires hardware)
pytest tests/test_hsm_plugin.py -v

# Run Yubikey hardware tests explicitly
pytest tests/test_hsm_plugin.py::TestRealYubikey -v -s
```

**Note:** You may need sudo if HID permissions are not configured:
```bash
sudo pytest tests/test_hsm_plugin.py::TestRealYubikey -v -s
```

## Troubleshooting

### Error: "OtpConnection not supported"

**Cause:** Insufficient HID permissions

**Solution:** Set up udev rules (see Option A above) or run with sudo

### Error: "No Yubikey device found"

**Cause:** Yubikey not connected or not recognized

**Solution:**
1. Ensure Yubikey is plugged in
2. Check with `ykman info`
3. Try unplugging and replugging

### Error: "No Yubikey with Challenge-Response found"

**Cause:** Challenge-Response not configured on any slot, or wrong slot specified

**Solution:**
1. Check configuration: `sudo ykman otp info`
2. Configure Challenge-Response: `ykman otp chalresp --generate 2`
3. If configured on slot 1, use `--hsm-slot 1`

### Error: "Touch timeout"

**Cause:** Yubikey requires touch but you didn't touch it in time

**Solution:** Run the command again and touch your Yubikey when prompted

## Security Considerations

### Benefits

- **Hardware-bound encryption**: Files encrypted with Yubikey HSM require the physical Yubikey for decryption
- **Pepper never stored**: The hsm_pepper is derived from hardware and never saved to disk
- **Deterministic**: Same salt always produces same pepper (required for decryption)

### Limitations

- **Same Yubikey required**: You must use the same physical Yubikey that encrypted the file
- **Slot matters**: The same slot must be used (stored in file metadata)
- **Secret cannot be backed up**: The Yubikey's Challenge-Response secret cannot be extracted

### Best Practices

1. **Backup Yubikey**: Consider a backup Yubikey programmed with the same secret
2. **Document slot usage**: Remember which slot you use for which purpose
3. **Test decryption**: Always test decryption immediately after encryption
4. **Keep Yubikey safe**: Loss of Yubikey = loss of access to encrypted files

## Architecture

### How It Works

1. **Encryption**:
   - Generate random 16-byte salt
   - Send salt to Yubikey as challenge
   - Receive 20-byte HMAC-SHA1 response (hsm_pepper)
   - Combine: `password + salt + hsm_pepper` → KDF → encryption key
   - Store only plugin name and slot in metadata (NOT the pepper)

2. **Decryption**:
   - Read salt and slot from metadata
   - Send salt to Yubikey as challenge (same slot)
   - Receive same 20-byte hsm_pepper
   - Combine: `password + salt + hsm_pepper` → KDF → decryption key

### Why HMAC-SHA1?

Yubikey Challenge-Response uses HMAC-SHA1, which produces 20-byte outputs. While SHA-1 is deprecated for digital signatures, HMAC-SHA1 is still considered secure for this use case (key derivation).

## API Version Compatibility

The plugin supports both older and newer yubikey-manager APIs:
- Handles `list_all_devices()` return value changes
- Supports tuple format `(device, device_info)`
- Uses OtpConnection for HID access

Tested with:
- yubikey-manager >= 5.0.0
- Yubikey 5 series (firmware 5.2.4+)

## See Also

- [HSM Plugin Guide](HSM_PLUGIN_GUIDE.md) - Full HSM plugin system documentation
- [Yubikey Manager Documentation](https://docs.yubico.com/software/yubikey/tools/ykman/)
- [Yubikey Challenge-Response](https://developers.yubico.com/yubico-c/Manuals/ykpersonalize.1.html)
