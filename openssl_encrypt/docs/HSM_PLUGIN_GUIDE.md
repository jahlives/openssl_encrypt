# HSM Plugin Guide

## Overview

HSM (Hardware Security Module) plugins enhance encryption security by adding a hardware-bound pepper value to the key derivation process. The pepper is derived from the hardware device and is never stored in the encrypted file, requiring the physical device to be present for both encryption and decryption.

## Security Model

### Hardware-Bound Encryption

When you use an HSM plugin:

1. **Encryption Process**:
   - A random 16-byte salt is generated
   - The salt is sent to the HSM device as a "challenge"
   - The HSM device computes a cryptographic response (pepper)
   - The final key is derived from: `password + salt + hsm_pepper`
   - Only the salt is stored in the file metadata (NOT the pepper)

2. **Decryption Process**:
   - The salt is read from the file metadata
   - The same HSM device must be present
   - The salt is sent as a challenge to the HSM
   - The HSM returns the same pepper (deterministic)
   - The key is re-derived using the same formula

3. **Security Benefits**:
   - **Hardware binding**: Files can only be decrypted with the specific HSM device
   - **No pepper storage**: The pepper value is never written to disk
   - **Two-factor security**: Requires both password AND hardware device
   - **Tamper resistance**: HSM devices protect cryptographic operations

## Yubikey Challenge-Response

### Prerequisites

1. **Yubikey Device**:
   - Yubikey 4, 5, or newer
   - Challenge-Response mode configured on slot 1 or 2

2. **Configure Challenge-Response**:
   ```bash
   # Install Yubikey Manager (if not already installed)
   pip install yubikey-manager

   # Configure Challenge-Response on slot 2 (recommended)
   ykman otp chalresp --generate 2
   ```

   Note: Slot 1 is typically used for OTP, so slot 2 is recommended for Challenge-Response.

3. **Install HSM Dependencies**:
   ```bash
   pip install -r requirements-hsm.txt
   ```

### Basic Usage

**Encryption with Auto-Detection**:
```bash
openssl-encrypt encrypt --hsm yubikey input.txt output.enc
```
The plugin will automatically detect which slot (1 or 2) has Challenge-Response configured.

**Encryption with Manual Slot**:
```bash
openssl-encrypt encrypt --hsm yubikey --hsm-slot 2 input.txt output.enc
```

**Decryption**:
```bash
openssl-encrypt decrypt --hsm yubikey output.enc input.txt
```
The same Yubikey must be present for decryption.

### Advanced Usage

**With Custom Hash Configuration**:
```bash
openssl-encrypt encrypt --hsm yubikey \
  --argon2 --argon2-time 4 --argon2-memory 1048576 \
  --sha512 100 --blake3 50 \
  input.txt output.enc
```

**With Post-Quantum Encryption**:
```bash
openssl-encrypt encrypt --hsm yubikey \
  --algorithm ml-kem-768-hybrid \
  input.txt output.enc
```

### How It Works

1. **Challenge-Response Protocol**:
   - Uses HMAC-SHA1 internally
   - Salt (16 bytes) → Challenge
   - HMAC-SHA1 Response (20 bytes) → hsm_pepper
   - Deterministic: Same challenge always produces same response

2. **Slot Detection**:
   - Scans slot 1 and slot 2
   - Uses first slot with Challenge-Response configured
   - Caches detected slot for subsequent operations

3. **Metadata Storage**:
   - Stores: HSM plugin name ("yubikey_hsm")
   - Stores: Slot number (if manually specified)
   - Does NOT store: The pepper value itself

## Error Handling

### Common Errors and Solutions

**Error: "No Yubikey device found"**
- Solution: Plug in your Yubikey
- Check: `ykman list` to verify device is detected

**Error: "No Yubikey with Challenge-Response found"**
- Solution: Configure Challenge-Response on your Yubikey
- Command: `ykman otp chalresp --generate 2`

**Error: "File was encrypted with HSM plugin 'yubikey_hsm' but no HSM plugin provided"**
- Solution: Add `--hsm yubikey` when decrypting
- Example: `openssl-encrypt decrypt --hsm yubikey file.enc file.txt`

**Error: "HSM pepper derivation failed"**
- Possible causes:
  - Wrong Yubikey (different device than used for encryption)
  - Yubikey slot was reprogrammed
  - Hardware communication error
- Solution: Use the original Yubikey that was used for encryption

### Security Warnings

**CRITICAL**: If you lose or reprogram your Yubikey, you will permanently lose access to files encrypted with it. There is no recovery mechanism.

**Recommendations**:
1. Keep a backup Yubikey programmed with the same secret
2. Document which Yubikey was used for which files
3. Test decryption immediately after encryption
4. Consider using `--hsm-slot` to specify and document the slot used

## Security Considerations

### Threat Model

**Protects Against**:
- Password-only attacks (attacker needs both password AND Yubikey)
- Remote attacks (physical device required)
- Password database breaches (pepper not stored)
- Insider threats (requires physical access to specific device)

**Does NOT Protect Against**:
- Physical theft of both encrypted file AND Yubikey
- Malware running on the system during encryption/decryption
- Side-channel attacks on the Yubikey device
- Quantum computing attacks (use PQC algorithms for that)

### Best Practices

1. **Slot Management**:
   - Use slot 2 for Challenge-Response (slot 1 typically for OTP)
   - Document which slot is used
   - Never reprogram slots that protect important files

2. **Backup Strategy**:
   - Program a backup Yubikey with identical secrets
   - Store backup Yubikey in a secure location
   - Test backup Yubikey regularly

3. **Key Ceremony**:
   - When setting up Challenge-Response, record:
     - Which Yubikey serial number was used
     - Which slot was programmed
     - Date and purpose of configuration
   - Store this information securely

4. **Operational Security**:
   - Don't leave Yubikey plugged in when not needed
   - Use strong passwords (HSM adds defense in depth, not a replacement)
   - Combine with strong KDF settings (Argon2, Scrypt)

## Future HSM Support

The HSM plugin system is designed to be extensible. Future support planned for:

- **TPM 2.0**: Hardware-bound encryption using Trusted Platform Module
- **Smart Cards**: Challenge-Response via PC/SC interface
- **Hardware Tokens**: PKCS#11 compatible devices
- **Cloud HSM**: AWS CloudHSM, Azure Key Vault (with appropriate warnings)

## Custom HSM Plugin Development

To develop a custom HSM plugin:

1. **Create Plugin Class**:
   ```python
   from openssl_encrypt.modules.plugin_system import HSMPlugin, PluginResult

   class CustomHSMPlugin(HSMPlugin):
       def __init__(self):
           super().__init__(
               plugin_id="custom_hsm",
               name="Custom HSM Plugin",
               version="1.0.0"
           )

       def get_hsm_pepper(self, salt, context):
           # Implement hardware Challenge-Response
           pepper = your_hardware_function(salt)
           return PluginResult.success_result(
               "Success",
               data={'hsm_pepper': pepper}
           )
   ```

2. **Requirements**:
   - `get_hsm_pepper()` must be deterministic
   - Same salt must always return same pepper
   - Pepper should be 16-32 bytes (cryptographically strong)
   - Use secure hardware communication
   - Never log or expose pepper values

3. **Testing**:
   - Test encryption and decryption
   - Verify determinism (multiple calls with same salt)
   - Test error handling (device not present)
   - Document device requirements

## Troubleshooting

### Verbose Mode

Use `--verbose` for detailed HSM plugin information:
```bash
openssl-encrypt encrypt --hsm yubikey --verbose input.txt output.enc
```

### Debug Mode

Use `--debug` for low-level debugging:
```bash
openssl-encrypt encrypt --hsm yubikey --debug input.txt output.enc
```

### Verify Yubikey Configuration

```bash
# List all connected Yubikey devices
ykman list

# Show Yubikey info
ykman info

# Check OTP configuration (includes Challenge-Response)
ykman otp info
```

## FAQ

**Q: Can I use multiple Yubikeys?**
A: Each file is bound to the specific Yubikey used during encryption. You can program multiple Yubikeys with the same secret for redundancy.

**Q: What happens if I lose my Yubikey?**
A: If you have a backup Yubikey with the same secret, you can decrypt. Otherwise, the files are permanently inaccessible.

**Q: Can I disable HSM after encryption?**
A: No. Once encrypted with HSM, the Yubikey is required for decryption. There is no "downgrade" option.

**Q: Does this work with Yubikey Bio?**
A: Yes, if Challenge-Response is configured on the Yubikey Bio.

**Q: Can I use this with automated scripts?**
A: Yes, but the Yubikey must be physically present. This is intentional for security.

**Q: Is this compatible with FIPS mode?**
A: The plugin itself is compatible, but ensure your Yubikey is a FIPS-certified model if FIPS compliance is required.

## Additional Resources

- [Yubikey Manager CLI Documentation](https://docs.yubico.com/software/yubikey/tools/ykman/)
- [Yubikey Challenge-Response Guide](https://developers.yubico.com/OTP/OTPs_Explained.html)
- [OpenSSL Encrypt Documentation](../README.md)
