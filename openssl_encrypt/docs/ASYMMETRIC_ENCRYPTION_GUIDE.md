# Asymmetric Encryption Guide

## Overview

openssl_encrypt now supports **post-quantum asymmetric encryption** using identity-based cryptography. This allows you to encrypt files for specific recipients using their public keys, with the added security of post-quantum algorithms.

### Key Features

- **Post-Quantum Security**: Uses NIST-standardized ML-KEM-768 for key encapsulation and ML-DSA-65 for digital signatures
- **Multiple Recipients**: Encrypt once for multiple recipients
- **Identity Management**: Simple CLI for managing identities and contacts
- **Defense in Depth**: Combines asymmetric key exchange with the existing KDF chain
- **DoS Protection**: Fast signature verification before expensive key derivation
- **Format Version 7**: New metadata format specifically for asymmetric mode

## Quick Start

### 1. Create Identities

First, create identities for yourself and your contacts:

```bash
# Create your own identity
openssl_encrypt identity create --name Alice --email alice@example.com

# Create another identity (e.g., for a colleague)
openssl_encrypt identity create --name Bob --email bob@example.com
```

You'll be prompted to enter a passphrase to protect the private keys.

### 2. List Your Identities

```bash
openssl_encrypt identity list
```

This shows all identities (both your own with private keys and contacts with public keys only).

### 3. Encrypt for a Recipient

```bash
openssl_encrypt encrypt --input secret.txt --for Bob --sign-with Alice
```

This will:
- Encrypt `secret.txt` for Bob (only Bob can decrypt)
- Sign with Alice's private key (proving it came from Alice)
- Prompt for Alice's passphrase
- Create `secret.txt.enc`

### 4. Decrypt a File

```bash
openssl_encrypt decrypt --input secret.txt.enc --key Bob --verify-from Alice
```

This will:
- Decrypt using Bob's private key
- Verify the signature from Alice
- Prompt for Bob's passphrase
- Create the decrypted file

## Identity Management

### Creating Identities

```bash
# Basic identity
openssl_encrypt identity create --name YourName --email your@email.com

# With custom algorithms
openssl_encrypt identity create --name YourName \
    --kem-algorithm ML-KEM-1024 \
    --sig-algorithm ML-DSA-87
```

**Available KEM algorithms:**
- `ML-KEM-512` (NIST Security Level 1)
- `ML-KEM-768` (NIST Security Level 3, default)
- `ML-KEM-1024` (NIST Security Level 5)

**Available Signature algorithms:**
- `ML-DSA-44` (NIST Security Level 2)
- `ML-DSA-65` (NIST Security Level 3, default)
- `ML-DSA-87` (NIST Security Level 5)

### Viewing Identity Details

```bash
openssl_encrypt identity show Alice
```

### Exporting Public Keys

To share your public key with others:

```bash
openssl_encrypt identity export --identity Alice --output alice_public.json
```

Send `alice_public.json` to your contacts (via email, secure messaging, etc.).

### Importing Public Keys

When you receive someone's public key:

```bash
openssl_encrypt identity import --file bob_public.json
```

This adds Bob as a contact (public keys only).

### Deleting Identities

```bash
# With confirmation prompt
openssl_encrypt identity delete Alice

# Skip confirmation
openssl_encrypt identity delete Alice --force
```

### Changing Passphrases

```bash
openssl_encrypt identity change-password Alice
```

## Advanced Usage

### Multiple Recipients

Encrypt for multiple recipients (all can decrypt):

```bash
openssl_encrypt encrypt --input secret.txt \
    --for Bob \
    --for Charlie \
    --for Diana \
    --sign-with Alice
```

Each recipient can independently decrypt the file with their own private key.

### Custom Hash Configuration

Use stronger key derivation:

```bash
openssl_encrypt encrypt --input secret.txt \
    --for Bob \
    --sign-with Alice \
    --sha512-rounds 10 \
    --blake2b-rounds 5 \
    --pbkdf2-iterations 200000
```

### Skip Signature Verification (Not Recommended)

```bash
openssl_encrypt decrypt --input secret.txt.enc \
    --key Bob \
    --no-verify
```

**Warning**: Only use `--no-verify` if you absolutely trust the source!

### Automatic Sender Discovery

If the sender's public key is in your identity store:

```bash
openssl_encrypt decrypt --input secret.txt.enc --key Bob
```

The tool will automatically find and verify Alice's signature if Alice is in your contacts.

## Security Considerations

### Identity Storage

Identities are stored in `~/.openssl_encrypt/identities/`:

```
~/.openssl_encrypt/identities/
├── alice/
│   ├── identity.json          (public metadata)
│   ├── encryption_public.pem  (ML-KEM public key)
│   ├── encryption_private.pem (ML-KEM private key, encrypted)
│   ├── signing_public.pem     (ML-DSA public key)
│   └── signing_private.pem    (ML-DSA private key, encrypted)
└── contacts/
    └── bob_public.json        (Bob's public keys only)
```

**Private keys are encrypted at rest** using Argon2id with your passphrase.

### Passphrase Requirements

- Minimum 8 characters
- Strong passphrases recommended (20+ characters, mixed case, numbers, symbols)
- Use a password manager to generate and store passphrases

### Trust Model

This system uses a **Trust-On-First-Use (TOFU)** model:

1. You receive someone's public key
2. You import it into your identity store
3. You trust that this public key belongs to the claimed person

**Important**: Verify fingerprints out-of-band (phone call, video chat, etc.):

```bash
openssl_encrypt identity show Bob
```

Compare the fingerprint with the one Bob tells you directly.

### Signature Verification

Always verify signatures when decrypting:

```bash
# Good - verifies signature
openssl_encrypt decrypt --input file.enc --key Bob --verify-from Alice

# Dangerous - skips verification
openssl_encrypt decrypt --input file.enc --key Bob --no-verify
```

Signature verification ensures:
1. The file was encrypted by the claimed sender
2. The file hasn't been tampered with
3. Protection against malicious files (DoS protection via fast signature check)

## File Format (V7)

Asymmetric encrypted files use Format Version 7:

```
{
  "format_version": 7,
  "mode": "asymmetric",
  "asymmetric": {
    "recipients": [
      {
        "key_id": "recipient_fingerprint",
        "kem_algorithm": "ML-KEM-768",
        "encapsulated_key": "base64...",
        "encrypted_password": "base64..."
      }
    ],
    "sender": {
      "key_id": "sender_fingerprint",
      "sig_algorithm": "ML-DSA-65"
    }
  },
  "signature": {
    "algorithm": "ML-DSA-65",
    "value": "base64..."
  },
  ...
}
---ENCRYPTED_DATA---
[encrypted file content]
```

## Troubleshooting

### "Identity not found"

```
ERROR: Identity 'Alice' not found
```

**Solution**: Create the identity or check spelling:

```bash
openssl_encrypt identity list
```

### "liboqs not available"

```
ERROR: liboqs not available. Cannot create identity.
```

**Solution**: Install the post-quantum cryptography library:

```bash
pip install liboqs-python
```

### "Incorrect passphrase"

```
ERROR: Incorrect passphrase
```

**Solution**: Double-check your passphrase. If forgotten, you cannot recover the private keys (by design).

### "SIGNATURE VERIFICATION FAILED"

```
ERROR: SIGNATURE VERIFICATION FAILED
```

**Possible causes**:
1. File was tampered with
2. Wrong sender specified
3. Sender's public key is incorrect

**Solution**: Verify the sender's identity and try again with correct `--verify-from`.

### "not encrypted for recipient"

```
ERROR: File not encrypted for recipient 'Bob'
```

**Solution**: The file was encrypted for different recipients. Check who the intended recipients are.

## Performance Notes

### Encryption Overhead

Asymmetric encryption adds:
- ~1.2 KB per recipient
- Slightly longer encryption time (ML-KEM operations)
- Same decryption time as symmetric mode (after key unwrapping)

### Recommended Use Cases

**Use asymmetric mode when:**
- Encrypting for specific individuals
- Need non-repudiation (digital signatures)
- Sharing encrypted files without sharing passwords
- Multi-recipient scenarios

**Use symmetric mode when:**
- Personal file encryption
- Maximum performance needed
- Single user scenario
- Backward compatibility required

## Migration from Symmetric

Existing symmetric encrypted files (V4, V5, V6) remain fully supported. You can:
1. Continue using symmetric mode
2. Decrypt old files normally
3. Re-encrypt with asymmetric mode if desired

No forced migration - both modes coexist.

## Examples

### Example 1: Secure Document Sharing

Alice wants to share a sensitive document with Bob and Charlie:

```bash
# Alice encrypts
openssl_encrypt encrypt --input report.pdf \
    --for Bob \
    --for Charlie \
    --sign-with Alice \
    --output report.pdf.enc

# Alice sends report.pdf.enc to Bob and Charlie

# Bob decrypts
openssl_encrypt decrypt --input report.pdf.enc \
    --key Bob \
    --verify-from Alice

# Charlie independently decrypts
openssl_encrypt decrypt --input report.pdf.enc \
    --key Charlie \
    --verify-from Alice
```

### Example 2: Team Communication

Dev team shares credentials:

```bash
# Export public keys
openssl_encrypt identity export --identity DevLead --output devlead_public.json

# Team members import
openssl_encrypt identity import --file devlead_public.json

# DevLead encrypts credentials for team
openssl_encrypt encrypt --input credentials.txt \
    --for Dev1 \
    --for Dev2 \
    --for Dev3 \
    --sign-with DevLead
```

### Example 3: Paranoid Security

Maximum security configuration:

```bash
# Create identity with strongest algorithms
openssl_encrypt identity create --name SecureAlice \
    --kem-algorithm ML-KEM-1024 \
    --sig-algorithm ML-DSA-87

# Encrypt with maximum KDF rounds
openssl_encrypt encrypt --input topsecret.txt \
    --for SecureBob \
    --sign-with SecureAlice \
    --sha512-rounds 20 \
    --blake2b-rounds 15 \
    --pbkdf2-iterations 500000
```

## API Usage (Python)

For programmatic usage:

```python
from openssl_encrypt.modules.identity import Identity, IdentityStore
from openssl_encrypt.modules.crypt_core import (
    encrypt_file_asymmetric,
    decrypt_file_asymmetric
)

# Load identities
store = IdentityStore()
alice = store.get_by_name("Alice", "alicepass", load_private_keys=True)
bob = store.get_by_name("Bob", None, load_private_keys=False)

# Encrypt
result = encrypt_file_asymmetric(
    input_file="secret.txt",
    output_file="secret.txt.enc",
    recipients=[bob],
    sender=alice
)

# Decrypt
decrypt_file_asymmetric(
    input_file="secret.txt.enc",
    output_file="decrypted.txt",
    recipient=bob,
    sender_public_key=alice.signing_public_key
)
```

## FAQ

**Q: Can I use the same identity on multiple machines?**

A: Yes. Export your identity directory `~/.openssl_encrypt/identities/alice/` and securely transfer it to another machine.

**Q: What happens if I forget my passphrase?**

A: Private keys are unrecoverable. This is by design for security. Always keep secure backups.

**Q: Can I encrypt for myself?**

A: Yes! Encrypt `--for Alice --sign-with Alice` to encrypt files for your own future use.

**Q: How secure is ML-KEM-768?**

A: ML-KEM-768 is NIST standardized (FIPS 203) and provides Security Level 3, equivalent to AES-192 against quantum computers.

**Q: Can quantum computers break this?**

A: No. ML-KEM and ML-DSA are specifically designed to resist quantum computer attacks.

**Q: Do I still need a strong passphrase with post-quantum crypto?**

A: Yes! Post-quantum algorithms protect the key exchange, but your passphrase protects your private keys at rest.

## Related Documentation

- [Main README](../README.md)
- [Security Architecture](SECURITY.md)
- [API Documentation](API.md)

## Support

- GitHub Issues: https://github.com/smirnfil/openssl_encrypt/issues
- Security Issues: Report privately via GitHub Security Advisories
