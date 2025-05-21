# Post-Quantum Encryption with Configurable Data Algorithms

## Overview

In version 5 of the metadata format, it is now possible to choose which symmetric encryption algorithm is used for data encryption when using Kyber for post-quantum key encapsulation. This feature allows better customization of the encryption process to meet specific security or performance requirements.

## Available Algorithms

When using a Kyber-based algorithm (kyber512-hybrid, kyber768-hybrid, or kyber1024-hybrid), you can now specify one of the following symmetric encryption algorithms for data encryption:

| Algorithm | Description | Recommended Use Case |
|---|---|---|
| `aes-gcm` (default) | AES-256 in GCM mode | General purpose, widely trusted |
| `aes-gcm-siv` | AES-256 in GCM-SIV mode | Resistant to nonce reuse, better for high-volume encryption |
| `aes-ocb3` | AES-256 in OCB3 mode | Faster than GCM, good performance option |
| `aes-siv` | AES in SIV mode | Strong misuse resistance, good for static data |
| `chacha20-poly1305` | ChaCha20-Poly1305 with 12-byte nonce | Better performance on hardware without AES acceleration |
| `xchacha20-poly1305` | ChaCha20-Poly1305 with 24-byte nonce | Safer for high-volume encryption, random nonce reuse is less likely |

## Using from the Command Line

To specify the data encryption algorithm when using the CLI:

```bash
# Use kyber768-hybrid with AES-GCM-SIV for data encryption
openssl_encrypt encrypt --algorithm kyber768-hybrid --encryption-data aes-gcm-siv \
    --input myfile.txt --output myfile.enc
    
# Use kyber1024-hybrid with ChaCha20-Poly1305 for data encryption
openssl_encrypt encrypt --algorithm kyber1024-hybrid --encryption-data chacha20-poly1305 \
    --input myfile.txt --output myfile.enc
```

The `--encryption-data` parameter only has an effect when using one of the Kyber hybrid algorithms.

## Using in Configuration Files

You can also specify the data encryption algorithm in configuration files:

```json
{
  "hash_config": {
    "sha512": 10000,
    "sha256": 0,
    "...": "...",
    "algorithm": "kyber768-hybrid"
  },
  "encryption_data": "chacha20-poly1305"
}
```

Or in YAML format:

```yaml
hash_config:
  sha512: 10000
  sha256: 0
  ...
  algorithm: kyber768-hybrid
encryption_data: chacha20-poly1305
```

## Using from the API

When using the API, you can specify the data encryption algorithm as follows:

```python
from openssl_encrypt.modules.crypt_core import encrypt_file, decrypt_file

# Encrypt a file with Kyber using XChaCha20-Poly1305 for data encryption
encrypt_file(
    input_file="myfile.txt",
    output_file="myfile.enc",
    password="my_secure_password",
    algorithm="kyber768-hybrid",
    encryption_data="xchacha20-poly1305"
)

# Decryption is automatic based on the metadata
decrypt_file(
    input_file="myfile.enc",
    output_file="myfile.dec", 
    password="my_secure_password"
)
```

## Performance and Security Considerations

1. **Performance:**
   - `aes-ocb3` generally offers the best performance on modern CPUs with AES-NI instructions
   - `chacha20-poly1305` may perform better on older CPUs or low-power devices without AES hardware acceleration

2. **Security:**
   - All provided algorithms offer strong security when used correctly
   - `aes-gcm-siv` and `aes-siv` provide better protection against nonce misuse
   - `xchacha20-poly1305` uses a larger nonce, reducing the risk of nonce collision in high-volume scenarios

3. **Compatibility:**
   - `aes-gcm` has the widest compatibility with other crypto libraries and systems
   - Some specialized algorithms might not be available in all environments

## Backward Compatibility

Files encrypted with previous versions will continue to decrypt correctly. Internally, version 4 and earlier files used AES-GCM for data encryption when using Kyber algorithms. When decrypting these files, the software automatically handles the differences in metadata format.

## Metadata Structure

With format version 5, the metadata now includes an `encryption_data` field in the `encryption` section:

```json
{
  "format_version": 5,
  "derivation_config": { ... },
  "hashes": { ... },
  "encryption": {
    "algorithm": "kyber768-hybrid",
    "encryption_data": "chacha20-poly1305",
    "pqc_public_key": "...",
    ...
  }
}
```

For more details about the metadata format, refer to the [metadata_format_v5.md](metadata_format_v5.md) document.