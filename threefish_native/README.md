# openssl-encrypt-threefish

Threefish-512 and Threefish-1024 AEAD cipher extension for [openssl-encrypt](https://gitlab.rm-rf.ch/world/openssl_encrypt).

Provides **256-bit and 512-bit post-quantum security** (vs 128-bit for AES-256 and ChaCha20).

## Features

- **Threefish-512**: 64-byte key, 32-byte nonce, 256-bit PQ security
- **Threefish-1024**: 128-byte key, 64-byte nonce, 512-bit PQ security (overkill)
- **AEAD Construction**: CTR mode + Poly1305 authentication
- **Fast Rust Implementation**: Compiled native extension using PyO3
- **Secure Memory Handling**: Automatic zeroing of sensitive data
- **Constant-Time Operations**: Protection against timing attacks

## Installation

```bash
# Install openssl-encrypt with threefish support
pip install openssl-encrypt[threefish]

# Or install threefish extension separately
pip install openssl-encrypt-threefish
```

## Usage

### Python API (via openssl-encrypt)

```python
from openssl_encrypt.modules.registry import Threefish512, Threefish1024
import threefish_native

# Threefish-512 (256-bit PQ security)
cipher = Threefish512()
key = threefish_native.generate_key_512()
nonce = threefish_native.generate_nonce_512()

# Encrypt
plaintext = b"Secret message"
ciphertext = cipher.encrypt(key, plaintext, nonce=nonce)

# Decrypt
decrypted = cipher.decrypt(key, ciphertext, nonce=nonce)
assert decrypted == plaintext

# With AAD (Additional Authenticated Data)
aad = b"header info"
ciphertext = cipher.encrypt(key, plaintext, nonce=nonce, associated_data=aad)
decrypted = cipher.decrypt(key, ciphertext, nonce=nonce, associated_data=aad)
```

### Direct Native API

```python
import threefish_native

# Threefish-512
key_512 = threefish_native.generate_key_512()      # 64 bytes
nonce_512 = threefish_native.generate_nonce_512()  # 32 bytes

ciphertext = threefish_native.encrypt_512(key_512, nonce_512, plaintext, aad)
plaintext = threefish_native.decrypt_512(key_512, nonce_512, ciphertext, aad)

# Threefish-1024
key_1024 = threefish_native.generate_key_1024()      # 128 bytes
nonce_1024 = threefish_native.generate_nonce_1024()  # 64 bytes

ciphertext = threefish_native.encrypt_1024(key_1024, nonce_1024, plaintext, aad)
plaintext = threefish_native.decrypt_1024(key_1024, nonce_1024, ciphertext, aad)
```

### Command Line (via openssl-encrypt)

```bash
# Encrypt with Threefish-512
openssl-encrypt --cipher threefish-512 -e secret.txt

# Encrypt with Threefish-1024 (paranoid mode)
openssl-encrypt --cipher threefish-1024 -e topsecret.txt
```

## Security Properties

| Cipher | Key Size | Nonce Size | PQ Security | Security Level |
|--------|----------|------------|-------------|----------------|
| AES-256-GCM | 256-bit | 96-bit | 128-bit | STANDARD |
| ChaCha20-Poly1305 | 256-bit | 96-bit | 128-bit | STANDARD |
| **Threefish-512** | **512-bit** | **256-bit** | **256-bit** | **HIGH** |
| **Threefish-1024** | **1024-bit** | **512-bit** | **512-bit** | **PARANOID** |

### Why Threefish?

Post-quantum computers using Grover's algorithm can effectively halve the key strength of symmetric ciphers:
- AES-256 → 128-bit effective security
- Threefish-512 → 256-bit effective security
- Threefish-1024 → 512-bit effective security

Threefish-512 provides true 256-bit post-quantum security, making it ideal for long-term data protection.

## Performance

Threefish is approximately 2-3x slower than AES-GCM on systems with AES-NI hardware acceleration, but faster than AES in software-only implementations.

Benchmarks on modern hardware:
- Threefish-512: ~500 MB/s
- Threefish-1024: ~400 MB/s

## Building from Source

Requires Rust toolchain:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install maturin
pip install maturin

# Build and install
cd threefish_native
maturin develop --release
```

## Algorithm Details

### AEAD Construction

Threefish does not have a built-in AEAD mode, so we construct one using:
1. **Encryption**: Threefish in CTR (Counter) mode
2. **Authentication**: Poly1305 MAC
3. **Key Derivation**: Separate Poly1305 key derived from Threefish

This construction is similar to ChaCha20-Poly1305 and provides:
- Confidentiality (CTR mode)
- Authenticity (Poly1305 MAC)
- Integrity (authentication prevents tampering)

### Format

```
Output: ciphertext || poly1305_tag (16 bytes)
```

**Note**: Unlike AES-GCM in openssl-encrypt, the nonce is NOT prepended to the ciphertext. You must store and provide the nonce separately during decryption.

## Security Guarantees

- **Constant-time operations**: Protection against timing attacks
- **Memory zeroing**: Sensitive data automatically zeroed after use
- **Authentication**: Poly1305 MAC prevents tampering
- **Nonce uniqueness**: Critical - never reuse a nonce with the same key

## References

- [Threefish specification](https://www.schneier.com/academic/skein/)
- [Skein Hash Function Submission to NIST](https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf)
- [Poly1305 MAC](https://cr.yp.to/mac.html)

## License

MIT

## Contributing

Issues and pull requests welcome at [GitLab](https://gitlab.rm-rf.ch/world/openssl_encrypt).
