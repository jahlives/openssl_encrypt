# Using MAYO and CROSS Signature Keys as Encryption Secrets

## Executive Summary

This analysis evaluates the feasibility of using MAYO and CROSS post-quantum signature private keys as encryption secrets for all implemented encryption algorithms in the OpenSSL Encrypt project.

**Key Finding**: ✅ **All MAYO and CROSS private keys are compatible with ALL 18 implemented encryption algorithms**, either through direct use or secure key derivation.

## Signature Algorithm Key Sizes

### MAYO (Multivariate Oil-and-Vinegar)
- **MAYO-1**: 32 bytes (256 bits) private key
- **MAYO-3**: 48 bytes (384 bits) private key
- **MAYO-5**: 64 bytes (512 bits) private key

### CROSS (Code-based Restricted Objects)
- **CROSS-128**: 16 bytes (128 bits) private key
- **CROSS-192**: 24 bytes (192 bits) private key
- **CROSS-256**: 32 bytes (256 bits) private key

## Implemented Encryption Algorithms

### Core Symmetric Encryption (8 algorithms)
| Algorithm | Key Size Required | Notes |
|-----------|-------------------|-------|
| Fernet | 32 bytes | URL-safe base64 encoded |
| AES-GCM | 32 bytes | AEAD with authentication |
| AES-GCM-SIV | 32 bytes | Nonce-misuse resistant |
| AES-SIV | 64 bytes | Synthetic IV mode |
| AES-OCB3 | 32 bytes | Offset codebook mode |
| ChaCha20-Poly1305 | 32 bytes | Stream cipher + MAC |
| XChaCha20-Poly1305 | 32 bytes | Extended nonce variant |
| Camellia | 32 bytes | Japanese block cipher |

### Post-Quantum Hybrid Encryption (10 algorithms)
| Algorithm | Key Size Required | Notes |
|-----------|-------------------|-------|
| ML-KEM-512-Hybrid | 32 bytes | NIST standardized |
| ML-KEM-768-Hybrid | 32 bytes | NIST standardized |
| ML-KEM-1024-Hybrid | 32 bytes | NIST standardized |
| ML-KEM-512-ChaCha20 | 32 bytes | Stream cipher variant |
| ML-KEM-768-ChaCha20 | 32 bytes | Stream cipher variant |
| ML-KEM-1024-ChaCha20 | 32 bytes | Stream cipher variant |
| HQC-128-Hybrid | 32 bytes | Code-based KEM |
| HQC-192-Hybrid | 32 bytes | Code-based KEM |
| HQC-256-Hybrid | 32 bytes | Code-based KEM |
| Legacy Kyber variants | 32 bytes | Deprecated but supported |

**Total**: 18 encryption algorithms requiring either 32 bytes or 64 bytes

## Compatibility Matrix

### Direct Compatibility (No Key Derivation Needed)

| Signature Algorithm | Compatible Encryption Algorithms | Count |
|---------------------|-----------------------------------|-------|
| MAYO-1 (32 bytes) | All 32-byte algorithms | 17/18 |
| MAYO-5 (64 bytes) | AES-SIV (64 bytes) | 1/18 |
| CROSS-256 (32 bytes) | All 32-byte algorithms | 17/18 |

### Key Derivation Required

| Signature Algorithm | Needs Derivation For | Derivation Method |
|---------------------|----------------------|-------------------|
| MAYO-3 (48 bytes) | All algorithms | HKDF/PBKDF2 → 32/64 bytes |
| MAYO-5 (64 bytes) | All 32-byte algorithms | SHA-256/HKDF → 32 bytes |
| CROSS-128 (16 bytes) | All algorithms | HKDF/Key stretching → 32/64 bytes |
| CROSS-192 (24 bytes) | All algorithms | HKDF/Key stretching → 32/64 bytes |

## Security Analysis

### ✅ Cryptographic Security
- **Entropy Preservation**: Key derivation maintains the entropy of source material
- **One-Way Property**: Derived keys cannot reveal signature private keys
- **Domain Separation**: Different algorithms get cryptographically independent keys
- **Post-Quantum Security**: PQ properties of signature keys are preserved

### ✅ Implementation Security
- **No Key Reuse**: Same signature key generates different encryption keys per algorithm
- **Forward Security**: Compromise of one encryption key doesn't affect others
- **Backward Compatibility**: Existing encryption workflows remain unchanged
- **Audit Trail**: Clear derivation path for security reviews

### ✅ Practical Security
- **Strong Key Material**: Signature keys are high-entropy cryptographic keys
- **Proven Algorithms**: Uses well-established key derivation functions
- **Standards Compliance**: Follows NIST recommendations for key derivation
- **Post-Quantum Ready**: Maintains security against quantum attacks

## Recommended Implementation

### Key Derivation Strategy
```python
def derive_encryption_key(signature_private_key: bytes,
                         target_algorithm: str,
                         target_key_size: int) -> bytes:
    """
    Derive encryption key from signature private key

    Args:
        signature_private_key: MAYO/CROSS private key bytes
        target_algorithm: Target encryption algorithm name
        target_key_size: Required key size (32 or 64 bytes)

    Returns:
        Derived encryption key of specified size
    """
    # Use HKDF for secure key derivation
    salt = b"OpenSSL-Encrypt-PQ-Signature-Key-Derivation"
    info = f"encryption-key-{target_algorithm}".encode()

    return HKDF(
        algorithm=hashes.SHA256(),
        length=target_key_size,
        salt=salt,
        info=info,
    ).derive(signature_private_key)
```

### CLI Integration Example
```bash
# Generate signature keys
python -m openssl_encrypt.crypt generate-signature-keys \
  --algorithm mayo-1 \
  --output-dir ./keys

# Use signature key for encryption
python -m openssl_encrypt.crypt encrypt \
  --algorithm aes-gcm \
  --signature-key ./keys/mayo-1-private.key \
  --input document.pdf \
  --output document.pdf.enc
```

## Benefits of This Approach

### 🔐 Enhanced Security
- **Unified Key Management**: Single signature key enables both signing and encryption
- **Reduced Key Proliferation**: Fewer keys to manage and secure
- **Post-Quantum Everything**: Both operations use PQ-secure key material
- **Cross-Algorithm Compatibility**: One key works with all encryption algorithms

### 🛠️ Operational Benefits
- **Simplified Workflows**: Single key for hybrid sign+encrypt operations
- **Reduced Storage**: Fewer key files to manage
- **Backup Simplification**: One key backup covers both operations
- **Access Control**: Unified permission model for both capabilities

### 🚀 Technical Advantages
- **Cryptographically Sound**: Based on proven key derivation techniques
- **Implementation Ready**: Existing codebase has necessary primitives
- **Standards Compliant**: Follows NIST key derivation recommendations
- **Future Proof**: Works with any new encryption algorithms added

## Conclusion

**All MAYO and CROSS signature private keys can be securely used as encryption secrets for ALL 18 implemented encryption algorithms** in the OpenSSL Encrypt project.

This capability would enable:
- Unified post-quantum key management
- Simplified hybrid sign+encrypt workflows
- Reduced key proliferation and management overhead
- Enhanced security through consolidated key material

The implementation is cryptographically sound, technically feasible, and operationally beneficial.

---

**Analysis Date**: 2025-06-19
**Algorithms Analyzed**: 6 signature algorithms × 18 encryption algorithms = 108 combinations
**Compatibility**: 100% (all combinations supported via direct use or secure key derivation)
