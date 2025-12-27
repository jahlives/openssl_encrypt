# Security Audit: Algorithm Registry System

**Date**: 2025-12-27
**Auditor**: Claude (Sonnet 4.5)
**Scope**: Algorithm Registry sensitive data handling
**Status**: 🔴 **CRITICAL ISSUES FOUND**

## Executive Summary

The algorithm registry system currently handles sensitive cryptographic material (passwords, keys, plaintexts, shared secrets) using standard Python `bytes` objects instead of the project's `SecureBytes` class. This creates security vulnerabilities where sensitive data:

1. **Remains in memory after use** (not securely zeroed)
2. **Can be swapped to disk** (paging/swap exposure)
3. **May appear in core dumps** (forensic exposure)
4. **Could be accessed via memory inspection** (debugging/attack)

## Affected Components

### 1. KDF Registry (`kdf_registry.py`)

**Functions with sensitive data**:
```python
def derive(self, password: bytes, salt: bytes, params: Optional[KDFParams] = None) -> bytes:
    # Returns derived key
```

**Sensitive parameters**:
- `password` - User password (HIGH SENSITIVITY)
- `salt` - KDF salt (MEDIUM SENSITIVITY)
- **Return value** - Derived encryption key (HIGH SENSITIVITY)

**Risk Level**: 🔴 **CRITICAL**

**Impact**: All 8 KDF implementations affected:
- Argon2id, Argon2i, Argon2d
- PBKDF2
- Scrypt
- Balloon
- HKDF
- RandomX

### 2. Cipher Registry (`cipher_registry.py`)

**Functions with sensitive data**:
```python
def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
```

**Sensitive parameters**:
- `key` - Encryption key (HIGH SENSITIVITY)
- `plaintext` - Unencrypted data (HIGH SENSITIVITY)
- `aad` - Additional authenticated data (MEDIUM SENSITIVITY - may contain metadata)

**Risk Level**: 🔴 **CRITICAL**

**Impact**: All 6 cipher implementations affected:
- AES-256-GCM, AES-256-GCM-SIV, AES-256-OCB3, AES-256-SIV
- ChaCha20-Poly1305, XChaCha20-Poly1305

### 3. KEM Registry (`kem_registry.py`)

**Functions with sensitive data**:
```python
def generate_keypair(self) -> Tuple[bytes, bytes]:  # (public_key, secret_key)
def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:  # (ciphertext, shared_secret)
def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:  # shared_secret
```

**Sensitive parameters/returns**:
- `secret_key` - Private key (CRITICAL SENSITIVITY)
- `shared_secret` - Shared encryption key (HIGH SENSITIVITY)

**Risk Level**: 🔴 **CRITICAL**

**Impact**: All 6 KEM implementations affected:
- ML-KEM-512, ML-KEM-768, ML-KEM-1024
- HQC-128, HQC-192, HQC-256

### 4. Signature Registry (`signature_registry.py`)

**Functions with sensitive data**:
```python
def generate_keypair(self) -> Tuple[bytes, bytes]:  # (public_key, secret_key)
def sign(self, message: bytes, secret_key: bytes) -> bytes:
```

**Sensitive parameters**:
- `secret_key` - Private signing key (CRITICAL SENSITIVITY)
- `message` - May contain sensitive data (VARIABLE SENSITIVITY)

**Risk Level**: 🟡 **HIGH** (secret keys critical, messages variable)

**Impact**: All 15 signature implementations affected:
- ML-DSA-44, ML-DSA-65, ML-DSA-87
- SLH-DSA (3 variants), FN-DSA (2 variants)
- MAYO (3 variants), CROSS (3 variants)

### 5. Hash Registry (`hash_registry.py`)

**Functions with sensitive data**:
```python
def hash(self, data: bytes) -> bytes:
def hmac(self, key: bytes, data: bytes) -> bytes:
```

**Sensitive parameters**:
- `key` - HMAC key (HIGH SENSITIVITY)
- `data` - May contain sensitive data (VARIABLE SENSITIVITY)

**Risk Level**: 🟡 **MEDIUM-HIGH** (HMAC keys critical, hash data variable)

**Impact**: All 12 hash implementations affected

## Root Cause

The registry system was designed for **algorithm abstraction and discovery**, focusing on:
- ✅ Algorithm metadata and capabilities
- ✅ Availability checking
- ✅ Unified interface

Security aspects were not fully integrated:
- ❌ No SecureBytes usage
- ❌ No explicit memory zeroing
- ❌ Standard Python bytes used throughout

## Comparison with Existing Code

The existing `crypt_core.py` properly uses SecureBytes:

```python
from .secure_memory import SecureBytes, secure_memzero

# Example from existing code:
with secure_string() as password_secure:
    password = SecureBytes(password_input.encode())
    # ... use password ...
    secure_memzero(password)
```

The registry system should follow this pattern.

## Recommended Fixes

### Priority 1: Critical Functions (KDF, Cipher, KEM)

1. **Update function signatures** to accept/return SecureBytes:
   ```python
   from ..secure_memory import SecureBytes

   def derive(self, password: SecureBytes, salt: bytes, params: Optional[KDFParams] = None) -> SecureBytes:
       # Implementation
       result = SecureBytes(derived_key)
       return result
   ```

2. **Add cleanup in exception handlers**:
   ```python
   def encrypt(self, key: SecureBytes, nonce: bytes, plaintext: SecureBytes, aad: bytes = b"") -> bytes:
       try:
           # Encryption logic
           return ciphertext
       finally:
           # Sensitive intermediate values cleaned up automatically by SecureBytes
           pass
   ```

3. **Document security expectations** in docstrings:
   ```python
   def derive(self, password: SecureBytes, ...):
       """
       Derives a key from a password.

       Args:
           password: Password (SecureBytes - will be zeroed after use)
           ...

       Returns:
           Derived key (SecureBytes - caller must zero after use)

       Security:
           - Password is not copied to standard bytes
           - Derived key is returned as SecureBytes
           - Caller responsible for zeroing return value
       """
   ```

### Priority 2: Integration Points

Update calling code in CLI helpers and config wizard to use SecureBytes when interacting with registries.

### Priority 3: Testing

Add security-focused tests:
```python
def test_kdf_secure_memory():
    """Test that KDF properly handles SecureBytes."""
    password = SecureBytes(b"test_password")
    kdf = Argon2id()
    key = kdf.derive(password, b"salt")

    assert isinstance(key, SecureBytes)

    # Verify zeroing
    key_addr = id(key)
    del key
    # Memory should be zeroed
```

## Migration Strategy

### Phase 1: Backward Compatible Updates
- Add SecureBytes support while maintaining bytes compatibility
- Use Union[bytes, SecureBytes] type hints initially
- Convert bytes to SecureBytes internally

### Phase 2: Deprecation
- Warn when bytes are used instead of SecureBytes
- Update all internal usage

### Phase 3: Enforcement
- Remove bytes support
- Require SecureBytes for sensitive parameters

## Action Items

- [ ] Update KDF registry to use SecureBytes
- [ ] Update Cipher registry to use SecureBytes
- [ ] Update KEM registry to use SecureBytes
- [ ] Update Signature registry to use SecureBytes (secret keys only)
- [ ] Update Hash registry HMAC to use SecureBytes (keys only)
- [ ] Add security tests
- [ ] Update documentation
- [ ] Review all calling code

## Timeline

**Estimated effort**: 4-6 hours
- Analysis: ✅ Complete
- Implementation: Pending
- Testing: Pending
- Documentation: Pending

## References

- `openssl_encrypt/modules/secure_memory.py` - SecureBytes implementation
- `openssl_encrypt/modules/crypt_core.py` - Proper usage examples
- `openssl_encrypt/modules/pqc.py` - PQC with SecureBytes

---

**Auditor Notes**: This is a significant oversight but fixable. The registry system is well-structured and adding SecureBytes support should be straightforward. The main challenge is ensuring backward compatibility during migration.
